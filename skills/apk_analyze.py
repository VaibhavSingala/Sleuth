"""Defensive static APK triage for Sleuth.

Read-only analysis of Android packages: fingerprint, structure, manifest /
permissions, string IOCs, and native .so capability map. Can also download a
direct APK URL into apks/. Dynamic install/launch lives in apk_device (host
emulator via ADB). Drop or download samples under apks/ (Docker: /app/apks/).
"""

from __future__ import annotations

import collections
import hashlib
import io
import re
import zipfile
from pathlib import Path
from typing import Any, Literal

# Project root = parent of skills/; in Docker CODE_ROOT is /app.
_SKILLS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SKILLS_DIR.parent
_APKS_DIR = _PROJECT_ROOT / "apks"

Action = Literal["triage", "manifest", "iocs", "natives", "report", "download"]

_MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024  # 512 MiB

# Dangerous / high-interest Android permissions (short names without prefix).
_DANGEROUS_PERMS = {
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "RECEIVE_MMS",
    "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "RECORD_AUDIO", "CAMERA",
    "READ_PHONE_STATE", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
    "QUERY_ALL_PACKAGES", "PACKAGE_USAGE_STATS",
    "WRITE_SETTINGS", "WRITE_SECURE_SETTINGS",
}

_CAPABILITY_MARKERS: dict[str, list[bytes]] = {
    "clipboard_read": [b"getPrimaryClip", b"addPrimaryClipChangedListener", b"coerceToText"],
    "clipboard_write": [b"setPrimaryClip"],
    "dyn_code_load": [
        b"DexClassLoader", b"InMemoryDexClassLoader", b"PathClassLoader",
        b"System.load", b"loadLibrary", b"dlopen",
    ],
    "reflection": [b"getDeclaredMethod", b"setAccessible", b"java/lang/reflect"],
    "accessibility": [b"AccessibilityService", b"TYPE_VIEW_CLICKED"],
    "overlay": [b"SYSTEM_ALERT_WINDOW", b"TYPE_APPLICATION_OVERLAY"],
    "device_admin": [b"DeviceAdminReceiver", b"BIND_DEVICE_ADMIN"],
    "sms": [b"SEND_SMS", b"Telephony.Sms", b"content://sms"],
    "contacts": [b"ContactsContract", b"content://com.android.contacts"],
    "location": [b"getLastKnownLocation", b"requestLocationUpdates", b"FusedLocation"],
    "camera_mic": [b"MediaRecorder", b"Camera.open", b"android.hardware.camera"],
    "network": [b"OkHttpClient", b"HttpURLConnection", b"javax/net/ssl", b"socket("],
    "crypto": [b"Cipher.getInstance", b"SecretKeySpec", b"MessageDigest"],
    "root_check": [b"/system/bin/su", b"magisk", b"SafetyNet", b"PlayIntegrity"],
    "anti_debug": [b"Debug.isDebuggerConnected", b"ptrace", b"TracerPid"],
}

_URL_RE = re.compile(rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}")
_IP_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_EMAIL_RE = re.compile(rb"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_TG_RE = re.compile(rb"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")

_BENIGN_ASSET_EXT = (
    ".so", ".png", ".jpg", ".jpeg", ".webp", ".ogg", ".mp3", ".ttf", ".otf",
    ".wav", ".mp4", ".json", ".xml", ".txt", ".html", ".css", ".js", ".svg",
)

_NETWORK_IMPORTS = {
    "socket", "connect", "getaddrinfo", "send", "recv", "SSL_write", "SSL_read",
    "curl_easy_perform", "curl_easy_init",
}
_MEMORY_IMPORTS = {"mmap", "mprotect", "mremap", "dlopen", "dlsym"}
_ANTIDEBUG_IMPORTS = {"ptrace", "fork", "prctl"}
_EXEC_IMPORTS = {"system", "execve", "popen", "execl"}


def _allowed_roots() -> list[Path]:
    roots = [_PROJECT_ROOT.resolve(), _APKS_DIR.resolve()]
    # Docker CODE_ROOT / explicit /app
    for extra in (Path("/app"), Path("/app/apks")):
        try:
            roots.append(extra.resolve())
        except OSError:
            pass
    # Dedupe
    seen: set[Path] = set()
    out: list[Path] = []
    for r in roots:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _resolve_apk(apk: str) -> Path | dict[str, Any]:
    """Resolve apk path; must exist and stay under project / apks roots."""
    raw = (apk or "").strip()
    if not raw:
        return {"ok": False, "error": "apk path is required."}

    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        # Prefer apks/ then project root
        for base in (_APKS_DIR, _PROJECT_ROOT, Path("/app/apks"), Path("/app")):
            trial = (base / raw).resolve()
            if trial.is_file():
                candidate = trial
                break
        else:
            candidate = (_APKS_DIR / raw).resolve()
    else:
        candidate = candidate.resolve()

    if not candidate.is_file():
        return {
            "ok": False,
            "error": f"APK not found: {raw}",
            "hint": "Drop the file under apks/ (Docker: /app/apks/) and pass that path.",
        }

    try:
        resolved = candidate.resolve()
    except OSError as exc:
        return {"ok": False, "error": f"Cannot resolve path: {exc}"}

    if not any(_is_under(resolved, root) for root in _allowed_roots()):
        return {
            "ok": False,
            "error": f"Refused: '{resolved}' is outside allowed roots "
                     f"(project / apks). Copy the sample into apks/.",
        }
    return resolved


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _hash_file(path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def _open_apk(path: Path) -> zipfile.ZipFile | dict[str, Any]:
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return {"ok": False, "error": f"Not a valid ZIP/APK: {path}"}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def _triage(path: Path) -> dict[str, Any]:
    hashes = _hash_file(path)
    z = _open_apk(path)
    if isinstance(z, dict):
        return z

    dex, libs, assets, meta, other = [], [], [], [], []
    abi: collections.Counter[str] = collections.Counter()
    with z:
        infos = z.infolist()
        for info in infos:
            name = info.filename
            size = info.file_size
            if re.fullmatch(r"classes\d*\.dex", name):
                dex.append({"name": name, "size": size})
            elif name.startswith("lib/"):
                libs.append({"name": name, "size": size})
                parts = name.split("/")
                if len(parts) >= 2:
                    abi[parts[1]] += 1
            elif name.startswith("assets/"):
                assets.append({"name": name, "size": size})
            elif name.startswith("META-INF/"):
                meta.append({"name": name, "size": size})
            else:
                other.append({"name": name, "size": size})

        hidden_so = [
            {"name": n, "size": s}
            for n, s in (
                (e["name"], e["size"]) for e in assets + other
            )
            if n.lower().endswith(".so")
        ]

        renamed: list[dict[str, Any]] = []
        for info in infos:
            if not info.filename.startswith("assets/") or info.file_size < 8:
                continue
            if info.filename.lower().endswith(_BENIGN_ASSET_EXT):
                continue
            try:
                head = z.open(info).read(4)
            except Exception:
                continue
            tag = None
            if head[:4] == b"dex\n":
                tag = "DEX"
            elif head[:4] == b"\x7fELF":
                tag = "ELF"
            elif head[:2] == b"PK":
                tag = "ZIP"
            if tag:
                renamed.append({
                    "name": info.filename,
                    "magic": tag,
                    "size": info.file_size,
                })

        has_v1 = any(n["name"].upper().endswith("MANIFEST.MF") for n in meta)

    return {
        "ok": True,
        "action": "triage",
        "file": str(path),
        "size_bytes": path.stat().st_size,
        "hashes": hashes,
        "virustotal_url": f"https://www.virustotal.com/gui/file/{hashes['sha256']}",
        "structure": {
            "entries": len(dex) + len(libs) + len(assets) + len(meta) + len(other),
            "dex": dex,
            "native_libs": libs,
            "abis": dict(abi),
            "assets_count": len(assets),
            "meta_inf_count": len(meta),
            "v1_signature_manifest": has_v1,
        },
        "hidden_so_outside_lib": hidden_so,
        "renamed_payload_magic": renamed,
        "notes": [
            "Static triage only — sample was not executed.",
            "A small extra classesN.dex often means an injected loader.",
            "Missing META-INF/MANIFEST.MF can indicate a re-signed / v2+ only build.",
        ],
    }


def _manifest(path: Path) -> dict[str, Any]:
    try:
        from androguard.core.apk import APK  # type: ignore
    except ImportError:
        return {
            "ok": False,
            "action": "manifest",
            "error": "androguard is not installed. pip install androguard "
                     "(rebuild Docker image after updating requirements.txt).",
            "skipped": True,
        }

    # androguard is chatty on broken manifests; keep skill output clean
    import logging
    ag_log = logging.getLogger("androguard")
    prev = ag_log.level
    ag_log.setLevel(logging.CRITICAL)
    try:
        try:
            a = APK(str(path))
        except Exception as exc:
            return {"ok": False, "action": "manifest", "error": f"androguard failed: {exc}"}
    finally:
        ag_log.setLevel(prev)

    def _safe(fn, default=None):
        try:
            return fn()
        except Exception:
            return default

    perms = sorted(set(_safe(a.get_permissions, []) or []))
    dangerous = []
    for p in perms:
        short = p.rsplit(".", 1)[-1]
        if short in _DANGEROUS_PERMS or any(d in p for d in _DANGEROUS_PERMS):
            dangerous.append(p)

    def _names(items) -> list[str]:
        out = []
        for item in items or []:
            if isinstance(item, str):
                out.append(item)
            else:
                out.append(str(item))
        return sorted(out)[:80]

    activities = _names(_safe(a.get_activities, []) or [])
    services = _names(_safe(a.get_services, []) or [])
    receivers = _names(_safe(a.get_receivers, []) or [])
    providers = _names(_safe(a.get_providers, []) or [])

    app_name = _safe(a.get_app_name, "") or ""
    package = _safe(a.get_package, None)
    version_name = None
    version_code = None
    try:
        version_name = a.get_androidversion_name()
    except Exception:
        version_name = (getattr(a, "androidversion", None) or {}).get("Name")
    try:
        version_code = a.get_androidversion_code()
    except Exception:
        version_code = (getattr(a, "androidversion", None) or {}).get("Code")

    # If androguard could not even get a package, treat as soft failure with partial data
    if not package and not perms and not activities:
        return {
            "ok": False,
            "action": "manifest",
            "error": "AndroidManifest.xml could not be parsed (invalid or missing AXML).",
            "file": str(path),
            "partial": True,
        }

    return {
        "ok": True,
        "action": "manifest",
        "file": str(path),
        "package": package,
        "app_name": app_name,
        "version_name": version_name,
        "version_code": version_code,
        "min_sdk": _safe(a.get_min_sdk_version),
        "target_sdk": _safe(a.get_target_sdk_version),
        "main_activity": _safe(a.get_main_activity),
        "permissions": perms,
        "dangerous_permissions": dangerous,
        "components": {
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "counts": {
                "activities": len(activities),
                "services": len(services),
                "receivers": len(receivers),
                "providers": len(providers),
            },
        },
        "notes": [
            "Permissions flagged as dangerous are high-interest for abuse reports.",
            "Absent SMS/contacts/accessibility/device-admin is a meaningfully "
            "less-dangerous profile when true.",
        ],
    }


def _scan_blob(data: bytes, caps: dict[str, bool],
               urls: set[str], ips: set[str], emails: set[str], tokens: set[str]) -> None:
    for name, needles in _CAPABILITY_MARKERS.items():
        if caps.get(name):
            continue
        if any(n in data for n in needles):
            caps[name] = True
    for m in _URL_RE.finditer(data):
        try:
            urls.add(m.group(0).decode("ascii", "ignore").rstrip(").,;\"'"))
        except Exception:
            pass
    for m in _IP_RE.finditer(data):
        try:
            ip = m.group(0).decode("ascii", "ignore")
            # skip version-like 0.0.0.0 / 255.255.255.255 noise lightly
            if ip not in ("0.0.0.0", "255.255.255.255", "127.0.0.1"):
                ips.add(ip)
        except Exception:
            pass
    for m in _EMAIL_RE.finditer(data):
        try:
            emails.add(m.group(0).decode("ascii", "ignore"))
        except Exception:
            pass
    for m in _TG_RE.finditer(data):
        try:
            tokens.add(m.group(0).decode("ascii", "ignore"))
        except Exception:
            pass


def _iocs(path: Path, max_file_bytes: int = 8_000_000) -> dict[str, Any]:
    z = _open_apk(path)
    if isinstance(z, dict):
        return z

    caps = {k: False for k in _CAPABILITY_MARKERS}
    urls: set[str] = set()
    ips: set[str] = set()
    emails: set[str] = set()
    tokens: set[str] = set()
    scanned = 0
    skipped_large = 0

    with z:
        for info in z.infolist():
            name = info.filename
            if info.is_dir():
                continue
            # Focus on code-ish members; still sample assets for hidden payloads
            interesting = (
                re.fullmatch(r"classes\d*\.dex", name)
                or name.startswith("lib/")
                or name.lower().endswith(".so")
                or name.startswith("assets/")
                or name.endswith(".bin")
            )
            if not interesting:
                continue
            if info.file_size > max_file_bytes:
                skipped_large += 1
                continue
            try:
                data = z.read(info)
            except Exception:
                continue
            scanned += 1
            _scan_blob(data, caps, urls, ips, emails, tokens)

    # Cap list sizes for the model context
    def _cap(s: set[str], n: int = 80) -> list[str]:
        return sorted(s)[:n]

    return {
        "ok": True,
        "action": "iocs",
        "file": str(path),
        "members_scanned": scanned,
        "members_skipped_large": skipped_large,
        "capabilities": {k: v for k, v in caps.items() if v},
        "capabilities_absent": sorted(k for k, v in caps.items() if not v),
        "urls": _cap(urls),
        "ips": _cap(ips, 40),
        "emails": _cap(emails, 40),
        "telegram_like_tokens": _cap(tokens, 10),
        "notes": [
            "IOCs are string hits from static blobs — hosts may be decoys or "
            "runtime-decrypted (not visible here).",
            "Use capabilities_absent as balance in an abuse/vendor report.",
        ],
    }


def _elf_map_bytes(data: bytes, name: str) -> dict[str, Any]:
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore
        from elftools.elf.sections import SymbolTableSection  # type: ignore
        from elftools.elf.relocation import RelocationSection  # type: ignore
    except ImportError:
        return {
            "name": name,
            "ok": False,
            "error": "pyelftools not installed",
            "skipped": True,
        }

    if not data.startswith(b"\x7fELF"):
        return {"name": name, "ok": False, "error": "not an ELF file"}

    try:
        ef = ELFFile(io.BytesIO(data))
    except Exception as exc:
        return {"name": name, "ok": False, "error": f"ELF parse failed: {exc}"}

    jni: list[str] = []
    imports: list[str] = []
    exports: list[str] = []
    stripped = True

    for section in ef.iter_sections():
        if isinstance(section, SymbolTableSection):
            if section.name == ".symtab":
                stripped = False
            for sym in section.iter_symbols():
                sname = sym.name or ""
                if not sname:
                    continue
                if sname.startswith("Java_"):
                    jni.append(sname)
                if sym.entry.st_info.type == "STT_FUNC" and sym.entry.st_shndx != "SHN_UNDEF":
                    exports.append(sname)
                if sym.entry.st_shndx == "SHN_UNDEF":
                    imports.append(sname)
        if isinstance(section, RelocationSection):
            # Dynamic imports often show up here when stripped
            try:
                for reloc in section.iter_relocations():
                    sym = reloc["r_info_sym"]
                    # best-effort; skip if unresolved
            except Exception:
                pass

    # Also walk dynamic segment symbols
    try:
        dyn = ef.get_section_by_name(".dynsym")
        if dyn is not None and isinstance(dyn, SymbolTableSection):
            for sym in dyn.iter_symbols():
                sname = sym.name or ""
                if not sname:
                    continue
                if sname.startswith("Java_") and sname not in jni:
                    jni.append(sname)
                if sym.entry.st_shndx == "SHN_UNDEF" and sname not in imports:
                    imports.append(sname)
    except Exception:
        pass

    import_set = set(imports)
    tags = []
    if import_set & _NETWORK_IMPORTS:
        tags.append("network")
    if import_set & _MEMORY_IMPORTS:
        tags.append("memory_patch_or_hooks")
    if import_set & _ANTIDEBUG_IMPORTS:
        tags.append("anti_debug")
    if import_set & _EXEC_IMPORTS:
        tags.append("shell_exec")
    if jni:
        tags.append("jni")

    return {
        "name": name,
        "ok": True,
        "arch": ef.get_machine_arch(),
        "bits": ef.elfclass,
        "stripped": stripped,
        "jni_exports": sorted(jni)[:60],
        "imports_sample": sorted(import_set)[:80],
        "capability_tags": tags,
    }


def _natives(path: Path) -> dict[str, Any]:
    try:
        import elftools  # noqa: F401
        has_elf = True
    except ImportError:
        has_elf = False

    z = _open_apk(path)
    if isinstance(z, dict):
        return z

    libs: list[dict[str, Any]] = []
    with z:
        for info in z.infolist():
            name = info.filename
            if info.is_dir():
                continue
            is_lib = name.startswith("lib/") and name.endswith(".so")
            is_hidden = (not name.startswith("lib/")) and name.lower().endswith(".so")
            # Also catch ELF magic under assets with non-.so names (handled lightly)
            if not (is_lib or is_hidden):
                continue
            try:
                data = z.read(info)
            except Exception as exc:
                libs.append({"name": name, "ok": False, "error": str(exc), "hidden": is_hidden})
                continue
            if not has_elf:
                libs.append({
                    "name": name,
                    "ok": True,
                    "size": info.file_size,
                    "hidden": is_hidden,
                    "note": "pyelftools not installed — listing only",
                })
                continue
            entry = _elf_map_bytes(data, name)
            entry["size"] = info.file_size
            entry["hidden"] = is_hidden
            libs.append(entry)

    result: dict[str, Any] = {
        "ok": True,
        "action": "natives",
        "file": str(path),
        "count": len(libs),
        "libraries": libs,
        "hidden_count": sum(1 for L in libs if L.get("hidden")),
    }
    if not has_elf:
        result["warning"] = (
            "pyelftools is not installed. pip install pyelftools "
            "(rebuild Docker image after updating requirements.txt)."
        )
    result["notes"] = [
        "Hidden .so under assets/ is a common cheat/mod loader pattern.",
        "capability_tags come from import names — statically-linked curl/OpenSSL "
        "can inflate 'network' without being C2 logic.",
    ]
    return result


def _safe_filename(name: str) -> str:
    base = Path(name or "sample.apk").name
    base = re.sub(r"[^\w.\-]+", "_", base).strip("._") or "sample.apk"
    if not base.lower().endswith(".apk"):
        base += ".apk"
    return base[:180]


def _download(url: str, filename: str = "") -> dict[str, Any]:
    """Download an APK from a direct URL into apks/."""
    url = (url or "").strip()
    if not url:
        return {"ok": False, "error": "url is required for download."}
    if not url.lower().startswith(("http://", "https://")):
        return {"ok": False, "error": "url must start with http:// or https://"}

    _APKS_DIR.mkdir(parents=True, exist_ok=True)
    # Derive filename from URL path if not given
    from urllib.parse import urlparse, unquote

    parsed = urlparse(url)
    guessed = unquote(Path(parsed.path).name) if parsed.path else ""
    out_name = _safe_filename(filename or guessed or "download.apk")
    dest = (_APKS_DIR / out_name).resolve()
    if not _is_under(dest, _APKS_DIR.resolve()):
        return {"ok": False, "error": "refused unsafe filename"}

    try:
        import httpx
    except ImportError:
        httpx = None  # type: ignore

    tmp = dest.with_suffix(dest.suffix + ".partial")
    try:
        if httpx is not None:
            with httpx.Client(follow_redirects=True, timeout=120.0) as client:
                with client.stream("GET", url) as resp:
                    if resp.status_code >= 400:
                        return {
                            "ok": False,
                            "error": f"HTTP {resp.status_code} fetching {url}",
                        }
                    total = 0
                    with tmp.open("wb") as fh:
                        for chunk in resp.iter_bytes(1 << 16):
                            total += len(chunk)
                            if total > _MAX_DOWNLOAD_BYTES:
                                fh.close()
                                tmp.unlink(missing_ok=True)
                                return {
                                    "ok": False,
                                    "error": f"download exceeds {_MAX_DOWNLOAD_BYTES} bytes limit",
                                }
                            fh.write(chunk)
        else:
            import urllib.request

            with urllib.request.urlopen(url, timeout=120) as resp:  # noqa: S310
                total = 0
                with tmp.open("wb") as fh:
                    while True:
                        chunk = resp.read(1 << 16)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > _MAX_DOWNLOAD_BYTES:
                            fh.close()
                            tmp.unlink(missing_ok=True)
                            return {
                                "ok": False,
                                "error": f"download exceeds {_MAX_DOWNLOAD_BYTES} bytes limit",
                            }
                        fh.write(chunk)

        # Basic APK/ZIP sanity check
        with tmp.open("rb") as fh:
            magic = fh.read(4)
        if magic[:2] != b"PK":
            tmp.unlink(missing_ok=True)
            return {
                "ok": False,
                "error": "downloaded file is not a ZIP/APK (missing PK header)",
            }

        tmp.replace(dest)
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        return {"ok": False, "error": f"download failed: {type(exc).__name__}: {exc}"}

    hashes = _hash_file(dest)
    return {
        "ok": True,
        "action": "download",
        "url": url,
        "path": str(dest),
        "size_bytes": dest.stat().st_size,
        "hashes": hashes,
        "hint": (
            "Next: apk_analyze(action='report', apk=path) for static triage, "
            "or apk_device(action='install', apk=path) to load it on a host emulator."
        ),
    }


def _report(path: Path) -> dict[str, Any]:
    triage = _triage(path)
    manifest = _manifest(path)
    iocs = _iocs(path)
    natives = _natives(path)

    sections_ok = {
        "triage": bool(triage.get("ok")),
        "manifest": bool(manifest.get("ok")),
        "iocs": bool(iocs.get("ok")),
        "natives": bool(natives.get("ok")),
    }
    return {
        "ok": sections_ok["triage"],  # structure is the baseline
        "action": "report",
        "file": str(path),
        "sections_ok": sections_ok,
        "triage": triage,
        "manifest": manifest,
        "iocs": iocs,
        "natives": natives,
        "summary": {
            "sha256": (triage.get("hashes") or {}).get("sha256"),
            "package": manifest.get("package") if manifest.get("ok") else None,
            "dangerous_permission_count": len(manifest.get("dangerous_permissions") or [])
            if manifest.get("ok") else None,
            "capability_hits": list((iocs.get("capabilities") or {}).keys())
            if iocs.get("ok") else [],
            "native_lib_count": natives.get("count") if natives.get("ok") else None,
            "hidden_so_count": natives.get("hidden_count") if natives.get("ok") else None,
        },
        "notes": [
            "Defensive static report only — do not use this to bypass protections "
            "or attack discovered infrastructure.",
            "Hand off IOCs / package identity to the vendor or abuse desk.",
        ],
    }


def apk_analyze(
    action: str,
    apk: str = "",
    url: str = "",
    filename: str = "",
) -> dict[str, Any]:
    """
    Defensive static analysis of an Android APK, plus direct-URL download into apks/.

    Typical flow:
      1. apk_analyze(action="download", url="https://…/app.apk")
         — or drop a file under apks/ (Docker: /app/apks/).
      2. apk_analyze(action="report", apk="/app/apks/app.apk") for static triage.
      3. Use apk_device to install/launch on a host Android emulator via ADB.

    Static actions never execute the sample. download only fetches bytes to disk.

    Args:
        action: One of download, triage, manifest, iocs, natives, report.
        apk: Path to the .apk (absolute under project/apks, or relative to apks/).
        url: Direct http(s) URL to an .apk (for download).
        filename: Optional save name under apks/ when downloading.

    Returns:
        Dict with ok and action-specific findings (path, hashes, permissions, IOCs, …).
    """
    action = (action or "").strip().lower().replace("-", "_")

    if action == "download":
        return _download(url, filename)

    resolved = _resolve_apk(apk)
    if isinstance(resolved, dict):
        return resolved
    path = resolved

    dispatch = {
        "triage": lambda: _triage(path),
        "manifest": lambda: _manifest(path),
        "iocs": lambda: _iocs(path),
        "natives": lambda: _natives(path),
        "report": lambda: _report(path),
    }
    if action not in dispatch:
        return {
            "ok": False,
            "error": (
                f"Unknown action '{action}'. Use one of: download, "
                + ", ".join(dispatch.keys())
            ),
        }
    return dispatch[action]()
