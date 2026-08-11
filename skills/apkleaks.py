"""Scan an APK for hardcoded secrets with APKLeaks (dwisiswant0/apkleaks).

Defensive secret/URI/key hunting only. Complements apk_analyze (structure /
permissions / IOCs) — use apkleaks when you need pattern-based secret extraction
from decompiled sources. Never use findings to attack third-party systems.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

_SKILLS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SKILLS_DIR.parent
_APKS_DIR = _PROJECT_ROOT / "apks"
_OUT_DIR = _APKS_DIR / "apkleaks_out"

_DEFAULT_TIMEOUT = float(os.environ.get("SLEUTH_APKLEAKS_TIMEOUT", "600"))


def _allowed_roots() -> list[Path]:
    roots = [_PROJECT_ROOT.resolve(), _APKS_DIR.resolve()]
    for extra in (Path("/app"), Path("/app/apks")):
        try:
            roots.append(extra.resolve())
        except OSError:
            pass
    seen: set[Path] = set()
    out: list[Path] = []
    for r in roots:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _resolve_apk(apk: str) -> Path | dict[str, Any]:
    raw = (apk or "").strip()
    if not raw:
        return {"ok": False, "error": "apk path is required."}

    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
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
            "error": (
                f"Refused: '{resolved}' is outside allowed roots "
                f"(project / apks). Copy the sample into apks/."
            ),
        }
    return resolved


def _find_apkleaks() -> list[str] | None:
    """Return argv prefix to invoke apkleaks, or None if missing."""
    exe = shutil.which("apkleaks")
    if exe:
        return [exe]
    # python -m apkleaks (package layout varies by version)
    try:
        import apkleaks  # noqa: F401
    except ImportError:
        return None
    return [os.environ.get("PYTHON", "python"), "-m", "apkleaks"]


def _safe_stem(name: str) -> str:
    base = Path(name).stem or "sample"
    return re.sub(r"[^\w.\-]+", "_", base).strip("._")[:120] or "sample"


def _parse_output(path: Path, as_json: bool) -> Any:
    text = path.read_text(encoding="utf-8", errors="replace")
    if as_json:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text, "parse_error": "output was not valid JSON"}
    return text


def apkleaks(
    apk: str,
    json_output: bool = True,
    pattern_file: str = "",
    jadx_args: str = "",
    timeout_sec: float = 0,
) -> dict[str, Any]:
    """
    Run APKLeaks against an Android APK to find hardcoded secrets, keys, and URIs.

    Typical flow:
      1. apk_analyze(action="download", url="…") or drop a file under apks/
      2. apkleaks(apk="/app/apks/app.apk")
      3. Cross-check interesting hits with apk_analyze(action="iocs", …)

    Requires the ``apkleaks`` package (and jadx on PATH, or let APKLeaks fetch it).
    Defensive analysis only — do not use discovered credentials against systems
    you do not own / are not authorized to test.

    Args:
        apk: Path to the .apk (under project/apks, or relative to apks/).
        json_output: If True (default), request JSON results for structured parsing.
        pattern_file: Optional path to a custom APKLeaks patterns JSON.
        jadx_args: Optional extra args passed to jadx via ``-a`` (e.g. "--deobf").
        timeout_sec: Kill the scan after N seconds (default SLEUTH_APKLEAKS_TIMEOUT
            or 600). Pass 0 to use the default.

    Returns:
        Dict with ok, findings (parsed JSON or text), output_path, and command meta.
    """
    resolved = _resolve_apk(apk)
    if isinstance(resolved, dict):
        return resolved
    path = resolved

    argv0 = _find_apkleaks()
    if not argv0:
        return {
            "ok": False,
            "error": "apkleaks is not installed.",
            "hint": "pip install apkleaks  (rebuild Docker image after updating requirements.txt).",
            "skipped": True,
        }

    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    stem = _safe_stem(path.name)
    out_name = f"{stem}.apkleaks.json" if json_output else f"{stem}.apkleaks.txt"
    out_path = (_OUT_DIR / out_name).resolve()
    if not _is_under(out_path, _OUT_DIR.resolve()):
        return {"ok": False, "error": "refused unsafe output path"}

    cmd = list(argv0) + ["-f", str(path), "-o", str(out_path)]
    if json_output:
        cmd.append("--json")

    if pattern_file:
        pf = Path(pattern_file).expanduser()
        if not pf.is_absolute():
            pf = (_PROJECT_ROOT / pattern_file).resolve()
        else:
            pf = pf.resolve()
        if not pf.is_file():
            return {"ok": False, "error": f"pattern_file not found: {pattern_file}"}
        if not any(_is_under(pf, root) for root in _allowed_roots()):
            return {"ok": False, "error": "pattern_file outside allowed roots"}
        cmd.extend(["-p", str(pf)])

    if jadx_args and jadx_args.strip():
        cmd.extend(["-a", jadx_args.strip()])

    timeout = timeout_sec if timeout_sec and timeout_sec > 0 else _DEFAULT_TIMEOUT

    # APKLeaks may write temp decompile dirs under CWD / tempfile; isolate CWD.
    with tempfile.TemporaryDirectory(prefix="sleuth-apkleaks-") as tmp:
        try:
            proc = subprocess.run(
                cmd,
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "error": f"apkleaks timed out after {timeout}s",
                "apk": str(path),
                "hint": "Raise SLEUTH_APKLEAKS_TIMEOUT or timeout_sec for large APKs.",
            }
        except FileNotFoundError as exc:
            return {"ok": False, "error": f"failed to spawn apkleaks: {exc}"}

    stderr_tail = (proc.stderr or "")[-4000:]
    stdout_tail = (proc.stdout or "")[-2000:]

    if not out_path.is_file():
        return {
            "ok": False,
            "error": "apkleaks finished but produced no output file",
            "returncode": proc.returncode,
            "stderr_tail": stderr_tail,
            "stdout_tail": stdout_tail,
            "command": cmd,
            "hint": (
                "Ensure jadx is available (APKLeaks can download it on first run). "
                "Heavily obfuscated APKs may fail decompilation."
            ),
        }

    findings = _parse_output(out_path, json_output)

    # Summarize for the model when JSON is a list/dict of pattern hits
    summary: dict[str, Any] = {}
    if isinstance(findings, dict):
        summary["keys"] = sorted(findings.keys())[:40]
        summary["key_count"] = len(findings)
    elif isinstance(findings, list):
        summary["item_count"] = len(findings)
    elif isinstance(findings, str):
        summary["chars"] = len(findings)
        summary["line_count"] = findings.count("\n") + (1 if findings else 0)

    return {
        "ok": proc.returncode == 0 or bool(findings),
        "apk": str(path),
        "output_path": str(out_path),
        "returncode": proc.returncode,
        "json": json_output,
        "summary": summary,
        "findings": findings,
        "stderr_tail": stderr_tail if proc.returncode != 0 else "",
        "notes": [
            "Static secret scan via jadx decompile + regex patterns.",
            "Expect false positives — verify before reporting.",
            "Do not use discovered keys/endpoints to attack systems.",
            "For structure/permissions use apk_analyze; for device install use apk_device.",
        ],
    }
