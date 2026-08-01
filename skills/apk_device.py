"""Drive a host Android emulator/device over ADB for dynamic APK ops.

Sleuth stays in Docker; the emulator runs on the HOST. Point ADB at the host
server (default host.docker.internal:5037). Isolated analysis AVDs only —
never install untrusted samples on a personal phone.

Host setup (once):
  adb kill-server
  adb -a nodaemon server start          # listen on all interfaces
  # start Android Studio AVD / Genymotion / physical device with USB debugging
  adb devices

Then from Sleuth:
  apk_device(action="devices")
  apk_device(action="install", apk="/app/apks/sample.apk")
  apk_device(action="launch", package="com.example.app")
  apk_device(action="logcat", package="com.example.app", lines=200)
  apk_device(action="screenshot")
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Literal

_SKILLS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _SKILLS_DIR.parent
_APKS_DIR = _PROJECT_ROOT / "apks"
_OUT_DIR = _APKS_DIR / "device_out"

Action = Literal[
    "devices",
    "wait",
    "install",
    "uninstall",
    "launch",
    "force_stop",
    "clear_data",
    "package_info",
    "logcat",
    "screenshot",
    "shell",
    "pull",
    "push",
    "run_pipeline",
]

_ADB_HOST = os.environ.get("SLEUTH_ADB_HOST", "host.docker.internal").strip() or "host.docker.internal"
_ADB_PORT = os.environ.get("SLEUTH_ADB_PORT", "5037").strip() or "5037"
_DEFAULT_TIMEOUT = float(os.environ.get("SLEUTH_ADB_TIMEOUT", "90"))


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


def _resolve_path(raw: str, *, must_exist: bool = True) -> Path | dict[str, Any]:
    raw = (raw or "").strip()
    if not raw:
        return {"ok": False, "error": "path is required."}
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        for base in (_APKS_DIR, _PROJECT_ROOT, Path("/app/apks"), Path("/app")):
            trial = (base / raw).resolve()
            if trial.exists() or not must_exist:
                candidate = trial
                if trial.exists() or not must_exist:
                    break
        else:
            candidate = (_APKS_DIR / raw).resolve()
    else:
        candidate = candidate.resolve()

    if must_exist and not candidate.exists():
        return {"ok": False, "error": f"not found: {raw}"}
    if not any(_is_under(candidate.resolve(), root) for root in _allowed_roots()):
        return {
            "ok": False,
            "error": f"Refused: path outside project/apks: {candidate}",
        }
    return candidate.resolve()


def _find_adb() -> str | None:
    return shutil.which("adb")


def _adb_base(serial: str = "") -> list[str]:
    adb = _find_adb()
    if not adb:
        raise FileNotFoundError(
            "adb not found in PATH. Install android-tools-adb in the image "
            "(rebuild Docker) or on the host."
        )
    cmd = [adb, "-H", _ADB_HOST, "-P", _ADB_PORT]
    if serial.strip():
        cmd += ["-s", serial.strip()]
    return cmd


def _run_adb(
    args: list[str],
    *,
    serial: str = "",
    timeout: float | None = None,
    text: bool = True,
) -> dict[str, Any]:
    limit = _DEFAULT_TIMEOUT if timeout is None else timeout
    try:
        cmd = _adb_base(serial) + args
    except FileNotFoundError as exc:
        return {"ok": False, "error": str(exc)}

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=text,
            timeout=limit,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": f"adb timed out after {limit:.0f}s: {' '.join(args)}",
            "adb_host": f"{_ADB_HOST}:{_ADB_PORT}",
        }
    except OSError as exc:
        return {"ok": False, "error": f"adb spawn failed: {exc}"}

    stdout = proc.stdout if text else proc.stdout
    stderr = proc.stderr if text else proc.stderr
    out: dict[str, Any] = {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "cmd": cmd,
        "adb_host": f"{_ADB_HOST}:{_ADB_PORT}",
    }
    if text:
        out["stdout"] = (stdout or "").strip()
        out["stderr"] = (stderr or "").strip()
        if proc.returncode != 0 and not out.get("error"):
            out["error"] = out["stderr"] or out["stdout"] or f"adb exit {proc.returncode}"
    else:
        out["stdout_bytes"] = len(stdout or b"")
        out["stderr"] = (stderr or b"").decode("utf-8", "replace").strip()
        out["_raw_stdout"] = stdout
        if proc.returncode != 0:
            out["error"] = out["stderr"] or f"adb exit {proc.returncode}"
    return out


def _devices(serial: str = "") -> dict[str, Any]:
    # `adb devices -l` ignores -s; list all
    res = _run_adb(["devices", "-l"], serial="", timeout=20)
    if not res.get("ok") and not res.get("stdout"):
        res["hint"] = (
            "Start the host ADB server listening on all interfaces, then boot an AVD:\n"
            "  adb kill-server && adb -a nodaemon server start\n"
            f"Container expects {_ADB_HOST}:{_ADB_PORT} (SLEUTH_ADB_HOST / SLEUTH_ADB_PORT)."
        )
        return res

    rows = []
    for line in (res.get("stdout") or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("list of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        rows.append({"serial": parts[0], "state": parts[1], "raw": line})
    online = [r for r in rows if r["state"] == "device"]
    return {
        "ok": True,
        "action": "devices",
        "adb_host": f"{_ADB_HOST}:{_ADB_PORT}",
        "devices": rows,
        "online": len(online),
        "hint": None if online else (
            "No online devices. Boot an Android emulator on the host and "
            "ensure adb server accepts remote clients (adb -a nodaemon server start)."
        ),
    }


def _wait(serial: str = "", timeout: float = 60) -> dict[str, Any]:
    res = _run_adb(["wait-for-device"], serial=serial, timeout=timeout)
    if not res.get("ok"):
        return {**res, "action": "wait"}
    # also wait for boot completed when possible
    boot = _run_adb(
        ["shell", "getprop", "sys.boot_completed"],
        serial=serial,
        timeout=30,
    )
    return {
        "ok": True,
        "action": "wait",
        "device_ready": True,
        "boot_completed": (boot.get("stdout") or "").strip(),
        "adb_host": res.get("adb_host"),
    }


def _package_from_apk(apk_path: Path) -> str | None:
    try:
        from androguard.core.apk import APK  # type: ignore
        import logging
        logging.getLogger("androguard").setLevel(logging.CRITICAL)
        return APK(str(apk_path)).get_package()
    except Exception:
        return None


def _install(apk: str, serial: str = "", replace: bool = True) -> dict[str, Any]:
    path = _resolve_path(apk)
    if isinstance(path, dict):
        return path
    args = ["install"]
    if replace:
        args.append("-r")
    args += ["-g", str(path)]  # -g grant permissions on modern Android
    res = _run_adb(args, serial=serial, timeout=max(_DEFAULT_TIMEOUT, 180))
    pkg = _package_from_apk(path)
    out = {
        "ok": res.get("ok") and "Success" in (res.get("stdout") or ""),
        "action": "install",
        "apk": str(path),
        "package": pkg,
        "stdout": res.get("stdout"),
        "stderr": res.get("stderr"),
        "adb_host": res.get("adb_host"),
    }
    if not out["ok"]:
        out["error"] = res.get("error") or res.get("stdout") or res.get("stderr") or "install failed"
        # -g may fail on older images; retry without grants
        if "-g" in args and res.get("returncode") not in (None, 0):
            retry = _run_adb(
                ["install", "-r", str(path)],
                serial=serial,
                timeout=max(_DEFAULT_TIMEOUT, 180),
            )
            if retry.get("ok") and "Success" in (retry.get("stdout") or ""):
                out.update({
                    "ok": True,
                    "stdout": retry.get("stdout"),
                    "stderr": retry.get("stderr"),
                    "error": None,
                    "note": "installed without -g (runtime permission grants)",
                })
    if out.get("ok") and pkg:
        out["hint"] = f"Launch with apk_device(action='launch', package='{pkg}')"
    return out


def _uninstall(package: str, serial: str = "") -> dict[str, Any]:
    package = (package or "").strip()
    if not package:
        return {"ok": False, "error": "package is required for uninstall."}
    res = _run_adb(["uninstall", package], serial=serial, timeout=60)
    ok = res.get("ok") and "Success" in ((res.get("stdout") or "") + (res.get("stderr") or ""))
    return {
        "ok": ok or res.get("ok"),
        "action": "uninstall",
        "package": package,
        "stdout": res.get("stdout"),
        "stderr": res.get("stderr"),
        "error": None if (ok or res.get("ok")) else res.get("error"),
        "adb_host": res.get("adb_host"),
    }


def _launch(package: str, activity: str = "", serial: str = "") -> dict[str, Any]:
    package = (package or "").strip()
    if not package:
        return {"ok": False, "error": "package is required for launch."}
    activity = (activity or "").strip()
    if activity:
        component = activity if "/" in activity else f"{package}/{activity}"
        res = _run_adb(
            ["shell", "am", "start", "-n", component],
            serial=serial,
            timeout=30,
        )
    else:
        # Monkey launcher — works without knowing the main activity
        res = _run_adb(
            [
                "shell", "monkey", "-p", package,
                "-c", "android.intent.category.LAUNCHER", "1",
            ],
            serial=serial,
            timeout=30,
        )
    ok = res.get("ok") and "Error" not in (res.get("stdout") or "") and "Error" not in (res.get("stderr") or "")
    return {
        "ok": ok,
        "action": "launch",
        "package": package,
        "activity": activity or None,
        "stdout": res.get("stdout"),
        "stderr": res.get("stderr"),
        "error": None if ok else (res.get("error") or res.get("stdout") or res.get("stderr")),
        "adb_host": res.get("adb_host"),
        "hint": "Emulator window is on the HOST desktop. Use screenshot to capture UI into apks/device_out/.",
    }


def _force_stop(package: str, serial: str = "") -> dict[str, Any]:
    package = (package or "").strip()
    if not package:
        return {"ok": False, "error": "package is required."}
    res = _run_adb(["shell", "am", "force-stop", package], serial=serial, timeout=20)
    return {
        "ok": bool(res.get("ok")),
        "action": "force_stop",
        "package": package,
        "stderr": res.get("stderr"),
        "error": res.get("error"),
        "adb_host": res.get("adb_host"),
    }


def _clear_data(package: str, serial: str = "") -> dict[str, Any]:
    package = (package or "").strip()
    if not package:
        return {"ok": False, "error": "package is required."}
    res = _run_adb(["shell", "pm", "clear", package], serial=serial, timeout=30)
    ok = res.get("ok") and "Success" in (res.get("stdout") or "")
    return {
        "ok": ok,
        "action": "clear_data",
        "package": package,
        "stdout": res.get("stdout"),
        "error": None if ok else res.get("error") or res.get("stdout"),
        "adb_host": res.get("adb_host"),
    }


def _package_info(package: str, serial: str = "") -> dict[str, Any]:
    package = (package or "").strip()
    if not package:
        return {"ok": False, "error": "package is required."}
    path = _run_adb(["shell", "pm", "path", package], serial=serial, timeout=20)
    dump = _run_adb(
        ["shell", "dumpsys", "package", package],
        serial=serial,
        timeout=40,
    )
    text = dump.get("stdout") or ""
    # Keep dump small for the model
    if len(text) > 6000:
        text = text[:6000] + "\n…[truncated]"
    return {
        "ok": bool(path.get("ok")),
        "action": "package_info",
        "package": package,
        "pm_path": path.get("stdout"),
        "dumpsys_preview": text,
        "error": path.get("error") if not path.get("ok") else None,
        "adb_host": path.get("adb_host"),
    }


def _logcat(
    package: str = "",
    lines: int = 200,
    serial: str = "",
    clear: bool = False,
) -> dict[str, Any]:
    lines = max(10, min(int(lines or 200), 2000))
    if clear:
        _run_adb(["logcat", "-c"], serial=serial, timeout=15)
    # Prefer filtered dump if package known: resolve PID
    args = ["logcat", "-d", "-t", str(lines)]
    res = _run_adb(args, serial=serial, timeout=40)
    text = res.get("stdout") or ""
    pkg = (package or "").strip()
    if pkg and text:
        # soft filter lines mentioning package
        filtered = [ln for ln in text.splitlines() if pkg in ln]
        if filtered:
            text = "\n".join(filtered[-lines:])
    if len(text) > 12000:
        text = text[-12000:]
    return {
        "ok": bool(res.get("ok")),
        "action": "logcat",
        "package_filter": pkg or None,
        "lines": lines,
        "log": text,
        "error": res.get("error"),
        "adb_host": res.get("adb_host"),
    }


def _screenshot(serial: str = "", filename: str = "") -> dict[str, Any]:
    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^\w.\-]+", "_", (filename or "").strip()) or f"screen_{int(time.time())}.png"
    if not name.lower().endswith(".png"):
        name += ".png"
    dest = (_OUT_DIR / name).resolve()
    if not _is_under(dest, _APKS_DIR.resolve()):
        return {"ok": False, "error": "refused unsafe filename"}

    remote = "/sdcard/sleuth_screenshot.png"
    cap = _run_adb(["shell", "screencap", "-p", remote], serial=serial, timeout=30)
    if not cap.get("ok"):
        # some images need stdout binary screencap
        raw = _run_adb(["exec-out", "screencap", "-p"], serial=serial, timeout=30, text=False)
        if not raw.get("ok"):
            return {
                "ok": False,
                "action": "screenshot",
                "error": cap.get("error") or raw.get("error") or "screencap failed",
                "adb_host": cap.get("adb_host"),
            }
        data = raw.get("_raw_stdout") or b""
        # exec-out sometimes inserts \r\n — fix common PNG corruption
        if data.startswith(b"\x89PNG"):
            pass
        else:
            data = data.replace(b"\r\n", b"\n")
        dest.write_bytes(data)
        return {
            "ok": True,
            "action": "screenshot",
            "path": str(dest),
            "size_bytes": dest.stat().st_size,
            "adb_host": raw.get("adb_host"),
        }

    pull = _run_adb(["pull", remote, str(dest)], serial=serial, timeout=30)
    _run_adb(["shell", "rm", "-f", remote], serial=serial, timeout=10)
    if not pull.get("ok") or not dest.is_file():
        return {
            "ok": False,
            "action": "screenshot",
            "error": pull.get("error") or "pull failed",
            "stdout": pull.get("stdout"),
            "adb_host": pull.get("adb_host"),
        }
    return {
        "ok": True,
        "action": "screenshot",
        "path": str(dest),
        "size_bytes": dest.stat().st_size,
        "adb_host": pull.get("adb_host"),
    }


def _shell(command: str, serial: str = "") -> dict[str, Any]:
    command = (command or "").strip()
    if not command:
        return {"ok": False, "error": "command is required for shell."}
    # Block obviously destructive host-level attempts; still allow device shell.
    res = _run_adb(["shell", command], serial=serial, timeout=_DEFAULT_TIMEOUT)
    out = (res.get("stdout") or "")
    if len(out) > 12000:
        out = out[:12000] + "\n…[truncated]"
    return {
        "ok": bool(res.get("ok")),
        "action": "shell",
        "command": command,
        "stdout": out,
        "stderr": res.get("stderr"),
        "error": res.get("error"),
        "adb_host": res.get("adb_host"),
    }


def _pull(remote: str, local: str = "", serial: str = "") -> dict[str, Any]:
    remote = (remote or "").strip()
    if not remote:
        return {"ok": False, "error": "remote path is required."}
    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    if local.strip():
        dest = _resolve_path(local, must_exist=False)
        if isinstance(dest, dict):
            return dest
    else:
        dest = _OUT_DIR / Path(remote).name
    res = _run_adb(["pull", remote, str(dest)], serial=serial, timeout=120)
    return {
        "ok": bool(res.get("ok")) and Path(dest).exists(),
        "action": "pull",
        "remote": remote,
        "local": str(dest),
        "stdout": res.get("stdout"),
        "error": res.get("error"),
        "adb_host": res.get("adb_host"),
    }


def _push(local: str, remote: str, serial: str = "") -> dict[str, Any]:
    remote = (remote or "").strip()
    if not remote:
        return {"ok": False, "error": "remote path is required."}
    path = _resolve_path(local)
    if isinstance(path, dict):
        return path
    res = _run_adb(["push", str(path), remote], serial=serial, timeout=120)
    return {
        "ok": bool(res.get("ok")),
        "action": "push",
        "local": str(path),
        "remote": remote,
        "stdout": res.get("stdout"),
        "error": res.get("error"),
        "adb_host": res.get("adb_host"),
    }


def _run_pipeline(
    apk: str,
    package: str = "",
    serial: str = "",
    log_lines: int = 150,
) -> dict[str, Any]:
    """wait → install → launch → brief pause → logcat → screenshot."""
    steps: list[dict[str, Any]] = []
    w = _wait(serial=serial, timeout=60)
    steps.append(w)
    if not w.get("ok"):
        return {"ok": False, "action": "run_pipeline", "steps": steps, "error": "device not ready"}

    inst = _install(apk, serial=serial)
    steps.append(inst)
    if not inst.get("ok"):
        return {"ok": False, "action": "run_pipeline", "steps": steps, "error": "install failed"}

    pkg = (package or "").strip() or inst.get("package") or ""
    if not pkg:
        return {
            "ok": False,
            "action": "run_pipeline",
            "steps": steps,
            "error": "package unknown — pass package= or ensure androguard can read the APK",
        }

    _run_adb(["logcat", "-c"], serial=serial, timeout=15)
    launch = _launch(pkg, serial=serial)
    steps.append(launch)
    time.sleep(3)
    logs = _logcat(package=pkg, lines=log_lines, serial=serial)
    steps.append(logs)
    shot = _screenshot(serial=serial)
    steps.append(shot)
    return {
        "ok": bool(launch.get("ok")),
        "action": "run_pipeline",
        "package": pkg,
        "apk": apk,
        "screenshot": shot.get("path"),
        "log_excerpt": (logs.get("log") or "")[:4000],
        "steps_ok": [bool(s.get("ok")) for s in steps],
        "hint": "Emulator GUI is on the host. Review screenshot under apks/device_out/.",
    }


def apk_device(
    action: str,
    apk: str = "",
    package: str = "",
    activity: str = "",
    serial: str = "",
    command: str = "",
    remote: str = "",
    local: str = "",
    filename: str = "",
    lines: int = 200,
    clear: bool = False,
    timeout: float = 0,
) -> dict[str, Any]:
    """
    Control a host Android emulator/device over ADB (install, launch, logcat, screenshot).

    The emulator runs on your HOST desktop; this skill only sends ADB commands.
    Use an isolated analysis AVD — do not install untrusted APKs on a personal phone.

    Args:
        action: devices, wait, install, uninstall, launch, force_stop, clear_data,
            package_info, logcat, screenshot, shell, pull, push, run_pipeline.
        apk: Path under apks/ for install / run_pipeline.
        package: Android package name (com.example.app).
        activity: Optional activity class for launch (or package/activity).
        serial: Optional adb device serial when several are connected.
        command: Device shell command (action=shell).
        remote / local: Paths for pull/push.
        filename: Screenshot filename under apks/device_out/.
        lines: logcat line count (default 200).
        clear: If true, clear logcat before dump.
        timeout: Unused placeholder for future per-call overrides.

    Returns:
        Dict with ok and action-specific fields. screenshots land in apks/device_out/.
    """
    action = (action or "").strip().lower().replace("-", "_")
    _ = timeout  # reserved

    if action == "devices":
        return _devices(serial)
    if action == "wait":
        return _wait(serial=serial)
    if action == "install":
        return _install(apk, serial=serial)
    if action == "uninstall":
        return _uninstall(package, serial=serial)
    if action == "launch":
        return _launch(package, activity=activity, serial=serial)
    if action == "force_stop":
        return _force_stop(package, serial=serial)
    if action == "clear_data":
        return _clear_data(package, serial=serial)
    if action == "package_info":
        return _package_info(package, serial=serial)
    if action == "logcat":
        return _logcat(package=package, lines=lines, serial=serial, clear=clear)
    if action == "screenshot":
        return _screenshot(serial=serial, filename=filename)
    if action == "shell":
        return _shell(command, serial=serial)
    if action == "pull":
        return _pull(remote, local=local, serial=serial)
    if action == "push":
        return _push(local, remote, serial=serial)
    if action == "run_pipeline":
        return _run_pipeline(apk, package=package, serial=serial, log_lines=lines or 150)

    return {
        "ok": False,
        "error": (
            f"Unknown action '{action}'. Use one of: devices, wait, install, uninstall, "
            "launch, force_stop, clear_data, package_info, logcat, screenshot, shell, "
            "pull, push, run_pipeline."
        ),
    }
