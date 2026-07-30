"""Run the Wapiti scanner as a subprocess and summarise its JSON report.

Wapiti is invoked through its Python module (not the console script, which may
not be on PATH) so it works regardless of how pip installed it.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import os
import sys
import tempfile

from .. import config

log = logging.getLogger(__name__)

# Runs wapiti's entry point with our args as argv (python -c can't take argv
# directly, so we splice it from sys.argv[1:]).
_RUNNER = (
    "import sys; from wapitiCore.main.wapiti import wapiti_asyncio_wrapper as w; "
    "sys.argv = ['wapiti'] + sys.argv[1:]; w()"
)

# Wapiti criticity level -> label.
_LEVELS = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Info"}


class WapitiError(RuntimeError):
    """Raised for gating or execution errors."""


def _available() -> bool:
    return importlib.util.find_spec("wapitiCore") is not None


def _check_active_allowed() -> None:
    if not config.WAPITI_ALLOW_ACTIVE_SCAN:
        raise WapitiError(
            "Active scanning is disabled. Set WAPITI_ALLOW_ACTIVE_SCAN=true to enable "
            "it, and only ever scan targets you own or are authorised to test."
        )


def _summarise(data: dict, target: str, timed_out: bool) -> str:
    vulns = {cat: items for cat, items in data.get("vulnerabilities", {}).items() if items}
    infos = data.get("infos", {})

    def _cat_level(items: list) -> int:
        return max((i.get("level", 1) for i in items), default=1)

    ordered = sorted(vulns.items(), key=lambda kv: (-_cat_level(kv[1]), kv[0]))
    total = sum(len(v) for v in vulns.values())

    lines = [
        f"# Wapiti scan — {target}",
        f"- Pages crawled: {infos.get('crawled_pages_nbr', '?')}  ·  "
        f"scope: {infos.get('scope', '?')}  ·  {infos.get('version', 'wapiti')}",
        f"- {total} finding(s) across {len(vulns)} categories."
        if vulns else "- No vulnerabilities reported.",
    ]
    for cat, items in ordered:
        level = _LEVELS.get(_cat_level(items), f"level {_cat_level(items)}")
        lines.append(f"\n## {cat}  ({level}, {len(items)})")
        seen = set()
        shown = 0
        for it in items:
            loc = f"{it.get('method', 'GET')} {it.get('path', '')}"
            if it.get("parameter"):
                loc += f"  [{it['parameter']}]"
            if loc in seen:
                continue
            seen.add(loc)
            lines.append(f"- `{loc}`")
            if it.get("info"):
                lines.append(f"  {it['info'][:200]}")
            shown += 1
            if shown >= 8:
                lines.append(f"- …{len(items) - shown} more")
                break
    if timed_out:
        lines.append(f"\n_Scan hit the {config.WAPITI_MAX_SCAN_TIME}s time cap; "
                     "results may be partial. Raise WAPITI_MAX_SCAN_TIME for more._")
    lines.append("\n---\nWapiti findings; confirm each before acting (scanners report "
                 "false positives).")
    return "\n".join(lines)


async def scan_url(url: str, max_time: int | None = None) -> str:
    """Actively scan ``url`` with Wapiti and return a Markdown summary. Gated."""
    try:
        _check_active_allowed()
    except WapitiError as exc:
        return f"Scan not started: {exc}"
    if not _available():
        return "Wapiti is not installed. Run: pip install wapiti3"
    if not url.strip():
        return "No URL to scan."

    max_time = int(max_time or config.WAPITI_MAX_SCAN_TIME)
    fd, report = tempfile.mkstemp(suffix=".json", prefix="wapiti_")
    os.close(fd)
    cmd = [
        sys.executable, "-c", _RUNNER,
        "-u", url, "-f", "json", "-o", report,
        "--flush-session", "--scope", config.WAPITI_SCOPE,
        "--max-scan-time", str(max_time), "--verify-ssl", "0",
    ]
    if config.WAPITI_MODULES:
        cmd += ["-m", config.WAPITI_MODULES]

    timed_out = False
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=max_time + 90)
        except asyncio.TimeoutError:
            timed_out = True
            proc.kill()
            await proc.wait()
    except OSError as exc:
        return f"Could not run wapiti: {exc}"

    try:
        with open(report, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        if timed_out:
            return (f"Wapiti hit the {max_time}s cap before writing a report. "
                    "Raise WAPITI_MAX_SCAN_TIME or narrow WAPITI_SCOPE to page.")
        detail = (stderr.decode("utf-8", "replace")[-300:] if not timed_out and stderr else "")
        return f"Wapiti produced no report. {detail}".strip()
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass

    return _summarise(data, url, timed_out)
