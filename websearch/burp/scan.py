"""Drive Burp Suite Professional's REST API: start scans, read results.

The REST API is Pro-only and off by default (enable it in Burp under
Settings -> Suite -> REST API). Starting a scan is active vulnerability
testing, so it is gated behind config.BURP_ALLOW_ACTIVE_SCAN and only ever
scans the URLs it is given.
"""

from __future__ import annotations

import asyncio
import logging
import os

import httpx

from .. import config

log = logging.getLogger(__name__)

_TERMINAL = {"succeeded", "failed", "paused"}


class BurpScanError(RuntimeError):
    """Raised for scan gating, connectivity or API errors."""


def _api_base() -> str:
    base = config.BURP_API_URL
    return f"{base}/{config.BURP_API_KEY}" if config.BURP_API_KEY else base


def _check_active_allowed() -> None:
    if not config.BURP_ALLOW_ACTIVE_SCAN:
        raise BurpScanError(
            "Active scanning is disabled. Set BURP_ALLOW_ACTIVE_SCAN=true to enable "
            "it, and only ever scan targets you own or are authorised to test."
        )


def _connect_hint(exc: Exception) -> str:
    hint = (
        f"Burp REST API not reachable at {config.BURP_API_URL} ({type(exc).__name__}). "
        "The REST API needs Burp Suite PROFESSIONAL, enabled under Settings -> Suite "
        "-> REST API. Without Burp Pro, use zap_scan or wapiti_scan instead (both free)."
    )
    if os.environ.get("SLEUTH_IN_DOCKER") and (
        "127.0.0.1" in config.BURP_API_URL or "localhost" in config.BURP_API_URL
    ):
        hint += (" Also: in Docker, 127.0.0.1 is the container, not your host — set "
                 "BURP_API_URL=http://host.docker.internal:1337 to reach host Burp.")
    return hint


async def start_scan(urls: list[str], config_name: str | None = None) -> str:
    """Start an active scan of ``urls``. Returns the Burp task id.

    Gated: raises BurpScanError unless active scanning is explicitly enabled.
    """
    _check_active_allowed()
    if isinstance(urls, str):
        urls = [urls]
    urls = [u for u in urls if u.strip()]
    if not urls:
        raise BurpScanError("No URLs to scan.")

    body: dict = {"urls": urls}
    name = config_name or config.BURP_SCAN_CONFIG
    if name:
        body["scan_configurations"] = [{"type": "NamedConfiguration", "name": name}]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{_api_base()}/v0.1/scan", json=body)
    except httpx.HTTPError as exc:
        raise BurpScanError(_connect_hint(exc)) from exc

    if resp.status_code not in (200, 201):
        raise BurpScanError(f"Burp refused the scan (HTTP {resp.status_code}): {resp.text[:200]}")

    # Task id comes back in the Location header, e.g. ".../v0.1/scan/3".
    location = resp.headers.get("location") or resp.headers.get("Location") or ""
    task_id = location.rstrip("/").rsplit("/", 1)[-1]
    if not task_id:
        try:
            task_id = str(resp.json().get("task_id", ""))
        except ValueError:
            task_id = ""
    if not task_id:
        raise BurpScanError("Scan started but Burp returned no task id.")
    return task_id


async def _fetch_status(client: httpx.AsyncClient, task_id: str) -> dict:
    resp = await client.get(f"{_api_base()}/v0.1/scan/{task_id}")
    if resp.status_code == 404:
        raise BurpScanError(f"No Burp scan with task id {task_id}.")
    if resp.status_code != 200:
        raise BurpScanError(f"Burp returned HTTP {resp.status_code} for task {task_id}.")
    return resp.json()


def _summarise(task_id: str, data: dict) -> str:
    status = data.get("scan_status", "unknown")
    metrics = data.get("scan_metrics", {}) or {}
    issues = [e.get("issue", {}) for e in data.get("issue_events", []) if e.get("issue")]

    by_sev: dict = {}
    for issue in issues:
        by_sev.setdefault(issue.get("severity", "unknown"), []).append(issue)

    lines = [
        f"# Burp scan {task_id} — {status}",
        f"- Crawl requests: {metrics.get('crawl_requests_made', '?')}",
        f"- Audit requests: {metrics.get('audit_requests_made', '?')}",
        f"- Issues found: {len(issues)}",
    ]
    for sev in ("high", "medium", "low", "info", "information"):
        group = by_sev.get(sev) or by_sev.get(sev.capitalize())
        if not group:
            continue
        lines.append(f"\n## {sev.capitalize()} ({len(group)})")
        for issue in group[:20]:
            where = issue.get("origin", "") + issue.get("path", "")
            lines.append(f"- {issue.get('name', '(unnamed)')} — `{where}`"
                         f"  [{issue.get('confidence', '?')}]")
    if status not in _TERMINAL:
        lines.append(f"\n_Scan still running. Check again with the task id: {task_id}._")
    return "\n".join(lines)


async def scan_status(task_id: str) -> str:
    """Return a Markdown summary of a scan's current status and issues."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            data = await _fetch_status(client, task_id)
    except BurpScanError as exc:
        return f"Could not get scan status: {exc}"
    except httpx.HTTPError as exc:
        return f"Could not get scan status: {_connect_hint(exc)}"
    return _summarise(task_id, data)


async def scan_url(url: str, wait: bool = True) -> str:
    """Tool-facing helper: scan one URL, optionally waiting for it to finish."""
    if wait:
        return await scan_and_wait([url])
    try:
        task_id = await start_scan([url])
    except BurpScanError as exc:
        return f"Scan not started: {exc}"
    return f"Started Burp scan of {url}; task id {task_id}. Check with burp_scan_status."


async def scan_and_wait(
    urls: list[str],
    config_name: str | None = None,
    timeout: float = 300.0,
    poll_interval: float = 10.0,
) -> str:
    """Start a scan and poll until it finishes or ``timeout`` elapses."""
    try:
        task_id = await start_scan(urls, config_name=config_name)
    except BurpScanError as exc:
        return f"Scan not started: {exc}"

    log.info("Burp scan %s started for %s", task_id, urls)
    waited = 0.0
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                data = await _fetch_status(client, task_id)
                if data.get("scan_status") in _TERMINAL:
                    return _summarise(task_id, data)
                if waited >= timeout:
                    return (
                        _summarise(task_id, data)
                        + f"\n\n_Stopped waiting after {int(timeout)}s; the scan is still "
                        f"running. Re-check later with task id {task_id}._"
                    )
                await asyncio.sleep(poll_interval)
                waited += poll_interval
    except BurpScanError as exc:
        return f"Scan {task_id} started but status polling failed: {exc}"
    except httpx.HTTPError as exc:
        return f"Scan {task_id} started but status polling failed: {_connect_hint(exc)}"
