"""Drive OWASP ZAP's JSON API: spider, active scan, read alerts.

ZAP runs as a daemon that is both a proxy and an API on one port (default
8090). Passive scanning of proxied traffic is automatic and free; the active
scanner sends attack payloads, so it is gated behind ZAP_ALLOW_ACTIVE_SCAN
and only ever scans the URL it is given.

    zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.key=YOURKEY
"""

from __future__ import annotations

import asyncio
import logging

import httpx

from .. import config

log = logging.getLogger(__name__)

_RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}


class ZapError(RuntimeError):
    """Raised for ZAP gating, connectivity or API errors."""


def _check_active_allowed() -> None:
    if not config.ZAP_ALLOW_ACTIVE_SCAN:
        raise ZapError(
            "Active scanning is disabled. Set ZAP_ALLOW_ACTIVE_SCAN=true to enable "
            "it, and only ever scan targets you own or are authorised to test."
        )


def _connect_hint(exc: Exception) -> str:
    return (
        f"ZAP API not reachable at {config.ZAP_API_URL} ({type(exc).__name__}). "
        "Start ZAP in daemon mode (zap.sh -daemon -port 8090 -config api.key=KEY) "
        "and set ZAP_API_URL / ZAP_API_KEY."
    )


async def _api(client: httpx.AsyncClient, path: str, **params) -> dict:
    """GET {ZAP_API_URL}/JSON/{path}/ with the API key. Returns parsed JSON."""
    if config.ZAP_API_KEY:
        params["apikey"] = config.ZAP_API_KEY
    resp = await client.get(f"{config.ZAP_API_URL}/JSON/{path}/", params=params)
    if resp.status_code != 200:
        raise ZapError(
            f"ZAP API {path} returned HTTP {resp.status_code}: {resp.text[:160]}")
    return resp.json()


async def version() -> str:
    """Return ZAP's version, or raise ZapError if unreachable (a health check)."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            data = await _api(client, "core/view/version")
    except httpx.HTTPError as exc:
        raise ZapError(_connect_hint(exc)) from exc
    return str(data.get("version", "unknown"))


async def _poll(client: httpx.AsyncClient, view: str, scan_id: str,
                timeout: float, interval: float) -> bool:
    """Poll a spider/ascan status view until 100% or timeout. True if complete."""
    waited = 0.0
    while True:
        data = await _api(client, view, scanId=scan_id)
        if str(data.get("status", "0")) == "100":
            return True
        if waited >= timeout:
            return False
        await asyncio.sleep(interval)
        waited += interval


def _summarise_alerts(baseurl: str, alerts: list) -> str:
    grouped: dict = {}
    for alert in alerts:
        name = alert.get("alert") or alert.get("name") or "(unnamed)"
        risk = (alert.get("risk") or "Informational").split(
            " ")[0].capitalize()
        key = (name, risk)
        entry = grouped.setdefault(
            key, {"urls": set(), "solution": alert.get("solution", "")})
        loc = alert.get("url", "")
        if alert.get("param"):
            loc += f" [{alert['param']}]"
        if loc:
            entry["urls"].add(loc)

    items = sorted(grouped.items(), key=lambda kv: (
        _RISK_ORDER.get(kv[0][1], 9), kv[0][0]))
    counts: dict = {}
    for (_n, risk), e in grouped.items():
        counts[risk] = counts.get(risk, 0) + max(1, len(e["urls"]))

    lines = [
        f"# ZAP alerts — {baseurl}",
        "**By risk:** " + (", ".join(f"{r} {counts[r]}" for r in
                                     ("High", "Medium", "Low", "Informational") if counts.get(r)) or "none"),
        f"\n{len(items)} distinct alert types.",
    ]
    current = None
    for (name, risk), e in items:
        if risk != current:
            current = risk
            lines.append(f"\n## {risk}")
        lines.append(f"\n### {name}")
        for url in sorted(e["urls"])[:8]:
            lines.append(f"- `{url}`")
        if len(e["urls"]) > 8:
            lines.append(f"- …{len(e['urls']) - 8} more")
    lines.append(
        "\n---\nZAP findings; confirm each before acting (scanners report false positives).")
    return "\n".join(lines)


async def alerts(url: str) -> str:
    """Read alerts ZAP has collected for a base URL (passive + active). Ungated."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            data = await _api(client, "core/view/alerts", baseurl=url, start="0", count="999")
    except ZapError as exc:
        return f"Could not read alerts: {exc}"
    except httpx.HTTPError as exc:
        return f"Could not read alerts: {_connect_hint(exc)}"
    found = data.get("alerts", [])
    if not found:
        return (f"No ZAP alerts for {url} yet. Proxy some traffic through ZAP "
                "(passive) or run an active scan first.")
    return _summarise_alerts(url, found)


async def scan_url(url: str, wait: bool = True, timeout: float = 300.0,
                   poll_interval: float = 5.0) -> str:
    """Spider then actively scan ``url``, then summarise alerts. Gated."""
    try:
        _check_active_allowed()
    except ZapError as exc:
        return f"Scan not started: {exc}"

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            # 1. Access the URL so it's in ZAP's site tree -- the active scanner
            #    refuses URLs it hasn't seen ("URL Not Found in the Scan Tree").
            try:
                await _api(client, "core/action/accessUrl", url=url, followRedirects="true")
            except ZapError as exc:
                return (f"ZAP could not reach {url} to seed the scan ({exc}). "
                        "Check the target is reachable from the ZAP container.")

            # 2. Spider to discover more pages. When waiting, let it finish
            #    (bounded) before active scanning so the tree is populated.
            spider = await _api(client, "spider/action/scan", url=url, recurse="true")
            spider_id = str(spider.get("scan", "0"))
            log.info("ZAP spider %s started for %s", spider_id, url)
            if wait:
                await _poll(client, "spider/view/status", spider_id,
                            timeout=min(timeout, 120), interval=poll_interval)

            # 3. Active scan -- the tree now has the target.
            ascan = await _api(client, "ascan/action/scan", url=url, recurse="true")
            ascan_id = str(ascan.get("scan", "0"))
            log.info("ZAP active scan %s started for %s", ascan_id, url)

            if not wait:
                return (f"Started ZAP spider {spider_id} and active scan {ascan_id} of {url}. "
                        f"Check with zap_scan_status (scan id {ascan_id}).")

            done = await _poll(client, "ascan/view/status", ascan_id, timeout, poll_interval)
            summary = await alerts(url)
            if not done:
                summary += (f"\n\n_Active scan {ascan_id} still running after {int(timeout)}s; "
                            f"re-check with that id for more._")
            return summary
    except ZapError as exc:
        return f"Scan failed: {exc}"
    except httpx.HTTPError as exc:
        return f"Scan failed: {_connect_hint(exc)}"


async def scan_status(scan_id: str, url: str = "") -> str:
    """Report an active scan's progress and any alerts so far."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            data = await _api(client, "ascan/view/status", scanId=scan_id)
            pct = data.get("status", "?")
            out = f"ZAP active scan {scan_id}: {pct}% complete."
            if url:
                out += "\n\n" + await alerts(url)
            return out
    except ZapError as exc:
        return f"Could not get scan status: {exc}"
    except httpx.HTTPError as exc:
        return f"Could not get scan status: {_connect_hint(exc)}"
