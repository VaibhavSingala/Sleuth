from __future__ import annotations

from typing import Any

from websearch import skill_runtime as rt

_LOG_FILE = "attack_log.json"


def attack_log(
    url: str = "",
    scanner: str = "",
    findings: dict | None = None,
    action: str = "log",
    limit: int = 20,
) -> dict[str, Any]:
    """
    Persistent attack/scan result log across sessions.

    Args:
        url: Target URL (required for action=log).
        scanner: Scanner or skill name (e.g. zap_scan, wapiti_scan).
        findings: Result dict to store (required for action=log).
        action: log (default), list, search, or summary.
        limit: Max records to return for list/search.

    Returns:
        Dict with operation result and matching records.
    """
    action = (action or "log").strip().lower()

    if action == "log":
        if not url.strip() or not scanner.strip():
            return {"ok": False, "error": "url and scanner are required for action=log."}
        if findings is None:
            findings = {}

        records: list[dict] = rt.read_json(_LOG_FILE, default=[])
        for rec in records:
            if rec.get("url") == url and rec.get("scanner") == scanner:
                return {
                    "ok": False,
                    "duplicate": True,
                    "message": f"Entry already exists for {url} / {scanner}. Use action=list to view.",
                    "existing": rec,
                }

        entry = {
            "id": len(records) + 1,
            "timestamp": rt.utc_now(),
            "url": url.strip(),
            "scanner": scanner.strip(),
            "findings": findings,
        }
        records.append(entry)
        rt.write_json(_LOG_FILE, records)
        return {"ok": True, "logged": True, "entry": entry}

    records = rt.read_json(_LOG_FILE, default=[])

    if action == "list":
        return {
            "ok": True,
            "count": len(records),
            "records": records[-max(1, min(limit, 100)):],
        }

    if action == "search":
        needle = url.strip().lower()
        matches = [
            r for r in records
            if needle in r.get("url", "").lower() or needle in r.get("scanner", "").lower()
        ]
        return {"ok": True, "query": url, "count": len(matches), "records": matches[-limit:]}

    if action == "summary":
        by_scanner: dict[str, int] = {}
        by_url: dict[str, int] = {}
        for r in records:
            by_scanner[r.get("scanner", "unknown")] = by_scanner.get(r.get("scanner", "unknown"), 0) + 1
            by_url[r.get("url", "unknown")] = by_url.get(r.get("url", "unknown"), 0) + 1
        return {
            "ok": True,
            "total_records": len(records),
            "unique_urls": len(by_url),
            "by_scanner": dict(sorted(by_scanner.items(), key=lambda x: -x[1])),
            "recent": records[-5:],
        }

    return {"ok": False, "error": f"Unknown action '{action}'. Use log, list, search, or summary."}
