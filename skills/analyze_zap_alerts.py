from __future__ import annotations

from typing import Any

from websearch import skill_runtime as rt

_RISK_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3, "Info": 4}


def analyze_zap_alerts(url: str) -> dict[str, Any]:
    """
    Fetch OWASP ZAP alerts for a URL and return a structured executive summary.

    Requires ZAP running in daemon mode (ZAP_API_URL / ZAP_API_KEY in .env).
    Passive alerts appear after proxying traffic; active scan alerts need zap_scan.

    Args:
        url: Base URL to check (e.g. https://example.com).

    Returns:
        Dict with alert counts by severity, top findings, and markdown report.
    """
    try:
        base = rt.normalize_url(url)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    zap = rt.fetch_zap_alerts(base)
    if not zap.get("ok"):
        return {"ok": False, "url": base, "error": zap.get("error"), "report": ""}

    alerts = zap.get("alerts", [])
    if not alerts:
        return {
            "ok": True,
            "url": base,
            "total": 0,
            "by_risk": {},
            "top_findings": [],
            "report": f"No ZAP alerts for {base}. Proxy traffic through ZAP or run an active scan first.",
        }

    by_risk: dict[str, list[dict[str, Any]]] = {}
    for alert in alerts:
        risk = (alert.get("risk") or alert.get("riskdesc", "Informational")).split()[0]
        risk = risk.capitalize()
        if risk == "Info":
            risk = "Informational"
        entry = {
            "name": alert.get("alert") or alert.get("name", "Unknown"),
            "url": alert.get("url", ""),
            "param": alert.get("param", ""),
            "confidence": alert.get("confidence", ""),
            "description": (alert.get("desc") or alert.get("description", ""))[:200],
            "solution": (alert.get("solution", ""))[:200],
            "cwe": alert.get("cweid", ""),
        }
        by_risk.setdefault(risk, []).append(entry)

    counts = {risk: len(items) for risk, items in by_risk.items()}
    sorted_risks = sorted(by_risk.items(), key=lambda kv: _RISK_ORDER.get(kv[0], 9))

    lines = [
        f"# ZAP Alert Analysis — {base}",
        "",
        f"**Total alerts:** {len(alerts)}",
        "**By risk:** " + ", ".join(f"{r}: {counts[r]}" for r in sorted(counts, key=lambda x: _RISK_ORDER.get(x, 9))),
        "",
    ]

    top_findings: list[dict[str, Any]] = []
    for risk, items in sorted_risks:
        lines.append(f"## {risk} ({len(items)})")
        for item in items[:10]:
            loc = item["url"]
            if item["param"]:
                loc += f" [{item['param']}]"
            lines.append(f"- **{item['name']}** — `{loc}`")
            if item["solution"]:
                lines.append(f"  - Fix: {item['solution']}")
            top_findings.append({**item, "risk": risk})
        if len(items) > 10:
            lines.append(f"- …and {len(items) - 10} more")
        lines.append("")

    lines.append("---")
    lines.append("Confirm each finding manually — scanners report false positives.")

    return {
        "ok": True,
        "url": base,
        "total": len(alerts),
        "by_risk": counts,
        "top_findings": top_findings[:20],
        "report": "\n".join(lines),
    }
