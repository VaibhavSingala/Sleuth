from __future__ import annotations

import os
from typing import Any

from websearch import skill_runtime as rt


def shodan(query: str, max_results: int = 10) -> dict[str, Any]:
    """
    Search the Shodan database for hosts matching a query (IPs, ports, banners).

    Requires SHODAN_API_KEY in the environment or .env file.

    Args:
        query: Shodan search query (e.g. 'apache country:US', or an IP).
        max_results: Maximum hosts to return (1-100).

    Returns:
        Dict with matches list, total count, and formatted summary.
    """
    api_key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not api_key:
        return {
            "ok": False,
            "error": (
                "SHODAN_API_KEY is not set. Add it to your .env file: "
                "SHODAN_API_KEY=your_key_here"
            ),
        }

    max_results = max(1, min(int(max_results), 100))
    url = "https://api.shodan.io/shodan/host/search"
    try:
        resp = rt.http_request(
            "GET",
            url,
            params={"key": api_key, "query": query, "page": 1},
            timeout=20.0,
        )
        if resp.status_code == 401:
            return {"ok": False, "error": "Invalid SHODAN_API_KEY (HTTP 401)."}
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"ok": False, "error": f"Shodan request failed: {exc}"}

    matches = data.get("matches", [])[:max_results]
    hosts = []
    for m in matches:
        host = {
            "ip": m.get("ip_str"),
            "port": m.get("port"),
            "org": m.get("org"),
            "os": m.get("os"),
            "hostnames": m.get("hostnames", []),
            "product": m.get("product"),
            "version": m.get("version"),
            "vulns": list(m.get("vulns", {}).keys()) if isinstance(m.get("vulns"), dict) else [],
        }
        hosts.append(host)

    return {
        "ok": True,
        "query": query,
        "total": data.get("total", len(hosts)),
        "returned": len(hosts),
        "hosts": hosts,
        "summary": _format_summary(query, hosts, data.get("total", 0)),
    }


def _format_summary(query: str, hosts: list, total: int) -> str:
    lines = [f'Shodan results for "{query}" ({len(hosts)} shown, {total} total):', ""]
    for i, h in enumerate(hosts, 1):
        name = h["hostnames"][0] if h["hostnames"] else h["ip"]
        product = f" — {h['product']}" if h.get("product") else ""
        vulns = f" [{len(h['vulns'])} CVEs]" if h.get("vulns") else ""
        lines.append(f"{i}. {name}:{h['port']}{product}{vulns}")
    return "\n".join(lines)
