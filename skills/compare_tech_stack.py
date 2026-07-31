from __future__ import annotations

from typing import Any

from websearch import skill_runtime as rt


def compare_tech_stack(url_a: str, url_b: str, detail: str = "standard") -> dict[str, Any]:
    """
    Compare two websites: technology stack, infrastructure, security headers,
    and keywords. Wraps the built-in compare_sites analyzer.

    Args:
        url_a: First site URL.
        url_b: Second site URL.
        detail: Report depth — summary, standard, or full.

    Returns:
        Dict with ok flag and markdown comparison report.
    """
    detail = detail if detail in ("summary", "standard", "full") else "standard"
    try:
        a = rt.normalize_url(url_a)
        b = rt.normalize_url(url_b)
        report = rt.compare_sites_report(a, b, detail=detail)
        return {"ok": True, "url_a": a, "url_b": b, "detail": detail, "report": report}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "url_a": url_a, "url_b": url_b}
