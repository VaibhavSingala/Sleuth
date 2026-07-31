from __future__ import annotations

from typing import Any

from websearch import skill_runtime as rt


def check_xss_reflection(
    url: str,
    payload: str = "",
    param: str = "",
) -> dict[str, Any]:
    """
    Test a URL for reflected Cross-Site Scripting (XSS).

    Injects the given payload (or built-in safe probes) and reports whether
    it is reflected in the response, with context and severity.

    Args:
        url: Target URL to test.
        payload: XSS payload. Uses built-in safe probes if omitted.
        param: Query parameter to inject into. Tests common names if omitted.

    Returns:
        Dict with vulnerability status, findings, and remediation hints.
    """
    result = rt.test_xss_reflection(url=url, payload=payload, param=param)
    if not result.get("ok"):
        return result

    result["recommendation"] = (
        "Reflected XSS likely — encode all user input in HTML context and set "
        "Content-Security-Policy. Verify manually; automated probes produce false positives."
        if result.get("vulnerable")
        else "No reflection detected with tested payloads. Try other parameters or POST body fields."
    )
    return result
