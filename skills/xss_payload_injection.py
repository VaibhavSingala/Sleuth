from __future__ import annotations

from typing import Any

from websearch import skill_runtime as rt


def xss_payload_injection(
    url: str,
    payload: str = "",
    param: str = "",
    method: str = "GET",
) -> dict[str, Any]:
    """
    Test a URL for reflected XSS by injecting payloads into query parameters.

    Tries multiple common parameter names when ``param`` is omitted, and uses
    built-in probe payloads when ``payload`` is omitted.

    Args:
        url: Target base URL (e.g. https://example.com/search).
        payload: XSS payload to inject. Uses safe default probes if empty.
        param: Specific query parameter to test. Tests common names if empty.
        method: HTTP method — GET or POST.

    Returns:
        Dict with findings per parameter, reflection context, and severity.
    """
    return rt.test_xss_reflection(url=url, payload=payload, param=param, method=method)
