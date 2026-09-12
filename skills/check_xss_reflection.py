import os
from urllib.parse import urlencode, urlparse

import requests


def check_xss_reflection(url: str, payload: str = "<script>alert(1)</script>") -> dict:
    """Test a URL for reflected XSS by injecting a payload into common parameters.

    Injects the payload into several common query parameters and reports which, if
    any, reflect it unescaped in the response (a reflected-XSS indicator).

    Args:
        url: The target URL (e.g. "https://example.com/").
        payload: The XSS payload to inject (default: a simple script alert).

    Returns:
        dict listing the parameters tested, which reflected the payload, and an
        overall `vulnerable` flag, or an {"error": ...} dict.
    """
    if os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return {
            "ok": False,
            "error": "Skill 'check_xss_reflection' is disabled. "
            "Set SLEUTH_ALLOW_ACTIVE_SKILLS=true for authorised targets only.",
        }

    params = ["q", "search", "s", "query", "name", "id", "message", "comment"]
    reflected: list[dict] = []
    has_query = bool(urlparse(url).query)
    for name in params:
        sep = "&" if has_query else "?"
        test_url = f"{url}{sep}{urlencode({name: payload})}"
        try:
            resp = requests.get(test_url, timeout=10)
        except requests.RequestException as exc:
            return {"error": f"request to {url} failed: {exc}"}
        if payload in resp.text:
            reflected.append({"param": name, "status": resp.status_code, "url": test_url})

    return {
        "url": url,
        "payload": payload,
        "params_tested": params,
        "reflected": reflected,
        "vulnerable": bool(reflected),
        "note": (
            "Payload appears unescaped in the response; confirm execution in a browser."
            if reflected
            else "No reflection on the tested parameters; try other injection points or params."
        ),
    }
