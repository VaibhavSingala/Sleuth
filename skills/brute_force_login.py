from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from websearch import skill_runtime as rt


def brute_force_login(
    url: str,
    username: str,
    password: str,
    login_path: str = "/login",
    username_field: str = "username",
    password_field: str = "password",
    success_indicators: str = "",
    failure_indicators: str = "",
) -> dict[str, Any]:
    """
    Attempt a single login against a web form and analyse the response.

    Only use on systems you own or are explicitly authorised to test.

    Args:
        url: Base URL of the target (e.g. https://example.com).
        username: Username to try.
        password: Password to try.
        login_path: Login endpoint path (default /login).
        username_field: Form field name for the username.
        password_field: Form field name for the password.
        success_indicators: Comma-separated strings that indicate success in the body.
        failure_indicators: Comma-separated strings that indicate failure in the body.

    Returns:
        Dict with status (success, failure, ambiguous), HTTP details, and clues.
    """
    try:
        base = rt.normalize_url(url)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    endpoint = urljoin(base + "/", login_path.lstrip("/"))
    payload = {username_field: username, password_field: password}

    success_kw = [s.strip() for s in success_indicators.split(",") if s.strip()] or [
        "welcome", "dashboard", "logout", "sign out", "my account",
    ]
    failure_kw = [s.strip() for s in failure_indicators.split(",") if s.strip()] or [
        "invalid", "incorrect", "failed", "wrong password", "bad credentials",
        "authentication failed", "login failed",
    ]

    try:
        resp = rt.http_request("POST", endpoint, data=payload, timeout=15.0, allow_redirects=True)
        body_lower = resp.text.lower()
        final_url = str(resp.url)

        # Redirect away from login page often means success
        if resp.history and "login" not in final_url.lower():
            status = "success"
            reason = f"Redirected to {final_url} after login POST."
        elif any(kw.lower() in body_lower for kw in success_kw) and not any(
            kw.lower() in body_lower for kw in failure_kw
        ):
            status = "success"
            reason = "Success indicator found in response body."
        elif any(kw.lower() in body_lower for kw in failure_kw):
            status = "failure"
            reason = "Failure indicator found in response body."
        elif resp.status_code in (401, 403):
            status = "failure"
            reason = f"HTTP {resp.status_code} returned."
        elif "set-cookie" in {k.lower() for k in resp.headers} and resp.status_code in (200, 302):
            status = "ambiguous"
            reason = "Session cookie set but no clear success/failure text — verify manually."
        else:
            status = "ambiguous"
            reason = f"HTTP {resp.status_code}; no clear success/failure indicators."

        return {
            "ok": True,
            "status": status,
            "reason": reason,
            "endpoint": endpoint,
            "username": username,
            "http_status": resp.status_code,
            "final_url": final_url,
            "response_length": len(resp.text),
            "cookies_set": bool(resp.cookies),
        }
    except Exception as exc:
        return {"ok": False, "endpoint": endpoint, "error": str(exc)}
