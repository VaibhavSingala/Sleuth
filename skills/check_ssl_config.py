from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from websearch import skill_runtime as rt


def check_ssl_config(url: str) -> dict[str, Any]:
    """
    Analyse SSL/TLS configuration for a URL: certificate, protocol, cipher,
    HSTS header, and expiry.

    Args:
        url: HTTPS URL or hostname (e.g. https://example.com).

    Returns:
        Dict with TLS details, security assessment, and recommendations.
    """
    try:
        target = rt.normalize_url(url)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    parsed = urlparse(target)
    hostname = parsed.hostname
    if not hostname:
        return {"ok": False, "error": f"Could not parse hostname from {target}"}

    port = parsed.port or (443 if parsed.scheme == "https" else 443)
    result: dict[str, Any] = {"ok": True, "url": target, "hostname": hostname, "issues": [], "recommendations": []}

    # TLS handshake inspection
    tls = rt.inspect_ssl(hostname, port=port)
    result["tls"] = tls

    if not tls.get("ok"):
        result["issues"].append(f"TLS handshake failed: {tls.get('error')}")
        result["recommendations"].append("Ensure the server supports HTTPS on port 443.")
    else:
        proto = tls.get("protocol", "")
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            result["issues"].append(f"Weak protocol negotiated: {proto}")
            result["recommendations"].append("Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2+.")
        if tls.get("expired"):
            result["issues"].append("Certificate has expired.")
        elif tls.get("days_until_expiry") is not None and tls["days_until_expiry"] < 30:
            result["issues"].append(f"Certificate expires in {tls['days_until_expiry']} days.")

    # HTTP security headers (HSTS etc.)
    try:
        resp = rt.http_request("GET", target, timeout=12.0)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        result["http_status"] = resp.status_code
        result["final_url"] = str(resp.url)

        if not str(resp.url).startswith("https://"):
            result["issues"].append("Final URL is not HTTPS — traffic may be downgraded.")
            result["recommendations"].append("Enforce HTTPS redirects and HSTS.")

        hsts = headers.get("strict-transport-security")
        result["hsts"] = hsts
        if not hsts:
            result["issues"].append("HSTS header missing.")
            result["recommendations"].append("Add Strict-Transport-Security with max-age >= 31536000.")

        for hdr in ("content-security-policy", "x-content-type-options", "x-frame-options"):
            result.setdefault("security_headers", {})[hdr] = headers.get(hdr)

        missing = [h for h in ("content-security-policy", "x-content-type-options", "x-frame-options") if h not in headers]
        if missing:
            result["issues"].append(f"Missing headers: {', '.join(missing)}")
    except Exception as exc:
        result["issues"].append(f"HTTP header check failed: {exc}")

    result["grade"] = (
        "A" if not result["issues"]
        else "B" if len(result["issues"]) <= 1
        else "C" if len(result["issues"]) <= 3
        else "D"
    )
    result["summary"] = (
        f"SSL grade {result['grade']}: {len(result['issues'])} issue(s) found."
        if result["issues"]
        else f"SSL grade A: TLS {tls.get('protocol', 'unknown')}, certificate valid."
    )
    return result
