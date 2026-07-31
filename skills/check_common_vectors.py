from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode, urlparse

from websearch import skill_runtime as rt


def check_common_vectors(url: str, param: str = "id") -> dict[str, Any]:
    """
    Quick passive checks for common web vulnerabilities on a target URL.

    Tests SQL injection error leakage, reflected XSS, directory traversal, and
    missing security headers. Heuristic only — confirm findings manually.

    Args:
        url: Base URL to test (e.g. https://example.com/page).
        param: Primary query parameter name for injection tests.

    Returns:
        Dict with per-vector status, severity, and details.
    """
    try:
        base = rt.normalize_url(url)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    results: dict[str, Any] = {}
    parsed = urlparse(base)

    # --- SQL injection (error-based) ---
    sqli_payloads = [
        f"{param}=1'",
        f"{param}=1' OR '1'='1",
        f"{param}=1; SELECT 1--",
    ]
    sqli_hits: list[str] = []
    for payload in sqli_payloads:
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{payload}"
        try:
            resp = rt.http_request("GET", test_url, timeout=12.0)
            errors = rt.detect_sql_errors(resp.text)
            if errors:
                sqli_hits.append(f"{test_url} → {errors[0]}")
        except Exception:
            pass
    results["sql_injection"] = {
        "status": "likely" if sqli_hits else "not_detected",
        "severity": "high" if sqli_hits else "info",
        "details": sqli_hits or "No SQL error messages detected.",
    }

    # --- Reflected XSS ---
    xss = rt.test_xss_reflection(base, param=param)
    results["reflected_xss"] = {
        "status": "likely" if xss.get("vulnerable") else "not_detected",
        "severity": "high" if xss.get("vulnerable") else "info",
        "details": xss.get("findings", [])[:3] or xss.get("summary"),
    }

    # --- Directory traversal ---
    traversal_paths = [
        f"{base}/../../../../etc/passwd",
        f"{base}/..%2f..%2f..%2fetc/passwd",
        f"{base}/?{param}=../../../etc/passwd",
    ]
    traversal_hits: list[str] = []
    for turl in traversal_paths:
        try:
            resp = rt.http_request("GET", turl, timeout=12.0)
            if "root:" in resp.text and (":0:0:" in resp.text or "/bin/" in resp.text):
                traversal_hits.append(turl)
        except Exception:
            pass
    results["directory_traversal"] = {
        "status": "likely" if traversal_hits else "not_detected",
        "severity": "critical" if traversal_hits else "info",
        "details": traversal_hits or "No /etc/passwd content retrieved.",
    }

    # --- Security headers ---
    try:
        resp = rt.http_request("GET", base, timeout=12.0)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        missing = []
        for h in ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"):
            if h not in headers:
                missing.append(h)
        results["security_headers"] = {
            "status": "weak" if missing else "good",
            "severity": "medium" if len(missing) >= 3 else ("low" if missing else "info"),
            "present": {h: headers[h] for h in headers if h.startswith(("strict-", "content-", "x-", "referrer-", "permissions-"))},
            "missing": missing,
        }
    except Exception as exc:
        results["security_headers"] = {"status": "error", "details": str(exc)}

    likely = [k for k, v in results.items() if v.get("status") in ("likely", "weak", "critical")]
    return {
        "ok": True,
        "url": base,
        "vectors_tested": len(results),
        "findings": results,
        "summary": (
            f"Potential issues in: {', '.join(likely)}. Verify manually."
            if likely
            else "No obvious issues detected with heuristic checks."
        ),
    }
