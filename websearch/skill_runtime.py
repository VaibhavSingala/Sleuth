"""Shared runtime helpers for authored skills in ``skills/``.

Skills are loaded as standalone modules, so they import from here instead of
relying on injected globals (``read_url``, ``ws``, etc.) that are not available
at runtime.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import httpx

from . import config

# Persistent skill data (attack logs, etc.) lives beside authored skills.
SKILLS_DATA_DIR = config.SKILLS_DIR / ".data"

# Common web paths used when no wordlist file is supplied.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "admin", "administrator", "login", "signin", "signup", "register",
    "dashboard", "api", "api/v1", "api/v2", "graphql", "swagger", "docs",
    "backup", "backups", "config", "configuration", ".env", ".git",
    ".git/HEAD", "wp-admin", "wp-login.php", "phpmyadmin", "server-status",
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "health",
    "status", "debug", "test", "staging", "dev", "console", "manager",
    "uploads", "assets", "static", "images", "js", "css", "vendor",
    "actuator", "actuator/health", ".aws/credentials", "crossdomain.xml",
)

# SQL error fragments that suggest injection success.
SQL_ERROR_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"SQL syntax.*MySQL",
        r"Warning.*\Wmysqli?_",
        r"PostgreSQL.*ERROR",
        r"Driver.* SQL[\s-]*Server",
        r"ORA-\d{5}",
        r"SQLite.*(syntax|error)",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
    )
)

# Default XSS probe payloads (safe — no exfiltration).
XSS_PROBE_PAYLOADS: tuple[str, ...] = (
    "<script>alert(1)</script>",
    '"><svg/onload=alert(1)>',
    "'-alert(1)-'",
    "<img src=x onerror=alert(1)>",
)

# Query-parameter names commonly reflected in search/forms.
COMMON_PARAM_NAMES: tuple[str, ...] = (
    "q", "query", "search", "s", "term", "keyword", "input", "name", "id",
    "page", "redirect", "url", "next", "return", "ref", "msg", "error",
)


def run_async(coro):
    """Run an async websearch coroutine from a synchronous skill."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Called from inside an active loop (unusual for skills) — isolate.
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def normalize_url(url: str, default_scheme: str = "https") -> str:
    """Ensure a URL has a scheme and no trailing slash issues for joining."""
    url = (url or "").strip()
    if not url:
        raise ValueError("URL is required.")
    if not url.startswith(("http://", "https://")):
        url = f"{default_scheme}://{url}"
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url.rstrip("/")


def _proxy_url() -> str | None:
    return config.BURP_PROXY or config.ZAP_PROXY or None


def http_client(timeout: float = 15.0) -> httpx.Client:
    """Sync HTTP client with project User-Agent and optional Burp/ZAP proxy."""
    proxy = _proxy_url()
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": config.USER_AGENT},
        proxy=proxy,
        verify=config.BURP_PROXY_VERIFY if proxy else True,
    )


def http_request(
    method: str,
    url: str,
    *,
    params: dict | None = None,
    data: dict | None = None,
    json_body: dict | None = None,
    headers: dict | None = None,
    timeout: float = 15.0,
    allow_redirects: bool = True,
) -> httpx.Response:
    """Perform a synchronous HTTP request with project defaults."""
    with http_client(timeout=timeout) as client:
        return client.request(
            method.upper(),
            url,
            params=params,
            data=data,
            json=json_body,
            headers=headers,
            follow_redirects=allow_redirects,
        )


def load_wordlist(wordlist_path: str = "", max_words: int = 500) -> list[str]:
    """Load paths from a file or fall back to the built-in wordlist."""
    words: list[str] = []
    if wordlist_path and wordlist_path.strip():
        path = Path(wordlist_path).expanduser()
        if path.is_file():
            words = [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip() and not ln.startswith("#")]
        else:
            raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")
    else:
        words = list(DEFAULT_WORDLIST)
    if max_words > 0:
        words = words[:max_words]
    return words


def data_path(name: str) -> Path:
    """Path for a persistent JSON data file under ``skills/.data/``."""
    SKILLS_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return SKILLS_DATA_DIR / name


def read_json(name: str, default: Any = None) -> Any:
    path = data_path(name)
    if not path.is_file():
        return default if default is not None else []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default if default is not None else []


def write_json(name: str, data: Any) -> None:
    path = data_path(name)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_sql_errors(text: str) -> list[str]:
    return [p.pattern for p in SQL_ERROR_PATTERNS if p.search(text)]


def detect_reflection(text: str, payload: str) -> dict[str, Any]:
    """Check how a payload appears in a response body."""
    if payload in text:
        return {"reflected": True, "context": "exact", "encoded": False}
    encoded = quote(payload, safe="")
    if encoded in text:
        return {"reflected": True, "context": "url_encoded", "encoded": True}
    # Partial reflection (tags stripped but inner text remains)
    stripped = re.sub(r"<[^>]+>", "", payload)
    if stripped and stripped in text and stripped != payload:
        return {"reflected": True, "context": "partial_tag_stripped", "encoded": False}
    return {"reflected": False, "context": None, "encoded": False}


def fetch_zap_alerts(url: str) -> dict[str, Any]:
    """Fetch structured ZAP alerts for a base URL (sync)."""
    base = normalize_url(url)
    params: dict[str, str] = {"baseurl": base, "start": "0", "count": "999"}
    if config.ZAP_API_KEY:
        params["apikey"] = config.ZAP_API_KEY
    api_url = f"{config.ZAP_API_URL}/JSON/core/view/alerts/"
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(api_url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"ZAP API unreachable at {config.ZAP_API_URL}: {exc}", "alerts": []}
    alerts = data.get("alerts", [])
    return {"ok": True, "url": base, "alerts": alerts, "count": len(alerts)}


def inspect_ssl(hostname: str, port: int = 443, timeout: float = 10.0) -> dict[str, Any]:
    """Inspect TLS certificate and negotiated protocol via the stdlib ssl module."""
    host = hostname.strip()
    if host.startswith("http"):
        host = urlparse(host).hostname or host
    result: dict[str, Any] = {"hostname": host, "port": port, "ok": False}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result.update({
                    "ok": True,
                    "protocol": ssock.version(),
                    "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [v for _t, v in cert.get("subjectAltName", ())],
                })
                # Expiry warning
                if cert.get("notAfter"):
                    try:
                        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expires - datetime.now(timezone.utc)).days
                        result["days_until_expiry"] = days_left
                        result["expired"] = days_left < 0
                    except ValueError:
                        pass
    except (socket.timeout, ssl.SSLError, OSError) as exc:
        result["error"] = str(exc)
    return result


def read_page(url: str, max_chars: int | None = None) -> str:
    """Fetch page text via the project's async ``read_url``."""
    from .core import read_url

    limit = max_chars if max_chars is not None else config.MAX_PAGE_CHARS
    return run_async(read_url(url, max_chars=limit))


def compare_sites_report(url_a: str, url_b: str, detail: str = "standard") -> str:
    """Run ``compare_sites`` from a sync skill context."""
    from .analyze import compare_sites

    return run_async(compare_sites(url_a, url_b, detail=detail))


def test_xss_reflection(
    url: str,
    payload: str = "",
    param: str = "",
    method: str = "GET",
) -> dict[str, Any]:
    """Test a URL for reflected XSS across common query parameters."""
    from urllib.parse import urlencode, urlparse

    try:
        base = normalize_url(url)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    payloads = [payload] if payload.strip() else list(XSS_PROBE_PAYLOADS)
    params_to_test = [param] if param.strip() else list(COMMON_PARAM_NAMES[:8])

    findings: list[dict[str, Any]] = []
    parsed = urlparse(base)

    for pname in params_to_test:
        for pload in payloads:
            try:
                if method.upper() == "POST":
                    resp = http_request("POST", base, data={pname: pload}, timeout=12.0)
                    test_url = f"{base} (POST {pname}=...)"
                else:
                    qs = urlencode({pname: pload})
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                    resp = http_request("GET", test_url, timeout=12.0)

                reflection = detect_reflection(resp.text, pload)
                if reflection["reflected"]:
                    sev = "high" if (
                        reflection.get("context") == "exact"
                        and ("<script" in pload.lower() or "onerror" in pload.lower())
                    ) else "medium"
                    findings.append({
                        "parameter": pname,
                        "method": method.upper(),
                        "payload": pload,
                        "test_url": test_url,
                        "status_code": resp.status_code,
                        "reflection": reflection,
                        "severity": sev,
                    })
            except Exception as exc:
                findings.append({"parameter": pname, "payload": pload, "error": str(exc)})

    vulnerable = [f for f in findings if f.get("severity") in ("high", "medium")]
    return {
        "ok": True,
        "url": base,
        "vulnerable": len(vulnerable) > 0,
        "findings_count": len(findings),
        "findings": findings,
        "summary": (
            f"Found {len(vulnerable)} reflected XSS indicator(s)."
            if vulnerable
            else "No reflected XSS indicators detected with tested payloads."
        ),
    }
