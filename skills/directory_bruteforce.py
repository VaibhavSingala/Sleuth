import os
from concurrent.futures import ThreadPoolExecutor

import requests

# Built-in common paths so the skill works with no external file. The old
# version required a wordlist and defaulted to a Linux-only
# /usr/share/wordlists path, which fails on Windows and fresh installs.
_DEFAULT_WORDS = [
    "admin",
    "administrator",
    "login",
    "logout",
    "register",
    "signup",
    "signin",
    "dashboard",
    "account",
    "my-account",
    "profile",
    "user",
    "users",
    "api",
    "api/v1",
    "api/v2",
    "graphql",
    "swagger",
    "swagger-ui",
    "openapi.json",
    "robots.txt",
    "sitemap.xml",
    "security.txt",
    ".well-known/security.txt",
    ".git/config",
    ".env",
    "config",
    "config.php",
    "configuration",
    "backup",
    "backups",
    "old",
    "tmp",
    "temp",
    "test",
    "dev",
    "uploads",
    "upload",
    "files",
    "download",
    "downloads",
    "images",
    "img",
    "assets",
    "static",
    "private",
    "secret",
    "hidden",
    "server-status",
    "phpinfo.php",
    "info.php",
    "status",
    "health",
    "metrics",
    "wp-admin",
    "wp-login.php",
    "wp-content",
    "xmlrpc.php",
    "cgi-bin",
    "console",
    "debug",
    "logs",
    "log",
    "error_log",
    "db",
    "database",
    "sql",
    "dump",
    "data",
    "feed",
    "rss",
    "cart",
    "checkout",
    "order",
    "orders",
    "product",
    "products",
    "category",
    "search",
    "contact",
    "about",
    "help",
    "support",
    "faq",
    "news",
    "blog",
    "post",
    "auth",
    "oauth",
    "token",
    "session",
    "settings",
    "setup",
    "install",
    "update",
    "upgrade",
    "maintenance",
    "portal",
    "internal",
    "intranet",
    "staff",
    "index.php",
    "index.html",
    "home",
    "main",
    "default",
    "report",
    "reports",
    "export",
    "invoice",
    "billing",
    "payment",
    "payments",
]

# Status codes worth surfacing: exists, redirect, or protected (often interesting).
_INTERESTING = {200, 204, 301, 302, 307, 308, 401, 403, 405}


def directory_bruteforce(url: str, wordlist_path: str = "", timeout: int = 5) -> dict:
    """Dictionary brute-force of common paths on a URL (authorised targets only).

    Uses a built-in common-paths list by default; pass wordlist_path to use your
    own newline-delimited file. Paths returning 200/redirect/401/403 are surfaced.

    Args:
        url: Base URL to scan (e.g. "https://example.com").
        wordlist_path: Optional path to a custom wordlist file.
        timeout: Per-request timeout in seconds.

    Returns:
        dict with the 'found' paths (path, url, status), counts, and the wordlist
        used -- or an {"error": ...} dict.
    """
    if os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return {
            "ok": False,
            "error": "Skill 'directory_bruteforce' is disabled. "
            "Set SLEUTH_ALLOW_ACTIVE_SKILLS=true for authorised targets only.",
            "found": [],
            "total_tested": 0,
        }

    words: list[str] | None = None
    if wordlist_path:
        try:
            with open(wordlist_path, encoding="utf-8", errors="ignore") as fh:
                words = [ln.strip() for ln in fh if ln.strip()]
        except OSError as exc:
            return {
                "error": f"could not read wordlist '{wordlist_path}': {exc}",
                "hint": "omit wordlist_path to use the built-in common-paths list",
                "found": [],
                "total_tested": 0,
            }
    if not words:
        words = _DEFAULT_WORDS

    base = url.rstrip("/")

    def _probe(word: str) -> dict | None:
        path = word.lstrip("/")
        target = f"{base}/{path}"
        try:
            resp = requests.get(target, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            return None
        if resp.status_code in _INTERESTING:
            entry = {"path": "/" + path, "url": target, "status": resp.status_code}
            loc = resp.headers.get("location")
            if loc:
                entry["redirects_to"] = loc
            return entry
        return None

    found: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(30, len(words))) as pool:
        for result in pool.map(_probe, words):
            if result is not None:
                found.append(result)
    found.sort(key=lambda e: (e["status"], e["path"]))

    return {
        "target": base,
        "wordlist": wordlist_path or "built-in common paths",
        "total_tested": len(words),
        "found_count": len(found),
        "found": found,
        "note": (
            "Statuses: 200/204 exists, 301/302/307/308 redirect, 401/403 protected "
            "(often the most interesting), 405 method-not-allowed."
            if found
            else "No interesting paths found among those tested."
        ),
    }
