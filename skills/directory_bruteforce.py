from __future__ import annotations

from typing import Any

from websearch import skill_runtime as rt


def directory_bruteforce(
    url: str,
    wordlist_path: str = "",
    max_words: int = 100,
    timeout: float = 5.0,
    status_codes: str = "200,301,302,403",
) -> dict[str, Any]:
    """
    Brute-force discover hidden directories and files on a web server.

    Uses a built-in common-path wordlist when no file is provided. Only test
    targets you own or are authorised to scan.

    Args:
        url: Base URL to scan (e.g. https://example.com).
        wordlist_path: Optional path to a wordlist file (one path per line).
        max_words: Maximum paths to test (default 100, cap 2000).
        timeout: Per-request timeout in seconds.
        status_codes: Comma-separated HTTP codes to treat as findings.

    Returns:
        Dict with found_paths, redirects, and scan statistics.
    """
    try:
        base = rt.normalize_url(url)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    max_words = max(1, min(int(max_words), 2000))
    accept_codes = {int(c.strip()) for c in status_codes.split(",") if c.strip().isdigit()}

    try:
        words = rt.load_wordlist(wordlist_path, max_words=max_words)
    except FileNotFoundError as exc:
        return {"ok": False, "error": str(exc), "found_paths": [], "total_tested": 0}

    found: list[dict[str, Any]] = []
    redirects: list[dict[str, Any]] = []
    errors = 0
    baseline_len: int | None = None

    # Grab baseline 404 length to filter soft-404 false positives
    try:
        baseline = rt.http_request("GET", f"{base}/__sleuth_nonexistent_{hash(base) % 99999}__", timeout=timeout)
        baseline_len = len(baseline.text)
    except Exception:
        pass

    for word in words:
        target = f"{base}/{word.lstrip('/')}"
        try:
            resp = rt.http_request("HEAD", target, timeout=timeout, allow_redirects=False)
            code = resp.status_code

            # Fall back to GET if HEAD is not allowed
            if code in (405, 501):
                resp = rt.http_request("GET", target, timeout=timeout, allow_redirects=False)
                code = resp.status_code

            if code in accept_codes:
                body_len = len(resp.text) if code != 301 else 0
                # Skip soft-404s: same size as baseline error page
                if baseline_len and code == 200 and abs(body_len - baseline_len) < 50:
                    continue
                entry = {"url": target, "status_code": code, "content_length": body_len}
                if 300 <= code < 400:
                    entry["location"] = resp.headers.get("location", "")
                    redirects.append(entry)
                else:
                    found.append(entry)
        except Exception:
            errors += 1

    return {
        "ok": True,
        "base_url": base,
        "total_tested": len(words),
        "found_count": len(found),
        "redirect_count": len(redirects),
        "error_count": errors,
        "found_paths": found,
        "redirects": redirects,
        "wordlist_source": wordlist_path or "built-in",
    }
