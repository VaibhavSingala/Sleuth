from __future__ import annotations

from typing import Optional

from websearch import config, skill_runtime as rt


def webscrape(url: str, max_chars: Optional[int] = None) -> dict:
    """
    Fetch a URL and return its main text content using the project's read_url
    extractor (strips nav, ads, and boilerplate).

    Args:
        url: Full URL to fetch (e.g. https://example.com/page).
        max_chars: Maximum characters to return (defaults to project limit).

    Returns:
        Dict with url, content, char_count, and any error message.
    """
    try:
        target = rt.normalize_url(url)
        content = rt.read_page(target, max_chars=max_chars)
        limit = max_chars if max_chars is not None else config.MAX_PAGE_CHARS
        return {
            "ok": True,
            "url": target,
            "content": content,
            "char_count": len(content),
            "truncated": len(content) >= limit,
        }
    except Exception as exc:
        return {"ok": False, "url": url, "error": str(exc), "content": ""}
