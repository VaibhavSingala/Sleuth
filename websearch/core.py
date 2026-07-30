"""High-level tool functions.

These return Markdown strings rather than JSON: small local models follow a
numbered, prose-shaped result list far more reliably than nested JSON, and it
makes citing sources natural.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from . import config
from .backends import SearchError, search
from .backends import news_search as _news_backend
from .fetch import FetchError, fetch_page

_TIMELIMITS = {
    "day": "d",
    "past_day": "d",
    "week": "w",
    "past_week": "w",
    "month": "m",
    "past_month": "m",
    "year": "y",
    "past_year": "y",
    "d": "d",
    "w": "w",
    "m": "m",
    "y": "y",
}


def _normalise_recency(recency: str | None) -> str | None:
    if not recency:
        return None
    return _TIMELIMITS.get(str(recency).strip().lower())


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


async def web_search(
    query: str,
    max_results: int = 5,
    recency: str | None = None,
) -> str:
    """Search the web and return a numbered list of results."""
    try:
        results = await search(
            query, max_results=max_results, timelimit=_normalise_recency(recency)
        )
    except SearchError as exc:
        return f"Search failed: {exc}"

    if not results:
        return f'No results found for "{query}". Try different or broader keywords.'

    lines = [
        f'Search results for "{query}" '
        f"(via {config.active_backend()}, retrieved {_today()}):",
        "",
    ]
    for i, result in enumerate(results, start=1):
        lines.append(f"{i}. {result.title or '(untitled)'}")
        lines.append(f"   URL: {result.url}")
        if result.published:
            lines.append(f"   Published: {result.published}")
        if result.snippet:
            lines.append(f"   {result.snippet}")
        lines.append("")

    lines.append(
        "These are snippets only. Use read_url on a result's URL to read the full page."
    )
    return "\n".join(lines)


async def news_search(
    query: str,
    max_results: int = 6,
    recency: str | None = None,
) -> str:
    """Search recent news and return a numbered list, newest signals first."""
    try:
        results = await _news_backend(
            query, max_results=max_results, timelimit=_normalise_recency(recency)
        )
    except SearchError as exc:
        return f"News search failed: {exc}"

    if not results:
        return f'No recent news found for "{query}".'

    lines = [f'News for "{query}" (via {config.active_backend()}, {_today()}):', ""]
    for i, result in enumerate(results, start=1):
        lines.append(f"{i}. {result.title or '(untitled)'}")
        source = result.extra.get("source") if result.extra else ""
        meta = " — ".join(p for p in (source, result.published) if p)
        if meta:
            lines.append(f"   {meta}")
        lines.append(f"   URL: {result.url}")
        if result.snippet:
            lines.append(f"   {result.snippet}")
        lines.append("")

    lines.append("Use read_url on any URL to read the full article.")
    return "\n".join(lines)


async def read_url(url: str, max_chars: int | None = None) -> str:
    """Fetch a single page and return its main text."""
    try:
        page = await fetch_page(url, max_chars=max_chars)
    except FetchError as exc:
        return f"Could not read page: {exc}"

    header = [f"# {page.title}" if page.title else "# (untitled page)", f"Source: {page.final_url}"]
    if page.final_url != page.url:
        header.append(f"(redirected from {page.url})")
    header.append("")
    body = page.text
    if page.truncated:
        body += "\n\n[...truncated. Ask for a larger max_chars to read further.]"
    return "\n".join(header) + body


async def research(
    query: str,
    max_pages: int | None = None,
    recency: str | None = None,
) -> str:
    """Search, then open the top pages and return their content in one pass.

    This is the tool to reach for when a question needs actual page content.
    It saves a small model from having to chain search -> read -> read itself,
    which is where most local-model tool loops fall apart.
    """
    max_pages = max(1, min(max_pages or config.RESEARCH_PAGES, 8))

    try:
        results = await search(
            query,
            max_results=max_pages + 3,  # spares, in case some pages fail to load
            timelimit=_normalise_recency(recency),
        )
    except SearchError as exc:
        return f"Search failed: {exc}"

    if not results:
        return f'No results found for "{query}". Try different or broader keywords.'

    async def _read(result):
        try:
            return result, await fetch_page(
                result.url, max_chars=config.RESEARCH_CHARS_PER_PAGE
            )
        except FetchError as exc:
            return result, exc

    pages = await asyncio.gather(*(_read(r) for r in results[: max_pages + 3]))

    sections: list[str] = []
    failures: list[str] = []
    for result, outcome in pages:
        if len(sections) >= max_pages:
            break
        if isinstance(outcome, Exception):
            failures.append(f"- {result.url} ({outcome})")
            continue
        index = len(sections) + 1
        sections.append(
            f"## Source [{index}]: {outcome.title or result.title or '(untitled)'}\n"
            f"URL: {outcome.final_url}\n\n"
            f"{outcome.text}"
            + ("\n\n[...page truncated]" if outcome.truncated else "")
        )

    if not sections:
        listing = "\n".join(f"- {r.title}: {r.url}" for r in results[:5])
        return (
            f'Found results for "{query}" but none of the pages could be read '
            f"(they may require JavaScript or block automated access):\n{listing}"
        )

    out = [
        f'Research digest for "{query}" — {len(sections)} sources read on {_today()} '
        f"(via {config.active_backend()}).",
        "",
        "\n\n---\n\n".join(sections),
        "",
        "---",
        "Answer using only the sources above, and cite them as [1], [2], etc.",
    ]
    if failures:
        out.append("\nPages that could not be read:\n" + "\n".join(failures))
    return "\n".join(out)
