"""Search backends.

All backends normalise to a list of :class:`SearchResult`. DuckDuckGo is the
default because it needs no API key; Brave, Tavily and a self-hosted SearXNG
are supported for better rate limits and result quality.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass, field

import httpx

from . import cache, config

log = logging.getLogger(__name__)


class SearchError(RuntimeError):
    """Raised when a backend cannot produce results."""


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str = ""
    published: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


def _clean(value: object) -> str:
    return " ".join(str(value or "").split())


# --- DuckDuckGo -----------------------------------------------------------


def _ddg_sync(
    query: str, max_results: int, region: str, timelimit: str | None, news: bool = False
):
    from ddgs import DDGS  # imported lazily so the other backends work without it

    kwargs: dict = {"max_results": max_results}
    if region:
        kwargs["region"] = region
    if timelimit:
        kwargs["timelimit"] = timelimit
    ddgs = DDGS()
    return ddgs.news(query, **kwargs) if news else ddgs.text(query, **kwargs)


async def _duckduckgo(
    query: str, max_results: int, region: str, timelimit: str | None, news: bool = False
) -> list[SearchResult]:
    try:
        raw = await asyncio.to_thread(
            _ddg_sync, query, max_results, region, timelimit, news
        )
    except Exception as exc:  # ddgs raises its own exception hierarchy
        raise SearchError(f"DuckDuckGo {'news' if news else 'search'} failed: {exc}") from exc

    return [
        SearchResult(
            title=_clean(item.get("title")),
            url=_clean(item.get("href") or item.get("url")),
            snippet=_clean(item.get("body") or item.get("description") or item.get("excerpt")),
            published=_clean(item.get("date") or item.get("published")),
            extra={"source": _clean(item.get("source"))} if item.get("source") else {},
        )
        for item in raw
        if item.get("href") or item.get("url")
    ]


# --- SearXNG (self-hosted, no key) ----------------------------------------


async def _searxng(
    query: str, max_results: int, region: str, timelimit: str | None
) -> list[SearchResult]:
    if not config.SEARXNG_URL:
        raise SearchError("SEARXNG_URL is not set.")
    params: dict = {"q": query, "format": "json", "language": "en"}
    if timelimit:
        params["time_range"] = {"d": "day", "w": "week", "m": "month", "y": "year"}.get(
            timelimit, ""
        )
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
        resp = await client.get(
            f"{config.SEARXNG_URL}/search",
            params=params,
            headers={"User-Agent": config.USER_AGENT},
        )
        resp.raise_for_status()
        payload = resp.json()

    return [
        SearchResult(
            title=_clean(item.get("title")),
            url=_clean(item.get("url")),
            snippet=_clean(item.get("content")),
            published=_clean(item.get("publishedDate")),
        )
        for item in payload.get("results", [])[:max_results]
        if item.get("url")
    ]


# --- Brave Search API -----------------------------------------------------


async def _brave(
    query: str, max_results: int, region: str, timelimit: str | None
) -> list[SearchResult]:
    if not config.BRAVE_API_KEY:
        raise SearchError("BRAVE_API_KEY is not set.")
    params: dict = {"q": query, "count": min(max_results, 20)}
    if timelimit in ("d", "w", "m", "y"):
        params["freshness"] = {"d": "pd", "w": "pw", "m": "pm", "y": "py"}[timelimit]
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
        resp = await client.get(
            "https://api.search.brave.com/res/v1/web/search",
            params=params,
            headers={
                "Accept": "application/json",
                "X-Subscription-Token": config.BRAVE_API_KEY,
            },
        )
        resp.raise_for_status()
        payload = resp.json()

    return [
        SearchResult(
            title=_clean(item.get("title")),
            url=_clean(item.get("url")),
            snippet=_clean(item.get("description")),
            published=_clean(item.get("age")),
        )
        for item in payload.get("web", {}).get("results", [])[:max_results]
        if item.get("url")
    ]


# --- Tavily (search API built for LLMs) -----------------------------------


async def _tavily(
    query: str, max_results: int, region: str, timelimit: str | None
) -> list[SearchResult]:
    if not config.TAVILY_API_KEY:
        raise SearchError("TAVILY_API_KEY is not set.")
    body: dict = {
        "api_key": config.TAVILY_API_KEY,
        "query": query,
        "max_results": min(max_results, 20),
        "search_depth": "basic",
    }
    if timelimit in ("d", "w", "m", "y"):
        body["days"] = {"d": 1, "w": 7, "m": 30, "y": 365}[timelimit]
    async with httpx.AsyncClient(timeout=config.HTTP_TIMEOUT) as client:
        resp = await client.post("https://api.tavily.com/search", json=body)
        resp.raise_for_status()
        payload = resp.json()

    return [
        SearchResult(
            title=_clean(item.get("title")),
            url=_clean(item.get("url")),
            snippet=_clean(item.get("content")),
        )
        for item in payload.get("results", [])[:max_results]
        if item.get("url")
    ]


_BACKENDS = {
    "duckduckgo": _duckduckgo,
    "ddg": _duckduckgo,
    "searxng": _searxng,
    "brave": _brave,
    "tavily": _tavily,
}


async def search(
    query: str,
    max_results: int | None = None,
    region: str | None = None,
    timelimit: str | None = None,
    backend: str | None = None,
) -> list[SearchResult]:
    """Run a search and return normalised results.

    ``timelimit`` accepts ``d``/``w``/``m``/``y`` to restrict results to the
    past day/week/month/year. Falls back to DuckDuckGo if the configured
    backend errors out.
    """
    query = query.strip()
    if not query:
        raise SearchError("Empty query.")

    name = (backend or config.active_backend()).lower()
    max_results = min(max_results or config.MAX_RESULTS, config.RESULTS_HARD_CAP)
    region = region or config.DEFAULT_REGION

    cache_key = f"{name}|{query}|{max_results}|{region}|{timelimit}"
    if (hit := cache.get("search", cache_key)) is not None:
        return [SearchResult(**item) for item in hit]

    fn = _BACKENDS.get(name)
    if fn is None:
        raise SearchError(
            f"Unknown backend '{name}'. Choose one of: {', '.join(sorted(set(_BACKENDS)))}"
        )

    try:
        results = await fn(query, max_results, region, timelimit)
    except SearchError:
        raise
    except Exception as exc:
        if name == "duckduckgo":
            raise SearchError(f"Search failed: {exc}") from exc
        log.warning("Backend %s failed (%s); falling back to DuckDuckGo.", name, exc)
        results = await _duckduckgo(query, max_results, region, timelimit)

    cache.set("search", cache_key, [r.as_dict() for r in results])
    return results


async def news_search(
    query: str,
    max_results: int | None = None,
    region: str | None = None,
    timelimit: str | None = None,
    backend: str | None = None,
) -> list[SearchResult]:
    """Search recent news.

    DuckDuckGo returns true news-typed results (with source and date). The
    keyed backends have no news endpoint here, so they fall back to a regular
    search biased to the past week.
    """
    query = query.strip()
    if not query:
        raise SearchError("Empty query.")

    name = (backend or config.active_backend()).lower()
    max_results = min(max_results or config.MAX_RESULTS, config.RESULTS_HARD_CAP)
    region = region or config.DEFAULT_REGION

    cache_key = f"news|{name}|{query}|{max_results}|{region}|{timelimit}"
    if (hit := cache.get("search", cache_key)) is not None:
        return [SearchResult(**item) for item in hit]

    try:
        if name in ("duckduckgo", "ddg"):
            results = await _duckduckgo(query, max_results, region, timelimit, news=True)
        else:
            results = await search(
                query, max_results, region, timelimit or "w", backend=name
            )
    except SearchError:
        if name in ("duckduckgo", "ddg"):
            raise
        log.warning("News via %s failed; falling back to DuckDuckGo news.", name)
        results = await _duckduckgo(query, max_results, region, timelimit, news=True)

    cache.set("search", cache_key, [r.as_dict() for r in results])
    return results
