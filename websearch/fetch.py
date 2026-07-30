"""Fetch a URL and reduce it to readable text.

Uses trafilatura for main-content extraction when available (it strips nav,
ads and boilerplate far better than a naive tag walk) and falls back to
BeautifulSoup otherwise.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import logging
import socket
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from . import cache, config
from .intercept import active_proxy, proxy_enabled, proxy_kwargs

log = logging.getLogger(__name__)

try:  # optional, but strongly recommended
    import trafilatura

    _HAS_TRAFILATURA = True
except ImportError:  # pragma: no cover
    _HAS_TRAFILATURA = False

try:
    import pypdf

    _HAS_PYPDF = True
except ImportError:  # pragma: no cover
    _HAS_PYPDF = False


class FetchError(RuntimeError):
    """Raised when a page cannot be fetched or parsed."""


@dataclass
class Page:
    url: str
    final_url: str
    title: str
    text: str
    truncated: bool = False

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "title": self.title,
            "text": self.text,
            "truncated": self.truncated,
        }


def _assert_public_url(url: str) -> None:
    """Reject non-HTTP schemes and private/loopback hosts.

    A fetched page can contain text aimed at the model ("now open
    http://169.254.169.254/..."). This is the guard that keeps such a nudge
    from turning into a request against the local network.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise FetchError(f"Refusing non-HTTP URL scheme: {parsed.scheme or '(none)'}")
    if not parsed.hostname:
        raise FetchError("URL has no host.")
    if not config.BLOCK_PRIVATE_ADDRESSES:
        return
    if proxy_enabled():
        # Traffic goes to the Burp proxy, which does its own DNS and connection,
        # so resolving locally here reflects nothing about the real target and
        # would wrongly block testing a personal site on localhost/LAN through
        # Burp. The proxy (and the user who configured it) owns that decision.
        return

    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise FetchError(f"Could not resolve host '{parsed.hostname}': {exc}") from exc

    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
        ):
            raise FetchError(
                f"Refusing to fetch private/internal address {address} ({parsed.hostname}). "
                "Set WEBSEARCH_BLOCK_PRIVATE=false to allow this."
            )


def _extract_with_bs4(html: str) -> tuple[str, str]:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    title = soup.title.get_text(strip=True) if soup.title else ""
    for tag in soup(["script", "style", "noscript", "nav", "header", "footer", "aside", "form"]):
        tag.decompose()
    body = soup.body or soup
    lines = [line.strip() for line in body.get_text("\n").splitlines()]
    text = "\n".join(line for line in lines if line)
    return title, text


def _extract(html: str, url: str) -> tuple[str, str]:
    if _HAS_TRAFILATURA:
        try:
            text = trafilatura.extract(
                html,
                url=url,
                include_comments=False,
                include_tables=True,
                favor_precision=True,
            )
            metadata = trafilatura.extract_metadata(html)
            title = (metadata.title if metadata else "") or ""
            if text and text.strip():
                return title, text.strip()
        except Exception as exc:  # trafilatura chokes on some malformed pages
            log.debug("trafilatura failed on %s: %r", url, exc)
    return _extract_with_bs4(html)


def _extract_pdf(raw: bytes) -> tuple[str, str]:
    """(title, text) from PDF bytes. CPU-bound -- call via asyncio.to_thread."""
    if not _HAS_PYPDF:
        raise FetchError("PDF support needs pypdf: pip install pypdf")
    try:
        reader = pypdf.PdfReader(io.BytesIO(raw))
    except Exception as exc:
        raise FetchError(f"Could not parse PDF: {exc}") from exc

    if reader.is_encrypted:
        try:
            reader.decrypt("")  # many PDFs are "encrypted" with an empty owner password
        except Exception as exc:
            raise FetchError(f"PDF is password-protected: {exc}") from exc

    title = ""
    try:
        if reader.metadata and reader.metadata.title:
            title = str(reader.metadata.title).strip()
    except Exception:
        pass

    parts = []
    for page in reader.pages:
        try:
            chunk = page.extract_text() or ""
        except Exception:
            continue
        if chunk.strip():
            parts.append(chunk.strip())
    return title, "\n\n".join(parts)


# Cache parsed robots.txt per origin so a burst of fetches costs one request.
_robots_cache: dict = {}


async def _robots_allows(client: httpx.AsyncClient, url: str) -> bool:
    if not config.RESPECT_ROBOTS:
        return True
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    parser = _robots_cache.get(origin)
    if parser is None:
        parser = urllib.robotparser.RobotFileParser()
        try:
            resp = await client.get(urljoin(origin, "/robots.txt"), timeout=8.0)
            parser.parse(resp.text.splitlines() if resp.status_code < 400 else [])
        except httpx.HTTPError:
            parser.parse([])  # unreachable robots.txt == no restrictions
        _robots_cache[origin] = parser

    return parser.can_fetch(config.USER_AGENT, url)


async def _render_with_browser(url: str) -> tuple[str, str]:
    """Load ``url`` in headless Chromium and return (final_url, rendered HTML).

    Only reached when a static fetch came back thin and JS_RENDER is on.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise FetchError(
            "JS rendering needs playwright: pip install playwright && "
            "playwright install chromium"
        ) from exc

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page(user_agent=config.USER_AGENT)
                await page.goto(
                    url,
                    wait_until="networkidle",
                    timeout=int(config.JS_RENDER_TIMEOUT * 1000),
                )
                return page.url, await page.content()
            finally:
                await browser.close()
    except Exception as exc:
        raise FetchError(f"Headless render failed for {url}: {exc}") from exc


async def _get_with_retries(client: httpx.AsyncClient, url: str) -> httpx.Response:
    """GET with backoff on transient failures (timeouts, 429, 5xx)."""
    attempts = max(1, config.HTTP_RETRIES + 1)
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            resp = await client.get(url)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                await asyncio.sleep(0.6 * (2**attempt))
                continue
            return resp
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_exc = exc
            if attempt < attempts - 1:
                await asyncio.sleep(0.6 * (2**attempt))
    hint = ""
    if proxy_enabled():
        _name, purl, _v = active_proxy()
        hint = (f" — target traffic is routed through the {_name} proxy at {purl}; "
                "if it isn't running, start it or unset "
                f"{'BURP_PROXY' if _name == 'burp' else 'ZAP_PROXY'}")
    raise FetchError(
        f"Could not fetch {url} after {attempts} attempts: "
        f"{type(last_exc).__name__}: {last_exc or '(no detail)'}{hint}"
    )


async def fetch_page(url: str, max_chars: int | None = None) -> Page:
    """Download ``url`` and return its readable text (HTML or PDF)."""
    url = url.strip()
    if not url:
        raise FetchError("Empty URL.")
    if not urlparse(url).scheme:
        url = "https://" + url

    max_chars = max_chars or config.MAX_PAGE_CHARS

    if (hit := cache.get("page", url)) is not None:
        page = Page(**hit)
        return _truncate(page, max_chars)

    await asyncio.to_thread(_assert_public_url, url)

    headers = {
        "User-Agent": config.USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    async with httpx.AsyncClient(
        timeout=config.HTTP_TIMEOUT, follow_redirects=True, headers=headers,
        **proxy_kwargs(),
    ) as client:
        if not await _robots_allows(client, url):
            raise FetchError(
                f"{url} is disallowed by the site's robots.txt. "
                "Set WEBSEARCH_RESPECT_ROBOTS=false to override."
            )

        resp = await _get_with_retries(client, url)
        if resp.status_code >= 400:
            raise FetchError(f"HTTP {resp.status_code} for {url}")

        content_type = resp.headers.get("content-type", "").lower()
        raw = resp.content
        final_url = str(resp.url)

        is_pdf = "pdf" in content_type or raw[:5] == b"%PDF-"
        if is_pdf:
            if not config.READ_PDF:
                raise FetchError(f"{url} is a PDF and PDF reading is disabled.")
            if len(raw) > config.MAX_PDF_BYTES:
                raise FetchError(
                    f"{url} is a {len(raw) // 1_000_000} MB PDF, over the "
                    f"{config.MAX_PDF_BYTES // 1_000_000} MB limit."
                )
            title, text = await asyncio.to_thread(_extract_pdf, raw)
            if not text.strip():
                raise FetchError(
                    f"{url} is a PDF with no extractable text "
                    "(likely a scan; OCR is not supported)."
                )
            page = Page(url=url, final_url=final_url, title=title, text=text)
            cache.set("page", url, page.as_dict())
            return _truncate(page, max_chars)

        if content_type and not any(
            kind in content_type for kind in ("html", "text", "xml", "json")
        ):
            raise FetchError(f"{url} is '{content_type}', not a readable text document.")

        html = raw[: config.MAX_PAGE_BYTES].decode(resp.encoding or "utf-8", errors="replace")
        if "html" in content_type or "<html" in html[:2000].lower():
            title, text = _extract(html, final_url)
        else:
            title, text = "", html

        # Thin result on an HTML page usually means it renders client-side.
        # Retry through a real browser when that fallback is enabled.
        if config.JS_RENDER and len(text.strip()) < config.JS_RENDER_MIN_CHARS:
            log.info("static fetch of %s was thin; retrying with headless browser", url)
            try:
                final_url, rendered = await _render_with_browser(final_url)
                r_title, r_text = _extract(rendered, final_url)
                if len(r_text.strip()) > len(text.strip()):
                    title, text = r_title or title, r_text
            except FetchError as exc:
                log.warning("%s", exc)

    if not text.strip():
        raise FetchError(
            f"No readable text found at {url} (page may require JavaScript; "
            "set WEBSEARCH_JS_RENDER=true to render it)."
        )

    page = Page(url=url, final_url=final_url, title=title, text=text)
    cache.set("page", url, page.as_dict())
    return _truncate(page, max_chars)


def _truncate(page: Page, max_chars: int) -> Page:
    if len(page.text) <= max_chars:
        return page
    return Page(
        url=page.url,
        final_url=page.final_url,
        title=page.title,
        text=page.text[:max_chars],
        truncated=True,
    )
