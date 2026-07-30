"""Passive collection layer for site analysis.

Everything here reads what a site publishes about itself: its own pages, the
standard metadata paths it serves, its public DNS records and the TLS
certificate it presents. Nothing probes for unpublished paths, guesses
filenames, or tests for vulnerabilities.
"""

from __future__ import annotations

import asyncio
import json
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from .. import config
from ..fetch import FetchError, _assert_public_url
from ..intercept import proxy_kwargs

# Standard, published-by-convention metadata paths. Fetching these is what a
# search-engine crawler does -- it is not path discovery.
WELL_KNOWN_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/humans.txt",
    "/ads.txt",
    "/manifest.json",
)

MAX_DOC_BYTES = 400_000


@dataclass
class Document:
    url: str
    status: int
    text: str = ""
    content_type: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300 and bool(self.text.strip())


@dataclass
class Probe:
    """Everything collected about one target, before interpretation."""

    input_url: str
    final_url: str = ""
    host: str = ""
    status: int = 0
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    html: str = ""
    redirects: list = field(default_factory=list)
    elapsed_ms: int = 0
    http_version: str = ""
    well_known: dict = field(default_factory=dict)  # path -> Document
    dns: dict = field(default_factory=dict)  # rtype -> [values]
    tls: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def _normalise(url: str) -> str:
    url = url.strip()
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


async def _get(client: httpx.AsyncClient, url: str) -> Document:
    try:
        resp = await client.get(url)
        raw = resp.content[:MAX_DOC_BYTES]
        return Document(
            url=str(resp.url),
            status=resp.status_code,
            text=raw.decode(resp.encoding or "utf-8", errors="replace"),
            content_type=resp.headers.get("content-type", ""),
        )
    except httpx.HTTPError as exc:
        return Document(url=url, status=0, text=f"{exc}")


def _lookup_dns(host: str) -> dict:
    """Public DNS records. Reveals hosting, mail and DNS providers."""
    records: dict = {}
    try:
        import dns.resolver
    except ImportError:
        return {"error": ["dnspython not installed"]}

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 6.0
    resolver.timeout = 3.0
    for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
        try:
            answers = resolver.resolve(host, rtype)
            records[rtype] = sorted(r.to_text().strip('"') for r in answers)
        except Exception:
            continue  # absent record types are normal, not errors
    return records


def _inspect_tls(host: str, port: int = 443) -> dict:
    """Certificate the server presents. SANs often reveal sibling hostnames."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                cipher = tls_sock.cipher() or ("", "", 0)
                version = tls_sock.version() or ""
    except (OSError, ssl.SSLError) as exc:
        return {"error": str(exc)}

    def _flatten(entries) -> dict:
        out = {}
        for group in entries or ():
            for key, value in group:
                out[key] = value
        return out

    subject = _flatten(cert.get("subject"))
    issuer = _flatten(cert.get("issuer"))
    return {
        "protocol": version,
        "cipher": cipher[0],
        "subject_cn": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName", "") or issuer.get("commonName", ""),
        "valid_from": cert.get("notBefore", ""),
        "valid_until": cert.get("notAfter", ""),
        "san": sorted({v for k, v in cert.get("subjectAltName", ()) if k == "DNS"}),
    }


def _looks_like_html(doc: Document) -> bool:
    head = doc.text.lstrip()[:200].lower()
    return "html" in doc.content_type.lower() or head.startswith(("<!doctype html", "<html"))


def _valid_well_known(path: str, doc: Document) -> bool:
    """Reject soft-404s.

    Many sites answer 200 with their normal HTML page for any unknown path.
    Without this check the report would claim a site publishes a security.txt
    when it simply never 404s.
    """
    if not doc.ok:
        return False
    if path.endswith(".txt") or "security.txt" in path:
        return not _looks_like_html(doc)
    if path.endswith(".json"):
        try:
            json.loads(doc.text)
        except ValueError:
            return False
        return True
    if "sitemap" in path or path.endswith(".xml"):
        lowered = doc.text.lower()
        return "<urlset" in lowered or "<sitemapindex" in lowered
    return not _looks_like_html(doc)


def _sitemap_urls_from_robots(robots: str, base: str) -> list:
    found = []
    for line in robots.splitlines():
        if line.lower().startswith("sitemap:"):
            found.append(urljoin(base, line.split(":", 1)[1].strip()))
    return found[:5]


async def collect(url: str, *, fetch_sitemaps: bool = True) -> Probe:
    """Gather everything about ``url`` that the site publishes itself."""
    url = _normalise(url)
    probe = Probe(input_url=url)

    # Same guard the fetch tool uses: never point this at internal hosts.
    await asyncio.to_thread(_assert_public_url, url)

    parsed = urlparse(url)
    probe.host = parsed.hostname or ""
    origin = f"{parsed.scheme}://{parsed.netloc}"

    headers = {
        "User-Agent": config.USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    limits = httpx.Limits(max_connections=6)

    async with httpx.AsyncClient(
        timeout=config.HTTP_TIMEOUT,
        follow_redirects=True,
        headers=headers,
        limits=limits,
        **proxy_kwargs(),
    ) as client:
        try:
            resp = await client.get(url)
        except httpx.HTTPError as exc:
            # Several httpx errors stringify to "", so name the type too.
            raise FetchError(
                f"Could not reach {url}: {type(exc).__name__}: {exc or '(no detail)'}"
            ) from exc

        probe.final_url = str(resp.url)
        probe.status = resp.status_code
        probe.headers = {k.lower(): v for k, v in resp.headers.items()}
        probe.cookies = dict(resp.cookies)
        probe.elapsed_ms = int(resp.elapsed.total_seconds() * 1000)
        probe.http_version = resp.http_version
        probe.redirects = [
            f"{r.status_code} {r.url}" for r in resp.history
        ]
        raw = resp.content[:MAX_DOC_BYTES]
        probe.html = raw.decode(resp.encoding or "utf-8", errors="replace")

        # Well-known metadata, fetched concurrently.
        docs = await asyncio.gather(
            *(_get(client, urljoin(origin, path)) for path in WELL_KNOWN_PATHS)
        )
        # Sites commonly serve the same file at two paths (/security.txt and
        # /.well-known/security.txt); report it once.
        seen_bodies: set = set()
        for path, doc in zip(WELL_KNOWN_PATHS, docs):
            if not _valid_well_known(path, doc):
                continue
            digest = hash(doc.text.strip())
            if digest in seen_bodies:
                continue
            seen_bodies.add(digest)
            probe.well_known[path] = doc

        # Sitemaps the robots.txt itself points at.
        robots = probe.well_known.get("/robots.txt")
        if fetch_sitemaps and robots:
            extra = _sitemap_urls_from_robots(robots.text, origin)
            extra = [u for u in extra if u not in {d.url for d in probe.well_known.values()}]
            if extra:
                for target, doc in zip(extra, await asyncio.gather(
                    *(_get(client, u) for u in extra)
                )):
                    if _valid_well_known("sitemap", doc):
                        probe.well_known[f"sitemap:{target}"] = doc

    if probe.host:
        probe.dns = await asyncio.to_thread(_lookup_dns, probe.host)
        if urlparse(probe.final_url or url).scheme == "https":
            probe.tls = await asyncio.to_thread(_inspect_tls, probe.host)

    return probe
