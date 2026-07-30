"""Content, SEO and on-page structure analysis.

Answers "what is this site about and how does it present itself" -- the
keyword side of recon, plus the structural signals (structured data, forms,
API references) that hint at how the site is put together.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

STOPWORDS = frozenset("""
a about above after again against all also am an and any are aren as at be because been
before being below between both but by can cannot could couldn did didn do does doesn
doing don down during each few for from further had hadn has hasn have haven having he
her here hers herself him himself his how i if in into is isn it its itself just let ll
me more most mustn my myself no nor not now of off on once only or other ought our ours
ourselves out over own re same shan she should shouldn so some such than that the their
theirs them themselves then there these they this those through to too under until up
ve very was wasn we were weren what when where which while who whom why will with won
would wouldn you your yours yourself yourselves get got make made use used using new
one two three like need want see know take come go via etc per may might must shall
""".split())

_TOKEN_RE = re.compile(r"[a-z][a-z''\-]{2,}")
# A version segment must be a whole path segment (/v1/), not a fragment of a
# CDN asset path like /v1.4.0/thing.min.js.
_API_RE = re.compile(
    r"""["'(]((?:https?://[^"'()\s]+?)?/(?:api|graphql|rest|rpc|_next/data|v\d{1,2})"""
    r"""(?:/[^"'()\s]{0,80})?)(?=["'()\s])""",
    re.I,
)
_STATIC_RE = re.compile(
    r"\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|pdf)(?:\?|#|$)", re.I
)


@dataclass
class Content:
    title: str = ""
    description: str = ""
    meta_keywords: str = ""
    canonical: str = ""
    robots_meta: str = ""
    lang: str = ""
    charset: str = ""
    viewport: str = ""
    favicon: str = ""
    open_graph: dict = field(default_factory=dict)
    twitter: dict = field(default_factory=dict)
    headings: list = field(default_factory=list)      # (level, text)
    word_count: int = 0
    keywords: list = field(default_factory=list)      # (term, count, density%)
    phrases: list = field(default_factory=list)       # (phrase, count)
    internal_links: int = 0
    external_links: int = 0
    external_domains: list = field(default_factory=list)
    images: int = 0
    images_missing_alt: int = 0
    schema_types: list = field(default_factory=list)
    hreflang: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    feeds: list = field(default_factory=list)


def _meta(soup: BeautifulSoup, **attrs) -> str:
    tag = soup.find("meta", attrs=attrs)
    return (tag.get("content") or "").strip() if tag else ""


def _visible_text(soup: BeautifulSoup) -> str:
    clone = BeautifulSoup(str(soup), "lxml")
    for tag in clone(["script", "style", "noscript", "template", "svg"]):
        tag.decompose()
    return clone.get_text(" ")


def _keywords(text: str) -> tuple:
    tokens = _TOKEN_RE.findall(text.lower())
    if not tokens:
        return 0, [], []

    meaningful = [t for t in tokens if t not in STOPWORDS and len(t) > 2]
    total = len(tokens)
    unigrams = [
        (term, count, round(count / total * 100, 2))
        for term, count in Counter(meaningful).most_common(25)
    ]

    # Build n-grams from the raw stream so word order survives, then drop any
    # phrase that starts or ends on a stopword -- those read as noise.
    phrases: Counter = Counter()
    for size in (2, 3):
        for i in range(len(tokens) - size + 1):
            gram = tokens[i : i + size]
            if gram[0] in STOPWORDS or gram[-1] in STOPWORDS:
                continue
            if any(len(w) <= 2 for w in gram):
                continue
            phrases[" ".join(gram)] += 1

    top_phrases = [(p, c) for p, c in phrases.most_common(20) if c > 1]
    return total, unigrams, top_phrases


def _structured_data(soup: BeautifulSoup) -> list:
    types: list = []
    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(tag.string or "{}")
        except (ValueError, TypeError):
            continue
        for node in data if isinstance(data, list) else [data]:
            if not isinstance(node, dict):
                continue
            found = node.get("@type") or node.get("type")
            for value in found if isinstance(found, list) else [found]:
                if value and value not in types:
                    types.append(str(value))
            for nested in node.get("@graph", []):
                if isinstance(nested, dict) and (t := nested.get("@type")):
                    for value in t if isinstance(t, list) else [t]:
                        if value not in types:
                            types.append(str(value))
    return types


def analyse(html: str, base_url: str) -> Content:
    """Extract content, SEO and structural signals from one page."""
    soup = BeautifulSoup(html, "lxml")
    content = Content()
    host = urlparse(base_url).hostname or ""

    content.title = (soup.title.get_text(strip=True) if soup.title else "")
    content.description = _meta(soup, name=re.compile(r"^description$", re.I))
    content.meta_keywords = _meta(soup, name=re.compile(r"^keywords$", re.I))
    content.robots_meta = _meta(soup, name=re.compile(r"^robots$", re.I))

    if html_tag := soup.find("html"):
        content.lang = (html_tag.get("lang") or "").strip()
    if charset_tag := soup.find("meta", charset=True):
        content.charset = charset_tag.get("charset", "")
    content.viewport = _meta(soup, name=re.compile(r"^viewport$", re.I))

    for link in soup.find_all("link", href=True):
        rels = [r.lower() for r in (link.get("rel") or [])]
        href = urljoin(base_url, link["href"])
        if "canonical" in rels:
            content.canonical = href
        elif "icon" in " ".join(rels) and not content.favicon:
            content.favicon = href
        elif "alternate" in rels:
            if link.get("hreflang"):
                content.hreflang.append(f"{link['hreflang']} -> {href}")
            elif "rss" in (link.get("type") or "") or "atom" in (link.get("type") or ""):
                content.feeds.append(href)

    for tag in soup.find_all("meta", property=re.compile(r"^og:", re.I)):
        content.open_graph[tag["property"].lower()] = (tag.get("content") or "")[:200]
    for tag in soup.find_all("meta", attrs={"name": re.compile(r"^twitter:", re.I)}):
        content.twitter[tag["name"].lower()] = (tag.get("content") or "")[:200]

    for level in range(1, 4):
        for tag in soup.find_all(f"h{level}"):
            text = tag.get_text(" ", strip=True)
            if text:
                content.headings.append((level, text[:120]))
    content.headings = content.headings[:40]

    text = _visible_text(soup)
    content.word_count, content.keywords, content.phrases = _keywords(text)

    external: Counter = Counter()
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        target_host = urlparse(urljoin(base_url, href)).hostname or ""
        if not target_host or target_host == host or target_host.endswith("." + host):
            content.internal_links += 1
        else:
            content.external_links += 1
            external[target_host] += 1
    content.external_domains = [f"{d} ({n})" for d, n in external.most_common(15)]

    images = soup.find_all("img")
    content.images = len(images)
    content.images_missing_alt = sum(1 for i in images if not (i.get("alt") or "").strip())

    content.schema_types = _structured_data(soup)

    for form in soup.find_all("form")[:10]:
        method = (form.get("method") or "get").upper()
        action = urljoin(base_url, form.get("action") or "")
        fields = [
            i.get("type") or i.name
            for i in form.find_all(["input", "select", "textarea"])[:12]
        ]
        content.forms.append(f"{method} {action or '(self)'} — fields: {', '.join(fields) or 'none'}")

    endpoints = {
        m.group(1) for m in _API_RE.finditer(html) if not _STATIC_RE.search(m.group(1))
    }
    content.api_endpoints = sorted(endpoints)[:25]

    return content
