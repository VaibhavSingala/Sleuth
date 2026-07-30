"""Assemble collected signals into a readable Markdown report."""

from __future__ import annotations

import re
from collections import defaultdict

from . import fingerprint
from .content import Content
from .probe import Probe

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)


def _section(title: str) -> str:
    return f"\n## {title}\n"


def _robots_summary(text: str) -> list:
    agents, disallows, sitemaps, crawl_delay = [], [], [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            agents.append(value)
        elif key == "disallow" and value:
            disallows.append(value)
        elif key == "sitemap":
            sitemaps.append(value)
        elif key == "crawl-delay":
            crawl_delay = value

    lines = [
        f"- User-agent groups: {len(agents)}"
        + (f" ({', '.join(dict.fromkeys(agents[:6]))})" if agents else "")
    ]
    if crawl_delay:
        lines.append(f"- Crawl-delay: {crawl_delay}")
    if sitemaps:
        lines.append(f"- Declared sitemaps: {', '.join(sitemaps[:5])}")
    if disallows:
        unique = list(dict.fromkeys(disallows))
        lines.append(f"- Disallowed paths ({len(unique)} unique), first 15:")
        lines += [f"  - `{p}`" for p in unique[:15]]
    return lines


def _sitemap_summary(text: str) -> str:
    locs = _LOC_RE.findall(text)
    if not locs:
        return "no <loc> entries found"
    kind = "sitemap index" if "<sitemapindex" in text.lower() else "URL set"
    sample = ", ".join(u for u in locs[:3])
    return f"{kind}, {len(locs)} entries — e.g. {sample}"


def build(
    probe: Probe,
    content: Content,
    *,
    detail: str = "standard",
    subdomains: dict | None = None,
) -> str:
    """Render the full analysis. ``detail`` is "summary", "standard" or "full"."""
    full = detail == "full"
    brief = detail == "summary"
    kw_limit = 8 if brief else (15 if not full else 25)
    out: list = []

    # --- Overview ---
    out.append(f"# Website analysis — {probe.host}")
    out.append("")
    out.append(f"- Requested: {probe.input_url}")
    if probe.final_url != probe.input_url:
        out.append(f"- Resolved to: {probe.final_url}")
    if probe.redirects:
        out.append(f"- Redirect chain: {' → '.join(probe.redirects)}")
    out.append(f"- Status: {probe.status} over {probe.http_version} in {probe.elapsed_ms} ms")
    if addresses := probe.dns.get("A", []) + probe.dns.get("AAAA", []):
        out.append(f"- Resolves to: {', '.join(addresses[:6])}")
    if content.title:
        out.append(f"- Title: {content.title}")
    if content.description:
        out.append(f"- Description: {content.description[:300]}")
    if content.lang:
        out.append(f"- Declared language: {content.lang}")

    # --- Technology ---
    detections = fingerprint.detect(probe)
    out.append(_section("Technology stack"))
    if not detections:
        out.append("No technologies matched. The site may be heavily proxied or "
                   "render entirely client-side.")
    else:
        grouped = defaultdict(list)
        for det in detections:
            grouped[det.category].append(det)
        for category in sorted(grouped):
            out.append(f"\n**{category}**")
            for det in grouped[category]:
                if brief:
                    out.append(f"- {det.name}")
                else:
                    out.append(f"- **{det.name}** — {'; '.join(det.evidence[:2])}")

    # --- Infrastructure ---
    out.append(_section("Infrastructure & architecture"))
    if providers := fingerprint.dns_providers(probe):
        out.append(f"- DNS provider: {', '.join(providers)}")
    if providers := fingerprint.mail_providers(probe):
        out.append(f"- Mail provider: {', '.join(providers)}")
    if server := probe.header("server"):
        out.append(f"- Server header: `{server}`")
    if powered := probe.header("x-powered-by"):
        out.append(f"- X-Powered-By: `{powered}`")
    if probe.cookies:
        out.append(f"- Cookies set on first load: {', '.join(list(probe.cookies)[:10])}")

    if probe.dns:
        out.append("\n**DNS records**")
        for rtype in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "CAA"):
            values = probe.dns.get(rtype)
            if not values:
                continue
            shown = values if full else values[:5]
            for value in shown:
                out.append(f"- {rtype}: `{value[:180]}`")
            if len(values) > len(shown):
                out.append(f"- {rtype}: …{len(values) - len(shown)} more")

    if probe.tls and "error" not in probe.tls:
        tls = probe.tls
        out.append("\n**TLS certificate**")
        out.append(f"- {tls['protocol']} / {tls['cipher']}")
        out.append(f"- Issued to `{tls['subject_cn']}` by {tls['issuer']}")
        out.append(f"- Valid {tls['valid_from']} → {tls['valid_until']}")
        if sans := tls.get("san"):
            shown = sans if full else sans[:12]
            out.append(f"- SANs ({len(sans)}): {', '.join(shown)}"
                       + ("" if len(shown) == len(sans) else " …"))
    elif probe.tls.get("error"):
        out.append(f"\n- TLS inspection failed: {probe.tls['error']}")

    # --- Subdomains (Certificate Transparency) ---
    if subdomains is not None:
        out.append(_section("Subdomains (Certificate Transparency)"))
        names = subdomains.get("subdomains", [])
        if names:
            total = subdomains.get("count", len(names))
            src = subdomains.get("source", "CT logs")
            note = f", {subdomains['note']}" if subdomains.get("note") else ""
            out.append(f"Found {total} names via {src}{note}:")
            shown = names if full else names[:25]
            for name in shown:
                out.append(f"- `{name}`")
            if len(names) > len(shown):
                out.append(f"- …{len(names) - len(shown)} more")
        elif subdomains.get("note"):
            out.append(f"- No results ({subdomains['note']}).")
        else:
            out.append("- None found in CT logs.")

    # --- Security headers ---
    present, absent = fingerprint.security_posture(probe)
    out.append(_section("Security headers"))
    out.append("_What the server already advertises in every response. "
               "A missing header is a hardening observation, not a vulnerability._\n")
    for header, value in present:
        out.append(f"- Present — `{header}: {value}`")
    for header, why in absent:
        out.append(f"- Absent — `{header}` ({why})")
    if versions := fingerprint.disclosed_versions(probe):
        out.append(f"\n- Version strings disclosed in headers: {', '.join(versions)}")

    # --- Content & keywords ---
    out.append(_section("Content & keywords"))
    out.append(f"- Visible word count: {content.word_count}")
    if content.meta_keywords:
        out.append(f"- Declared meta keywords: {content.meta_keywords[:300]}")
    if content.keywords:
        out.append(f"\n**Top terms** (count, share of all words)\n")
        for term, count, density in content.keywords[:kw_limit]:
            out.append(f"- {term} — {count}× ({density}%)")
    if content.phrases and not brief:
        out.append(f"\n**Recurring phrases**\n")
        for phrase, count in content.phrases[: kw_limit - 2]:
            out.append(f"- \"{phrase}\" — {count}×")

    if content.headings and not brief:
        out.append("\n**Heading outline**\n")
        for level, text in content.headings[: 25 if full else 12]:
            out.append(f"{'  ' * (level - 1)}- H{level}: {text}")

    # --- SEO / metadata ---
    out.append(_section("SEO & metadata"))
    out.append(f"- Canonical: {content.canonical or '(none)'}")
    out.append(f"- Robots meta: {content.robots_meta or '(none)'}")
    out.append(f"- Viewport: {content.viewport or '(none)'}")
    out.append(f"- Open Graph tags: {len(content.open_graph)}"
               + (f" — {', '.join(list(content.open_graph)[:8])}" if content.open_graph else ""))
    out.append(f"- Twitter card tags: {len(content.twitter)}")
    if content.schema_types:
        out.append(f"- Structured data types: {', '.join(content.schema_types[:15])}")
    if content.hreflang:
        out.append(f"- hreflang alternates ({len(content.hreflang)}): "
                   f"{', '.join(content.hreflang[:8])}")
    if content.feeds:
        out.append(f"- Feeds: {', '.join(content.feeds[:5])}")
    out.append(f"- Images: {content.images} ({content.images_missing_alt} without alt text)")
    out.append(f"- Links: {content.internal_links} internal, {content.external_links} external")
    if content.external_domains and not brief:
        out.append(f"- Top external domains: {', '.join(content.external_domains[:10])}")

    # --- Published site surface ---
    out.append(_section("Published site metadata"))
    if not probe.well_known:
        out.append("- None of the standard metadata files were served.")
    for path, doc in probe.well_known.items():
        if path == "/robots.txt":
            out.append("\n**robots.txt**")
            out += _robots_summary(doc.text)
        elif path.startswith("sitemap:") or path == "/sitemap.xml":
            out.append(f"\n**{doc.url}** — {_sitemap_summary(doc.text)}")
        elif "security.txt" in path:
            out.append("\n**security.txt** (published vulnerability-reporting contact)")
            for line in doc.text.splitlines()[:8]:
                if line.strip() and not line.startswith("#"):
                    out.append(f"- `{line.strip()[:150]}`")
        elif path == "/manifest.json":
            out.append(f"\n**manifest.json** — {doc.text[:300].strip()}")
        else:
            out.append(f"\n**{path}** — {len(doc.text)} bytes served")

    # --- Application surface ---
    if content.forms or content.api_endpoints:
        out.append(_section("Application surface"))
        if content.forms:
            out.append("**Forms on the landing page**")
            for form in content.forms:
                out.append(f"- {form}")
        if content.api_endpoints:
            out.append("\n**API-shaped paths referenced in the markup/JS**")
            shown = content.api_endpoints if full else content.api_endpoints[:12]
            for endpoint in shown:
                out.append(f"- `{endpoint}`")

    out.append(_section("Scope note"))
    out.append(
        "Passive analysis only: this reads the pages and metadata the site "
        "publishes, its public DNS records, the TLS certificate it presents, and "
        "public Certificate Transparency logs. No path discovery, port scanning "
        "or vulnerability probing was performed, so absence of a finding is not "
        "evidence of absence."
    )
    if probe.errors:
        out.append("\nCollection warnings: " + "; ".join(probe.errors))

    return "\n".join(out)


# --- Comparison -----------------------------------------------------------


def _tech_by_category(probe: Probe) -> dict:
    grouped: dict = defaultdict(set)
    for det in fingerprint.detect(probe):
        grouped[det.category].add(det.name)
    return grouped


def _keyword_set(content: Content, n: int = 15) -> list:
    return [term for term, _c, _d in content.keywords[:n]]


def build_comparison(
    probe_a: Probe, content_a: Content, probe_b: Probe, content_b: Content
) -> str:
    """Contrast two profiled sites: stack, infra, security, keywords."""
    a, b = probe_a.host, probe_b.host
    out = [f"# Site comparison — {a} vs {b}", ""]

    # Snapshot table.
    out.append(f"| | **{a}** | **{b}** |")
    out.append("|---|---|---|")
    out.append(f"| Title | {content_a.title[:50] or '—'} | {content_b.title[:50] or '—'} |")
    out.append(f"| Status | {probe_a.status} | {probe_b.status} |")
    out.append(f"| Response | {probe_a.elapsed_ms} ms | {probe_b.elapsed_ms} ms |")
    out.append(f"| Server | {probe_a.header('server') or '—'} | {probe_b.header('server') or '—'} |")
    out.append(f"| DNS provider | {', '.join(fingerprint.dns_providers(probe_a)) or '—'} "
               f"| {', '.join(fingerprint.dns_providers(probe_b)) or '—'} |")
    out.append(f"| Mail provider | {', '.join(fingerprint.mail_providers(probe_a)) or '—'} "
               f"| {', '.join(fingerprint.mail_providers(probe_b)) or '—'} |")
    pres_a, _ = fingerprint.security_posture(probe_a)
    pres_b, _ = fingerprint.security_posture(probe_b)
    out.append(f"| Security headers | {len(pres_a)}/7 | {len(pres_b)}/7 |")
    out.append(f"| Word count | {content_a.word_count} | {content_b.word_count} |")

    # Technology, by category, split into shared / unique.
    tech_a, tech_b = _tech_by_category(probe_a), _tech_by_category(probe_b)
    out.append(_section("Technology"))
    for category in sorted(set(tech_a) | set(tech_b)):
        sa, sb = tech_a.get(category, set()), tech_b.get(category, set())
        shared = sorted(sa & sb)
        only_a = sorted(sa - sb)
        only_b = sorted(sb - sa)
        out.append(f"\n**{category}**")
        if shared:
            out.append(f"- both: {', '.join(shared)}")
        if only_a:
            out.append(f"- {a} only: {', '.join(only_a)}")
        if only_b:
            out.append(f"- {b} only: {', '.join(only_b)}")

    # Keyword overlap and divergence.
    kw_a, kw_b = _keyword_set(content_a), _keyword_set(content_b)
    shared_kw = [k for k in kw_a if k in kw_b]
    out.append(_section("Keywords"))
    out.append(f"- Shared top terms: {', '.join(shared_kw) or '(none in common)'}")
    out.append(f"- {a} emphasises: {', '.join(k for k in kw_a if k not in kw_b)[:300] or '—'}")
    out.append(f"- {b} emphasises: {', '.join(k for k in kw_b if k not in kw_a)[:300] or '—'}")

    out.append(_section("Scope note"))
    out.append(
        "Passive comparison from each site's own published pages, headers, DNS "
        "and TLS. No intrusive testing was performed against either site."
    )
    return "\n".join(out)
