"""Full passive analysis of a website, or a comparison of two.

    python -m websearch.analyze example.com
    python -m websearch.analyze example.com --detail full --save report.md
    python -m websearch.analyze example.com --vs competitor.com

Reads only what the target publishes about itself: its pages, its standard
metadata files, its public DNS records, the TLS certificate it presents, and
the Certificate Transparency logs for its domain.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .fetch import FetchError
from .recon import analyse, build, collect
from .recon.subdomains import discover_subdomains

DETAIL_LEVELS = ("summary", "standard", "full")


async def _profile(url: str, detail: str):
    """Collect + interpret one site. Returns (probe, content, subdomains|None)."""
    probe = await collect(url)
    content = analyse(probe.html, probe.final_url or probe.input_url)
    # CT-log lookup is skipped at summary depth to keep it fast.
    subdomains = None
    if detail != "summary" and probe.host:
        subdomains = await discover_subdomains(probe.host)
    return probe, content, subdomains


async def analyze_site(
    url: str,
    detail: str = "standard",
    max_chars: int | None = None,
) -> str:
    """Analyse ``url`` and return a Markdown report."""
    detail = detail if detail in DETAIL_LEVELS else "standard"
    try:
        probe, content, subdomains = await _profile(url, detail)
    except FetchError as exc:
        return f"Could not analyse the site: {exc}"

    report = build(probe, content, detail=detail, subdomains=subdomains)
    return _cap(report, max_chars)


async def compare_sites(
    url_a: str,
    url_b: str,
    detail: str = "standard",
    max_chars: int | None = None,
) -> str:
    """Profile two sites and contrast their stacks, security and keywords.

    The competitive-intelligence view: what each is built with, what each
    targets, and where they diverge.
    """
    detail = detail if detail in DETAIL_LEVELS else "standard"
    results = await asyncio.gather(
        _profile(url_a, detail), _profile(url_b, detail), return_exceptions=True
    )
    for label, res in zip((url_a, url_b), results):
        if isinstance(res, Exception):
            return f"Could not analyse {label}: {res}"

    (probe_a, content_a, _), (probe_b, content_b, _) = results
    from .recon.report import build_comparison

    report = build_comparison(probe_a, content_a, probe_b, content_b)
    return _cap(report, max_chars)


def _cap(report: str, max_chars: int | None) -> str:
    if max_chars and len(report) > max_chars:
        return report[:max_chars] + "\n\n[...report truncated. Raise max_chars for the rest.]"
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive analysis of a website.")
    parser.add_argument("url", help="Site to analyse, e.g. example.com")
    parser.add_argument("--vs", metavar="URL", help="Compare against a second site.")
    parser.add_argument("--detail", choices=DETAIL_LEVELS, default="standard")
    parser.add_argument("--save", metavar="PATH", help="Also write the report to a file.")
    args = parser.parse_args()

    try:
        if args.vs:
            report = asyncio.run(compare_sites(args.url, args.vs, detail=args.detail))
        else:
            report = asyncio.run(analyze_site(args.url, detail=args.detail))
    except KeyboardInterrupt:
        sys.exit(130)

    print(report)
    if args.save:
        with open(args.save, "w", encoding="utf-8") as handle:
            handle.write(report)
        print(f"\nSaved to {args.save}", file=sys.stderr)


if __name__ == "__main__":
    main()
