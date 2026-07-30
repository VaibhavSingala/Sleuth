"""Feed reconnaissance results into Burp.

Two complementary things:
- `seed_targets` requests each URL through the Burp proxy, so the target and
  its discovered endpoints populate Burp's site map / proxy history ready to
  scan. This works with any Burp edition.
- `build_scope` emits a Burp target-scope JSON you can load in Burp so a scan
  stays confined to the intended host and its subdomains.

`feed_recon` ties them together: it runs the passive analyzer, collects the
site's own endpoints and CT-log subdomains, seeds them, and returns the scope.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

from .. import config
from ..fetch import FetchError, _assert_public_url
from ..intercept import proxy_enabled, proxy_kwargs

log = logging.getLogger(__name__)


def _registrable(host: str) -> str:
    host = (host or "").lower().strip()
    return host[4:] if host.startswith("www.") else host


async def seed_targets(urls: list[str]) -> dict:
    """GET each URL through the Burp proxy to populate its site map.

    Returns {"seeded": [...], "skipped": [...]}. Requires BURP_PROXY.
    """
    result: dict = {"seeded": [], "skipped": []}
    if not proxy_enabled():
        result["skipped"].append("BURP_PROXY is not set — nothing sent to Burp")
        return result

    headers = {"User-Agent": config.USER_AGENT}
    async with httpx.AsyncClient(
        timeout=config.HTTP_TIMEOUT, follow_redirects=True, headers=headers,
        **proxy_kwargs(),
    ) as client:
        async def _one(url: str):
            try:
                await asyncio.to_thread(_assert_public_url, url)
                await client.get(url)
                return url, None
            except (FetchError, httpx.HTTPError) as exc:
                return url, f"{type(exc).__name__}"

        for url, err in await asyncio.gather(*(_one(u) for u in urls)):
            if err:
                result["skipped"].append(f"{url} ({err})")
            else:
                result["seeded"].append(url)
    return result


def build_scope(host: str) -> dict:
    """A Burp target-scope object confining scans to ``host`` and subdomains."""
    base = _registrable(host)
    escaped = re.escape(base)
    return {
        "target": {
            "scope": {
                "advanced_mode": True,
                "include": [
                    {"enabled": True, "protocol": "any",
                     "host": f"^(.*\\.)?{escaped}$", "file": "^/.*"},
                ],
                "exclude": [],
            }
        }
    }


async def feed_recon(url: str, max_targets: int = 40) -> str:
    """Analyze ``url``, seed its endpoints/subdomains into Burp, return a summary.

    Passive discovery (the site's own pages + CT logs) followed by seeding
    those URLs through the proxy. No guessing of hidden paths.
    """
    # Imported here to keep the module import-light and avoid any cycle.
    from ..recon import analyse, collect
    from ..recon.subdomains import discover_subdomains

    try:
        probe = await collect(url)
    except FetchError as exc:
        return f"Could not analyse {url}: {exc}"

    base_url = probe.final_url or probe.input_url
    content = analyse(probe.html, base_url)
    host = probe.host

    # Candidate targets: the page itself, its API-shaped endpoints, and the
    # roots of any subdomains seen in Certificate Transparency logs.
    targets: list = [base_url]
    for endpoint in content.api_endpoints:
        targets.append(urljoin(base_url, endpoint))
    subs = await discover_subdomains(host) if host else {"subdomains": []}
    scheme = urlparse(base_url).scheme or "https"
    for sub in subs.get("subdomains", []):
        targets.append(f"{scheme}://{sub}")

    # De-dupe, keep order, cap.
    seen: set = set()
    unique: list = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)
    unique = unique[:max_targets]

    seeded = await seed_targets(unique)
    scope = build_scope(host)

    lines = [
        f"# Fed recon for {host} into Burp",
        "",
        f"Discovered {len(unique)} candidate targets "
        f"({len(content.api_endpoints)} endpoints, "
        f"{len(subs.get('subdomains', []))} subdomains).",
    ]
    if proxy_enabled():
        lines.append(f"\nSeeded into Burp's site map via the proxy: {len(seeded['seeded'])} "
                     f"OK, {len(seeded['skipped'])} skipped.")
    else:
        lines.append("\n**BURP_PROXY is not set**, so nothing was sent to Burp's site map. "
                     "Set it (e.g. http://127.0.0.1:8080) and re-run to populate Burp.")
    if seeded["skipped"]:
        lines.append("Skipped: " + "; ".join(seeded["skipped"][:8]))

    lines.append("\n## Target scope JSON")
    lines.append("Load in Burp (Target -> Scope -> paste / Load) to confine scanning:")
    lines.append("```json\n" + json.dumps(scope, indent=2) + "\n```")
    lines.append(
        "\nSeeding and scope only. Nothing here launches a scan or guesses hidden "
        "paths — run the scan yourself once the scope looks right, on a target you "
        "are authorised to test."
    )
    return "\n".join(lines)
