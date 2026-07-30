"""Feed reconnaissance into ZAP.

Requests the target plus its discovered endpoints and CT-log subdomains
through ZAP's proxy, which passively scans everything that passes through --
so this populates ZAP's site tree and produces passive alerts for free, with
no active attack traffic. Follow up with `zap_alerts` or an active scan.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin, urlparse

import httpx

from .. import config
from ..fetch import FetchError, _assert_public_url

log = logging.getLogger(__name__)


async def feed_recon(url: str, max_targets: int = 40) -> str:
    """Analyze ``url`` and route its endpoints/subdomains through the ZAP proxy."""
    if not config.ZAP_PROXY:
        return ("ZAP_PROXY is not set. Point it at ZAP's proxy (e.g. "
                "http://127.0.0.1:8090) and re-run so traffic reaches ZAP.")

    from ..recon import analyse, collect
    from ..recon.subdomains import discover_subdomains

    try:
        probe = await collect(url)
    except FetchError as exc:
        return f"Could not analyse {url}: {exc}"

    base_url = probe.final_url or probe.input_url
    content = analyse(probe.html, base_url)
    host = probe.host

    targets = [base_url]
    for endpoint in content.api_endpoints:
        targets.append(urljoin(base_url, endpoint))
    subs = await discover_subdomains(host) if host else {"subdomains": []}
    scheme = urlparse(base_url).scheme or "https"
    for sub in subs.get("subdomains", []):
        targets.append(f"{scheme}://{sub}")

    seen: set = set()
    unique = [t for t in targets if not (t in seen or seen.add(t))][:max_targets]

    kwargs = {"proxy": config.ZAP_PROXY}
    if not config.ZAP_PROXY_VERIFY:
        kwargs["verify"] = False

    seeded, skipped = [], []
    async with httpx.AsyncClient(
        timeout=config.HTTP_TIMEOUT, follow_redirects=True,
        headers={"User-Agent": config.USER_AGENT}, **kwargs,
    ) as client:
        async def _one(target: str):
            try:
                await asyncio.to_thread(_assert_public_url, target)
                await client.get(target)
                return target, None
            except (FetchError, httpx.HTTPError) as exc:
                return target, type(exc).__name__

        for target, err in await asyncio.gather(*(_one(t) for t in unique)):
            (skipped if err else seeded).append(f"{target}{' (' + err + ')' if err else ''}")

    return "\n".join([
        f"# Fed recon for {host} into ZAP",
        f"\nRouted {len(seeded)} of {len(unique)} URLs through ZAP's proxy "
        f"({len(content.api_endpoints)} endpoints, {len(subs.get('subdomains', []))} subdomains).",
        "ZAP has passively scanned them. Read findings with `zap_alerts`, or run an "
        "active scan for deeper coverage.",
        ("\nSkipped: " + "; ".join(skipped[:8])) if skipped else "",
    ])
