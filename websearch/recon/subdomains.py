"""Passive subdomain discovery via Certificate Transparency logs.

Every publicly-trusted TLS certificate is logged to CT, and those logs are
public and searchable at crt.sh. Reading them reveals hostnames an
organisation has issued certificates for -- api., staging., mail., vpn.,
admin. and the like -- which is often the most informative view of a site's
real footprint.

This is passive: it queries a public log, not the target. It does not brute
force names, resolve them, or connect to any discovered host.
"""

from __future__ import annotations

import logging
import re

import httpx

from .. import config

log = logging.getLogger(__name__)

_WILDCARD = re.compile(r"^\*\.")


class SourceError(RuntimeError):
    """A single CT source failed; try the next."""


def _registrable(domain: str) -> str:
    """Strip a leading www. and any scheme/path to get the base domain."""
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0].split(":")[0]
    return domain[4:] if domain.startswith("www.") else domain


def _keep(name: str, base: str) -> str:
    name = _WILDCARD.sub("", (name or "").strip().lower())
    if name and name != base and (name == base or name.endswith("." + base)):
        return name
    return ""


async def _from_crtsh(client: httpx.AsyncClient, base: str) -> set:
    resp = await client.get("https://crt.sh/", params={"q": f"%.{base}", "output": "json"})
    if resp.status_code != 200 or not resp.text.strip():
        raise SourceError(f"crt.sh HTTP {resp.status_code}")
    entries = resp.json()
    if not isinstance(entries, list):
        raise SourceError("crt.sh unexpected format")
    names = set()
    for entry in entries:
        if isinstance(entry, dict):
            for raw in (entry.get("name_value", "") or "").splitlines():
                if kept := _keep(raw, base):
                    names.add(kept)
    return names


async def _from_certspotter(client: httpx.AsyncClient, base: str) -> set:
    # Free, no key; low unauth rate limit, so it is the fallback not the primary.
    resp = await client.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": base, "include_subdomains": "true", "expand": "dns_names"},
    )
    if resp.status_code != 200:
        raise SourceError(f"certspotter HTTP {resp.status_code}")
    names = set()
    for entry in resp.json():
        if isinstance(entry, dict):
            for raw in entry.get("dns_names", []) or []:
                if kept := _keep(raw, base):
                    names.add(kept)
    return names


async def discover_subdomains(domain: str, limit: int = 100) -> dict:
    """Return {"domain", "subdomains": [...], "count", "note", "source"}.

    Tries crt.sh, then certspotter. Never raises for the caller's sake --
    network and parse failures come back as an empty list with a note, so
    analysis can proceed regardless.
    """
    base = _registrable(domain)
    result: dict = {"domain": base, "subdomains": [], "count": 0, "note": "", "source": ""}
    if not base or "." not in base:
        result["note"] = "not a valid domain"
        return result

    sources = (("crt.sh", _from_crtsh), ("certspotter", _from_certspotter))
    names: set = set()
    problems: list = []
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.SUBDOMAIN_TIMEOUT),
        headers={"User-Agent": config.USER_AGENT},
        follow_redirects=True,
    ) as client:
        for source_name, fetch in sources:
            try:
                names = await fetch(client, base)
                if names:
                    result["source"] = source_name
                    break
                problems.append(f"{source_name}: empty")
            except (httpx.HTTPError, ValueError, SourceError) as exc:
                problems.append(f"{source_name}: {type(exc).__name__ if not isinstance(exc, SourceError) else exc}")

    if not names:
        result["note"] = "; ".join(problems) or "no data"
        return result

    ordered = sorted(names, key=lambda n: (n.count("."), n))
    result["count"] = len(ordered)
    result["subdomains"] = ordered[:limit]
    if len(ordered) > limit:
        result["note"] = f"showing {limit} of {len(ordered)}"
    return result
