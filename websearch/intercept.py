"""Resolve which intercepting proxy target traffic routes through.

Burp and ZAP can't both intercept the same requests, so this is the single
place that decides. Burp wins if both are configured. Used by the page
fetcher, the site analyzer, and the recon-seeding helpers.
"""

from __future__ import annotations

import logging

from . import config

log = logging.getLogger(__name__)


def active_proxy() -> tuple[str, str, bool]:
    """Return (name, url, verify) for the configured proxy, or ("", "", False)."""
    if config.BURP_PROXY and config.ZAP_PROXY:
        log.warning("Both BURP_PROXY and ZAP_PROXY are set; using Burp.")
        return "burp", config.BURP_PROXY, config.BURP_PROXY_VERIFY
    if config.BURP_PROXY:
        return "burp", config.BURP_PROXY, config.BURP_PROXY_VERIFY
    if config.ZAP_PROXY:
        return "zap", config.ZAP_PROXY, config.ZAP_PROXY_VERIFY
    return "", "", False


def proxy_enabled() -> bool:
    return bool(active_proxy()[1])


def proxy_kwargs() -> dict:
    """httpx.AsyncClient kwargs to route through the active proxy, or {}."""
    _name, url, verify = active_proxy()
    if not url:
        return {}
    kwargs: dict = {"proxy": url}
    if not verify:
        # Both Burp and ZAP re-sign TLS with their own CA; without trusting it,
        # verification against the real chain fails every request.
        kwargs["verify"] = False
    return kwargs
