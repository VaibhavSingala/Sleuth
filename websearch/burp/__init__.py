"""Burp Suite integration: proxy routing, report triage, recon feed, scans.

Everything here is for testing sites you own or are authorised to test. The
active-scan path is gated behind an explicit opt-in (config.BURP_ALLOW_ACTIVE_SCAN)
and always targets URLs you pass it -- it never discovers targets on its own.

Import submodules directly (e.g. ``from .burp.proxy import proxy_kwargs``);
this package intentionally does no eager imports so that ``fetch`` can pull in
``burp.proxy`` without an import cycle.
"""
