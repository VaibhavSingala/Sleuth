"""OWASP ZAP integration: proxy routing, spider + active scan, alerts, feed.

ZAP is the free alternative to Burp Pro -- proxy, API and active scanner are
all free. For testing sites you own or are authorised to test. The active
scan path is gated behind config.ZAP_ALLOW_ACTIVE_SCAN and only scans URLs
you pass it.

Import submodules directly (no eager imports here) to avoid import cycles.
"""
