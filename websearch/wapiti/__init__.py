"""Wapiti integration: a free, pip-installable web vulnerability scanner.

Wapiti (`pip install wapiti3`) is pure Python -- no Java and no separate
application, so it works where installing Burp Pro or ZAP isn't possible. It
crawls the target and sends attack payloads (XSS, SQLi, command injection,
path traversal, etc.), then writes a JSON report.

Active testing -- gated behind config.WAPITI_ALLOW_ACTIVE_SCAN and only for
targets you own or are authorised to test.
"""
