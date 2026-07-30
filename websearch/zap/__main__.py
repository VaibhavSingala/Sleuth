"""Command-line interface for the OWASP ZAP integration.

    python -m websearch.zap version
    python -m websearch.zap feed https://your-site.example
    python -m websearch.zap alerts https://your-site.example
    python -m websearch.zap scan https://your-site.example
    python -m websearch.zap status 0 --baseurl https://your-site.example

`scan` performs active vulnerability testing and only runs when
ZAP_ALLOW_ACTIVE_SCAN=true against a target you are authorised to test.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .scan import ZapError, alerts, scan_status, scan_url, version
from .seed import feed_recon


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m websearch.zap", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="Check ZAP connectivity.")
    p = sub.add_parser("feed", help="Seed recon through ZAP's proxy (passive).")
    p.add_argument("url")
    p = sub.add_parser("alerts", help="Read ZAP alerts for a base URL.")
    p.add_argument("url")
    p = sub.add_parser("scan", help="Spider + ACTIVE scan (gated).")
    p.add_argument("url")
    p.add_argument("--no-wait", action="store_true")
    p = sub.add_parser("status", help="Check an active scan by id.")
    p.add_argument("scan_id")
    p.add_argument("--baseurl", default="")
    args = parser.parse_args()

    try:
        if args.command == "version":
            try:
                print("ZAP version:", asyncio.run(version()))
            except ZapError as exc:
                print(exc); sys.exit(1)
        elif args.command == "feed":
            print(asyncio.run(feed_recon(args.url)))
        elif args.command == "alerts":
            print(asyncio.run(alerts(args.url)))
        elif args.command == "scan":
            print(asyncio.run(scan_url(args.url, wait=not args.no_wait)))
        elif args.command == "status":
            print(asyncio.run(scan_status(args.scan_id, baseurl=args.baseurl)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
