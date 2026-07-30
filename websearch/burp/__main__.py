"""Command-line interface for the Burp integration.

    python -m websearch.burp parse report.xml
    python -m websearch.burp feed https://your-site.example
    python -m websearch.burp scope your-site.example
    python -m websearch.burp scan https://your-site.example
    python -m websearch.burp status 3

`scan` performs active vulnerability testing and only runs when
BURP_ALLOW_ACTIVE_SCAN=true against a target you are authorised to test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .reports import parse_report
from .scan import scan_status, scan_url
from .seed import build_scope, feed_recon


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m websearch.burp", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("parse", help="Triage a Burp XML issue export.")
    p.add_argument("path")

    p = sub.add_parser("feed", help="Seed recon into Burp's site map + emit scope.")
    p.add_argument("url")

    p = sub.add_parser("scope", help="Print a Burp target-scope JSON for a domain.")
    p.add_argument("domain")

    p = sub.add_parser("scan", help="Start an ACTIVE Burp scan (Pro; gated).")
    p.add_argument("url")
    p.add_argument("--no-wait", action="store_true", help="Return a task id instead of waiting.")

    p = sub.add_parser("status", help="Check a Burp scan by task id.")
    p.add_argument("task_id")

    args = parser.parse_args()

    try:
        if args.command == "parse":
            print(parse_report(args.path))
        elif args.command == "feed":
            print(asyncio.run(feed_recon(args.url)))
        elif args.command == "scope":
            print(json.dumps(build_scope(args.domain), indent=2))
        elif args.command == "scan":
            print(asyncio.run(scan_url(args.url, wait=not args.no_wait)))
        elif args.command == "status":
            print(asyncio.run(scan_status(args.task_id)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
