"""CLI for the Wapiti scanner integration.

    python -m websearch.wapiti scan https://your-site.example
    python -m websearch.wapiti scan https://your-site.example --max-time 300

Active vulnerability testing -- runs only when WAPITI_ALLOW_ACTIVE_SCAN=true
against a target you are authorised to test.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from .scan import scan_url


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m websearch.wapiti", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("scan", help="Actively scan a URL (gated).")
    p.add_argument("url")
    p.add_argument("--max-time", type=int, default=None, help="Time cap in seconds.")
    args = parser.parse_args()

    try:
        if args.command == "scan":
            print(asyncio.run(scan_url(args.url, max_time=args.max_time)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
