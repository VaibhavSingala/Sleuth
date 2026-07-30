#!/usr/bin/env python
"""Entrypoint for the websearch MCP server.

Referenced directly from LM Studio's mcp.json, so it inserts the project root
on sys.path rather than assuming a particular working directory.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from websearch.server import main  # noqa: E402

if __name__ == "__main__":
    main()
