#!/usr/bin/env python
"""Register the websearch MCP server with LM Studio.

Merges an entry into ~/.lmstudio/mcp.json, keeping any servers already there
and writing a .bak of the previous file first.

    python install.py            # add / update the entry
    python install.py --remove   # take it back out
    python install.py --print    # just show the JSON, change nothing
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

SERVER_NAME = "websearch"
PROJECT_ROOT = Path(__file__).resolve().parent
MCP_CONFIG = Path.home() / ".lmstudio" / "mcp.json"


def entry() -> dict:
    return {
        "command": sys.executable,
        "args": [str(PROJECT_ROOT / "run_server.py")],
        "env": {"PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"},
    }


def load_config() -> dict:
    if not MCP_CONFIG.is_file():
        return {"mcpServers": {}}
    try:
        data = json.loads(MCP_CONFIG.read_text(encoding="utf-8") or "{}")
    except json.JSONDecodeError as exc:
        sys.exit(f"{MCP_CONFIG} is not valid JSON ({exc}). Fix or delete it, then rerun.")
    data.setdefault("mcpServers", {})
    return data


def save_config(data: dict) -> None:
    MCP_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    if MCP_CONFIG.is_file():
        backup = MCP_CONFIG.with_suffix(".json.bak")
        shutil.copy2(MCP_CONFIG, backup)
        print(f"Backed up existing config to {backup}")
    MCP_CONFIG.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remove", action="store_true", help="Remove the entry.")
    parser.add_argument("--print", dest="print_only", action="store_true",
                        help="Print the entry without writing anything.")
    args = parser.parse_args()

    if args.print_only:
        print(json.dumps({"mcpServers": {SERVER_NAME: entry()}}, indent=2))
        return

    config = load_config()

    if args.remove:
        if config["mcpServers"].pop(SERVER_NAME, None) is None:
            print(f"'{SERVER_NAME}' was not registered; nothing to do.")
            return
        save_config(config)
        print(f"Removed '{SERVER_NAME}' from {MCP_CONFIG}")
        return

    existed = SERVER_NAME in config["mcpServers"]
    config["mcpServers"][SERVER_NAME] = entry()
    save_config(config)

    print(f"{'Updated' if existed else 'Added'} '{SERVER_NAME}' in {MCP_CONFIG}")
    print(json.dumps(entry(), indent=2))
    print(
        "\nNext:\n"
        "  1. Restart LM Studio (fully quit, then reopen).\n"
        "  2. Load a tool-calling capable model.\n"
        "  3. In the chat sidebar open the Integrations / plugin panel and enable "
        "'websearch'.\n"
        "  4. Ask something current -- the model should call `research`."
    )


if __name__ == "__main__":
    main()
