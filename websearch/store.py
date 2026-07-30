"""Disk-backed conversation storage for the chat web page.

One JSON file per conversation under a conversations directory. Each holds the
LLM message history (to continue with full context) plus a display transcript
(``turns``) that records the tool steps, so reloading a chat shows what
happened, ChatGPT/Claude-style.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .agent import system_prompt

CONV_DIR = Path(config._env("WEBSEARCH_CONV_DIR", str(config.PROJECT_ROOT / "conversations")))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _path(conv_id: str) -> Path:
    # ids are uu4 hex; guard against traversal from any external caller anyway.
    safe = "".join(c for c in conv_id if c.isalnum() or c in "-_")
    return CONV_DIR / f"{safe}.json"


def new_conversation() -> dict:
    return {
        "id": uuid.uuid4().hex,
        "title": "",
        "created": _now(),
        "updated": _now(),
        "messages": [{"role": "system", "content": system_prompt(_today())}],
        "turns": [],
    }


def load(conv_id: str) -> dict | None:
    path = _path(conv_id)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def load_or_create(conv_id: str | None) -> dict:
    if conv_id:
        existing = load(conv_id)
        if existing is not None:
            return existing
    return new_conversation()


def save(conv: dict) -> None:
    conv["updated"] = _now()
    CONV_DIR.mkdir(parents=True, exist_ok=True)
    path = _path(conv["id"])
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(conv, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)  # atomic-ish: never leave a half-written file


def delete(conv_id: str) -> bool:
    path = _path(conv_id)
    try:
        path.unlink()
        return True
    except OSError:
        return False


def rename(conv_id: str, title: str) -> bool:
    conv = load(conv_id)
    if conv is None:
        return False
    conv["title"] = title.strip()[:120] or conv.get("title", "")
    save(conv)
    return True


def list_conversations() -> list[dict]:
    """Return [{id, title, updated}] newest first."""
    if not CONV_DIR.is_dir():
        return []
    out = []
    for path in CONV_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        out.append({
            "id": data.get("id", path.stem),
            "title": data.get("title") or "(untitled)",
            "updated": data.get("updated", ""),
        })
    out.sort(key=lambda c: c["updated"], reverse=True)
    return out
