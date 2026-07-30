"""Tiny TTL cache on disk.

Keeps repeated searches and page fetches from hammering the upstream
providers -- DuckDuckGo in particular will rate-limit a chatty agent within
a few minutes without this.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from . import config


def _path_for(namespace: str, key: str):
    digest = hashlib.sha256(f"{namespace}:{key}".encode("utf-8")).hexdigest()[:32]
    return config.CACHE_DIR / namespace / f"{digest}.json"


def get(namespace: str, key: str) -> Any | None:
    if not config.CACHE_ENABLED:
        return None
    path = _path_for(namespace, key)
    try:
        if not path.is_file():
            return None
        if time.time() - path.stat().st_mtime > config.CACHE_TTL_SECONDS:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def set(namespace: str, key: str, value: Any) -> None:  # noqa: A001 - mirrors dict API
    if not config.CACHE_ENABLED:
        return
    path = _path_for(namespace, key)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
    except (OSError, TypeError, ValueError):
        pass  # a broken cache must never break a search


def clear() -> int:
    """Delete every cached entry. Returns the number of files removed."""
    removed = 0
    if not config.CACHE_DIR.is_dir():
        return 0
    for path in config.CACHE_DIR.rglob("*.json"):
        try:
            path.unlink()
            removed += 1
        except OSError:
            pass
    return removed
