"""Shared pytest fixtures and path setup.

The package is not yet pip-installed in every dev checkout, so make sure the
project root is importable. Once `pip install -e .` is the norm this becomes a
no-op, and after the src/ migration it points at ``src/``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
for _candidate in (_ROOT, _ROOT / "src"):
    if (_candidate / "websearch").is_dir() or (_candidate / "sleuth").is_dir():
        sys.path.insert(0, str(_candidate))

_SLEUTH_ENV_PREFIXES = ("WEBSEARCH_", "SLEUTH_", "BURP_", "ZAP_", "WAPITI_", "LLM_")


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Remove Sleuth-controlled env vars so helper defaults are deterministic."""
    for key in list(os.environ):
        if key.startswith(_SLEUTH_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch
