"""Smoke test: the package imports and exposes its documented public API."""

from __future__ import annotations

import importlib


def test_version_is_a_string() -> None:
    pkg = importlib.import_module("websearch")
    assert isinstance(pkg.__version__, str)
    assert pkg.__version__.count(".") >= 1


def test_public_tools_are_callable() -> None:
    pkg = importlib.import_module("websearch")
    for name in ("web_search", "read_url", "research"):
        assert callable(getattr(pkg, name)), f"{name} should be callable"
