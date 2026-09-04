"""Unit tests for the env-parsing helpers in the config module.

These test the pure functions directly with monkeypatched environment variables,
so they are independent of any local ``.env`` file.
"""

from __future__ import annotations

import importlib

import pytest

config = importlib.import_module("websearch.config")


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1", True), ("true", True), ("YES", True), ("on", True),
     ("0", False), ("false", False), ("no", False), ("", None)],
)
def test_env_bool(monkeypatch: pytest.MonkeyPatch, value: str, expected: bool | None) -> None:
    monkeypatch.setenv("SLEUTH_TEST_FLAG", value)
    # Empty string must fall back to the supplied default.
    default = True if expected is None else not expected
    result = config._env_bool("SLEUTH_TEST_FLAG", default)
    assert result == (default if expected is None else expected)


def test_env_int_and_float_fall_back_on_garbage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLEUTH_TEST_NUM", "not-a-number")
    assert config._env_int("SLEUTH_TEST_NUM", 7) == 7
    assert config._env_float("SLEUTH_TEST_NUM", 1.5) == 1.5


def test_env_int_parses_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SLEUTH_TEST_NUM", "42")
    assert config._env_int("SLEUTH_TEST_NUM", 0) == 42


def test_active_backend_returns_known_name() -> None:
    assert config.active_backend() in {"tavily", "brave", "searxng", "duckduckgo"}
