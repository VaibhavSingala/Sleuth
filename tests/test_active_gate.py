"""The intrusive-skill allowlist is a security-load-bearing constant.

A regression here (an active skill silently dropping out of the gate) would let
it register as a tool without ``SLEUTH_ALLOW_ACTIVE_SKILLS``, so pin it.
"""

from __future__ import annotations

import importlib

config = importlib.import_module("websearch.config")

EXPECTED_ACTIVE_SKILLS = {
    "brute_force_login",
    "xss_payload_injection",
    "directory_bruteforce",
    "comprehensive_vulnerability_check",
    "check_xss_reflection",
    "check_common_vectors",
}


def test_active_skill_names_is_frozen_and_complete() -> None:
    assert isinstance(config.ACTIVE_SKILL_NAMES, frozenset)
    assert config.ACTIVE_SKILL_NAMES == EXPECTED_ACTIVE_SKILLS


def test_gate_defaults_are_safe_without_env(clean_env) -> None:
    # With no Sleuth env vars set, the dangerous capabilities default off.
    assert config._env_bool("SLEUTH_ALLOW_EXEC", False) is False
    assert config._env_bool("SLEUTH_ALLOW_SELF_EDIT", False) is False
    assert config._env_bool("SLEUTH_ALLOW_ACTIVE_SKILLS", False) is False
    assert config._env_bool("WEBSEARCH_BLOCK_PRIVATE", True) is True
