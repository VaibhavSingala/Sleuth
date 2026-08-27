"""Opt-in gate for intrusive skills. Files in this directory that start with
``_`` are not registered as tools.

Set ``SLEUTH_ALLOW_ACTIVE_SKILLS=true`` only for systems you own or have
written permission to test.
"""

from __future__ import annotations

import os

_TRUE = {"1", "true", "yes", "on"}


def allowed() -> bool:
    return os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() in _TRUE


def denied(skill: str) -> dict:
    return {
        "ok": False,
        "error": (
            f"Skill '{skill}' is disabled. Set SLEUTH_ALLOW_ACTIVE_SKILLS=true "
            "in .env for authorised targets only."
        ),
    }
