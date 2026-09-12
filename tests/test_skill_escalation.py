"""The Needle -> skill_write escalation handoff.

When ``skill_write`` is called with a ``description`` but no ``code`` (the router
escalated because no existing tool fits), a code model must write the code, and
the result must still pass the syntax + smoke-test gate before going live. These
pin the branches of that handoff so a regression can't silently ship un-authored
or un-tested skills.

The author model is mocked (no network / no Ollama needed): we monkeypatch the
one HTTP call in ``_author_skill_code``.
"""

from __future__ import annotations

import importlib

import httpx
import pytest

skills = importlib.import_module("websearch.skills")
config = importlib.import_module("websearch.config")

# A benign, self-contained skill the mock "author model" returns. Wrapped in a
# markdown fence to also exercise fence-stripping.
GENERATED_OK = """\
```python
import ipaddress


def is_reserved_ip(ip: str) -> dict:
    \"\"\"Report whether an IP address is reserved / special-use.

    Args:
        ip: the IP address to classify.

    Returns:
        dict with the ip and an is_reserved flag, or an error.
    \"\"\"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        return {"error": str(exc)}
    return {"ip": ip, "is_reserved": bool(addr.is_reserved or addr.is_private)}
```
"""

# Code that loads but crashes on call (references a name nothing injects) --
# exactly what the smoke-test gate exists to catch.
GENERATED_BROKEN = """\
def fetch_title(url: str) -> str:
    \"\"\"Fetch a page title.\"\"\"
    return read_url(url=url)[:80]
"""


@pytest.fixture
def isolated_skills(tmp_path, monkeypatch):
    """Point the skill registry at an empty temp dir with authoring enabled."""
    monkeypatch.setattr(config, "SKILLS_DIR", tmp_path)
    monkeypatch.setattr(config, "SKILLS_ENABLED", True)
    monkeypatch.setattr(config, "SKILL_AUTHOR_ENABLED", True)
    monkeypatch.setattr(config, "SKILL_SMOKE_TEST", True)
    monkeypatch.setattr(config, "SKILL_AUTHOR_MODEL", "sleuth-skill-coder")
    monkeypatch.setattr(skills.REGISTRY, "dir", tmp_path)
    monkeypatch.setattr(skills.REGISTRY, "skills", {})
    return tmp_path


def _mock_author(monkeypatch, content: str) -> dict:
    """Make the author model return ``content``; capture the request payload."""
    captured: dict = {}

    class _Resp:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"choices": [{"message": {"content": content}}]}

    def _post(url, json, headers, timeout):
        captured["url"] = url
        captured["payload"] = json
        return _Resp()

    monkeypatch.setattr(skills.httpx, "post", _post)
    return captured


def test_escalation_authors_and_registers(isolated_skills, monkeypatch):
    captured = _mock_author(monkeypatch, GENERATED_OK)

    out = skills.skill_write(
        "is_reserved_ip",
        description="report whether an IP address is reserved or special-use",
    )

    # It called the author model with a two-message (system+user) chat request.
    assert captured["url"].endswith("/chat/completions")
    assert captured["payload"]["model"] == "sleuth-skill-coder"
    assert len(captured["payload"]["messages"]) == 2

    # The fence-stripped code was written to disk and the skill went live.
    assert (isolated_skills / "is_reserved_ip.py").is_file()
    assert "is live and callable now" in out
    assert "auto-authored by sleuth-skill-coder" in out
    assert "Smoke test: passed." in out
    skill = skills.REGISTRY.skills.get("is_reserved_ip")
    assert skill is not None and skill.error is None


def test_escalation_requires_code_or_description(isolated_skills, monkeypatch):
    called = _mock_author(monkeypatch, GENERATED_OK)
    out = skills.skill_write("nothing_here")  # neither code nor description
    assert "Provide either `code`" in out
    assert not called  # the author model was never contacted
    assert not (isolated_skills / "nothing_here.py").exists()


def test_escalation_disabled_asks_for_code(isolated_skills, monkeypatch):
    monkeypatch.setattr(config, "SKILL_AUTHOR_ENABLED", False)
    called = _mock_author(monkeypatch, GENERATED_OK)
    out = skills.skill_write("some_tool", description="do something useful")
    assert "skill-author model is disabled" in out
    assert not called


def test_escalation_author_unreachable(isolated_skills, monkeypatch):
    def _boom(url, json, headers, timeout):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(skills.httpx, "post", _boom)
    out = skills.skill_write("some_tool", description="do something useful")
    assert "Could not auto-author skill 'some_tool'" in out
    assert not (isolated_skills / "some_tool.py").exists()


def test_escalation_authored_code_failing_smoke_is_rejected(isolated_skills, monkeypatch):
    _mock_author(monkeypatch, GENERATED_BROKEN)
    out = skills.skill_write("fetch_title", description="fetch a page title")
    # The gate catches the call-time crash and shows the generated code to fix.
    assert "FAILED the smoke test" in out
    assert "NameError" in out
    assert "read_url" in out  # the offending generated code is echoed back


def test_direct_code_still_works_without_author(isolated_skills, monkeypatch):
    # Explicit code must not touch the author model (backward compatibility).
    def _post(*a, **k):
        raise AssertionError("author model must not be called when code is given")

    monkeypatch.setattr(skills.httpx, "post", _post)
    code = 'def echo(text: str) -> str:\n    """Return the text unchanged."""\n    return text\n'
    out = skills.skill_write("echo", code=code)
    assert "is live and callable now" in out
    assert "auto-authored" not in out
