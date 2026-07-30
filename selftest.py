#!/usr/bin/env python
"""End-to-end check that search, page fetching and the MCP server all work.

    python selftest.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from websearch import config  # noqa: E402
from websearch.core import read_url, research, web_search  # noqa: E402

PASS, FAIL = "[PASS]", "[FAIL]"
failures = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global failures
    print(f"{PASS if ok else FAIL} {name}")
    if detail:
        print("       " + detail.replace("\n", "\n       ")[:400])
    if not ok:
        failures += 1


async def main() -> int:
    # Neutralise any Burp/ZAP proxy from the user's .env: the self-test checks
    # the skill's code, not a live proxy deployment. Otherwise every httpx fetch
    # would route to a proxy that probably isn't running during the test.
    config.BURP_PROXY = ""
    config.ZAP_PROXY = ""

    print(f"backend : {config.active_backend()}")
    print(f"cache   : {'on' if config.CACHE_ENABLED else 'off'} "
          f"(ttl {config.CACHE_TTL_SECONDS}s)\n")

    # 1. Search
    out = await web_search("LM Studio local LLM server", max_results=3)
    check("web_search returns results", "URL: http" in out, out.splitlines()[0] if out else "")

    # 2. Read a stable, fetch-friendly page
    out = await read_url("https://example.com")
    check("read_url extracts text", "Example Domain" in out, out[:200])

    # 3. Full research pipeline
    out = await research("what is the Model Context Protocol", max_pages=2)
    check("research reads pages", "## Source [1]" in out, out[:250])

    # 4. SSRF guard
    out = await read_url("http://169.254.169.254/latest/meta-data/")
    check("blocks internal addresses", "Refusing to fetch private" in out, out[:200])

    # 5. PDF reading
    out = await read_url("https://arxiv.org/pdf/1706.03762", max_chars=800)
    check("read_url extracts PDF text", "Attention Is All You Need" in out, out[:150])

    # 6. News search
    from websearch.core import news_search

    out = await news_search("technology", max_results=3)
    check("news_search returns articles", "URL: http" in out, out.splitlines()[0] if out else "")

    # 7. Site comparison
    from websearch.analyze import analyze_site, compare_sites

    out = await compare_sites("example.com", "example.org", detail="summary")
    check("compare_sites contrasts two sites", "Site comparison" in out and "Technology" in out, "")

    # 8. Tolerant tool-call parsing (offline unit check)
    from websearch.agent import _parse_text_tool_calls

    recovered = _parse_text_tool_calls(
        '<tool_call>{"name": "web_search", "arguments": {"query": "x"}}</tool_call>'
    )
    check("recovers tool calls emitted as text",
          len(recovered) == 1 and recovered[0]["function"]["name"] == "web_search", "")
    check("ignores non-tool JSON in answers",
          _parse_text_tool_calls('answer with {"name": "Guido"}') == [], "")

    # 9. Burp integration (offline: parse a sample export, gate, scope)
    import tempfile
    from websearch.burp.reports import parse_report
    from websearch.burp.scan import scan_url
    from websearch.burp.seed import build_scope

    sample = (
        '<?xml version="1.0"?><issues><issue><name>SQL injection</name>'
        '<host>https://t.example</host><location>/x?id=1</location>'
        '<severity>High</severity><confidence>Certain</confidence></issue></issues>'
    )
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as fh:
        fh.write(sample)
        sample_path = fh.name
    out = parse_report(sample_path)
    check("burp parse_report triages XML", "SQL injection" in out and "High" in out, "")

    config.BURP_ALLOW_ACTIVE_SCAN = False
    out = await scan_url("https://t.example")
    check("burp active scan gated off by default", "BURP_ALLOW_ACTIVE_SCAN" in out, "")

    scope_host = build_scope("t.example")["target"]["scope"]["include"][0]["host"]
    check("burp build_scope emits host regex", "example" in scope_host and scope_host.startswith("^"), "")

    # 9b. OWASP ZAP integration (offline: gate)
    from websearch.zap.scan import scan_url as zap_scan_url

    config.ZAP_ALLOW_ACTIVE_SCAN = False
    out = await zap_scan_url("https://t.example")
    check("zap active scan gated off by default", "ZAP_ALLOW_ACTIVE_SCAN" in out, "")

    from websearch.wapiti.scan import scan_url as wapiti_scan_url

    config.WAPITI_ALLOW_ACTIVE_SCAN = False
    out = await wapiti_scan_url("https://t.example")
    check("wapiti active scan gated off by default", "WAPITI_ALLOW_ACTIVE_SCAN" in out, "")

    # 9c. Smarter tools: calculator is exact and refuses code injection
    from websearch.extras import calculate

    check("calculate is exact", calculate("2 ** 16") == "2 ** 16 = 65536", "")
    check("calculate blocks injection", "Cannot evaluate" in calculate("__import__('os')"), "")

    # 9d. Conversation store: create -> save -> load -> delete (temp dir)
    import tempfile as _tf
    from pathlib import Path as _P
    from websearch import store

    store.CONV_DIR = _P(_tf.mkdtemp())
    conv = store.new_conversation()
    conv["title"] = "selftest"
    conv["turns"].append({"role": "user", "content": "hi"})
    store.save(conv)
    check("store lists saved conversation",
          any(c["id"] == conv["id"] for c in store.list_conversations()), "")
    check("store loads it back", (store.load(conv["id"]) or {}).get("title") == "selftest", "")
    store.delete(conv["id"])
    check("store deletes it", store.load(conv["id"]) is None, "")

    # 10. Site analysis: fingerprinting, DNS/TLS and keyword extraction
    out = await analyze_site("wordpress.org", detail="standard")
    check("analyze_site detects CMS", "WordPress" in out, "")
    check("analyze_site reads DNS + TLS",
          "DNS records" in out and "TLS certificate" in out, "")
    check("analyze_site extracts keywords", "Top terms" in out, "")

    # Soft-404 guard: a site that 200s on everything must not be reported as
    # publishing a security.txt.
    out = await analyze_site("example.com", detail="summary")
    check("analyze_site rejects soft-404 metadata", "security.txt" not in out, "")

    # 11. Chat web app: routes wired, streaming loop reusable
    from websearch import webchat
    from websearch.agent import run_stream

    routes = {r.path for r in webchat.app.routes}
    check("webchat exposes its routes",
          {"/", "/api/chat", "/api/models", "/api/status", "/api/conversations"} <= routes,
          f"found: {sorted(routes)}")
    check("agent exposes a streaming loop for the web UI",
          callable(run_stream) and __import__("inspect").isasyncgenfunction(run_stream), "")

    # Every tool schema's params must be accepted by its handler (catches
    # schema/signature drift like zap_alerts(url) vs alerts(baseurl)).
    import inspect as _inspect
    from websearch import agent as _agent

    mismatches = []
    for _tool in _agent.TOOLS:
        _fn = _tool["function"]
        _handler = _agent.HANDLERS.get(_fn["name"])
        if _handler is None:
            mismatches.append(f"{_fn['name']}: no handler")
            continue
        _sig = _inspect.signature(_handler)
        _kw = any(p.kind == p.VAR_KEYWORD for p in _sig.parameters.values())
        for _pname in _fn.get("parameters", {}).get("properties", {}):
            if _pname not in _sig.parameters and not _kw:
                mismatches.append(f"{_fn['name']}.{_pname}")
    check("every tool schema matches its handler signature", not mismatches, str(mismatches))

    # 12. MCP server imports and registers its tools
    from websearch.server import mcp

    tools = {t.name for t in await mcp.list_tools()}
    expected = {
        "web_search", "news_search", "read_url", "research",
        "analyze_site", "compare_sites", "wikipedia", "calculate", "clear_web_cache",
        "burp_parse_report", "burp_feed", "burp_scan", "burp_scan_status",
        "zap_feed", "zap_alerts", "zap_scan", "zap_scan_status", "wapiti_scan",
    }
    check("MCP server exposes tools", expected <= tools, f"found: {sorted(tools)}")

    # 13. Self-extension: authored skills, code self-editing, execution.
    # Runs entirely in a temp dir so it never touches real source (offline).
    import shutil as _shutil
    import tempfile as _tf2
    from pathlib import Path as _P2
    from websearch import skills as _skills

    _skdir = _P2(_tf2.mkdtemp())
    config.SKILLS_ENABLED = True
    config.CODE_EDIT_ENABLED = True
    config.EXEC_ENABLED = True
    config.SKILLS_DIR = _skdir
    config.BACKUP_DIR = _skdir / ".backups"
    config.CODE_ROOT = _skdir
    _skills.REGISTRY.dir = _skdir
    _skills.REGISTRY.skills = {}

    _code = ('def add_two(a: int, b: int):\n'
             '    """Add two integers."""\n'
             '    return a + b\n')
    _msg = _skills.skill_write("add_two", _code)
    check("skill_write authors a callable tool", "live and callable" in _msg, _msg[:120])

    _skills.refresh()
    _names = {t["function"]["name"] for t in _agent.active_tools()}
    check("authored skill appears in the agent tool list", "add_two" in _names, "")
    _h = _agent.resolve_handler("add_two")
    check("authored skill invokes with typed args",
          _h is not None and (await _h(a=2, b=3)) == "5", "")

    check("skill_write refuses a built-in tool name",
          "built-in tool name" in _skills.skill_write("research", _code), "")
    check("code_read blocks path traversal out of CODE_ROOT",
          "outside CODE_ROOT" in _skills.code_read("../../etc/passwd"), "")

    _skills.code_write("mod.py", "x = 1\n")
    _revert = _skills.code_write("mod.py", "def broken(:\n")
    check("code_write auto-reverts a syntax error",
          "syntax error" in _revert and (_skdir / "mod.py").read_text() == "x = 1\n", "")
    check("python_exec runs against the live package",
          "45" in await _skills.python_exec("result = sum(range(10))"), "")
    check("MCP server exposes the self-extension tools",
          {"skill_write", "skill_call", "code_write", "python_exec"} <= tools, "")

    _shutil.rmtree(_skdir, ignore_errors=True)

    print(f"\n{'All checks passed.' if not failures else f'{failures} check(s) failed.'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
