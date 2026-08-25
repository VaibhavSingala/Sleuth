"""MCP server exposing web search to LM Studio.

Runs over stdio. Nothing may be written to stdout except MCP protocol frames,
so all logging is pinned to stderr.
"""

from __future__ import annotations

import logging
import sys

from mcp.server.fastmcp import FastMCP

from . import cache, config, skills
from .analyze import analyze_site as _analyze_site
from .analyze import compare_sites as _compare_sites
from .burp.reports import parse_report as _burp_parse_report
from .burp.scan import scan_status as _burp_scan_status
from .burp.scan import scan_url as _burp_scan_url
from .burp.seed import feed_recon as _burp_feed
from .core import news_search as _news_search
from .extras import calculate as _calculate
from .extras import wikipedia_lookup as _wikipedia
from .wapiti.scan import scan_url as _wapiti_scan_url
from .zap.scan import alerts as _zap_alerts
from .zap.scan import scan_status as _zap_scan_status
from .zap.scan import scan_url as _zap_scan_url
from .zap.seed import feed_recon as _zap_feed
from .core import read_url as _read_url
from .core import research as _research
from .core import web_search as _web_search

# Root stays at WARNING so no dependency can flood LM Studio's server log --
# ddgs and its Rust HTTP client (primp) log every upstream engine request at
# INFO. Only this package's logger is allowed to be chattier.
logging.basicConfig(
    stream=sys.stderr,
    level=logging.WARNING,
    format="[websearch] %(levelname)s %(message)s",
)
logging.getLogger("websearch").setLevel(config.LOG_LEVEL)
for _noisy in ("primp", "ddgs", "httpx", "httpcore", "trafilatura", "urllib3"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

mcp = FastMCP(
    "websearch",
    instructions=(
        "Live web access. Use `research` for questions needing real page content "
        "(it reads HTML and PDFs), `web_search` to find URLs, `news_search` for "
        "recent/time-sensitive topics, `read_url` to read a specific page or PDF, "
        "`analyze_site` to profile one website's technology, keywords and "
        "infrastructure, and `compare_sites` to contrast two sites. When the user "
        "writes `/analyze <url>`, call `analyze_site` on that URL. "
        "For authorised security testing there are Burp Suite tools "
        "(`burp_parse_report`, `burp_feed`, `burp_scan`/`burp_scan_status` -- Burp "
        "Pro, gated), OWASP ZAP tools (`zap_feed`, `zap_alerts`, `zap_scan`/"
        "`zap_scan_status` -- free scanner, gated), and `wapiti_scan` (free "
        "pip-installable scanner, gated). "
        "If a capability you need does not exist, you can author it: `skill_write` "
        "saves a function (Python) or a script (JavaScript, Bash, Ruby, Perl, PHP, "
        "Go, Lua, R) as a new tool (call it via `skill_call` this "
        "session, or reconnect to get it as its own tool), and you can read and "
        "edit this server's own source (`code_read`/`code_write`) and run code "
        "(`python_exec`/`shell_exec`) when those are enabled. "
        "Always prefer these tools over recalling facts for anything current, "
        "version-specific, or that you are unsure about."
    ),
)

# Reserve the built-in tool names so an authored skill can't shadow one.
skills.reserve({
    "web_search", "news_search", "wikipedia", "calculate", "read_url", "research",
    "analyze_site", "compare_sites", "burp_parse_report", "burp_feed", "burp_scan",
    "burp_scan_status", "zap_feed", "zap_alerts", "zap_scan", "zap_scan_status",
    "wapiti_scan", "clear_web_cache", "skill_call",
})


@mcp.tool()
async def web_search(query: str, max_results: int = 5, recency: str = "") -> str:
    """Search the web and return titles, URLs and short snippets.

    Use this to find out *where* information lives. The snippets are short --
    follow up with read_url when you need the actual content.

    Args:
        query: Search keywords. Plain keywords beat full sentences.
        max_results: How many results to return (1-20).
        recency: Optional freshness filter: "day", "week", "month" or "year".
    """
    return await _web_search(query, max_results=max_results, recency=recency or None)


@mcp.tool()
async def news_search(query: str, max_results: int = 6, recency: str = "") -> str:
    """Search recent news articles, with source and date.

    Use for "what's happening with X", breaking developments, or anything
    time-sensitive. For deeper background, follow up with read_url or research.

    Args:
        query: What to look for in the news.
        max_results: How many articles to return (1-20).
        recency: Optional freshness filter: "day", "week", "month" or "year".
    """
    return await _news_search(query, max_results=max_results, recency=recency or None)


@mcp.tool()
async def wikipedia(query: str) -> str:
    """Look up a short, reliable factual summary from Wikipedia.

    Good for definitions, people, places, events and other encyclopedic facts.
    Faster and more reliable than a web search when the answer is encyclopedic.

    Args:
        query: What to look up, e.g. "Alan Turing" or "Model Context Protocol".
    """
    return await _wikipedia(query)


@mcp.tool()
async def calculate(expression: str) -> str:
    """Evaluate an arithmetic or math expression exactly.

    Use this for any calculation instead of doing mental math. Supports
    + - * / // % **, parentheses, and functions like sqrt, sin, log, factorial.

    Args:
        expression: e.g. "(1234 * 5678) / 3" or "sqrt(2) + log(100)".
    """
    return _calculate(expression)


@mcp.tool()
async def read_url(url: str, max_chars: int = 12000) -> str:
    """Fetch a web page and return its main text with navigation and ads stripped.

    Args:
        url: Full URL of the page to read.
        max_chars: Maximum characters of page text to return.
    """
    return await _read_url(url, max_chars=max_chars)


@mcp.tool()
async def research(query: str, max_pages: int = 3, recency: str = "") -> str:
    """Search the web AND read the top pages, returning their content in one call.

    This is the best default for any question that needs real information from
    the web. It does search-then-read for you, so you get citable source text
    back from a single tool call.

    Args:
        query: What you want to find out.
        max_pages: How many pages to open and read (1-8).
        recency: Optional freshness filter: "day", "week", "month" or "year".
    """
    return await _research(query, max_pages=max_pages, recency=recency or None)


@mcp.tool()
async def analyze_site(url: str, detail: str = "standard", max_chars: int = 20000) -> str:
    """Profile one website: technology stack, keywords, SEO and infrastructure.

    Call this when the user writes `/analyze <url>`, or asks what a site is
    built with, what it is about, what keywords it targets, or who hosts it.

    Passive only -- it reads the pages and metadata the site publishes, its
    public DNS records and its TLS certificate. It does not scan ports,
    discover hidden paths or test for vulnerabilities.

    Args:
        url: The site to analyse, e.g. "example.com".
        detail: "summary" (compact), "standard", or "full" (everything).
        max_chars: Truncate the report beyond this length.
    """
    return await _analyze_site(url, detail=detail, max_chars=max_chars)


@mcp.tool()
async def compare_sites(url_a: str, url_b: str, detail: str = "standard") -> str:
    """Compare two websites: technology, infrastructure, security and keywords.

    The competitive-intelligence view -- what each site is built with, what
    each targets, and where they diverge. Passive only, same as analyze_site.

    Args:
        url_a: First site, e.g. "example.com".
        url_b: Second site to compare against.
        detail: "summary", "standard" or "full".
    """
    return await _compare_sites(url_a, url_b, detail=detail)


@mcp.tool()
async def burp_parse_report(path: str) -> str:
    """Triage a Burp Suite XML issue export: findings ranked by severity.

    Reads a report you exported from Burp (Scanner/Target -> Report issues ->
    XML) and summarises it — counts by severity, each issue with its affected
    locations. Read-only.

    Args:
        path: Path to the Burp XML export file.
    """
    return _burp_parse_report(path)


@mcp.tool()
async def burp_feed(url: str) -> str:
    """Feed passive recon (endpoints + CT-log subdomains) into Burp.

    Analyses the site, seeds discovered URLs through the Burp proxy so they
    populate Burp's site map, and returns a target-scope JSON to load in Burp.
    Needs BURP_PROXY set. Does not launch a scan or guess hidden paths. For
    targets you own or are authorised to test.

    Args:
        url: The site to profile and feed into Burp.
    """
    return await _burp_feed(url)


@mcp.tool()
async def burp_scan(url: str, wait: bool = True) -> str:
    """Start an ACTIVE Burp vulnerability scan of a URL (Burp Suite Pro).

    Active testing — only for targets you own or are authorised to test. It is
    disabled unless BURP_ALLOW_ACTIVE_SCAN=true and the Burp Pro REST API is
    enabled. With wait=True it polls until the scan finishes and summarises the
    issues; with wait=False it returns a task id to check later.

    Args:
        url: The target URL to scan.
        wait: Wait for completion and summarise (True) or return a task id (False).
    """
    return await _burp_scan_url(url, wait=wait)


@mcp.tool()
async def burp_scan_status(task_id: str) -> str:
    """Check a running or finished Burp scan by its task id.

    Args:
        task_id: The id returned when the scan was started.
    """
    return await _burp_scan_status(task_id)


@mcp.tool()
async def zap_feed(url: str) -> str:
    """Route recon (endpoints + subdomains) through OWASP ZAP's proxy.

    ZAP passively scans everything proxied, so this populates ZAP's site tree
    and yields passive findings with no attack traffic. Needs ZAP_PROXY set.
    Read results with zap_alerts. For authorised targets.

    Args:
        url: The site to profile and feed into ZAP.
    """
    return await _zap_feed(url)


@mcp.tool()
async def zap_alerts(url: str) -> str:
    """Read the alerts OWASP ZAP has collected for a base URL (free, read-only).

    Args:
        url: The base URL whose alerts to read.
    """
    return await _zap_alerts(url)


@mcp.tool()
async def zap_scan(url: str, wait: bool = True) -> str:
    """Spider then run an ACTIVE OWASP ZAP vulnerability scan of a URL.

    ZAP's scanner is free. This is active testing — only for targets you own
    or are authorised to test, and disabled unless ZAP_ALLOW_ACTIVE_SCAN=true
    with ZAP running in daemon mode.

    Args:
        url: The target URL to scan.
        wait: Wait for completion and summarise (True) or return a scan id (False).
    """
    return await _zap_scan_url(url, wait=wait)


@mcp.tool()
async def zap_scan_status(scan_id: str, url: str = "") -> str:
    """Check an OWASP ZAP active scan by id, with alerts so far.

    Args:
        scan_id: The scan id returned when the scan started.
        url: Optional base URL to include current alerts for.
    """
    return await _zap_scan_status(scan_id, url=url)


@mcp.tool()
async def wapiti_scan(url: str, max_time: int = 0) -> str:
    """Actively scan a URL with Wapiti, a free pip-installable scanner.

    No Burp Pro or ZAP needed -- Wapiti is pure Python (`pip install wapiti3`).
    It crawls the target and tests for XSS, SQLi, command injection, path
    traversal and more, then summarises findings. Active testing: only for
    targets you own or are authorised to test, and disabled unless
    WAPITI_ALLOW_ACTIVE_SCAN=true.

    Args:
        url: The target URL to scan.
        max_time: Optional time cap in seconds (0 = use the configured default).
    """
    return await _wapiti_scan_url(url, max_time=max_time or None)


@mcp.tool()
async def clear_web_cache() -> str:
    """Clear cached search results and pages, forcing the next call to refetch."""
    return f"Cleared {cache.clear()} cached entries."


async def skill_call(name: str, arguments_json: str = "{}") -> str:
    """Call a self-authored skill by name with JSON-encoded arguments.

    A skill authored during this session is not registered as its own MCP tool
    until the client reconnects (LM Studio reads the tool list once, at
    connect). This dispatcher runs it in the meantime. `arguments_json` is a
    JSON object of the skill's parameters, e.g. '{"city": "Paris"}'.
    """
    import json

    skills.refresh()
    try:
        kwargs = json.loads(arguments_json or "{}")
    except json.JSONDecodeError as exc:
        return f"Bad arguments_json: {exc}"
    if not isinstance(kwargs, dict):
        return "arguments_json must be a JSON object."
    handler = skills.skill_handlers().get(name)
    if handler is None:
        listing = skills.skill_list()
        return f"No authored skill named '{name}'.\n\n{listing}"
    return await handler(**kwargs)


def _register_self_extension() -> None:
    """Expose the self-extension tools, and register already-authored skills as
    first-class MCP tools. New skills written mid-session are reachable through
    `skill_call` until the client reconnects."""
    if not config.SKILLS_ENABLED:
        return

    for fn in (skills.skill_write, skills.skill_list, skills.skill_read,
               skills.skill_delete, skills.code_read, skills.code_search):
        mcp.add_tool(fn)
    if config.CODE_EDIT_ENABLED:
        mcp.add_tool(skills.code_write)
        mcp.add_tool(skills.code_revert)
    if config.EXEC_ENABLED:
        mcp.add_tool(skills.python_exec)
        mcp.add_tool(skills.shell_exec)
    mcp.add_tool(skill_call)

    skills.refresh()
    for skill in skills.REGISTRY.valid():
        try:  # a skill with an exotic signature shouldn't stop the server
            mcp.add_tool(skill.fn, name=skill.name, description=skill.description)
        except Exception as exc:  # noqa: BLE001
            logging.getLogger(__name__).warning(
                "could not register skill '%s' as an MCP tool: %s", skill.name, exc
            )


_register_self_extension()


def main() -> None:
    logging.getLogger(__name__).info(
        "starting websearch MCP server (backend=%s, cache=%s)",
        config.active_backend(),
        "on" if config.CACHE_ENABLED else "off",
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
