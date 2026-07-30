"""Configuration for the web-search skill.

Every setting is overridable with an environment variable, or by putting
``KEY=value`` lines in a ``.env`` file at the project root. Environment
variables win over ``.env``.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    """Minimal .env loader so users can keep API keys in a file, not in mcp.json."""
    env_file = PROJECT_ROOT / ".env"
    if not env_file.is_file():
        return
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")
        # Real environment variables take precedence over the file.
        os.environ.setdefault(key, value)


_load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name) or default)
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name).lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on")


# --- Search backend -------------------------------------------------------
# "auto" picks the best backend for which credentials are present, falling
# back to DuckDuckGo (which needs no key).
BACKEND = _env("WEBSEARCH_BACKEND", "auto").lower()

BRAVE_API_KEY = _env("BRAVE_API_KEY")
TAVILY_API_KEY = _env("TAVILY_API_KEY")
SEARXNG_URL = _env("SEARXNG_URL").rstrip("/")

# Empty means "let the backend decide" -- the legacy "wt-wt" value makes
# ddgs' newer multi-engine aggregator build broken per-engine URLs.
DEFAULT_REGION = _env("WEBSEARCH_REGION", "")
MAX_RESULTS = _env_int("WEBSEARCH_MAX_RESULTS", 5)
RESULTS_HARD_CAP = _env_int("WEBSEARCH_RESULTS_HARD_CAP", 20)

# --- Page fetching --------------------------------------------------------
USER_AGENT = _env(
    "WEBSEARCH_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36",
)
HTTP_TIMEOUT = _env_float("WEBSEARCH_TIMEOUT", 20.0)
MAX_PAGE_BYTES = _env_int("WEBSEARCH_MAX_PAGE_BYTES", 3_000_000)
MAX_PAGE_CHARS = _env_int("WEBSEARCH_MAX_PAGE_CHARS", 12_000)

# PDFs are fetched whole (the cross-reference table lives at the end, so a
# truncated PDF is unparseable) up to this size, then refused.
READ_PDF = _env_bool("WEBSEARCH_READ_PDF", True)
MAX_PDF_BYTES = _env_int("WEBSEARCH_MAX_PDF_BYTES", 15_000_000)

# Transient-failure retry (network blips, 429/5xx). 0 disables.
HTTP_RETRIES = _env_int("WEBSEARCH_HTTP_RETRIES", 2)

# Obey robots.txt when fetching pages. On by default -- it is the polite
# default and keeps an automated agent from hammering paths a site asks
# crawlers to avoid. Analysis of the site's own metadata is exempt.
RESPECT_ROBOTS = _env_bool("WEBSEARCH_RESPECT_ROBOTS", True)

# Retry a thin/JS-only page through a headless browser (Playwright). Off by
# default because it needs a ~300 MB Chromium download; enable once installed.
JS_RENDER = _env_bool("WEBSEARCH_JS_RENDER", False)
JS_RENDER_TIMEOUT = _env_float("WEBSEARCH_JS_RENDER_TIMEOUT", 20.0)
# A static fetch yielding fewer than this many chars is treated as "thin" and
# retried with the browser when JS_RENDER is on.
JS_RENDER_MIN_CHARS = _env_int("WEBSEARCH_JS_RENDER_MIN_CHARS", 500)

# How many pages `research` opens and reads per query.
RESEARCH_PAGES = _env_int("WEBSEARCH_RESEARCH_PAGES", 3)
RESEARCH_CHARS_PER_PAGE = _env_int("WEBSEARCH_RESEARCH_CHARS", 4_000)

# Certificate Transparency (crt.sh) lookup for /analyze. It is best-effort
# enrichment and crt.sh is frequently slow, so the wait is kept short.
SUBDOMAIN_TIMEOUT = _env_float("WEBSEARCH_SUBDOMAIN_TIMEOUT", 12.0)

# Refuse to fetch private/loopback addresses. Only turn this off on a
# trusted network -- it is what stops a web page from talking the model
# into probing your LAN or cloud metadata endpoints.
BLOCK_PRIVATE_ADDRESSES = _env_bool("WEBSEARCH_BLOCK_PRIVATE", True)

# --- Logging --------------------------------------------------------------
# Applies to this package's own logger. Dependencies are capped at WARNING
# regardless, so LM Studio's server log stays readable.
LOG_LEVEL = _env("WEBSEARCH_LOG_LEVEL", "INFO").upper()

# --- Burp Suite integration -----------------------------------------------
# Route the skill's target-facing traffic (read_url / research / analyze_site)
# through Burp's proxy so every request shows up in Burp for inspection and
# replay. Empty = no proxying (default). Example: http://127.0.0.1:8080
BURP_PROXY = _env("BURP_PROXY").rstrip("/")
# Burp intercepts TLS with its own CA, so verifying against the real cert
# fails while proxying. Off by default when a proxy is set; flip on if you
# have installed Burp's CA into the trust store.
BURP_PROXY_VERIFY = _env_bool("BURP_PROXY_VERIFY", False)

# Burp Suite Professional REST API (Settings -> Suite -> REST API).
BURP_API_URL = _env("BURP_API_URL", "http://127.0.0.1:1337").rstrip("/")
BURP_API_KEY = _env("BURP_API_KEY")
# Optional named scan configuration defined in Burp (e.g. "Lightweight").
BURP_SCAN_CONFIG = _env("BURP_SCAN_CONFIG")

# Active vulnerability scanning is intrusive. It must be explicitly enabled,
# and only ever pointed at targets you own or are authorised to test. This
# gate is a deliberate speed-bump, not a substitute for having permission.
BURP_ALLOW_ACTIVE_SCAN = _env_bool("BURP_ALLOW_ACTIVE_SCAN", False)

# --- OWASP ZAP integration ------------------------------------------------
# ZAP is the free alternative to Burp Pro: its proxy, API and active scanner
# are all free. Proxy and API share one port (default 8090 in daemon mode).
ZAP_PROXY = _env("ZAP_PROXY").rstrip("/")
ZAP_PROXY_VERIFY = _env_bool("ZAP_PROXY_VERIFY", False)
# API base; defaults to the proxy URL, or ZAP's usual daemon port.
ZAP_API_URL = (_env("ZAP_API_URL") or _env("ZAP_PROXY") or "http://127.0.0.1:8090").rstrip("/")
ZAP_API_KEY = _env("ZAP_API_KEY")
ZAP_ALLOW_ACTIVE_SCAN = _env_bool("ZAP_ALLOW_ACTIVE_SCAN", False)

# --- Wapiti (pip-installable active scanner; no Java, no separate app) -----
# Same gate as the others: active testing, authorised targets only.
WAPITI_ALLOW_ACTIVE_SCAN = _env_bool("WAPITI_ALLOW_ACTIVE_SCAN", False)
WAPITI_MAX_SCAN_TIME = _env_int("WAPITI_MAX_SCAN_TIME", 180)  # seconds, hard cap
WAPITI_SCOPE = _env("WAPITI_SCOPE", "folder")  # page | folder | domain | url
# Attack modules; blank = wapiti's default set. e.g. "xss,sql,exec,file,redirect"
WAPITI_MODULES = _env("WAPITI_MODULES")

# --- Self-extension (skills the model writes for itself) ------------------
# The model can author Python functions into SKILLS_DIR and call them as tools
# on the very next turn, read and patch this package's own source, and execute
# arbitrary Python or shell. That is a lot of rope: this agent reads untrusted
# web pages, so a prompt-injected page that talks the model into writing a
# skill gets arbitrary code execution with this process's environment -- .env
# API keys included. Each capability has its own kill-switch below so you can
# narrow it without touching code.
SKILLS_ENABLED = _env_bool("SLEUTH_SKILLS", True)
SKILLS_DIR = Path(_env("SLEUTH_SKILLS_DIR", str(PROJECT_ROOT / "skills")))

# Editing the package's own source. CODE_ROOT bounds what the code_* tools may
# reach; point it elsewhere to work on another tree, or narrow it to sandbox
# the model into a subdirectory.
CODE_EDIT_ENABLED = _env_bool("SLEUTH_ALLOW_SELF_EDIT", True)
CODE_ROOT = Path(_env("SLEUTH_CODE_ROOT", str(PROJECT_ROOT)))

# Every write is snapshotted first, so code_revert can undo a bad edit and a
# file that stops parsing is rolled back automatically.
BACKUP_DIR = Path(_env("SLEUTH_BACKUP_DIR", str(PROJECT_ROOT / ".backups")))
BACKUP_KEEP = _env_int("SLEUTH_BACKUP_KEEP", 20)

# Arbitrary execution. python_exec runs in-process against the live package
# (that is the point -- it can call what it just wrote); shell_exec spawns a
# subprocess, so its timeout is the only one that can actually kill the work.
EXEC_ENABLED = _env_bool("SLEUTH_ALLOW_EXEC", True)
EXEC_TIMEOUT = _env_float("SLEUTH_EXEC_TIMEOUT", 30.0)
SKILL_TIMEOUT = _env_float("SLEUTH_SKILL_TIMEOUT", 60.0)

# --- Cache ----------------------------------------------------------------
CACHE_ENABLED = _env_bool("WEBSEARCH_CACHE", True)
CACHE_DIR = Path(_env("WEBSEARCH_CACHE_DIR", str(PROJECT_ROOT / ".cache")))
CACHE_TTL_SECONDS = _env_int("WEBSEARCH_CACHE_TTL", 900)  # 15 minutes

# --- Local LLM server (used by agent.py only) -----------------------------
# "auto" probes LM Studio (:1234) then Ollama (:11434). Set a provider name
# or an explicit LLM_BASE_URL to skip detection.
# The older LMSTUDIO_* names still work so existing setups keep running.
LLM_PROVIDER = _env("LLM_PROVIDER", "auto").lower()
LLM_BASE_URL = (_env("LLM_BASE_URL") or _env("LMSTUDIO_BASE_URL")).rstrip("/")
LLM_API_KEY = _env("LLM_API_KEY") or _env("LMSTUDIO_API_KEY")
LLM_MODEL = _env("LLM_MODEL") or _env("LMSTUDIO_MODEL")  # empty -> auto-pick


def active_backend() -> str:
    """Resolve ``BACKEND=auto`` into a concrete backend name."""
    if BACKEND != "auto":
        return BACKEND
    if TAVILY_API_KEY:
        return "tavily"
    if BRAVE_API_KEY:
        return "brave"
    if SEARXNG_URL:
        return "searxng"
    return "duckduckgo"
