"""Auto-review classifier for host-damaging execution.

Mirrors Cursor Auto-review's job: let the agent keep working without a human
clicking Approve on every call, while stopping actions that would wreck *this
machine*. Authorised work against an engagement **target** (HTTP to a URL,
ssh/adb to a remote host, ZAP/Burp/Wapiti, payload skills) is allowed even
when the payload is "malicious" from the target's point of view.

Order of checks (same shape as Cursor's allowlist → review):

1. Built-in tools that never execute untrusted host code skip review.
2. Remote sessions (ssh/adb/kubectl to a non-loopback host) are treated as
   the target and stripped before host-damage rules run.
3. Remaining text is scanned for local disk/process/boot destruction.

This is best-effort static review, not a sandbox. Keep ``SLEUTH_ALLOW_EXEC``
and the other kill-switches for defence in depth.
"""

from __future__ import annotations

import ast
import json
import re
import socket
from dataclasses import dataclass
from pathlib import Path

from . import config

BLOCK_PREFIX = "Blocked by auto-review"


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str = ""
    rule: str = ""

    def message(self) -> str:
        if self.allowed:
            return ""
        extra = f" [{self.rule}]" if self.rule else ""
        return (
            f"{BLOCK_PREFIX}{extra}: {self.reason}\n"
            "Auto-review blocks code that would damage the Sleuth host "
            "(disk wipe, piping a download into a local shell, killing PID 1, "
            "overwriting /etc, disabling this gate). Work aimed at an engagement "
            "target — HTTP to a URL, ssh/adb to a remote host, scanner tools — is allowed."
        )


ALLOW = Verdict(True)

_ALLOWLIST_TOOLS = {
    "web_search", "news_search", "read_url", "research", "wikipedia", "calculate",
    "analyze_site", "compare_sites", "quick_recon", "compare_and_summarize",
    "burp_parse_report", "burp_feed", "burp_scan", "burp_scan_status",
    "zap_feed", "zap_alerts", "zap_scan", "zap_scan_status",
    "wapiti_scan", "clear_web_cache",
    "skill_list", "skill_read", "skill_delete",
    "code_read", "code_search",
}

_LOCAL_HOSTS = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0", "ip6-localhost",
    "host.docker.internal",
}

# Host-damage patterns. Do NOT match "attack" vocabulary or /etc/passwd inside
# a target URL (directory traversal checks are target-directed).
_HOST_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("wipe-root", re.compile(
        r"\b(?:rm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*|"
        r"rmdir|"
        r"del\s+/[fsq]|"
        r"rd\s+/s|"
        r"Remove-Item\b[^\n]*-Recurse)"
        r"\s+(?:--\s+)?"
        r"(?:[\"']?/(?:[\"'\s]|$)|[\"']?/\*|"
        r"~(?:/|[\"'\s]|$)|\$HOME\b|/home(?:/|[\"'\s]|$)|"
        r"/etc(?:/|[\"'\s]|$)|/usr(?:/|[\"'\s]|$)|/var(?:/|[\"'\s]|$)|"
        r"/boot\b|/root(?:/|[\"'\s]|$)|"
        r"C:\\(?:Windows|Users)\\\\|%USERPROFILE%)",
        re.I,
    )),
    ("disk-device", re.compile(
        r"\b(?:mkfs(?:\.\w+)?|fdisk|parted|diskpart)\b|"
        r"\bformat\s+[a-z]:|"
        r"\bdd\b[^\n]*\bof\s*=\s*/dev/|"
        r">\s*/dev/sd[a-z]\b|"
        r"\bshred\s+[^\n]*/dev/",
        re.I,
    )),
    ("fork-bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;")),
    ("fork-bomb-py", re.compile(r"os\.fork\s*\(")),
    ("halt-host", re.compile(
        r"(?:^|[;|&]\s*|sudo\s+)(?:shutdown|reboot|poweroff|halt)\b",
        re.I | re.M,
    )),
    ("kill-init", re.compile(r"\bkill\s+-9\s+1\b|\bkillall\s+-9\s+init\b", re.I)),
    ("pipe-to-shell", re.compile(
        r"(?:curl|wget|fetch)\b[^\n]{0,200}\|\s*(?:ba)?sh\b",
        re.I,
    )),
    ("decode-to-shell", re.compile(
        r"base64\s+(?:-d|--decode|-D)\b[^\n]{0,80}\|\s*(?:ba)?sh\b",
        re.I,
    )),
    ("write-etc", re.compile(
        r"(?:>>?|tee\s+(?:-a\s+)?)\s*/etc/|"
        r"open\s*\(\s*['\"]/etc/[^'\"]+['\"]\s*,\s*['\"][aw]",
        re.I,
    )),
    ("chmod-system", re.compile(
        r"\bchmod\s+(?:-R\s+)?[0-7]{3,4}\s+/|"
        r"\bchown\s+-R\s+\S+\s+/",
        re.I,
    )),
    ("iptables-flush", re.compile(r"\b(?:iptables|nft)\s+(?:-F|--flush)\b", re.I)),
    ("crontab-wipe", re.compile(r"\bcrontab\s+-r\b", re.I)),
    ("disable-gate", re.compile(r"\bAUTO_REVIEW\s*=\s*False\b")),
]

_PY_WIPE_CALLS = {"rmtree", "removedirs", "rmdir"}
_PY_EXEC_CALLS = {"system", "popen", "call", "run", "Popen", "check_output", "check_call"}

_SSH_RE = re.compile(
    r"\b(?:ssh|scp)\b(?P<opts>(?:\s+-\S+(?:\s+\S+)?)*)\s+(?P<dest>\S+)(?P<rest>[^\n]*)",
    re.I,
)
_ADB_SHELL_RE = re.compile(r"\badb\b[^\n]*\bshell\b", re.I)
_KUBE_EXEC_RE = re.compile(r"\bkubectl\b[^\n]*\bexec\b", re.I)


def _local_hosts() -> set[str]:
    hosts = set(_LOCAL_HOSTS)
    try:
        hosts.add(socket.gethostname().lower())
    except OSError:
        pass
    try:
        hosts.add(socket.getfqdn().lower())
    except OSError:
        pass
    extra = (getattr(config, "AUTO_REVIEW_LOCAL_HOSTS", "") or "")
    for part in extra.split(","):
        part = part.strip().lower()
        if part:
            hosts.add(part)
    return hosts


def _host_of(token: str) -> str:
    token = token.strip().strip("\"'")
    if "@" in token and not token.startswith("@"):
        token = token.rsplit("@", 1)[-1]
    if token.startswith("[") and "]" in token:
        token = token[1:token.index("]")]
    if ":" in token and token.count(":") == 1:
        token = token.split(":", 1)[0]
    return token.lower()


def _is_local_host(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in _local_hosts():
        return True
    if host.endswith(".localhost"):
        return True
    return False


def _strip_target_sessions(text: str) -> str:
    """Drop ssh/adb/kubectl-to-remote chunks so target-side rm is not scored."""

    def ssh_sub(match: re.Match) -> str:
        dest = _host_of(match.group("dest"))
        if dest.startswith("-"):
            return match.group(0)
        if _is_local_host(dest):
            return match.group("rest")
        return " "

    text = _SSH_RE.sub(ssh_sub, text)
    text = _ADB_SHELL_RE.sub(" ", text)
    text = _KUBE_EXEC_RE.sub(" ", text)
    return text


def _ast_strings(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return ""
    chunks: list[str] = []

    class Collector(ast.NodeVisitor):
        def visit_Constant(self, node: ast.Constant) -> None:
            if isinstance(node.value, str):
                chunks.append(node.value)

        def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    chunks.append(part.value)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            name = ""
            func = node.func
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name in _PY_WIPE_CALLS or name in _PY_EXEC_CALLS:
                chunks.append(name)
            self.generic_visit(node)

    Collector().visit(tree)
    return "\n".join(chunks)


def classify_text(text: str) -> Verdict:
    """Classify a command or source blob. Target-session inner commands are ignored."""
    if not text or not str(text).strip():
        return ALLOW
    original = str(text)
    scanned = _strip_target_sessions(original)
    scanned_plus = scanned + "\n" + _ast_strings(original)
    for rule, pattern in _HOST_RULES:
        if pattern.search(scanned_plus) or pattern.search(scanned):
            # HTTP traversal tests mention /etc/passwd on the TARGET. Only the
            # write-etc / wipe rules should fire; wipe-root requires rm/del.
            return Verdict(
                False,
                "this looks like it would damage or take over the Sleuth host "
                "rather than the engagement target.",
                rule,
            )
    # os.remove("/") / pathlib unlink of /
    if re.search(
        r"(?:os\.remove|os\.unlink|Path\([^)]*\)\.unlink)\s*\(\s*['\"]/(?:['\"]|home|etc)",
        scanned,
        re.I,
    ):
        return Verdict(False, "this would delete files on the Sleuth host.", "py-unlink-root")
    if re.search(r"shutil\.rmtree\s*\(\s*['\"]/(?:['\"]|\s|,)", scanned):
        return Verdict(False, "this would recursively delete host directories.", "py-rmtree-root")
    return ALLOW


def _blob(arguments: dict | None, extra: str = "") -> str:
    parts = [extra or ""]
    if arguments:
        try:
            parts.append(json.dumps(arguments, default=str))
        except (TypeError, ValueError):
            parts.append(str(arguments))
        for key in ("code", "command", "content", "script", "source"):
            val = arguments.get(key)
            if isinstance(val, str):
                parts.append(val)
    return "\n".join(p for p in parts if p)


def _protected_write(path: str) -> bool:
    try:
        resolved = Path(path)
        if not resolved.is_absolute():
            resolved = (config.CODE_ROOT / path).resolve()
        else:
            resolved = resolved.resolve()
        locked = (config.CODE_ROOT / "websearch" / "auto_review.py").resolve()
        return resolved == locked
    except (OSError, RuntimeError):
        return Path(path).name == "auto_review.py"


def review(name: str, arguments: dict | None = None, *, source: str = "") -> Verdict:
    """Classify a tool call. Safe built-ins skip; exec/write/skills are reviewed."""
    if not getattr(config, "AUTO_REVIEW", True):
        return ALLOW
    arguments = arguments or {}
    tool = (name or "").strip()
    if tool in _ALLOWLIST_TOOLS:
        return ALLOW

    if tool == "code_write":
        path = str(arguments.get("path") or "")
        if _protected_write(path):
            return Verdict(
                False,
                "the auto-review classifier file is protected from code_write.",
                "protected-file",
            )
        return classify_text(_blob(arguments, source))

    if tool == "code_revert":
        path = str(arguments.get("path") or "")
        if _protected_write(path):
            return Verdict(
                False,
                "the auto-review classifier file is protected from code_revert.",
                "protected-file",
            )
        return ALLOW

    if tool in {"python_exec", "shell_exec", "skill_write"}:
        blob = _blob(arguments, source)
        if tool == "shell_exec" and re.search(r"auto_review\.py", blob, re.I):
            return Verdict(
                False,
                "the auto-review classifier file is protected from shell_exec.",
                "protected-file",
            )
        return classify_text(blob)

    # Authored skills and anything else that might run host code: scan source
    # plus arguments. Target HTTP in the same blob does not override a wipe.
    return classify_text(_blob(arguments, source))


def guard(name: str, arguments: dict | None = None, *, source: str = "") -> str | None:
    """Return a block message, or None if the call may run."""
    verdict = review(name, arguments, source=source)
    if verdict.allowed:
        return None
    return verdict.message()
