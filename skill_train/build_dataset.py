#!/usr/bin/env python3
"""Build a skill-authoring SFT dataset for Qwen2.5-Coder-3B (trained with Soup).

Goal: teach a small code model to WRITE new Sleuth skills on demand — i.e. turn
"I need a tool that does X" into a function that satisfies Sleuth's skill
contract (see websearch/skills.py::skill_write):

  * define a top-level function named the same as the skill (or `run`);
  * type-hint the args (they become the tool arguments);
  * write a Google-style docstring (Args/Returns) — it becomes the tool
    description;
  * return a dict or str; other Sleuth tools (read_url, compare_sites, ws.*)
    are already in scope and may be called directly.

Source of truth = the real, working skills in ../skills. Each one is a gold
(instruction -> code) example. We paraphrase the instruction a few ways to widen
coverage. Output is Alpaca-format JSONL, which Soup auto-detects.

Output: skill_train/data/sleuth_skills.jsonl
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SKILLS_DIR = ROOT.parent / "skills"
OUT = ROOT / "data" / "sleuth_skills.jsonl"

# The contract, stated once. Baked into every example so the model learns the
# rules, not just the surface form of these particular skills.
SYSTEM = (
    "You are Sleuth's skill author. When a capability does not exist yet, you "
    "write a new Sleuth skill as a single, SELF-CONTAINED code file. Rules: "
    "define ONE top-level function named exactly like the skill (or `run`); "
    "type-hint every argument (they become the tool's arguments); write a "
    "Google-style docstring with Args and Returns (it becomes the tool "
    "description); return a dict or str. Import everything you use at the top of "
    "the file — nothing is injected into scope. For deterministic work use the "
    "Python standard library (ipaddress, hashlib, base64, json, re, socket, ssl, "
    "urllib, datetime); NEVER pull in an LLM or agent framework (langchain, "
    "openai, ...) to do plain computation. Handle bad input by returning an "
    "{'error': ...} dict rather than raising. Gate any active/intrusive skill "
    "behind the SLEUTH_ALLOW_ACTIVE_SKILLS env var. Output only the code file, "
    "no prose."
)

# Skills too large/complex to be single-shot generation targets for a 3B model;
# they would dominate the loss. Excluded from the training set.
SKIP = {
    "_active_gate.py", "self_train.py", "apk_device.py",
    "maltego.py", "apk_analyze.py",
}

# Tool names some older skills call as if injected into scope. Nothing is
# actually injected (verified against websearch/skills.py), so those skills are
# latently broken and teach the wrong pattern — exclude them from training.
INJECTED_TOOLS = (
    "read_url", "web_search", "research", "compare_sites", "analyze_site",
    "news_search", "wikipedia", "xss_payload_injection",
)


def _uses_injected_tools(source: str) -> bool:
    """True if the skill calls a Sleuth tool it never imports (assumes scope)."""
    if re.search(r"\bws\.", source):  # the `ws` package handle, never injected
        return True
    for tool in INJECTED_TOOLS:
        called = re.search(rf"\b{tool}\s*\(", source)
        imported = re.search(rf"\bimport\b.*\b{tool}\b", source)
        if called and not imported:
            return True
    return False

# Instruction templates — {name} = skill name, {summary} = docstring one-liner.
TEMPLATES = [
    "Write a Sleuth skill named `{name}` that {summary}",
    "I need a new tool that {summary} Call it `{name}`.",
    "There's no tool for this yet: {summary} Author a skill `{name}` for it.",
    "Create a `{name}` skill. It should {summary}",
]


def summarise(docstring: str | None, name: str) -> str:
    """First sentence of the docstring, lower-cased, as a capability phrase."""
    if not docstring:
        return f"provides the {name.replace('_', ' ')} capability."
    # Collapse wrapped lines to one string, then stop at the first sentence end
    # (the summary line often wraps across several physical lines).
    text = " ".join(docstring.strip().split())
    first = text.split(". ")[0].strip().rstrip(",")
    if not first.endswith("."):
        first += "."
    return first[0].lower() + first[1:]


def top_function_doc(source: str, stem: str) -> tuple[str | None, str | None]:
    """Return (name, docstring) of the skill's entry function.

    The contract names the entry function after the file (or `run`). Prefer that
    match so we don't train on a private helper (leading-underscore) that merely
    happens to be defined first.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None, None
    defs = [n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    by_name = {n.name: n for n in defs}
    for candidate in (stem, "run"):
        if candidate in by_name:
            n = by_name[candidate]
            return n.name, ast.get_docstring(n)
    # Fall back to the first PUBLIC top-level def.
    for n in defs:
        if not n.name.startswith("_"):
            return n.name, ast.get_docstring(n)
    return None, None


# Correct, self-contained gold skills authored by hand — stdlib only, following
# the contract. These fill the capability gaps the model botched (it reached for
# langchain to expand a CIDR) and model the stdlib-first behaviour we want.
SYNTHETIC: list[tuple[str, str]] = [
    ("cidr_expand", '''\
import ipaddress


def cidr_expand(cidr: str) -> dict:
    """Expand a CIDR range into the list of host IP addresses it contains.

    Args:
        cidr: CIDR notation, e.g. "192.168.1.0/24".

    Returns:
        dict with the network, host count, and the host IPs (capped at 1024),
        or an {"error": ...} dict for invalid input.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return {"error": f"invalid CIDR '{cidr}': {exc}"}
    hosts = [str(ip) for ip in net.hosts()]
    return {"network": str(net), "num_hosts": len(hosts), "hosts": hosts[:1024]}
'''),
    ("jwt_decode", '''\
import base64
import json


def jwt_decode(token: str) -> dict:
    """Decode a JWT's header and claims WITHOUT verifying the signature.

    Args:
        token: The compact JWT string (header.payload.signature).

    Returns:
        dict with "header" and "claims", or an {"error": ...} dict.
    """
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "not a JWT: expected header.payload.signature"}

    def _seg(seg: str) -> dict:
        pad = "=" * (-len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg + pad))

    try:
        return {"header": _seg(parts[0]), "claims": _seg(parts[1])}
    except (ValueError, json.JSONDecodeError) as exc:
        return {"error": f"could not decode JWT: {exc}"}
'''),
    ("bulk_file_hash", '''\
import hashlib
import os


def bulk_file_hash(directory: str) -> dict:
    """Compute the SHA-256 of every file under a directory, recursively.

    Args:
        directory: Path to the folder to hash.

    Returns:
        dict mapping each file path to its SHA-256 hex digest (or an error
        string for files that could not be read).
    """
    manifest: dict = {}
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            path = os.path.join(root, fname)
            try:
                digest = hashlib.sha256()
                with open(path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(65536), b""):
                        digest.update(chunk)
                manifest[path] = digest.hexdigest()
            except OSError as exc:
                manifest[path] = f"error: {exc}"
    return manifest
'''),
    ("b64_decode", '''\
import base64
import binascii


def b64_decode(data: str) -> dict:
    """Decode a Base64 string to text, flagging non-UTF-8 (binary) payloads.

    Args:
        data: The Base64-encoded string.

    Returns:
        dict with the decoded "text" and byte length, or an {"error": ...} dict.
    """
    try:
        raw = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as exc:
        return {"error": f"invalid Base64: {exc}"}
    try:
        return {"text": raw.decode("utf-8"), "bytes": len(raw)}
    except UnicodeDecodeError:
        return {"text": None, "bytes": len(raw), "note": "binary data (not UTF-8)"}
'''),
    ("url_parts", '''\
from urllib.parse import parse_qs, urlparse


def url_parts(url: str) -> dict:
    """Break a URL into scheme, host, port, path and query parameters.

    Args:
        url: The URL to parse.

    Returns:
        dict describing the URL's components.
    """
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "host": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parse_qs(parsed.query),
        "fragment": parsed.fragment,
    }
'''),
    ("unix_time_convert", '''\
from datetime import datetime, timezone


def unix_time_convert(timestamp: int) -> dict:
    """Convert a Unix epoch timestamp into a human-readable UTC datetime.

    Args:
        timestamp: Seconds since the Unix epoch (UTC).

    Returns:
        dict with the ISO-8601 UTC string and weekday, or an {"error": ...} dict.
    """
    try:
        dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        return {"error": f"invalid timestamp: {exc}"}
    return {"utc": dt.isoformat(), "weekday": dt.strftime("%A")}
'''),
    ("dns_lookup", '''\
import socket


def dns_lookup(hostname: str) -> dict:
    """Resolve a hostname to its IPv4/IPv6 addresses.

    Args:
        hostname: The domain name to resolve, e.g. "example.com".

    Returns:
        dict with the sorted, de-duplicated addresses, or an {"error": ...} dict.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return {"error": f"could not resolve '{hostname}': {exc}"}
    addrs = sorted({info[4][0] for info in infos})
    return {"hostname": hostname, "addresses": addrs}
'''),
]


def _rows_for(fn_name: str, summary: str, source: str) -> list[dict]:
    return [{
        "instruction": tmpl.format(name=fn_name, summary=summary),
        "input": SYSTEM,
        "output": source.rstrip() + "\n",
    } for tmpl in TEMPLATES]


def build() -> list[dict]:
    rows: list[dict] = []
    files = sorted(p for p in SKILLS_DIR.glob("*.py") if p.name not in SKIP)
    included: list[str] = []
    excluded: list[str] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        fn_name, doc = top_function_doc(source, path.stem)
        if not fn_name:
            continue  # not a well-formed skill file
        if _uses_injected_tools(source):
            excluded.append(path.name)  # assumes tools in scope — broken pattern
            continue
        included.append(path.name)
        rows += _rows_for(fn_name, summarise(doc, fn_name), source)

    # Hand-written, self-contained gold skills.
    for fn_name, source in SYNTHETIC:
        doc = top_function_doc(source, fn_name)[1]
        rows += _rows_for(fn_name, summarise(doc, fn_name), source)

    print(f"mined {len(included)} skills: {', '.join(included)}")
    print(f"excluded {len(excluded)} (assume injected tools): {', '.join(excluded)}")
    print(f"synthetic {len(SYNTHETIC)} skills: {', '.join(n for n, _ in SYNTHETIC)}")
    return rows


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = build()
    with OUT.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} examples -> {OUT}")


if __name__ == "__main__":
    main()
