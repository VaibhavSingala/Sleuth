"""Parse a Burp Suite issue export into a triage summary.

Handles Burp's XML export (Target -> Site map / Scanner -> "Report issues" ->
XML). Groups issues by severity, aggregates the same issue across locations,
and strips the HTML that Burp wraps its descriptions in.
"""

from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

_SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Information": 3}
_TAG_RE = re.compile(r"<[^>]+>")


class BurpReportError(RuntimeError):
    """Raised when a report cannot be read or parsed."""


@dataclass
class Issue:
    name: str
    severity: str
    confidence: str
    locations: list = field(default_factory=list)  # "host/path"
    detail: str = ""


def _text(element, tag: str) -> str:
    child = element.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _strip_html(value: str, limit: int = 300) -> str:
    value = html.unescape(_TAG_RE.sub(" ", value or ""))
    value = " ".join(value.split())
    return value[:limit] + ("…" if len(value) > limit else "")


def _parse_xml(raw: str) -> list:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise BurpReportError(f"Not valid Burp XML: {exc}") from exc
    if root.tag != "issues":
        raise BurpReportError(
            f"Root element is <{root.tag}>, expected <issues>. "
            "Export from Burp as XML (not HTML)."
        )

    # Aggregate the same finding reported at multiple locations.
    grouped: dict = {}
    for node in root.findall("issue"):
        name = _text(node, "name") or "(unnamed issue)"
        severity = _text(node, "severity") or "Information"
        confidence = _text(node, "confidence")
        host = _text(node, "host")
        # location carries the injection point (query/param); richer for triage.
        path = _text(node, "location") or _text(node, "path")
        key = (name, severity)
        issue = grouped.get(key)
        if issue is None:
            issue = Issue(name=name, severity=severity, confidence=confidence,
                          detail=_strip_html(_text(node, "issueDetail")
                                             or _text(node, "issueBackground")))
            grouped[key] = issue
        location = f"{host}{path}".strip()
        if location and location not in issue.locations:
            issue.locations.append(location)
    return list(grouped.values())


def parse_report(path: str) -> str:
    """Read a Burp XML export at ``path`` and return a Markdown triage summary."""
    file = Path(path).expanduser()
    if not file.is_file():
        return f"No file at {file}."
    try:
        raw = file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"Could not read {file}: {exc}"

    head = raw.lstrip()[:200].lower()
    if not (head.startswith("<?xml") or "<issues" in head):
        if "<html" in head:
            return (
                f"{file} looks like an HTML report. Re-export from Burp as XML "
                "(Scanner/Target -> Report issues -> XML) for a structured triage."
            )
        return f"{file} is not a recognised Burp XML export."

    try:
        issues = _parse_xml(raw)
    except BurpReportError as exc:
        return f"Could not parse report: {exc}"

    if not issues:
        return f"No issues found in {file.name}. (An empty scan, or a filtered export.)"

    issues.sort(key=lambda i: (_SEVERITY_ORDER.get(i.severity, 9), i.name.lower()))

    counts: dict = defaultdict(int)
    for issue in issues:
        counts[issue.severity] += len(issue.locations) or 1

    lines = [
        f"# Burp scan triage — {file.name}",
        "",
        "**Totals by severity:** "
        + ", ".join(
            f"{sev} {counts[sev]}"
            for sev in ("High", "Medium", "Low", "Information")
            if counts.get(sev)
        ),
        f"\n{len(issues)} distinct issue types across "
        f"{sum(len(i.locations) or 1 for i in issues)} locations.",
    ]

    current = None
    for issue in issues:
        if issue.severity != current:
            current = issue.severity
            lines.append(f"\n## {current}")
        lines.append(f"\n### {issue.name}  ·  confidence: {issue.confidence or 'n/a'}")
        shown = issue.locations[:8]
        for loc in shown:
            lines.append(f"- `{loc}`")
        if len(issue.locations) > len(shown):
            lines.append(f"- …{len(issue.locations) - len(shown)} more locations")
        if issue.detail:
            lines.append(f"\n  {issue.detail}")

    lines.append(
        "\n---\nTriage view of Burp's own findings. Confirm each against the "
        "request/response in Burp before acting; scanners do report false positives."
    )
    return "\n".join(lines)
