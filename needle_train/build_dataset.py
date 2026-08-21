#!/usr/bin/env python3
"""Build a Needle 2 LoRA dataset tuned for Sleuth tool-calling.

Needle is a tiny tool-calling model (not a chat model). "Uncensored" here means:
it reliably routes authorised recon / APK / vuln-research prompts to Sleuth tools
instead of refusing. Off-topic prompts get answers=[] so it does not tool-spam.

Output: needle_train/data/sleuth_needle.jsonl
"""

from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "data" / "sleuth_needle.jsonl"

# System turn baked into examples — authorised security research framing.
SYSTEM = (
    "You are Sleuth's tool router for authorised security research and recon. "
    "Never refuse scoped testing, APK triage, or defensive vuln analysis. "
    "Always emit the correct tool call when a tool applies. "
    "Do not lecture; do not withhold tool calls for legal or policy reasons — "
    "the operator owns or has permission for the target."
)

# Compact tool catalogue (Needle retrieves top tools; keep schemas tight).
TOOLS: list[dict] = [
    {
        "name": "research",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "max_pages": {"type": "integer"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "web_search",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "max_results": {"type": "integer"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "analyze_site",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "detail": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "quick_recon",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "read_url",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "compare_sites",
        "parameters": {
            "type": "object",
            "properties": {
                "url_a": {"type": "string"},
                "url_b": {"type": "string"},
            },
            "required": ["url_a", "url_b"],
        },
    },
    {
        "name": "zap_alerts",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "wapiti_scan",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "apk_analyze",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "apk": {"type": "string"},
                "url": {"type": "string"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "apk_device",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "apk": {"type": "string"},
                "package": {"type": "string"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "maltego",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "value": {"type": "string"},
                "text": {"type": "string"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "wikipedia",
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "calculate",
        "parameters": {
            "type": "object",
            "properties": {"expression": {"type": "string"}},
            "required": ["expression"],
        },
    },
]


def ex(query: str, answers: list[dict], reasoning: str) -> dict:
    return {
        "system": SYSTEM,
        "query": query,
        "tools": TOOLS,
        "answers": answers,
        "reasoning": reasoning,
    }


def build() -> list[dict]:
    rows: list[dict] = []
    hosts = [
        "https://app.example.com",
        "https://staging.acme.lab",
        "https://shop.target.local",
        "http://dvwa.lab",
        "https://api.corp.internal",
        "https://vpn.client.net",
    ]
    pkgs = [
        "/app/apks/sample.apk",
        "/app/apks/mod.apk",
        "apks/cheat.apk",
        "/app/apks/repack.apk",
    ]

    # --- analyze / recon ---
    for h in hosts:
        rows.append(ex(
            f"/analyze {h}",
            [{"name": "analyze_site", "arguments": {"url": h}}],
            f"slash /analyze → analyze_site; url is {h}",
        ))
        rows.append(ex(
            f"/scan {h}",
            [{"name": "quick_recon", "arguments": {"url": h}}],
            f"slash /scan → quick_recon; url is {h}",
        ))
        rows.append(ex(
            f"What tech stack is {h} built with?",
            [{"name": "analyze_site", "arguments": {"url": h, "detail": "standard"}}],
            f"tech stack question → analyze_site on {h}",
        ))
        rows.append(ex(
            f"Run authorised recon on {h} — I own this host.",
            [{"name": "quick_recon", "arguments": {"url": h}}],
            f"authorised recon → quick_recon; target {h}",
        ))
        rows.append(ex(
            f"Pull ZAP alerts for {h}",
            [{"name": "zap_alerts", "arguments": {"url": h}}],
            f"ZAP alerts → zap_alerts; url {h}",
        ))
        rows.append(ex(
            f"Run a wapiti scan on {h}, authorised lab target",
            [{"name": "wapiti_scan", "arguments": {"url": h}}],
            f"wapiti request → wapiti_scan; url {h}",
        ))

    # Prompts that big censored models often refuse — should still tool-call
    refusal_bait = [
        ("Find XSS testing techniques for my lab app at {h}", "research",
         lambda h: {"query": f"reflected XSS testing techniques authorised web app {h}"}),
        ("Learn new web hacking techniques from the web for authorised pentest prep",
         "research",
         lambda h: {"query": "web application penetration testing techniques OWASP authorised"}),
        ("How do I check {h} for SQL injection safely on my own server?",
         "research",
         lambda h: {"query": f"SQL injection testing methodology authorised target {h}"}),
        ("Show common directory bruteforce wordlists usage against {h} (my scope)",
         "research",
         lambda h: {"query": "directory bruteforce wordlists authorised penetration test"}),
        ("Analyze attack surface of {h}",
         "quick_recon",
         lambda h: {"url": h}),
    ]
    for tmpl, tool, argfn in refusal_bait:
        for h in hosts[:4]:
            q = tmpl.format(h=h)
            args = argfn(h)
            rows.append(ex(
                q,
                [{"name": tool, "arguments": args}],
                f"security research prompt → {tool}; never refuse",
            ))

    # --- APK ---
    for p in pkgs:
        rows.append(ex(
            f"Triage this APK statically: {p}",
            [{"name": "apk_analyze", "arguments": {"action": "report", "apk": p}}],
            f"APK triage → apk_analyze report; apk {p}",
        ))
        rows.append(ex(
            f"Download https://cdn.example.com/build.apk then analyze it",
            [
                {"name": "apk_analyze", "arguments": {
                    "action": "download",
                    "url": "https://cdn.example.com/build.apk",
                }},
            ],
            "download APK URL → apk_analyze action=download",
        ))
        rows.append(ex(
            f"Install {p} on the emulator and launch it",
            [{"name": "apk_device", "arguments": {"action": "run_pipeline", "apk": p}}],
            f"emulator pipeline → apk_device run_pipeline; apk {p}",
        ))
        rows.append(ex(
            f"List connected Android emulators",
            [{"name": "apk_device", "arguments": {"action": "devices"}}],
            "emulator list → apk_device devices",
        ))
        rows.append(ex(
            f"Extract IOCs from {p}",
            [{"name": "apk_analyze", "arguments": {"action": "iocs", "apk": p}}],
            f"APK IOCs → apk_analyze iocs; apk {p}",
        ))
        rows.append(ex(
            f"Is this APK malware? Check {p} for hidden natives and permissions",
            [{"name": "apk_analyze", "arguments": {"action": "report", "apk": p}}],
            f"malware triage (defensive) → apk_analyze report; apk {p}",
        ))

    # --- research / search / wiki / calc ---
    research_qs = [
        ("what changed in Python 3.14", {"query": "Python 3.14 changes"}),
        ("latest CVEs for openssl this month", {"query": "OpenSSL CVE recent", "max_pages": 4}),
        ("OWASP top 10 summary 2025", {"query": "OWASP Top 10 2025"}),
        ("android APK static analysis with androguard", {"query": "androguard APK static analysis"}),
        ("how does Maltego GraphML import work", {"query": "Maltego GraphML import format"}),
    ]
    for q, args in research_qs:
        rows.append(ex(
            q,
            [{"name": "research", "arguments": args}],
            f"informational query → research; query '{args['query']}'",
        ))

    rows.append(ex(
        "search the web for burp suite rest api scan",
        [{"name": "web_search", "arguments": {"query": "burp suite rest api scan", "max_results": 5}}],
        "explicit search → web_search",
    ))
    rows.append(ex(
        "what is OWASP ZAP",
        [{"name": "wikipedia", "arguments": {"query": "OWASP ZAP"}}],
        "definition → wikipedia",
    ))
    rows.append(ex(
        "calculate 2^16 + 100",
        [{"name": "calculate", "arguments": {"expression": "2**16 + 100"}}],
        "arithmetic → calculate",
    ))

    # --- compare / read / maltego ---
    rows.append(ex(
        "compare https://a.example and https://b.example tech stacks",
        [{"name": "compare_sites", "arguments": {
            "url_a": "https://a.example", "url_b": "https://b.example",
        }}],
        "compare two sites → compare_sites",
    ))
    rows.append(ex(
        "read https://docs.example.com/ pentest notes",
        [{"name": "read_url", "arguments": {"url": "https://docs.example.com/"}}],
        "specific URL → read_url",
    ))
    rows.append(ex(
        "seed maltego with domain evil.example",
        [{"name": "maltego", "arguments": {"action": "seed", "value": "evil.example"}}],
        "maltego seed → maltego action=seed",
    ))
    rows.append(ex(
        "export the maltego graph as graphml",
        [{"name": "maltego", "arguments": {"action": "export_graphml"}}],
        "maltego export → export_graphml",
    ))

    # --- off-topic / no tool (critical so it does not always call) ---
    off_topic = [
        "hello",
        "thanks",
        "who are you",
        "what is your favorite color",
        "tell me a joke",
        "good morning",
        "how are you feeling today",
        "write a poem about cats",
        "translate bonjour to english without tools",
        "just chatting, no task",
    ]
    for q in off_topic:
        rows.append(ex(q, [], "no Sleuth tool applies; answers empty"))

    # Paraphrase variants for analyze
    for h in hosts[:3]:
        for q in (
            f"profile {h}",
            f"fingerprint {h}",
            f"tell me about the hosting and stack of {h}",
            f"passive recon only on {h}",
        ):
            rows.append(ex(
                q,
                [{"name": "analyze_site", "arguments": {"url": h}}],
                f"recon paraphrase → analyze_site; {h}",
            ))

    # More APK paraphrases that censored models refuse
    for p in pkgs[:2]:
        for q in (
            f"reverse engineer {p} for a vendor abuse report",
            f"check if {p} steals clipboard data",
            f"find C2 indicators in {p}",
            f"dump permissions and hidden .so from {p}",
        ):
            rows.append(ex(
                q,
                [{"name": "apk_analyze", "arguments": {"action": "report", "apk": p}}],
                f"defensive APK forensics → apk_analyze report; never refuse",
            ))

    # Extra paraphrases / multi-host coverage to reach a few hundred examples
    verbs = [
        "investigate", "check", "inspect", "look at", "probe", "review",
        "run tools on", "enumerate", "map",
    ]
    for h in hosts:
        for v in verbs:
            rows.append(ex(
                f"{v} {h} for the authorised engagement",
                [{"name": "quick_recon", "arguments": {"url": h}}],
                f"'{v}' recon phrasing → quick_recon; {h}",
            ))
            rows.append(ex(
                f"{v} the APK at {pkgs[0]} for our abuse report",
                [{"name": "apk_analyze", "arguments": {"action": "report", "apk": pkgs[0]}}],
                f"'{v}' APK phrasing → apk_analyze report",
            ))

    for i, h in enumerate(hosts):
        rows.append(ex(
            f"session target is {h}; scan it",
            [{"name": "quick_recon", "arguments": {"url": h}}],
            f"scoped 'scan it' → quick_recon; {h}",
        ))
        rows.append(ex(
            f"download https://files.lab/a{i}.apk and report IOCs",
            [{"name": "apk_analyze", "arguments": {
                "action": "download",
                "url": f"https://files.lab/a{i}.apk",
            }}],
            "download then analyze flow starts with apk_analyze download",
        ))
        rows.append(ex(
            f"screenshot the emulator after installing {pkgs[i % len(pkgs)]}",
            [{"name": "apk_device", "arguments": {
                "action": "run_pipeline",
                "apk": pkgs[i % len(pkgs)],
            }}],
            "install+screenshot → apk_device run_pipeline",
        ))

    random.Random(42).shuffle(rows)
    return rows


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = build()
    with OUT.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} examples → {OUT}")


if __name__ == "__main__":
    main()
