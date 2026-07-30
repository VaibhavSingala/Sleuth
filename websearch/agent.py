"""Standalone search-enabled chat against a local OpenAI-compatible server.

LM Studio and Ollama are both detected automatically; any other server
speaking the OpenAI chat-completions API works via LLM_BASE_URL.

    python -m websearch.agent "what changed in Python 3.14"
    python -m websearch.agent            # interactive REPL

This is the route to use with Ollama: Ollama serves models but has no MCP
client of its own, so the MCP server cannot plug into it directly.

Requires a running server (LM Studio: Developer tab -> Start Server;
Ollama: `ollama serve`) with a tool-calling capable model available.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import re
import sys
from datetime import datetime, timezone

import httpx

from . import config, llm, skills
from .analyze import analyze_site, compare_sites
from .burp.reports import parse_report as burp_parse_report
from .burp.scan import scan_status as burp_scan_status
from .burp.scan import scan_url as burp_scan
from .burp.seed import feed_recon as burp_feed
from .core import news_search, read_url, research, web_search
from .extras import calculate, wikipedia_lookup
from .wapiti.scan import scan_url as wapiti_scan
from .zap.scan import alerts as zap_alerts
from .zap.scan import scan_status as zap_scan_status
from .zap.scan import scan_url as zap_scan
from .zap.seed import feed_recon as zap_feed

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_site",
            "description": (
                "Profile one website: technology stack, keywords, SEO and "
                "infrastructure. Use for '/analyze <url>' or when asked what a "
                "site is built with, what it is about, or who hosts it."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Site to analyse."},
                    "detail": {
                        "type": "string",
                        "description": "Report depth.",
                        "enum": ["summary", "standard", "full"],
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "research",
            "description": (
                "Search the web AND read the top pages, returning their content in "
                "one call. Best default for any question needing real information "
                "from the web."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What to find out."},
                    "max_pages": {
                        "type": "integer",
                        "description": "How many pages to open and read (1-8).",
                        "default": 3,
                    },
                    "recency": {
                        "type": "string",
                        "description": "Optional freshness filter.",
                        "enum": ["day", "week", "month", "year"],
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "compare_sites",
            "description": (
                "Compare two websites: technology, infrastructure, security "
                "and keywords. Passive competitive-intelligence view."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url_a": {"type": "string", "description": "First site."},
                    "url_b": {"type": "string", "description": "Second site."},
                    "detail": {
                        "type": "string",
                        "enum": ["summary", "standard", "full"],
                    },
                },
                "required": ["url_a", "url_b"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for titles, URLs and short snippets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search keywords."},
                    "max_results": {
                        "type": "integer",
                        "description": "Number of results (1-20).",
                        "default": 5,
                    },
                    "recency": {
                        "type": "string",
                        "description": "Optional freshness filter.",
                        "enum": ["day", "week", "month", "year"],
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "news_search",
            "description": "Search recent news articles, with source and date.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What to look for."},
                    "max_results": {
                        "type": "integer",
                        "description": "Articles to return (1-20).",
                        "default": 6,
                    },
                    "recency": {
                        "type": "string",
                        "description": "Optional freshness filter.",
                        "enum": ["day", "week", "month", "year"],
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "wikipedia",
            "description": "Look up a short, reliable factual summary from Wikipedia.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string", "description": "What to look up."}},
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculate",
            "description": ("Evaluate an arithmetic/math expression exactly. Use for any "
                            "calculation instead of mental math."),
            "parameters": {
                "type": "object",
                "properties": {"expression": {"type": "string",
                               "description": "e.g. '(1234*5678)/3' or 'sqrt(2)+log(100)'."}},
                "required": ["expression"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_url",
            "description": "Fetch one web page (HTML or PDF) and return its main text.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Full URL to read."},
                    "max_chars": {
                        "type": "integer",
                        "description": "Max characters to return.",
                        "default": 12000,
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_parse_report",
            "description": "Triage a Burp Suite XML issue export, ranked by severity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the Burp XML export."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_feed",
            "description": (
                "Feed passive recon (endpoints + subdomains) into Burp's site map "
                "and return a target-scope JSON. Needs BURP_PROXY. No scanning."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Site to profile and feed into Burp."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_scan",
            "description": (
                "Start an ACTIVE Burp vulnerability scan of a URL (Burp Pro). Only "
                "for authorised targets; disabled unless BURP_ALLOW_ACTIVE_SCAN=true."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to scan."},
                    "wait": {
                        "type": "boolean",
                        "description": "Wait and summarise (true) or return a task id (false).",
                        "default": True,
                    },
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "burp_scan_status",
            "description": "Check a running or finished Burp scan by task id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "task_id": {"type": "string", "description": "Burp scan task id."},
                },
                "required": ["task_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "zap_feed",
            "description": ("Route recon (endpoints + subdomains) through OWASP ZAP's "
                            "proxy for free passive scanning. Needs ZAP_PROXY."),
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "Site to feed into ZAP."}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "zap_alerts",
            "description": "Read the alerts OWASP ZAP has collected for a base URL (free).",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string", "description": "Base URL."}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "zap_scan",
            "description": ("Spider + ACTIVE OWASP ZAP scan of a URL (free scanner). Only "
                            "for authorised targets; disabled unless ZAP_ALLOW_ACTIVE_SCAN=true."),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to scan."},
                    "wait": {"type": "boolean",
                             "description": "Wait and summarise (true) or return a scan id (false).",
                             "default": True},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "zap_scan_status",
            "description": "Check an OWASP ZAP active scan by id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "ZAP scan id."},
                    "url": {"type": "string", "description": "Optional base URL for alerts."},
                },
                "required": ["scan_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "wapiti_scan",
            "description": ("Actively scan a URL with Wapiti, a free pip-installable "
                            "scanner (no Burp Pro / ZAP needed). Authorised targets only; "
                            "disabled unless WAPITI_ALLOW_ACTIVE_SCAN=true."),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL to scan."},
                    "max_time": {"type": "integer",
                                 "description": "Time cap in seconds (0 = default)."},
                },
                "required": ["url"],
            },
        },
    },
]

HANDLERS = {
    "research": research,
    "web_search": web_search,
    "news_search": news_search,
    "read_url": read_url,
    "analyze_site": analyze_site,
    "compare_sites": compare_sites,
    "wikipedia": wikipedia_lookup,
    "calculate": calculate,
    "burp_parse_report": burp_parse_report,
    "burp_feed": burp_feed,
    "burp_scan": burp_scan,
    "burp_scan_status": burp_scan_status,
    "zap_feed": zap_feed,
    "zap_alerts": zap_alerts,
    "zap_scan": zap_scan,
    "zap_scan_status": zap_scan_status,
    "wapiti_scan": wapiti_scan,
}

# The built-in tool names are reserved so an authored skill can't shadow one.
skills.reserve(HANDLERS.keys())


def active_tools(*, include_meta: bool = True) -> list[dict]:
    """The tool list offered to the model this round: built-ins + (if enabled)
    the self-extension meta-tools + every currently-valid authored skill.

    Rebuilt each round so a skill written mid-conversation is callable on the
    next one. Callers refresh the skill registry before calling this.
    """
    tools = list(TOOLS)
    if include_meta:
        tools += skills.meta_tool_schemas()
    tools += skills.skill_tool_schemas()
    return tools


def resolve_handler(name: str):
    """Look up a handler across built-ins, meta-tools and authored skills."""
    if name in HANDLERS:
        return HANDLERS[name]
    return skills.resolve(name)


def _is_tool(name: str) -> bool:
    return name in HANDLERS or skills.is_tool(name)


SKILLS_PROMPT = (
    "\n- You can extend yourself. If a capability you need does not exist, use "
    "`skill_write` to author a Python function and it becomes a callable tool "
    "immediately (list them with `skill_list`). You can also read and edit this "
    "project's own source (`code_read`/`code_search`/`code_write`) and run code "
    "(`python_exec`/`shell_exec`). Prefer a small, well-named skill over "
    "repeating ad-hoc `python_exec`."
)

SYSTEM_PROMPT = (
    "You are a helpful assistant with live web access.\n"
    "Today's date is {today}.\n\n"
    "Rules:\n"
    "- For anything current, version-specific, or that you are not certain "
    "about, call a tool instead of answering from memory.\n"
    "- Prefer `research` — it searches and reads pages in one step.\n"
    "- Use `calculate` for any arithmetic, and `wikipedia` for encyclopedic "
    "facts (definitions, people, places) — do not compute or recall these yourself.\n"
    "- If the user writes `/analyze <url>`, call `analyze_site` on that URL "
    "and summarise the report.\n"
    "- Base your answer on what the tools returned, and cite sources as "
    "[1], [2] with their URLs at the end.\n"
    "- If the tools find nothing useful, say so plainly rather than guessing."
    "{skills}"
)


def system_prompt(today: str) -> str:
    """The system prompt for `today`, including the self-extension hint only
    when skills are enabled (so we never advertise tools we won't offer)."""
    hint = SKILLS_PROMPT if config.SKILLS_ENABLED else ""
    return SYSTEM_PROMPT.format(today=today, skills=hint)


_TOOL_TAG_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)
_FENCE_RE = re.compile(r"```(?:json|tool_call|tool)?\s*(\{.*?\})\s*```", re.S)


def _parse_text_tool_calls(content: str) -> list[dict]:
    """Recover tool calls a model wrote as text into OpenAI tool_call dicts.

    Handles <tool_call>{...}</tool_call>, ```json {...}``` fences, and a bare
    top-level JSON object. Every candidate must name a known tool, which keeps
    ordinary JSON that happens to appear in an answer from being mistaken for
    a call.
    """
    candidates = _TOOL_TAG_RE.findall(content) + _FENCE_RE.findall(content)
    stripped = content.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        candidates.append(stripped)

    calls: list[dict] = []
    seen: set = set()
    for i, raw in enumerate(candidates):
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue

        # Accept {"name","arguments"}, {"tool","parameters"}, or
        # {"function": {"name","arguments"}}.
        fn = obj.get("function")
        if isinstance(fn, dict):
            name, args = fn.get("name"), fn.get("arguments", {})
        else:
            name = obj.get("name") or obj.get("tool")
            args = obj.get("arguments", obj.get("parameters", obj.get("args", {})))

        if not isinstance(name, str) or not _is_tool(name):
            continue
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        if not isinstance(args, dict):
            continue

        key = f"{name}:{json.dumps(args, sort_keys=True)}"
        if key in seen:  # dedupe a call quoted twice in the same message
            continue
        seen.add(key)
        calls.append({
            "id": f"text_call_{i}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)},
        })
    return calls


async def _call_tool(name: str, arguments: dict) -> str:
    handler = resolve_handler(name)
    if handler is None:
        return f"Error: unknown tool '{name}'."
    try:
        result = handler(**arguments)
        if inspect.isawaitable(result):  # handlers may be sync or async
            result = await result
        return result
    except TypeError as exc:
        return f"Error: bad arguments for {name}: {exc}"
    except Exception as exc:  # never let a tool crash the loop
        return f"Error running {name}: {exc}"


def _preview(text: str, limit: int = 240) -> str:
    text = " ".join(str(text).split())
    return text[:limit] + ("…" if len(text) > limit else "")


async def run_stream(messages: list[dict], *, max_rounds: int = 6, model: str | None = None):
    """Drive the tool-calling loop, yielding events as they happen.

    This is the single loop implementation; `chat()` consumes it for the CLI
    and the web UI streams the same events. `messages` is appended to in place,
    so it doubles as the conversation history. Event shapes:
      {"type":"meta","provider","model"}
      {"type":"note","text"}
      {"type":"answer_delta","text"}   # streamed answer tokens (live typing)
      {"type":"answer_reset"}          # discard streamed text (it was a tool preamble)
      {"type":"tool_call","name","args","recovered"}
      {"type":"tool_result","name","preview"}
      {"type":"answer","text"}         # final, complete answer (for render + CLI)
      {"type":"error","text"}

    Works against any OpenAI-compatible server; LM Studio and Ollama are
    detected automatically.
    """
    async with httpx.AsyncClient(timeout=300.0) as client:
        try:
            provider, base_url, api_key = await llm.detect(client)
            if api_key:
                client.headers["Authorization"] = f"Bearer {api_key}"
            # An explicit model (from the web UI's picker) wins; otherwise
            # auto-pick a tool-capable one.
            model = model or await llm.resolve_model(client, provider, base_url)
        except llm.ProviderError as exc:
            yield {"type": "error", "text": str(exc)}
            return
        except httpx.HTTPError as exc:
            yield {"type": "error", "text": f"Could not reach the local LLM server: {exc}"}
            return

        yield {"type": "meta", "provider": provider, "model": model}

        seen: dict[str, str] = {}
        for round_idx in range(max_rounds):
            # On the final round, drop the tools so the model has to answer in
            # prose with what it already has, instead of calling yet another
            # tool and falling off the end with nothing to say.
            final_round = round_idx == max_rounds - 1
            payload: dict = {
                "model": model, "messages": messages, "temperature": 0.3, "stream": True,
            }
            if not final_round:
                # Re-scan the skills directory each round so a tool the model
                # just authored with skill_write is offered on the next one.
                skills.refresh()
                payload["tools"] = active_tools()
                payload["tool_choice"] = "auto"

            content_parts: list[str] = []
            reasoning_parts: list[str] = []
            tool_acc: dict[int, dict] = {}
            emitted_delta = False
            try:
                async with client.stream(
                    "POST", f"{base_url}/chat/completions", json=payload
                ) as resp:
                    if resp.status_code >= 400:
                        await resp.aread()
                        yield {"type": "error",
                               "text": f"{provider} returned {resp.status_code}: {llm.error_text(resp)}"}
                        return
                    async for line in resp.aiter_lines():
                        line = line.strip()
                        if not line.startswith("data:"):
                            continue
                        data = line[5:].strip()
                        if data == "[DONE]":
                            break
                        try:
                            choice = (json.loads(data).get("choices") or [{}])[0]
                        except json.JSONDecodeError:
                            continue
                        delta = choice.get("delta") or {}
                        if delta.get("content"):
                            content_parts.append(delta["content"])
                            emitted_delta = True
                            yield {"type": "answer_delta", "text": delta["content"]}
                        # Reasoning models (DeepSeek-R1, QwQ, some gemma variants)
                        # stream their thinking here, separate from the answer.
                        if delta.get("reasoning_content"):
                            reasoning_parts.append(delta["reasoning_content"])
                            yield {"type": "reasoning_delta", "text": delta["reasoning_content"]}
                        for tc in delta.get("tool_calls") or []:
                            slot = tool_acc.setdefault(
                                tc.get("index", 0), {"id": "", "name": "", "arguments": ""}
                            )
                            if tc.get("id"):
                                slot["id"] = tc["id"]
                            fn = tc.get("function") or {}
                            if fn.get("name"):
                                slot["name"] = fn["name"]
                            if fn.get("arguments"):
                                slot["arguments"] += fn["arguments"]
            except httpx.HTTPError as exc:
                yield {"type": "error", "text": f"Request to {provider} failed: {exc}"}
                return

            content = "".join(content_parts)
            reasoning = "".join(reasoning_parts)
            tool_calls = [
                {"id": s["id"] or f"call_{i}", "type": "function",
                 "function": {"name": s["name"], "arguments": s["arguments"] or "{}"}}
                for i, s in sorted(tool_acc.items()) if s["name"]
            ]

            # Some local models emit tool calls as text (<tool_call>{...}</tool_call>
            # or a JSON fence) instead of using the tool_calls field -- and reasoning
            # models put that text in reasoning_content. Recover from either.
            recovered_flag = False
            if not tool_calls and not final_round:
                recovered = _parse_text_tool_calls(content or reasoning)
                if recovered:
                    tool_calls = recovered
                    recovered_flag = True

            # If we streamed text but the round is really a tool call, the streamed
            # text was a preamble/tool-call-text -- tell the UI to drop it.
            if tool_calls and emitted_delta:
                yield {"type": "answer_reset"}
            if recovered_flag:
                yield {"type": "note", "text": "recovered tool call from model text"}

            assistant_msg: dict = {"role": "assistant", "content": content or None}
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            messages.append(assistant_msg)

            if not tool_calls:
                # A reasoning model may leave `content` empty and put everything
                # in `reasoning_content` -- fall back to it rather than show a
                # bare "(empty response)".
                answer = content or reasoning or "(empty response)"
                yield {"type": "answer", "text": answer}
                return

            for call in tool_calls:
                name = call["function"]["name"]
                try:
                    arguments = json.loads(call["function"]["arguments"] or "{}")
                except json.JSONDecodeError:
                    arguments = {}
                yield {"type": "tool_call", "name": name, "args": arguments,
                       "recovered": recovered_flag}

                # A model that gets an unhelpful result often calls the exact
                # same thing again. Don't re-run it -- return the prior result
                # with an instruction to change course or answer now.
                key = f"{name}:{json.dumps(arguments, sort_keys=True)}"
                if key in seen:
                    result = (
                        f"You already called {name} with these exact arguments; the "
                        f"result was:\n{seen[key]}\n\nDo not call it again the same way. "
                        "Try different arguments or another tool, or give your final "
                        "answer now using what you have."
                    )
                else:
                    result = await _call_tool(name, arguments)
                    seen[key] = result

                yield {"type": "tool_result", "name": name, "preview": _preview(result)}
                messages.append(
                    {"role": "tool", "tool_call_id": call.get("id", ""), "content": result}
                )

        # Unreachable in practice: the final round has no tools, so it answers
        # above. Kept as a defensive backstop.
        yield {"type": "answer", "text": "Stopped after too many tool rounds without a final answer."}


async def chat(
    messages: list[dict],
    *,
    max_rounds: int = 6,
    verbose: bool = True,
    model: str | None = None,
) -> str:
    """Run the tool loop to completion and return the final answer text.

    Thin wrapper over `run_stream` that prints step events to stderr (for the
    CLI) and raises on error, preserving the previous behaviour.
    """
    answer = "(no answer)"
    async for event in run_stream(messages, max_rounds=max_rounds, model=model):
        kind = event["type"]
        if kind == "error":
            raise RuntimeError(event["text"])
        if verbose and kind == "meta":
            print(f"  [{event['provider']}] {event['model']}", file=sys.stderr)
        elif verbose and kind == "note":
            print(f"  ({event['text']})", file=sys.stderr)
        elif verbose and kind == "tool_call":
            print(f"  -> {event['name']}({json.dumps(event['args'])[:120]})", file=sys.stderr)
        elif kind == "answer":
            answer = event["text"]
    return answer


async def ask(question: str, verbose: bool = True) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return await chat(
        [
            {"role": "system", "content": system_prompt(today)},
            {"role": "user", "content": question},
        ],
        verbose=verbose,
    )


async def _repl() -> None:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    messages = [{"role": "system", "content": system_prompt(today)}]
    print("Search-enabled chat. Ctrl-C or 'exit' to quit.\n")
    while True:
        try:
            question = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if question.lower() in ("exit", "quit"):
            return
        if not question:
            continue
        messages.append({"role": "user", "content": question})
        answer = await chat(messages)
        print(f"\nbot> {answer}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Web-search-enabled chat via LM Studio.")
    parser.add_argument("question", nargs="*", help="Question to ask; omit for a REPL.")
    parser.add_argument("-q", "--quiet", action="store_true", help="Hide tool-call trace.")
    args = parser.parse_args()

    try:
        if args.question:
            print(asyncio.run(ask(" ".join(args.question), verbose=not args.quiet)))
        else:
            asyncio.run(_repl())
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
