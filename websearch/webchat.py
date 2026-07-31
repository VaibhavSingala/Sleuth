"""A local chat web page backed by the tool-using agent.

    python -m websearch.webchat            # serve on http://127.0.0.1:8765
    python -m websearch.webchat --port 9000 --open

You chat in the browser; the model decides which tools to call (search, news,
read_url, research, analyze_site, compare_sites, the Burp tools), and each
tool call streams to the page as it happens before the final answer renders.

Binds to 127.0.0.1 only -- it is a local single-user tool, not a public server.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import webbrowser
from pathlib import Path

import httpx
import uvicorn
from sse_starlette.sse import EventSourceResponse
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route

from . import llm, skills, store
from .agent import expand_slash_command, run_stream

_HTML = Path(__file__).resolve().parent / "static" / "chat.html"


async def index(request: Request) -> HTMLResponse:
    try:
        return HTMLResponse(_HTML.read_text(encoding="utf-8"))
    except OSError as exc:
        return HTMLResponse(f"<h1>chat.html missing</h1><pre>{exc}</pre>", status_code=500)


async def status(request: Request) -> JSONResponse:
    """Report which local LLM the agent would use right now."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            provider, base_url, api_key = await llm.detect(client)
            if api_key:
                client.headers["Authorization"] = f"Bearer {api_key}"
            model = await llm.resolve_model(client, provider, base_url)
        return JSONResponse({"ok": True, "provider": provider, "model": model})
    except llm.ProviderError as exc:
        return JSONResponse({"ok": False, "error": str(exc)})
    except httpx.HTTPError as exc:
        return JSONResponse({"ok": False, "error": f"Cannot reach a local LLM: {exc}"})


async def models(request: Request) -> JSONResponse:
    """List selectable chat models for the running provider, plus the default."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            provider, base_url, api_key = await llm.detect(client)
            if api_key:
                client.headers["Authorization"] = f"Bearer {api_key}"
            available = await llm.list_models(client, provider, base_url)
            try:
                default = await llm.resolve_model(client, provider, base_url)
            except llm.ProviderError:
                default = available[0]["id"] if available else ""
        return JSONResponse(
            {"ok": True, "provider": provider, "models": available, "default": default}
        )
    except llm.ProviderError as exc:
        return JSONResponse({"ok": False, "error": str(exc)})
    except httpx.HTTPError as exc:
        return JSONResponse({"ok": False, "error": f"Cannot reach a local LLM: {exc}"})


async def conversations(request: Request) -> JSONResponse:
    """List saved conversations, newest first."""
    return JSONResponse({"conversations": store.list_conversations()})


async def conversation_get(request: Request) -> JSONResponse:
    """Return one conversation's display transcript."""
    conv = store.load(request.path_params["conv_id"])
    if conv is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({
        "id": conv["id"],
        "title": conv.get("title", ""),
        "scope": conv.get("scope", {"target_url": ""}),
        "turns": conv.get("turns", []),
    })


async def conversation_scope(request: Request) -> JSONResponse:
    """Pin or clear the target URL for a conversation."""
    data = await request.json()
    conv_id = request.path_params["conv_id"]
    target = (data.get("target_url") or "").strip()
    if not store.load(conv_id):
        return JSONResponse({"error": "not found"}, status_code=404)
    ok = store.set_scope(conv_id, target)
    conv = store.load(conv_id)
    return JSONResponse({
        "ok": ok,
        "scope": conv.get("scope", {"target_url": ""}) if conv else {},
    })


async def skills_catalog(request: Request) -> JSONResponse:
    """Return the authored skill catalog for the UI."""
    return JSONResponse({"ok": True, "skills": skills.skill_catalog()})


async def conversation_delete(request: Request) -> JSONResponse:
    return JSONResponse({"ok": store.delete(request.path_params["conv_id"])})


async def conversation_rename(request: Request) -> JSONResponse:
    data = await request.json()
    ok = store.rename(request.path_params["conv_id"], data.get("title", ""))
    return JSONResponse({"ok": ok})


async def chat(request: Request) -> EventSourceResponse:
    data = await request.json()
    conv_id = (data.get("conversation_id") or "").strip() or None
    message = (data.get("message") or "").strip()
    model = (data.get("model") or "").strip() or None

    async def events():
        if not message:
            yield {"data": json.dumps({"type": "error", "text": "Empty message."})}
            yield {"data": json.dumps({"type": "done"})}
            return

        conv = store.load_or_create(conv_id)
        scope = conv.get("scope", {"target_url": ""})
        message = expand_slash_command(message, scope)
        if not conv.get("title"):
            conv["title"] = message[:60]
        conv["messages"].append({"role": "user", "content": message})
        conv["turns"].append({"role": "user", "content": message})
        # Tell the client the id + title up front (new chats need the id).
        yield {"data": json.dumps({"type": "conversation", "id": conv["id"],
                                   "title": conv["title"],
                                   "scope": scope})}

        turn: dict = {"role": "assistant", "content": "", "steps": []}
        answer_text = ""
        stopped = False
        try:
            async for event in run_stream(conv["messages"], model=model, scope=scope):
                etype = event["type"]
                if etype == "tool_call":
                    turn["steps"].append({"name": event["name"], "args": event.get("args", {})})
                elif etype == "tool_result" and turn["steps"]:
                    turn["steps"][-1]["preview"] = event.get("preview", "")
                    if event.get("report"):
                        turn["steps"][-1]["report"] = event["report"]
                # Accumulate the streamed answer so a turn stopped mid-generation
                # still persists what was produced. `answer` is the final,
                # authoritative text; `answer_reset` discards a tool-call preamble.
                elif etype == "answer_delta":
                    answer_text += event.get("text", "")
                elif etype == "answer_reset":
                    answer_text = ""
                elif etype == "answer":
                    answer_text = event["text"]
                yield {"data": json.dumps(event)}
        except (asyncio.CancelledError, GeneratorExit):
            # The browser hit Stop and disconnected. Persist what we have (below,
            # in finally) and re-raise so the server can tear the request down.
            # Re-raising ends the async-for, which closes run_stream's HTTP
            # connection to the LLM, stopping generation.
            stopped = True
            raise
        except Exception as exc:  # a crash must not hang the browser's stream
            yield {"data": json.dumps({"type": "error", "text": f"{type(exc).__name__}: {exc}"})}
            answer_text = answer_text or f"(error: {exc})"
        finally:
            # Persist on every exit path — normal finish, error, or stop — so a
            # turn the user interrupted (and their message) is never lost, even
            # if they stopped it during the model's reasoning phase before any
            # answer token. No yielding here: the generator may be closing.
            turn["content"] = answer_text or ("(stopped)" if stopped else "")
            if turn["content"] or turn["steps"]:
                conv["turns"].append(turn)
            try:
                store.save(conv)
            except OSError:
                pass

        yield {"data": json.dumps({"type": "done"})}

    return EventSourceResponse(events())


app = Starlette(routes=[
    Route("/", index),
    Route("/api/status", status),
    Route("/api/models", models),
    Route("/api/skills", skills_catalog),
    Route("/api/conversations", conversations),
    Route("/api/conversations/{conv_id}", conversation_get),
    Route("/api/conversations/{conv_id}/scope", conversation_scope, methods=["POST"]),
    Route("/api/conversations/{conv_id}/delete", conversation_delete, methods=["POST"]),
    Route("/api/conversations/{conv_id}/rename", conversation_rename, methods=["POST"]),
    Route("/api/chat", chat, methods=["POST"]),
])


def main() -> None:
    parser = argparse.ArgumentParser(description="Local tool-using chat web page.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default localhost).")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", help="Open a browser tab on start.")
    args = parser.parse_args()

    url = f"http://{args.host}:{args.port}"
    print(f"webchat on {url}  (Ctrl-C to stop)", file=sys.stderr)
    if args.open:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
