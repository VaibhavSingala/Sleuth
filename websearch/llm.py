"""Provider layer for OpenAI-compatible local LLM servers.

Supports LM Studio and Ollama out of the box, plus any other server speaking
the OpenAI chat-completions API. The differences that actually matter are
model discovery and telling chat models apart from embedding models -- the
`/v1/models` list is identical in shape for both and says neither.
"""

from __future__ import annotations

import asyncio
import logging
import os

import httpx

from . import config

log = logging.getLogger(__name__)

# Inside a container the LLM runs on the host, reachable via host.docker.internal;
# on the host it's plain localhost. The Docker image sets SLEUTH_IN_DOCKER=1.
_LLM_HOST = "host.docker.internal" if os.environ.get("SLEUTH_IN_DOCKER") else "localhost"
PROVIDERS = {
    "lmstudio": {"base_url": f"http://{_LLM_HOST}:1234/v1", "api_key": "lm-studio"},
    "ollama": {"base_url": f"http://{_LLM_HOST}:11434/v1", "api_key": "ollama"},
}

# LM Studio reports these in /api/v0/models; Ollama reports capabilities.
_LMSTUDIO_CHAT_TYPES = ("llm", "vlm")


class ProviderError(RuntimeError):
    """Raised when no usable provider or model can be reached."""


def _root(base_url: str) -> str:
    return base_url.rstrip("/").removesuffix("/v1")


async def _alive(client: httpx.AsyncClient, base_url: str) -> bool:
    try:
        resp = await client.get(f"{base_url.rstrip('/')}/models", timeout=3.0)
        return resp.status_code < 500
    except httpx.HTTPError:
        return False


async def detect(client: httpx.AsyncClient) -> tuple:
    """Return (provider_name, base_url, api_key) for whatever is running.

    An explicit base URL always wins. Otherwise LM Studio is probed first,
    then Ollama, so an existing setup keeps working unchanged.
    """
    if config.LLM_BASE_URL:
        name = config.LLM_PROVIDER if config.LLM_PROVIDER != "auto" else "custom"
        # Never return an empty key: "Authorization: Bearer " is an illegal
        # header and httpx rejects it before the request leaves.
        default_key = PROVIDERS.get(name, {}).get("api_key", "local")
        return name, config.LLM_BASE_URL, config.LLM_API_KEY or default_key

    if config.LLM_PROVIDER in PROVIDERS:
        spec = PROVIDERS[config.LLM_PROVIDER]
        return config.LLM_PROVIDER, spec["base_url"], config.LLM_API_KEY or spec["api_key"]

    for name, spec in PROVIDERS.items():
        if await _alive(client, spec["base_url"]):
            log.info("detected %s at %s", name, spec["base_url"])
            return name, spec["base_url"], config.LLM_API_KEY or spec["api_key"]

    raise ProviderError(
        "No local LLM server found. Start LM Studio's server (Developer tab) "
        "or run `ollama serve`, or set LLM_BASE_URL explicitly."
    )


async def _lmstudio_models(client: httpx.AsyncClient, base_url: str) -> list:
    """LM Studio's native endpoint reports a type per model."""
    resp = await client.get(f"{_root(base_url)}/api/v0/models", timeout=8.0)
    resp.raise_for_status()
    models = [
        m for m in resp.json().get("data", []) if m.get("type") in _LMSTUDIO_CHAT_TYPES
    ]
    loaded = [m for m in models if m.get("state") == "loaded"]
    return [m["id"] for m in (loaded or models)]


async def _ollama_models(client: httpx.AsyncClient, base_url: str) -> list:
    """Ollama reports per-model capabilities, including tool support.

    Worth the extra calls: "the model silently never calls tools" is the most
    common failure, and here we can find out before spending a request on it.
    """
    root = _root(base_url)
    resp = await client.get(f"{root}/api/tags", timeout=8.0)
    resp.raise_for_status()
    names = [m["name"] for m in resp.json().get("models", [])]
    if not names:
        raise ProviderError(
            "Ollama has no models pulled. Fetch a tool-capable one first, e.g. "
            "`ollama pull qwen3:4b`."
        )

    async def _capabilities(name: str) -> tuple:
        try:
            show = await client.post(f"{root}/api/show", json={"model": name}, timeout=8.0)
            show.raise_for_status()
            return name, [c.lower() for c in show.json().get("capabilities", [])]
        except (httpx.HTTPError, ValueError):
            return name, []

    results = await asyncio.gather(*(_capabilities(n) for n in names[:12]))

    tool_capable, chat_capable = [], []
    for name, caps in results:
        if "embedding" in caps:
            continue
        if "tools" in caps:
            tool_capable.append(name)
        elif caps or "embed" not in name.lower():
            chat_capable.append(name)

    if tool_capable:
        return tool_capable
    if chat_capable:
        log.warning(
            "No Ollama model reports tool support; trying %s anyway. "
            "Pull a tool-capable model (e.g. qwen3:4b) if it ignores the tools.",
            chat_capable[0],
        )
        return chat_capable
    raise ProviderError(
        "Ollama has only embedding models. Pull a chat model, e.g. `ollama pull qwen3:4b`."
    )


async def _openai_models(client: httpx.AsyncClient, base_url: str) -> list:
    resp = await client.get(f"{base_url.rstrip('/')}/models", timeout=8.0)
    resp.raise_for_status()
    ids = [m["id"] for m in resp.json().get("data", [])]
    return [i for i in ids if "embed" not in i.lower()]


_PICKERS = {"lmstudio": _lmstudio_models, "ollama": _ollama_models}


async def resolve_model(client: httpx.AsyncClient, provider: str, base_url: str) -> str:
    """Pick a chat model, never an embedding model.

    Only the native endpoints distinguish chat models from embedding models
    with any authority, so they are tried first. When the provider is unknown
    (an explicit base URL, say) both natives are probed before falling back to
    /v1/models, whose flat list of ids can only be filtered by name.
    """
    if config.LLM_MODEL:
        return config.LLM_MODEL

    known = provider in _PICKERS
    pickers = [(provider, _PICKERS[provider])] if known else list(_PICKERS.items())

    for name, picker in pickers:
        try:
            if candidates := await picker(client, base_url):
                return candidates[0]
        except ProviderError:
            if known:
                raise  # e.g. "Ollama has no models pulled" -- a real answer
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            if known:
                log.warning(
                    "%s native model listing failed (%r); falling back to "
                    "/v1/models, which may pick a less suitable model.", name, exc
                )

    candidates = await _openai_models(client, base_url)
    if not candidates:
        raise ProviderError(
            f"{provider} exposes no chat model (only embedding models, or none at all). "
            "Load or pull one, or set LLM_MODEL."
        )
    return candidates[0]


async def list_models(client: httpx.AsyncClient, provider: str, base_url: str) -> list[dict]:
    """Best-effort list of selectable chat models: [{"id", "tools"}].

    Never raises -- returns [] on any failure so the picker degrades quietly.
    ``tools`` marks whether the model is known to support tool calling (only
    Ollama reports this; elsewhere it is assumed True).
    """
    try:
        if provider == "ollama":
            root = _root(base_url)
            resp = await client.get(f"{root}/api/tags", timeout=8.0)
            resp.raise_for_status()
            names = [m["name"] for m in resp.json().get("models", [])]

            async def _cap(name: str) -> tuple:
                try:
                    show = await client.post(f"{root}/api/show", json={"model": name}, timeout=8.0)
                    show.raise_for_status()
                    return name, [c.lower() for c in show.json().get("capabilities", [])]
                except (httpx.HTTPError, ValueError):
                    return name, []

            out = []
            for name, caps in await asyncio.gather(*(_cap(n) for n in names)):
                if "embedding" in caps:
                    continue
                out.append({"id": name, "tools": "tools" in caps})
            return out

        if provider == "lmstudio":
            resp = await client.get(f"{_root(base_url)}/api/v0/models", timeout=8.0)
            resp.raise_for_status()
            return [
                {"id": m["id"], "tools": True}
                for m in resp.json().get("data", [])
                if m.get("type") in _LMSTUDIO_CHAT_TYPES
            ]
    except (httpx.HTTPError, ValueError, KeyError):
        pass

    try:  # generic OpenAI-compatible fallback
        resp = await client.get(f"{base_url.rstrip('/')}/models", timeout=8.0)
        resp.raise_for_status()
        return [
            {"id": m["id"], "tools": True}
            for m in resp.json().get("data", [])
            if "embed" not in m["id"].lower()
        ]
    except (httpx.HTTPError, ValueError, KeyError):
        return []


def error_text(resp: httpx.Response) -> str:
    """Pull the server's error message out of a failed response."""
    try:
        payload = resp.json()
    except ValueError:
        return resp.text[:300]
    error = payload.get("error", payload)
    if isinstance(error, dict):
        return str(error.get("message", error))[:300]
    return str(error)[:300]
