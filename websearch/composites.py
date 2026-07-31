"""Composite high-level tools for small models that struggle with tool chains."""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
from typing import Any

from . import config, skills
from .analyze import analyze_site, compare_sites


def _load_skill(name: str):
    """Load a skill function from ``skills/`` if the file exists."""
    path = config.SKILLS_DIR / f"{name}.py"
    if not path.is_file():
        return None
    modname = f"websearch._composite.{name}"
    try:
        spec = importlib.util.spec_from_file_location(modname, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
        fn = getattr(module, name, None) or getattr(module, "run", None)
        return fn if callable(fn) else None
    except Exception:
        return None


async def _run_skill(name: str, **kwargs) -> Any | None:
    fn = _load_skill(name)
    if fn is None:
        handler = skills.resolve(name)
        if handler is None:
            return None
        result = handler(**kwargs)
        if inspect.isawaitable(result):
            result = await result
        return result
    result = await asyncio.to_thread(fn, **kwargs)
    return result


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("report", "summary", "content"):
            if key in value and value[key]:
                return str(value[key])
        return json.dumps(value, indent=2, ensure_ascii=False, default=str)
    return str(value)


async def quick_recon(url: str, detail: str = "standard") -> str:
    """One-shot passive recon: site profile, SSL check, and common vulnerability probes.

    Combines analyze_site with security skills in a single call so small models
    do not have to chain multiple tools themselves.

    Args:
        url: Target URL or hostname.
        detail: Profile depth — summary, standard, or full.

    Returns:
        Markdown report with all sections combined.
    """
    detail = detail if detail in ("summary", "standard", "full") else "standard"
    sections: list[str] = [f"# Quick recon — {url}", ""]

    profile = await analyze_site(url, detail=detail)
    sections.append("## Site profile")
    sections.append(profile)
    sections.append("")

    ssl = await _run_skill("check_ssl_config", url=url)
    if ssl is not None:
        sections.append("## SSL / TLS")
        sections.append(_as_text(ssl))
        sections.append("")

    vectors = await _run_skill("check_common_vectors", url=url)
    if vectors is not None:
        sections.append("## Common vulnerability probes")
        sections.append(_as_text(vectors))
        sections.append("")

    sections.append("---")
    sections.append(
        "Passive recon only. Confirm findings manually before acting. "
        "For active scanning, use zap_scan or wapiti_scan on authorised targets."
    )
    return "\n".join(sections)


async def compare_and_summarize(
    url_a: str,
    url_b: str,
    detail: str = "standard",
) -> str:
    """Compare two sites and prepend an executive summary.

    Wraps compare_sites and adds a short lead paragraph highlighting the
    biggest differences — easier for small models to present clearly.

    Args:
        url_a: First site URL.
        url_b: Second site URL.
        detail: Report depth — summary, standard, or full.

    Returns:
        Markdown with executive summary followed by the full comparison.
    """
    detail = detail if detail in ("summary", "standard", "full") else "standard"
    report = await compare_sites(url_a, url_b, detail=detail)

    summary_lines = [
        f"# Comparison summary — {url_a} vs {url_b}",
        "",
        "**Executive summary:** Side-by-side comparison of technology stack, "
        "infrastructure, security headers, and keywords. Review the sections "
        "below for evidence-backed differences.",
        "",
        "---",
        "",
        report,
    ]
    return "\n".join(summary_lines)
