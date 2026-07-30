"""Small, high-value tools that make a local model noticeably smarter.

- `wikipedia_lookup`: fast, reliable factual summaries (no API key).
- `calculate`: a safe arithmetic evaluator -- local models routinely botch
  arithmetic, and this hands them an exact answer.
"""

from __future__ import annotations

import ast
import asyncio
import math
import operator
from urllib.parse import quote

from . import config

# --- Wikipedia ------------------------------------------------------------


def _wiki_get_json(url: str) -> dict:
    """Fetch JSON from Wikimedia. Uses primp because Wikimedia's bot protection
    403s plain httpx by its TLS fingerprint regardless of User-Agent."""
    import primp

    client = primp.Client(impersonate="chrome_130", timeout=config.HTTP_TIMEOUT)
    resp = client.get(url)
    if resp.status_code != 200:
        raise RuntimeError(f"HTTP {resp.status_code}")
    return resp.json()


async def wikipedia_lookup(query: str) -> str:
    """Return a short factual summary of the best-matching Wikipedia article.

    Uses Wikipedia's REST endpoints (search then summary).
    """
    query = (query or "").strip()
    if not query:
        return "Empty query."
    try:
        search_url = (
            "https://en.wikipedia.org/w/rest.php/v1/search/page"
            f"?q={quote(query)}&limit=1"
        )
        pages = (await asyncio.to_thread(_wiki_get_json, search_url)).get("pages", [])
        if not pages:
            return f'No Wikipedia article found for "{query}".'
        key = pages[0].get("key") or pages[0].get("title", "").replace(" ", "_")
        data = await asyncio.to_thread(
            _wiki_get_json,
            f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote(key, safe='')}",
        )
    except ImportError:
        return "Wikipedia lookup needs the 'primp' package (bundled with ddgs)."
    except Exception as exc:
        return f"Wikipedia lookup failed: {type(exc).__name__}: {exc}"

    extract = (data.get("extract") or "").strip()
    if not extract:
        return f'Found "{data.get("title", key)}" but it has no summary (may be a disambiguation page).'
    url = data.get("content_urls", {}).get("desktop", {}).get("page", "")
    return f"# {data.get('title', key)}\n\n{extract}\n\nSource: {url}"


# --- Calculator (safe AST evaluation) -------------------------------------

_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
    ast.Pow: operator.pow, ast.USub: operator.neg, ast.UAdd: operator.pos,
}
_FUNCS = {name: getattr(math, name) for name in (
    "sqrt", "sin", "cos", "tan", "asin", "acos", "atan", "atan2", "log", "log10",
    "log2", "exp", "floor", "ceil", "factorial", "degrees", "radians", "hypot", "gcd",
)}
_FUNCS.update({"abs": abs, "round": round, "min": min, "max": max, "sum": sum})
_CONSTS = {"pi": math.pi, "e": math.e, "tau": math.tau}


class _CalcError(ValueError):
    pass


def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, bool) or not isinstance(node.value, (int, float)):
            raise _CalcError("only numbers are allowed")
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        left, right = _eval(node.left), _eval(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > 1000:
            raise _CalcError("exponent too large")
        return _OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    if isinstance(node, ast.Name):
        if node.id in _CONSTS:
            return _CONSTS[node.id]
        raise _CalcError(f"unknown name '{node.id}'")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        fn = node.func.id
        if fn not in _FUNCS or node.keywords:
            raise _CalcError(f"unknown or invalid function '{fn}'")
        if fn == "factorial":
            arg = _eval(node.args[0])
            if arg > 1000:
                raise _CalcError("factorial argument too large")
        return _FUNCS[fn](*[_eval(a) for a in node.args])
    raise _CalcError("unsupported expression")


def calculate(expression: str) -> str:
    """Evaluate an arithmetic/math expression safely and return the result.

    Supports + - * / // % **, parentheses, and common math functions
    (sqrt, sin, log, factorial, …) and constants (pi, e, tau).
    """
    expression = (expression or "").strip()
    if not expression:
        return "Empty expression."
    try:
        tree = ast.parse(expression, mode="eval")
        result = _eval(tree)
    except ZeroDivisionError:
        return "Error: division by zero."
    except _CalcError as exc:
        return f"Cannot evaluate '{expression}': {exc}."
    except (SyntaxError, ValueError, TypeError, OverflowError) as exc:
        return f"Cannot evaluate '{expression}': {exc}."
    if isinstance(result, float) and result.is_integer():
        result = int(result)
    return f"{expression} = {result}"
