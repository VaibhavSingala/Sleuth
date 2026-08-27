"""Self-authored skills, code self-editing, and arbitrary execution.

This is the subsystem that lets the model extend itself. It can:

- **write a function into ``SKILLS_DIR`` and call it as a tool on the
  very next turn** -- ``skill_write`` / ``skill_list`` / ``skill_read`` /
  ``skill_delete``. Python skills define a function whose name is the file stem
  (or ``run``); its signature becomes the tool's JSON parameter schema and its
  docstring the tool description. The same tools accept JavaScript, Bash, Ruby,
  Perl, PHP, Go, Lua and R: those files run in a subprocess and take JSON
  arguments on argv/stdin.
- **read and patch this package's own source** -- ``code_read`` /
  ``code_search`` / ``code_write`` / ``code_revert``. Every write is snapshotted
  to ``BACKUP_DIR`` first, and a ``.py`` file that stops parsing is rolled back
  automatically so a bad edit can't take the running process down.
- **run arbitrary Python in-process or a shell command** -- ``python_exec``
  (against the live package, so it can call what it just wrote) and
  ``shell_exec``.

Each capability has an independent kill-switch in :mod:`config`. This agent
reads untrusted web pages, so with everything on, a prompt-injected page that
talks the model into authoring a skill reaches arbitrary code execution with
this process's environment. Narrow the ``SLEUTH_*`` flags to taste.
"""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import io
import json
import logging
import os
import re
import subprocess
import sys
import traceback
import typing
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

from . import config, skill_lang, auto_review

log = logging.getLogger(__name__)

# Tool names the model may not claim for a skill: the built-in web tools plus
# the meta-tools below. agent.py / server.py call reserve() with their own
# built-in names at import time; the meta names are seeded here.
_RESERVED: set[str] = set()


def reserve(names) -> None:
    """Record tool names a skill is not allowed to shadow."""
    _RESERVED.update(names)


# --- signature -> JSON schema --------------------------------------------

_JSON_TYPES = {
    str: "string", int: "integer", float: "number",
    bool: "boolean", list: "array", dict: "object",
}
_JSON_TYPE_NAMES = {
    "str": "string", "int": "integer", "float": "number",
    "bool": "boolean", "list": "array", "dict": "object",
}


def _annotation_to_json(annotation) -> str:
    """Best-effort map of a Python annotation to a JSON-schema type name."""
    if annotation is inspect.Parameter.empty:
        return "string"
    if isinstance(annotation, str):  # `from __future__ import annotations`
        return _JSON_TYPE_NAMES.get(annotation.split("|")[0].strip().lower(), "string")
    if annotation in _JSON_TYPES:
        return _JSON_TYPES[annotation]
    origin = typing.get_origin(annotation)
    if origin is typing.Union or (origin is not None and str(origin) == "types.UnionType"):
        for arg in typing.get_args(annotation):
            if arg is not type(None):
                return _annotation_to_json(arg)
        return "string"
    if origin in _JSON_TYPES:
        return _JSON_TYPES[origin]
    return "string"


def _schema_from_fn(fn) -> dict:
    """Derive an OpenAI-style parameter schema from a function signature."""
    props: dict = {}
    required: list = []
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return {"type": "object", "properties": {}}
    for name, p in sig.parameters.items():
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        prop = {"type": _annotation_to_json(p.annotation)}
        if p.default is inspect.Parameter.empty:
            required.append(name)
        elif isinstance(p.default, (str, int, float, bool)):
            prop["default"] = p.default
        props[name] = prop
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _first_paragraph(doc: str | None) -> str:
    if not doc:
        return ""
    out: list[str] = []
    for line in doc.strip().splitlines():
        if not line.strip():
            break
        out.append(line.strip())
    return " ".join(out)


def _signature_str(fn) -> str:
    try:
        return str(inspect.signature(fn))
    except (TypeError, ValueError):
        return "(...)"


_JSON_TO_PY = {
    "string": str, "integer": int, "number": float,
    "boolean": bool, "array": list, "object": dict,
}


def _bind_schema_signature(fn, schema: dict, name: str):
    """Give an external skill wrapper a signature FastMCP / inspect can read."""
    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    params: list[inspect.Parameter] = []
    for pname, spec in props.items():
        spec = spec if isinstance(spec, dict) else {}
        json_type = spec.get("type", "string")
        if isinstance(json_type, list):
            json_type = json_type[0] if json_type else "string"
        default = inspect.Parameter.empty
        if pname not in required or "default" in spec:
            default = spec.get("default", None)
        params.append(inspect.Parameter(
            pname,
            kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
            default=default,
            annotation=_JSON_TO_PY.get(json_type, str),
        ))
    try:
        fn.__signature__ = inspect.Signature(params)
    except (TypeError, ValueError):
        pass
    fn.__name__ = name
    return fn


# --- the skill registry ---------------------------------------------------


class Skill:
    __slots__ = (
        "name", "path", "fn", "is_async", "schema", "description",
        "mtime", "error", "language",
    )

    def __init__(self, name: str, path: Path):
        self.name = name
        self.path = path
        self.fn = None
        self.is_async = False
        self.schema: dict = {"type": "object", "properties": {}}
        self.description = ""
        self.error: str | None = None
        self.mtime = 0.0
        self.language = "python"


class Registry:
    """Loads skill source files and keeps them in sync with disk by mtime."""

    def __init__(self, directory: Path):
        self.dir = directory
        self.skills: dict[str, Skill] = {}

    def refresh(self) -> None:
        if not config.SKILLS_ENABLED or not self.dir.is_dir():
            self.skills = {}
            return
        seen: set[str] = set()
        for path in skill_lang.iter_skill_sources(self.dir):
            name = path.stem
            seen.add(name)
            try:
                mtime = path.stat().st_mtime
                meta = skill_lang.meta_path(self.dir, name)
                if meta.is_file():
                    mtime = max(mtime, meta.stat().st_mtime)
            except OSError:
                continue
            existing = self.skills.get(name)
            if existing is None or existing.mtime != mtime:
                self.skills[name] = self._load(name, path, mtime)
        for stale in set(self.skills) - seen:  # deleted on disk
            del self.skills[stale]

    def _load(self, name: str, path: Path, mtime: float) -> Skill:
        skill = Skill(name, path)
        skill.mtime = mtime
        meta = skill_lang.read_meta(self.dir, name)
        language = meta.get("language") or skill_lang.language_for_ext(path.suffix) or "python"
        try:
            language = skill_lang.normalize_language(language) or "python"
        except ValueError:
            language = "python"
        skill.language = language
        lang = skill_lang.LANGUAGES[language]
        if lang.in_process:
            return self._load_python(skill, name, path, meta)
        return self._load_external(skill, name, path, lang, meta)

    def _apply_meta(self, skill: Skill, meta: dict, fallback_desc: str) -> None:
        if meta.get("description"):
            skill.description = meta["description"]
        elif not skill.description:
            skill.description = fallback_desc
        schema = meta.get("schema")
        if isinstance(schema, dict) and schema.get("properties"):
            skill.schema = schema

    def _load_python(self, skill: Skill, name: str, path: Path, meta: dict) -> Skill:
        try:
            code = path.read_text(encoding="utf-8")
        except OSError as exc:
            skill.error = f"could not read {path}: {exc}"
            return skill
        blocked = auto_review.classify_text(code)
        if not blocked.allowed:
            skill.error = blocked.message()
            return skill
        modname = f"websearch._skills.{name}"
        try:
            spec = importlib.util.spec_from_file_location(modname, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[modname] = module  # so dataclasses / relative refs resolve
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception:
            skill.error = traceback.format_exc(limit=3)
            log.warning("skill %s failed to import:\n%s", name, skill.error)
            return skill
        fn = getattr(module, name, None) or getattr(module, "run", None)
        if not callable(fn):
            skill.error = (
                f"no callable named '{name}' or 'run' found in the file; "
                "define one of those as the skill's entry point."
            )
            return skill
        skill.fn = fn
        skill.is_async = inspect.iscoroutinefunction(fn)
        skill.schema = _schema_from_fn(fn)
        skill.description = _first_paragraph(fn.__doc__) or f"Skill '{name}'."
        self._apply_meta(skill, meta, skill.description)
        return skill

    def _load_external(
        self, skill: Skill, name: str, path: Path, lang: skill_lang.Language, meta: dict
    ) -> Skill:
        if not lang.available():
            skill.error = (
                f"{lang.name} interpreter '{lang.argv[0]}' is not installed; "
                "install it or rewrite the skill in python."
            )
            return skill
        try:
            code = path.read_text(encoding="utf-8")
        except OSError as exc:
            skill.error = f"could not read {path}: {exc}"
            return skill
        comment_desc, comment_schema = skill_lang.schema_from_comments(code)
        blocked = auto_review.classify_text(code)
        if not blocked.allowed:
            skill.error = blocked.message()
            return skill
        skill.schema = comment_schema
        skill.description = comment_desc or f"Skill '{name}' ({lang.name})."
        self._apply_meta(skill, meta, skill.description)
        fn = skill_lang.make_external_fn(name, path, lang)
        _bind_schema_signature(fn, skill.schema, name)
        fn.__doc__ = skill.description
        skill.fn = fn
        skill.is_async = False
        return skill

    def valid(self) -> list[Skill]:
        return [s for s in self.skills.values() if s.error is None and s.fn is not None]


REGISTRY = Registry(config.SKILLS_DIR)


def refresh() -> None:
    REGISTRY.refresh()


# --- coercion + skill invocation -----------------------------------------


def _to_text(value) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "(no return value)"
    try:
        return json.dumps(value, indent=2, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


async def _invoke_skill(skill: Skill, kwargs: dict) -> str:
    try:
        source = skill.path.read_text(encoding="utf-8") if skill.path.is_file() else ""
    except OSError:
        source = ""
    blocked = auto_review.guard(skill.name, kwargs, source=source)
    if blocked:
        return blocked
    try:
        if skill.is_async:
            value = await asyncio.wait_for(skill.fn(**kwargs), timeout=config.SKILL_TIMEOUT)
        else:
            value = await asyncio.wait_for(
                asyncio.to_thread(skill.fn, **kwargs), timeout=config.SKILL_TIMEOUT
            )
    except asyncio.TimeoutError:
        return f"Error: skill '{skill.name}' timed out after {config.SKILL_TIMEOUT:.0f}s."
    except TypeError as exc:
        return f"Error: bad arguments for skill '{skill.name}': {exc}"
    except Exception:
        return f"Error running skill '{skill.name}':\n{traceback.format_exc(limit=4)}"
    return _to_text(value)


def _skill_wrapper(skill: Skill):
    async def wrapper(**kwargs):
        return await _invoke_skill(skill, kwargs)
    wrapper.__name__ = skill.name
    wrapper.__doc__ = skill.description
    if skill.fn is not None:
        try:
            wrapper.__signature__ = inspect.signature(skill.fn)
        except (TypeError, ValueError):
            pass
    return wrapper


# --- meta-tools: skill management ----------------------------------------

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,48}$")


def _bad_name(name: str) -> str | None:
    if not _NAME_RE.match(name or ""):
        return (
            f"Invalid skill name '{name}'. Use a short lower_snake_case identifier "
            "(letters, digits, underscores; starting with a letter)."
        )
    if name in _RESERVED:
        return f"'{name}' is a built-in tool name; choose another."
    return None


def skill_write(
    name: str,
    code: str,
    description: str = "",
    language: str = "auto",
    parameters: str = "",
) -> str:
    """Create or replace a skill and register it as a callable tool.

    `code` is the full source. For Python, define a function named `name` (or
    `run`); its parameters become the tool's arguments and its docstring the
    description. For other languages (`javascript`, `bash`, `ruby`, `perl`,
    `php`, `go`, `lua`, `r`) the file is run as a subprocess. Pass arguments as
    JSON on argv[1], stdin, `SLEUTH_ARGS_JSON`, or `SLEUTH_ARG_<NAME>`, and
    print the result to stdout.

    `language` is `auto` (detect from shebang/source), or an explicit name.
    `parameters` is optional JSON describing the tool args when they cannot be
    inferred (`{"f": "number"}` or a full schema with `properties`).
    """
    if not config.SKILLS_ENABLED:
        return "Skills are disabled (SLEUTH_SKILLS=false)."
    bad = _bad_name(name)
    if bad:
        return bad
    blocked = auto_review.guard("skill_write", {"name": name, "code": code})
    if blocked:
        return blocked
    try:
        lang_name = skill_lang.detect_language(code, hint=language)
        schema_override = skill_lang.schema_from_parameters(parameters)
    except ValueError as exc:
        return str(exc)
    lang = skill_lang.LANGUAGES[lang_name]
    config.SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    path = config.SKILLS_DIR / f"{name}{lang.ext}"
    if lang.in_process:
        try:
            compile(code, str(path), "exec")
        except SyntaxError as exc:
            return f"Skill not saved -- syntax error: {exc}"
    try:
        staging = path.with_name(f".{path.stem}.staging{path.suffix}")
        skill_lang.write_atomic(staging, code)
    except OSError as exc:
        return f"Could not write skill file: {exc}"
    syntax_err = skill_lang.syntax_check(lang, staging)
    if syntax_err:
        try:
            staging.unlink()
        except OSError:
            pass
        return f"Skill not saved -- syntax error: {syntax_err}"
    try:
        os.replace(staging, path)
    except OSError as exc:
        try:
            staging.unlink()
        except OSError:
            pass
        return f"Could not write skill file: {exc}"
    skill_lang.remove_skill_files(config.SKILLS_DIR, name, keep=path)

    comment_desc, comment_schema = skill_lang.schema_from_comments(code)
    meta: dict = {"language": lang_name}
    if description.strip():
        meta["description"] = description.strip()
    elif comment_desc:
        meta["description"] = comment_desc
    schema = schema_override or (comment_schema if comment_schema.get("properties") else None)
    if schema:
        meta["schema"] = schema
    if not lang.in_process or description.strip() or schema_override:
        skill_lang.write_meta(config.SKILLS_DIR, name, meta)
    else:
        skill_lang.write_meta(config.SKILLS_DIR, name, {})

    REGISTRY.skills.pop(name, None)  # force a reload of this stem
    REGISTRY.refresh()
    skill = REGISTRY.skills.get(name)
    if skill is None:
        return f"Wrote {path} but it did not load."
    if skill.error:
        return (
            f"Saved {path}, but it does not work yet -- fix and call skill_write "
            f"again:\n{skill.error}"
        )
    return (
        f"Skill '{name}' is live and callable now.\n"
        f"Language: {skill.language}\n"
        f"File: {path.name}\n"
        f"Signature: {name}{_signature_str(skill.fn)}\n"
        f"Description: {skill.description}\n"
        f"Parameters: {json.dumps(skill.schema.get('properties', {}))}"
    )


def skill_list() -> str:
    """List every authored skill with its signature, description and status."""
    if not config.SKILLS_ENABLED:
        return "Skills are disabled (SLEUTH_SKILLS=false)."
    REGISTRY.refresh()
    if not REGISTRY.skills:
        return f"No skills yet. Author one with skill_write. Directory: {config.SKILLS_DIR}"
    lines = [f"Skills in {config.SKILLS_DIR}:", ""]
    for name in sorted(REGISTRY.skills):
        skill = REGISTRY.skills[name]
        lang = getattr(skill, "language", "python")
        if skill.error:
            lines.append(
                f"- {name} [{lang}]  [BROKEN] {skill.error.splitlines()[-1][:80]}"
            )
        else:
            lines.append(
                f"- {name}{_signature_str(skill.fn)} [{lang}] — {skill.description}"
            )
    return "\n".join(lines)


def skill_catalog() -> list[dict]:
    """Structured skill catalog for the webchat UI."""
    if not config.SKILLS_ENABLED:
        return []
    REGISTRY.refresh()
    catalog: list[dict] = []
    for name in sorted(REGISTRY.skills):
        skill = REGISTRY.skills[name]
        props = skill.schema.get("properties", {}) if skill.schema else {}
        params = list(props.keys())
        example_args = ", ".join(
            f'{p}="..."' for p in params[:3]
        )
        example = f"{name}({example_args})" if example_args else f"{name}()"
        catalog.append({
            "name": name,
            "description": skill.description or f"Skill '{name}'.",
            "language": getattr(skill, "language", "python"),
            "ok": skill.error is None and skill.fn is not None,
            "parameters": params,
            "example": example,
            "error": (skill.error or "")[:120] if skill.error else "",
        })
    return catalog


def skill_read(name: str) -> str:
    """Return the full source of an authored skill so it can be edited."""
    path = skill_lang.find_skill_source(config.SKILLS_DIR, name)
    if path is None or not path.is_file():
        return f"No skill named '{name}'. Use skill_list to see what exists."
    try:
        lang = skill_lang.language_for_ext(path.suffix) or "python"
        return f"# {path} ({lang})\n\n{path.read_text(encoding='utf-8')}"
    except OSError as exc:
        return f"Could not read skill: {exc}"


def skill_delete(name: str) -> str:
    """Delete an authored skill by name."""
    path = skill_lang.find_skill_source(config.SKILLS_DIR, name)
    if path is None or not path.is_file():
        return f"No skill named '{name}'."
    try:
        skill_lang.remove_skill_files(config.SKILLS_DIR, name)
    except OSError as exc:
        return f"Could not delete skill: {exc}"
    REGISTRY.skills.pop(name, None)
    return f"Deleted skill '{name}'."


# --- meta-tools: code self-editing ---------------------------------------


def _resolve_in_root(path: str) -> Path | None:
    """Resolve `path` and confirm it stays inside CODE_ROOT (no traversal)."""
    root = config.CODE_ROOT.resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve()
    if candidate == root or root in candidate.parents:
        return candidate
    return None


def _backup_path(target: Path) -> Path:
    rel = target.resolve().relative_to(config.CODE_ROOT.resolve())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    flat = str(rel).replace("/", "__").replace("\\", "__")
    return config.BACKUP_DIR / f"{flat}.{stamp}.bak"


def _prune_backups(target: Path) -> None:
    rel = target.resolve().relative_to(config.CODE_ROOT.resolve())
    flat = str(rel).replace("/", "__").replace("\\", "__")
    backups = sorted(config.BACKUP_DIR.glob(f"{flat}.*.bak"))
    for old in backups[: -config.BACKUP_KEEP] if config.BACKUP_KEEP > 0 else []:
        try:
            old.unlink()
        except OSError:
            pass


def code_read(path: str, max_chars: int = 20000) -> str:
    """Read a source file under CODE_ROOT, with line numbers for editing."""
    target = _resolve_in_root(path)
    if target is None:
        return f"Refused: '{path}' is outside CODE_ROOT ({config.CODE_ROOT})."
    if not target.is_file():
        return f"No such file: {target}"
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return f"Could not read {target}: {exc}"
    truncated = len(text) > max_chars
    numbered = "\n".join(f"{i:>5}  {ln}" for i, ln in enumerate(text[:max_chars].splitlines(), 1))
    out = f"# {target}\n{numbered}"
    if truncated:
        out += f"\n\n[...truncated at {max_chars} chars; pass a larger max_chars.]"
    return out


def code_search(pattern: str, glob: str = "*.py", max_results: int = 60) -> str:
    """Search source files under CODE_ROOT for a regex; returns file:line hits."""
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return f"Bad regex: {exc}"
    root = config.CODE_ROOT.resolve()
    hits: list[str] = []
    for file in root.rglob(glob):
        if any(part in {"__pycache__", ".backups", ".cache", ".git", "conversations"}
               for part in file.parts):
            continue
        if not file.is_file():
            continue
        try:
            for n, line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
                if rx.search(line):
                    rel = file.relative_to(root)
                    hits.append(f"{rel}:{n}: {line.strip()[:160]}")
                    if len(hits) >= max_results:
                        hits.append(f"[...capped at {max_results} matches]")
                        return "\n".join(hits)
        except (OSError, UnicodeDecodeError):
            continue
    return "\n".join(hits) if hits else f"No matches for /{pattern}/ in {glob} files."


def code_write(path: str, content: str) -> str:
    """Overwrite a source file under CODE_ROOT (snapshotted; auto-reverts a
    ``.py`` file that stops parsing)."""
    if not config.CODE_EDIT_ENABLED:
        return "Self-editing is disabled (SLEUTH_ALLOW_SELF_EDIT=false)."
    blocked = auto_review.guard("code_write", {"path": path, "content": content})
    if blocked:
        return blocked
    target = _resolve_in_root(path)
    if target is None:
        return f"Refused: '{path}' is outside CODE_ROOT ({config.CODE_ROOT})."

    previous: str | None = None
    if target.exists():
        try:
            previous = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            previous = None
        if previous is not None:
            config.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            try:
                _backup_path(target).write_text(previous, encoding="utf-8")
                _prune_backups(target)
            except OSError as exc:
                return f"Aborted: could not snapshot {target} before writing: {exc}"

    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_text(content, encoding="utf-8")
    except OSError as exc:
        return f"Could not write {target}: {exc}"

    if target.suffix == ".py":
        try:
            compile(content, str(target), "exec")
        except SyntaxError as exc:
            if previous is not None:
                target.write_text(previous, encoding="utf-8")
                return f"Reverted: the new content has a syntax error and was not kept: {exc}"
            return f"Kept, but it has a syntax error (no prior version to revert to): {exc}"

    verb = "Updated" if previous is not None else "Created"
    return f"{verb} {target} ({len(content)} chars). A backup of the prior version was saved."


def code_revert(path: str) -> str:
    """Restore a source file from its most recent snapshot in BACKUP_DIR."""
    if not config.CODE_EDIT_ENABLED:
        return "Self-editing is disabled (SLEUTH_ALLOW_SELF_EDIT=false)."
    blocked = auto_review.guard("code_revert", {"path": path})
    if blocked:
        return blocked
    target = _resolve_in_root(path)
    if target is None:
        return f"Refused: '{path}' is outside CODE_ROOT ({config.CODE_ROOT})."
    try:
        rel = target.relative_to(config.CODE_ROOT.resolve())
    except ValueError:
        return f"Refused: '{path}' is outside CODE_ROOT."
    flat = str(rel).replace("/", "__").replace("\\", "__")
    backups = sorted(config.BACKUP_DIR.glob(f"{flat}.*.bak"))
    if not backups:
        return f"No snapshot found for {target}."
    newest = backups[-1]
    try:
        target.write_text(newest.read_text(encoding="utf-8"), encoding="utf-8")
    except OSError as exc:
        return f"Could not restore {target}: {exc}"
    return f"Reverted {target} from snapshot {newest.name}."


# --- meta-tools: arbitrary execution -------------------------------------

_MAX_EXEC_OUTPUT = 8000


def _clip(text: str) -> str:
    text = text or ""
    if len(text) > _MAX_EXEC_OUTPUT:
        return text[:_MAX_EXEC_OUTPUT] + f"\n[...output clipped at {_MAX_EXEC_OUTPUT} chars]"
    return text


def _run_python_sync(code: str) -> str:
    import websearch  # seed the namespace with the live package for convenience

    ns: dict = {"__name__": "__sleuth_exec__", "ws": websearch, "websearch": websearch}
    buf = io.StringIO()
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            exec(compile(code, "<python_exec>", "exec"), ns)
    except Exception:
        return _clip(buf.getvalue() + "\n" + traceback.format_exc(limit=5))
    out = buf.getvalue()
    if "result" in ns and ns["result"] is not None:
        out += ("\n" if out else "") + f"result = {ns['result']!r}"
    return _clip(out) or "(no output; set a `result` variable or print() to see values.)"


async def python_exec(code: str) -> str:
    """Execute Python in-process against the live package and return its output.

    `print()` output is captured; a variable named `result` is also reported.
    The package is available as `ws`/`websearch`. Runs synchronously -- for
    async code, call `asyncio.run(...)` yourself.
    """
    if not config.EXEC_ENABLED:
        return "Execution is disabled (SLEUTH_ALLOW_EXEC=false)."
    blocked = auto_review.guard("python_exec", {"code": code})
    if blocked:
        return blocked
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_python_sync, code), timeout=config.EXEC_TIMEOUT
        )
    except asyncio.TimeoutError:
        return (
            f"python_exec timed out after {config.EXEC_TIMEOUT:.0f}s. "
            "(The code may still be running in a background thread.)"
        )


async def shell_exec(command: str, timeout: float = 0) -> str:
    """Run a shell command from CODE_ROOT and return its stdout, stderr and code."""
    if not config.EXEC_ENABLED:
        return "Execution is disabled (SLEUTH_ALLOW_EXEC=false)."
    blocked = auto_review.guard("shell_exec", {"command": command})
    if blocked:
        return blocked
    limit = timeout or config.EXEC_TIMEOUT

    def _run() -> str:
        try:
            proc = subprocess.run(
                command, shell=True, cwd=str(config.CODE_ROOT),
                capture_output=True, text=True, timeout=limit,
            )
        except subprocess.TimeoutExpired:
            return f"Command timed out after {limit:.0f}s."
        parts = [f"exit code: {proc.returncode}"]
        if proc.stdout:
            parts.append("stdout:\n" + proc.stdout)
        if proc.stderr:
            parts.append("stderr:\n" + proc.stderr)
        return _clip("\n".join(parts))

    return await asyncio.to_thread(_run)


# --- assembly: schemas + handlers for the surfaces -----------------------

_META_SCHEMAS: list[dict] = [
    {
        "name": "skill_write", "group": "skills",
        "description": (
            "Author a new tool for yourself in Python, JavaScript, Bash, Ruby, "
            "Perl, PHP, Go, Lua or R. Python: define a function named the same "
            "as the skill (or `run`); its parameters become the tool arguments "
            "and its docstring the description. Other languages run as a "
            "subprocess — read JSON args from argv[1] / stdin / SLEUTH_ARGS_JSON "
            "/ SLEUTH_ARG_<NAME> and print the result to stdout. Use this when a "
            "capability you need doesn't exist yet."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string",
                         "description": "lower_snake_case tool name (also the file stem)."},
                "code": {"type": "string",
                         "description": "Full source of the skill."},
                "description": {"type": "string",
                                "description": "Optional human summary (docstring / @param comments used if omitted)."},
                "language": {"type": "string",
                             "description": "python, javascript, bash, ruby, perl, php, go, lua, r, or auto to detect.",
                             "default": "auto"},
                "parameters": {"type": "string",
                               "description": "Optional JSON object of tool args, e.g. {\"f\":\"number\"}, when they cannot be inferred."},
            },
            "required": ["name", "code"],
        },
    },
    {
        "name": "skill_list", "group": "skills",
        "description": "List the skills you have authored, with signatures and status.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "skill_read", "group": "skills",
        "description": "Read the source of one of your authored skills to edit it.",
        "parameters": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Skill name."}},
            "required": ["name"],
        },
    },
    {
        "name": "skill_delete", "group": "skills",
        "description": "Delete one of your authored skills.",
        "parameters": {
            "type": "object",
            "properties": {"name": {"type": "string", "description": "Skill name."}},
            "required": ["name"],
        },
    },
    {
        "name": "code_read", "group": "code",
        "description": "Read a source file of this project (with line numbers) so you can edit it.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the project root."},
                "max_chars": {"type": "integer", "default": 20000},
            },
            "required": ["path"],
        },
    },
    {
        "name": "code_search", "group": "code",
        "description": "Regex-search the project's source to find where something is defined.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Regular expression."},
                "glob": {"type": "string", "description": "Filename glob (default *.py).",
                         "default": "*.py"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "code_write", "group": "code_edit",
        "description": (
            "Overwrite a source file of THIS project. The prior version is "
            "snapshotted first, and a Python file that no longer parses is "
            "auto-reverted. Read the file first; write the whole new content."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the project root."},
                "content": {"type": "string", "description": "The complete new file content."},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "code_revert", "group": "code_edit",
        "description": "Undo your last code_write to a file by restoring its newest snapshot.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path relative to the project root."}},
            "required": ["path"],
        },
    },
    {
        "name": "python_exec", "group": "exec",
        "description": (
            "Run Python in-process against the live package and get its output. "
            "Good for trying a skill you just wrote, or one-off computation. The "
            "package is available as `ws`. print() is captured; a `result` "
            "variable is reported. Auto-review blocks host-damaging code; "
            "target-directed work is allowed."
        ),
        "parameters": {
            "type": "object",
            "properties": {"code": {"type": "string", "description": "Python source to execute."}},
            "required": ["code"],
        },
    },
    {
        "name": "shell_exec", "group": "exec",
        "description": (
            "Run a shell command from the project root and return its output. "
            "Auto-review blocks host-damaging commands; work aimed at a remote "
            "target (curl to a URL, ssh/adb to a remote host) is allowed."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command line to run."},
                "timeout": {"type": "integer", "description": "Seconds (0 = default)."},
            },
            "required": ["command"],
        },
    },
]

_META_HANDLERS = {
    "skill_write": skill_write, "skill_list": skill_list,
    "skill_read": skill_read, "skill_delete": skill_delete,
    "code_read": code_read, "code_search": code_search,
    "code_write": code_write, "code_revert": code_revert,
    "python_exec": python_exec, "shell_exec": shell_exec,
}

reserve(_META_HANDLERS.keys())


def _group_enabled(group: str) -> bool:
    if group in ("skills", "code"):
        return config.SKILLS_ENABLED
    if group == "code_edit":
        return config.SKILLS_ENABLED and config.CODE_EDIT_ENABLED
    if group == "exec":
        return config.SKILLS_ENABLED and config.EXEC_ENABLED
    return False


def meta_tool_schemas() -> list[dict]:
    """OpenAI tool schemas for the enabled meta-tools."""
    out = []
    for spec in _META_SCHEMAS:
        if not _group_enabled(spec["group"]):
            continue
        out.append({
            "type": "function",
            "function": {
                "name": spec["name"],
                "description": spec["description"],
                "parameters": spec["parameters"],
            },
        })
    return out


def meta_handlers() -> dict:
    """Callables for the enabled meta-tools, keyed by tool name."""
    return {
        spec["name"]: _META_HANDLERS[spec["name"]]
        for spec in _META_SCHEMAS
        if _group_enabled(spec["group"])
    }


def skill_tool_schemas() -> list[dict]:
    """OpenAI tool schemas for every currently-valid authored skill."""
    if not config.SKILLS_ENABLED:
        return []
    out = []
    for skill in REGISTRY.valid():
        out.append({
            "type": "function",
            "function": {
                "name": skill.name,
                "description": skill.description,
                "parameters": skill.schema,
            },
        })
    return out


def skill_handlers() -> dict:
    """Async callables for every currently-valid authored skill."""
    if not config.SKILLS_ENABLED:
        return {}
    return {skill.name: _skill_wrapper(skill) for skill in REGISTRY.valid()}


def resolve(name: str):
    """Return a handler for a meta-tool or authored skill, or None."""
    meta = meta_handlers()
    if name in meta:
        return meta[name]
    return skill_handlers().get(name)


def is_tool(name: str) -> bool:
    return name in meta_handlers() or name in REGISTRY.skills


# --- standalone CLI (python -m websearch.skills) -------------------------


def _cli() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m websearch.skills",
        description="Inspect and manage the model's self-authored skills.",
    )
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("list", help="List authored skills.")
    p_read = sub.add_parser("read", help="Print a skill's source.")
    p_read.add_argument("name")
    p_new = sub.add_parser("write", help="Create a skill from a source file on disk.")
    p_new.add_argument("name")
    p_new.add_argument("file", help="Path to the skill source (extension selects language).")
    p_new.add_argument("--language", default="auto",
                       help="python/javascript/bash/... or auto (default: from file extension).")
    p_new.add_argument("--parameters", default="",
                       help="JSON object describing tool arguments.")
    p_del = sub.add_parser("delete", help="Delete a skill.")
    p_del.add_argument("name")
    p_run = sub.add_parser("call", help="Invoke a skill with JSON arguments.")
    p_run.add_argument("name")
    p_run.add_argument("json_args", nargs="?", default="{}",
                       help='e.g. \'{"city": "Paris"}\'')
    p_py = sub.add_parser("exec", help="Run Python in-process (python_exec).")
    p_py.add_argument("code")
    args = parser.parse_args()

    if args.cmd in (None, "list"):
        print(skill_list())
        return 0
    if args.cmd == "read":
        print(skill_read(args.name))
        return 0
    if args.cmd == "write":
        try:
            code = Path(args.file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"Could not read {args.file}: {exc}", file=sys.stderr)
            return 1
        hint = args.language
        if hint in ("auto", "", None):
            from . import skill_lang as _sl
            hint = _sl.language_for_ext(Path(args.file).suffix) or "auto"
        print(skill_write(args.name, code, language=hint, parameters=args.parameters))
        return 0
    if args.cmd == "delete":
        print(skill_delete(args.name))
        return 0
    if args.cmd == "call":
        refresh()
        skill = REGISTRY.skills.get(args.name)
        if skill is None or skill.error or skill.fn is None:
            print(f"Skill '{args.name}' is not available.", file=sys.stderr)
            return 1
        try:
            kwargs = json.loads(args.json_args)
        except json.JSONDecodeError as exc:
            print(f"Bad JSON arguments: {exc}", file=sys.stderr)
            return 1
        print(asyncio.run(_invoke_skill(skill, kwargs)))
        return 0
    if args.cmd == "exec":
        print(asyncio.run(python_exec(args.code)))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="[skills] %(levelname)s %(message)s")
    try:  # keep em-dashes etc. readable on a legacy Windows code page
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    raise SystemExit(_cli())
