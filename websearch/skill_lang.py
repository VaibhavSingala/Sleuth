"""Polyglot skill files: language detection, schema hints, and interpreters.

Python skills still load in-process (see :mod:`websearch.skills`). Every other
language is a source file invoked as a subprocess. Arguments are a JSON object
passed as:

- the first CLI argument after the script path
- stdin
- ``SLEUTH_ARGS_JSON``
- ``SLEUTH_ARG_<NAME>`` (string form of each argument)

The skill prints its result on stdout.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import config


@dataclass(frozen=True)
class Language:
    name: str
    ext: str
    argv: tuple[str, ...]
    aliases: tuple[str, ...] = ()
    in_process: bool = False

    def available(self) -> bool:
        if self.in_process:
            return True
        return shutil.which(self.argv[0]) is not None


LANGUAGES: dict[str, Language] = {
    "python": Language("python", ".py", ("python",), ("py", "python3"), in_process=True),
    "javascript": Language("javascript", ".js", ("node",), ("js", "node", "nodejs")),
    "bash": Language("bash", ".sh", ("bash",), ("sh", "shell", "zsh")),
    "ruby": Language("ruby", ".rb", ("ruby",), ("rb",)),
    "perl": Language("perl", ".pl", ("perl",), ("pl",)),
    "php": Language("php", ".php", ("php",)),
    "go": Language("go", ".go", ("go", "run"), ("golang",)),
    "lua": Language("lua", ".lua", ("lua",)),
    "r": Language("r", ".R", ("Rscript",), ("rscript", "R")),
}

_ALIAS_TO_NAME = {
    lang.name: lang.name
    for lang in LANGUAGES.values()
}
for lang in LANGUAGES.values():
    for alias in lang.aliases:
        _ALIAS_TO_NAME[alias.lower()] = lang.name

EXT_TO_LANG = {lang.ext.lower(): lang.name for lang in LANGUAGES.values()}
EXT_TO_LANG[".mjs"] = "javascript"
EXT_TO_LANG[".r"] = "r"

CODE_EXTS = {lang.ext for lang in LANGUAGES.values()} | {".mjs", ".r"}
_EXT_PRIORITY = {
    ".py": 0, ".js": 1, ".mjs": 2, ".sh": 3, ".rb": 4,
    ".pl": 5, ".php": 6, ".go": 7, ".lua": 8, ".r": 9, ".R": 9,
}

_TYPE_ALIASES = {
    "str": "string", "text": "string", "string": "string",
    "int": "integer", "integer": "integer", "int32": "integer", "int64": "integer",
    "float": "number", "double": "number", "number": "number", "num": "number",
    "bool": "boolean", "boolean": "boolean",
    "list": "array", "array": "array",
    "dict": "object", "object": "object", "map": "object",
}

_PARAM_RE = re.compile(
    r"@(?:param|arg)\s+"
    r"(?:\{(?P<jstype>[^}]+)\}\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*(?P<colontype>[A-Za-z0-9_|]+))?"
    r"(?:\s*=\s*(?P<default>[^\s-]+))?",
    re.IGNORECASE,
)

_SHEBANG_HINTS = (
    ("python", "python"),
    ("node", "javascript"),
    ("nodejs", "javascript"),
    ("bash", "bash"),
    ("zsh", "bash"),
    ("ruby", "ruby"),
    ("perl", "perl"),
    ("php", "php"),
    ("lua", "lua"),
    ("rscript", "r"),
)


def supported_names() -> list[str]:
    return [lang.name for lang in LANGUAGES.values()]


def normalize_language(name: str | None) -> str | None:
    if not name:
        return None
    key = name.strip().lower()
    if key in ("auto", "detect", ""):
        return None
    resolved = _ALIAS_TO_NAME.get(key)
    if resolved is None:
        raise ValueError(
            f"Unknown skill language '{name}'. "
            f"Use one of: {', '.join(supported_names())}."
        )
    return resolved


def language_for_ext(ext: str) -> str | None:
    return EXT_TO_LANG.get(ext.lower())


def detect_language(code: str, hint: str = "auto", filename: str = "") -> str:
    """Resolve a language from an explicit hint, filename, shebang, or source."""
    explicit = normalize_language(hint)
    if explicit:
        return explicit
    if filename:
        by_ext = language_for_ext(Path(filename).suffix)
        if by_ext:
            return by_ext
    lines = code.strip().splitlines()
    if lines and lines[0].startswith("#!"):
        she = lines[0].lower()
        for token, lang in _SHEBANG_HINTS:
            if token in she:
                return lang
        if she.rstrip().endswith("/sh"):
            return "bash"
    sample = code[:4000]
    if re.search(r"^\s*package\s+main\b", sample, re.M):
        return "go"
    if "<?php" in sample:
        return "php"
    if re.search(
        r"\b(process\.argv|module\.exports|require\(|console\.log)\b", sample
    ) or re.search(r"^\s*(export\s+)?(async\s+)?function\b", sample, re.M):
        return "javascript"
    if re.search(r"^\s*use\s+(strict|warnings)\s*;", sample, re.M):
        return "perl"
    if re.search(r"^\s*sub\s+[A-Za-z_]", sample, re.M) and "my $" in sample:
        return "perl"
    if re.search(r"^\s*def\s+\w+", sample, re.M) and re.search(
        r"^\s*end\b", sample, re.M
    ):
        return "ruby"
    if re.search(r"^\s*(set -e|if\s+\[\[)", sample, re.M):
        return "bash"
    return "python"


def json_type(name: str) -> str:
    return _TYPE_ALIASES.get((name or "string").split("|")[0].strip().lower(), "string")


def schema_from_parameters(raw) -> dict | None:
    """Turn the skill_write ``parameters`` argument into a JSON schema."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"parameters must be JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("parameters must be a JSON object.")
    else:
        raise ValueError("parameters must be a JSON object or JSON string.")
    if "properties" in data and isinstance(data["properties"], dict):
        schema = {"type": "object", "properties": data["properties"]}
        if data.get("required"):
            schema["required"] = list(data["required"])
        return schema
    props: dict = {}
    required: list[str] = []
    for key, value in data.items():
        if isinstance(value, str):
            props[key] = {"type": json_type(value)}
            required.append(key)
        elif isinstance(value, dict):
            spec = dict(value)
            spec["type"] = json_type(spec.get("type", "string"))
            props[key] = spec
            if "default" not in spec:
                required.append(key)
        else:
            props[key] = {"type": "string"}
            required.append(key)
    schema = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def schema_from_comments(code: str) -> tuple[str, dict]:
    """Pull a description and parameter schema out of @param / @arg comments."""
    description = ""
    props: dict = {}
    required: list[str] = []
    for raw_line in code.splitlines()[:80]:
        stripped = raw_line.strip()
        if stripped.startswith("#!"):
            continue
        is_comment = (
            stripped.startswith("#")
            or stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
        )
        line = stripped.lstrip("#/*").strip().lstrip("*").strip()
        if not line:
            continue
        match = _PARAM_RE.search(raw_line)
        if match:
            name = match.group("name")
            type_name = match.group("jstype") or match.group("colontype") or "string"
            spec: dict = {"type": json_type(type_name)}
            default = match.group("default")
            if default is not None:
                spec["default"] = _literal(default)
            else:
                required.append(name)
            props[name] = spec
            continue
        if not is_comment:
            continue
        if line.lower().startswith("@skill "):
            description = description or line[7:].strip()
            continue
        if not description and not line.startswith("@"):
            description = line
    schema: dict = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return description, schema


def _literal(text: str):
    lowered = text.strip().rstrip(",;")
    if lowered.lower() in ("true", "false"):
        return lowered.lower() == "true"
    try:
        if "." in lowered:
            return float(lowered)
        return int(lowered)
    except ValueError:
        return lowered.strip("\"'")


def meta_path(directory: Path, name: str) -> Path:
    return directory / f"{name}.meta.json"


def read_meta(directory: Path, name: str) -> dict:
    path = meta_path(directory, name)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write_meta(directory: Path, name: str, data: dict) -> None:
    path = meta_path(directory, name)
    if not data:
        if path.is_file():
            path.unlink()
        return
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def iter_skill_sources(directory: Path) -> list[Path]:
    """Return one source file per skill stem, preferring Python if both exist."""
    if not directory.is_dir():
        return []
    chosen: dict[str, Path] = {}
    for path in sorted(directory.iterdir(), key=lambda p: p.name):
        if not path.is_file() or path.name.startswith(("_", ".")):
            continue
        if path.suffix not in CODE_EXTS and path.suffix.lower() not in {
            e.lower() for e in CODE_EXTS
        }:
            continue
        if path.name.endswith(".meta.json"):
            continue
        name = path.stem
        existing = chosen.get(name)
        if existing is None:
            chosen[name] = path
            continue
        old_rank = _EXT_PRIORITY.get(existing.suffix, 50)
        new_rank = _EXT_PRIORITY.get(path.suffix, 50)
        if new_rank < old_rank:
            chosen[name] = path
    return [chosen[name] for name in sorted(chosen)]


def find_skill_source(directory: Path, name: str) -> Path | None:
    for path in iter_skill_sources(directory):
        if path.stem == name:
            return path
    # Fall back to a missing preferred python path for error messages.
    return None


def remove_skill_files(directory: Path, name: str, keep: Path | None = None) -> list[Path]:
    """Delete source + sidecar files for ``name``, optionally keeping one path."""
    removed: list[Path] = []
    if not directory.is_dir():
        return removed
    for path in list(directory.iterdir()):
        if not path.is_file():
            continue
        if path == keep:
            continue
        if path.stem == name and (
            path.suffix in CODE_EXTS
            or path.suffix.lower() in {e.lower() for e in CODE_EXTS}
            or path.name == f"{name}.meta.json"
        ):
            path.unlink()
            removed.append(path)
    return removed


def syntax_check(lang: Language, path: Path) -> str | None:
    """Return a syntax-error message, or None if the file looks valid / uncheckable."""
    if lang.in_process:
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except SyntaxError as exc:
            return str(exc)
        return None
    if not lang.available():
        return None
    if lang.name == "javascript":
        cmd = ["node", "--check", str(path)]
    elif lang.name == "bash":
        cmd = ["bash", "-n", str(path)]
    elif lang.name == "ruby":
        cmd = ["ruby", "-c", str(path)]
    elif lang.name == "perl":
        cmd = ["perl", "-c", str(path)]
    elif lang.name == "php":
        cmd = ["php", "-l", str(path)]
    elif lang.name == "go":
        # gofmt -e reports parse errors without rewriting the file.
        cmd = ["gofmt", "-e", str(path)]
    elif lang.name == "lua":
        cmd = ["luac", "-p", str(path)]
    elif lang.name == "r":
        return None
    else:
        return None
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=20, cwd=str(path.parent)
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
    return None


def make_external_fn(name: str, path: Path, lang: Language):
    """Return a sync callable that runs ``path`` with JSON arguments."""

    def run(**kwargs):
        payload = json.dumps(kwargs, default=str)
        env = os.environ.copy()
        env["SLEUTH_SKILL"] = name
        env["SLEUTH_ARGS_JSON"] = payload
        for key, value in kwargs.items():
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                env[f"SLEUTH_ARG_{key.upper()}"] = "" if value is None else str(value)
        cmd = list(lang.argv) + [str(path), payload]
        try:
            proc = subprocess.run(
                cmd,
                input=payload,
                capture_output=True,
                text=True,
                timeout=config.SKILL_TIMEOUT,
                cwd=str(path.parent),
                env=env,
            )
        except FileNotFoundError:
            return f"Error: '{lang.argv[0]}' is not installed (needed for {lang.name} skills)."
        except subprocess.TimeoutExpired:
            return f"Error: skill '{name}' timed out after {config.SKILL_TIMEOUT:.0f}s."
        out = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip()
        if proc.returncode != 0:
            parts = [f"Error: skill '{name}' exited {proc.returncode}."]
            if out:
                parts.append("stdout:\n" + out)
            if err:
                parts.append("stderr:\n" + err)
            return "\n".join(parts)
        return out or err or "(no output)"

    run.__name__ = name
    run.__qualname__ = name
    return run


def write_atomic(path: Path, code: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name, dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(code)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
