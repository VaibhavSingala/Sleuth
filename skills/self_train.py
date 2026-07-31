"""Persistent self-training loop for the AI agent.

Stores lessons, practice attempts, and goals on disk so the model can improve
across conversations. Use alongside skill_write to turn repeated patterns into
new tools.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

# Stored next to authored skills; hidden from the skill glob (starts with _).
_TRAINING_DIR = Path(__file__).resolve().parent / ".training"
_KNOWLEDGE_FILE = _TRAINING_DIR / "knowledge.json"
_SESSIONS_FILE = _TRAINING_DIR / "sessions.json"
_GOALS_FILE = _TRAINING_DIR / "goals.json"

Action = Literal[
    "record_lesson",
    "recall",
    "log_attempt",
    "set_goal",
    "complete_goal",
    "review",
    "next_step",
    "export_dataset",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_dir() -> None:
    _TRAINING_DIR.mkdir(parents=True, exist_ok=True)


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def _save(path: Path, rows: list[dict[str, Any]]) -> None:
    _ensure_dir()
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")


def _parse_tags(tags: str) -> list[str]:
    if not tags or not tags.strip():
        return []
    return [t.strip().lower() for t in re.split(r"[,;]+", tags) if t.strip()]


def _tokenize(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9_]+", text.lower()) if len(w) > 2}


def _score_relevance(query: str, row: dict[str, Any]) -> int:
    """Simple keyword overlap score for recall ranking."""
    q = _tokenize(query)
    if not q:
        return 0
    hay = " ".join(
        str(row.get(k, "")) for k in ("topic", "lesson", "reflection", "task", "context")
    )
    hay += " " + " ".join(row.get("tags", []))
    tokens = _tokenize(hay)
    return len(q & tokens)


def _record_lesson(
    topic: str,
    lesson: str,
    outcome: str = "neutral",
    tags: str = "",
    context: str = "",
) -> dict[str, Any]:
    if not topic.strip():
        return {"ok": False, "error": "topic is required for record_lesson."}
    if not lesson.strip():
        return {"ok": False, "error": "lesson is required for record_lesson."}

    rows = _load(_KNOWLEDGE_FILE)
    entry = {
        "id": len(rows) + 1,
        "timestamp": _now(),
        "topic": topic.strip(),
        "lesson": lesson.strip(),
        "outcome": outcome.strip().lower() or "neutral",
        "tags": _parse_tags(tags),
        "context": context.strip(),
    }
    rows.append(entry)
    _save(_KNOWLEDGE_FILE, rows)
    return {
        "ok": True,
        "message": f"Recorded lesson #{entry['id']} on '{entry['topic']}'.",
        "entry": entry,
        "hint": (
            "If this pattern will recur, consider skill_write to turn it into a "
            "reusable tool so you do not relearn it each session."
        ),
    }


def _recall(topic: str, limit: int = 8) -> dict[str, Any]:
    rows = _load(_KNOWLEDGE_FILE)
    if not rows:
        return {
            "ok": True,
            "matches": [],
            "message": "No lessons stored yet. Use record_lesson after each insight.",
        }

    scored = [(row, _score_relevance(topic, row)) for row in rows]
    if topic.strip():
        scored = [(r, s) for r, s in scored if s > 0]
        scored.sort(key=lambda x: (-x[1], x[0].get("timestamp", "")))
    else:
        scored = [(r, 0) for r in rows[-limit:]]

    matches = [r for r, _ in scored[: max(1, min(limit, 20))]]
    return {
        "ok": True,
        "query": topic,
        "count": len(matches),
        "matches": matches,
        "message": (
            f"Found {len(matches)} relevant lesson(s)."
            if topic.strip()
            else f"Showing {len(matches)} most recent lesson(s)."
        ),
    }


def _log_attempt(
    task: str,
    outcome: str,
    reflection: str = "",
    tags: str = "",
    skill_used: str = "",
) -> dict[str, Any]:
    if not task.strip():
        return {"ok": False, "error": "task is required for log_attempt."}
    if not outcome.strip():
        return {"ok": False, "error": "outcome is required (success, failure, or partial)."}

    rows = _load(_SESSIONS_FILE)
    entry = {
        "id": len(rows) + 1,
        "timestamp": _now(),
        "task": task.strip(),
        "outcome": outcome.strip().lower(),
        "reflection": reflection.strip(),
        "tags": _parse_tags(tags),
        "skill_used": skill_used.strip(),
    }
    rows.append(entry)
    _save(_SESSIONS_FILE, rows)

    follow_up = []
    o = entry["outcome"]
    if o in ("failure", "partial", "fail"):
        follow_up.append("record_lesson with what went wrong and how to fix it.")
        follow_up.append("Consider skill_write if a missing tool caused the failure.")
    elif o in ("success", "ok", "pass"):
        follow_up.append("record_lesson to capture the technique for next time.")

    return {
        "ok": True,
        "message": f"Logged practice attempt #{entry['id']}.",
        "entry": entry,
        "suggested_next": follow_up,
    }


def _set_goal(goal: str, priority: str = "medium", tags: str = "") -> dict[str, Any]:
    if not goal.strip():
        return {"ok": False, "error": "goal is required for set_goal."}

    rows = _load(_GOALS_FILE)
    entry = {
        "id": len(rows) + 1,
        "timestamp": _now(),
        "goal": goal.strip(),
        "priority": (priority.strip().lower() or "medium"),
        "tags": _parse_tags(tags),
        "status": "active",
        "completed_at": None,
    }
    rows.append(entry)
    _save(_GOALS_FILE, rows)
    return {"ok": True, "message": f"Training goal #{entry['id']} set.", "entry": entry}


def _complete_goal(goal_id: int) -> dict[str, Any]:
    rows = _load(_GOALS_FILE)
    for row in rows:
        if row.get("id") == goal_id:
            row["status"] = "completed"
            row["completed_at"] = _now()
            _save(_GOALS_FILE, rows)
            return {"ok": True, "message": f"Goal #{goal_id} marked completed.", "entry": row}
    return {"ok": False, "error": f"No goal with id {goal_id}."}


def _review() -> dict[str, Any]:
    knowledge = _load(_KNOWLEDGE_FILE)
    sessions = _load(_SESSIONS_FILE)
    goals = _load(_GOALS_FILE)

    active_goals = [g for g in goals if g.get("status") == "active"]
    completed_goals = [g for g in goals if g.get("status") == "completed"]
    failures = [s for s in sessions if s.get("outcome") in ("failure", "partial", "fail")]
    successes = [s for s in sessions if s.get("outcome") in ("success", "ok", "pass")]

    # Tag frequency across lessons — surfaces recurring themes.
    tag_counts: dict[str, int] = {}
    for row in knowledge:
        for tag in row.get("tags", []):
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    top_tags = sorted(tag_counts.items(), key=lambda x: -x[1])[:8]

    return {
        "ok": True,
        "summary": {
            "lessons_recorded": len(knowledge),
            "practice_attempts": len(sessions),
            "successes": len(successes),
            "failures": len(failures),
            "active_goals": len(active_goals),
            "completed_goals": len(completed_goals),
            "top_tags": top_tags,
        },
        "active_goals": active_goals,
        "recent_lessons": knowledge[-5:],
        "recent_attempts": sessions[-5:],
        "training_loop": [
            "1. set_goal — define a capability to develop.",
            "2. Attempt real tasks; log_attempt after each try.",
            "3. record_lesson for every insight (especially failures).",
            "4. recall before similar tasks to avoid repeating mistakes.",
            "5. skill_write when a pattern repeats 2+ times.",
            "6. review periodically; complete_goal when satisfied.",
        ],
    }


def _next_step(focus: str = "") -> dict[str, Any]:
    """Suggest the next self-training action based on stored state."""
    knowledge = _load(_KNOWLEDGE_FILE)
    sessions = _load(_SESSIONS_FILE)
    goals = [g for g in _load(_GOALS_FILE) if g.get("status") == "active"]

    suggestions: list[str] = []

    if not goals:
        suggestions.append(
            "set_goal — pick one concrete capability to improve (e.g. 'write XSS "
            "payloads that bypass filters')."
        )
    else:
        if focus.strip():
            ranked = sorted(goals, key=lambda g: -_score_relevance(focus, g))
        else:
            priority_order = {"high": 3, "medium": 2, "low": 1}
            ranked = sorted(
                goals,
                key=lambda g: (-priority_order.get(g.get("priority", "medium"), 2), g.get("id", 0)),
            )
        top = ranked[0]
        suggestions.append(
            f"Work on active goal #{top['id']}: {top['goal']}. "
            "Run a real task, then log_attempt with the outcome."
        )

    recent_failures = [
        s for s in sessions[-10:]
        if s.get("outcome") in ("failure", "partial", "fail")
    ]
    if recent_failures:
        last = recent_failures[-1]
        suggestions.append(
            f"Recent failure on '{last['task'][:80]}' — record_lesson with root cause "
            "and fix, or skill_write a tool to prevent recurrence."
        )

    if focus.strip():
        recall_result = _recall(focus, limit=3)
        if recall_result.get("matches"):
            suggestions.append(
                f"recall found {len(recall_result['matches'])} prior lesson(s) on "
                f"'{focus}' — read them before retrying."
            )
        else:
            suggestions.append(
                f"No prior lessons on '{focus}' — after your next attempt, "
                "record_lesson so future sessions start smarter."
            )

    if len(knowledge) >= 3 and not any("skill_write" in s for s in suggestions):
        suggestions.append(
            "You have several lessons stored — scan them for patterns worth "
            "turning into skills via skill_write."
        )

    return {
        "ok": True,
        "focus": focus,
        "suggestions": suggestions,
        "active_goal_count": len(goals),
    }


def _export_dataset(format: str = "jsonl") -> dict[str, Any]:
    """Export stored lessons as a fine-tuning-friendly dataset."""
    knowledge = _load(_KNOWLEDGE_FILE)
    if not knowledge:
        return {"ok": False, "error": "No lessons to export. Record some first."}

    _ensure_dir()
    out_path = _TRAINING_DIR / "export.jsonl"
    lines: list[str] = []

    for row in knowledge:
        user_msg = f"Topic: {row.get('topic', '')}"
        if row.get("context"):
            user_msg += f"\nContext: {row['context']}"
        assistant_msg = row.get("lesson", "")
        if row.get("outcome") and row["outcome"] != "neutral":
            assistant_msg += f"\n\nOutcome: {row['outcome']}"

        record = {
            "messages": [
                {"role": "user", "content": user_msg},
                {"role": "assistant", "content": assistant_msg},
            ],
            "metadata": {
                "tags": row.get("tags", []),
                "timestamp": row.get("timestamp"),
                "source": "sleuth_self_train",
            },
        }
        lines.append(json.dumps(record, ensure_ascii=False))

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "ok": True,
        "message": f"Exported {len(lines)} training example(s).",
        "path": str(out_path),
        "format": format,
        "hint": (
            "Use this JSONL with your local fine-tuning stack (Ollama modelfile, "
            "LM Studio, Axolotl, etc.) to bake lessons into model weights."
        ),
    }


def self_train(
    action: str,
    topic: str = "",
    lesson: str = "",
    outcome: str = "neutral",
    tags: str = "",
    context: str = "",
    task: str = "",
    reflection: str = "",
    skill_used: str = "",
    goal: str = "",
    priority: str = "medium",
    goal_id: int = 0,
    limit: int = 8,
    focus: str = "",
) -> dict[str, Any]:
    """
    Persistent self-training loop: record lessons, log practice, set goals, and
    improve across sessions.

    The model trains itself by running a loop:
    1. set_goal — define what to get better at.
    2. Attempt real work; log_attempt with outcome and reflection.
    3. record_lesson for every insight (failures are especially valuable).
    4. recall before similar tasks to apply past learnings.
    5. skill_write when a technique repeats — turn knowledge into a tool.
    6. review / next_step to see progress and what to do next.
    7. export_dataset when enough lessons exist for optional fine-tuning.

    Args:
        action: One of record_lesson, recall, log_attempt, set_goal,
            complete_goal, review, next_step, export_dataset.
        topic: Subject area (for record_lesson / recall).
        lesson: What was learned (for record_lesson).
        outcome: success, failure, partial, or neutral.
        tags: Comma-separated labels (e.g. "xss,python,api").
        context: Extra background for a lesson.
        task: What you tried (for log_attempt).
        reflection: Post-mortem notes (for log_attempt).
        skill_used: Tool or skill name used during an attempt.
        goal: Training objective (for set_goal).
        priority: high, medium, or low (for set_goal).
        goal_id: Goal to mark done (for complete_goal).
        limit: Max results for recall (default 8).
        focus: Optional focus area for next_step suggestions.

    Returns:
        A dict with ok, message, and action-specific data.
    """
    action = (action or "").strip().lower().replace("-", "_")

    dispatch = {
        "record_lesson": lambda: _record_lesson(topic, lesson, outcome, tags, context),
        "recall": lambda: _recall(topic, limit),
        "log_attempt": lambda: _log_attempt(task, outcome, reflection, tags, skill_used),
        "set_goal": lambda: _set_goal(goal, priority, tags),
        "complete_goal": lambda: _complete_goal(goal_id),
        "review": _review,
        "next_step": lambda: _next_step(focus or topic),
        "export_dataset": _export_dataset,
    }

    if action not in dispatch:
        return {
            "ok": False,
            "error": (
                f"Unknown action '{action}'. Use one of: "
                + ", ".join(dispatch.keys())
            ),
        }

    return dispatch[action]()
