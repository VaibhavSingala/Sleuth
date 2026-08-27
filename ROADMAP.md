# Sleuth — where to add logic next

This is an implementation map, not a calendar. Each item names the files to
change and the behaviour that should exist when it is done. Work top to
bottom: later layers assume the ones above them.

The goal is a **smarter control loop**, not a longer tool list. Sleuth already
has recon, scanners, polyglot `skill_write`, and a chat UI. What it lacks is
memory, planning, verification, and composition — the model still walks
`websearch/agent.py` in a flat “call a tool, stuff the result in, repeat”
loop (`max_rounds=6`).

---

## 1. Session brain (investigation state)

**Why.** Scope is a URL string. Findings from `analyze_site`, ZAP, Wapiti, and
authored skills never meet. The model re-derives the same facts every turn.

**Add** a durable object per conversation (next to `websearch/store.py`):

- `target`, allowed actions, kill-switches already in `.env`
- `facts[]` (host, tech, endpoints, certs) with evidence + source tool
- `hypotheses[]` (open / confirmed / rejected)
- `work_queue[]` (next cheap check before an expensive scan)

**Wire it in** `run_stream` (`websearch/agent.py`): inject a short “state
card” into the system prompt each round; after each tool result, run a
deterministic merger (not the LLM) that updates facts from known report
shapes (`websearch/recon/report.py`, ZAP alert JSON, Wapiti output).

**Done when** `/scan example.com` followed by “what’s the stack?” does not
call `analyze_site` again if the profile is already in state.

---

## 2. Planner vs executor (two-role loop)

**Why.** Small models waste rounds on the wrong tool, or scan before they
fingerprint. `composites.py` (`quick_recon`, `compare_and_summarize`) is the
right idea — one call instead of a chain — but it is hardcoded, not general.

**Add** in `websearch/agent.py` (keep it local, no extra service):

1. **Plan round** — model may only call `plan_next` / `set_queue` (or write
   structured JSON). Output is a list of steps with a *cost tier*
   (`cheap` = DNS/read, `medium` = site profile, `expensive` = active scan).
2. **Act rounds** — expose only the tools needed for the current step, not
   the full catalogue. Rebuild `active_tools()` from the queue.
3. **Verify round** — a checklist: did the last result answer the step, or
   retry / skip.

Respect existing gates (`ZAP_ALLOW_ACTIVE_SCAN`, `SLEUTH_ALLOW_EXEC`, etc.)
in the planner so “expensive” never bypasses `.env`.

**Done when** a tiny model can complete recon without calling `zap_scan`
before `analyze_site`, and without dumping every MCP tool into every round.

---

## 3. Memory that actually feeds the model

**Why.** `skills/self_train.py` already stores lessons, goals, and a dataset
export — but the agent does not recall it unless the model thinks to call
that skill. Chat history in `conversations/` is a transcript, not retrieval.

**Add:**

- On each user message, `recall` top-k lessons tagged for the current
  target / task into the system prompt (cap tokens; this is `self_train`
  logic lifted into `websearch/memory.py`).
- After a failure (timeout, empty research, broken skill), auto
  `record_lesson` with the tool name and error — no extra model call.
- Optional: embed conversation chunks later; keyword overlap in
  `_score_relevance` is enough for v1.

**Done when** “we already know this host uses Cloudflare” survives a new
chat without the user repeating it.

---

## 4. Finding correlation (one report, many sensors)

**Why.** `comprehensive_vulnerability_check.py` concatenates sibling skills.
ZAP, Wapiti, Burp, SSL, and XSS checks speak different schemas. The model
is asked to be the SIEM.

**Add** `websearch/findings.py`:

- Normalise `{severity, title, url, evidence, sensor, cwe?}`
- Dedup by (url path + title fingerprint)
- Rank: confirmed (two sensors) > single sensor > info

Feed that list to the state card (section 1) and to a single
`findings_summary` tool so the model stops pasting three raw dumps.

**Done when** ZAP XSS + the reflection skill collapse to one finding with
two evidence lines.

---

## 5. Skill platform (make polyglot skills compounding)

**Why.** `skill_write` can now author Python / JS / Bash / Go / … but each
skill is a lonely file. No tests, no shared HTTP helper, no composition.

**Add:**

| Piece | Where |
|---|---|
| `skill_test(name)` smoke-run with fixture args | `websearch/skills.py` |
| Shared JSON argv contract already in `skill_lang.py` — document a 20-line template per language | `skills/_templates/` |
| `skill_compose(name, steps)` — a YAML/JSON skill that calls others in order, like `composites.quick_recon` but model-authored | new loader next to `Registry` |
| Docker language packs as optional compose profiles (`nodejs` is in; ruby/go opt-in) | `docker-compose.yml` |

**Done when** the model can write `f_to_c` in JS, `skill_test` passes, and a
compose skill can call `check_ssl_config` then `analyze_site` without new
Python in `composites.py`.

---

## 6. Two-model routing (Needle + reasoner)

**Why.** `needle_train/` already trains a 45M router that only emits tool
calls. The chat model still both routes *and* writes prose, so a 7B local
model burns context on tool JSON.

**Add** in `websearch/llm.py` + `run_stream`:

- If `LLM_ROUTER_URL` is set, send `{user, state_card, tool_names}` to
  Needle (or any router); execute those tools; send *only* tool results +
  question to the chat model for the answer.
- Expand `needle_train/build_dataset.py` from real `conversations/*.json`
  (tool sequences that worked) instead of only synthetic lines.

**Done when** a weak chat model still produces a cited answer because
Needle picked `research` / `quick_recon` correctly.

---

## 7. Reliability so “smarter” does not mean “fragile”

These are small and unblock everything else:

- **Pin `mcp`** to a release that still has `FastMCP` (`websearch/server.py`
  imports `mcp.server.fastmcp`). Current unpinned `mcp>=1.2.0` can break
  `selftest.py` on a fresh install.
- **CI**: run the offline slice of `selftest.py` (skills, schema/signature
  match, path traversal) without live DuckDuckGo.
- **Sandbox / auto-review**: `python_exec` / non-Python skills currently share
  the host process/env. Auto-review (`websearch/auto_review.py`) blocks
  host-damaging commands while allowing target-directed work. Optional
  `SLEUTH_SKILL_SANDBOX=bwrap|docker` can isolate further later; until then,
  keep the kill-switches obvious in the UI.

---

## Suggested order of pull requests

1. Investigation state + merger (1) — every later feature reads this.
2. Tool subsetting per step (2) without a full planner — even a static
   “recon kit vs scan kit” split helps small models.
3. Wire `self_train` recall into the prompt (3).
4. `findings.py` normalisation (4).
5. `skill_test` + compose skills (5).
6. Router/reasoner split (6) once 1–2 exist so the router has a state card
   to condition on.
7. Pin MCP + split selftest for CI (7) anytime; do it first if installs
   keep breaking.

Do not start by adding more scanner wrappers. Power here is **closing the
loop**: observe → update state → pick the next cheap step → verify →
remember.
