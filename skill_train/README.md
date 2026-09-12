# Sleuth × Qwen2.5-Coder-3B — the skill author

Fine-tune [Qwen2.5-Coder-3B](https://ollama.com/library/qwen2.5-coder) with the
[Soup](https://github.com/MakazhanAlpamys/Soup) trainer so Sleuth has a small,
local model that **writes new skills on demand** — the generation half that the
tiny Needle router (`../needle_train`) cannot do.

## The two-model split

| Model | Size | Job |
|-------|------|-----|
| Needle 2 (`../needle_train`) | ~14 MB | Route every turn; **escalate** to `skill_write` when no tool fits |
| **Qwen2.5-Coder-3B (this)** | ~2 GB (4-bit) | On escalation, author the skill's actual code |

Needle emits `skill_write{name, description}`; this model turns that into a
function that satisfies Sleuth's skill contract, and the real `skill_write` runs
it (auto-reverted if it fails to parse — see `websearch/auto_review.py`).

## Data

`build_dataset.py` turns the real, working skills in `../skills` into
`(instruction -> code)` pairs (Alpaca JSONL), 4 instruction paraphrases each.
The four large/complex skills are skipped as single-shot targets. The contract
is stated in every example's `input`, so the model learns the rules, not just
these 12 skills.

**More real skills = a better author.** Every skill the system authors and keeps
becomes future training data — re-run `build_dataset.py` before each retrain.

## Train

```bash
chmod +x train.sh
./train.sh
```

Artifacts:

| Path | Role |
|------|------|
| `data/sleuth_skills.jsonl` | Training set |
| `output/` | LoRA adapter + merged GGUF |

Knobs live in `soup.yaml` (`epochs`, `lr`, LoRA `r`/`alpha`, `quantization`).
Low VRAM (< ~6 GB)? Set `stream_layers: true` in `soup.yaml`.

## Serve + wire the handoff

Import the GGUF into Ollama under the name Sleuth expects:

```bash
ollama create sleuth-skill-coder -f Modelfile   # FROM ./output/<file>.gguf
```

This model is the **skill author**, not Sleuth's main model — the Needle router
stays the main model. `skill_write` calls this endpoint automatically whenever it
is invoked with a `description` but no `code` (the escalation path). Configure it
in `.env`:

```env
SLEUTH_SKILL_AUTHOR=true
SLEUTH_SKILL_AUTHOR_URL=http://host.docker.internal:11434/v1
SLEUTH_SKILL_AUTHOR_MODEL=sleuth-skill-coder
```

The generated code is syntax-checked and smoke-tested before it goes live
(`websearch/skills.py`); a structural crash or hang is rejected with a
fix-and-retry message rather than shipped.

## Caveat

~60 examples from 15 skills is a bootstrap, not a finished model. Expect the
first pass to handle skills close to the training set well and novel ones
unevenly. The smoke-test gate is the safety net; grow the dataset as the real
skill library grows.
