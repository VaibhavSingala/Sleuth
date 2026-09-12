#!/usr/bin/env bash
# Fine-tune Qwen2.5-Coder-3B to author Sleuth skills, using the Soup trainer.
#   https://github.com/MakazhanAlpamys/Soup
#
# Result: a LoRA adapter + a GGUF you can load from Ollama / LM Studio and point
# Sleuth at via LLM_PROVIDER=custom.
set -euo pipefail
cd "$(dirname "$0")"

# Invoke via the module, not the `soup` shim: on Windows Store Python the
# console-script dir (Scripts) is read-only and not on PATH.
SOUP="python -m soup_cli"

# 1. Trainer ([train] pulls in PyTorch). Check the module, not a PATH shim.
if ! python -c "import soup_cli" >/dev/null 2>&1; then
  pip install "soup-cli[train]"
fi

# 2. Build the SFT dataset from the real skills in ../skills.
python build_dataset.py

# 3. Validate config + data first (fast, no training), then train (QLoRA).
#    `echo y` answers soup's interactive "Start training? [Y/n]" prompt so this
#    works non-interactively (CI, background runs).
$SOUP train --config soup.yaml --dry-run
echo y | $SOUP train --config soup.yaml

# 4. Export a GGUF for Ollama / LM Studio (merges the adapter first).
$SOUP export --model ./output --format gguf

echo
echo "Done. Load ./output (GGUF) into Ollama, then point Sleuth at it:"
echo "  LLM_PROVIDER=custom"
echo "  LLM_BASE_URL=http://host.docker.internal:11434/v1"
echo "  LLM_MODEL=sleuth-skill-coder"
