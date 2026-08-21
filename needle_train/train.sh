#!/usr/bin/env bash
# Fine-tune Needle 2 for Sleuth tool routing, then export a .cact archive.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="${HOME}/.local/bin:${PATH}"

python3 build_dataset.py

DATA="data/sleuth_needle.jsonl"
ADAPTER="checkpoints/sleuth_needle_lora.pkl"
CACT="dist/sleuth_needle.cact"
mkdir -p checkpoints dist

echo "==> LoRA fine-tune (CPU-friendly defaults)"
needle finetune "$DATA" \
  --epochs "${EPOCHS:-15}" \
  --batch-size "${BATCH:-8}" \
  --lr "${LR:-1e-4}" \
  --lora-rank "${RANK:-16}" \
  --lora-alpha "${ALPHA:-32}" \
  --max-len "${MAXLEN:-512}" \
  --val-split 0.1 \
  --out "$ADAPTER"

echo "==> Locate base checkpoint"
BASE=""
for cand in \
  checkpoints/needle2.pkl \
  "$HOME/.cache/needle/needle2.pkl" \
  "$HOME/.cache/huggingface/hub"/models--Cactus-Compute--needle2/**/needle2.pkl
do
  # shellcheck disable=SC2086
  if compgen -G "$cand" > /dev/null 2>&1; then
    BASE=$(compgen -G "$cand" | head -1)
    break
  fi
done

if [[ -z "$BASE" ]]; then
  echo "Base checkpoint not found after finetune; trying needle build auto path..."
  # finetune usually leaves a copy under checkpoints/
  if [[ -f checkpoints/needle2.pkl ]]; then
    BASE=checkpoints/needle2.pkl
  else
    echo "ERROR: need base needle2.pkl — re-run finetune or download weights" >&2
    find "$HOME/.cache" -name 'needle2.pkl' 2>/dev/null | head
    exit 1
  fi
fi

echo "==> Build .cact from $BASE + $ADAPTER"
needle build "$BASE" --lora "$ADAPTER" --out "$CACT"

echo "==> Done: $CACT"
ls -lh "$CACT" "$ADAPTER"
