#!/usr/bin/env bash
# Serve the tuned Sleuth Needle model behind an OpenAI-compatible API.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="${HOME}/.local/bin:${PATH}"

CACT="${WEIGHTS:-dist/sleuth_needle.cact}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
MODEL_ID="${MODEL_ID:-sleuth-needle}"

if [[ ! -f "$CACT" ]]; then
  echo "Missing $CACT — run ./train.sh first (or set WEIGHTS=)." >&2
  exit 1
fi

echo "Serving $CACT as $MODEL_ID on http://${HOST}:${PORT}/v1"
echo "Point Sleuth at it:"
echo "  LLM_PROVIDER=custom"
echo "  LLM_BASE_URL=http://host.docker.internal:${PORT}/v1"
echo "  LLM_MODEL=${MODEL_ID}"

exec needle-openai \
  --host "$HOST" \
  --port "$PORT" \
  --weights "$CACT" \
  --model-id "$MODEL_ID" \
  "$@"
