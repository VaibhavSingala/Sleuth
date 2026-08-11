# Conversion / Direct GGUF Loading

This project **does not** rewrite your LM Studio GGUF into another multi-gigabyte weight file.

```text
model.gguf  →  bin/model-converter (validate + tiny .model.json sidecar)
            →  bin/model (C99 inference, streams tensors from the same GGUF)
```

## Your model

```text
D:\lmstudio\models\HauhauCS\Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive\
  Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_M.gguf
```

Architecture: **qwen35moe** (hybrid Gated DeltaNet + full GQA + MoE).  
See `MODEL_ANALYSIS.md`.

## Build (Linux / WSL)

```bash
cd kimi-k3-in-c
sudo apt-get install -y build-essential libomp-dev   # once
make
```

Produces:

* `bin/k3` — original Kimi K3 engine (unchanged)
* `bin/model-converter` — GGUF inspect / validate / sidecar
* `bin/model` — qwen35moe inference
* `bin/compare-model` — greedy token dump for LM Studio comparison

## Convert (validate)

```bash
./bin/model-converter \
  /mnt/d/lmstudio/models/HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_M.gguf
```

Writes `….gguf.model.json` next to the GGUF (metadata only).

## Run

```bash
./bin/model \
  /mnt/d/lmstudio/models/HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_M.gguf \
  --prompt "Hello" \
  --gen 32 \
  --ram 8G \
  --context 512
```

Chat mode:

```bash
./bin/model model.gguf --chat --prompt "Explain PostgreSQL indexing" --gen 100
```

## Why no second weight file?

Q4_K_M is already an efficient on-disk layout. Re-packing would waste ~21 GB and risk quant drift. The C engine `pread`s tensor slabs (experts streamed per token).

## Validation

```bash
./bin/compare-model model.gguf --prompt "The capital of France is" --tokens 20
```

Compare greedy token IDs against LM Studio (`temperature=0`, same prompt).
