# GGUF Format (as used here)

We read **GGUF v3** directly. Tensor payloads stay in the original file.

## Layout

```text
magic "GGUF" | version u32 | tensor_count u64 | kv_count u64
KV pairs…
Tensor infos (name, ndims, dims[], type, offset)…
[align 32]
Tensor data…
```

Offsets in tensor infos are relative to the aligned data section.

## Types used by this Q4_K_M model

| Type | Enum | Block | Notes |
|---|---:|---|---|
| F32 | 0 | 4 B | norms, router, SSM scalars, conv1d |
| Q4_K | 12 | 144 B / 256 w | most projections + expert up/gate |
| Q6_K | 14 | 210 B / 256 w | LM head, many qkv/down |

Dequant matches llama.cpp `dequantize_row_q4_K` / `q6_K`.

## Architecture key prefix

`general.architecture = qwen35moe`

Hyperparams under `qwen35moe.*` (embedding_length, block_count, expert_*, ssm_*, rope.*, attention.*).

Tokenizer under `tokenizer.ggml.*` (tokens, merges, bos/eos, chat_template).

## Sidecar

`bin/model-converter` writes `model.gguf.model.json` — metadata only, not weights.
