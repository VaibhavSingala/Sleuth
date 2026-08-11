# Model Analysis: Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive (Q4_K_M)

**Status:** GGUF validated; C99 direct-load engine scaffolded (`bin/model-converter`, `bin/model`, `bin/compare-model`).  
**Date:** 2026-08-11  
**Source path (user):**  
`D:\lmstudio\models\HauhauCS\Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive\Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_M.gguf`  
**Public mirror used for metadata inspection (identical filename on Hugging Face):**  
`HauhauCS/Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive`  
**Base model:** `Qwen/Qwen3.6-35B-A3B`

This document is produced from a **direct GGUF header/metadata parse** of the first 128 MiB of the Q4_K_M file (complete KV table + complete tensor info table; tensor *payloads* were not downloaded) plus the official HF `config.json` / tokenizer config for `Qwen/Qwen3.6-35B-A3B`.

---

## Summary verdict

| Question | Answer |
|---|---|
| Is this Kimi K3? | **No.** |
| Is this a standard Llama/Qwen dense Transformer? | **No.** |
| What is it? | **`qwen35moe`**: hybrid **Gated DeltaNet (linear attention) + Gated full attention + MoE**, multimodal-capable text trunk |
| Can K3 kernels be reused as-is? | Only generic pieces (RMSNorm, matmul scaffolding, streaming/cache philosophy). **Not** KDA, MLA, SiTU-GLU, MXFP4, tiktoken. |
| Prefer direct GGUF loading? | **Yes** — do not invent a second packed format unless streaming layout forces it. |
| Ready to implement without architectural work? | **No.** Gated DeltaNet + Q4_K/Q6_K + GGUF BPE tokenizer must be built first. |

---

## GGUF file identity

```text
GGUF file:     Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive-Q4_K_M.gguf
File size:     21,166,758,016 bytes (~19.72 GiB / 21.17 GB)
GGUF version:  3
Architecture:  qwen35moe
Model name:    Qwen3.6-35B-A3B-Uncensored-HauhauCS-Aggressive
general.basename / finetune / size_label: KL0.0764 / 3Ref / 35B-A3B
Parameter count: ~35B total, ~3B activated (official); ~34.66B weight elements counted from tensor dims
Quantization:  Q4_K_M (general.file_type=15 MOSTLY_Q4_K; imatrix)
Tensor count:  733
Vocabulary size: 248,320
Context length: 262,144 (native; extensible per Qwen docs)
Embedding dimension: 2,048
Number of layers: 40
Attention heads (full): 16
KV heads (full): 2
Head dimension (full): 256
RoPE dimension (full): 64  (= partial_rotary_factor 0.25 × 256)
Intermediate dimension (MoE expert): 512
Shared expert intermediate: 512
Normalization: RMSNorm, eps = 1e-6
Activation: SiLU (SwiGLU-style gated MLP)
MoE: yes — 256 routed experts, 8 used/token + 1 shared
Tokenizer: GPT-2 BPE (tokenizer.ggml.model = gpt2), pre = qwen35
Chat template: present in GGUF (Jinja, multimodal-aware Qwen chat)
```

### Quantization breakdown (from tensor type table)

| GGUF type | Count | Role (typical) |
|---|---:|---|
| `Q4_K` | 371 | Most projections / expert up+gate |
| `Q6_K` | 61 | `output.weight`, many `attn_qkv` / `ffn_down_*` |
| `F32` | 301 | Norms, router (`ffn_gate_inp`), SSM scalars/biases, `ssm_conv1d` |

**Implication:** inference must implement **blockwise Q4_K and Q6_K dequant→matmul**. Do **not** widen the whole model to FP32 (~140+ GB).

Default sampling metadata embedded in GGUF:

- `general.sampling.temp` = 1.0  
- `general.sampling.top_k` = 20  
- `general.sampling.top_p` ≈ 0.95  

Tokenizer special IDs from GGUF:

- BOS / pad: `248044`  
- EOS: `248046`  

(Official HF text config lists `bos_token_id`/`eos_token_id` as `248044` for the base model; GGUF chat EOS differs — use GGUF tokenizer metadata at runtime.)

---

## Architecture (actual)

Official layout (Qwen README):

```text
10 × ( 3 × (Gated DeltaNet → MoE) → 1 × (Gated Attention → MoE) )
```

Observed in this GGUF (0-based block indices):

| Kind | Layer indices | Count |
|---|---|---:|
| Linear / Gated DeltaNet (`ssm_*` + fused `attn_qkv`) | 0,1,2, 4,5,6, 8,9,10, … 36,37,38 | 30 |
| Full gated attention (`attn_q/k/v` + Q/K norms) | 3,7,11,15,19,23,27,31,35,39 | 10 |

Matches `qwen35moe.full_attention_interval = 4`.

### Text / MoE hyperparams (from GGUF KV + HF `text_config`)

```text
hidden_size                         2048
num_hidden_layers                   40
vocab_size                          248320
num_attention_heads                 16
num_key_value_heads                 2
head_dim (full attn)                256
partial_rotary_factor               0.25  → rope dims 64
rope_theta                          10_000_000
rope_type                           default + interleaved mRoPE sections [11,11,10] (+ pad 0 in GGUF)
attn_output_gate                    true
rms_norm_eps                        1e-6
hidden_act                          silu
num_experts                         256
num_experts_per_tok                 8
moe_intermediate_size               512
shared_expert_intermediate_size     512
tie_word_embeddings                 false
linear_conv_kernel_dim              4
linear_num_key_heads                16
linear_key_head_dim                 128
linear_num_value_heads              32
linear_value_head_dim               128
ssm.conv_kernel                     4
ssm.inner_size                      4096
ssm.state_size                      128
ssm.time_step_rank                  32
ssm.group_count                     16
```

### Multimodal note

HF architecture is `Qwen3_5MoeForConditionalGeneration` with a **vision tower**. The LM Studio file named above is the **language GGUF**; an accompanying `mmproj-...-f16.gguf` (~899 MB) is required for image/video.  

**Phase-1 scope recommendation:** text-only inference from the main GGUF. Vision/mmproj is a separate backend, not required to validate logits on text prompts.

### MTP (multi-token prediction)

Base Qwen3.6 trains an MTP head. This Q4_K_M community GGUF’s tensor list ends at `blk.39.*` with **no** `blk.40.nextn.*` / MTP tensors observed in the 733-tensor table. Treat MTP as **absent** unless a different GGUF is supplied.

---

## Per-layer tensor map (GGUF names)

### Every layer (MoE FFN + norms)

```text
blk.N.attn_norm.weight                 F32 [2048]
blk.N.post_attention_norm.weight       F32 [2048]
blk.N.ffn_gate_inp.weight              F32 [2048, 256]     # router
blk.N.ffn_gate_exps.weight             Q4_K [2048, 512, 256]
blk.N.ffn_up_exps.weight               Q4_K [2048, 512, 256]
blk.N.ffn_down_exps.weight             Q6_K [512, 2048, 256]
blk.N.ffn_gate_inp_shexp.weight        F32 [2048]          # shared-expert gate
blk.N.ffn_gate_shexp.weight            Q4_K [2048, 512]
blk.N.ffn_up_shexp.weight              Q4_K [2048, 512]
blk.N.ffn_down_shexp.weight            Q6_K [512, 2048]
```

### Linear-attention layers (Gated DeltaNet)

```text
blk.N.attn_qkv.weight                  Q6_K [2048, 8192]   # Q(2048)+K(2048)+V(4096)
blk.N.attn_gate.weight                 Q4_K [2048, 4096]   # Z / output gate path
blk.N.ssm_conv1d.weight                F32  [4, 8192]
blk.N.ssm_alpha.weight                 Q4_K [2048, 32]
blk.N.ssm_beta.weight                  Q4_K [2048, 32]
blk.N.ssm_a                            F32  [32]
blk.N.ssm_dt.bias                      F32  [32]
blk.N.ssm_norm.weight                  F32  [128]
blk.N.ssm_out.weight                   Q4_K [4096, 2048]
```

### Full-attention layers (Gated Attention / GQA)

```text
blk.N.attn_q.weight                    Q4_K [2048, 8192]   # 16*256 (+ gate fusion — verify at bind time)
blk.N.attn_k.weight                    Q4_K [2048, 512]    # 2*256
blk.N.attn_v.weight                    Q6_K [2048, 512]
blk.N.attn_output.weight               Q4_K [4096, 2048]
blk.N.attn_q_norm.weight               F32  [256]
blk.N.attn_k_norm.weight               F32  [256]
```

### Global

```text
token_embd.weight                      Q4_K [2048, 248320]
output_norm.weight                     F32  [2048]
output.weight                          Q6_K [2048, 248320]  # untied LM head
```

---

## Forward pass (text) — must follow this, not K3

```text
token_embd(ids)
  → for layer in 0..39:
        x = RMSNorm(x, attn_norm)
        if linear layer:
            x = x + GatedDeltaNet(x)     # shortconv + recurrent delta-rule state + gate + out_proj
        else:
            x = x + GatedAttention(x)    # Q/K RMSNorm, partial RoPE/mRoPE, GQA, output gate, o_proj
        x = RMSNorm(x, post_attention_norm)
        x = x + MoE(x)                   # router → top-8 experts + shared SwiGLU expert
  → RMSNorm(x, output_norm)
  → logits = output @ x
```

Critical details that differ from “generic Llama”:

1. **Hybrid attention schedule** (3 linear : 1 full), not uniform MHA/GQA.  
2. **Gated DeltaNet** recurrent state (not Kimi KDA; not Mamba-2 identically).  
3. **Q/K norms** on full-attention layers.  
4. **Partial RoPE** (64 of 256 dims) with **interleaved mRoPE sections** `[11,11,10]`.  
5. **Attention output gating**.  
6. **MoE**: 256 experts, top-8 + **one shared** expert (SwiGLU), expert width 512.  
7. **Pre-norm twice per layer** (`attn_norm` then `post_attention_norm` before MoE).  
8. **Untied** embeddings / LM head; LM head is Q6_K.

---

## K3 repository mapping (reuse vs replace)

### Existing K3 stack (inspected + built)

| Module | Role today |
|---|---|
| `src/core/k3_ops.c` | RMSNorm, SiTU-GLU, ShortConv, KDA, Gated MLA, LatentMoE, MXFP4/BF16/Q8 matmul |
| `src/io/k3_st.c` | safetensors reader |
| `src/io/k3_trunk.c` / `k3_cache.c` | trunk streaming + expert LRU |
| `src/model/k3_bind.c` | K3 tensor name binding |
| `src/tokenizer/k3_tok.h` | tiktoken |
| `src/cli/k3_run.c` | K3 CLI |
| Tests | op fixtures + tiny full-model oracle — **all weightless tests PASSED** after build |

Build note: this environment needed `libomp-dev` so `-fopenmp` could link; after that `make` and `make test` succeeded (tokenizer parity skipped — no K3 `tiktoken.model` present).

### What transfers

| Asset | Transferability |
|---|---|
| Streaming / RAM-budget philosophy | **Keep** — experts dominate disk (~32B of ~35B params) |
| Expert LRU + prefetch idea (`k3_cache`) | **Adapt** to GGUF offsets / Q4_K–Q6_K expert tensors |
| RMSNorm kernel | **Reuse** (eps differs: 1e-6) |
| Generic matmul + OpenMP/AVX discipline | **Reuse / extend** |
| CLI stats (tok/s, RSS, RAM presets) | **Reuse pattern** for new `bin/model` |
| KDA / MLA / SiTU-GLU / MXFP4 / safetensors / tiktoken | **Do not force onto this model** |

### What must be added (new backend)

```text
src/gguf/          GGUF v3 reader (KV + tensor index + mmap/pread slices)
src/quant/         Q4_K, Q6_K (+ F32/F16/BF16) block dequant / qmatmul
src/model/qwen35/  architecture config + tensor bind + layer dispatch
src/ops/           Gated DeltaNet, GQA+partial RoPE+mRoPE, SwiGLU MoE
src/tokenizer/     GPT-2 BPE from GGUF tokens+merges (pre=qwen35)
src/chat/          Jinja-lite or constrained chat template applicator
src/cli/model.c    generic CLI
src/cli/compare.c  token/logit validation harness
```

K3 remains behind its existing `bin/k3` path; generic GGUF path is additive.

---

## Direct GGUF vs conversion

**Decision: direct GGUF loading.**

Reasons:

1. File is already Q4_K_M (~21 GB). Re-packing duplicates disk and risks quant drift.  
2. Metadata + offsets are complete in the GGUF header; streaming is `pread`/`mmap` by tensor offset.  
3. LM Studio / llama.cpp already standardize on this container.

Optional later: a **sidecar index** (tiny JSON/binary of layer→offset ranges) to speed cold start — **not** a second weight file.

Python may be used for one-time tokenizer/chat-template extraction tests and reference logits; **inference binaries stay C99**.

---

## Memory / streaming plan (preserve K3 philosophy)

Rough residency classes on this Q4_K_M:

| Class | Contents | Strategy |
|---|---|---|
| Hot small | norms, routers, SSM F32 tensors, conv1d | pin |
| Warm | embeddings, LM head (~Q4_K/~Q6_K, ~0.5B elems each) | pin if `--ram` allows; else stream |
| Trunk | per-layer attn + shared expert + DeltaNet proj | ring / pinned prefix by RAM preset |
| Cold huge | `ffn_*_exps` (256 experts × 40 layers) | **never fully resident**; load top-8 (+prefetch) per token |

RAM presets (proposed CLI):

```text
--ram 8G|16G|32G|64G
--preset laptop|desktop|server
```

This host for development has **~15 GiB RAM** and **4 CPUs** — enough to implement and validate with aggressive streaming; not enough to pin the whole 21 GB file.

---

## Tokenizer & chat template

- `tokenizer.ggml.model = gpt2`  
- `tokenizer.ggml.pre = qwen35`  
- `tokenizer.ggml.tokens` length **248320**  
- `tokenizer.ggml.merges` length **247587**  
- Chat template is the Qwen multimodal Jinja template (vision/video placeholders, tools, `<|im_start|>` …).  

Validation requirement:

```text
LM Studio / HF tokenizer IDs  ==  C BPE IDs
```

for multiple prompts, including special tokens and `--chat` formatting.

---

## Validation plan (against LM Studio)

1. Greedy decode (`temperature = 0`) on identical prompt + context.  
2. Compare **token IDs**, not prose similarity.  
3. Where possible, dump LM Studio / llama.cpp reference logits and compare within a documented tolerance (Q4_K noise).  
4. Utility target:

```bash
./bin/compare-model model.gguf --prompt "The capital of France is" --tokens 20
```

5. Keep `make test` green for existing K3 unit/oracle tests.

---

## Unsupported / missing operations vs current C engine

These are **required** before claiming the model runs:

1. **GGUF reader** (not safetensors).  
2. **Q4_K / Q6_K** kernels (block dequant + matmul).  
3. **Gated DeltaNet** linear-attention recurrence + short conv + gating (distinct from K3 KDA).  
4. **GQA full attention** with Q/K RMSNorm, partial RoPE, interleaved mRoPE, attention output gate.  
5. **SwiGLU MoE** with 256 experts / top-8 / shared expert (not LatentMoE + SiTU-GLU + MXFP4).  
6. **GPT-2 BPE** from GGUF (not tiktoken).  
7. **Chat template** application.  
8. (Later) **mmproj / vision** if image prompts are required.  
9. (Later) **MTP** if a GGUF that includes nextn tensors is supplied.

Forcing this checkpoint through the existing KDA/MLA graph would compile a wrong model that still emits fluent text — exactly the failure mode K3’s own docs warn against.

---

## Proposed implementation phases (after approval)

1. **Scaffold:** keep K3 intact; add parallel `gguf` + `model` abstraction; CLI stub `bin/model`.  
2. **IO + quant:** GGUF index, streaming reader, Q4_K/Q6_K matmul with portable + AVX2 paths.  
3. **Tokenizer + chat:** extract from GGUF; parity tests.  
4. **Ops:** RMSNorm, RoPE/mRoPE, GQA attn, Gated DeltaNet, SwiGLU MoE.  
5. **Runtime:** layer loop, KV cache (full layers), recurrent state (linear layers), RAM presets.  
6. **Validate:** `compare-model` vs llama.cpp/LM Studio greedy tokens + logit diffs.  
7. **Docs:** `GGUF_FORMAT.md`, `ARCHITECTURE.md` (generic), `CONVERSION.md`, `VALIDATION.md`, `PERFORMANCE.md`.  
8. **Perf:** only after correctness — profile dequant, MoE gather, disk I/O.

---

## Inspection provenance

```text
Method: HTTP range GET bytes 0..134217727 of the HF Q4_K_M GGUF
        + parse GGUF v3 KV (45 keys) and all 733 tensor descriptors
        + cross-check Qwen/Qwen3.6-35B-A3B config.json / tokenizer_config.json
K3 build: make && make test  → ALL WEIGHTLESS TESTS PASSED
          (tokenizer parity skipped: no local K3 tiktoken.model)
```

Weights were **not** altered. Full 21 GB payload was **not** required for this analysis and has not been permanently stored in the workspace beyond the temporary 128 MiB header used for inspection.
