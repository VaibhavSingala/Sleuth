/* SPDX-License-Identifier: Apache-2.0 */
/* Qwen3.5/3.6 MoE (GGUF arch qwen35moe) — direct GGUF inference. */
#ifndef MODEL_QWEN35_H
#define MODEL_QWEN35_H

#include "gguf.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define Q35_MAX_LAYERS 64
#define Q35_MAX_EXPERTS 512
#define Q35_MAX_TOPK 16
#define Q35_MAX_CTX 8192 /* runtime default cap; model supports 262144 */

typedef struct {
    int hidden;           /* 2048 */
    int n_layers;         /* 40 */
    int vocab;            /* 248320 */
    float rms_eps;        /* 1e-6 */

    int n_heads;          /* 16 */
    int n_kv_heads;       /* 2 */
    int head_dim;         /* 256 */
    int rope_dim;         /* 64 */
    float rope_theta;     /* 1e7 */
    int rope_sections[4]; /* [11,11,10,0] */
    int full_attn_interval; /* 4 */

    /* Gated DeltaNet / SSM */
    int ssm_conv;         /* 4 */
    int ssm_inner;        /* 4096 */
    int ssm_state;        /* 128 = head dim for K/V in linear attn */
    int ssm_dt_rank;      /* 32 = num value heads */
    int ssm_n_group;      /* 16 = num key heads */

    /* MoE */
    int n_experts;        /* 256 */
    int topk;             /* 8 */
    int expert_ff;        /* 512 */
    int shared_ff;        /* 512 */

    int bos_id;
    int eos_id;
    int pad_id;

    uint8_t is_linear[Q35_MAX_LAYERS]; /* 1 = Gated DeltaNet */
} Q35Cfg;

typedef struct {
    const GgufTensor *attn_norm;
    const GgufTensor *post_attn_norm;
    /* full attn */
    const GgufTensor *wq; /* Q+gate fused */
    const GgufTensor *wk;
    const GgufTensor *wv;
    const GgufTensor *wo;
    const GgufTensor *q_norm;
    const GgufTensor *k_norm;
    /* linear attn */
    const GgufTensor *wqkv;
    const GgufTensor *wgate;
    const GgufTensor *ssm_conv1d;
    const GgufTensor *ssm_alpha;
    const GgufTensor *ssm_beta;
    const GgufTensor *ssm_a;
    const GgufTensor *ssm_dt;
    const GgufTensor *ssm_norm;
    const GgufTensor *ssm_out;
    /* moe */
    const GgufTensor *router;
    const GgufTensor *gate_exps;
    const GgufTensor *up_exps;
    const GgufTensor *down_exps;
    const GgufTensor *shexp_gate;
    const GgufTensor *shexp_up;
    const GgufTensor *shexp_down;
    const GgufTensor *shexp_inp_gate;
} Q35LayerTensors;

typedef struct {
    GgufFile gguf;
    Q35Cfg cfg;
    Q35LayerTensors layers[Q35_MAX_LAYERS];
    const GgufTensor *tok_embd;
    const GgufTensor *output_norm;
    const GgufTensor *output;

    /* RAM budget in bytes for weight cache (experts + trunk). */
    size_t ram_budget;
    int n_threads;

    /* Working buffers (owned). */
    float *x;           /* [hidden] */
    float *xb;          /* [hidden] */
    float *xb2;         /* scratch */
    float *logits;      /* [vocab] — optional, may be null until needed */

    /* Per-layer recurrent state for linear attn: [n_v_heads][head][head] */
    float **ssm_state;  /* n_layers pointers; NULL for full-attn layers */
    float **conv_state; /* short-conv history */

    /* KV cache for full-attn layers: [layer][pos][kv_heads*head_dim] */
    float **k_cache;
    float **v_cache;
    int pos;
    int ctx_cap;
} Q35Model;

int q35_cfg_from_gguf(Q35Cfg *c, const GgufFile *g);
int q35_load(Q35Model *m, const char *gguf_path, size_t ram_budget, int ctx_cap);
void q35_free(Q35Model *m);

/* Encode one token into residual stream (embedding lookup + dequant). */
int q35_embed(Q35Model *m, int token_id, float *out);

/* Run one decode step at current m->pos. Writes logits into m->logits. */
int q35_decode(Q35Model *m, int token_id);

/* Greedy argmax over logits. */
int q35_argmax(const float *logits, int n);

size_t q35_parse_ram(const char *s); /* "8G", "16G", "laptop", ... */

#ifdef __cplusplus
}
#endif
#endif
