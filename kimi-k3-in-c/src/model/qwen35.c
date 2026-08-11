/* SPDX-License-Identifier: Apache-2.0 */
#include "qwen35.h"
#include "ops.h"
#include "quant.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const GgufTensor *must_tensor(const GgufFile *g, const char *name, int required)
{
    const GgufTensor *t = gguf_find_tensor(g, name);
    if (!t && required)
        fprintf(stderr, "q35: missing required tensor %s\n", name);
    return t;
}

static int load_f32_tensor(const GgufFile *g, const GgufTensor *t, float *dst, int n)
{
    if (!t || t->type != GGML_TYPE_F32) return -1;
    return gguf_read_tensor_bytes(g, t, 0, dst, (size_t)n * sizeof(float));
}

static int matmul_tensor(Q35Model *m, float *y, const float *x, const GgufTensor *t,
                         int in, int out)
{
    size_t nbytes = ggml_nbytes(t);
    void *buf = malloc(nbytes);
    if (!buf) return -1;
    if (gguf_read_tensor_bytes(&m->gguf, t, 0, buf, nbytes)) {
        free(buf);
        return -2;
    }
    int rc = quant_matmul(y, x, buf, t->type, in, out);
    free(buf);
    return rc;
}

/* Load one expert's gate/up/down rows for expert e from 3D tensors. */
static int matmul_expert(Q35Model *m, float *y, const float *x, const GgufTensor *t,
                         int in, int out, int expert, int n_experts)
{
    (void)n_experts;
    /* Tensor layout [in, out, n_experts] with in contiguous — each expert slab is
     * out * row_bytes, expert e starts at e * out * row_bytes. */
    size_t row_bytes = quant_nbytes(t->type, in);
    size_t expert_bytes = row_bytes * (size_t)out;
    void *buf = malloc(expert_bytes);
    if (!buf) return -1;
    uint64_t off = (uint64_t)expert * expert_bytes;
    if (gguf_read_tensor_bytes(&m->gguf, t, off, buf, expert_bytes)) {
        free(buf);
        return -2;
    }
    int rc = quant_matmul(y, x, buf, t->type, in, out);
    free(buf);
    return rc;
}

int q35_cfg_from_gguf(Q35Cfg *c, const GgufFile *g)
{
    memset(c, 0, sizeof(*c));
    const char *arch = NULL;
    if (gguf_kv_str(g, "general.architecture", &arch) || !arch ||
        strcmp(arch, "qwen35moe") != 0) {
        fprintf(stderr, "q35: unsupported architecture '%s' (need qwen35moe)\n",
                arch ? arch : "(null)");
        return -1;
    }
    uint32_t u;
    float f;
    if (gguf_kv_u32(g, "qwen35moe.embedding_length", &u)) return -2;
    c->hidden = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.block_count", &u)) return -2;
    c->n_layers = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.attention.head_count", &u)) return -2;
    c->n_heads = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.attention.head_count_kv", &u)) return -2;
    c->n_kv_heads = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.attention.key_length", &u)) return -2;
    c->head_dim = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.rope.dimension_count", &u)) return -2;
    c->rope_dim = (int)u;
    if (gguf_kv_f32(g, "qwen35moe.rope.freq_base", &f)) return -2;
    c->rope_theta = f;
    if (gguf_kv_f32(g, "qwen35moe.attention.layer_norm_rms_epsilon", &f)) return -2;
    c->rms_eps = f;
    if (gguf_kv_u32(g, "qwen35moe.expert_count", &u)) return -2;
    c->n_experts = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.expert_used_count", &u)) return -2;
    c->topk = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.expert_feed_forward_length", &u)) return -2;
    c->expert_ff = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.expert_shared_feed_forward_length", &u)) return -2;
    c->shared_ff = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.ssm.conv_kernel", &u)) return -2;
    c->ssm_conv = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.ssm.inner_size", &u)) return -2;
    c->ssm_inner = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.ssm.state_size", &u)) return -2;
    c->ssm_state = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.ssm.time_step_rank", &u)) return -2;
    c->ssm_dt_rank = (int)u;
    if (gguf_kv_u32(g, "qwen35moe.ssm.group_count", &u)) return -2;
    c->ssm_n_group = (int)u;
    c->full_attn_interval = 4;
    gguf_kv_u32(g, "qwen35moe.full_attention_interval", &u);
    if (u) c->full_attn_interval = (int)u;

    const GgufKV *sec = gguf_find_kv(g, "qwen35moe.rope.dimension_sections");
    if (sec && sec->type == GGUF_TYPE_ARRAY && sec->v.arr.etype == GGUF_TYPE_INT32) {
        int32_t *p = (int32_t *)sec->v.arr.data;
        for (int i = 0; i < 4 && i < (int)sec->v.arr.n; i++) c->rope_sections[i] = p[i];
    } else {
        c->rope_sections[0] = 11;
        c->rope_sections[1] = 11;
        c->rope_sections[2] = 10;
        c->rope_sections[3] = 0;
    }

    /* vocab from tokenizer tokens array */
    const GgufKV *toks = gguf_find_kv(g, "tokenizer.ggml.tokens");
    c->vocab = toks ? (int)toks->v.arr.n : 0;
    gguf_kv_u32(g, "tokenizer.ggml.bos_token_id", &u);
    c->bos_id = (int)u;
    gguf_kv_u32(g, "tokenizer.ggml.eos_token_id", &u);
    c->eos_id = (int)u;
    gguf_kv_u32(g, "tokenizer.ggml.padding_token_id", &u);
    c->pad_id = (int)u;

    if (c->n_layers > Q35_MAX_LAYERS) return -3;
    for (int i = 0; i < c->n_layers; i++)
        c->is_linear[i] = ((i + 1) % c->full_attn_interval) != 0;
    return 0;
}

static int bind_layer(Q35Model *m, int i)
{
    char name[128];
    Q35LayerTensors *L = &m->layers[i];
    memset(L, 0, sizeof(*L));
#define T(field, fmt, req)                                                     \
    do {                                                                       \
        snprintf(name, sizeof(name), fmt, i);                                  \
        L->field = must_tensor(&m->gguf, name, req);                           \
        if (req && !L->field) return -1;                                       \
    } while (0)

    T(attn_norm, "blk.%d.attn_norm.weight", 1);
    T(post_attn_norm, "blk.%d.post_attention_norm.weight", 1);
    T(router, "blk.%d.ffn_gate_inp.weight", 1);
    T(gate_exps, "blk.%d.ffn_gate_exps.weight", 1);
    T(up_exps, "blk.%d.ffn_up_exps.weight", 1);
    T(down_exps, "blk.%d.ffn_down_exps.weight", 1);
    T(shexp_gate, "blk.%d.ffn_gate_shexp.weight", 1);
    T(shexp_up, "blk.%d.ffn_up_shexp.weight", 1);
    T(shexp_down, "blk.%d.ffn_down_shexp.weight", 1);
    T(shexp_inp_gate, "blk.%d.ffn_gate_inp_shexp.weight", 1);

    if (m->cfg.is_linear[i]) {
        T(wqkv, "blk.%d.attn_qkv.weight", 1);
        T(wgate, "blk.%d.attn_gate.weight", 1);
        T(ssm_conv1d, "blk.%d.ssm_conv1d.weight", 1);
        T(ssm_alpha, "blk.%d.ssm_alpha.weight", 1);
        T(ssm_beta, "blk.%d.ssm_beta.weight", 1);
        T(ssm_a, "blk.%d.ssm_a", 1);
        T(ssm_dt, "blk.%d.ssm_dt.bias", 1);
        T(ssm_norm, "blk.%d.ssm_norm.weight", 1);
        T(ssm_out, "blk.%d.ssm_out.weight", 1);
    } else {
        T(wq, "blk.%d.attn_q.weight", 1);
        T(wk, "blk.%d.attn_k.weight", 1);
        T(wv, "blk.%d.attn_v.weight", 1);
        T(wo, "blk.%d.attn_output.weight", 1);
        T(q_norm, "blk.%d.attn_q_norm.weight", 1);
        T(k_norm, "blk.%d.attn_k_norm.weight", 1);
    }
#undef T
    return 0;
}

size_t q35_parse_ram(const char *s)
{
    if (!s) return (size_t)8 << 30;
    if (strcmp(s, "laptop") == 0) return (size_t)8 << 30;
    if (strcmp(s, "desktop") == 0) return (size_t)32 << 30;
    if (strcmp(s, "server") == 0) return (size_t)64 << 30;
    char *end = NULL;
    double v = strtod(s, &end);
    if (end == s) return (size_t)8 << 30;
    if (*end == 'G' || *end == 'g') return (size_t)(v * (1ull << 30));
    if (*end == 'M' || *end == 'm') return (size_t)(v * (1ull << 20));
    return (size_t)v;
}

int q35_load(Q35Model *m, const char *gguf_path, size_t ram_budget, int ctx_cap)
{
    memset(m, 0, sizeof(*m));
    m->ram_budget = ram_budget ? ram_budget : q35_parse_ram("laptop");
    m->ctx_cap = ctx_cap > 0 ? ctx_cap : 2048;
    m->n_threads = 4;
    if (gguf_open(&m->gguf, gguf_path)) {
        fprintf(stderr, "q35: failed to open %s\n", gguf_path);
        return -1;
    }
    if (q35_cfg_from_gguf(&m->cfg, &m->gguf)) {
        q35_free(m);
        return -2;
    }
    m->tok_embd = must_tensor(&m->gguf, "token_embd.weight", 1);
    m->output_norm = must_tensor(&m->gguf, "output_norm.weight", 1);
    m->output = must_tensor(&m->gguf, "output.weight", 1);
    if (!m->tok_embd || !m->output_norm || !m->output) {
        q35_free(m);
        return -3;
    }
    for (int i = 0; i < m->cfg.n_layers; i++) {
        if (bind_layer(m, i)) {
            q35_free(m);
            return -4;
        }
    }

    int H = m->cfg.hidden;
    m->x = (float *)calloc((size_t)H, sizeof(float));
    m->xb = (float *)calloc((size_t)H, sizeof(float));
    m->xb2 = (float *)calloc((size_t)H * 8, sizeof(float)); /* generous scratch */
    m->logits = (float *)calloc((size_t)m->cfg.vocab, sizeof(float));
    m->ssm_state = (float **)calloc((size_t)m->cfg.n_layers, sizeof(float *));
    m->conv_state = (float **)calloc((size_t)m->cfg.n_layers, sizeof(float *));
    m->k_cache = (float **)calloc((size_t)m->cfg.n_layers, sizeof(float *));
    m->v_cache = (float **)calloc((size_t)m->cfg.n_layers, sizeof(float *));
    if (!m->x || !m->xb || !m->xb2 || !m->logits) {
        q35_free(m);
        return -5;
    }

    int dv = m->cfg.ssm_state;
    int nv = m->cfg.ssm_dt_rank;
    int conv_ch = m->cfg.ssm_inner + 2 * m->cfg.ssm_n_group * m->cfg.ssm_state;
    for (int i = 0; i < m->cfg.n_layers; i++) {
        if (m->cfg.is_linear[i]) {
            m->ssm_state[i] = (float *)calloc((size_t)nv * dv * dv, sizeof(float));
            m->conv_state[i] =
                (float *)calloc((size_t)conv_ch * (m->cfg.ssm_conv - 1), sizeof(float));
        } else {
            size_t kv = (size_t)m->ctx_cap * m->cfg.n_kv_heads * m->cfg.head_dim;
            m->k_cache[i] = (float *)calloc(kv, sizeof(float));
            m->v_cache[i] = (float *)calloc(kv, sizeof(float));
        }
    }
    m->pos = 0;
    return 0;
}

void q35_free(Q35Model *m)
{
    if (!m) return;
    free(m->x);
    free(m->xb);
    free(m->xb2);
    free(m->logits);
    if (m->ssm_state) {
        for (int i = 0; i < m->cfg.n_layers; i++) free(m->ssm_state[i]);
        free(m->ssm_state);
    }
    if (m->conv_state) {
        for (int i = 0; i < m->cfg.n_layers; i++) free(m->conv_state[i]);
        free(m->conv_state);
    }
    if (m->k_cache) {
        for (int i = 0; i < m->cfg.n_layers; i++) free(m->k_cache[i]);
        free(m->k_cache);
    }
    if (m->v_cache) {
        for (int i = 0; i < m->cfg.n_layers; i++) free(m->v_cache[i]);
        free(m->v_cache);
    }
    gguf_close(&m->gguf);
    memset(m, 0, sizeof(*m));
}

int q35_embed(Q35Model *m, int token_id, float *out)
{
    if (token_id < 0 || token_id >= m->cfg.vocab) return -1;
    int H = m->cfg.hidden;
    size_t row_bytes = quant_nbytes(m->tok_embd->type, H);
    void *buf = malloc(row_bytes);
    if (!buf) return -1;
    if (gguf_read_tensor_bytes(&m->gguf, m->tok_embd, (uint64_t)token_id * row_bytes, buf,
                               row_bytes)) {
        free(buf);
        return -2;
    }
    switch (m->tok_embd->type) {
    case GGML_TYPE_F32: quant_dequant_f32(buf, out, H); break;
    case GGML_TYPE_Q4_K: quant_dequant_q4_k(buf, out, H); break;
    case GGML_TYPE_Q6_K: quant_dequant_q6_k(buf, out, H); break;
    default:
        free(buf);
        return -3;
    }
    free(buf);
    return 0;
}

int q35_argmax(const float *logits, int n)
{
    int best = 0;
    float bv = logits[0];
    for (int i = 1; i < n; i++)
        if (logits[i] > bv) {
            bv = logits[i];
            best = i;
        }
    return best;
}

static int moe_ffn(Q35Model *m, int li, const float *x, float *y)
{
    const Q35Cfg *c = &m->cfg;
    const Q35LayerTensors *L = &m->layers[li];
    float *router = m->xb2;
    float *scores = m->xb2 + c->n_experts;

    if (matmul_tensor(m, router, x, L->router, c->hidden, c->n_experts)) return -1;
    /* softmax routing */
    memcpy(scores, router, (size_t)c->n_experts * sizeof(float));
    ops_softmax(scores, c->n_experts);

    int idx[Q35_MAX_TOPK];
    float wts[Q35_MAX_TOPK];
    for (int k = 0; k < c->topk; k++) {
        int best = -1;
        float bv = -1e30f;
        for (int e = 0; e < c->n_experts; e++) {
            int used = 0;
            for (int j = 0; j < k; j++)
                if (idx[j] == e) used = 1;
            if (used) continue;
            if (scores[e] > bv) {
                bv = scores[e];
                best = e;
            }
        }
        idx[k] = best;
        wts[k] = bv;
    }
    /* renorm topk weights */
    float s = 0.f;
    for (int k = 0; k < c->topk; k++) s += wts[k];
    for (int k = 0; k < c->topk; k++) wts[k] /= s;

    memset(y, 0, (size_t)c->hidden * sizeof(float));
    float *gate = (float *)malloc((size_t)c->expert_ff * sizeof(float));
    float *up = (float *)malloc((size_t)c->expert_ff * sizeof(float));
    float *hid = (float *)malloc((size_t)c->expert_ff * sizeof(float));
    float *down = (float *)malloc((size_t)c->hidden * sizeof(float));
    if (!gate || !up || !hid || !down) {
        free(gate);
        free(up);
        free(hid);
        free(down);
        return -1;
    }
    for (int k = 0; k < c->topk; k++) {
        int e = idx[k];
        if (matmul_expert(m, gate, x, L->gate_exps, c->hidden, c->expert_ff, e, c->n_experts))
            goto fail;
        if (matmul_expert(m, up, x, L->up_exps, c->hidden, c->expert_ff, e, c->n_experts))
            goto fail;
        ops_silu(gate, gate, c->expert_ff);
        for (int i = 0; i < c->expert_ff; i++) hid[i] = gate[i] * up[i];
        /* down: weight dims (ff, hidden) → matmul in=ff out=hidden */
        if (matmul_expert(m, down, hid, L->down_exps, c->expert_ff, c->hidden, e, c->n_experts))
            goto fail;
        for (int i = 0; i < c->hidden; i++) y[i] += wts[k] * down[i];
    }

    /* shared expert */
    if (matmul_tensor(m, gate, x, L->shexp_gate, c->hidden, c->shared_ff)) goto fail;
    if (matmul_tensor(m, up, x, L->shexp_up, c->hidden, c->shared_ff)) goto fail;
    ops_silu(gate, gate, c->shared_ff);
    for (int i = 0; i < c->shared_ff; i++) hid[i] = gate[i] * up[i];
    if (matmul_tensor(m, down, hid, L->shexp_down, c->shared_ff, c->hidden)) goto fail;
    float sg;
    if (load_f32_tensor(&m->gguf, L->shexp_inp_gate, m->xb2, c->hidden) == 0) {
        /* shexp_inp_gate is [hidden] vector — dot with x then sigmoid */
        double acc = 0.0;
        for (int i = 0; i < c->hidden; i++) acc += (double)m->xb2[i] * (double)x[i];
        sg = 1.0f / (1.0f + expf(-(float)acc));
    } else {
        sg = 1.0f;
    }
    for (int i = 0; i < c->hidden; i++) y[i] += sg * down[i];

    free(gate);
    free(up);
    free(hid);
    free(down);
    return 0;
fail:
    free(gate);
    free(up);
    free(hid);
    free(down);
    return -1;
}

static int full_attn(Q35Model *m, int li, const float *x, float *y)
{
    const Q35Cfg *c = &m->cfg;
    const Q35LayerTensors *L = &m->layers[li];
    int H = c->hidden, Dh = c->head_dim, nh = c->n_heads, nkv = c->n_kv_heads;
    /* Q+gate fused: out = nh * Dh * 2 */
    int qg = nh * Dh * 2;
    float *qgbuf = (float *)malloc((size_t)qg * sizeof(float));
    float *kbuf = (float *)malloc((size_t)nkv * Dh * sizeof(float));
    float *vbuf = (float *)malloc((size_t)nkv * Dh * sizeof(float));
    float *qnormw = (float *)malloc((size_t)Dh * sizeof(float));
    float *knormw = (float *)malloc((size_t)Dh * sizeof(float));
    float *att = (float *)malloc((size_t)(m->pos + 1) * sizeof(float));
    float *xb = (float *)malloc((size_t)nh * Dh * sizeof(float));
    if (!qgbuf || !kbuf || !vbuf || !qnormw || !knormw || !att || !xb) {
        free(qgbuf);
        free(kbuf);
        free(vbuf);
        free(qnormw);
        free(knormw);
        free(att);
        free(xb);
        return -1;
    }
    if (matmul_tensor(m, qgbuf, x, L->wq, H, qg)) goto fail;
    if (matmul_tensor(m, kbuf, x, L->wk, H, nkv * Dh)) goto fail;
    if (matmul_tensor(m, vbuf, x, L->wv, H, nkv * Dh)) goto fail;
    load_f32_tensor(&m->gguf, L->q_norm, qnormw, Dh);
    load_f32_tensor(&m->gguf, L->k_norm, knormw, Dh);

    /* split Q and gate; Q is even slots in fused layout per llama.cpp view */
    float *q = (float *)malloc((size_t)nh * Dh * sizeof(float));
    float *gate = (float *)malloc((size_t)nh * Dh * sizeof(float));
    if (!q || !gate) {
        free(q);
        free(gate);
        goto fail;
    }
    for (int h = 0; h < nh; h++) {
        memcpy(q + h * Dh, qgbuf + h * Dh * 2, (size_t)Dh * sizeof(float));
        memcpy(gate + h * Dh, qgbuf + h * Dh * 2 + Dh, (size_t)Dh * sizeof(float));
        ops_rmsnorm(q + h * Dh, q + h * Dh, qnormw, Dh, c->rms_eps);
    }
    for (int h = 0; h < nkv; h++)
        ops_rmsnorm(kbuf + h * Dh, kbuf + h * Dh, knormw, Dh, c->rms_eps);

    ops_rope_multi(q, nh, Dh, c->rope_dim, m->pos, c->rope_theta, c->rope_sections);
    ops_rope_multi(kbuf, nkv, Dh, c->rope_dim, m->pos, c->rope_theta, c->rope_sections);

    /* write KV cache */
    memcpy(m->k_cache[li] + (size_t)m->pos * nkv * Dh, kbuf,
           (size_t)nkv * Dh * sizeof(float));
    memcpy(m->v_cache[li] + (size_t)m->pos * nkv * Dh, vbuf,
           (size_t)nkv * Dh * sizeof(float));

    float scale = 1.0f / sqrtf((float)Dh);
    int kv_mul = nh / nkv;
    for (int h = 0; h < nh; h++) {
        int hkv = h / kv_mul;
        for (int t = 0; t <= m->pos; t++) {
            const float *k = m->k_cache[li] + (size_t)t * nkv * Dh + hkv * Dh;
            double acc = 0.0;
            for (int j = 0; j < Dh; j++) acc += (double)q[h * Dh + j] * (double)k[j];
            att[t] = (float)acc * scale;
        }
        ops_softmax(att, m->pos + 1);
        float *out_h = xb + h * Dh;
        memset(out_h, 0, (size_t)Dh * sizeof(float));
        for (int t = 0; t <= m->pos; t++) {
            const float *v = m->v_cache[li] + (size_t)t * nkv * Dh + hkv * Dh;
            for (int j = 0; j < Dh; j++) out_h[j] += att[t] * v[j];
        }
        /* sigmoid gate */
        for (int j = 0; j < Dh; j++) {
            float g = 1.0f / (1.0f + expf(-gate[h * Dh + j]));
            out_h[j] *= g;
        }
    }
    if (matmul_tensor(m, y, xb, L->wo, nh * Dh, H)) {
        free(q);
        free(gate);
        goto fail;
    }
    free(q);
    free(gate);
    free(qgbuf);
    free(kbuf);
    free(vbuf);
    free(qnormw);
    free(knormw);
    free(att);
    free(xb);
    return 0;
fail:
    free(qgbuf);
    free(kbuf);
    free(vbuf);
    free(qnormw);
    free(knormw);
    free(att);
    free(xb);
    return -1;
}

static int linear_attn(Q35Model *m, int li, const float *x, float *y)
{
    const Q35Cfg *c = &m->cfg;
    const Q35LayerTensors *L = &m->layers[li];
    int H = c->hidden;
    int nk = c->ssm_n_group, nv = c->ssm_dt_rank, d = c->ssm_state;
    int qkv_dim = nk * d * 2 + nv * d; /* 8192 */
    float *qkv = (float *)malloc((size_t)qkv_dim * sizeof(float));
    float *z = (float *)malloc((size_t)nv * d * sizeof(float));
    float *alpha = (float *)malloc((size_t)nv * sizeof(float));
    float *beta = (float *)malloc((size_t)nv * sizeof(float));
    float *dt = (float *)malloc((size_t)nv * sizeof(float));
    float *A = (float *)malloc((size_t)nv * sizeof(float));
    float *conv_w = NULL;
    float *norm_w = (float *)malloc((size_t)d * sizeof(float));
    float *core = (float *)malloc((size_t)nv * d * sizeof(float));
    if (!qkv || !z || !alpha || !beta || !dt || !A || !norm_w || !core) goto fail;

    if (matmul_tensor(m, qkv, x, L->wqkv, H, qkv_dim)) goto fail;
    if (matmul_tensor(m, z, x, L->wgate, H, nv * d)) goto fail;
    if (matmul_tensor(m, alpha, x, L->ssm_alpha, H, nv)) goto fail;
    if (matmul_tensor(m, beta, x, L->ssm_beta, H, nv)) goto fail;
    load_f32_tensor(&m->gguf, L->ssm_dt, dt, nv);
    load_f32_tensor(&m->gguf, L->ssm_a, A, nv);
    load_f32_tensor(&m->gguf, L->ssm_norm, norm_w, d);
    ops_sigmoid(beta, beta, nv);

    /* alpha_softplus(alpha + dt) * A  → gate (log-space decay) */
    float *asp = (float *)malloc((size_t)nv * sizeof(float));
    if (!asp) goto fail;
    for (int i = 0; i < nv; i++) asp[i] = alpha[i] + dt[i];
    ops_softplus(asp, asp, nv);
    float *g = (float *)malloc((size_t)nv * sizeof(float));
    if (!g) {
        free(asp);
        goto fail;
    }
    for (int i = 0; i < nv; i++) g[i] = expf(A[i] * asp[i]); /* A already stores -exp(A_log) */
    free(asp);

    size_t cw = ggml_nbytes(L->ssm_conv1d);
    conv_w = (float *)malloc(cw);
    if (!conv_w || gguf_read_tensor_bytes(&m->gguf, L->ssm_conv1d, 0, conv_w, cw)) {
        free(g);
        goto fail;
    }
    float *qkv_c = (float *)malloc((size_t)qkv_dim * sizeof(float));
    if (!qkv_c) {
        free(g);
        goto fail;
    }
    ops_shortconv(qkv_c, qkv, conv_w, m->conv_state[li], qkv_dim, c->ssm_conv);
    ops_silu(qkv_c, qkv_c, qkv_dim);

    float *q0 = qkv_c;
    float *k0 = qkv_c + nk * d;
    float *v0 = qkv_c + 2 * nk * d;
    for (int h = 0; h < nk; h++) {
        ops_l2norm(q0 + h * d, d, c->rms_eps);
        ops_l2norm(k0 + h * d, d, c->rms_eps);
    }

    float qscale = 1.0f / sqrtf((float)d);
    int rep = nv / nk;
    for (int hv = 0; hv < nv; hv++) {
        int hk = hv / rep;
        float *S = m->ssm_state[li] + (size_t)hv * d * d;
        float *o = core + hv * d;
        ops_deltanet_step(S, o, q0 + hk * d, k0 + hk * d, v0 + hv * d, g[hv], beta[hv], d,
                          qscale);
        /* gated RMSNorm with z */
        float tmp[256];
        ops_rmsnorm(tmp, o, norm_w, d, c->rms_eps);
        for (int j = 0; j < d; j++) {
            float zv = z[hv * d + j];
            float silu = zv / (1.0f + expf(-zv));
            o[j] = tmp[j] * silu;
        }
    }
    free(g);
    free(qkv_c);
    if (matmul_tensor(m, y, core, L->ssm_out, nv * d, H)) goto fail;

    free(qkv);
    free(z);
    free(alpha);
    free(beta);
    free(dt);
    free(A);
    free(conv_w);
    free(norm_w);
    free(core);
    return 0;
fail:
    free(qkv);
    free(z);
    free(alpha);
    free(beta);
    free(dt);
    free(A);
    free(conv_w);
    free(norm_w);
    free(core);
    return -1;
}

int q35_decode(Q35Model *m, int token_id)
{
    if (m->pos >= m->ctx_cap) {
        fprintf(stderr, "q35: context full (%d)\n", m->ctx_cap);
        return -1;
    }
    if (q35_embed(m, token_id, m->x)) return -2;

    float *attn_out = (float *)malloc((size_t)m->cfg.hidden * sizeof(float));
    float *ffn_out = (float *)malloc((size_t)m->cfg.hidden * sizeof(float));
    float *norm_w = (float *)malloc((size_t)m->cfg.hidden * sizeof(float));
    if (!attn_out || !ffn_out || !norm_w) {
        free(attn_out);
        free(ffn_out);
        free(norm_w);
        return -3;
    }

    for (int li = 0; li < m->cfg.n_layers; li++) {
        const Q35LayerTensors *L = &m->layers[li];
        load_f32_tensor(&m->gguf, L->attn_norm, norm_w, m->cfg.hidden);
        ops_rmsnorm(m->xb, m->x, norm_w, m->cfg.hidden, m->cfg.rms_eps);

        if (m->cfg.is_linear[li]) {
            if (linear_attn(m, li, m->xb, attn_out)) goto fail;
        } else {
            if (full_attn(m, li, m->xb, attn_out)) goto fail;
        }
        for (int i = 0; i < m->cfg.hidden; i++) m->x[i] += attn_out[i];

        load_f32_tensor(&m->gguf, L->post_attn_norm, norm_w, m->cfg.hidden);
        ops_rmsnorm(m->xb, m->x, norm_w, m->cfg.hidden, m->cfg.rms_eps);
        if (moe_ffn(m, li, m->xb, ffn_out)) goto fail;
        for (int i = 0; i < m->cfg.hidden; i++) m->x[i] += ffn_out[i];
    }

    load_f32_tensor(&m->gguf, m->output_norm, norm_w, m->cfg.hidden);
    ops_rmsnorm(m->xb, m->x, norm_w, m->cfg.hidden, m->cfg.rms_eps);
    if (matmul_tensor(m, m->logits, m->xb, m->output, m->cfg.hidden, m->cfg.vocab)) goto fail;

    m->pos++;
    free(attn_out);
    free(ffn_out);
    free(norm_w);
    return 0;
fail:
    free(attn_out);
    free(ffn_out);
    free(norm_w);
    return -4;
}
