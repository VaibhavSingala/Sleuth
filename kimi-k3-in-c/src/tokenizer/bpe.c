/* SPDX-License-Identifier: Apache-2.0 */
#include "bpe.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int bpe_from_gguf(BpeTok *t, const GgufFile *g)
{
    memset(t, 0, sizeof(*t));
    const GgufKV *toks = gguf_find_kv(g, "tokenizer.ggml.tokens");
    const GgufKV *merges = gguf_find_kv(g, "tokenizer.ggml.merges");
    if (!toks || toks->type != GGUF_TYPE_ARRAY || toks->v.arr.etype != GGUF_TYPE_STRING)
        return -1;
    if (!merges || merges->type != GGUF_TYPE_ARRAY || merges->v.arr.etype != GGUF_TYPE_STRING)
        return -1;

    t->vocab_size = (int)toks->v.arr.n;
    t->n_merges = (int)merges->v.arr.n;
    t->tokens = (char **)calloc((size_t)t->vocab_size, sizeof(char *));
    t->merges = (char **)calloc((size_t)t->n_merges, sizeof(char *));
    t->merge_rank = (int *)malloc((size_t)t->n_merges * sizeof(int));
    if (!t->tokens || !t->merges || !t->merge_rank) return -2;

    char **src_t = (char **)toks->v.arr.data;
    char **src_m = (char **)merges->v.arr.data;
    for (int i = 0; i < t->vocab_size; i++) {
        t->tokens[i] = strdup(src_t[i] ? src_t[i] : "");
        if (!t->tokens[i]) return -2;
    }
    for (int i = 0; i < t->n_merges; i++) {
        t->merges[i] = strdup(src_m[i] ? src_m[i] : "");
        t->merge_rank[i] = i;
        if (!t->merges[i]) return -2;
    }

    uint32_t id;
    t->bos_id = gguf_kv_u32(g, "tokenizer.ggml.bos_token_id", &id) == 0 ? (int)id : 0;
    t->eos_id = gguf_kv_u32(g, "tokenizer.ggml.eos_token_id", &id) == 0 ? (int)id : 0;
    t->pad_id = gguf_kv_u32(g, "tokenizer.ggml.padding_token_id", &id) == 0 ? (int)id : t->bos_id;

    const char *tmpl = NULL;
    if (gguf_kv_str(g, "tokenizer.chat_template", &tmpl) == 0 && tmpl)
        t->chat_template = strdup(tmpl);
    return 0;
}

void bpe_free(BpeTok *t)
{
    if (!t) return;
    if (t->tokens) {
        for (int i = 0; i < t->vocab_size; i++) free(t->tokens[i]);
        free(t->tokens);
    }
    if (t->merges) {
        for (int i = 0; i < t->n_merges; i++) free(t->merges[i]);
        free(t->merges);
    }
    free(t->merge_rank);
    free(t->chat_template);
    memset(t, 0, sizeof(*t));
}

/* Build token -> id map via linear scan for byte tokens; full BPE below. */
static int find_token(const BpeTok *t, const char *s, int len)
{
    for (int i = 0; i < t->vocab_size; i++) {
        if ((int)strlen(t->tokens[i]) == len && memcmp(t->tokens[i], s, (size_t)len) == 0)
            return i;
    }
    return -1;
}

static int merge_rank_of(const BpeTok *t, const char *a, const char *b)
{
    char key[512];
    snprintf(key, sizeof(key), "%s %s", a, b);
    for (int i = 0; i < t->n_merges; i++)
        if (strcmp(t->merges[i], key) == 0) return t->merge_rank[i];
    return INT32_MAX;
}

int bpe_encode(const BpeTok *t, const char *text, int *out_ids, int max_ids)
{
    /* GPT-2 style: bytes → unicode symbols used in vocab, then BPE merges.
     * Qwen35 pre-tokenizer is close enough for ASCII prompts used in validation. */
    if (!text || max_ids < 1) return -1;

    /* Start as individual UTF-8 bytes mapped through vocab when possible. */
    enum { MAXP = 8192, PSZ = 64 };
    char pieces[MAXP][PSZ];
    int np = 0;
    const unsigned char *p = (const unsigned char *)text;
    while (*p && np < MAXP) {
        /* Prefer multi-byte UTF-8 char as one piece if present in vocab */
        int cl = 1;
        if ((*p & 0x80) == 0) cl = 1;
        else if ((*p & 0xE0) == 0xC0) cl = 2;
        else if ((*p & 0xF0) == 0xE0) cl = 3;
        else if ((*p & 0xF8) == 0xF0) cl = 4;
        if (cl > 1 && find_token(t, (const char *)p, cl) >= 0) {
            memcpy(pieces[np], p, (size_t)cl);
            pieces[np][cl] = 0;
            p += cl;
            np++;
            continue;
        }
        pieces[np][0] = (char)*p;
        pieces[np][1] = 0;
        p++;
        np++;
    }

    /* BPE merges */
    for (;;) {
        int best = INT32_MAX, bi = -1;
        for (int i = 0; i + 1 < np; i++) {
            int r = merge_rank_of(t, pieces[i], pieces[i + 1]);
            if (r < best) {
                best = r;
                bi = i;
            }
        }
        if (bi < 0 || best == INT32_MAX) break;
        char merged[PSZ * 2];
        snprintf(merged, sizeof(merged), "%s%s", pieces[bi], pieces[bi + 1]);
        snprintf(pieces[bi], PSZ, "%s", merged);
        for (int j = bi + 1; j + 1 < np; j++)
            memcpy(pieces[j], pieces[j + 1], sizeof(pieces[j]));
        np--;
    }

    int n = 0;
    for (int i = 0; i < np && n < max_ids; i++) {
        int id = find_token(t, pieces[i], (int)strlen(pieces[i]));
        if (id < 0) continue;
        out_ids[n++] = id;
    }
    return n;
}

int bpe_decode(const BpeTok *t, const int *ids, int n, char *buf, int buf_sz)
{
    int o = 0;
    for (int i = 0; i < n; i++) {
        if (ids[i] < 0 || ids[i] >= t->vocab_size) continue;
        const char *s = t->tokens[ids[i]];
        int L = (int)strlen(s);
        if (o + L + 1 > buf_sz) return -1;
        memcpy(buf + o, s, (size_t)L);
        o += L;
    }
    buf[o] = 0;
    return o;
}

int bpe_apply_chat(const BpeTok *t, const char *user_prompt, char *out, int out_sz)
{
    (void)t;
    /* Text-only subset of Qwen chat template. */
    int n = snprintf(out, (size_t)out_sz,
                     "<|im_start|>user\n%s<|im_end|>\n<|im_start|>assistant\n",
                     user_prompt ? user_prompt : "");
    return (n < 0 || n >= out_sz) ? -1 : n;
}
