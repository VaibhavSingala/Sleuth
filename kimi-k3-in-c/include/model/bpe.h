/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MODEL_BPE_H
#define MODEL_BPE_H

#include "gguf.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int vocab_size;
    char **tokens;          /* vocab_size strings (owned) */
    int *token_score_order; /* optional */
    /* merge ranks: key "t1 t2" -> rank */
    char **merges;          /* n_merges strings "a b" */
    int n_merges;
    int *merge_rank;        /* parallel to merges, 0..n_merges-1 */
    int bos_id, eos_id, pad_id;
    char *chat_template;    /* owned copy or NULL */
} BpeTok;

int bpe_from_gguf(BpeTok *t, const GgufFile *g);
void bpe_free(BpeTok *t);

/* Encode UTF-8 text to token ids. Returns count, or -1 on error. */
int bpe_encode(const BpeTok *t, const char *text, int *out_ids, int max_ids);

/* Decode ids to text into buf. Returns bytes written (excl NUL), or -1. */
int bpe_decode(const BpeTok *t, const int *ids, int n, char *buf, int buf_sz);

/* Minimal chat wrap for Qwen: <|im_start|>user\n{p}<|im_end|>\n<|im_start|>assistant\n */
int bpe_apply_chat(const BpeTok *t, const char *user_prompt, char *out, int out_sz);

#ifdef __cplusplus
}
#endif
#endif
