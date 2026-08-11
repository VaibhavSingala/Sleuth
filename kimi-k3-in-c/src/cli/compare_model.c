/* SPDX-License-Identifier: Apache-2.0 */
#include "bpe.h"
#include "qwen35.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *gguf = NULL, *prompt = "The capital of France is";
    int ntok = 20, ctx = 512;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-' && !gguf) gguf = argv[i];
        else if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) prompt = argv[++i];
        else if (strcmp(argv[i], "--tokens") == 0 && i + 1 < argc) ntok = atoi(argv[++i]);
        else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc) ctx = atoi(argv[++i]);
    }
    if (!gguf) {
        fprintf(stderr, "usage: %s model.gguf --prompt TEXT --tokens N\n", argv[0]);
        return 1;
    }

    Q35Model model;
    if (q35_load(&model, gguf, q35_parse_ram("laptop"), ctx)) return 2;
    BpeTok tok;
    if (bpe_from_gguf(&tok, &model.gguf)) return 3;

    int ids[1024];
    int n = bpe_encode(&tok, prompt, ids, 1024);
    if (n <= 0) {
        fprintf(stderr, "tokenize failed\n");
        return 4;
    }
    for (int i = 0; i < n; i++)
        if (q35_decode(&model, ids[i])) return 5;

    printf("TOKEN VALIDATION (greedy C engine — compare against LM Studio manually)\n\n");
    int match = 0;
    for (int i = 0; i < ntok; i++) {
        int id = q35_argmax(model.logits, model.cfg.vocab);
        char piece[256];
        bpe_decode(&tok, &id, 1, piece, (int)sizeof(piece));
        printf("token %d:\nC:          %s  (id=%d)\n", i, piece, id);
        printf("(reference: run same prompt in LM Studio with temperature=0)\n\n");
        match++; /* structure ready; external ref comparison is offline */
        if (id == model.cfg.eos_id) {
            ntok = i + 1;
            break;
        }
        if (q35_decode(&model, id)) break;
    }
    printf("RESULT: generated %d/%d tokens (greedy). Supply LM Studio token dump to score MATCH.\n",
           match, ntok);
    bpe_free(&tok);
    q35_free(&model);
    return 0;
}
