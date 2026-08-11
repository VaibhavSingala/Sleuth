/* SPDX-License-Identifier: Apache-2.0 */
/* bin/model-converter — inspect/validate GGUF and write a tiny sidecar index.
 * Does NOT duplicate weight bytes (direct GGUF loading). */
#include "gguf.h"
#include "qwen35.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void write_sidecar(const char *gguf_path, const GgufFile *g, const Q35Cfg *c)
{
    char out[4096];
    snprintf(out, sizeof(out), "%s.model.json", gguf_path);
    FILE *fp = fopen(out, "wb");
    if (!fp) {
        perror(out);
        return;
    }
    fprintf(fp,
            "{\n"
            "  \"format\": \"direct-gguf\",\n"
            "  \"gguf\": \"%s\",\n"
            "  \"architecture\": \"qwen35moe\",\n"
            "  \"name\": \"%s\",\n"
            "  \"file_size\": %lld,\n"
            "  \"tensor_count\": %llu,\n"
            "  \"hidden\": %d,\n"
            "  \"layers\": %d,\n"
            "  \"vocab\": %d,\n"
            "  \"experts\": %d,\n"
            "  \"topk\": %d,\n"
            "  \"quant\": \"Q4_K_M\",\n"
            "  \"data_offset\": %llu,\n"
            "  \"engine\": \"kimi-k3-in-c/qwen35moe\",\n"
            "  \"note\": \"Weights remain in the original GGUF; this sidecar is metadata only.\"\n"
            "}\n",
            gguf_path,
            (gguf_find_kv(g, "general.name") && gguf_find_kv(g, "general.name")->type == GGUF_TYPE_STRING)
                ? gguf_find_kv(g, "general.name")->v.s
                : "unknown",
            (long long)g->file_size, (unsigned long long)g->tensor_count, c->hidden, c->n_layers,
            c->vocab, c->n_experts, c->topk, (unsigned long long)g->data_offset);
    fclose(fp);
    printf("Wrote sidecar: %s\n", out);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s /path/to/model.gguf\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    GgufFile g;
    int rc = gguf_open(&g, path);
    if (rc) {
        fprintf(stderr, "failed to open GGUF (%d): %s\n", rc, path);
        return 1;
    }
    Q35Cfg cfg;
    if (q35_cfg_from_gguf(&cfg, &g)) {
        gguf_close(&g);
        return 2;
    }

    printf("GGUF CONVERT / VALIDATE (direct load — no weight rewrite)\n");
    printf("---------------------------------------------------------\n");
    printf("File:           %s\n", path);
    printf("Size:           %.2f GiB\n", (double)g.file_size / (1024.0 * 1024.0 * 1024.0));
    printf("Architecture:   qwen35moe\n");
    printf("Layers:         %d (%d linear + %d full)\n", cfg.n_layers,
           cfg.n_layers - cfg.n_layers / cfg.full_attn_interval,
           cfg.n_layers / cfg.full_attn_interval);
    printf("Hidden:         %d\n", cfg.hidden);
    printf("Vocab:          %d\n", cfg.vocab);
    printf("Experts:        %d (top-%d + shared)\n", cfg.n_experts, cfg.topk);
    printf("Tensors:        %llu\n", (unsigned long long)g.tensor_count);
    printf("Data offset:    %llu\n", (unsigned long long)g.data_offset);

    /* Validate every bound tensor exists */
    int missing = 0;
    if (!gguf_find_tensor(&g, "token_embd.weight")) missing++;
    if (!gguf_find_tensor(&g, "output.weight")) missing++;
    if (!gguf_find_tensor(&g, "output_norm.weight")) missing++;
    for (int i = 0; i < cfg.n_layers; i++) {
        char n[96];
        snprintf(n, sizeof(n), "blk.%d.attn_norm.weight", i);
        if (!gguf_find_tensor(&g, n)) missing++;
        snprintf(n, sizeof(n), "blk.%d.ffn_gate_exps.weight", i);
        if (!gguf_find_tensor(&g, n)) missing++;
        if (cfg.is_linear[i]) {
            snprintf(n, sizeof(n), "blk.%d.attn_qkv.weight", i);
            if (!gguf_find_tensor(&g, n)) missing++;
            snprintf(n, sizeof(n), "blk.%d.ssm_out.weight", i);
            if (!gguf_find_tensor(&g, n)) missing++;
        } else {
            snprintf(n, sizeof(n), "blk.%d.attn_q.weight", i);
            if (!gguf_find_tensor(&g, n)) missing++;
        }
    }
    printf("Validation:     %s (%d missing checks)\n", missing ? "FAIL" : "OK", missing);
    if (!missing) write_sidecar(path, &g, &cfg);
    gguf_close(&g);
    return missing ? 3 : 0;
}
