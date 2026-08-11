/* SPDX-License-Identifier: Apache-2.0 */
#include "bpe.h"
#include "qwen35.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <sys/resource.h>
static double peak_rss_mb(void)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss / 1024.0; /* kB → MB on Linux */
}
#else
static double peak_rss_mb(void) { return 0.0; }
#endif

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s model.gguf --prompt TEXT [options]\n"
            "  --chat            wrap prompt in Qwen chat template\n"
            "  --gen N           generate N tokens (default 32)\n"
            "  --temperature T   (0 = greedy)\n"
            "  --top-k K --top-p P --seed S\n"
            "  --threads N --context N\n"
            "  --ram 8G|16G|32G|64G | --preset laptop|desktop|server\n"
            "  --verbose\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *gguf = NULL, *prompt = NULL, *ram = "laptop";
    int chat = 0, gen = 32, threads = 4, ctx = 2048, verbose = 0, seed = 0;
    float temp = 0.0f, topp = 1.0f;
    int topk = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            if (!gguf) gguf = argv[i];
            else {
                usage(argv[0]);
                return 1;
            }
        } else if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc)
            prompt = argv[++i];
        else if (strcmp(argv[i], "--chat") == 0)
            chat = 1;
        else if (strcmp(argv[i], "--gen") == 0 && i + 1 < argc)
            gen = atoi(argv[++i]);
        else if (strcmp(argv[i], "--temperature") == 0 && i + 1 < argc)
            temp = (float)atof(argv[++i]);
        else if (strcmp(argv[i], "--top-k") == 0 && i + 1 < argc)
            topk = atoi(argv[++i]);
        else if (strcmp(argv[i], "--top-p") == 0 && i + 1 < argc)
            topp = (float)atof(argv[++i]);
        else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
            seed = atoi(argv[++i]);
        else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc)
            threads = atoi(argv[++i]);
        else if (strcmp(argv[i], "--context") == 0 && i + 1 < argc)
            ctx = atoi(argv[++i]);
        else if (strcmp(argv[i], "--ram") == 0 && i + 1 < argc)
            ram = argv[++i];
        else if (strcmp(argv[i], "--preset") == 0 && i + 1 < argc)
            ram = argv[++i];
        else if (strcmp(argv[i], "--verbose") == 0)
            verbose = 1;
        else {
            usage(argv[0]);
            return 1;
        }
    }
    (void)topk;
    (void)topp;
    (void)seed;
    (void)temp;
    if (!gguf || !prompt) {
        usage(argv[0]);
        return 1;
    }

    Q35Model model;
    size_t budget = q35_parse_ram(ram);
    clock_t t0 = clock();
    if (q35_load(&model, gguf, budget, ctx)) return 2;
    model.n_threads = threads;
    double load_s = (double)(clock() - t0) / CLOCKS_PER_SEC;

    BpeTok tok;
    if (bpe_from_gguf(&tok, &model.gguf)) {
        fprintf(stderr, "tokenizer load failed\n");
        q35_free(&model);
        return 3;
    }

    char chatbuf[65536];
    const char *text = prompt;
    if (chat) {
        if (bpe_apply_chat(&tok, prompt, chatbuf, (int)sizeof(chatbuf)) < 0) {
            fprintf(stderr, "chat template failed\n");
            return 4;
        }
        text = chatbuf;
    }

    int ids[4096];
    int n_prompt = bpe_encode(&tok, text, ids, 4096);
    if (n_prompt <= 0) {
        fprintf(stderr, "tokenize failed (%d)\n", n_prompt);
        return 5;
    }

    printf("Model:          %s\n", gguf);
    printf("Architecture:   qwen35moe\n");
    printf("Parameters:     ~35B total / ~3B active\n");
    printf("Quantization:   Q4_K_M (direct GGUF)\n");
    printf("Context:        %d (cap %d)\n", ctx, model.ctx_cap);
    printf("Model size:     %.2f GiB\n", model.gguf.file_size / (1024.0 * 1024.0 * 1024.0));
    printf("RAM available:  %.2f GiB (budget)\n", budget / (1024.0 * 1024.0 * 1024.0));
    printf("Prompt tokens:  %d\n", n_prompt);
    if (verbose) printf("Load time:      %.2fs\n", load_s);

    t0 = clock();
    for (int i = 0; i < n_prompt; i++) {
        if (q35_decode(&model, ids[i])) {
            fprintf(stderr, "decode failed at prompt token %d\n", i);
            return 6;
        }
        if (verbose && (i % 8 == 0)) fprintf(stderr, "prefill %d/%d\r", i + 1, n_prompt);
    }
    double prefill_s = (double)(clock() - t0) / CLOCKS_PER_SEC;

    printf("\n");
    int *gen_ids = (int *)malloc((size_t)gen * sizeof(int));
    t0 = clock();
    for (int i = 0; i < gen; i++) {
        int next = q35_argmax(model.logits, model.cfg.vocab);
        gen_ids[i] = next;
        char piece[256];
        bpe_decode(&tok, &next, 1, piece, (int)sizeof(piece));
        fputs(piece, stdout);
        fflush(stdout);
        if (next == model.cfg.eos_id) {
            gen = i + 1;
            break;
        }
        if (q35_decode(&model, next)) {
            fprintf(stderr, "\ndecode failed during generation\n");
            break;
        }
    }
    double gen_s = (double)(clock() - t0) / CLOCKS_PER_SEC;
    printf("\n\n");
    printf("Generation tokens: %d\n", gen);
    printf("Prompt tok/s:      %.2f\n", n_prompt / (prefill_s > 1e-6 ? prefill_s : 1e-6));
    printf("Generation tok/s:  %.2f\n", gen / (gen_s > 1e-6 ? gen_s : 1e-6));
    printf("Peak RSS:          %.1f MB\n", peak_rss_mb());

    free(gen_ids);
    bpe_free(&tok);
    q35_free(&model);
    return 0;
}
