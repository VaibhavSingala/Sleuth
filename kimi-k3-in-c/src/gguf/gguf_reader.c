/* SPDX-License-Identifier: Apache-2.0 */
#include "gguf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

static int read_exact(FILE *fp, void *dst, size_t n)
{
    return fread(dst, 1, n, fp) == n ? 0 : -1;
}

static char *read_string(FILE *fp)
{
    uint64_t n = 0;
    if (read_exact(fp, &n, 8) != 0) return NULL;
    char *s = (char *)malloc((size_t)n + 1);
    if (!s) return NULL;
    if (n && read_exact(fp, s, (size_t)n) != 0) {
        free(s);
        return NULL;
    }
    s[n] = 0;
    return s;
}

static int read_value(FILE *fp, GgufKV *kv)
{
    uint32_t t = 0;
    if (read_exact(fp, &t, 4) != 0) return -1;
    kv->type = (GgufValType)t;
    memset(&kv->v, 0, sizeof(kv->v));
    switch (kv->type) {
    case GGUF_TYPE_UINT8: {
        uint8_t x;
        if (read_exact(fp, &x, 1)) return -1;
        kv->v.u64 = x;
        return 0;
    }
    case GGUF_TYPE_INT8: {
        int8_t x;
        if (read_exact(fp, &x, 1)) return -1;
        kv->v.i64 = x;
        return 0;
    }
    case GGUF_TYPE_UINT16: {
        uint16_t x;
        if (read_exact(fp, &x, 2)) return -1;
        kv->v.u64 = x;
        return 0;
    }
    case GGUF_TYPE_INT16: {
        int16_t x;
        if (read_exact(fp, &x, 2)) return -1;
        kv->v.i64 = x;
        return 0;
    }
    case GGUF_TYPE_UINT32: {
        uint32_t x;
        if (read_exact(fp, &x, 4)) return -1;
        kv->v.u64 = x;
        return 0;
    }
    case GGUF_TYPE_INT32: {
        int32_t x;
        if (read_exact(fp, &x, 4)) return -1;
        kv->v.i64 = x;
        return 0;
    }
    case GGUF_TYPE_FLOAT32: {
        float x;
        if (read_exact(fp, &x, 4)) return -1;
        kv->v.f64 = x;
        return 0;
    }
    case GGUF_TYPE_BOOL: {
        uint8_t x;
        if (read_exact(fp, &x, 1)) return -1;
        kv->v.b = x != 0;
        return 0;
    }
    case GGUF_TYPE_STRING:
        kv->v.s = read_string(fp);
        return kv->v.s ? 0 : -1;
    case GGUF_TYPE_UINT64:
        return read_exact(fp, &kv->v.u64, 8);
    case GGUF_TYPE_INT64:
        return read_exact(fp, &kv->v.i64, 8);
    case GGUF_TYPE_FLOAT64:
        return read_exact(fp, &kv->v.f64, 8);
    case GGUF_TYPE_ARRAY: {
        uint32_t et = 0;
        uint64_t n = 0;
        if (read_exact(fp, &et, 4) || read_exact(fp, &n, 8)) return -1;
        kv->v.arr.etype = (GgufValType)et;
        kv->v.arr.n = n;
        kv->v.arr.data = NULL;
        if (et == GGUF_TYPE_STRING) {
            char **ss = (char **)calloc((size_t)n, sizeof(char *));
            if (!ss && n) return -1;
            for (uint64_t i = 0; i < n; i++) {
                ss[i] = read_string(fp);
                if (!ss[i]) {
                    while (i--) free(ss[i]);
                    free(ss);
                    return -1;
                }
            }
            kv->v.arr.data = ss;
            return 0;
        }
        size_t esz = 0;
        switch (et) {
        case GGUF_TYPE_UINT8:
        case GGUF_TYPE_INT8:
        case GGUF_TYPE_BOOL: esz = 1; break;
        case GGUF_TYPE_UINT16:
        case GGUF_TYPE_INT16: esz = 2; break;
        case GGUF_TYPE_UINT32:
        case GGUF_TYPE_INT32:
        case GGUF_TYPE_FLOAT32: esz = 4; break;
        case GGUF_TYPE_UINT64:
        case GGUF_TYPE_INT64:
        case GGUF_TYPE_FLOAT64: esz = 8; break;
        default: return -1;
        }
        size_t bytes = (size_t)n * esz;
        void *buf = NULL;
        if (bytes) {
            buf = malloc(bytes);
            if (!buf) return -1;
            if (read_exact(fp, buf, bytes)) {
                free(buf);
                return -1;
            }
        }
        kv->v.arr.data = buf;
        return 0;
    }
    default:
        return -1;
    }
}

static void free_kv(GgufKV *kv)
{
    if (!kv) return;
    free(kv->key);
    if (kv->type == GGUF_TYPE_STRING) free(kv->v.s);
    if (kv->type == GGUF_TYPE_ARRAY) {
        if (kv->v.arr.etype == GGUF_TYPE_STRING && kv->v.arr.data) {
            char **ss = (char **)kv->v.arr.data;
            for (uint64_t i = 0; i < kv->v.arr.n; i++) free(ss[i]);
        }
        free(kv->v.arr.data);
    }
}

size_t ggml_type_block_elems(GgmlType t)
{
    switch (t) {
    case GGML_TYPE_F32:
    case GGML_TYPE_F16:
    case GGML_TYPE_BF16: return 1;
    case GGML_TYPE_Q4_0:
    case GGML_TYPE_Q4_1:
    case GGML_TYPE_Q5_0:
    case GGML_TYPE_Q5_1:
    case GGML_TYPE_Q8_0:
    case GGML_TYPE_Q8_1: return 32;
    case GGML_TYPE_Q2_K:
    case GGML_TYPE_Q3_K:
    case GGML_TYPE_Q4_K:
    case GGML_TYPE_Q5_K:
    case GGML_TYPE_Q6_K:
    case GGML_TYPE_Q8_K: return 256;
    default: return 0;
    }
}

size_t ggml_type_block_size(GgmlType t)
{
    switch (t) {
    case GGML_TYPE_F32: return 4;
    case GGML_TYPE_F16:
    case GGML_TYPE_BF16: return 2;
    case GGML_TYPE_Q4_0: return 2 + 16;
    case GGML_TYPE_Q4_1: return 2 + 2 + 16;
    case GGML_TYPE_Q5_0: return 2 + 4 + 16;
    case GGML_TYPE_Q5_1: return 2 + 2 + 4 + 16;
    case GGML_TYPE_Q8_0: return 2 + 32;
    case GGML_TYPE_Q8_1: return 4 + 4 + 32;
    case GGML_TYPE_Q2_K: return 2 + 2 + 16 + 64;
    case GGML_TYPE_Q3_K: return 2 + 32 + 64 + 12;
    case GGML_TYPE_Q4_K: return 2 + 2 + 12 + 128; /* 144 */
    case GGML_TYPE_Q5_K: return 2 + 2 + 12 + 32 + 128;
    case GGML_TYPE_Q6_K: return 2 + 16 + 192; /* 210 */
    case GGML_TYPE_Q8_K: return 4 + 256 + 32 * 2;
    default: return 0;
    }
}

size_t ggml_nbytes(const GgufTensor *t)
{
    uint64_t ne = 1;
    for (uint32_t i = 0; i < t->n_dims; i++) ne *= t->dims[i];
    size_t be = ggml_type_block_elems(t->type);
    size_t bs = ggml_type_block_size(t->type);
    if (!be || !bs) return 0;
    return (size_t)((ne + be - 1) / be) * bs;
}

int gguf_open(GgufFile *g, const char *path)
{
    memset(g, 0, sizeof(*g));
    g->path = strdup(path);
    g->fp = fopen(path, "rb");
    if (!g->fp) {
        free(g->path);
        g->path = NULL;
        return -1;
    }
    char magic[4];
    if (read_exact(g->fp, magic, 4) || memcmp(magic, "GGUF", 4) != 0) {
        gguf_close(g);
        return -2;
    }
    if (read_exact(g->fp, &g->version, 4)) {
        gguf_close(g);
        return -3;
    }
    if (read_exact(g->fp, &g->tensor_count, 8) || read_exact(g->fp, &g->kv_count, 8)) {
        gguf_close(g);
        return -3;
    }
    g->kv = (GgufKV *)calloc((size_t)g->kv_count, sizeof(GgufKV));
    if (!g->kv && g->kv_count) {
        gguf_close(g);
        return -4;
    }
    for (uint64_t i = 0; i < g->kv_count; i++) {
        g->kv[i].key = read_string(g->fp);
        if (!g->kv[i].key || read_value(g->fp, &g->kv[i])) {
            gguf_close(g);
            return -5;
        }
    }
    g->tensors = (GgufTensor *)calloc((size_t)g->tensor_count, sizeof(GgufTensor));
    if (!g->tensors && g->tensor_count) {
        gguf_close(g);
        return -4;
    }
    for (uint64_t i = 0; i < g->tensor_count; i++) {
        GgufTensor *t = &g->tensors[i];
        t->name = read_string(g->fp);
        if (!t->name || read_exact(g->fp, &t->n_dims, 4)) {
            gguf_close(g);
            return -6;
        }
        if (t->n_dims > 4) {
            gguf_close(g);
            return -6;
        }
        for (uint32_t d = 0; d < t->n_dims; d++) {
            if (read_exact(g->fp, &t->dims[d], 8)) {
                gguf_close(g);
                return -6;
            }
        }
        uint32_t ty = 0;
        if (read_exact(g->fp, &ty, 4) || read_exact(g->fp, &t->offset, 8)) {
            gguf_close(g);
            return -6;
        }
        t->type = (GgmlType)ty;
    }
    /* Align to 32 bytes */
    long pos = ftell(g->fp);
    if (pos < 0) {
        gguf_close(g);
        return -7;
    }
    g->data_offset = (uint64_t)((pos + 31) & ~31L);
    if (fseek(g->fp, 0, SEEK_END) != 0) {
        gguf_close(g);
        return -7;
    }
    g->file_size = ftell(g->fp);
    return 0;
}

void gguf_close(GgufFile *g)
{
    if (!g) return;
    if (g->fp) fclose(g->fp);
    g->fp = NULL;
    free(g->path);
    g->path = NULL;
    if (g->kv) {
        for (uint64_t i = 0; i < g->kv_count; i++) free_kv(&g->kv[i]);
        free(g->kv);
        g->kv = NULL;
    }
    if (g->tensors) {
        for (uint64_t i = 0; i < g->tensor_count; i++) free(g->tensors[i].name);
        free(g->tensors);
        g->tensors = NULL;
    }
}

const GgufKV *gguf_find_kv(const GgufFile *g, const char *key)
{
    for (uint64_t i = 0; i < g->kv_count; i++)
        if (strcmp(g->kv[i].key, key) == 0) return &g->kv[i];
    return NULL;
}

const GgufTensor *gguf_find_tensor(const GgufFile *g, const char *name)
{
    for (uint64_t i = 0; i < g->tensor_count; i++)
        if (strcmp(g->tensors[i].name, name) == 0) return &g->tensors[i];
    return NULL;
}

int gguf_kv_u32(const GgufFile *g, const char *key, uint32_t *out)
{
    const GgufKV *kv = gguf_find_kv(g, key);
    if (!kv) return -1;
    *out = (uint32_t)kv->v.u64;
    return 0;
}

int gguf_kv_u64(const GgufFile *g, const char *key, uint64_t *out)
{
    const GgufKV *kv = gguf_find_kv(g, key);
    if (!kv) return -1;
    *out = kv->v.u64;
    return 0;
}

int gguf_kv_f32(const GgufFile *g, const char *key, float *out)
{
    const GgufKV *kv = gguf_find_kv(g, key);
    if (!kv) return -1;
    *out = (float)kv->v.f64;
    return 0;
}

int gguf_kv_str(const GgufFile *g, const char *key, const char **out)
{
    const GgufKV *kv = gguf_find_kv(g, key);
    if (!kv || kv->type != GGUF_TYPE_STRING) return -1;
    *out = kv->v.s;
    return 0;
}

int gguf_read_tensor_bytes(const GgufFile *g, const GgufTensor *t,
                           uint64_t off, void *dst, size_t nbytes)
{
    uint64_t abs = g->data_offset + t->offset + off;
    if (fseek(g->fp, (long)abs, SEEK_SET) != 0) return -1;
    return read_exact(g->fp, dst, nbytes);
}
