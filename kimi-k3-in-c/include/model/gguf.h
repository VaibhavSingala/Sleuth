/* SPDX-License-Identifier: Apache-2.0 */
/* Minimal GGUF v3 reader for direct inference (no second weight file). */
#ifndef MODEL_GGUF_H
#define MODEL_GGUF_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GGUF_TYPE_UINT8 = 0,
    GGUF_TYPE_INT8 = 1,
    GGUF_TYPE_UINT16 = 2,
    GGUF_TYPE_INT16 = 3,
    GGUF_TYPE_UINT32 = 4,
    GGUF_TYPE_INT32 = 5,
    GGUF_TYPE_FLOAT32 = 6,
    GGUF_TYPE_BOOL = 7,
    GGUF_TYPE_STRING = 8,
    GGUF_TYPE_ARRAY = 9,
    GGUF_TYPE_UINT64 = 10,
    GGUF_TYPE_INT64 = 11,
    GGUF_TYPE_FLOAT64 = 12
} GgufValType;

typedef enum {
    GGML_TYPE_F32 = 0,
    GGML_TYPE_F16 = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q8_1 = 9,
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
    GGML_TYPE_BF16 = 30
} GgmlType;

typedef struct {
    char *key;
    GgufValType type;
    /* Scalar payloads (STRING points into owned heap). ARRAY metadata only. */
    union {
        uint64_t u64;
        int64_t i64;
        double f64;
        int b;
        char *s;
        struct {
            GgufValType etype;
            uint64_t n;
            void *data; /* etype elements, or char** for STRING */
        } arr;
    } v;
} GgufKV;

typedef struct {
    char *name;
    uint32_t n_dims;
    uint64_t dims[4];
    GgmlType type;
    uint64_t offset; /* relative to data section */
} GgufTensor;

typedef struct {
    FILE *fp;
    char *path;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t kv_count;
    GgufKV *kv;
    GgufTensor *tensors;
    uint64_t data_offset; /* absolute file offset of first tensor byte */
    int64_t file_size;
} GgufFile;

int gguf_open(GgufFile *g, const char *path);
void gguf_close(GgufFile *g);

const GgufKV *gguf_find_kv(const GgufFile *g, const char *key);
const GgufTensor *gguf_find_tensor(const GgufFile *g, const char *name);

/* Typed KV helpers. Return 0 on success. */
int gguf_kv_u32(const GgufFile *g, const char *key, uint32_t *out);
int gguf_kv_u64(const GgufFile *g, const char *key, uint64_t *out);
int gguf_kv_f32(const GgufFile *g, const char *key, float *out);
int gguf_kv_str(const GgufFile *g, const char *key, const char **out);

size_t ggml_type_block_size(GgmlType t); /* bytes per block */
size_t ggml_type_block_elems(GgmlType t);
size_t ggml_nbytes(const GgufTensor *t);

/* Read nbytes at tensor payload + off into dst. Returns 0 on success. */
int gguf_read_tensor_bytes(const GgufFile *g, const GgufTensor *t,
                           uint64_t off, void *dst, size_t nbytes);

#ifdef __cplusplus
}
#endif
#endif
