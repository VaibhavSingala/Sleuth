/* SPDX-License-Identifier: Apache-2.0 */
/* Q4_K / Q6_K dequant + matmul (llama.cpp-compatible layouts). */
#include "quant.h"

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint16_t ggml_fp16_t;

static float fp16_to_fp32(ggml_fp16_t h)
{
    /* IEEE half → float (handles normals; enough for GGUF scales). */
    uint32_t sign = (uint32_t)(h & 0x8000) << 16;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) bits = sign;
        else {
            exp = 127 - 15 + 1;
            while ((mant & 0x400) == 0) {
                mant <<= 1;
                exp--;
            }
            mant &= 0x3FF;
            bits = sign | (exp << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        bits = sign | 0x7F800000u | (mant << 13);
    } else {
        bits = sign | ((exp + (127 - 15)) << 23) | (mant << 13);
    }
    float f;
    memcpy(&f, &bits, 4);
    return f;
}

typedef struct {
    ggml_fp16_t d;
    ggml_fp16_t dmin;
    uint8_t scales[K_SCALE_SIZE];
    uint8_t qs[QK_K / 2];
} block_q4_K;

typedef struct {
    uint8_t ql[QK_K / 2];
    uint8_t qh[QK_K / 4];
    int8_t scales[QK_K / 16];
    ggml_fp16_t d;
} block_q6_K;

static inline void get_scale_min_k4(int j, const uint8_t *q, uint8_t *d, uint8_t *m)
{
    if (j < 4) {
        *d = q[j] & 63;
        *m = q[j + 4] & 63;
    } else {
        *d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
        *m = (q[j + 4] >> 4) | ((q[j - 0] >> 6) << 4);
    }
}

void quant_dequant_q4_k(const void *data, float *out, int64_t n)
{
    const block_q4_K *x = (const block_q4_K *)data;
    const int nb = (int)(n / QK_K);
    float *y = out;
    for (int i = 0; i < nb; i++) {
        const uint8_t *q = x[i].qs;
        const float d = fp16_to_fp32(x[i].d);
        const float min = fp16_to_fp32(x[i].dmin);
        int is = 0;
        uint8_t sc, m;
        for (int j = 0; j < QK_K; j += 64) {
            get_scale_min_k4(is + 0, x[i].scales, &sc, &m);
            const float d1 = d * sc, m1 = min * m;
            get_scale_min_k4(is + 1, x[i].scales, &sc, &m);
            const float d2 = d * sc, m2 = min * m;
            for (int l = 0; l < 32; ++l) *y++ = d1 * (q[l] & 0xF) - m1;
            for (int l = 0; l < 32; ++l) *y++ = d2 * (q[l] >> 4) - m2;
            q += 32;
            is += 2;
        }
    }
}

void quant_dequant_q6_k(const void *data, float *out, int64_t n)
{
    const block_q6_K *x = (const block_q6_K *)data;
    const int64_t nb = n / QK_K;
    float *y = out;
    for (int64_t i = 0; i < nb; i++) {
        const float d = fp16_to_fp32(x[i].d);
        const uint8_t *ql = x[i].ql;
        const uint8_t *qh = x[i].qh;
        const int8_t *sc = x[i].scales;
        for (int n0 = 0; n0 < QK_K; n0 += 128) {
            for (int l = 0; l < 32; ++l) {
                int is = l / 16;
                const int8_t q1 = (int8_t)((ql[l + 0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
                const int8_t q2 = (int8_t)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
                const int8_t q3 = (int8_t)((ql[l + 0] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
                const int8_t q4 = (int8_t)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
                y[l + 0] = d * sc[is + 0] * q1;
                y[l + 32] = d * sc[is + 2] * q2;
                y[l + 64] = d * sc[is + 4] * q3;
                y[l + 96] = d * sc[is + 6] * q4;
            }
            y += 128;
            ql += 64;
            qh += 32;
            sc += 8;
        }
    }
}

void quant_dequant_f32(const void *data, float *out, int64_t n)
{
    memcpy(out, data, (size_t)n * sizeof(float));
}

size_t quant_nbytes(GgmlType type, int64_t n)
{
    size_t be = ggml_type_block_elems(type);
    size_t bs = ggml_type_block_size(type);
    if (!be || !bs) return 0;
    return (size_t)((n + (int64_t)be - 1) / (int64_t)be) * bs;
}

int quant_matmul(float *y, const float *x, const void *W, GgmlType type,
                 int in, int out)
{
    /* Dequantize one output row at a time to limit peak scratch. */
    float *row = (float *)malloc((size_t)in * sizeof(float));
    if (!row) return -1;
    size_t row_bytes = quant_nbytes(type, in);
    const uint8_t *base = (const uint8_t *)W;
    for (int r = 0; r < out; r++) {
        const void *src = base + r * row_bytes;
        switch (type) {
        case GGML_TYPE_F32: quant_dequant_f32(src, row, in); break;
        case GGML_TYPE_Q4_K: quant_dequant_q4_k(src, row, in); break;
        case GGML_TYPE_Q6_K: quant_dequant_q6_k(src, row, in); break;
        default:
            free(row);
            return -2;
        }
        double acc = 0.0;
        for (int c = 0; c < in; c++) acc += (double)row[c] * (double)x[c];
        y[r] = (float)acc;
    }
    free(row);
    return 0;
}
