/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MODEL_QUANT_H
#define MODEL_QUANT_H

#include "gguf.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QK_K 256
#define K_SCALE_SIZE 12

/* Dequantize an entire tensor (or a row-major matrix) into float.
 * n = number of elements. Data must be tightly packed blocks. */
void quant_dequant_q4_k(const void *data, float *out, int64_t n);
void quant_dequant_q6_k(const void *data, float *out, int64_t n);
void quant_dequant_f32(const void *data, float *out, int64_t n);

/* y[out] = W[out][in] . x[in], W may be quantized. */
int quant_matmul(float *y, const float *x, const void *W, GgmlType type,
                 int in, int out);

/* Bytes required to store `n` elements of the given type. */
size_t quant_nbytes(GgmlType type, int64_t n);

#ifdef __cplusplus
}
#endif
#endif
