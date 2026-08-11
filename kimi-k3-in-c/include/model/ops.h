/* SPDX-License-Identifier: Apache-2.0 */
#ifndef MODEL_OPS_H
#define MODEL_OPS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void ops_rmsnorm(float *y, const float *x, const float *w, int n, float eps);
void ops_silu(float *y, const float *x, int n);
void ops_sigmoid(float *y, const float *x, int n);
void ops_softmax(float *x, int n);
void ops_softplus(float *y, const float *x, int n);
void ops_l2norm(float *x, int n, float eps);

/* Partial interleaved mRoPE on first rope_dim of each head (neox-style pairs). */
void ops_rope_multi(float *q, int n_heads, int head_dim, int rope_dim, int pos,
                    float theta, const int sections[4]);

/* Causal depthwise conv1d over channels, kernel k, updates state [channels*(k-1)]. */
void ops_shortconv(float *y, const float *x, const float *w, float *state,
                   int channels, int k);

/* Gated DeltaNet one-token step per value-head.
 * S is [dv][dv] row-major state; q,k length dk (=dv typically); v length dv.
 * g = decay (already exp'd), beta scalar in (0,1], scale applied to q. */
void ops_deltanet_step(float *S, float *o, const float *q, const float *k,
                       const float *v, float g, float beta, int d, float qscale);

#ifdef __cplusplus
}
#endif
#endif
