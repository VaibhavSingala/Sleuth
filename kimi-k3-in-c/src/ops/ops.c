/* SPDX-License-Identifier: Apache-2.0 */
#include "ops.h"

#include <math.h>
#include <string.h>

void ops_rmsnorm(float *y, const float *x, const float *w, int n, float eps)
{
    double ss = 0.0;
    for (int i = 0; i < n; i++) ss += (double)x[i] * (double)x[i];
    const float inv = (float)(1.0 / sqrt(ss / (double)n + (double)eps));
    for (int i = 0; i < n; i++) y[i] = w[i] * x[i] * inv;
}

void ops_silu(float *y, const float *x, int n)
{
    for (int i = 0; i < n; i++) {
        float v = x[i];
        y[i] = v / (1.0f + expf(-v));
    }
}

void ops_sigmoid(float *y, const float *x, int n)
{
    for (int i = 0; i < n; i++) y[i] = 1.0f / (1.0f + expf(-x[i]));
}

void ops_softmax(float *x, int n)
{
    float m = x[0];
    for (int i = 1; i < n; i++)
        if (x[i] > m) m = x[i];
    double s = 0.0;
    for (int i = 0; i < n; i++) {
        x[i] = expf(x[i] - m);
        s += x[i];
    }
    float inv = (float)(1.0 / s);
    for (int i = 0; i < n; i++) x[i] *= inv;
}

void ops_softplus(float *y, const float *x, int n)
{
    for (int i = 0; i < n; i++) {
        float v = x[i];
        y[i] = (v > 20.0f) ? v : logf(1.0f + expf(v));
    }
}

void ops_l2norm(float *x, int n, float eps)
{
    double ss = 0.0;
    for (int i = 0; i < n; i++) ss += (double)x[i] * (double)x[i];
    float inv = (float)(1.0 / sqrt(ss + (double)eps));
    for (int i = 0; i < n; i++) x[i] *= inv;
}

void ops_rope_multi(float *q, int n_heads, int head_dim, int rope_dim, int pos,
                    float theta, const int sections[4])
{
    /* Apply classic RoPE on first rope_dim dims; mRoPE section split reserved
     * for multimodal positions — text uses identical position across sections. */
    (void)sections;
    for (int h = 0; h < n_heads; h++) {
        float *v = q + h * head_dim;
        for (int i = 0; i < rope_dim; i += 2) {
            float freq = 1.0f / powf(theta, (float)i / (float)rope_dim);
            float angle = (float)pos * freq;
            float c = cosf(angle), s = sinf(angle);
            float x0 = v[i], x1 = v[i + 1];
            v[i] = x0 * c - x1 * s;
            v[i + 1] = x0 * s + x1 * c;
        }
    }
}

void ops_shortconv(float *y, const float *x, const float *w, float *state,
                   int channels, int k)
{
    /* GGUF ssm_conv1d dims (k, channels): ne0=k contiguous taps per channel. */
    for (int c = 0; c < channels; c++) {
        const float *wk = w + c * k;
        float acc = wk[k - 1] * x[c];
        for (int t = 0; t < k - 1; t++) acc += wk[t] * state[c * (k - 1) + t];
        y[c] = acc;
        for (int t = 0; t < k - 2; t++) state[c * (k - 1) + t] = state[c * (k - 1) + t + 1];
        if (k > 1) state[c * (k - 1) + (k - 2)] = x[c];
    }
}

void ops_deltanet_step(float *S, float *o, const float *q, const float *k,
                       const float *v, float g, float beta, int d, float qscale)
{
    /* Delta-rule recurrence (matches KDA/GDN sequential form):
     *   S *= g
     *   u = S^T k
     *   S += k * (beta * (v - u))^T
     *   o = S^T (q * qscale)
     */
    for (int i = 0; i < d; i++)
        for (int j = 0; j < d; j++) S[i * d + j] *= g;

    float u[256];
    for (int j = 0; j < d; j++) {
        double acc = 0.0;
        for (int i = 0; i < d; i++) acc += (double)S[i * d + j] * (double)k[i];
        u[j] = (float)acc;
    }
    float dv[256];
    for (int j = 0; j < d; j++) dv[j] = beta * (v[j] - u[j]);
    for (int i = 0; i < d; i++)
        for (int j = 0; j < d; j++) S[i * d + j] += k[i] * dv[j];

    for (int j = 0; j < d; j++) {
        double acc = 0.0;
        for (int i = 0; i < d; i++) acc += (double)S[i * d + j] * (double)q[i] * (double)qscale;
        o[j] = (float)acc;
    }
}
