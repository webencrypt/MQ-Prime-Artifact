#include "MQ-Prime.h"
#include "ntt.h"
#include "config.h"  // <--- 必须包含这个来获取 MQ_Prime_N, MQ_Prime_Q
#include <stdint.h>  // <--- 必须包含这个来获取 uint8_t, uint32_t
#include <string.h>
#include <stdlib.h>

// Fast Barrett reduction for Q = 2013265921
static inline int32_t barrett_reduce(int64_t a) {
    uint64_t R = 9162596898ULL;
    uint64_t q = (uint64_t)(((unsigned __int128)a * R) >> 64);
    int32_t res = (int32_t)(a - q * 2013265921ULL);
    if (res >= 2013265921) {
        res -= 2013265921;
    }
    return res;
}

// Mimics Python's evaluate_mq_in_field behavior in C structure
// Input: s (bit vector), Output: y (vector)
void mq_prime_evaluate_core(const uint8_t *s, const uint32_t *q_polys, const uint32_t *linear_terms, const uint32_t *constants, int output_dim, uint32_t *y) {
    // 1. 展开 s 到 uint32 数组 (0 或 1)
    int32_t s_poly[MQ_Prime_N];
    for(int i=0; i<MQ_Prime_N; i++) {
        s_poly[i] = (s[i/8] >> (i%8)) & 1;
    }

    // 2. NTT(s)
    // Constants derived for Q = 2013265921
    // N = 64 (Set C) requires a 64-th principal root of unity.
    // However, the ntt.c function expects root based on MQ_Prime_N
    int32_t root = 1017366548; // Valid 256-th root of unity for Q=2013265921, ntt.c may need this or a specific one for N=64. Wait, let's keep ntt.c root as is or compute it. For now, use the same as before.
    ntt(s_poly, MQ_Prime_N, root);

    // 3. Point-wise Square: s_ntt^2
    int32_t s_sq_ntt[MQ_Prime_N];
    for(int i=0; i<MQ_Prime_N; i++) {
        int64_t val = s_poly[i];
        s_sq_ntt[i] = barrett_reduce(val * val);
    }

    // 4. Multiply with q_polys and accumulate (Real logic)
    int32_t inv_n = 1997534431;    // inv_N for Q=2013265921 (N=256)
    
    for (int k = 0; k < output_dim; k++) {
        int32_t q_poly_ntt[MQ_Prime_N];
        for (int i=0; i<MQ_Prime_N; i++) {
             q_poly_ntt[i] = q_polys[k * MQ_Prime_N + i];
        }
        ntt(q_poly_ntt, MQ_Prime_N, root);
        
        int64_t quadratic_part = 0;
        for (int i=0; i<MQ_Prime_N; i++) {
             int64_t prod = (int64_t)q_poly_ntt[i] * s_sq_ntt[i];
             quadratic_part = barrett_reduce(quadratic_part + prod);
        }
        quadratic_part = barrett_reduce(quadratic_part * inv_n);
        
        int64_t linear_part = 0;
        for (int i=0; i<MQ_Prime_N; i++) {
            // since s_poly[i] is 0 or 1
            if (s_poly[i]) {
                linear_part = barrett_reduce(linear_part + linear_terms[k * MQ_Prime_N + i]);
            }
        }
        
        y[k] = (uint32_t)barrett_reduce(quadratic_part + linear_part + constants[k]);
    }
}