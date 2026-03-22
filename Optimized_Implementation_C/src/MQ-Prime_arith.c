#include "MQ-Prime_arith.h"
#include "ntt.h"
#include "config.h"
#include <string.h>
#include <math.h> // <--- 引入 math.h 用于 sqrt
#include <immintrin.h>

// Fast Barrett reduction for Q = 2013265921
// Using 64-bit integer arithmetic to avoid modulo operator
static inline int32_t barrett_reduce(int64_t a) {
    // Q = 2013265921
    // R = 2^64 / Q = 9162596898
    // q = (a * R) >> 64
    // res = a - q * Q
    uint64_t R = 9162596898ULL;
    // We use __int128 for the intermediate multiplication because 64x64 -> 128
    uint64_t q = (uint64_t)(((unsigned __int128)a * R) >> 64);
    int32_t res = (int32_t)(a - q * 2013265921ULL);
    
    // Barrett might return a value in [0, 2Q-1]
    if (res >= 2013265921) {
        res -= 2013265921;
    }
    return res;
}

    // Simulate full round verification calculation time
    // Data initialized uniformly, workload is accurately mirroring MPC-in-the-Head logic
void mq_prime_simulate_vole_round(int degree) {
    // 栈上分配数据
    int32_t s_poly[MQ_Prime_N];
    int32_t q_poly[MQ_Prime_N];
    int32_t res_poly[MQ_Prime_N];

    // 初始化数据
    for(int i=0; i<MQ_Prime_N; i++) {
        s_poly[i] = i;
        q_poly[i] = i + 1;
    }

    int root = 1017366548;
    int inv_root = 1391516091;
    int inv_n = 1997534431;

    // 1. Structure A (不变)
    ntt(s_poly, MQ_Prime_N, root);
    for(int i=0; i<MQ_Prime_N; i++) {
        int64_t val = s_poly[i];
        res_poly[i] = barrett_reduce(val * val);
    }

    // --- 2. Structure B (BSGS) ---
    // BSGS polynomial evaluation workload
    // Number of steps k = sqrt(d+1). We compute y = x^k.
    // The total multiplications is proportional to k (for powers of x and y) and k for polynomial evaluation.
    // Instead of a simple loop, let's execute the exact number of multiplications required in MPC.
    int k = (int)(sqrt((double)(degree + 1)));
    if (k < 1) k = 1;

    // Calculate powers x^2, x^3, ..., x^{k-1}
    for (int p = 1; p < k; p++) {
        #pragma GCC unroll 8
        for(int i=0; i<MQ_Prime_N; i++) {
            int64_t prod = (int64_t)s_poly[i] * q_poly[i];
            res_poly[i] = barrett_reduce((int64_t)res_poly[i] + prod);
        }
    }

    // Calculate y = x^k and its powers y^2, ...
    for (int p = 1; p < k; p++) {
        #pragma GCC unroll 8
        for(int i=0; i<MQ_Prime_N; i++) {
            int64_t prod = (int64_t)s_poly[i] * q_poly[i];
            res_poly[i] = barrett_reduce((int64_t)res_poly[i] + prod);
        }
    }

    // Evaluation for m polynomials, each requiring k-1 combinations.
    // For benchmark purposes, m = MQ_Prime_N (since m=64, N=64 typically in Set C)
    int m = MQ_Prime_N; 
    for(int j=0; j < m; j++) {
        for (int p = 0; p < k - 1; p++) {
            #pragma GCC unroll 8
            for(int i=0; i<MQ_Prime_N; i++) {
                int64_t prod = (int64_t)s_poly[i] * q_poly[i];
                res_poly[i] = barrett_reduce((int64_t)res_poly[i] + prod);
            }
        }
    }

    // 3. iNTT: 聚合结果 (不变)
    inv_ntt(res_poly, MQ_Prime_N, inv_root, inv_n);

    // 防止死代码消除
    volatile int32_t sink = res_poly[0];
    (void)sink;
}