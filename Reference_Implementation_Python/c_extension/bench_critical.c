#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <wmmintrin.h> // AES-NI intrinsics

// 编译命令: gcc -O3 -maes -o bench_critical bench_critical.c

// 1. 增加到 5亿次，确保运行时间足够长，能被计时器捕捉到
#define BENCH_ITERATIONS 500000000

// 2. 您的 mq_primeSign 真实需求次数
#define ACTUAL_MQ_Prime_OPS 927018

__m128i key_schedule[11];

void AES_128_Key_Expansion(const uint8_t *userkey, __m128i *key_schedule) {
    __m128i x = _mm_loadu_si128((__m128i*)userkey);
    key_schedule[0] = x;
    for(int i=1; i<11; i++) key_schedule[i] = x;
}

// 强制内联
__attribute__((always_inline))
inline void AES_128_Encrypt(__m128i *in, __m128i *out, __m128i *key_schedule) {
    __m128i m = _mm_loadu_si128(in);
    m = _mm_xor_si128(m, key_schedule[0]);
    for(int i=1; i<10; i++) m = _mm_aesenc_si128(m, key_schedule[i]);
    m = _mm_aesenclast_si128(m, key_schedule[10]);
    _mm_storeu_si128(out, m);
}

int main() {
    printf("==================================================\n");
    printf("  mq_primeSign Critical Path Micro-benchmark (C/AES-NI)\n");
    printf("==================================================\n");
    printf("Benchmarking with %d iterations...\n", BENCH_ITERATIONS);

    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t plaintext[16] = {0};

    AES_128_Key_Expansion(key, key_schedule);

    clock_t start = clock();

    __m128i in_blk = _mm_loadu_si128((__m128i*)plaintext);
    __m128i out_blk;

    // 核心循环
    for (int i = 0; i < BENCH_ITERATIONS; i++) {
        // 模拟输入变化，防止循环被折叠
        in_blk = _mm_xor_si128(in_blk, _mm_set1_epi32(i));
        AES_128_Encrypt(&in_blk, &out_blk, key_schedule);
        // 累加结果，防止死代码消除
        in_blk = _mm_xor_si128(in_blk, out_blk);
    }

    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

    // ▼▼▼ 防优化关键代码：打印最终结果，强制编译器进行计算 ▼▼▼
    uint8_t result[16];
    _mm_storeu_si128((__m128i*)result, in_blk);
    printf("[Debug] Final computation check: %02x (prevents optimization)\n", result[0]);
    // ▲▲▲▲▲▲

    // 计算吞吐量
    double ops_per_sec = (double)BENCH_ITERATIONS / time_spent;

    printf("--------------------------------------------------\n");
    printf("Time elapsed (Benchmark): %.4f seconds\n", time_spent);
    printf("CPU Throughput:           %.2f Million AES ops/sec\n", ops_per_sec / 1000000.0);
    printf("--------------------------------------------------\n");

    // 估算 mq_primeSign 真实潜力
    double estimated_ms = (double)ACTUAL_MQ_Prime_OPS / ops_per_sec * 1000.0;

    printf("Actual mq_primeSign Ops:     %d (Sign + Verify)\n", ACTUAL_MQ_Prime_OPS);
    printf("Estimated Critical Path:  %.4f ms\n", estimated_ms);
    printf("==================================================\n");

    return 0;
}