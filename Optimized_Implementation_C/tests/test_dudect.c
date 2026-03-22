#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <x86intrin.h> // 用于 rdtsc 测速

#include "config.h"
#include "aes_core.h"
#include "aes_hash.h"
#include "ggm.h"
#include "MQ-Prime_arith.h"

// =========================================================
// 统计学工具 (Welford's Online Algorithm)
// =========================================================
typedef struct {
    double mean;
    double m2;
    uint64_t count;
} t_context;

void t_push(t_context *ctx, double x) {
    ctx->count++;
    double delta = x - ctx->mean;
    ctx->mean += delta / ctx->count;
    double delta2 = x - ctx->mean;
    ctx->m2 += delta * delta2;
}

double t_compute(t_context *ctx) {
    if (ctx->count < 2) return 0.0;
    return ctx->m2 / (ctx->count - 1);
}

// 计算两个集合的 T-value
double t_test(t_context *ctx1, t_context *ctx2) {
    double var1 = t_compute(ctx1);
    double var2 = t_compute(ctx2);
    double num = ctx1->mean - ctx2->mean;
    double den = sqrt(var1 / ctx1->count + var2 / ctx2->count);
    if (den == 0) return 0.0;
    return num / den;
}

// =========================================================
// 被测函数 (The Victim)
// =========================================================
// 这里把 Sign 的全流程封装起来
void victim_function(uint8_t *seed, uint8_t *leaves_buf, uint8_t *hash_buf) {
    // 1. GGM Expansion (Input depends on seed)
    ggm_expand_all(seed, leaves_buf);

    // 2. Hash (Input depends on leaves)
    // 模拟几轮哈希
    for(int i=0; i<MPC_PARTIES; i++) {
        aes_hash(leaves_buf + i*SEED_BYTES, SEED_BYTES, hash_buf);
    }

    // 3. Arithmetic (Simulation)
    mq_prime_simulate_vole_round(6);

    // 防止优化
    volatile uint8_t sink = hash_buf[0];
    (void)sink;
}

// =========================================================
// Main Loop
// =========================================================
int main() {
    printf("========================================================\n");
    printf("  mq_prime Constant-Time Verification (Dudect)\n");
    printf("  Config: %s\n", NAME_STR);
    printf("  Target: t-value should stay within [-4.5, 4.5]\n");
    printf("========================================================\n");

    aes_global_init();

    t_context ctx_fix = {0};
    t_context ctx_rand = {0};

    // 准备数据
    uint8_t fix_seed[SEED_BYTES];
    uint8_t rand_seed[SEED_BYTES];
    memset(fix_seed, 0, SEED_BYTES);

    // 预分配内存
    uint8_t *leaves = malloc(MPC_PARTIES * SEED_BYTES);
    uint8_t hash_out[HASH_BYTES];

    srand(time(NULL));

    // 热身 (Warmup)
    for(int i=0; i<1000; i++) victim_function(fix_seed, leaves, hash_out);

    printf("Running measurements... (Press Ctrl+C to stop)\n\n");
    printf("   Iterations |   T-Value  | Status \n");
    printf("--------------|------------|--------\n");

    uint64_t iterations = 0;
    while (iterations < 1000000) { // 跑 100万次
        for(int i=0; i<1000; i++) { // 批处理
            // 生成随机种子
            for(int b=0; b<SEED_BYTES; b++) rand_seed[b] = rand() & 0xFF;

            // 随机选择跑 Fix 还是 Rand (模拟抛硬币)
            // 这样可以消除系统负载波动的影响
            int coin = rand() % 2;

            uint64_t start = __rdtsc(); // 读取 CPU 周期
            if (coin == 0) {
                victim_function(fix_seed, leaves, hash_out);
            } else {
                victim_function(rand_seed, leaves, hash_out);
            }
            uint64_t end = __rdtsc();

            // 记录数据 (简单的异常值过滤: > 2倍均值通常是中断)
            double cycles = (double)(end - start);
            if (cycles < 1000000) { // 过滤明显的上下文切换噪音
                if (coin == 0) t_push(&ctx_fix, cycles);
                else t_push(&ctx_rand, cycles);
            }
        }
        iterations += 1000;

        // 每 10万次打印一次结果
        if (iterations % 50000 == 0) {
            double t = t_test(&ctx_fix, &ctx_rand);
            printf("  %9lu   |  %8.4f  | %s\n",
                   iterations, t,
                   (fabs(t) < 4.5) ? "PASS" : "FAIL <<<<<");
        }
    }

    free(leaves);
    return 0;
}