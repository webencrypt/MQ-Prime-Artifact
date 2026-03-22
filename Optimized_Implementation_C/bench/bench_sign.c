#include <stdio.h>
#include <time.h>
#include <stdlib.h> // 包含 malloc 以便在 GGM 中使用

#include "config.h"
#include "aes_core.h"
#include "aes_hash.h"
#include "ggm.h"
#include "MQ-Prime_arith.h"

#include <omp.h>

int main() {
    printf("========================================================\n");
    printf("  mq_prime Final Paper Benchmark (Full)\n");
    printf("  Config: %s\n", NAME_STR);
    printf("========================================================\n");

    aes_global_init(); // 初始化 AES 硬件常数

    double start, end;

    // ========================================================
    // A: 标准性能基准测试
    // ========================================================
    printf("\n--- Part A: Overall Performance Benchmark ---\n");

    // 1. GGM Tree (Stack Allocated, 8-way Parallel)
    printf("[1] GGM Tree Expansion...\n");
    // 使用栈分配
    uint8_t root_seed[SEED_BYTES] = {0};

    int iter_perf = 50000;
    start = omp_get_wtime();
    #pragma omp parallel for
    for(int i=0; i<iter_perf; i++) {
        uint8_t leaves[TREE_BUF_SIZE];
        ggm_expand_all(root_seed, leaves);
    }
    end = omp_get_wtime();
    double t_ggm = (end-start)/iter_perf * 1000.0;
    printf(" -> %.6f ms / tree\n", t_ggm);

    // 2. Hash & Merkle (AES-Hash)
    printf("[2] Commitment & Merkle...\n");
    int ops_hash = 2 * MPC_PARTIES; // 约 2N 次哈希

    start = omp_get_wtime();
    #pragma omp parallel for
    for(int i=0; i<iter_perf * ops_hash; i++) {
        uint8_t hash_out[HASH_BYTES];
        uint8_t local_leaves[TREE_BUF_SIZE] = {0};
        aes_hash(local_leaves, 64, hash_out);
    }
    end = omp_get_wtime();
    double t_hash_single = (end-start)/(iter_perf*ops_hash) * 1000.0;
    double t_merkle = t_hash_single * ops_hash;
    printf(" -> %.6f ms / hash\n", t_hash_single);
    printf(" -> %.6f ms / Merkle tree\n", t_merkle);

    // 3. Arithmetic
    printf("[3] VOLE Arithmetic (d=6)...\n");
    int iter_arith_base = 100000;
    start = omp_get_wtime();
    #pragma omp parallel for
    for(int i=0; i<iter_arith_base; i++) {
        mq_prime_simulate_vole_round(6);
    }
    end = omp_get_wtime();
    double t_arith = (end-start)/iter_arith_base * 1000.0;
    printf(" -> %.6f ms / round\n", t_arith);

    // --- Final Tally (总性能) ---
    double t_round = t_ggm + t_merkle + t_arith;
    double t_total = t_round * MQ_Prime_TAU;

    printf("\n========================================================\n");
    printf("  FINAL ESTIMATED SIGN TIME: %.4f ms\n", t_total);
    printf("========================================================\n");

    // ========================================================
    // B: 算术成本 vs. 度数 d 的基准测试
    // ========================================================
    printf("\n--- Part B: Arithmetic Cost vs. Degree d ---\n");

    int iter_arith_sweep = 10000; // 迭代次数可以少一点，因为要跑多轮

    printf("  Degree (d) | Time per Round (ms)\n");
    printf("  -----------|---------------------\n");

    for (int d = 2; d <= 20; d += 2) {
        start = omp_get_wtime();
        #pragma omp parallel for
        for(int i=0; i<iter_arith_sweep; i++) {
            mq_prime_simulate_vole_round(d); // 调用带参数的函数
        }
        end = omp_get_wtime();
        double time_per_round = (end - start) / iter_arith_sweep * 1000.0;
        printf("     %2d      |      %.6f\n", d, time_per_round);
    }

    printf("\n========================================================\n");
    printf("  Benchmark Complete.\n");
    printf("========================================================\n");

    return 0;
}