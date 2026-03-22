#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// ==========================================================
// 参数集自动选择逻辑 (Auto-Selection Logic)
// ----------------------------------------------------------
// 逻辑说明:
// 1. 优先检查 CMake 传入的宏 (PARAM_SET_A/B/C)
// 2. 如果没有定义 (例如在 IDE 中直接点击运行), 默认使用 Set C
// ==========================================================

#if defined(PARAM_SET_A)
#define MQ_Prime_PARAM_SET 1
#elif defined(PARAM_SET_B)
#define MQ_Prime_PARAM_SET 2
#elif defined(PARAM_SET_C)
#define MQ_Prime_PARAM_SET 3
#else
// [Default] 如果未指定, 默认使用性能最强的 Set C
#define MQ_Prime_PARAM_SET 3
#endif

// ==========================================================
// 常量定义
// ==========================================================
#define MQ_Prime_Q 2013265921 // NTT Prime
#define SEED_BYTES 16         // AES-128
#define HASH_BYTES 32         // Output Hash Size (256-bit)

// ==========================================================
// 具体参数映射
// ==========================================================
#if MQ_Prime_PARAM_SET == 1
// Set A (Conservative)
    #define MQ_Prime_N 256
    #define MPC_PARTIES 256
    #define MQ_Prime_TAU 16
    #define TREE_DEPTH 8
    #define NAME_STR "Set A (Conservative, n=256)"

#elif MQ_Prime_PARAM_SET == 2
// Set B (Recommended)
    #define MQ_Prime_N 128
    #define MPC_PARTIES 128
    #define MQ_Prime_TAU 19
    #define TREE_DEPTH 7
    #define NAME_STR "Set B (Recommended, n=128)"

#elif MQ_Prime_PARAM_SET == 3
// Set C (Aggressive/Performance)
#define MQ_Prime_N 64
#define MPC_PARTIES 64
#define MQ_Prime_TAU 11
#define TREE_DEPTH 6
#define NAME_STR "Set C (Performance, n=64)"

#endif

// ==========================================================
// 内存分配辅助宏
// ==========================================================
// 栈上分配的最大缓冲大小 (适应最大 N=256 的情况)
#define MAX_TREE_NODES 256
#define TREE_BUF_SIZE (MAX_TREE_NODES * SEED_BYTES)

#endif // CONFIG_H