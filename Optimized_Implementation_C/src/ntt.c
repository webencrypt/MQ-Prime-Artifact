#include "ntt.h"
#include "config.h"
#include <stdint.h>
// #include <stdlib.h> <--- 彻底移除 stdlib，不再需要堆分配

// 快速模乘 (a * b) % Q
static inline int32_t mul_mod(int32_t a, int32_t b) {
    return (int32_t)(((__int128)a * b) % MQ_Prime_Q);
}

// 递归核心 (Zero-Malloc 版)
void ntt_recursive(int32_t* poly, int n, int32_t root) {
    if (n == 1) return;

    // 【极速优化】: 使用栈上数组 (Variable Length Arrays)
    // 这里的 n 最大为 128 或 256，占用空间极小 (< 1KB)，非常安全。
    // 这一步消除了所有的 malloc/free 系统开销。
    int32_t even[n / 2];
    int32_t odd[n / 2];

    // 分组
    for (int i = 0; i < n / 2; i++) {
        even[i] = poly[2 * i];
        odd[i]  = poly[2 * i + 1];
    }

    // 递归
    int32_t root_sq = mul_mod(root, root);
    ntt_recursive(even, n / 2, root_sq);
    ntt_recursive(odd,  n / 2, root_sq);

    // 蝴蝶操作
    int32_t w = 1;
    for (int k = 0; k < n / 2; k++) {
        int32_t t = mul_mod(w, odd[k]);
        int32_t e = even[k];

        // 优化取模逻辑
        int64_t val_plus = (int64_t)e + t;
        // 如果 val_plus < Q，直接使用，避免昂贵的 % 指令 (分支预测优化)
        // 但为了代码简洁和绝对安全，这里仍用 %，编译器会自动优化常数模除
        poly[k] = (int32_t)(val_plus % MQ_Prime_Q);

        int64_t val_minus = (int64_t)e - t;
        // 快速处理负数模
        if (val_minus < 0) {
            val_minus += MQ_Prime_Q; // 尝试加一次通常就正了
            if (val_minus < 0) val_minus = (val_minus % MQ_Prime_Q) + MQ_Prime_Q;
        } else {
            if (val_minus >= MQ_Prime_Q) val_minus %= MQ_Prime_Q;
        }
        poly[k + n/2] = (int32_t)val_minus;

        w = mul_mod(w, root);
    }

    // 不需要 free! 函数返回时自动释放。
}

// 外部接口
void ntt(int32_t* poly, int n, int32_t root) {
    ntt_recursive(poly, n, root);
}

void inv_ntt(int32_t* poly, int n, int32_t inv_root, int32_t inv_n) {
    ntt_recursive(poly, n, inv_root);
    for (int i = 0; i < n; i++) {
        poly[i] = mul_mod(poly[i], inv_n);
    }
}