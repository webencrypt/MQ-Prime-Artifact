#include "ntt.h"
#include <stdio.h>

// 辅助函数：模乘 (a * b) % Q
int64_t multiply(int64_t a, int64_t b) {
    return (a * b) % Q;
}

// Cooley-Tukey NTT 递归实现
void ntt_recursive(int32_t* poly, int n, int32_t root) {
    if (n == 1) return;

    // 简单的递归实现（非原地，需要栈空间，对于N=512是安全的）
    // 为了保持简单性，这里使用变长数组 (VLA)
    // 如果编译器不支持 C99，可能需要 malloc，但在 GCC/MinGW 下通常没问题
    int32_t even[n / 2];
    int32_t odd[n / 2];
    for (int i = 0; i < n / 2; i++) {
        even[i] = poly[2 * i];
        odd[i] = poly[2 * i + 1];
    }

    int32_t root_squared = (int32_t)multiply(root, root);
    ntt_recursive(even, n / 2, root_squared);
    ntt_recursive(odd, n / 2, root_squared);

    int32_t w = 1;
    for (int k = 0; k < n / 2; k++) {
        int64_t t = multiply(w, odd[k]);
        int64_t e = even[k];
        poly[k] = (e + t) % Q;
        poly[k + n / 2] = (e - t + Q) % Q;
        w = (int32_t)multiply(w, root);
    }
}

// 接口函数：NTT
void ntt(int32_t* poly, int n, int32_t root) {
    ntt_recursive(poly, n, root);
}

// 接口函数：逆 NTT
void inv_ntt(int32_t* poly, int n, int32_t inv_root, int32_t inv_n) {
    // 逆 NTT 实际上就是用 inv_root 做 NTT，最后乘上 inv_n
    ntt_recursive(poly, n, inv_root);

    for (int i = 0; i < n; i++) {
        poly[i] = (int32_t)multiply(poly[i], inv_n);
    }
}