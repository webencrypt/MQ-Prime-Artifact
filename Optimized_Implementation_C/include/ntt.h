#ifndef NTT_H
#define NTT_H

#include <stdint.h> // <--- 确保包含这个

// 函数声明
void ntt(int32_t* poly, int n, int32_t root);
void inv_ntt(int32_t* poly, int n, int32_t inv_root, int32_t inv_n);

#endif // NTT_H