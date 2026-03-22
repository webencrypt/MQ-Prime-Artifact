#ifndef NTT_H
#define NTT_H

#include <stdint.h>

// 修改模数为 NTT 友好的素数: 2013265921
// 2013265921 = 15 * 2^27 + 1
#define Q 2013265921

void ntt(int32_t* poly, int n, int32_t root);
void inv_ntt(int32_t* poly, int n, int32_t inv_root, int32_t inv_n);

#endif // NTT_H