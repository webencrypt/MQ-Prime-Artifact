#ifndef AES_CORE_H
#define AES_CORE_H

#include <stdint.h>
#include <wmmintrin.h>

// 真实场景：每个用户/每轮可能都有不同的 Key
// 但为了性能，通常系统参数（如哈希常数）是预计算的
extern __m128i HARAKA_ROUND_KEYS[11]; // 用于哈希的固定常数

// 初始化哈希常数
void aes_global_init(void);

// 标准 AES-128 密钥扩展 (真实计算)
void AES_128_Key_Expansion(const uint8_t *userkey, __m128i *key_schedule);

// 8路并行加密宏 (保持不变，这是最高效的)
#define AES_ENC_8(m0, m1, m2, m3, m4, m5, m6, m7, k) \
    m0 = _mm_aesenc_si128(m0, k); \
    m1 = _mm_aesenc_si128(m1, k); \
    m2 = _mm_aesenc_si128(m2, k); \
    m3 = _mm_aesenc_si128(m3, k); \
    m4 = _mm_aesenc_si128(m4, k); \
    m5 = _mm_aesenc_si128(m5, k); \
    m6 = _mm_aesenc_si128(m6, k); \
    m7 = _mm_aesenc_si128(m7, k);

#define AES_LAST_8(m0, m1, m2, m3, m4, m5, m6, m7, k) \
    m0 = _mm_aesenclast_si128(m0, k); \
    m1 = _mm_aesenclast_si128(m1, k); \
    m2 = _mm_aesenclast_si128(m2, k); \
    m3 = _mm_aesenclast_si128(m3, k); \
    m4 = _mm_aesenclast_si128(m4, k); \
    m5 = _mm_aesenclast_si128(m5, k); \
    m6 = _mm_aesenclast_si128(m6, k); \
    m7 = _mm_aesenclast_si128(m7, k);

#endif