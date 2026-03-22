#include "aes_hash.h"
#include "aes_core.h"
#include <wmmintrin.h>
#include <string.h>
#include <stdint.h>

// 内部置换函数 (Permutation): 运行一次 AES-NI
static inline __m128i aes_permute(__m128i state) {
    // Davies-Meyer-like permutation: AES_k(m) ^ m
    // 但为了纯粹的速度，我们可以只用 AES 本身作为置换，这也是安全的
    // state = _mm_xor_si128(state, HARAKA_ROUND_KEYS[0]);
    // for(int i=1; i<10; i++) state = _mm_aesenc_si128(state, HARAKA_ROUND_KEYS[i]);
    // state = _mm_aesenclast_si128(state, HARAKA_ROUND_KEYS[10]);
    // return state;

    // 更高效的 Haraka v2 风格置换
    __m128i tmp = state;
    for(int i=0; i<5; ++i) { // 5 rounds
        tmp = _mm_aesenc_si128(tmp, HARAKA_ROUND_KEYS[i*2]);
        tmp = _mm_aesenc_si128(tmp, HARAKA_ROUND_KEYS[i*2+1]);
    }
    return _mm_xor_si128(tmp, state);
}

// ==========================================================
// Sponge Construction for Hashing
// Rate (r) = 128 bits, Capacity (c) = 128 bits
// State = r || c
// ==========================================================
void aes_hash(const uint8_t *data, size_t len, uint8_t *out) {
    // 1. 初始化 256-bit 状态 (State)
    __m128i state_r = _mm_setzero_si128(); // Rate part
    __m128i state_c = _mm_setzero_si128(); // Capacity part

    // 2. 吸收阶段 (Absorbing)
    size_t processed = 0;
    while (processed < len) {
        // 准备 128-bit 消息块
        __m128i block = _mm_setzero_si128();
        size_t to_copy = (len - processed < 16) ? (len - processed) : 16;
        memcpy(&block, data + processed, to_copy);

        // 吸收: state_r ^= block
        state_r = _mm_xor_si128(state_r, block);

        // 置换 (Permutation): 搅乱整个 256-bit 状态
        // 我们用两次独立的 AES 置换来处理 Rate 和 Capacity
        state_r = aes_permute(state_r);
        state_c = aes_permute(state_c);
        // 然后再混合一下
        state_c = _mm_xor_si128(state_c, state_r);

        processed += 16;
    }

    // 3. 挤出阶段 (Squeezing)
    // 第一次置换
    state_r = aes_permute(state_r);
    state_c = aes_permute(state_c);
    state_c = _mm_xor_si128(state_c, state_r);

    // 输出前 128 bits
    _mm_storeu_si128((__m128i*)out, state_r);

    // 第二次置换
    state_r = aes_permute(state_r);
    state_c = aes_permute(state_c);
    state_c = _mm_xor_si128(state_c, state_r);

    // 输出后 128 bits
    _mm_storeu_si128((__m128i*)(out + 16), state_r);
}