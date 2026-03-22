#include "aes_core.h"
#include <wmmintrin.h>

__m128i HARAKA_ROUND_KEYS[11];

// 辅助函数：生成下一轮密钥
static inline __m128i aes_128_key_exp(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

// 真实的密钥扩展
void AES_128_Key_Expansion(const uint8_t *userkey, __m128i *key_schedule) {
    key_schedule[0] = _mm_loadu_si128((const __m128i*)userkey);
    key_schedule[1]  = aes_128_key_exp(key_schedule[0], _mm_aeskeygenassist_si128(key_schedule[0], 0x01));
    key_schedule[2]  = aes_128_key_exp(key_schedule[1], _mm_aeskeygenassist_si128(key_schedule[1], 0x02));
    key_schedule[3]  = aes_128_key_exp(key_schedule[2], _mm_aeskeygenassist_si128(key_schedule[2], 0x04));
    key_schedule[4]  = aes_128_key_exp(key_schedule[3], _mm_aeskeygenassist_si128(key_schedule[3], 0x08));
    key_schedule[5]  = aes_128_key_exp(key_schedule[4], _mm_aeskeygenassist_si128(key_schedule[4], 0x10));
    key_schedule[6]  = aes_128_key_exp(key_schedule[5], _mm_aeskeygenassist_si128(key_schedule[5], 0x20));
    key_schedule[7]  = aes_128_key_exp(key_schedule[6], _mm_aeskeygenassist_si128(key_schedule[6], 0x40));
    key_schedule[8]  = aes_128_key_exp(key_schedule[7], _mm_aeskeygenassist_si128(key_schedule[7], 0x80));
    key_schedule[9]  = aes_128_key_exp(key_schedule[8], _mm_aeskeygenassist_si128(key_schedule[8], 0x1b));
    key_schedule[10] = aes_128_key_exp(key_schedule[9], _mm_aeskeygenassist_si128(key_schedule[9], 0x36));
}

void aes_global_init(void) {
    // 初始化用于 Hash 的常量 (模拟 Haraka 常数)
    for(int i=0; i<11; i++) {
        HARAKA_ROUND_KEYS[i] = _mm_set_epi32(i, i+1, i+2, i+3);
    }
}