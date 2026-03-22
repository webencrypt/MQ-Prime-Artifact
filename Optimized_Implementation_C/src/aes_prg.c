#include "aes_prg.h"
#include <string.h>
#include <wmmintrin.h> // AES-NI intrinsics

// ==========================================================
// AES-128 Key Expansion Helper Functions
// ==========================================================

// 辅助宏：生成下一轮密钥
// RCON 是轮常数，使用 _mm_aeskeygenassist_si128 生成辅助数据
// 然后通过 shuffle 和 xor 计算出下一轮的 Round Key
static inline __m128i aes_128_key_exp(__m128i key, __m128i keygened) {
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

// 完整的 AES-128 密钥扩展算法
// 将 16字节 userkey 扩展为 11个 128位的 Round Keys (key_schedule)
static void AES_128_Key_Expansion(const uint8_t *userkey, __m128i *key_schedule) {
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

// ==========================================================
// AES-128 Encryption Core (Single Block)
// ==========================================================
static inline void AES_128_Encrypt(__m128i *in, __m128i *out, __m128i *key_schedule) {
    __m128i m = _mm_loadu_si128(in);

    m = _mm_xor_si128(m, key_schedule[0]);
    m = _mm_aesenc_si128(m, key_schedule[1]);
    m = _mm_aesenc_si128(m, key_schedule[2]);
    m = _mm_aesenc_si128(m, key_schedule[3]);
    m = _mm_aesenc_si128(m, key_schedule[4]);
    m = _mm_aesenc_si128(m, key_schedule[5]);
    m = _mm_aesenc_si128(m, key_schedule[6]);
    m = _mm_aesenc_si128(m, key_schedule[7]);
    m = _mm_aesenc_si128(m, key_schedule[8]);
    m = _mm_aesenc_si128(m, key_schedule[9]);
    m = _mm_aesenclast_si128(m, key_schedule[10]);

    _mm_storeu_si128(out, m);
}

// ==========================================================
// PRG Interface Implementation
// ==========================================================

void aes_prg_init(aes_prg_ctx *ctx, const uint8_t *seed, int seed_len) {
    // 1. 准备 Key
    // 如果 seed 不足 16 字节，用 0 填充；如果超过，只取前 16 字节
    // (实际应用中应该先 hash seed 得到 16 字节 key，这里为了性能直接截断)
    uint8_t key[16] = {0};
    if (seed_len >= 16) {
        memcpy(key, seed, 16);
    } else {
        memcpy(key, seed, seed_len);
    }

    // 2. 扩展密钥
    AES_128_Key_Expansion(key, ctx->key_schedule);

    // 3. 初始化计数器 (Counter)
    // 通常做法：前 8 字节来自 seed 的后半部分 (如果有)，后 8 字节为 0
    // 这里简单起见，初始化为全 0
    ctx->ctr_vec = _mm_setzero_si128();

    // 4. 重置缓冲状态
    // 设置为 16 表示缓冲区是空的 (已读完)，下次 read 会触发 generate
    ctx->buffer_pos = 16;
}

void aes_prg_read(aes_prg_ctx *ctx, uint8_t *out, size_t out_len) {
    size_t bytes_generated = 0;

    while (bytes_generated < out_len) {
        // 检查缓冲区是否为空
        if (ctx->buffer_pos == 16) {
            __m128i out_block;

            // AES-CTR: Encrypt(Counter) -> Random Block
            AES_128_Encrypt(&ctx->ctr_vec, &out_block, ctx->key_schedule);

            // 存入缓冲区
            _mm_storeu_si128((__m128i*)ctx->buffer, out_block);

            // 计数器加 1 (64-bit 算术加法)
            // _mm_add_epi64 是 SSE2 指令，将两个 64位整数相加
            // 这里我们只增加低 64 位。对于短时间的 PRG 来说，2^64 次方足够了。
            ctx->ctr_vec = _mm_add_epi64(ctx->ctr_vec, _mm_set_epi64x(0, 1));

            // 重置读取指针
            ctx->buffer_pos = 0;
        }

        // 计算本次能复制多少字节
        size_t available = 16 - ctx->buffer_pos;
        size_t needed = out_len - bytes_generated;
        size_t to_copy = (available < needed) ? available : needed;

        // 复制数据到输出
        memcpy(out + bytes_generated, ctx->buffer + ctx->buffer_pos, to_copy);

        // 更新指针
        ctx->buffer_pos += to_copy;
        bytes_generated += to_copy;
    }
}