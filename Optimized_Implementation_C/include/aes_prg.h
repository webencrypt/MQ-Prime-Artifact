#ifndef AES_PRG_H
#define AES_PRG_H

#include <stdint.h>
#include <wmmintrin.h> // AES-NI
#include "config.h"

// AES-CTR 模式 PRG 上下文
typedef struct {
    __m128i key_schedule[11]; // AES-128 (10 rounds)
    __m128i ctr_vec;          // 当前计数器
    uint8_t buffer[16];       // 缓冲块
    int buffer_pos;           // 当前缓冲位置
} aes_prg_ctx;

// 初始化 PRG
void aes_prg_init(aes_prg_ctx *ctx, const uint8_t *seed, int seed_len);

// 获取随机字节
void aes_prg_read(aes_prg_ctx *ctx, uint8_t *out, size_t out_len);

#endif