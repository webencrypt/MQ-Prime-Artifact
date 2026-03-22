#ifndef AES_HASH_H
#define AES_HASH_H

#include <stdint.h>
#include <stddef.h>

// 初始化 AES 哈希所需的常量
void aes_hash_init(void);

// 使用 AES-NI 计算哈希
// 输入: data (任意长度), len
// 输出: out (32字节 / 256-bit)
void aes_hash(const uint8_t *data, size_t len, uint8_t *out);

#endif