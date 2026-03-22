#include "ggm.h"
#include "aes_core.h" // 必须包含，用于 AES_ENC_8 和 HARAKA_ROUND_KEYS
#include "config.h"   // 必须包含，用于 TREE_BUF_SIZE, TREE_DEPTH
#include <wmmintrin.h>
#include <string.h>
#include <stdint.h>

void ggm_expand_all(const uint8_t *root_seed, uint8_t *leaves) {
    // 栈上分配缓冲区，强制 16 字节对齐以支持 SIMD 加载
    // TREE_BUF_SIZE 在 config.h 中定义 (例如 256*16)
    __attribute__((aligned(16))) uint8_t buf1[TREE_BUF_SIZE];
    __attribute__((aligned(16))) uint8_t buf2[TREE_BUF_SIZE];

    uint8_t *curr = buf1;
    uint8_t *next = buf2;

    // 初始化根节点
    memcpy(curr, root_seed, SEED_BYTES);
    int num_nodes = 1;

    // 用于域分离的常量 (Domain Separation Constant)
    // Left = AES(Key, Parent), Right = AES(Key, Parent ^ 1)
    __m128i ONE = _mm_set_epi32(0,0,0,1);

    for (int d = 0; d < TREE_DEPTH; d++) {
        int i = 0;

        // ==========================================================
        // 8路并行循环 (Unrolled Loop for 8-way Parallelism)
        // 每次处理 4 个父节点 -> 生成 8 个子节点 (4左 + 4右)
        // 利用 AES-NI 的流水线隐藏延迟
        // ==========================================================
        for (; i <= num_nodes - 4; i += 4) {
            // 1. 加载 4 个父节点
            __m128i p0 = _mm_load_si128((__m128i*)(curr + i*16));
            __m128i p1 = _mm_load_si128((__m128i*)(curr + (i+1)*16));
            __m128i p2 = _mm_load_si128((__m128i*)(curr + (i+2)*16));
            __m128i p3 = _mm_load_si128((__m128i*)(curr + (i+3)*16));

            // 2. 准备 8 个输入块
            // 左孩子输入 = Parent
            __m128i l0 = p0;
            __m128i l1 = p1;
            __m128i l2 = p2;
            __m128i l3 = p3;

            // 右孩子输入 = Parent XOR 1
            __m128i r0 = _mm_xor_si128(p0, ONE);
            __m128i r1 = _mm_xor_si128(p1, ONE);
            __m128i r2 = _mm_xor_si128(p2, ONE);
            __m128i r3 = _mm_xor_si128(p3, ONE);

            // 3. 并行加密 8 个块 (Fixed-Key PRG)
            // Round 0 (AddRoundKey)
            l0 = _mm_xor_si128(l0, HARAKA_ROUND_KEYS[0]); r0 = _mm_xor_si128(r0, HARAKA_ROUND_KEYS[0]);
            l1 = _mm_xor_si128(l1, HARAKA_ROUND_KEYS[0]); r1 = _mm_xor_si128(r1, HARAKA_ROUND_KEYS[0]);
            l2 = _mm_xor_si128(l2, HARAKA_ROUND_KEYS[0]); r2 = _mm_xor_si128(r2, HARAKA_ROUND_KEYS[0]);
            l3 = _mm_xor_si128(l3, HARAKA_ROUND_KEYS[0]); r3 = _mm_xor_si128(r3, HARAKA_ROUND_KEYS[0]);

            // Rounds 1-9 (AESENC)
            for(int r=1; r<10; r++) {
                // 使用 aes_core.h 中定义的 8路宏
                AES_ENC_8(l0, r0, l1, r1, l2, r2, l3, r3, HARAKA_ROUND_KEYS[r]);
            }

            // Round 10 (AESENCLAST)
            AES_LAST_8(l0, r0, l1, r1, l2, r2, l3, r3, HARAKA_ROUND_KEYS[10]);

            // 4. 存回 Next Buffer
            // 布局: [L0, R0, L1, R1, L2, R2, L3, R3]
            _mm_store_si128((__m128i*)(next + (2*i)*16), l0);
            _mm_store_si128((__m128i*)(next + (2*i+1)*16), r0);

            _mm_store_si128((__m128i*)(next + (2*i+2)*16), l1);
            _mm_store_si128((__m128i*)(next + (2*i+3)*16), r1);

            _mm_store_si128((__m128i*)(next + (2*i+4)*16), l2);
            _mm_store_si128((__m128i*)(next + (2*i+5)*16), r2);

            _mm_store_si128((__m128i*)(next + (2*i+6)*16), l3);
            _mm_store_si128((__m128i*)(next + (2*i+7)*16), r3);
        }

        // ==========================================================
        // 处理剩余节点 (Tail Case)
        // 当 num_nodes 不是 4 的倍数时 (例如第0层 num=1, 第1层 num=2)
        // ==========================================================
        for (; i < num_nodes; i++) {
            __m128i p = _mm_load_si128((__m128i*)(curr + i*16));

            __m128i l = _mm_xor_si128(p, HARAKA_ROUND_KEYS[0]);
            __m128i r = _mm_xor_si128(_mm_xor_si128(p, ONE), HARAKA_ROUND_KEYS[0]);

            for(int r_idx=1; r_idx<10; r_idx++) {
                l = _mm_aesenc_si128(l, HARAKA_ROUND_KEYS[r_idx]);
                r = _mm_aesenc_si128(r, HARAKA_ROUND_KEYS[r_idx]);
            }

            l = _mm_aesenclast_si128(l, HARAKA_ROUND_KEYS[10]);
            r = _mm_aesenclast_si128(r, HARAKA_ROUND_KEYS[10]);

            _mm_store_si128((__m128i*)(next + (2*i)*16), l);
            _mm_store_si128((__m128i*)(next + (2*i+1)*16), r);
        }

        // 交换指针 (Ping-Pong)
        uint8_t *tmp = curr; curr = next; next = tmp;
        num_nodes *= 2;
    }

    // 将最终结果复制到输出数组
    memcpy(leaves, curr, MPC_PARTIES * SEED_BYTES);
}