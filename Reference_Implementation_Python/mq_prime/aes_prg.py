# mq_prime/aes_prg.py
from Crypto.Cipher import AES
from Crypto.Util import Counter

# 全局计数器 (用于性能剖析)
AES_OPS_COUNT = 0


def reset_aes_count():
    global AES_OPS_COUNT
    AES_OPS_COUNT = 0


def get_aes_count():
    return AES_OPS_COUNT


class AES_PRG:
    def __init__(self, seed: bytes):
        """
        用一个种子初始化 AES-CTR 模式的 PRG。
        支持 16 (AES-128), 24 (AES-192), 32 (AES-256) 字节的种子。
        """
        # ▼▼▼ 修改：允许 16, 24, 32 字节的种子 ▼▼▼
        if len(seed) not in (16, 24, 32):
            raise ValueError(f"Seed must be 16, 24, or 32 bytes for AES. Got {len(seed)} bytes.")
        # ▲▲▲

        self.cipher = AES.new(seed, AES.MODE_CTR, counter=Counter.new(128))

    def read(self, n_bytes: int) -> bytes:
        """
        从 PRG 中读取指定数量的伪随机字节。
        """
        global AES_OPS_COUNT

        # AES 块大小固定为 16 字节 (无论密钥长度是多少)
        num_blocks = (n_bytes + 15) // 16
        AES_OPS_COUNT += num_blocks

        return self.cipher.encrypt(b'\x00' * n_bytes)