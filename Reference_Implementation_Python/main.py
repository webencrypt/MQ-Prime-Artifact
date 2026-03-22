# main.py


import time
import os
import json
import numpy as np
from hashlib import sha256
import secrets

# 复用 v2 的确定性 PRNG 设置
import random

random.SystemRandom = lambda: det_prng

from mq_prime.faest_framework import mq_prime_keygen_v3, sign_v3, verify_v3
from mq_prime.data_structures import SignatureV3


# 1. 创建一个继承自 random.Random 的、功能完整的确定性PRNG类
class SeededRandom(random.Random):
    def __init__(self, seed):
        # 使用 sha256 来确保任何种子都能生成一个高质量的内部状态
        # 调用父类的构造函数，并传入一个整数作为种子
        super().__init__(int.from_bytes(sha256(seed).digest(), 'big'))

    def urandom(self, n):
        # 为 os.urandom 提供一个 bytes 接口
        if n == 0:
            return b''
        return self.getrandbits(n * 8).to_bytes(n, 'big')

det_prng = SeededRandom(b"mq-prime-true-deterministic-seed-final")
os.urandom = det_prng.urandom



def run_v3_demo():
    print("=" * 60)
    print(" mq-prime-over-FAEST-style 演示 (v3.7 全二进制序列化)") # <--- Update title
    print("=" * 60)

    # --- 1. 密钥生成 ---
    print("\n[1] 正在生成密钥对...")
    start_time = time.time()
    pk, sk = mq_prime_keygen_v3()
    end_time = time.time()
    print("    密钥生成成功！")
    print(f"    > 耗时: {end_time - start_time:.4f} 秒")

    # --- 2. 准备消息 ---
    message = b"This is a test message for mq-prime 3.0 FAEST-style scheme."
    print("\n[2] 待签名的消息:")
    print(f"    - 消息内容: '{message.decode()}'")

    # --- 3. 生成签名 ---
    print("\n[3] 正在使用私钥对消息进行签名...")
    start_time = time.time()
    signature = sign_v3(sk, message)
    end_time = time.time()

    # ▼▼▼ 使用新的二进制序列化 ▼▼▼
    sig_bytes = signature.to_bytes()

    print("    签名生成成功！")
    print(f"    - 签名 salt: {signature.salt.hex()}")
    print(f"    - 签名 commitment_hash: {signature.commitment_hash.hex()}")
    # ▼▼▼ 观察新的、更小的签名大小 ▼▼▼
    print(f"    - 签名 proofs 长度 (二进制序列化后): {len(sig_bytes)} 字节")
    print(f"    > 耗时: {end_time - start_time:.4f} 秒")

    # --- 4. 验证签名 ---
    print("\n[4] 正在验证签名...")

    # ▼▼▼ 使用新的二进制反序列化 ▼▼▼
    signature_reloaded = SignatureV3.from_bytes(sig_bytes)

    start_time = time.time()
    is_valid = verify_v3(pk, message, signature_reloaded)
    end_time = time.time()

    print(f"    > 耗时: {end_time - start_time:.4f} 秒")
    if is_valid:
        print("    ✅ 验证成功！签名是有效的。")
    else:
        print("    ❌ 验证失败！签名是无效的。")

    print("\n" + "=" * 60)
    print(" 3.0 版本演示完成")
    print("=" * 60)


if __name__ == "__main__":
    run_v3_demo()

