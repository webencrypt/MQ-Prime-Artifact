# mq_prime/hash_utils.py

import hashlib
from typing import Union


def shake_128_xof(seed: bytes, length: int) -> bytes:
    """
    使用 SHAKE128 从一个种子生成指定长度的可扩展输出 (XOF)。
    这是生成随机磁带和长种子的正确函数。
    """
    if not isinstance(seed, bytes):
        raise TypeError("Input seed for shake_128_xof must be bytes")
    return hashlib.shake_128(seed).digest(length)


def H(*args: Union[bytes, str, int, list, tuple]) -> bytes:
    """
    一个固定的、32字节输出的哈希函数 (SHA-256)，用于承诺和挑战。
    """
    hasher = hashlib.sha256()

    # 将所有输入参数统一转换成字节串并更新哈希状态
    # 使用一个简单的递归函数来处理嵌套列表/元组
    def update_hash(data):
        if isinstance(data, (list, tuple)):
            for item in data:
                update_hash(item)
        elif isinstance(data, bytes):
            hasher.update(data)
        elif isinstance(data, str):
            hasher.update(data.encode('utf-8'))
        elif isinstance(data, int):
            # 将整数转换为一个标准长度的字节表示，以避免歧义
            hasher.update(data.to_bytes(8, 'big', signed=True))
        else:
            raise TypeError(f"Unsupported type for hashing: {type(data)}")

    update_hash(args)
    return hasher.digest()


def derive_from_seed(seed: bytes, index: int, length: int) -> bytes:
    """
    使用 SHAKE128 从一个种子和索引中确定性地派生出指定长度的字节串。
    索引确保从同一个种子可以派生出不同的输出。
    """
    # 将索引打包成一个固定长度的字节串，以避免歧义
    index_bytes = index.to_bytes(4, 'big')
    # 哈希 (seed || index) 来生成输出
    return shake_128_xof(seed + index_bytes, length)