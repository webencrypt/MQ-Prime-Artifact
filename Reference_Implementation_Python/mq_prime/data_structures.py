# mq_prime/data_structures.py
from dataclasses import dataclass, field
from typing import List, Dict, Any
import numpy as np
from .parameters import DEFAULT_PARAMS_V3 as params
from .serialization import (
    pack_uint32, pack_bytes_with_len, pack_list_of_bytes,
    unpack_uint32, unpack_bytes_with_len, unpack_list_of_bytes
)


# ... (PublicKey, PrivateKey dataclasses remain the same) ...
@dataclass(frozen=True)
class PublicKey:
    seed_P: bytes
    p: bytes


@dataclass(frozen=True)
class PrivateKey:
    s: bytes
    pk: PublicKey


@dataclass
class SignatureV3:
    salt: bytes
    commitment_hash: bytes
    # proofs 列表现在将包含字节串，而不是字典
    proofs: List[bytes] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """将签名对象完全序列化为紧凑的字节串。"""
        # 1. 写入固定长度的 salt 和 commitment_hash
        buffer = self.salt + self.commitment_hash

        # 2. 打包 proofs 列表 (它是一个字节串列表)
        buffer += pack_list_of_bytes(self.proofs)

        return buffer

    @classmethod
    def from_bytes(cls, sig_bytes: bytes):
        """从字节串完全反序列化为签名对象。"""
        offset = 0

        # 1. 读取 salt 和 commitment_hash
        salt = sig_bytes[offset: offset + params.salt_size]
        offset += params.salt_size
        commitment_hash = sig_bytes[offset: offset + params.hash_digest_size]
        offset += params.hash_digest_size

        # 2. 解包 proofs 列表
        proofs, offset = unpack_list_of_bytes(sig_bytes, offset)

        if offset != len(sig_bytes):
            raise ValueError("反序列化后仍有剩余字节，格式错误！")

        return cls(salt=salt, commitment_hash=commitment_hash, proofs=proofs)

# --- 辅助函数 ---
# 这些函数现在可以移到 data_structures.py 中，因为序列化/反序列化在这里进行
def convert_bytes_to_hex_recursive(obj):
    if isinstance(obj, dict): return {k: convert_bytes_to_hex_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list): return [convert_bytes_to_hex_recursive(elem) for elem in obj]
    if isinstance(obj, bytes): return obj.hex()
    return obj


def convert_hex_to_bytes_recursive(obj):
    if isinstance(obj, dict): return {k: convert_hex_to_bytes_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list): return [convert_hex_to_bytes_recursive(elem) for elem in obj]
    if isinstance(obj, str):
        try:
            # 简单的启发式方法来判断字符串是否为十六进制
            if len(obj) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in obj):
                return bytes.fromhex(obj)
        except (ValueError, TypeError):
            pass
    return obj