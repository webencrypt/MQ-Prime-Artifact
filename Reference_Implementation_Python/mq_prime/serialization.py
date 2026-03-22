# mq_prime/serialization.py

import numpy as np
from typing import List

# --- 写入/打包 (Packing) 函数 ---

def pack_uint32(val: int) -> bytes:
    """将一个整数打包成4字节大端序。"""
    return val.to_bytes(4, 'big')

def pack_bytes_with_len(data: bytes) -> bytes:
    """打包一个字节串: 写入4字节长度，然后写入数据。"""
    if data is None:
        return pack_uint32(0)
    return pack_uint32(len(data)) + data

def pack_numpy_array(arr: np.ndarray) -> bytes:
    """打包一个Numpy数组: 转换为字节串然后打包。"""
    if arr is None:
        return pack_uint32(0)
    return pack_bytes_with_len(arr.tobytes())

def pack_list_of_bytes(data_list: List[bytes]) -> bytes:
    """打包一个字节串列表。"""
    # 写入列表中的元素数量
    num_items = len(data_list)
    buffer = pack_uint32(num_items)
    # 依次打包每个字节串
    for item in data_list:
        buffer += pack_bytes_with_len(item)
    return buffer


# --- 读取/解包 (Unpacking) 函数 ---

def unpack_uint32(buffer: bytes, offset: int) -> (int, int):
    """从缓冲区解包一个4字节整数。"""
    val = int.from_bytes(buffer[offset:offset+4], 'big')
    return val, offset + 4

def unpack_bytes_with_len(buffer: bytes, offset: int) -> (bytes, int):
    """从缓冲区解包一个字节串。"""
    length, offset = unpack_uint32(buffer, offset)
    if length == 0:
        return b'', offset
    data = buffer[offset:offset+length]
    offset += length
    return data, offset

def unpack_numpy_array(buffer: bytes, offset: int, dtype: np.dtype) -> (np.ndarray, int):
    """从缓冲区解包一个Numpy数组。"""
    data, offset = unpack_bytes_with_len(buffer, offset)
    if not data:
        return np.array([], dtype=dtype), offset
    return np.frombuffer(data, dtype=dtype), offset

def unpack_list_of_bytes(buffer: bytes, offset: int) -> (List[bytes], int):
    """从缓冲区解包一个字节串列表。"""
    num_items, offset = unpack_uint32(buffer, offset)
    data_list = []
    for _ in range(num_items):
        item, offset = unpack_bytes_with_len(buffer, offset)
        data_list.append(item)
    return data_list, offset