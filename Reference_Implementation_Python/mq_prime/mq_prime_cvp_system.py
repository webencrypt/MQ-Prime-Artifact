# 文件: mq_prime/mq_prime_cvp_system.py (NTT 优化版)

import numpy as np
import hashlib
from typing import Dict, List, Tuple
from .parameters import SecurityParametersV3, DEFAULT_PARAMS_V3
from .hash_utils import shake_128_xof
from .ntt_wrapper import *


class NTTEngine:
    """
    支持动态 N 的 C语言加速 NTT 引擎。
    """

    def __init__(self, n: int, q: int):
        # 更新检查逻辑，只允许我们新的 NTT 友好素数
        if q != 2013265921:
            # 为了兼容旧代码（如果有的话），我们暂时允许旧素数但抛出警告或报错
            # 这里我们强制要求新素数以确保正确性
            raise ValueError("Q must be 2013265921 (NTT-friendly prime) for this implementation.")

        if (n & (n - 1)) != 0:
            raise ValueError(f"N must be a power of 2, got {n}")

        self.n = n
        self.q = q
        self.inv_n = pow(n, -1, q)

        # 对于 p = 2013265921，31 是一个原根 (generator)
        g = 31
        # 计算 n 次本原单位根
        # root = g^((q-1)/n) mod q
        self.root_of_unity = pow(g, (q - 1) // n, q)
        self.inv_root_of_unity = pow(self.root_of_unity, -1, q)

    def ntt(self, poly: np.ndarray) -> np.ndarray:
        poly_int32 = poly.astype(np.int32)
        return c_ntt(poly_int32.copy(), self.n, self.root_of_unity)

    def inv_ntt(self, ntt_poly: np.ndarray) -> np.ndarray:
        poly_int32 = ntt_poly.astype(np.int32)
        return c_inv_ntt(poly_int32.copy(), self.n, self.inv_root_of_unity, self.inv_n)
# =================================================================
# === 新的代数系统：NTTSystem ===
# =================================================================

class NTTSystem:
    """
    【NTT优化版】使用多项式乘法定义的结构化系统。
    """

    def __init__(self, rng_seed: int, params: SecurityParametersV3, output_dim: int, label: str):
        self.params = params
        self.output_dim = output_dim
        self.label = label
        self.rng = np.random.RandomState(rng_seed)
        n, p = self.params.n, self.params.p

        # 初始化 NTT 引擎
        self.ntt_engine = NTTEngine(n, p)

        # 核心变化：系统由一组随机多项式定义
        # quadratic_polys[k] 是一个系数向量，用于与 s 进行多项式乘法
        self.quadratic_polys = self.rng.randint(0, p, size=(output_dim, n), dtype=np.uint32)

        # 线性项和常数项保持向量形式
        self.linear_terms_vec = self.rng.randint(0, p, size=(output_dim, n), dtype=np.uint32)
        self.constants = self.rng.randint(0, p, size=output_dim, dtype=np.uint32)


    def evaluate(self, s: np.ndarray) -> np.ndarray:
        """使用NTT高效地评估系统"""
        n, p = self.params.n, self.params.p

        s_ntt = self.ntt_engine.ntt(s)
        q_polys_ntt = np.array([self.ntt_engine.ntt(q_poly) for q_poly in self.quadratic_polys], dtype=np.uint64)

        s_ntt_64 = s_ntt.astype(np.uint64)
        quadratic_term_ntt = (s_ntt_64 * s_ntt_64) % p
        result_ntt = (q_polys_ntt * quadratic_term_ntt) % p

        inv_n = self.ntt_engine.inv_n
        quadratic_part = (np.sum(result_ntt, axis=1, dtype=np.uint64) * inv_n) % p

        linear_part = np.sum(self.linear_terms_vec.astype(np.uint64) * s.astype(np.uint64), axis=1) % p

        final_result = (quadratic_part + linear_part + self.constants.astype(np.uint64)) % p
        return final_result.astype(np.uint32)

# =================================================================
# === 修改 mq_primeCVPSystem 以使用 NTTSystem ===
# =================================================================

class mq_primeCVPSystem:
    def __init__(self, seed_P: bytes, params: SecurityParametersV3 = DEFAULT_PARAMS_V3):
        self.seed_P = seed_P
        self.params = params
        self.P_A: NTTSystem = None
        self.P_B: NTTSystem = None
        self.Compress = None


    def generate_from_seed(self):
        # 确保 n 是2的幂，以兼容NTT
        if not (self.params.n > 0 and (self.params.n & (self.params.n - 1)) == 0):
            raise ValueError(f"Parameter 'n' must be a power of 2 for NTT-based system, but got {self.params.n}.")

        seed_material = shake_128_xof(self.seed_P, 12)
        seed_a = int.from_bytes(seed_material[0:4], 'big')
        seed_b = int.from_bytes(seed_material[4:8], 'big')
        seed_compress = int.from_bytes(seed_material[8:12], 'big')

        self.P_A = NTTSystem(seed_a, self.params, self.params.m, "P_A")
        self.P_B = NTTSystem(seed_b, self.params, 1, "P_B")
        self.Compress = self._generate_compress_poly(seed_compress)

    def get_mpc_multiplication_count(self) -> int:
        """
        【sqrt(d) 优化版】计算MPC中的乘法门数量。
        """
        # 核心的非线性部分 s_ntt .* s_ntt 保持不变。
        shared_mults = self.params.n

        # 【核心优化】压缩门的乘法数量被显著减少。
        # 对于 d=8, k=3 的多项式，每个多项式求值现在只需要 5 次 MPC 乘法。
        # 由于所有 m 个多项式共享同一个输入 x，它们的幂次计算可以被复用。

        # 1. 预计算 x 的低次幂 (x^2, x^3): 需要 2 个门 (共享)
        # 2. 预计算 y=x^3 的幂 (y^2): 需要 1 个门 (共享)
        # k = sqrt(d+1) = 3
        shared_power_mults = (3 - 1) + (3 - 2)  # (k-1) + (k-2) = 2 + 1 = 3

        # 3. 每个多项式的最终组合：需要 2 个门 (不共享)
        #    P_i(x) = Q_i0 + Q_i1*y + Q_i2*y^2
        #    term_i1 = Q_i2 * y^2
        #    term_i2 = Q_i1 * y
        combination_mults_per_poly = (3 - 1)  # (k-1) = 2

        compress_mults = shared_power_mults + self.params.m * combination_mults_per_poly

        return shared_mults + compress_mults


    def _generate_compress_poly(self, seed: int) -> List[List[int]]:
        rng = np.random.RandomState(seed)
        polynomials = []
        for _ in range(self.params.m):
            coeffs = rng.randint(0, self.params.p, size=self.params.d + 1).tolist()
            polynomials.append(coeffs)
        return polynomials


    def evaluate_compress(self, x: int) -> np.ndarray:
        # ... (此函数保持不变) ...
        result = np.zeros(self.params.m, dtype=np.uint32)
        x_int = int(x)
        for i, poly_coeffs in enumerate(self.Compress):
            poly_val = 0
            for j, coeff in enumerate(poly_coeffs):
                term = (int(coeff) * pow(x_int, j, self.params.p)) % self.params.p
                poly_val = (poly_val + term) % self.params.p
            result[i] = poly_val
        return result


    def evaluate(self, s: np.ndarray) -> np.ndarray:
        p_a = self.P_A.evaluate(s)
        x_s_vector = self.P_B.evaluate(s)
        x_s = int(x_s_vector[0])
        p_compress = self.evaluate_compress(x_s)
        return (p_a.astype(np.uint64) + p_compress.astype(np.uint64)) % self.params.p