# mq_prime/vole_engine.py

import numpy as np
from typing import List, Dict
from .parameters import SecurityParametersV3
from .mq_prime_cvp_system import mq_primeCVPSystem
from .aes_prg import AES_PRG
from .hash_utils import H
from .ggm_tree import GGMTree


def modInverse(a, m):
    a = a % m
    m0 = m
    x0, x1 = 0, 1
    if m == 1: return 0
    while a > 1: q = a // m; m, a = a % m, m; x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 = x1 + m0
    return x1


class VOLE_Engine:
    def __init__(self, params: SecurityParametersV3, salt: bytes, round_idx: int):
        self.params = params
        self.salt = salt
        self.round_idx = round_idx
        base_seed_material = salt + round_idx.to_bytes(4, 'big')
        self.base_seed = H(b'base_seed:' + base_seed_material)
        self.share_prg = AES_PRG(H(b'share_seed:' + self.base_seed)[:16])


    def _share_secret(self, secret: np.ndarray) -> np.ndarray:
        secret = np.atleast_1d(secret)
        N = self.params.num_mpc_parties
        n_len = secret.shape[0]
        shares = np.zeros((N, n_len), dtype=np.uint32)
        if n_len == 0: return shares
        random_bytes = self.share_prg.read((N - 1) * n_len * 4)
        flat_shares = np.frombuffer(random_bytes, dtype=np.uint32) % self.params.p
        shares[1:, :] = flat_shares.reshape(N - 1, n_len)

        # --- 关键修复 START ---
        # 在求和时指定 dtype=np.uint64 来防止累加器溢出
        sum_other_shares = np.sum(shares[1:, :], axis=0, dtype=np.uint64)
        # --- 关键修复 END ---

        shares[0, :] = (secret.astype(np.uint64) - sum_other_shares) % self.params.p
        return shares.astype(np.uint32)


    def prove_gate(self, x_shares: np.ndarray, y_shares: np.ndarray, seed_0: bytes, debug_gate_id: int = -1) -> tuple:
        N, p = self.params.num_mpc_parties, self.params.p

        # 使用Python int确保计算正确性
        x = int(np.sum(x_shares.astype(np.uint64), dtype=np.uint64) % p)
        y = int(np.sum(y_shares.astype(np.uint64), dtype=np.uint64) % p)
        z_scalar = (x * y) % p

        z_share_prg = AES_PRG(H(b'z_share_seed:' + seed_0)[:16])

        z_shares = np.zeros((N, 1), dtype=object)
        random_bytes = z_share_prg.read((N - 1) * 4)
        flat_shares = np.frombuffer(random_bytes, dtype=np.uint32) % p
        sum_other = 0
        for i in range(N - 1):
            z_shares[i + 1, 0] = int(flat_shares[i])
            sum_other = (sum_other + int(flat_shares[i])) % p
        z_shares[0, 0] = (z_scalar - sum_other + p) % p

        gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seed_0)[:16])
        gate_vole_prg = AES_PRG(gate_master_prg.read(16))
        gate_chal_prg = AES_PRG(gate_master_prg.read(16))
        vole_seeds = [seed_0] + [gate_vole_prg.read(self.params.seed_size) for _ in range(N - 1)]
        h_w0_commitment = H(vole_seeds[0])

        w = np.zeros((N, y_shares.shape[1]), dtype=object)
        for i in range(N):
            prg = AES_PRG(vole_seeds[i])
            rand_val = int(np.frombuffer(prg.read(y_shares.shape[1] * 4), dtype=np.uint32)[0] % p)
            w[i, 0] = (int(y_shares[i, 0]) * 2 + rand_val) % p

        e = int(np.frombuffer(gate_chal_prg.read(y_shares.shape[1] * 4), dtype=np.uint32)[0] % p)

        v_sum = 0
        for i in range(N):
            x_minus_e = (int(x_shares[i, 0]) - e + p) % p
            term1 = (int(w[i, 0]) * x_minus_e) % p
            term2 = (2 * int(z_shares[i, 0])) % p
            current_val = (term1 - term2 + p) % p
            v_sum = (v_sum + current_val) % p
        v = np.uint32(v_sum)

        gate_proof_public = {"v": v.tobytes(), "h_w0_commitment": h_w0_commitment}
        # 返回 z_shares 时，需要转换回 numpy uint32 数组，以保持接口一致性
        gate_secrets = {"z_shares": z_shares.astype(np.uint32)}
        return gate_secrets["z_shares"], gate_proof_public, gate_secrets


    def verify_gate(self, proof: dict, secrets: dict, x_shares: np.ndarray, y_shares: np.ndarray,
                    debug_gate_id: int = -1) -> bool:
        N, p = self.params.num_mpc_parties, self.params.p
        z_shares = secrets["z_shares"]
        seed_0 = secrets["seed_0"]
        x0, y0, z0 = x_shares[0, :], y_shares[0, :], z_shares[0, :]
        v_from_proof = np.frombuffer(proof["v"], dtype=np.uint32)
        h_w0_from_proof = proof["h_w0_commitment"]
        gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seed_0)[:16])
        gate_vole_prg = AES_PRG(gate_master_prg.read(16))
        gate_chal_prg = AES_PRG(gate_master_prg.read(16))
        revealed_seeds_list = [gate_vole_prg.read(self.params.seed_size) for _ in range(N - 1)]
        e = np.frombuffer(gate_chal_prg.read(y_shares.shape[1] * 4), dtype=np.uint32).reshape(y_shares.shape[1]) % p
        w_revealed = np.zeros((N - 1, y_shares.shape[1]), dtype=np.uint64)
        for i in range(N - 1):
            prg = AES_PRG(revealed_seeds_list[i])
            rand_val = np.frombuffer(prg.read(y_shares.shape[1] * 4), dtype=np.uint32).reshape(y_shares.shape[1]) % p
            w_revealed[i, :] = (y_shares[i + 1, :].astype(np.uint64) * 2 + rand_val.astype(np.uint64)) % p
        sum_term = 0
        for i in range(1, N):
            x_minus_e = (x_shares[i].astype(np.uint64) - e.astype(np.uint64) + p) % p
            term1 = (w_revealed[i - 1].astype(np.uint64) * x_minus_e) % p
            term2 = (2 * z_shares[i].astype(np.uint64)) % p
            current_sum = sum(int(val) for val in term1.flatten())
            current_sub = sum(int(val) for val in term2.flatten())
            current_val = (current_sum - current_sub) % p
            sum_term = (sum_term + current_val) % p
        term_2z0 = (2 * int(z0[0])) % p
        numerator = (int(v_from_proof[0]) - sum_term + term_2z0 + p) % p
        denominator = (int(x0[0]) - int(e[0]) + p) % p
        inv_denominator = modInverse(denominator, p)
        w0_recalc = (numerator * inv_denominator) % p
        h_w0_recalc = H(seed_0)
        prg0 = AES_PRG(seed_0)
        rand_val_0_expected = np.frombuffer(prg0.read(y_shares.shape[1] * 4), dtype=np.uint32).reshape(
            y_shares.shape[1]) % p
        w0_expected = (int(y0[0]) * 2 + int(rand_val_0_expected[0])) % p

        if debug_gate_id == 3137:
            print("\n" + "---" * 10)
            print("--- VERIFY_GATE DEBUG (GATE 3137) ---")
            print(f"    v (from proof): {v_from_proof[0]}")
            print(f"    x_shares[0]: {x0.tolist()}, x_shares[1]: {x_shares[1].tolist()}")
            print(f"    y_shares[0]: {y0.tolist()}, y_shares[1]: {y_shares[1].tolist()}")
            print(f"    z_shares (from proof): {z_shares.flatten().tolist()}")
            print(f"    challenge 'e': {e.flatten().tolist()}")
            print(f"    w_revealed:\n{w_revealed}")
            print(f"    sum_term (over revealed parties): {sum_term}")
            print(f"    numerator: {numerator}")
            print(f"    denominator: {denominator}")
            print(f"    w0_recalc: {w0_recalc}")
            print(f"    w0_expected: {w0_expected}")
            print(f"    h_w0_recalc == h_w0_from_proof: {h_w0_recalc == h_w0_from_proof}")
            print(f"    w0_recalc == w0_expected: {w0_recalc == w0_expected}")
            print("---" * 10 + "\n")

        if h_w0_recalc != h_w0_from_proof: return False
        return w0_recalc == w0_expected


    def prove_batch_gates(self, x_shares_batch: np.ndarray, y_shares_batch: np.ndarray,
                          seeds_0_batch: List[bytes]) -> tuple:
        N, p = self.params.num_mpc_parties, self.params.p
        num_gates = x_shares_batch.shape[1]

        # --- FIX START ---
        # 使用 Python 的 int 进行计算以防止溢出
        x_batch_int = [int(s) for s in np.sum(x_shares_batch, axis=0, dtype=np.uint64) % p]
        y_batch_int = [int(s) for s in np.sum(y_shares_batch, axis=0, dtype=np.uint64) % p]
        z_batch_int = [(x * y) % p for x, y in zip(x_batch_int, y_batch_int)]
        # --- FIX END ---

        z_shares_batch = np.zeros((N, num_gates), dtype=np.uint32)
        for i in range(num_gates):
            z_share_prg = AES_PRG(H(b'z_share_seed:' + seeds_0_batch[i])[:16])
            random_bytes = z_share_prg.read((N - 1) * 4)
            flat_shares = np.frombuffer(random_bytes, dtype=np.uint32) % p
            z_shares_batch[1:, i] = flat_shares
            sum_other_shares = np.sum(z_shares_batch[1:, i], dtype=np.uint64)
            z_shares_batch[0, i] = (z_batch_int[i] - int(sum_other_shares % p) + p) % p

        vole_seeds_batch = [[b''] * num_gates for _ in range(N)]
        h_w0_commitments_batch = []
        e_batch = np.zeros(num_gates, dtype=np.uint32)
        for i in range(num_gates):
            gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seeds_0_batch[i])[:16])
            gate_vole_prg = AES_PRG(gate_master_prg.read(16))
            gate_chal_prg = AES_PRG(gate_master_prg.read(16))
            current_vole_seeds = [seeds_0_batch[i]] + [gate_vole_prg.read(self.params.seed_size) for _ in range(N - 1)]
            for party in range(N): vole_seeds_batch[party][i] = current_vole_seeds[party]
            h_w0_commitments_batch.append(H(current_vole_seeds[0]))
            e_batch[i] = np.frombuffer(gate_chal_prg.read(4), dtype=np.uint32)[0] % p

        w_batch = np.zeros((N, num_gates), dtype=np.uint64)
        for i in range(N):
            for j in range(num_gates):
                prg = AES_PRG(vole_seeds_batch[i][j])
                rand_val = np.frombuffer(prg.read(4), dtype=np.uint32)[0] % p
                w_batch[i, j] = (y_shares_batch[i, j].astype(np.uint64) * 2 + rand_val) % p

        # --- FIX START ---
        # 使用 Python 的 int 重新计算 term1_batch 以防止溢出
        v_terms_batch = np.zeros((N, num_gates), dtype=np.uint64)
        for i in range(N):
            for j in range(num_gates):
                x_minus_e_ij = (int(x_shares_batch[i, j]) - int(e_batch[j]) + p) % p
                term1_ij = (int(w_batch[i, j]) * x_minus_e_ij) % p
                term2_ij = (2 * int(z_shares_batch[i, j])) % p
                v_terms_batch[i, j] = (term1_ij - term2_ij + p) % p
        # --- FIX END ---

        v_batch = np.sum(v_terms_batch, axis=0, dtype=np.uint64) % p

        batch_gate_proof_public = {"v_batch": v_batch.astype(np.uint32).tobytes(),
                                   "h_w0_commitments_batch": h_w0_commitments_batch}
        batch_gate_secrets = {"z_shares_batch": z_shares_batch.astype(np.uint32)}
        return batch_gate_secrets, batch_gate_proof_public


    def verify_batch_gates(self, public_proofs: Dict, secrets: Dict, x_shares_batch: np.ndarray,
                           y_shares_batch: np.ndarray) -> bool:
        N, p = self.params.num_mpc_parties, self.params.p
        num_gates = x_shares_batch.shape[1]

        v_batch_from_proof = np.frombuffer(public_proofs["v_batch"], dtype=np.uint32)
        h_w0s_from_proof = public_proofs["h_w0_commitments_batch"]
        z_shares_batch = secrets["z_shares_batch"]
        seeds_0_batch = secrets["seeds_0_batch"]

        x0_batch, y0_batch, z0_batch = x_shares_batch[0, :], y_shares_batch[0, :], z_shares_batch[0, :]

        e_batch = np.zeros(num_gates, dtype=np.uint64)
        w_revealed_batch_int = [[0] * num_gates for _ in range(N - 1)]

        for j in range(num_gates):
            seed_0 = seeds_0_batch[j]
            gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seed_0)[:16])
            gate_vole_prg = AES_PRG(gate_master_prg.read(16))
            gate_chal_prg = AES_PRG(gate_master_prg.read(16))

            e_batch[j] = np.frombuffer(gate_chal_prg.read(4), dtype=np.uint32)[0] % p

            revealed_seeds_list = [gate_vole_prg.read(self.params.seed_size) for _ in range(N - 1)]
            for i in range(N - 1):
                prg = AES_PRG(revealed_seeds_list[i])
                rand_val = np.frombuffer(prg.read(4), dtype=np.uint32)[0] % p
                # --- FIX START ---
                # 计算时使用 Python int
                w_revealed_batch_int[i][j] = (int(y_shares_batch[i + 1, j]) * 2 + int(rand_val)) % p
                # --- FIX END ---

        sum_term_batch = np.zeros(num_gates, dtype=np.uint64)

        # --- FIX START ---
        # 循环累加每个被揭示方的贡献, 使用 int 防止溢出
        for j in range(num_gates):
            current_gate_sum_term = 0
            for i in range(1, N):
                x_minus_e_ij = (int(x_shares_batch[i, j]) - int(e_batch[j]) + p) % p
                # w_revealed for party i is at index i-1
                term1_ij = (w_revealed_batch_int[i - 1][j] * x_minus_e_ij) % p
                term2_ij = (2 * int(z_shares_batch[i, j])) % p
                current_gate_sum_term = (current_gate_sum_term + term1_ij - term2_ij + p) % p
            sum_term_batch[j] = current_gate_sum_term
        # --- FIX END ---

        term_2z0_batch = (2 * z0_batch.astype(np.uint64)) % p
        numerator_batch = (v_batch_from_proof.astype(np.uint64) - sum_term_batch + term_2z0_batch + p) % p
        denominator_batch = (x0_batch.astype(np.uint64) - e_batch + p) % p

        inv_denominator_batch = np.array([modInverse(int(d), p) for d in denominator_batch], dtype=np.uint64)
        w0_recalc_batch = (numerator_batch * inv_denominator_batch) % p

        for j in range(num_gates):
            seed_0 = seeds_0_batch[j]

            h_w0_recalc = H(seed_0)
            if h_w0_recalc != h_w0s_from_proof[j]:
                return False

            prg0 = AES_PRG(seed_0)
            rand_val_0_expected = np.frombuffer(prg0.read(4), dtype=np.uint32)[0] % p
            w0_expected = (int(y0_batch[j]) * 2 + int(rand_val_0_expected)) % p

            if w0_recalc_batch[j] != w0_expected:
                return False

        return True


    def prove_batch_gates_aggregated(self, x_shares_batch: np.ndarray, y_shares_batch: np.ndarray,
                                     seeds_0_batch: List[bytes]) -> tuple:
        """
        【优化版】使用随机线性组合，为一批门生成一个聚合的VOLE证明。
        """
        N, p = self.params.num_mpc_parties, self.params.p
        num_gates = x_shares_batch.shape[1]

        # --- 签名者和验证者共享的随机性来源 ---
        # 这个 PRG 用于生成随机线性组合的挑战权重
        aggregation_chal_prg = AES_PRG(H(b'agg_chal_seed:' + self.base_seed)[:16])

        # 1. z_shares 的计算保持不变
        x_batch_int = [int(s) for s in np.sum(x_shares_batch, axis=0, dtype=np.uint64) % p]
        y_batch_int = [int(s) for s in np.sum(y_shares_batch, axis=0, dtype=np.uint64) % p]
        z_batch_int = [(x * y) % p for x, y in zip(x_batch_int, y_batch_int)]
        z_shares_batch = np.zeros((N, num_gates), dtype=np.uint32)
        for i in range(num_gates):
            z_share_prg = AES_PRG(H(b'z_share_seed:' + seeds_0_batch[i])[:16])
            random_bytes = z_share_prg.read((N - 1) * 4)
            flat_shares = np.frombuffer(random_bytes, dtype=np.uint32) % p
            z_shares_batch[1:, i] = flat_shares
            sum_other_shares = np.sum(z_shares_batch[1:, i], dtype=np.uint64)
            z_shares_batch[0, i] = (z_batch_int[i] - int(sum_other_shares % p) + p) % p

        # 2. h_w0 和 e 的计算保持不变
        h_w0_commitments_batch = []
        e_batch = np.zeros(num_gates, dtype=np.uint32)
        vole_seeds_batch = [[b''] * num_gates for _ in range(N)]
        for i in range(num_gates):
            gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seeds_0_batch[i])[:16])
            gate_vole_prg = AES_PRG(gate_master_prg.read(16))
            gate_chal_prg = AES_PRG(gate_master_prg.read(16))
            current_vole_seeds = [seeds_0_batch[i]] + [gate_vole_prg.read(self.params.seed_size) for _ in range(N - 1)]
            for party in range(N): vole_seeds_batch[party][i] = current_vole_seeds[party]
            h_w0_commitments_batch.append(H(current_vole_seeds[0]))
            e_batch[i] = np.frombuffer(gate_chal_prg.read(4), dtype=np.uint32)[0] % p

        # 3. w_batch 的计算保持不变
        w_batch = np.zeros((N, num_gates), dtype=np.uint64)
        for i in range(N):
            for j in range(num_gates):
                prg = AES_PRG(vole_seeds_batch[i][j])
                rand_val = np.frombuffer(prg.read(4), dtype=np.uint32)[0] % p
                w_batch[i, j] = (y_shares_batch[i, j].astype(np.uint64) * 2 + rand_val) % p

        # 4. 【核心变化】计算聚合的 v_agg
        v_terms_batch = np.zeros((N, num_gates), dtype=np.uint64)
        for i in range(N):
            for j in range(num_gates):
                # 使用 Python int 进行中间乘积计算，确保不会溢出
                x_minus_e_ij = (int(x_shares_batch[i, j]) - int(e_batch[j]) + p) % p
                term1 = (int(w_batch[i, j]) * x_minus_e_ij) % p
                term2 = (2 * int(z_shares_batch[i, j])) % p
                v_terms_batch[i, j] = (term1 - term2 + p) % p

        v_batch = np.sum(v_terms_batch, axis=0) % p

        challenge_weights = np.frombuffer(aggregation_chal_prg.read(num_gates * 4), dtype=np.uint32) % p

        # 计算 v_agg 时也使用 int
        v_agg = 0
        for j in range(num_gates):
            v_agg = (v_agg + int(challenge_weights[j]) * int(v_batch[j])) % p

        # 5. 组装新的、更小的证明
        # v_batch 不再需要，只发送 v_agg
        batch_gate_proof_public = {
            "v_agg": np.uint32(v_agg).tobytes(),
            "h_w0_commitments_batch": h_w0_commitments_batch
        }
        batch_gate_secrets = {"z_shares_batch": z_shares_batch.astype(np.uint32)}
        return batch_gate_secrets, batch_gate_proof_public

    def verify_batch_gates_aggregated(self, public_proofs: Dict, secrets: Dict, x_shares_batch: np.ndarray,
                                      y_shares_batch: np.ndarray, ggm_root_seed: bytes, ggm_depth: int) -> bool:
        N, p = self.params.num_mpc_parties, self.params.p
        num_gates = x_shares_batch.shape[1]

        aggregation_chal_prg = AES_PRG(H(b'agg_chal_seed:' + self.base_seed)[:16])

        v_agg_from_proof = np.frombuffer(public_proofs["v_agg"], dtype=np.uint32)[0]
        h_w0s_from_proof = public_proofs["h_w0_commitments_batch"]

        z_shares_revealed = secrets["z_shares_batch"]
        seeds_0_revealed = secrets["seeds_0_batch"]
        revealed_indices = secrets["revealed_indices"]
        revealed_indices_set = set(revealed_indices)

        z_shares_map = {idx: z_shares_revealed[:, i:i + 1] for i, idx in enumerate(revealed_indices)}

        challenge_weights = np.frombuffer(aggregation_chal_prg.read(num_gates * 4), dtype=np.uint32).astype(
            np.uint64) % p

        full_z_shares = np.zeros((N, num_gates), dtype=np.uint64)
        e_batch = np.zeros(num_gates, dtype=np.uint64)
        w_batch = np.zeros((N, num_gates), dtype=np.uint64)

        from .ggm_tree import GGMTree  # 修复 NameError
        temp_ggm_tree = GGMTree(ggm_root_seed, ggm_depth)

        for j in range(num_gates):
            seed_0 = temp_ggm_tree.get_leaf(j)

            if H(seed_0) != h_w0s_from_proof[j]: return False

            if j in revealed_indices_set:
                full_z_shares[:, j] = z_shares_map[j].flatten().astype(np.uint64)
            else:
                x_rec = np.sum(x_shares_batch[:, j], dtype=np.uint64) % p
                y_rec = np.sum(y_shares_batch[:, j], dtype=np.uint64) % p
                z_rec = (x_rec * y_rec) % p

                z_share_prg = AES_PRG(H(b'z_share_seed:' + seed_0)[:16])
                rand_bytes = z_share_prg.read((N - 1) * 4)
                flat_s = np.frombuffer(rand_bytes, dtype=np.uint32) % p
                full_z_shares[1:, j] = flat_s
                sum_other = np.sum(full_z_shares[1:, j]) % p
                full_z_shares[0, j] = (int(z_rec) - int(sum_other) + int(p)) % int(p)
                
            gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seed_0)[:16])
            gate_vole_prg = AES_PRG(gate_master_prg.read(16))
            gate_chal_prg = AES_PRG(gate_master_prg.read(16))
            e_batch[j] = np.frombuffer(gate_chal_prg.read(4), dtype=np.uint32)[0] % p

            revealed_seeds = [gate_vole_prg.read(16) for _ in range(N - 1)]

            prg0 = AES_PRG(seed_0)
            rand0 = np.frombuffer(prg0.read(4), dtype=np.uint32)[0] % p
            w_batch[0, j] = (y_shares_batch[0, j].astype(np.uint64) * 2 + rand0) % p

            for i in range(N - 1):
                prg = AES_PRG(revealed_seeds[i])
                rand_val = np.frombuffer(prg.read(4), dtype=np.uint32)[0] % p
                w_batch[i + 1, j] = (y_shares_batch[i + 1, j].astype(np.uint64) * 2 + rand_val) % p

        # --- 最终修复：重写验证方程，避免 einsum 溢出 ---
        # 我们通过分步计算来镜像签名者的逻辑

        # 1. 计算每个门的 v_j 的期望值
        v_terms_batch = np.zeros((N, num_gates), dtype=np.uint64)
        for i in range(N):
            for j in range(num_gates):
                # 使用 Python int 进行中间乘积计算，确保不会溢出
                x_minus_e_ij = (int(x_shares_batch[i, j]) - int(e_batch[j]) + p) % p
                term1 = (int(w_batch[i, j]) * x_minus_e_ij) % p
                term2 = (2 * int(full_z_shares[i, j])) % p
                v_terms_batch[i, j] = (term1 - term2 + p) % p

        # 2. 对所有参与方求和，得到每个门的 v_j 的期望值
        v_batch_expected = np.sum(v_terms_batch, axis=0, dtype=np.uint64) % p

        # 3. 计算期望的聚合值 v_agg
        expected_v_agg = np.sum((challenge_weights * v_batch_expected) % p) % p

        return expected_v_agg == v_agg_from_proof


    def verify_batch_gates_aggregated_reconstruction(
            self,
            public_proofs: Dict,
            full_x_shares: np.ndarray,  # 现在接收完整的份额
            full_y_shares: np.ndarray,  # 现在接收完整的份额
            ggm_root_seed: bytes,
            ggm_depth: int
    ) -> bool:
        """
        【最终修复版 v2】VOLE聚合证明验证函数。
        它现在接收完整的输入份额，只负责纯粹的代数验证。
        """
        N, p = self.params.num_mpc_parties, self.params.p
        num_gates = full_x_shares.shape[1]

        # --- 1. 解包证明 ---
        v_agg_from_proof = int(np.frombuffer(public_proofs["v_agg"], dtype=np.uint32)[0])
        h_w0s_from_proof = public_proofs["h_w0_commitments_batch"]

        # --- 2. 准备验证所需的所有数据 ---
        aggregation_chal_prg = AES_PRG(H(b'agg_chal_seed:' + self.base_seed)[:16])
        challenge_weights = np.frombuffer(aggregation_chal_prg.read(num_gates * 4), dtype=np.uint32)

        temp_ggm_tree = GGMTree(ggm_root_seed, ggm_depth)

        # --- 3. 重建验证方程的所有组件 ---
        full_x_shares = full_x_shares.astype(object)  # 切换到Python int以保证数值稳定
        full_y_shares = full_y_shares.astype(object)

        full_z_shares = np.zeros((N, num_gates), dtype=object)
        e_batch = np.zeros(num_gates, dtype=object)
        w_batch = np.zeros((N, num_gates), dtype=object)

        x_rec_int = [int(s) for s in np.sum(full_x_shares, axis=0) % p]
        y_rec_int = [int(s) for s in np.sum(full_y_shares, axis=0) % p]
        z_rec_int = [(x * y) % p for x, y in zip(x_rec_int, y_rec_int)]

        for j in range(num_gates):
            seed_0 = temp_ggm_tree.get_leaf(j)
            if H(seed_0) != h_w0s_from_proof[j]: return False

            z_share_prg = AES_PRG(H(b'z_share_seed:' + seed_0)[:16])
            rand_bytes = z_share_prg.read((N - 1) * 4)
            flat_s = np.frombuffer(rand_bytes, dtype=np.uint32) % p
            sum_other = 0
            for i in range(N - 1):
                full_z_shares[i + 1, j] = int(flat_s[i])
                sum_other = (sum_other + int(flat_s[i])) % p

            full_z_shares[0, j] = (z_rec_int[j] - sum_other + p) % p

            gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seed_0)[:16])
            gate_vole_prg = AES_PRG(gate_master_prg.read(16))
            gate_chal_prg = AES_PRG(gate_master_prg.read(16))
            e_batch[j] = int(np.frombuffer(gate_chal_prg.read(4), dtype=np.uint32)[0] % p)

            all_vole_seeds = [seed_0] + [gate_vole_prg.read(16) for _ in range(N - 1)]

            for i in range(N):
                prg = AES_PRG(all_vole_seeds[i])
                rand_val = int(np.frombuffer(prg.read(4), dtype=np.uint32)[0] % p)
                w_batch[i, j] = (int(full_y_shares[i, j]) * 2 + rand_val) % p

        # --- 4. 计算期望的 v_agg ---
        expected_v_agg = 0
        for j in range(num_gates):
            v_j = 0
            for i in range(N):
                x_minus_e_ij = (int(full_x_shares[i, j]) - int(e_batch[j]) + p) % p
                term1 = (int(w_batch[i, j]) * x_minus_e_ij) % p
                term2 = (2 * int(full_z_shares[i, j])) % p
                v_i_j = (term1 - term2 + p) % p
                v_j = (v_j + v_i_j) % p

            expected_v_agg = (expected_v_agg + int(challenge_weights[j]) * v_j) % p

        return expected_v_agg == v_agg_from_proof

    def verify_gate_reconstruction(
            self,
            public_proof: Dict,  # 包含 v 和 h_w0_commitment
            full_x_shares: np.ndarray,  # 完整的 x 份额 (N, 1)
            full_y_shares: np.ndarray,  # 完整的 y 份额 (N, 1)
            seed_0: bytes
    ) -> bool:
        """
        【最终版】VOLE单门验证函数。
        它使用完整的输入份额来验证一个门的正确性。
        """
        N, p = self.params.num_mpc_parties, self.params.p

        # --- 1. 解包证明 ---
        v_from_proof = int(np.frombuffer(public_proof["v"], dtype=np.uint32)[0])
        h_w0_from_proof = public_proof["h_w0_commitment"]

        # --- 2. 检查 h_w0 承诺 ---
        # 调用者已经通过 Merkle 树验证了 h_w0 的可信度
        # 但我们仍然要检查证明中的 h_w0 是否与 seed_0 对应
        if H(seed_0) != h_w0_from_proof:
            return False

        # --- 3. 重建验证方程的所有组件 (与聚合验证类似，但只针对一个门) ---
        full_x_shares = full_x_shares.astype(object)
        full_y_shares = full_y_shares.astype(object)

        x_rec = int(np.sum(full_x_shares, axis=0)[0]) % p
        y_rec = int(np.sum(full_y_shares, axis=0)[0]) % p
        z_rec = (x_rec * y_rec) % p

        # 重建 z_shares
        z_share_prg = AES_PRG(H(b'z_share_seed:' + seed_0)[:16])
        rand_bytes = z_share_prg.read((N - 1) * 4)
        flat_s = np.frombuffer(rand_bytes, dtype=np.uint32) % p

        full_z_shares = np.zeros((N, 1), dtype=object)
        sum_other = 0
        for i in range(N - 1):
            full_z_shares[i + 1, 0] = int(flat_s[i])
            sum_other = (sum_other + int(flat_s[i])) % p
        full_z_shares[0, 0] = (z_rec - sum_other + p) % p

        # 重建 e 和 w
        gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seed_0)[:16])
        gate_vole_prg = AES_PRG(gate_master_prg.read(16))
        gate_chal_prg = AES_PRG(gate_master_prg.read(16))
        e_val = int(np.frombuffer(gate_chal_prg.read(4), dtype=np.uint32)[0] % p)

        all_vole_seeds = [seed_0] + [gate_vole_prg.read(16) for _ in range(N - 1)]
        w_vec = np.zeros((N, 1), dtype=object)
        for i in range(N):
            prg = AES_PRG(all_vole_seeds[i])
            rand_val = int(np.frombuffer(prg.read(4), dtype=np.uint32)[0] % p)
            w_vec[i, 0] = (int(full_y_shares[i, 0]) * 2 + rand_val) % p

        # --- 4. 计算期望的 v ---
        expected_v = 0
        for i in range(N):
            x_minus_e = (int(full_x_shares[i, 0]) - e_val + p) % p
            term1 = (int(w_vec[i, 0]) * x_minus_e) % p
            term2 = (2 * int(full_z_shares[i, 0])) % p
            v_i = (term1 - term2 + p) % p
            expected_v = (expected_v + v_i) % p

        return expected_v == v_from_proof

    def prove_batch_gates_aggregated_individual(
            self,
            x_shares_batch: np.ndarray,
            y_shares_batch: np.ndarray,
            seeds_0_batch: List[bytes],
            challenge_seed: bytes
    ) -> tuple:
        """
        【新】为一批输入*不同*的门生成一个聚合VOLE证明。
        使用一个外部提供的 challenge_seed 来生成聚合权重。
        """
        N, p = self.params.num_mpc_parties, self.params.p  # <--- 修正行
        num_gates = x_shares_batch.shape[1]

        # 这部分与旧的聚合证明函数几乎完全相同
        x_batch_int = [int(s) for s in np.sum(x_shares_batch.astype(np.uint64), axis=0) % p]
        y_batch_int = [int(s) for s in np.sum(y_shares_batch.astype(np.uint64), axis=0) % p]
        z_batch_int = [(x * y) % p for x, y in zip(x_batch_int, y_batch_int)]

        z_shares_batch = np.zeros((N, num_gates), dtype=object)
        for i in range(num_gates):
            z_share_prg = AES_PRG(H(b'z_share_seed:' + seeds_0_batch[i])[:16])
            rand_bytes = z_share_prg.read((N - 1) * 4)
            flat_s = np.frombuffer(rand_bytes, dtype=np.uint32) % p
            sum_other = 0
            for k in range(N - 1):
                z_shares_batch[k + 1, i] = int(flat_s[k])
                sum_other = (sum_other + int(flat_s[k])) % p
            z_shares_batch[0, i] = (z_batch_int[i] - sum_other + p) % p

        e_batch = np.zeros(num_gates, dtype=object)
        w_batch = np.zeros((N, num_gates), dtype=object)
        for i in range(num_gates):
            gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seeds_0_batch[i])[:16])
            gate_vole_prg = AES_PRG(gate_master_prg.read(16))
            gate_chal_prg = AES_PRG(gate_master_prg.read(16))
            all_vole_seeds = [seeds_0_batch[i]] + [gate_vole_prg.read(16) for _ in range(N - 1)]
            e_batch[i] = int(np.frombuffer(gate_chal_prg.read(4), dtype=np.uint32)[0] % p)
            for party_idx in range(N):
                prg = AES_PRG(all_vole_seeds[party_idx])
                rand_val = int(np.frombuffer(prg.read(4), dtype=np.uint32)[0] % p)
                w_batch[party_idx, i] = (int(y_shares_batch[party_idx, i]) * 2 + rand_val) % p

        # 计算 v_batch
        v_batch = np.zeros(num_gates, dtype=object)
        for j in range(num_gates):
            v_j = 0
            for i in range(N):
                x_minus_e = (int(x_shares_batch[i, j]) - int(e_batch[j]) + p) % p
                term1 = (int(w_batch[i, j]) * x_minus_e) % p
                term2 = (2 * int(z_shares_batch[i, j])) % p
                v_i_j = (term1 - term2 + p) % p
                v_j = (v_j + v_i_j) % p
            v_batch[j] = v_j

        # 使用外部种子生成聚合权重
        aggregation_chal_prg = AES_PRG(H(challenge_seed)[:16])
        challenge_weights = np.frombuffer(aggregation_chal_prg.read(num_gates * 4), dtype=np.uint32)

        v_agg = 0
        for j in range(num_gates):
            v_agg = (v_agg + int(challenge_weights[j]) * int(v_batch[j])) % p

        # 返回 v_agg 和 z_shares (用于签名端的电路模拟)
        return np.uint32(v_agg), z_shares_batch.astype(np.uint32)


    def verify_batch_gates_aggregated_individual(
            self,
            v_agg_from_proof: int,
            challenge_seed: bytes,
            full_x_shares: np.ndarray,
            full_y_shares: np.ndarray,
            ggm_tree: GGMTree,
            gate_indices: List[int]
    ) -> bool:
        """
        【新】验证一批输入*不同*的门的聚合证明。
        """
        N, p = self.params.num_mpc_parties, self.params.p
        num_gates = full_x_shares.shape[1]

        # 这部分与 reconstruction 验证函数几乎完全相同，只是最后比较 v_agg
        aggregation_chal_prg = AES_PRG(H(challenge_seed)[:16])
        challenge_weights = np.frombuffer(aggregation_chal_prg.read(num_gates * 4), dtype=np.uint32)

        full_x_shares = full_x_shares.astype(object)
        full_y_shares = full_y_shares.astype(object)

        full_z_shares = np.zeros((N, num_gates), dtype=object)
        e_batch = np.zeros(num_gates, dtype=object)
        w_batch = np.zeros((N, num_gates), dtype=object)

        x_rec_int = [int(s) for s in np.sum(full_x_shares, axis=0) % p]
        y_rec_int = [int(s) for s in np.sum(full_y_shares, axis=0) % p]
        z_rec_int = [(x * y) % p for x, y in zip(x_rec_int, y_rec_int)]

        for j, gate_idx in enumerate(gate_indices):
            seed_0 = ggm_tree.get_leaf(gate_idx)

            # z_shares 重建
            z_share_prg = AES_PRG(H(b'z_share_seed:' + seed_0)[:16])
            rand_bytes = z_share_prg.read((N - 1) * 4)
            flat_s = np.frombuffer(rand_bytes, dtype=np.uint32) % p
            sum_other = 0
            for i in range(N - 1):
                full_z_shares[i + 1, j] = int(flat_s[i])
                sum_other = (sum_other + int(flat_s[i])) % p
            full_z_shares[0, j] = (z_rec_int[j] - sum_other + p) % p

            # e 和 w 重建
            gate_master_prg = AES_PRG(H(b'gate_master_prg:' + seed_0)[:16])
            gate_vole_prg = AES_PRG(gate_master_prg.read(16))
            gate_chal_prg = AES_PRG(gate_master_prg.read(16))
            e_batch[j] = int(np.frombuffer(gate_chal_prg.read(4), dtype=np.uint32)[0] % p)
            all_vole_seeds = [seed_0] + [gate_vole_prg.read(16) for _ in range(N - 1)]
            for i in range(N):
                prg = AES_PRG(all_vole_seeds[i])
                rand_val = int(np.frombuffer(prg.read(4), dtype=np.uint32)[0] % p)
                w_batch[i, j] = (int(full_y_shares[i, j]) * 2 + rand_val) % p

        expected_v_agg = 0
        for j in range(num_gates):
            v_j = 0
            for i in range(N):
                x_minus_e = (int(full_x_shares[i, j]) - int(e_batch[j]) + p) % p
                term1 = (int(w_batch[i, j]) * x_minus_e) % p
                term2 = (2 * int(full_z_shares[i, j])) % p
                v_i_j = (term1 - term2 + p) % p
                v_j = (v_j + v_i_j) % p
            expected_v_agg = (expected_v_agg + int(challenge_weights[j]) * v_j) % p

        return expected_v_agg == v_agg_from_proof