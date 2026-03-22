import os
import numpy as np
import math
from mq_prime.timer import Timer  # 确保 utils/timer.py 存在

# 导入配置
from .parameters import DEFAULT_PARAMS_V3 as global_default_params
from .data_structures import PublicKey, PrivateKey, SignatureV3
from .mq_prime_cvp_system import mq_primeCVPSystem
from .vole_engine import VOLE_Engine
from .hash_utils import *

# 导入高级组件
from .merkle_tree_quad import build_merkle_tree, get_batch_merkle_proof, verify_batch_merkle_proof
from .ggm_tree import GGMTree, GGMTreeWithCache
from .aes_prg import AES_PRG
from .serialization import (
    pack_list_of_bytes, unpack_list_of_bytes,
    pack_uint32, pack_bytes_with_len, unpack_bytes_with_len
)

# 树的叉数配置 (4 = Quadtree)
ARITY = 4


# -----------------------------------------------------------------------------
# 辅助函数区 (保持 File 15 逻辑不变)
# -----------------------------------------------------------------------------

def _evaluate_mq_in_field(s_field, mq_system, p_mod):
    """【NTT优化版】在 F_p 域上使用NTT评估一个结构化MQ系统。"""
    n, p = mq_system.params.n, mq_system.params.p
    s_ntt = mq_system.ntt_engine.ntt(s_field)
    q_polys_ntt = np.array([mq_system.ntt_engine.ntt(q_poly) for q_poly in mq_system.quadratic_polys], dtype=np.uint64)
    s_ntt_64 = s_ntt.astype(np.uint64)
    quadratic_term_ntt = (s_ntt_64 * s_ntt_64) % p
    result_ntt = (q_polys_ntt * quadratic_term_ntt) % p
    inv_n = mq_system.ntt_engine.inv_n
    quadratic_part = (np.sum(result_ntt, axis=1, dtype=np.uint64) * inv_n) % p
    linear_part = np.sum(mq_system.linear_terms_vec.astype(np.uint64) * s_field.astype(np.uint64), axis=1) % p
    final_result = (quadratic_part + linear_part + mq_system.constants.astype(np.uint64)) % p
    return final_result.astype(np.uint32)


def _calculate_q_shares(poly_coeffs, wire_shares, params):
    k = 3
    p = params.p
    q_shares = {}
    for j in range(k):
        current_q_shares = np.zeros((params.num_mpc_parties, 1), dtype=object)
        for l in range(k):
            coeff_idx = j * k + l
            coeff = poly_coeffs[coeff_idx] if coeff_idx < len(poly_coeffs) else 0
            current_q_shares = (current_q_shares + int(coeff) * wire_shares[f'x^{l}'])
        q_shares[j] = (current_q_shares % p)
    return q_shares


def mpc_evaluate_compress_sqrt(engine, ggm_tree, x_shares, all_coeffs, start_gate_idx, params):
    """【最终修复版】使用 sqrt(d) 优化，并行计算所有 Compress 多项式。"""
    p = params.p
    m = params.m
    k = 3
    gate_idx = start_gate_idx
    wire_shares = {}
    v_aggs_compress = []

    stages = [
        {'name': 'x^2', 'x_in': 'x^1', 'y_in': 'x^1', 'out': 'x^2', 'seed_name': '1'},
        {'name': 'x^3', 'x_in': 'x^2', 'y_in': 'x^1', 'out': 'y^1', 'seed_name': '2'},
        {'name': 'y^2', 'x_in': 'y^1', 'y_in': 'y^1', 'out': 'y^2', 'seed_name': '3'},
    ]
    wire_shares['x^1'] = x_shares.astype(object)

    for stage in stages:
        x_batch = wire_shares[stage['x_in']]
        y_batch = wire_shares[stage['y_in']]
        seeds_batch = [ggm_tree.get_leaf(gate_idx)]
        v_agg, z_shares_batch = engine.prove_batch_gates_aggregated_individual(
            x_batch.astype(np.uint32), y_batch.astype(np.uint32), seeds_batch,
            f'compress_agg_chal_seed_{stage["seed_name"]}:'.encode() + engine.base_seed
        )
        v_aggs_compress.append(v_agg)
        wire_shares[stage['out']] = z_shares_batch.astype(object)
        gate_idx += 1

    wire_shares['x^0'] = np.zeros_like(x_shares, dtype=object)
    wire_shares['x^0'][0, 0] = 1
    parallel_x, parallel_y, parallel_seeds = [], [], []
    for i in range(m):
        q_shares = _calculate_q_shares(all_coeffs[i], wire_shares, params)
        parallel_x.append(q_shares[2])
        parallel_y.append(wire_shares['y^2'])
        parallel_seeds.append(ggm_tree.get_leaf(gate_idx))
        gate_idx += 1
        parallel_x.append(q_shares[1])
        parallel_y.append(wire_shares['y^1'])
        parallel_seeds.append(ggm_tree.get_leaf(gate_idx))
        gate_idx += 1

    v_agg, _ = engine.prove_batch_gates_aggregated_individual(
        np.hstack(parallel_x).astype(np.uint32), np.hstack(parallel_y).astype(np.uint32),
        parallel_seeds, b'compress_agg_chal_seed_4:' + engine.base_seed
    )
    v_aggs_compress.append(v_agg)
    return v_aggs_compress, gate_idx


# -----------------------------------------------------------------------------
# 主要接口函数
# -----------------------------------------------------------------------------

def mq_prime_keygen_v3(params_arg=None):
    # 使用 active_params 避免变量名冲突
    active_params = params_arg if params_arg else global_default_params

    with Timer('keygen_init'):
        s_bytes = os.urandom(active_params.n // 8)
        seed_P = os.urandom(active_params.seed_size)
        system = mq_primeCVPSystem(seed_P, active_params)
        system.generate_from_seed()

    with Timer('keygen_eval'):
        s_bits = np.unpackbits(np.frombuffer(s_bytes, dtype=np.uint8))[:active_params.n]
        p_vector = _evaluate_mq_in_field(s_bits.astype(np.uint32), system.P_A, active_params.p)

    pk = PublicKey(seed_P, p_vector.astype('>u4').tobytes())
    sk = PrivateKey(s_bytes, pk)
    return pk, sk


def sign_v3(sk: PrivateKey, message: bytes, params_arg=None) -> SignatureV3:
    # 【修复 1】: 解决 UnboundLocalError
    # 不要使用 'params' 这个名字作为局部变量，因为它也是全局导入的模块别名
    active_params = params_arg if params_arg else global_default_params

    # 【修复 2】: 添加 Timer 以显示 Micro-benchmarks
    with Timer('sign_init'):
        s = np.unpackbits(np.frombuffer(sk.s, dtype=np.uint8))[:active_params.n]
        system = mq_primeCVPSystem(sk.pk.seed_P, active_params)
        system.generate_from_seed()

        pre_hash = H(sk.s, message, sk.pk.seed_P, sk.pk.p)
        salt = H(b"salt:" + pre_hash)
        t = 0
        engine = VOLE_Engine(active_params, salt, t)

    # --- 1. 份额生成 ---
    with Timer('sign_share_gen'):
        seed_prg = AES_PRG(H(b'seed_gen_seed:' + engine.base_seed)[:16])
        seeds = [seed_prg.read(active_params.seed_size) for _ in range(active_params.num_mpc_parties)]
        share_len_bytes = active_params.n * 4
        r_shares = np.array(
            [np.frombuffer(derive_from_seed(seeds[i], 0, share_len_bytes), dtype=np.uint32) % active_params.p for i in
             range(active_params.num_mpc_parties)])
        s_int = s.astype(np.uint64)
        r_sum = np.sum(r_shares.astype(np.uint64), axis=0) % active_params.p
        delta = (s_int - r_sum + active_params.p) % active_params.p
        s_shares = r_shares.astype(np.uint64)
        s_shares[0, :] = (s_shares[0, :] + delta) % active_params.p
        s_shares = s_shares.astype(np.uint32)

    # --- 2. MPC 模拟 (VOLE Proving) ---
    with Timer('sign_mpc_eval'):
        num_mults = system.get_mpc_multiplication_count()
        ggm_depth = math.ceil(math.log2(num_mults)) if num_mults > 0 else 0
        ggm_prg = AES_PRG(H(b'ggm_root_seed:' + engine.base_seed)[:16])
        ggm_root_seed = ggm_prg.read(active_params.seed_size)
        ggm_tree = GGMTreeWithCache(ggm_root_seed, ggm_depth)

        ntt_engine = system.P_A.ntt_engine
        s_ntt_shares = np.array([ntt_engine.ntt(s_share) for s_share in s_shares])
        num_independent_gates = active_params.n
        x_shares_batch = np.hstack([s_ntt_shares[:, i:i + 1] for i in range(num_independent_gates)])
        seeds_0_batch = [ggm_tree.get_leaf(i) for i in range(num_independent_gates)]

        # 证明独立门
        v_agg_independent, _ = engine.prove_batch_gates_aggregated_individual(
            x_shares_batch.astype(np.uint32), x_shares_batch.astype(np.uint32), seeds_0_batch,
            b'independent_agg_chal_seed:' + engine.base_seed
        )

        # 重建与计算 Compress 电路
        s_reconstructed = np.sum(s_shares, axis=0, dtype=np.uint64) % active_params.p
        p_b_from_shares = _evaluate_mq_in_field(s_reconstructed, system.P_B, active_params.p)
        pb_share_prg = AES_PRG(H(b'pb_share_seed:' + engine.base_seed)[:16])

        def share_pb(secret_val):
            shares = np.zeros((active_params.num_mpc_parties, secret_val.shape[0]), dtype=np.uint32)
            shares[1:, :] = np.frombuffer(
                pb_share_prg.read((active_params.num_mpc_parties - 1) * secret_val.shape[0] * 4),
                dtype=np.uint32).reshape(active_params.num_mpc_parties - 1, -1) % active_params.p
            sum_other = np.sum(shares[1:, :].astype(np.uint64), axis=0) % active_params.p
            shares[0, :] = (secret_val.astype(np.uint64) - sum_other + active_params.p) % active_params.p
            return shares

        p_b_shares = share_pb(p_b_from_shares)

        # 证明 Compress 电路
        v_aggs_compress, _ = mpc_evaluate_compress_sqrt(
            engine, ggm_tree, p_b_shares[:, 0:1], system.Compress,
            num_independent_gates, active_params
        )

    # --- 3. 承诺 (Merkle Tree Build) ---
    with Timer('sign_commit_gen'):
        seed_commitments = [H(seed) for seed in seeds]
        delta_commitment = H(delta.astype(np.uint32).tobytes())
        all_ggm_leaves = ggm_tree.populate_all_leaves()[:num_mults]
        all_commitments = seed_commitments + [delta_commitment] + all_ggm_leaves
        merkle_root, merkle_tree, unpadded_sizes = build_merkle_tree(all_commitments, arity=ARITY)

    # --- 4. 挑战生成 (Fiat-Shamir) ---
    with Timer('sign_challenge'):
        challenge_hasher = hashlib.sha256()
        challenge_hasher.update(b'faest_challenge_seed:')
        challenge_hasher.update(salt)
        challenge_hasher.update(merkle_root)
        indices_to_open = set()
        prg_seed = challenge_hasher.digest()
        chal_prg = AES_PRG(prg_seed[:16])
        while len(indices_to_open) < active_params.num_challenge_parties:
            indices_to_open.add(int.from_bytes(chal_prg.read(4), 'big') % active_params.num_mpc_parties)
        sorted_indices_to_open = sorted(list(indices_to_open))

    # --- 5. 证明生成 (Response) ---
    with Timer('sign_proof_gen'):
        revealed_seeds = [seeds[i] for i in sorted_indices_to_open]
        merkle_indices_to_reveal = set(sorted_indices_to_open)
        merkle_indices_to_reveal.add(active_params.num_mpc_parties)
        batch_merkle_proof = get_batch_merkle_proof(merkle_tree, sorted(list(merkle_indices_to_reveal)), unpadded_sizes,
                                                    arity=ARITY)

        all_h_w0s = [H(ggm_tree.get_leaf(i)) for i in range(num_mults)]
        h_w0_merkle_root, _, _ = build_merkle_tree(all_h_w0s, arity=ARITY)

        proof_buffer = b''
        proof_buffer += merkle_root
        proof_buffer += h_w0_merkle_root
        proof_buffer += ggm_root_seed
        proof_buffer += _evaluate_mq_in_field(s, system.P_A, active_params.p).astype('>u4').tobytes()
        proof_buffer += pack_bytes_with_len(b"".join([pack_uint32(i) for i in sorted_indices_to_open]))
        proof_buffer += delta.astype(np.uint32).tobytes()
        proof_buffer += pack_list_of_bytes(revealed_seeds)
        proof_buffer += pack_list_of_bytes(batch_merkle_proof)

        proof_buffer += v_agg_independent.tobytes()
        for v_agg in v_aggs_compress:
            proof_buffer += v_agg.tobytes()

    proof_list = [proof_buffer]
    commitment_hash = H(proof_buffer)
    return SignatureV3(salt=salt, commitment_hash=commitment_hash, proofs=proof_list)


def verify_v3(pk: PublicKey, message: bytes, signature: SignatureV3, params_arg=None) -> bool:
    active_params = params_arg if params_arg else global_default_params

    with Timer('verify_init'):
        system = mq_primeCVPSystem(pk.seed_P, active_params)
        system.generate_from_seed()
        p_vector = np.frombuffer(pk.p, dtype='>u4')

    # --- 1. 解包 ---
    with Timer('verify_unpack'):
        if len(signature.proofs) != 1: return False
        proof_bytes = signature.proofs[0]
        if H(proof_bytes) != signature.commitment_hash: return False

        try:
            offset = 0
            merkle_root, offset = proof_bytes[offset:offset + 32], offset + 32
            h_w0_merkle_root, offset = proof_bytes[offset:offset + 32], offset + 32

            # 动态种子长度
            seed_len = active_params.seed_size
            ggm_root_seed, offset = proof_bytes[offset:offset + seed_len], offset + seed_len

            final_output_from_proof, offset = np.frombuffer(proof_bytes[offset:offset + active_params.m * 4],
                                                            dtype='>u4'), offset + active_params.m * 4
            indices_bytes, offset = unpack_bytes_with_len(proof_bytes, offset)
            indices_to_open = [int.from_bytes(indices_bytes[i:i + 4], 'big') for i in range(0, len(indices_bytes), 4)]
            delta_bytes, offset = proof_bytes[offset:offset + active_params.n * 4], offset + active_params.n * 4
            delta = np.frombuffer(delta_bytes, dtype=np.uint32)
            revealed_seeds, offset = unpack_list_of_bytes(proof_bytes, offset)
            batch_merkle_proof, offset = unpack_list_of_bytes(proof_bytes, offset)

            v_agg_independent_bytes, offset = proof_bytes[offset:offset + 4], offset + 4
            v_aggs_compress_bytes = [proof_bytes[offset + i * 4:offset + (i + 1) * 4] for i in range(4)]
            offset += 16
        except Exception:
            return False

    # --- 2. 种子重建与 Merkle 验证 ---
    with Timer('verify_reconstruct_seeds'):
        num_mults = system.get_mpc_multiplication_count()
        ggm_depth = math.ceil(math.log2(num_mults)) if num_mults > 0 else 0
        num_independent_gates = active_params.n
        t = 0
        engine = VOLE_Engine(active_params, signature.salt, t)

        seed_prg = AES_PRG(H(b'seed_gen_seed:' + engine.base_seed)[:16])
        all_seeds_recalculated = [seed_prg.read(active_params.seed_size) for _ in range(active_params.num_mpc_parties)]
        seed_map = {idx: seed for idx, seed in zip(indices_to_open, revealed_seeds)}

        # 验证被揭示的种子
        for i in indices_to_open:
            if i not in seed_map or all_seeds_recalculated[i] != seed_map[i]:
                return False

        revealed_leaf_hashes_main = {active_params.num_mpc_parties: H(delta_bytes)}
        for i in indices_to_open: revealed_leaf_hashes_main[i] = H(all_seeds_recalculated[i])
        total_main_leaves = active_params.num_mpc_parties + 1 + num_mults

        if not verify_batch_merkle_proof(merkle_root, batch_merkle_proof, revealed_leaf_hashes_main, total_main_leaves,
                                         arity=ARITY):
            return False

    # --- 3. 份额恢复 ---
    with Timer('verify_recover_shares'):
        share_len_bytes = active_params.n * 4
        r_shares = np.array(
            [np.frombuffer(derive_from_seed(all_seeds_recalculated[i], 0, share_len_bytes),
                           dtype=np.uint32) % active_params.p for
             i in range(active_params.num_mpc_parties)])
        full_s_shares = r_shares.astype(np.uint64)
        full_s_shares[0, :] = (full_s_shares[0, :] + delta.astype(np.uint64)) % active_params.p
        full_s_shares = full_s_shares.astype(np.uint32)

        verifier_ggm_tree = GGMTree(ggm_root_seed, ggm_depth)
        all_h_w0s_recalculated = [H(verifier_ggm_tree.get_leaf(i)) for i in range(num_mults)]
        recalculated_h_w0_root = build_merkle_tree(all_h_w0s_recalculated, arity=ARITY)[0]
        if recalculated_h_w0_root != h_w0_merkle_root:
            return False

    # --- 4. MPC 验证 (VOLE Verification) ---
    with Timer('verify_mpc_check'):
        ntt_engine = system.P_A.ntt_engine
        full_s_ntt_shares = np.array([ntt_engine.ntt(s_share) for s_share in full_s_shares])
        x_batch_all = np.hstack([full_s_ntt_shares[:, i:i + 1] for i in range(num_independent_gates)])
        v_agg_independent_from_proof = int(np.frombuffer(v_agg_independent_bytes, dtype=np.uint32)[0])

        if not engine.verify_batch_gates_aggregated_individual(v_agg_independent_from_proof,
                                                               b'independent_agg_chal_seed:' + engine.base_seed,
                                                               x_batch_all, x_batch_all, verifier_ggm_tree,
                                                               list(range(num_independent_gates))):
            return False

        s_reconstructed = np.sum(full_s_shares, axis=0, dtype=np.uint64) % active_params.p
        pb_reconstructed = _evaluate_mq_in_field(s_reconstructed, system.P_B, active_params.p)
        pb_share_prg = AES_PRG(H(b'pb_share_seed:' + engine.base_seed)[:16])

        def share_pb(secret_val):
            shares = np.zeros((active_params.num_mpc_parties, secret_val.shape[0]), dtype=object)
            r_bytes = pb_share_prg.read((active_params.num_mpc_parties - 1) * secret_val.shape[0] * 4)
            flat_s = np.frombuffer(r_bytes, dtype=np.uint32) % active_params.p
            shares[1:, :] = flat_s.reshape(active_params.num_mpc_parties - 1, -1).astype(object)
            sum_other = np.sum(shares[1:, :].astype(np.uint64), axis=0) % active_params.p
            shares[0, :] = (secret_val.astype(np.uint64) - sum_other + active_params.p) % active_params.p
            return shares.astype(object)

        p_b_shares = share_pb(pb_reconstructed)
        v_aggs_from_proof = [int(np.frombuffer(b, dtype=np.uint32)[0]) for b in v_aggs_compress_bytes]
        wire_shares = {}
        gate_idx = num_independent_gates

        stages = [
            {'name': 'x^2', 'x_in': 'x^1', 'y_in': 'x^1', 'out': 'x^2', 'seed_name': '1'},
            {'name': 'x^3', 'x_in': 'x^2', 'y_in': 'x^1', 'out': 'y^1', 'seed_name': '2'},
            {'name': 'y^2', 'x_in': 'y^1', 'y_in': 'y^1', 'out': 'y^2', 'seed_name': '3'},
        ]
        wire_shares['x^1'] = p_b_shares

        for i, stage in enumerate(stages):
            x_sh = wire_shares[stage['x_in']]
            y_sh = wire_shares[stage['y_in']]
            if not engine.verify_batch_gates_aggregated_individual(v_aggs_from_proof[i],
                                                                   f'compress_agg_chal_seed_{stage["seed_name"]}:'.encode() + engine.base_seed,
                                                                   x_sh, y_sh, verifier_ggm_tree, [gate_idx]):
                return False
            x_rec = int(np.sum(x_sh.astype(np.uint64), axis=0)[0]) % active_params.p
            y_rec = int(np.sum(y_sh.astype(np.uint64), axis=0)[0]) % active_params.p
            z_rec = (x_rec * y_rec) % active_params.p
            z_share_prg = AES_PRG(H(b'z_share_seed:' + verifier_ggm_tree.get_leaf(gate_idx))[:16])
            flat_s = np.frombuffer(z_share_prg.read((active_params.num_mpc_parties - 1) * 4),
                                   dtype=np.uint32) % active_params.p
            z_shares = np.zeros((active_params.num_mpc_parties, 1), dtype=object)
            sum_other = np.sum(flat_s.astype(np.uint64)) % active_params.p
            z_shares[1:, 0] = flat_s.astype(object)
            z_shares[0, 0] = (z_rec - int(sum_other) + active_params.p) % active_params.p
            wire_shares[stage['out']] = z_shares
            gate_idx += 1

        wire_shares['x^0'] = np.zeros_like(p_b_shares, dtype=object)
        wire_shares['x^0'][0, 0] = 1
        parallel_x, parallel_y, parallel_indices = [], [], []
        for i in range(active_params.m):
            q_shares = _calculate_q_shares(system.Compress[i], wire_shares, active_params)
            parallel_x.append(q_shares[2])
            parallel_y.append(wire_shares['y^2'])
            parallel_indices.append(gate_idx)
            gate_idx += 1
            parallel_x.append(q_shares[1])
            parallel_y.append(wire_shares['y^1'])
            parallel_indices.append(gate_idx)
            gate_idx += 1

        if not engine.verify_batch_gates_aggregated_individual(v_aggs_from_proof[3],
                                                               b'compress_agg_chal_seed_4:' + engine.base_seed,
                                                               np.hstack(parallel_x), np.hstack(parallel_y),
                                                               verifier_ggm_tree, parallel_indices):
            return False

    if not np.array_equal(final_output_from_proof, p_vector): return False

    return True