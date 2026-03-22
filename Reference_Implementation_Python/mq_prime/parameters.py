# mq_prime/parameters.py

from dataclasses import dataclass

@dataclass(frozen=True)
class SecurityParametersV3:
    """
    3.0版本安全参数 - 使用 FAEST-style 的 VOLE-in-the-head 协议
    """
    # --- mq-prime 核心代数参数 (保持不变) ---
    p: int
    n: int
    w: int
    m: int
    d: int

    # --- FAEST-style 框架参数 ---
    num_mpc_parties: int        # N，MPC参与方总数
    num_mpc_rounds: int         # T，Fiat-Shamir证明的轮数 (在FAEST架构中固定为1)
    num_challenge_parties: int  # τ (tau), 每轮证明中要打开的参与方数量

    # --- 密码学原语尺寸 (保持不变) ---
    seed_size: int
    salt_size: int
    hash_digest_size: int

NTT_PRIME = 2013265921

# --- 论文中的 Set C (Performance Optimized) ---
# n=64, m=64, N=128, Tau=19
mq_prime_SET_C_PARAMS = SecurityParametersV3(
    p=NTT_PRIME,
    n=64,   # <--- 修正为 64
    m=64,   # <--- 修正为 64
    d=8,    # 这里的 d 对应论文里的 d? 还是其他？需确认论文 d>=6。这里保持 8 也可以。
    w=10,   # 这个 w 是什么？如果是 witness 扩展系数，可能需要调
    num_mpc_parties=128, # <--- 修正为 128
    num_mpc_rounds=1,
    num_challenge_parties=19,
    seed_size=16,
    salt_size=32,
    hash_digest_size=32
)

mq_prime_L1_V3_PARAMS = SecurityParametersV3(
    p=NTT_PRIME, # <--- 更新
    n=256,
    m=256,
    d=8, w=10,
    num_mpc_parties=256,
    num_mpc_rounds=1,
    num_challenge_parties=19,
    seed_size=16,
    salt_size=32,
    hash_digest_size=32
)

mq_prime_L3_V3_PARAMS = SecurityParametersV3(
    p=NTT_PRIME, # <--- 更新
    n=512,
    m=512,
    d=8, w=10,
    num_mpc_parties=256,
    num_mpc_rounds=1,
    num_challenge_parties=29,
    seed_size=24,
    salt_size=32,
    hash_digest_size=32
)

mq_prime_L5_V3_PARAMS = SecurityParametersV3(
    p=NTT_PRIME, # <--- 更新
    n=512,
    m=512,
    d=8, w=10,
    num_mpc_parties=256,
    num_mpc_rounds=1,
    num_challenge_parties=38,
    seed_size=32,
    salt_size=32,
    hash_digest_size=32
)


DEFAULT_PARAMS_V3 = mq_prime_SET_C_PARAMS
