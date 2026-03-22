import time
import sys

# 设置随机种子
set_random_seed(42)

def generate_and_attack_mq_prime(n, d, p=65537):
    """
    生成一个规模为 n, 包含度数为 d 的 Structure B 的 mq_prime 系统并攻击。
    """
    print(f"--- Testing mq_prime with n={n}, d={d}, p={p} ---")

    # 1. 定义多项式环
    R = PolynomialRing(GF(p), names=[f's{i}' for i in range(n)])
    s_vars = R.gens()
    s_vec_sym = vector(R, s_vars)

    # 2. 模拟 Structure A (NTT-based Quadratic)
    M_ntt = random_matrix(GF(p), n, n)
    while not M_ntt.is_invertible():
        M_ntt = random_matrix(GF(p), n, n)

    s_ntt_sym = M_ntt * s_vec_sym
    s_sq_ntt_sym = vector(R, [val^2 for val in s_ntt_sym])

    # 模拟最终的线性混合层
    M_final = random_matrix(GF(p), n, n)
    y_A_sym = M_final * s_sq_ntt_sym

    # --- 3. 【核心修改】: 模拟 Structure B (High-Degree Polynomial) ---
    # 3.1. 构造线性投影 x
    L_B = random_vector(GF(p), n)
    x_sym = L_B * s_vec_sym

    # 3.2. 构造高次多项式 f(x)
    # 我们只需要一个高次多项式来破坏结构，所以只加一个
    f_coeffs = [randint(0, p-1) for _ in range(d+1)]
    f_sym = sum(f_coeffs[k] * (x_sym^k) for k in range(d+1))

    # --- 4. 构建最终方程组 y = y_A + y_B ---
    # 这里我们简化：m-1 个方程来自 Structure A，1 个方程来自 Structure B
    # 这样可以观察到高次项的影响

    # 计算真实值 (Public Key)
    s_true = vector(GF(p), [randint(0, p - 1) for _ in range(n)])

    y_A_true = M_final * vector(GF(p), [(val^2) for val in M_ntt * s_true])
    x_true = L_B * s_true
    f_true = sum(f_coeffs[k] * (x_true^k) for k in range(d+1))

    system_polys = []
    # m-1 个二次方程
    for i in range(n - 1):
        system_polys.append(y_A_sym[i] - y_A_true[i])

    # 1 个高次方程
    system_polys.append(f_sym - f_true)

    # 5. 发起 Gröbner Basis 攻击
    print(f"System generated. {n} vars, {n-1} quadratic eqns, 1 degree-{d} eqn.")
    print("Computing Gröbner Basis (F4 algorithm)...")

    I = R.ideal(system_polys)
    t_start = time.time()
    try:
        gb = I.groebner_basis(algorithm='libsingular:slimgb')
    except Exception as e:
        print(f"GB computation failed or interrupted: {e}")
        return None

    duration = t_end = time.time() - t_start
    print(f"GB Computed in {duration:.4f} seconds.")

    is_solved = len(gb) > 0 and I.dimension() == 0
    print(f"Solved: {is_solved}")

    return duration


def compare_structure_vs_random(n, d, p=65537):
    print(f"\n--- Comparing Structured vs Random (n={n}) ---")
    R = PolynomialRing(GF(p), names=[f's{i}' for i in range(n)])
    s = vector(R, R.gens())
    
    # 1. 构造 Structured (mq_prime with real NTT)
    w = GF(p).multiplicative_generator() ^ ((p-1)//n)
    M_ntt = matrix(GF(p), n, n, lambda i, j: w^(i*j)) # Real Fourier Matrix
    M_inv = M_ntt.inverse()
    s_ntt = M_ntt * s
    Q = [randint(1, p-1) for _ in range(n)]
    P_A = M_inv * vector([Q[i] * s_ntt[i]^2 for i in range(n)])
    
    # Add Structure B
    L_B = random_vector(GF(p), n)
    x = L_B * s
    f_x = sum([randint(1, p-1) * x^k for k in range(2, d+1)])
    
    sys_struct = [P_A[i] + f_x for i in range(n)] # Structure A + B
    
    # 2. 构造 Random
    sys_rand = []
    for _ in range(n):
        # 随机二次方程
        poly = 0
        for i in range(n):
            for j in range(i, n):
                poly += randint(0, p-1) * s[i] * s[j]
        sys_rand.append(poly)
        
    # --- Attack Structured ---
    t0 = time.time()
    _ = R.ideal(sys_struct).groebner_basis('libsingular:slimgb')
    t_struct = time.time() - t0
    print(f"Structured Time: {t_struct:.4f} s")
    
    # --- Attack Random ---
    t0 = time.time()
    _ = R.ideal(sys_rand).groebner_basis('libsingular:slimgb')
    t_rand = time.time() - t0
    print(f"Random Time:     {t_rand:.4f} s")
    
    ratio = t_struct / t_rand
    print(f"Ratio (Struct/Rand): {ratio:.2f}")

# 跑一下 n=10, 12
compare_structure_vs_random(10, 6)
compare_structure_vs_random(12, 6)

# --- 主实验循环 ---
print("=========================================================")
print(" mq_prime Security Experiment vs. Degree d (SageMath)")
print(" Goal: Estimate complexity increase with higher degree")
print("=========================================================")

results_vs_d = {}

# 固定一个很小的 n (例如 n=8)，否则跑不动
n_fixed = 8
# 测试 d 从 2 到 10
degree_range = range(2, 11)

for d in degree_range:
    time_taken = generate_and_attack_mq_prime(n_fixed, d, p=65537)

    if time_taken:
        results_vs_d[d] = time_taken
    else:
        print(f"Stopping at d={d} due to failure or timeout.")
        break

print("\n--- Summary of Results (n=8 fixed) ---")
print(f"{'d':<5} | {'Time (s)':<15}")
print("-" * 25)
for d, t in results_vs_d.items():
    print(f"{d:<5} | {t:<15.4f}")