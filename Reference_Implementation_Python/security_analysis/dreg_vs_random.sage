import time
import sys
import matplotlib.pyplot as plt
import numpy as np

# 设置随机种子
set_random_seed(42)

def analyze_system_dreg(n, d, p=65537, is_random=False):
    """
    分析一个系统的 Degree of Regularity
    """
    R = PolynomialRing(GF(p), names=[f's{i}' for i in range(n)])
    s = vector(R, R.gens())
    
    system_polys = []
    
    if is_random:
        # --- 构造纯随机 MQ ---
        print(f"--- Analyzing Random MQ: n={n} ---")
        for _ in range(n):
            poly = 0
            for i in range(n):
                for j in range(i, n):
                    poly += randint(0, p-1) * s[i] * s[j]
            system_polys.append(poly)
    else:
        # --- 构造 MQ-Prime ---
        print(f"--- Analyzing MQ-Prime: n={n}, d={d} ---")
        # Structure A (NTT)
        w = GF(p).multiplicative_generator() ^ ((p - 1) // n)
        M_ntt = matrix(GF(p), n, n, lambda i, j: w^(i * j))
        M_inv = M_ntt.inverse()
        s_ntt = M_ntt * s
        Q = [randint(1, p-1) for _ in range(n)]
        P_A = M_inv * vector([Q[i] * s_ntt[i]^2 for i in range(n)])
        
        # Structure B
        L_B = random_vector(GF(p), n)
        x = L_B * s
        f_x = sum([randint(1, p-1) * x^k for k in range(2, d+1)])
        
        system_polys = [P_A[i] + f_x - randint(0,p-1) for i in range(n)]

    # --- 计算 D_reg ---
    I = R.ideal(system_polys)
    max_degree = -1
    
    try:
        gb = I.groebner_basis(algorithm='libsingular:slimgb')
        if gb:
            max_degree = max(f.degree() for f in gb)
        print(f"Max Degree in GB: {max_degree}")
    except Exception as e:
        print(f"GB computation failed: {e}")
        
    return max_degree

# --- 主实验循环 ---
print("=========================================================")
print(" D_reg Comparison: MQ-Prime vs. Random MQ")
print("=========================================================")

results = {}
test_range = range(8, 13, 2) # n=12 可能会很慢

for n in test_range:
    # 跑 mq_prime
    d_reg_mq_prime = analyze_system_dreg(n, d=6, p=65537)
    
    # 跑 Random (d=2)
    d_reg_rand = analyze_system_dreg(n, d=2, p=65537, is_random=True)
    
    if d_reg_mq_prime > 0 and d_reg_rand > 0:
        results[n] = {'mq_prime': d_reg_mq_prime, 'random': d_reg_rand}
    else:
        break

# --- 打印结果 ---
print("\n--- Summary of Results ---")
print(f"{'n':<5} | {'D_reg (mq_prime)':<15} | {'D_reg (Random)'}")
print("-" * 40)
for n, res in results.items():
    print(f"{n:<5} | {res['mq_prime']:<15} | {res['random']}")

# --- 绘图 ---
if results:
    n_vals = np.array(list(results.keys()))
    mq_prime_dregs = np.array([res['mq_prime'] for res in results.values()])
    rand_dregs = np.array([res['random'] for res in results.values()])

    plt.figure(figsize=(8, 5))
    plt.plot(n_vals, mq_prime_dregs, marker='o', linestyle='-', color='r', label='MQ-Prime ($d=6$)')
    plt.plot(n_vals, rand_dregs, marker='s', linestyle='--', color='b', label='Random MQ ($d=2$)')
    
    plt.title('Degree of Regularity Growth Comparison')
    plt.xlabel('Dimension $n$')
    plt.ylabel('Max Degree in Gröbner Basis ($D_{reg}$)')
    plt.grid(True)
    plt.legend()
    plt.savefig('dreg_comparison_plot.png')
    plt.show()