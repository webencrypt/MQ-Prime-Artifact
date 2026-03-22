import sys

# 设置随机种子
set_random_seed(42)

def check_rank_profile(n, d, p=65537):
    print(f"\n--- Checking Rank Profile for n={n}, d={d} ---")

    # 1. 定义环和变量
    R = PolynomialRing(GF(p), names=[f's{i}' for i in range(n)])
    s = vector(R, R.gens())

    # 2. 构建 mq_prime 结构 (Structure A)
    # 寻找 n 次单位根 (前提: n 整除 p-1)
    if (p - 1) % n != 0:
        print(f"Error: n={n} does not divide p-1, cannot exist NTT.")
        return

    g = GF(p).multiplicative_generator()
    w = g ^ ((p - 1) // n)

    # 构建 Fourier 矩阵 (NTT)
    M_ntt = matrix(GF(p), n, n, lambda i, j: w^(i * j))
    M_inv = M_ntt.inverse()

    # s_ntt = NTT(s)
    s_ntt = M_ntt * s

    # 逐点平方: s_ntt[i]^2
    s_sq = vector(R, [val^2 for val in s_ntt])

    # 随机对角矩阵 Q (这里简化为向量逐点乘)
    Q_vec = vector(GF(p), [randint(1, p-1) for _ in range(n)])
    s_Q_sq = vector(R, [Q_vec[i] * s_sq[i] for i in range(n)])

    # iNTT 变换回来
    P_A = M_inv * s_Q_sq

    # 3. 构建 Structure B (High Degree)
    # 线性投影 x
    L_B = random_vector(GF(p), n)
    x = (L_B * s) # 标量多项式

    # 高次多项式 P_B
    P_B_poly = sum([randint(1, p-1) * x^k for k in range(2, d+1)])

    # 组合: mq_prime = P_A + P_B (加到每一个分量上，或者作为第 m 个方程)
    # 这里我们模拟加到每个分量上，最大限度破坏结构
    P_mq_prime = vector([y + P_B_poly for y in P_A])

    # 4. 构建纯随机系统 (作为对照组)
    P_rand_list = []
    for _ in range(n):
        # 生成随机二次型: s * M * s
        mat = random_matrix(GF(p), n, n)
        poly = s * mat * s
        P_rand_list.append(poly)
    P_rand = vector(P_rand_list)

    # 5. 计算微分秩 (Differential Rank)
    # 核心思想：计算 Jacobian 矩阵在随机点的秩
    print("Computing Jacobian at random point...")

    # 随机点 a
    a_point = [randint(0, p-1) for _ in range(n)]
    dict_sub = {s[i]: a_point[i] for i in range(n)}

    # 计算 mq_prime 的 Jacobian
    J_mq_prime = jacobian(P_mq_prime, s)
    J_mq_prime_eval = J_mq_prime.subs(dict_sub)
    rank_h = J_mq_prime_eval.rank()

    # 计算 Random 的 Jacobian
    J_rand = jacobian(P_rand, s)
    J_rand_eval = J_rand.subs(dict_sub)
    rank_r = J_rand_eval.rank()

    print(f"mq_prime Rank:  {rank_h} / {n}")
    print(f"Random Rank: {rank_r} / {n}")

    if rank_h == n and rank_r == n:
        print(">> RESULT: mq_prime has FULL RANK (Same as Random). No MinRank defect.")
    else:
        print(f">> RESULT: Rank Defect? mq_prime={rank_h}, Random={rank_r}")

# 运行测试
check_rank_profile(n=16, d=6)
check_rank_profile(n=32, d=6)