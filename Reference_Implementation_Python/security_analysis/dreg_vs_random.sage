import matplotlib.pyplot as plt
import numpy as np
import os

# Theoretical Degree of Regularity (Dreg) using Macaulay bound for semi-regular systems.
# The formula is: Dreg = 1 + sum(d_i - 1) for i = 1 to m

def dreg_random_mq(n):
    # For random MQ, we have m=n equations of degree 2
    # Dreg = 1 + n * (2 - 1) = n + 1
    return n + 1

def dreg_mq_prime(n, d):
    # For MQ-Prime, we have m=n equations.
    # Practically, Structure A gives (n-1) quadratic equations,
    # and Structure B adds 1 high-degree equation of degree d.
    # Actually, if Structure B is added to all n equations, the maximum degree is d for all of them.
    # However, the structure B is a univariate polynomial f(x) of degree d.
    # As stated in the paper's graph: 17 vs 13 for n=12 (17 = 12 + 6 - 1).
    # This implies Dreg = 1 + (n-1)*(2-1) + 1*(d-1) = n + d - 1.
    return n + d - 1

def main():
    print("=========================================================")
    print(" D_reg Comparison: MQ-Prime vs. Random MQ (Theoretical)")
    print("=========================================================")
    
    n_vals = [8, 10, 12]
    d = 6
    
    results = {}
    for n in n_vals:
        dreg_mq = dreg_mq_prime(n, d)
        dreg_rand = dreg_random_mq(n)
        results[n] = {'mq_prime': dreg_mq, 'random': dreg_rand}
        
    print(f"{'n':<5} | {'D_reg (MQ-Prime)':<18} | {'D_reg (Random MQ)':<18}")
    print("-" * 50)
    for n in n_vals:
        print(f"{n:<5} | {results[n]['mq_prime']:<18} | {results[n]['random']:<18}")
        
    # --- 绘图 ---
    n_arr = np.array(n_vals)
    mq_prime_dregs = np.array([results[n]['mq_prime'] for n in n_vals])
    rand_dregs = np.array([results[n]['random'] for n in n_vals])

    plt.figure(figsize=(8, 5))
    plt.plot(n_arr, mq_prime_dregs, marker='o', linestyle='-', color='r', label='MQ-Prime ($d=6$)')
    plt.plot(n_arr, rand_dregs, marker='s', linestyle='--', color='b', label='Random MQ ($d=2$)')
    
    plt.title('Degree of Regularity Growth Comparison')
    plt.xlabel('Dimension $n$')
    plt.ylabel('Degree of Regularity ($D_{reg}$)')
    plt.grid(True)
    plt.legend()
    plt.xticks(n_vals)
    
    save_path = 'dreg_comparison_plot.png'
    plt.savefig(save_path)
    print(f"\nPlot saved successfully to {save_path}")

if __name__ == '__main__':
    main()
