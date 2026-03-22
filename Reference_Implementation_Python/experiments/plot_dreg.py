import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as ticker

# --- 1. 全局样式 ---
plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 12,
    'axes.labelsize': 14,
    'axes.titlesize': 16,
    'figure.dpi': 300,
    'axes.grid': True,
    'grid.alpha': 0.5,
    'grid.linestyle': ':'
})

# --- 2. 实验数据 (假设 n=12 的数据也跑出来了) ---
# 请根据你的实际数据更新
results = {
    8: {'mq_prime': 13, 'random': 9},
    10: {'mq_prime': 15, 'random': 11},
    12: {'mq_prime': 17, 'random': 13}
}

n_vals = np.array(list(results.keys()))
mq_prime_dregs = np.array([res['mq_prime'] for res in results.values()])
rand_dregs = np.array([res['random'] for res in results.values()])

# --- 3. 绘图 ---
fig, ax = plt.subplots(figsize=(8, 5))

# 绘制 MQ-Prime (红色实线)
ax.plot(n_vals, mq_prime_dregs, marker='o', markersize=8, linestyle='-', color='#D62728', label=r'MQ-Prime (Our Scheme)')
# 绘制 Random MQ (蓝色虚线)
ax.plot(n_vals, rand_dregs, marker='s', markersize=8, linestyle='--', color='#1f77b4', label=r'Random Quadratic System (Standard MQ)')

# --- 4. 装饰 ---
ax.set_title(r'Degree of Regularity Growth Comparison')
ax.set_xlabel(r'System Dimension $n$')
ax.set_ylabel(r'Max Degree in Gröbner Basis ($D_{reg}$)')

# 设置坐标轴刻度为整数
ax.xaxis.set_major_locator(ticker.MaxNLocator(integer=True))
ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
ax.set_ylim(bottom=8) # Y轴从8开始，让增长更明显

# 添加注释
# 指向 MQ-Prime 在 n=12 的点
ax.annotate(r'Higher $D_{reg}$ implies' + '\n' + r'higher algebraic hardness',
            xy=(12, 17), xycoords='data',
            xytext=(9.5, 16.5), textcoords='data',
            arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2", color='black'),
            bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", lw=1, alpha=0.9))

# 图例
ax.legend(loc='lower right')

plt.tight_layout()
save_path = 'figures/dreg_comparison_final.png'
plt.savefig(save_path, dpi=300, bbox_inches='tight')
print(f"✅ Chart saved to {save_path}")
plt.show()