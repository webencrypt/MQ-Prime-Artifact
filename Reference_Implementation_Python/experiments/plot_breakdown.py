import matplotlib.pyplot as plt
import numpy as np

# --- 1. 全局样式 (学术风) ---
plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 12,
    'axes.labelsize': 14,
    'axes.titlesize': 16,
    'figure.dpi': 300,
    'axes.grid': True,
    'grid.alpha': 0.3,
    'grid.linestyle': '--'
})

# --- 2. 实测数据录入 (ms -> us) ---

# Set C: n=64, N=64, Tau=11 (Fast / Table 2 Parameters)
tau_c = 11
# 数据来源: 最新的 C bench_sign.c 测试结果 (0.045ms total)
c_ggm   = 0.000100 * 1000 * tau_c
c_hash  = 0.003636 * 1000 * tau_c
c_arith = 0.000400 * 1000 * tau_c

# Set B: n=128, N=128, Tau=19 (Recommended)
tau_b = 19
# 数据来源: 最新的 C bench_sign.c 测试结果 (0.062ms total)
b_ggm   = 0.000307 * 1000 * tau_b
b_hash  = 0.001511 * 1000 * tau_b
b_arith = 0.001464 * 1000 * tau_b

# Set A: n=256, N=256, Tau=16 (Conservative)
tau_a = 16
# 数据来源: 最新的 C bench_sign.c 测试结果 (0.121ms total)
a_ggm   = 0.000550 * 1000 * tau_a
a_hash  = 0.002517 * 1000 * tau_a
a_arith = 0.004529 * 1000 * tau_a

# --- 3. 数据打包 ---
labels = [r'Set C' + '\n($n=64$)',
          r'Set B' + '\n($n=128$)',
          r'Set A' + '\n($n=256$)']

ggm_data = np.array([c_ggm, b_ggm, a_ggm])
hash_data = np.array([c_hash, b_hash, a_hash])
arith_data = np.array([c_arith, b_arith, a_arith])

total_data = ggm_data + hash_data + arith_data

# --- 4. 绘图 ---
fig, ax = plt.subplots(figsize=(8, 6))
width = 0.55

# 配色
c_ggm_col = '#4E79A7'   # 蓝
c_hash_col = '#F28E2B'  # 橙
c_arith_col = '#59A14F' # 绿

p1 = ax.bar(labels, ggm_data, width, label='GGM Expansion', color=c_ggm_col, edgecolor='white', linewidth=0.5)
p2 = ax.bar(labels, hash_data, width, bottom=ggm_data, label='Commitment (Hash)', color=c_hash_col, edgecolor='white', linewidth=0.5)
p3 = ax.bar(labels, arith_data, width, bottom=ggm_data+hash_data, label='VOLE Arithmetic', color=c_arith_col, edgecolor='white', linewidth=0.5)

# --- 5. 标注 ---

# 总时间标签
for i, total in enumerate(total_data):
    ax.text(i, total + 5, rf"{total:.1f} $\mu$s", ha='center', va='bottom', fontsize=12, fontweight='bold')

# 百分比标签
def add_labels(rects, data_array):
    for i, rect in enumerate(rects):
        height = rect.get_height()
        pct = height / total_data[i] * 100
        if pct > 5: # 只有占比大于5%才显示
            ax.text(rect.get_x() + rect.get_width()/2., rect.get_y() + height/2.,
                    f"{pct:.0f}%",
                    ha='center', va='center', color='white', fontsize=10, fontweight='bold')

add_labels(p1, ggm_data)
add_labels(p2, hash_data)
add_labels(p3, arith_data)

# --- 6. 装饰 ---
ax.set_ylabel(r'Total Signing Time ($\mu$s)')
ax.set_title(r'Performance Scalability Analysis', pad=15)
ax.set_ylim(0, max(total_data) * 1.15)

# 网格
ax.grid(False, axis='x')
ax.grid(True, axis='y')

ax.legend(loc='upper left', frameon=True, framealpha=0.95)

plt.tight_layout()
save_path = 'figures/breakdown_real.png'
plt.savefig(save_path, dpi=300, bbox_inches='tight')
print(f"✅ Chart saved to {save_path}")
plt.show()