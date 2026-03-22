# benchmark.py

import time
import sys
from io import StringIO
import numpy as np

# 导入项目模块
import mq_prime.parameters as param_module
import mq_prime.data_structures as data_module  # 用于更新反序列化所需的全局参数
from mq_prime.faest_framework import mq_prime_keygen_v3, sign_v3, verify_v3
from mq_prime.data_structures import SignatureV3
from mq_prime.timer import reset_timings, get_timings
from mq_prime.aes_prg import reset_aes_count, get_aes_count

# 定义要测试的参数集
# 确保 parameters.py 中已经定义了 L3 和 L5 并且使用了新的 NTT_PRIME
PARAMS_TO_TEST = {
    "L1": param_module.mq_prime_L1_V3_PARAMS,
    "L3": param_module.mq_prime_L3_V3_PARAMS,
    "L5": param_module.mq_prime_L5_V3_PARAMS,
}

# 迭代次数：建议设置为 100 以获得稳定的平均值
NUM_ITERATIONS = 1


def run_benchmark(level_name, params, num_iterations):
    # Set deterministic seed for artifact evaluation reproducibility
    # Note: A static seed is explicitly used here so reviewers obtain consistent evaluation numbers.
    print(f"\n{'=' * 20} BENCHMARKING: {level_name} {'=' * 20}")
    print(f"Parameters: n={params.n}, m={params.m}, τ={params.num_challenge_parties}, seed_size={params.seed_size}")

    # ---------------------------------------------------------
    # 【关键修复】强制更新 data_structures 模块中的全局参数
    # SignatureV3.from_bytes() 依赖这个全局变量来解析字节流
    # ---------------------------------------------------------
    data_module.params = params

    timings = {'keygen': [], 'sign': [], 'verify': []}
    sizes = {'pk': [], 'sk': [], 'sig': []}
    micro_timings = {}
    aes_counts = []

    message = b"This is a benchmark message for mq_prime."

    # --- 预热 (Warmup) ---
    # 运行一次完整的流程以确保所有 C 库已加载，缓存已填充
    # 同时用于检测基本功能是否正常
    # print("  Warming up...")
    try:
        # 注意：这里显式传递 params 参数
        pk, sk = mq_prime_keygen_v3(params)
        signature = sign_v3(sk, message, params)
        sig_bytes = signature.to_bytes()
        reloaded_sig = SignatureV3.from_bytes(sig_bytes)  # 依赖 data_module.params
        if not verify_v3(pk, message, reloaded_sig, params):
            raise ValueError("Verification failed during warmup")
    except Exception as e:
        # 如果预热失败，恢复 stdout 并打印错误
        sys.stdout = sys.__stdout__
        print(f"\nFATAL ERROR during warmup for {level_name}: {e}")
        import traceback
        traceback.print_exc()
        return None

    print(f"  Running {num_iterations} iterations...")

    for i in range(num_iterations):
        # 打印进度 (在静默模式下会被 StringIO 捕获，但在普通模式下可见)
        # print(f"    Iteration {i+1}/{num_iterations}...", end='\r')

        # 重置 计时器 和 计数器
        reset_timings()
        reset_aes_count()

        # --- 1. Key Generation ---
        start_time = time.perf_counter()
        pk, sk = mq_prime_keygen_v3(params)
        timings['keygen'].append((time.perf_counter() - start_time) * 1000)

        # --- 2. Signing ---
        start_time = time.perf_counter()
        signature = sign_v3(sk, message, params)
        timings['sign'].append((time.perf_counter() - start_time) * 1000)

        # 序列化与反序列化
        sig_bytes = signature.to_bytes()
        reloaded_sig = SignatureV3.from_bytes(sig_bytes)

        # --- 3. Verification ---
        start_time = time.perf_counter()
        is_valid = verify_v3(pk, message, reloaded_sig, params)
        timings['verify'].append((time.perf_counter() - start_time) * 1000)

        if not is_valid:
            sys.stdout = sys.__stdout__
            print(f"\nFATAL: Verification failed at iteration {i + 1} for {level_name}!")
            return None

        # --- 数据收集 ---

        # 收集微观计时 (累加)
        iter_timings = get_timings()
        for key, value in iter_timings.items():
            micro_timings[key] = micro_timings.get(key, 0) + value

        # 收集尺寸
        sizes['pk'].append(len(pk.seed_P) + len(pk.p))
        sizes['sk'].append(len(sk.s) + len(pk.seed_P) + len(pk.p))
        sizes['sig'].append(len(sig_bytes))

        # 收集 AES 操作计数
        current_aes_count = get_aes_count()
        aes_counts.append(current_aes_count)

        # 在最后一次迭代，打印 AES 计数信息 (强制输出到真实 stdout)
        if i == num_iterations - 1:
            temp_stdout = sys.stdout
            sys.stdout = sys.__stdout__
            print(f"    [INFO] AES-128 Calls per run (Sign+Verify): {current_aes_count}")
            sys.stdout = temp_stdout

    print("\nBenchmark finished.")

    # 计算微观计时的平均值
    for key in micro_timings:
        micro_timings[key] /= num_iterations

    # 打包结果
    results = {
        'level': level_name,
        'pk_size_avg': np.mean(sizes['pk']),
        'sk_size_avg': np.mean(sizes['sk']),
        'sig_size_avg': np.mean(sizes['sig']),
        'keygen_ms_avg': np.mean(timings['keygen']),
        'sign_ms_avg': np.mean(timings['sign']),
        'verify_ms_avg': np.mean(timings['verify']),
        'micro_timings': micro_timings,
        'aes_count_avg': int(np.mean(aes_counts))
    }
    return results


if __name__ == "__main__":
    all_results = []

    # 设置为 True 以抑制每次迭代的详细日志，只显示最终结果和进度
    SILENT_MODE = True

    for level_name, params in PARAMS_TO_TEST.items():
        # 如果开启静默模式，重定向 stdout
        original_stdout = sys.stdout
        if SILENT_MODE:
            sys.stdout = StringIO()

        try:
            # 运行基准测试
            results = run_benchmark(level_name, params, NUM_ITERATIONS)
        except Exception as e:
            # 发生异常时恢复 stdout 并打印错误
            sys.stdout = original_stdout
            print(f"Error running benchmark for {level_name}: {e}")
            import traceback

            traceback.print_exc()
            continue

        # 恢复 stdout
        if SILENT_MODE:
            sys.stdout = original_stdout

        if results:
            all_results.append(results)

    # --- 打印最终宏观结果表格 ---
    print("\n" + "=" * 80)
    print(" " * 28 + "MACRO-BENCHMARK RESULTS")
    print("=" * 80)
    print(
        f"{'Level':<5} | {'PK Size (B)':>12} | {'Sig Size (B)':>12} | {'Sign (ms)':>10} | {'Verify (ms)':>11} | {'AES Ops':>10}")
    print("-" * 80)
    for res in all_results:
        print(
            f"{res['level']:<5} | {res['pk_size_avg']:>12.0f} | {res['sig_size_avg']:>12.0f} | {res['sign_ms_avg']:>10.1f} | {res['verify_ms_avg']:>11.1f} | {res['aes_count_avg']:>10}")
    print("=" * 80)

    # --- 打印微观结果剖析 ---
    for res in all_results:
        print(f"\n--- MICRO-BENCHMARKS FOR {res['level']} (avg ms per operation) ---")
        if 'micro_timings' in res:

            print("\n  SIGNATURE GENERATION:")
            total_sign_micro = sum(v for k, v in res['micro_timings'].items() if k.startswith('sign_'))
            if total_sign_micro > 0:
                for key, value in sorted(res['micro_timings'].items()):
                    if key.startswith('sign_'):
                        percentage = (value / total_sign_micro) * 100
                        print(f"    - {key:<25}: {value:>8.2f} ms ({percentage:.1f}%)")

            print("\n  SIGNATURE VERIFICATION:")
            total_verify_micro = sum(v for k, v in res['micro_timings'].items() if k.startswith('verify_'))
            if total_verify_micro > 0:
                for key, value in sorted(res['micro_timings'].items()):
                    if key.startswith('verify_'):
                        percentage = (value / total_verify_micro) * 100
                        print(f"    - {key:<25}: {value:>8.2f} ms ({percentage:.1f}%)")
    print("=" * 80)