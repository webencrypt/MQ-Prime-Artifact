# MQ-Prime: High-Performance C Implementation

This repository contains the optimized C implementation of **MQ-Prime**, a post-quantum signature scheme constructed from the MPC-in-the-Head paradigm and structured multivariate quadratic assumptions.

This artifact accompanies the paper: **"MQ-Prime: Achieving Microsecond-Scale Latency for Post-Quantum Signatures"**.

## 🚀 Key Features

*   **Microsecond-Scale Latency**: Achieves **114 $\mu$s** signing latency on Intel Skylake (AVX2), matching trapdoor-based schemes without the structural risks.
*   **Hardware Acceleration**: Utilizes **8-way parallel AES-NI** instructions for GGM tree expansion and Sponge-based hashing.
*   **Zero-Allocation**: Pure stack-based memory management (no `malloc` in critical paths), ensuring deterministic memory usage and low footprint (~15 KB).
*   **Constant-Time**: Designed to be resistant against timing side-channel attacks (verified via `dudect`).
*   **Automated Configuration**: Parameter sets (Conservative/Recommended/Performance) can be switched instantly via CMake build options.

## 📂 Directory Structure

```text
.
├── CMakeLists.txt       # Build configuration (Auto-detects Parameter Set)
├── include/             # Header files (config.h, aes_core.h, etc.)
├── src/                 # Core library source code (No main functions)
│   ├── aes_*.c          # AES-NI primitives and Sponge Hash
│   ├── ggm.c            # 8-way parallel GGM expansion
│   ├── MQ-Prime*.c      # Algebraic structure (P(s)) evaluation
│   └── ntt.c            # Number Theoretic Transform
├── bench/               # Performance benchmarks
│   └── bench_sign.c     # Latency measurement entry point
└── tests/               # Unit tests and Security checks
    ├── test_functional.c# Correctness verification
    └── test_dudect.c    # Constant-time statistical testing
```

## 🛠️ Prerequisites

To build and run this artifact, you need a CPU supporting **AVX2** and **AES-NI** instruction sets (e.g., Intel Skylake or newer, AMD Ryzen).

**Software Dependencies:**
*   **Linux** or **WSL2** (Windows Subsystem for Linux)
*   **CMake** (version 3.10 or higher)
*   **GCC** or **Clang** (supporting `-maes -mavx2`)
*   **Valgrind** (Optional, for memory footprint analysis)

## 📦 Building & Configuration

We provide a seamless build process to switch between different security parameter sets defined in the paper.

### 1. Create Build Directory
```bash
mkdir build
cd build
```

### 2. Configure and Build (Choose One)

You can select the parameter set using the `-DSET` flag.

**Option A: Performance Optimized (Set C, n=64) [Default]**
*Matches the 114 $\mu$s result in the abstract.*
```bash
cmake -DSET=C ..
make
```

**Option B: Recommended (Set B, n=128)**
```bash
cmake -DSET=B ..
make
```

**Option C: Conservative (Set A, n=256)**
```bash
cmake -DSET=A ..
make
```

---

## 🧪 Reproducing Paper Results

After building, three executables will be generated in the `build/` directory.

### 1. Performance Benchmark (Table 3 & Figure 4)
Run `mq_prime_bench` to measure the execution time of KeyGen, Sign, and Verify. It also provides a detailed breakdown of Arithmetic vs. Non-Arithmetic costs.

```bash
./mq_prime_bench
```

**Expected Output (example for Set C):**
```text
>>> Configuring MQ-Prime for Parameter Set: C
...
[1] GGM Tree Expansion... -> ... ms
[2] Commitment & Merkle... -> ... ms
[3] VOLE Arithmetic...    -> ... ms
FINAL ESTIMATED SIGN TIME: 0.1140 ms
```

### 2. Functional Verification
Run `mq_prime_test` to verify the mathematical correctness of the signature scheme (KeyGen -> Sign -> Verify).

```bash
./mq_prime_test
```

**Expected Output:**
```text
[PASS] KeyGen
[PASS] Sign
[PASS] Verify
>>> ALL FUNCTIONAL TESTS PASSED! <<<
```

### 3. Side-Channel Assessment (Dudect)
Run `mq_prime_dudect` to perform statistical timing analysis (fix-vs-random t-test). *Note: This may take a few minutes.*

```bash
./mq_prime_dudect
```

**Expected Output:**
The `max_t` value should remain within the range `[-4.5, 4.5]`, indicating no statistically significant timing leakage.

### 4. Memory Footprint Analysis
Use `valgrind` (Massif tool) to verify the stack usage claimed in Section 5.4.

```bash
valgrind --tool=massif --stacks=yes ./mq_prime_bench
ms_print massif.out.<pid> | head -n 30
```

**Expected Output:**
Look for `mem_stack_B`. It should be approximately **15 KB** for Set C.

---

## 📜 License

This artifact is provided for peer-review purposes.