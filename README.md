# MQ-Prime: Source Code

This repository contains the source code, benchmarks, and analysis scripts for the paper:
**"MQ-Prime: Achieving Microsecond-Scale Latency for Post-Quantum Signatures"**

## 📁 Repository Structure

The source code is deliberately separated into two implementations to decouple hardware-specific performance optimizations from high-level cryptographic verification:

### 1. `Optimized_Implementation_C/`
- **Purpose**: Demonstrates the physical lower-bound performance of the cryptographic core. It isolates the most computationally expensive components (NTT, BSGS polynomial evaluation, GGM tree expansion, and Merkle tree hashing).
- **Features**: 
  - Pure C99, zero dynamic memory allocation during execution.
  - Accelerated via **AVX2**, **AES-NI**, and **OpenMP** multi-threading.
  - Fast Barrett reduction for constant-time modular arithmetic over $\mathbb{F}_Q$ ($Q = 2013265921$).
- **Results**: Achieves microsecond-scale latency for core signature operations.

### 2. `Reference_Implementation_Python/`
- **Purpose**: Provides a full, end-to-end reference implementation of the KeyGen, Sign, and Verify algorithms. Outputs actual keys and signature byte streams.
- **Features**: 
  - Clear, readable logic corresponding to the mathematical descriptions in the paper.
  - Includes a C-extension (`ntt.so`) to accelerate polynomial arithmetic within Python.
  - Contains SageMath scripts (`security_analysis/`) for algebraic cryptanalysis and parameter selection.
- **Results**: Verifies signature sizes (e.g., Set C: ~4 KB) and public key sizes.

---

## 🚀 Getting Started

### Prerequisites
- **OS**: Linux / Ubuntu (WSL2 is supported)
- **Compiler**: GCC or Clang with OpenMP and AVX2/AES-NI support.
- **Build System**: CMake (>= 3.10)
- **Python**: Python 3.8+ (with `numpy`, `pycryptodome`, `matplotlib`)

---

### Step 1: Evaluating the C Optimized Implementation

This step reproduces the high-performance execution.

```bash
cd Optimized_Implementation_C
mkdir -p build && cd build
# Configure for Parameter Set C (Performance focused)
cmake -DSET=C ..
make

# Run the performance benchmark
./mq_prime_bench

# Run functional tests (checks structure logic)
./mq_prime_test

# Run Dudect constant-time analysis (Let it run for a few seconds/minutes)
./mq_prime_dudect
```

---

### Step 2: Evaluating the Python Reference Implementation

This step generates actual signatures, verifies them, and benchmarks macro-level sizes.

```bash
cd Reference_Implementation_Python

# 1. Install dependencies
pip install -r requirements.txt

# 2. Compile the C-Extension for Python (Optional but recommended)
python build_c_ext.py

# 3. Run the end-to-end macro-benchmark
python benchmark.py
```

---

## 📊 Summary of Executables

| Component | Verified By | Command |
| :--- | :--- | :--- |
| **Latency Benchmark** | C Implementation | `./mq_prime_bench` |
| **Signature Sizes & Scaling** | Python Implementation | `python benchmark.py` |
| **Constant-Time Execution** | C Dudect Test | `./mq_prime_dudect` |
| **Functional Correctness** | Python & C Tests | `python main.py` / `./mq_prime_test` |
