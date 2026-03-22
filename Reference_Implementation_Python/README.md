# MQ-Prime: Reference Implementation & Security Analysis

This folder contains the **pure Python reference implementation** of MQ-Prime and **SageMath scripts** used for the algebraic security analysis (Section 4 and Appendix B of the paper).

## ⚠️ Performance Note

Please note that this is a **reference implementation** optimized for **readability, algorithmic clarity, and logic verification**, NOT for speed.

*   **Logic Verification**: This code demonstrates the mathematical correctness of the MQ-Prime scheme (KeyGen, Sign, Verify) and the correctness of the security analysis.
*   **Performance Claims**: The microsecond-level latency (**114 $\mu$s**) reported in the paper is obtained from the **Optimized C Implementation** (located in the `../Optimized_Implementation_C` directory), which utilizes AVX2/AES-NI hardware acceleration.
*   **Expectation**: This Python implementation is significantly slower (~0.2s for Set C) than the C implementation.

## 📂 Directory Structure

*   `mq_prime/`: The core Python package implementing the signature scheme (MPCitH, VOLE, GGM, etc.).
*   `security_analysis/`: **SageMath scripts** for reproducing the algebraic attacks (Gröbner Basis, MinRank) and Degree of Regularity experiments.
*   `c_extension/`: Optional C source code to accelerate the Number Theoretic Transform (NTT) in Python.
*   `experiments/`: Scripts and figures for reproducing the breakdown plots.
*   `tests/`: Unit tests for individual components.
*   `main.py`: The main entry point for a full signing/verification demo.

## 🛠️ Prerequisites

*   **Python 3.8+**
*   **SageMath** (Only required for scripts in `security_analysis/`)

### 1. Installation

We recommend using a virtual environment to manage dependencies (PEP 668):

```bash
# Create and activate virtual environment
python3 -m venv .venv

# Linux/macOS
source .venv/bin/activate
# Windows
.\.venv\Scripts\Activate

# Install dependencies
pip install -r requirements.txt
```

### 2. (Optional) Compile C-Extension

To speed up the NTT operations in Python, you can compile the C extension. If skipped, the code will fallback to a slower pure Python implementation or warn you.

```bash
# Linux / WSL / macOS
gcc -shared -o c_extension/ntt.so -fPIC c_extension/ntt.c

# Windows (MinGW/MSVC)
gcc -shared -o c_extension/ntt.dll c_extension/ntt.c
```

---

## 🚀 Running the Code

### 1. Full Demo (KeyGen -> Sign -> Verify)
Runs the scheme using the **Performance-Optimized Parameter Set (Set C, n=64)**, matching the configuration used for the primary results in the paper.

```bash
python main.py
```
*Expected Output:* Correctness checks passed, signature size ~4.0 KB.

### 2. Macro-Benchmarks
Runs benchmarks across different parameter sets (L1, L3, L5) to demonstrate scalability.

```bash
python benchmark.py
```

### 3. Run Unit Tests
```bash
python -m unittest discover tests
```

---

## 🔐 Reproducing Security Analysis

The following scripts require **SageMath** to be installed and available in your path.

### 1. Degree of Regularity Comparison
Verifies that the structured MQ-Prime system maintains a high Degree of Regularity ($D_{reg}$) compared to random systems (Figure 2 in the paper).

```bash
sage security_analysis/dreg_vs_random.sage
```

### 2. MinRank Attack Complexity
Verifies the resistance against Rectangular MinRank attacks.

```bash
sage security_analysis/minrank_check.sage
```

## 📜 License

This artifact is provided for peer-review purposes.