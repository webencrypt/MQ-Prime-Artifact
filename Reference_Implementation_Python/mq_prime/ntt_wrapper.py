import ctypes
import numpy as np
import os
import platform
import sys

# =========================================================================
# 1. Dynamic Library Loading (Robust)
# =========================================================================

# Determine library name based on OS
system_name = platform.system()
if system_name == "Windows":
    lib_name = 'ntt.dll'
else:
    # On Linux/Mac, standard output is usually just .so
    lib_name = 'ntt.so'

# Locate the library relative to this file
# Structure: ./mq_prime/ntt_wrapper.py -> ../c_extension/ntt.so
current_dir = os.path.dirname(os.path.abspath(__file__))
lib_dir = os.path.abspath(os.path.join(current_dir, '..', 'c_extension'))
full_lib_path = os.path.join(lib_dir, lib_name)

_ntt_lib = None

if os.path.exists(full_lib_path):
    try:
        _ntt_lib = ctypes.CDLL(full_lib_path)

        # Define argument types only if loaded successfully
        # ntt(int32_t* poly, int n, int root)
        _ntt_lib.ntt.argtypes = [
            np.ctypeslib.ndpointer(dtype=np.int32, flags='C_CONTIGUOUS'),
            ctypes.c_int,
            ctypes.c_int
        ]
        _ntt_lib.ntt.restype = None

        # inv_ntt(int32_t* poly, int n, int inv_root, int inv_n)
        _ntt_lib.inv_ntt.argtypes = [
            np.ctypeslib.ndpointer(dtype=np.int32, flags='C_CONTIGUOUS'),
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int
        ]
        _ntt_lib.inv_ntt.restype = None

    except OSError as e:
        print(f"[Warning] Failed to load C-extension: {e}")
        _ntt_lib = None
else:
    # Soft warning, don't crash the whole program
    print(f"[Note] C-extension not found at '{full_lib_path}'.")
    print("       To enable acceleration, run 'python build_c_ext.py'.")
    print("       Running without C acceleration (functions will fail if called).")
    _ntt_lib = None


# =========================================================================
# 2. Wrapper Functions
# =========================================================================

def c_ntt(poly: np.ndarray, n: int, root: int) -> np.ndarray:
    if _ntt_lib is None:
        raise RuntimeError("C-Extension not loaded. Please compile 'c_extension/ntt.c' first.")

    if poly.dtype != np.int32:
        poly = poly.astype(np.int32)
    if not poly.flags['C_CONTIGUOUS']:
        poly = np.ascontiguousarray(poly, dtype=np.int32)

    _ntt_lib.ntt(poly, n, root)
    return poly


def c_inv_ntt(poly: np.ndarray, n: int, inv_root: int, inv_n: int) -> np.ndarray:
    if _ntt_lib is None:
        raise RuntimeError("C-Extension not loaded. Please compile 'c_extension/ntt.c' first.")

    if poly.dtype != np.int32:
        poly = poly.astype(np.int32)
    if not poly.flags['C_CONTIGUOUS']:
        poly = np.ascontiguousarray(poly, dtype=np.int32)

    _ntt_lib.inv_ntt(poly, n, inv_root, inv_n)
    return poly