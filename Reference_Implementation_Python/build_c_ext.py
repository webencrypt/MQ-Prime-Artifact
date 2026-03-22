import os
import subprocess
import platform
import sys

def build():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    c_ext_dir = os.path.join(current_dir, 'c_extension')
    
    os.chdir(c_ext_dir)
    
    system = platform.system()
    if system == "Windows":
        # Using MSVC
        print("Building for Windows using MSVC...")
        cmd = ["cl", "/O2", "/LD", "ntt.c", "/Fentt.dll"]
    else:
        # Using GCC/Clang
        print(f"Building for {system} using GCC...")
        cmd = ["gcc", "-O3", "-fPIC", "-shared", "-o", "ntt.so", "ntt.c"]
        
    try:
        subprocess.check_call(cmd)
        print("Build successful!")
    except subprocess.CalledProcessError as e:
        print(f"Build failed: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("Compiler not found. Please install gcc (Linux/Mac) or MSVC (Windows).")
        sys.exit(1)

if __name__ == "__main__":
    build()
