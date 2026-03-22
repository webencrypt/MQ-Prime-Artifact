cmake_minimum_required(VERSION 3.10)
project(MQ-Prime_Artifact C)

set(CMAKE_C_STANDARD 99)

# =========================================================
# 1. 编译选项与平台适配 (Windows/WSL/Linux)
# =========================================================
if(MSVC)
    add_compile_options(/O2 /arch:AVX2 /W4)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS) # 防止 MSVC 报 scanf 等警告
else()
    # 针对 GCC/Clang (WSL/Linux)
    add_compile_options(-O3 -maes -mavx2 -march=native -Wall -Wextra -fopenmp)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fopenmp")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fopenmp")
endif()

include_directories(include)

# =========================================================
# 2. 参数集切换开关 (Artifact 核心功能)
# 用法: cmake -DSET=A ..  (默认为 C)
# =========================================================
if(NOT DEFINED SET)
    set(SET "C") # Default to Performance Set C (114 us)
endif()

message(STATUS ">>> Configuring MQ-Prime for Parameter Set: ${SET}")

if(SET STREQUAL "A")
    add_definitions(-DPARAM_SET_A)
elseif(SET STREQUAL "B")
    add_definitions(-DPARAM_SET_B)
else()
    add_definitions(-DPARAM_SET_C)
endif()

# =========================================================
# 3. 核心源文件库
# =========================================================
set(COMMON_SOURCES
        src/aes_core.c
        src/aes_hash.c
        src/aes_prg.c
        src/ggm.c
        src/MQ-Prime.c
        src/MQ-Prime_arith.c
        src/ntt.c
)

# 创建静态库，避免重复编译
add_library(mq_prime_lib STATIC ${COMMON_SOURCES})

# =========================================================
# 4. 可执行目标
# =========================================================

# (A) 性能基准测试 (Paper Table 3 & Figure 4)
add_executable(mq_prime_bench bench/bench_sign.c)
target_link_libraries(mq_prime_bench mq_prime_lib)

# (B) 功能正确性测试
add_executable(mq_prime_test tests/test_functional.c)
target_link_libraries(mq_prime_test mq_prime_lib)

# (C) 侧信道测试 (dudect)
add_executable(mq_prime_dudect tests/test_dudect.c)
target_link_libraries(mq_prime_dudect mq_prime_lib)

# Linux/WSL 下链接数学库
if(NOT MSVC)
    target_link_libraries(mq_prime_bench m)
    target_link_libraries(mq_prime_test m)
    target_link_libraries(mq_prime_dudect m)
endif()