# utils/timer.py

import time

# 用于存储全局计时结果的字典
GLOBAL_TIMINGS = {}

class Timer:
    def __init__(self, name):
        self.name = name
    def __enter__(self):
        self.start = time.perf_counter()
    def __exit__(self, type, value, traceback):
        duration = (time.perf_counter() - self.start) * 1000 # ms
        GLOBAL_TIMINGS[self.name] = GLOBAL_TIMINGS.get(self.name, 0) + duration

def reset_timings():
    GLOBAL_TIMINGS.clear()

def get_timings():
    return GLOBAL_TIMINGS