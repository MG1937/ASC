import time
t_start = time.perf_counter()

from core.dex.dex_manager import DexManager
from utils.decompiler import decompile_dex_bytes

SAMPLE = "classes.dex"
CLASS = "Lcom/google/android/material/timepicker/ClockFaceView;"

manager = DexManager(SAMPLE, debug=False)
new_dex = manager.extract_and_rebuild(CLASS)
source_code = decompile_dex_bytes(new_dex, CLASS)

t_end = time.perf_counter()

print(source_code)
print(f"\n[INFO] Total Execution Time in test.py: {(t_end - t_start):.4f} s")

