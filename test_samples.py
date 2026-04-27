import os
import time

from core.dex.dex_manager import DexManager
from utils.decompiler import decompile_dex_bytes

SAMPLE = "classes5.dex"

# Initialize manager once, as it loads the DEX file which is heavy
manager = DexManager(SAMPLE, debug=False)

testcases = []
with open("testcase.txt", "r") as f:
    for line in f:
        line = line.strip()
        if line:
            testcases.append(line)

print(f"[INFO] Loaded {len(testcases)} testcases.")

total_time = 0
success_count = 0

for i, clazz in enumerate(testcases):
    try:
        t_start = time.perf_counter()
        
        new_dex = manager.extract_and_rebuild(clazz)
#        source_code = decompile_dex_bytes(new_dex, clazz)
        
        t_end = time.perf_counter()

#        print(source_code)
        
        exec_time = (t_end - t_start) * 1000000
        total_time += exec_time
        success_count += 1
        
        if (i + 1) % 100 == 0:
            print(f"[INFO] Processed {i + 1}/{len(testcases)} classes...")
            
    except Exception as e:
        print(f"[ERROR] Failed to process {clazz}: {e}")

if success_count > 0:
    avg_time = total_time / success_count
    print(f"\n[RESULT] Total Successful: {success_count}/{len(testcases)}")
    print(f"[RESULT] Average Execution Time per class: {avg_time:.2f} us")
    print(f"[RESULT] Total Execution Time for {success_count} classes: {total_time / 1000000:.4f} s")
else:
    print("\n[RESULT] All testcases failed.")

