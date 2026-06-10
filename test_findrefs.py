from findrefs.locator.insn_locator import InsnLocator
from utils.tinydex import DEX 
import mmap

import time
t_start = time.perf_counter()
f = open("./classes.dex","rb")
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
buf = memoryview(mm)
dex = DEX.parse(buf, "classes.dex")
insn_locator = InsnLocator(dex)
insn_locator._build_map_bymap()
t_end = time.perf_counter()
print(f"[DEBUG] insn_locator Time: {(t_end - t_start)*1000000:.2f} us")
print(len(insn_locator.insn_offs))
print(insn_locator.method_map)

