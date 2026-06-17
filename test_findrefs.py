from findrefs.locator.insn_locator import InsnLocator
from findrefs.locator.string_locator import StringLocator
from findrefs.scan.code_item_scan import CodeItemScanner

from utils.tinydex import DEX 
import mmap

import time
t_start = time.perf_counter()
f = open("./classes.dex","rb")
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
buf = memoryview(mm)
dex = DEX.parse(buf, "classes.dex")
insn_locator = InsnLocator(dex)
insn_locator.parse()
t_end = time.perf_counter()
print(f"[DEBUG] insn_locator Time: {(t_end - t_start)*1000000:.2f} us")

t_start = time.perf_counter()
locator = StringLocator(dex)
offsets = locator.locate("view")
t_end = time.perf_counter()
print(f"[DEBUG] string_locator Time: {(t_end - t_start)*1000000:.2f} us")

t_start = time.perf_counter()
codescanner = CodeItemScanner(insn_locator)
scan = {"string": offsets}
codescanner.scan(scan)
t_end = time.perf_counter()
print(f"[DEBUG] code_scan Time: {(t_end - t_start)*1000000:.2f} us")
print(scan)
