from findrefs.locator.insn_locator import InsnLocator
from findrefs.locator.method_locator import MethodLocator
from findrefs.locator.string_locator import StringLocator
from findrefs.scan.code_item_scan import CodeItemScanner

from utils.tinydex import DEX 
from utils.tinydex import DexMethod
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
offsets = locator.locate("create")
t_end = time.perf_counter()
print(f"[DEBUG] string_locator Time: {(t_end - t_start)*1000000:.2f} us")

t_start = time.perf_counter()
codescanner = CodeItemScanner(insn_locator)
scan = {"string": offsets}
codescanner.scan(scan)
t_end = time.perf_counter()
print(f"[DEBUG] code_scan Time: {(t_end - t_start)*1000000:.2f} us")
print(scan)

t_start = time.perf_counter()
classes = []
for mid in scan["string"]:
    dexmethod = DexMethod(dex, mid)
    classes.append(dexmethod.cls.fullname)
t_end = time.perf_counter()
print(f"[DEBUG] dexmethod Time: {(t_end - t_start)*1000000:.2f} us")
print(classes)

t_start = time.perf_counter()
method_locator = MethodLocator(dex)
method_locator.set_str_locator(locator)
sample_method = DexMethod(dex, 0)
wild_methods = method_locator.locate({"class": None, "method": "view"})
class_methods = method_locator.locate({"class": sample_method.cls.fullname, "method": None})
precise_methods = method_locator.locate({"class": sample_method.cls.fullname, "method": sample_method.name})
t_end = time.perf_counter()
print(f"[DEBUG] method_locator Time: {(t_end - t_start)*1000000:.2f} us")
print({"class": None, "method": "view"}, len(wild_methods), sorted(list(wild_methods))[:5])
print({"class": sample_method.cls.fullname, "method": None}, len(class_methods), sorted(list(class_methods))[:5])
print({"class": sample_method.cls.fullname, "method": sample_method.name}, len(precise_methods), sorted(list(precise_methods)))
