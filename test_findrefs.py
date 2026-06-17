from findrefs.locator.insn_locator import InsnLocator
from findrefs.locator.field_locator import FieldLocator
from findrefs.locator.method_locator import MethodLocator
from findrefs.locator.string_locator import StringLocator
from findrefs.locator.type_locator import TypeLocator
from findrefs.scan.code_item_scan import CodeItemScanner

from utils.tinydex import DEX 
from utils.tinydex import DexField
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
print(f"[DEBUG] string_ref_count: {len(scan['string'])}")

t_start = time.perf_counter()
classes = []
for mid in scan["string"]:
    dexmethod = DexMethod(dex, mid)
    classes.append(dexmethod.cls.fullname)
t_end = time.perf_counter()
print(f"[DEBUG] dexmethod Time: {(t_end - t_start)*1000000:.2f} us")
print(f"[DEBUG] string_ref_class_count: {len(classes)}")

t_start = time.perf_counter()
type_locator = TypeLocator(dex)
type_locator.set_str_locator(locator)
field_locator = FieldLocator(dex)
field_locator.set_str_locator(locator)
field_locator.set_type_locator(type_locator)
method_locator = MethodLocator(dex)
method_locator.set_str_locator(locator)
method_locator.set_type_locator(type_locator)
sample_method = DexMethod(dex, 0)
sample_field = DexField(dex, 0)

t_case_start = time.perf_counter()
wild_methods = method_locator.locate({"class": None, "method": "view"})
t_case_end = time.perf_counter()
print(f"[DEBUG] method_locator_none_class Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] method_locator_none_class Count: {len(wild_methods)}")

t_case_start = time.perf_counter()
precise_class_methods = method_locator.locate({"class": [sample_method.cls.fullname, True], "method": None})
t_case_end = time.perf_counter()
print(f"[DEBUG] method_locator_precise_class_only Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] method_locator_precise_class_only Count: {len(precise_class_methods)}")

t_case_start = time.perf_counter()
precise_methods = method_locator.locate({"class": [sample_method.cls.fullname, True], "method": sample_method.name})
t_case_end = time.perf_counter()
print(f"[DEBUG] method_locator_precise_class_method Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] method_locator_precise_class_method Count: {len(precise_methods)}")

t_case_start = time.perf_counter()
fuzzy_class_methods = method_locator.locate({"class": ["AccessibilityServiceInfo", False], "method": None})
t_case_end = time.perf_counter()
print(f"[DEBUG] method_locator_fuzzy_class_only Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] method_locator_fuzzy_class_only Count: {len(fuzzy_class_methods)}")

t_case_start = time.perf_counter()
fuzzy_methods = method_locator.locate({"class": ["AccessibilityServiceInfo", False], "method": sample_method.name})
t_case_end = time.perf_counter()
print(f"[DEBUG] method_locator_fuzzy_class_method Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] method_locator_fuzzy_class_method Count: {len(fuzzy_methods)}")
t_end = time.perf_counter()
print(f"[DEBUG] method_locator Time: {(t_end - t_start)*1000000:.2f} us")

t_start = time.perf_counter()
t_case_start = time.perf_counter()
wild_fields = field_locator.locate({"class": None, "field": "action"})
t_case_end = time.perf_counter()
print(f"[DEBUG] field_locator_none_class Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] field_locator_none_class Count: {len(wild_fields)}")

t_case_start = time.perf_counter()
precise_class_fields = field_locator.locate({"class": [sample_field.cls.fullname, True], "field": None})
t_case_end = time.perf_counter()
print(f"[DEBUG] field_locator_precise_class_only Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] field_locator_precise_class_only Count: {len(precise_class_fields)}")

t_case_start = time.perf_counter()
precise_fields = field_locator.locate({"class": [sample_field.cls.fullname, True], "field": sample_field.name})
t_case_end = time.perf_counter()
print(f"[DEBUG] field_locator_precise_class_field Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] field_locator_precise_class_field Count: {len(precise_fields)}")

t_case_start = time.perf_counter()
fuzzy_class_fields = field_locator.locate({"class": ["Notification", False], "field": None})
t_case_end = time.perf_counter()
print(f"[DEBUG] field_locator_fuzzy_class_only Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] field_locator_fuzzy_class_only Count: {len(fuzzy_class_fields)}")

t_case_start = time.perf_counter()
fuzzy_fields = field_locator.locate({"class": ["Notification", False], "field": sample_field.name})
t_case_end = time.perf_counter()
print(f"[DEBUG] field_locator_fuzzy_class_field Time: {(t_case_end - t_case_start)*1000000:.2f} us")
print(f"[DEBUG] field_locator_fuzzy_class_field Count: {len(fuzzy_fields)}")
t_end = time.perf_counter()
print(f"[DEBUG] field_locator Time: {(t_end - t_start)*1000000:.2f} us")

t_start = time.perf_counter()
method_scan = {"method": precise_methods}
codescanner.scan(method_scan)
t_end = time.perf_counter()
print(f"[DEBUG] method_ref_scan Time: {(t_end - t_start)*1000000:.2f} us")
print(f"[DEBUG] method_ref_count: {len(method_scan['method'])}")

t_start = time.perf_counter()
field_scan = {"field": precise_fields}
codescanner.scan(field_scan)
t_end = time.perf_counter()
print(f"[DEBUG] field_ref_scan Time: {(t_end - t_start)*1000000:.2f} us")
print(f"[DEBUG] field_ref_count: {len(field_scan['field'])}")

t_start = time.perf_counter()
type_idxs = type_locator.locate("View")
t_end = time.perf_counter()
print(f"[DEBUG] type_locator Time: {(t_end - t_start)*1000000:.2f} us")
print(f"[DEBUG] type_locator Count: {len(type_idxs)}")

t_start = time.perf_counter()
type_scan = {"type": type_idxs}
codescanner.scan(type_scan)
t_end = time.perf_counter()
print(f"[DEBUG] type_ref_scan Time: {(t_end - t_start)*1000000:.2f} us")
print(f"[DEBUG] type_ref_count: {len(type_scan['type'])}")
