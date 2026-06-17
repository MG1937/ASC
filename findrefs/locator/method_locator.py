from findrefs.locator.base_locator import BaseLocator
from collections import defaultdict
import struct

# Auth: MG1937
_STRUCT_HHI = struct.Struct('<HHI')
_STRUCT_I = struct.Struct('<I')

class MethodLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.str_locator = None
        self.parsed = False
        self.clz_maps = defaultdict(set) # {type_idx : {method_idx, ...}}
        self.method_maps = defaultdict(set) # {name_idx : {method_idx, ...}}

    def set_str_locator(self, locator):
        self.str_locator = locator

    # table build is very fast, dont worry about performance
    def _build_map(self):
        method_ids_off, method_ids_size = self.header.methods
        clz_maps = self.clz_maps
        method_maps = self.method_maps
        buf = self.buf

        for method_idx in range(method_ids_size):
            class_idx, _, name_idx = _STRUCT_HHI.unpack_from(buf, method_ids_off)
            method_ids_off += 8
            clz_maps[class_idx].add(method_idx)
            method_maps[name_idx].add(method_idx)
        self.parsed = True

    def _find_type_idx(self, clz : str):
        left = 0
        type_ids_off, type_ids_size = self.header.types
        right = type_ids_size - 1
        buf = self.buf
        strings = self.dex.strings

        while left <= right:
            mid = (left + right) >> 1
            desc_idx = _STRUCT_I.unpack_from(buf, type_ids_off + (mid << 2))[0]
            desc = strings[desc_idx]
            if desc == clz:
                return mid
            if desc < clz:
                left = mid + 1
            else:
                right = mid - 1
        return -1

    # find struct: {"class" : "None|clz", "method" : "None|fuzzy_method"}
    # the two values cannot both be None
    # if class not None, input clz must be precise dalvik format value
    # if method not None, input method name can be a fuzzy value
    # if class is None, find out all method idx that contains the fuzzy method name while dont give shit about class
    # if class is set, find out all methods below this class which matches the method condition
    def locate(self, find : dict) -> set:
        if not self.parsed:
            self._build_map()

        clz = find.get("class")
        method = find.get("method")
        if clz == "":
            clz = None
        if method == "":
            method = None
        if clz is None and method is None:
            return set()

        if clz is None:
            name_idxs = self.str_locator.locate(method)
            method_maps = self.method_maps
            ret = set()
            for name_idx in name_idxs:
                mids = method_maps.get(name_idx)
                if mids is None:
                    continue
                ret.update(mids)
            return ret

        type_idx = self._find_type_idx(clz)
        if type_idx == -1:
            return set()
        clz_mids = self.clz_maps.get(type_idx)
        if clz_mids is None:
            return set()
        if method is None:
            return set(clz_mids)

        name_idxs = self.str_locator.locate(method)
        ret = set()
        for name_idx in name_idxs:
            mids = self.method_maps.get(name_idx)
            if mids is not None:
                ret.update(clz_mids & mids)
        return ret
