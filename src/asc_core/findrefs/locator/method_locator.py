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

    def set_type_locator(self, locator):
        self.type_locator = locator

    # table build is very fast, dont worry about performance
    def _build_map(self):
        if self.parsed:
            return
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

    # which is different with type locator, this func for precise clz name
    # while type locator is for fuzzy search
    def _find_type_idx_precisely(self, clz : str):
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

    def _collect_clz_mids(self, type_idxs) -> set:
        ret = set()
        clz_maps = self.clz_maps
        for type_idx in type_idxs:
            mids = clz_maps.get(type_idx)
            if mids is not None:
                ret.update(mids)
        return ret

    def _match_clz_mids(self, clz_mids : set, method : str) -> set:
        ret = set()
        methods = self.dex.methods
        for mid in clz_mids:
            if methods[mid].name.find(method) != -1:
                ret.add(mid)
        return ret

    # find struct: {"class" : ["None|clz", precise], "method" : "None|fuzzy_method"}
    # the two values cannot both be None
    # if class not None, input clz must be precise dalvik format value or fuzzy clz
    # if method not None, input method name can be a fuzzy value
    # if class is None, find out all method idx that contains the fuzzy method name while dont give shit about class
    # if class is set, find out all methods below this class which matches the method condition
    def locate(self, find : dict) -> set:
        if not self.parsed:
            self._build_map()

        clz = find.get("class")
        method = find.get("method")
        clz_precise = True
        if clz is not None:
            clz, clz_precise = clz
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

        if clz_precise:
            type_idx = self._find_type_idx_precisely(clz)
            if type_idx == -1:
                return set()
            clz_mids = self.clz_maps.get(type_idx)
            if clz_mids is None:
                return set()
            clz_mids = set(clz_mids)
        else:
            clz_mids = self._collect_clz_mids(self.type_locator.locate(clz))
            if not clz_mids:
                return set()
        if method is None:
            return clz_mids
        if clz_precise:
            return self._match_clz_mids(clz_mids, method)

        name_idxs = self.str_locator.locate(method)
        ret = set()
        for name_idx in name_idxs:
            mids = self.method_maps.get(name_idx)
            if mids is not None:
                ret.update(clz_mids & mids)
        return ret
