from findrefs.locator.base_locator import BaseLocator
from collections import defaultdict
import struct
import time

# Auth: MG1937
_STRUCT_HHI = struct.Struct('<HHI')
_STRUCT_I = struct.Struct('<I')

class FieldLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.str_locator = None
        self.type_locator = None
        self.parsed = False
        self.clz_maps = defaultdict(set) # {type_idx : {field_idx, ...}}
        self.field_maps = defaultdict(set) # {name_idx : {field_idx, ...}}

    def set_str_locator(self, locator):
        self.str_locator = locator    

    def set_type_locator(self, locator):
        self.type_locator = locator

    # table build is very fast, dont worry about performance
    def _build_map(self):
        if self.parsed:
            return
        t_start = time.perf_counter() if self.debug else None
        field_ids_off, field_ids_size = self.header.fields
        clz_maps = self.clz_maps
        field_maps = self.field_maps
        buf = self.buf

        for field_idx in range(field_ids_size):
            class_idx, _, name_idx = _STRUCT_HHI.unpack_from(buf, field_ids_off)
            field_ids_off += 8
            clz_maps[class_idx].add(field_idx)
            field_maps[name_idx].add(field_idx)
        self.parsed = True
        self._debug_log("build_map", t_start, field_ids_size)

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

    def _collect_clz_fids(self, type_idxs) -> set:
        ret = set()
        clz_maps = self.clz_maps
        for type_idx in type_idxs:
            fids = clz_maps.get(type_idx)
            if fids is not None:
                ret.update(fids)
        return ret

    def _match_clz_fids(self, clz_fids : set, field : str) -> set:
        ret = set()
        fields = self.dex.fields
        for fid in clz_fids:
            if fields[fid].name.find(field) != -1:
                ret.add(fid)
        return ret

    # find struct: {"class" : ["None|clz", precise], "field" : "None|fuzzy_field"}
    # the two values cannot both be None
    # if class not None, input clz must be precise dalvik format value or fuzzy clz
    # if field not None, input field name can be a fuzzy value
    # if class is None, find out all field idx that contains the fuzzy field name while dont give shit about class
    # if class is set, find out all fields below this class which matches the field condition
    def locate(self, find : dict) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()

        clz = find.get("class")
        field = find.get("field")
        clz_precise = True
        if clz is not None:
            clz, clz_precise = clz
            if clz == "":
                clz = None
        if field == "":
            field = None
        if clz is None and field is None:
            self._debug_log("locate", t_start, 0)
            return set()

        if clz is None:
            name_idxs = self.str_locator.locate(field)
            field_maps = self.field_maps
            ret = set()
            for name_idx in name_idxs:
                fids = field_maps.get(name_idx)
                if fids is None:
                    continue
                ret.update(fids)
            self._debug_log("locate", t_start, len(ret))
            return ret

        if clz_precise:
            type_idx = self._find_type_idx_precisely(clz)
            if type_idx == -1:
                self._debug_log("locate", t_start, 0)
                return set()
            clz_fids = self.clz_maps.get(type_idx)
            if clz_fids is None:
                self._debug_log("locate", t_start, 0)
                return set()
            clz_fids = set(clz_fids)
        else:
            clz_fids = self._collect_clz_fids(self.type_locator.locate(clz))
            if not clz_fids:
                self._debug_log("locate", t_start, 0)
                return set()
        if field is None:
            self._debug_log("locate", t_start, len(clz_fids))
            return clz_fids
        if clz_precise:
            ret = self._match_clz_fids(clz_fids, field)
            self._debug_log("locate", t_start, len(ret))
            return ret

        name_idxs = self.str_locator.locate(field)
        ret = set()
        for name_idx in name_idxs:
            fids = self.field_maps.get(name_idx)
            if fids is not None:
                ret.update(clz_fids & fids)
        self._debug_log("locate", t_start, len(ret))
        return ret
