from findrefs.locator.base_locator import BaseLocator
from collections import defaultdict
import struct
import time

# Auth: MG1937
_STRUCT_I = struct.Struct('<I')

class TypeLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.str_locator = None
        self.parsed = False
        self.type_maps = defaultdict(set) # {str_idx : {type_idx, ...}}
        
    def set_str_locator(self, locator):
        self.str_locator = locator

    def _build_map(self):
        if self.parsed:
            return
        t_start = time.perf_counter() if self.debug else None
        type_ids_off, type_ids_size = self.header.types
        type_maps = self.type_maps
        buf = self.buf

        for type_idx in range(type_ids_size):
            str_idx = _STRUCT_I.unpack_from(buf, type_ids_off)[0]
            type_ids_off += 4
            type_maps[str_idx].add(type_idx)
        self.parsed = True
        self._debug_log("build_map", t_start, len(type_maps))

    def locate(self, type_str : str) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()
        if type_str == "":
            self._debug_log("locate", t_start, 0)
            return set()

        str_idxs = self.str_locator.locate(type_str)
        ret = set()
        type_maps = self.type_maps
        for str_idx in str_idxs:
            ret.update(type_maps.get(str_idx, ()))
        self._debug_log("locate", t_start, len(ret))
        return ret
