from findrefs.locator.base_locator import BaseLocator
import struct
from bisect import bisect_right
from utils.leb128 import read_uleb128_len
import re
import time

# Auth: MG1937
_STRUCT_I = struct.Struct('<I')

# r8 using MUTF8 to handle string payload,
# so 0x00 will be encoded to 0xC0 0x80
class StringLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.stridx_map = {} # {string_data_off : string_idx}
        self.strdata_start = 0
        self.strdata_end = 0
        self.string_offsets = []
        self.parsed = False
    
    def _build_map(self):
        if self.parsed:
            return
        t_start = time.perf_counter() if self.debug else None
        string_ids_off, string_ids_size = self.header.strings
        stridx_map = self.stridx_map
        buf = self.buf
        for idx in range(string_ids_size):
            data_offset = _STRUCT_I.unpack_from(buf, string_ids_off)[0]
            string_ids_off += 4
            stridx_map[data_offset] = idx
        self.string_offsets = sorted(stridx_map)
        if self.string_offsets:
            self.strdata_start = self.string_offsets[0]
            last = self.string_offsets[-1]
            self.strdata_end = buf.obj.find(b'\x00', last + read_uleb128_len(buf, last)) + 1
        self.parsed = True
        self._debug_log("build_map", t_start, len(stridx_map))

    def _match_string_offset(self, string : str):
        buf = self.buf
        string = string.encode('utf-8')
        strdata_start = self.strdata_start
        strdata_end = self.strdata_end
        submem = buf[strdata_start: strdata_end]
        
        mm = submem.obj
        pattern = re.compile(string)
        
        for match in pattern.finditer(submem):
            start = strdata_start + match.start()
            item = self.string_offsets[bisect_right(self.string_offsets, start) - 1]
            content_start = item + read_uleb128_len(buf, item)
            content_end = mm.find(b'\x00', content_start, strdata_end)
            if start >= content_start and strdata_start + match.end() <= content_end:
                yield item

    def locate(self, string : str) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()
        if not self.string_offsets:
            return set()
        stridx_map = self.stridx_map
        located_idx = set()
        for offset in self._match_string_offset(string):
            located_idx.add(stridx_map[offset])
        # return set for O(1) lookup
        self._debug_log("locate", t_start, len(located_idx))
        return located_idx
        
