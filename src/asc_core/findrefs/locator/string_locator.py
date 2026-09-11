from findrefs.locator.base_locator import BaseLocator
import struct
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
        self.parsed = False
    
    def _build_map(self):
        if self.parsed:
            return
        t_start = time.perf_counter() if self.debug else None
        string_ids_off, string_ids_size = self.header.strings
        stridx_map = self.stridx_map
        buf = self.buf
        if not string_ids_size:
            self.parsed = True
            self._debug_log("build_map", t_start, 0)
            return
        # might buggy.. r8 not specify the first string data off is the begging of all string data off, but usually it was...
        self.strdata_start = _STRUCT_I.unpack_from(buf, string_ids_off)[0]
        for idx in range(string_ids_size):
            data_offset = _STRUCT_I.unpack_from(buf, string_ids_off)[0]
            string_ids_off += 4
            stridx_map[data_offset] = idx
        # Include the final string_data_item. The existing lookup maps a
        # match through the following string offset, so add an end sentinel
        # for the final item without changing that mapping scheme.
        self.strdata_end = buf.obj.find(
            b'\x00', data_offset + read_uleb128_len(buf, data_offset)
        ) + 1
        stridx_map[self.strdata_end] = string_ids_size
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
        
        # offsets = []
        for match in pattern.finditer(submem):
            offset = strdata_start + match.end()
            offset = mm.find(b'\x00', offset, strdata_end)
            yield offset + 1
            # offsets.append(offset + 1) # skip over 00 byte
        # return offsets

    def locate(self, string : str) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()
        stridx_map = self.stridx_map
        located_idx = set()
        for offset in self._match_string_offset(string):
            located_idx.add(stridx_map[offset] - 1)
        # return set for O(1) lookup
        self._debug_log("locate", t_start, len(located_idx))
        return located_idx
        
