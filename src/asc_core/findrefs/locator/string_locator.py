from findrefs.locator.base_locator import BaseLocator
import struct
import sys
from bisect import bisect_right
from utils.leb128 import read_uleb128_len
import re
import time

# Auth: MG1937
_STRUCT_I = struct.Struct('<I')

def _overlapping(pattern, submem):
    pos = 0
    limit = len(submem)
    while pos <= limit:
        match = pattern.search(submem, pos)
        if match is None:
            return
        yield match
        pos = match.start() + 1


# MUTF-8 NUL encoding: 0xC0 0x80
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
        ids = buf[string_ids_off:string_ids_off + string_ids_size * 4]
        offsets = (ids.cast('I').tolist() if sys.byteorder == 'little' else
                   [item[0] for item in _STRUCT_I.iter_unpack(ids)])
        stridx_map.update(zip(offsets, range(string_ids_size)))
        self.string_offsets = sorted(offsets)
        self.ids_in_physical_order = offsets == self.string_offsets
        if offsets:
            self.strdata_start = self.string_offsets[0]
            last = self.string_offsets[-1]
            self.strdata_end = buf.obj.find(b'\x00', last + read_uleb128_len(buf, last)) + 1
            stridx_map[self.strdata_end] = string_ids_size
        self.parsed = True
        self._debug_log("build_map", t_start, string_ids_size)

    def _match_string_index(self, string : str):
        buf = self.buf
        string = string.encode('utf-8')
        strdata_start = self.strdata_start
        strdata_end = self.strdata_end
        submem = buf[strdata_start: strdata_end]
        
        mm = submem.obj
        literal = bool(string) and b'\x00' not in string and re.escape(string) == string
        pattern = re.compile(string + b'[^\x00]*\x00' if literal else string)
        
        matches = pattern.finditer(submem) if literal else _overlapping(pattern, submem)
        for match in matches:
            start = strdata_start + match.start()
            content_end = strdata_start + match.end() - 1 if literal else mm.find(b'\x00', start, strdata_end)
            query_end = start + len(string) if literal else strdata_start + match.end()
            next_idx = self.stridx_map.get(content_end + 1)
            if self.ids_in_physical_order and next_idx is not None and next_idx > 0:
                idx = next_idx - 1
                item = self.string_offsets[idx]
            else:
                item = self.string_offsets[bisect_right(self.string_offsets, start) - 1]
                idx = self.stridx_map[item]
            content_start = item + (read_uleb128_len(buf, item) if buf[item] & 128 else 1)
            if mm.find(b'\x00', content_start, start) != -1:
                continue
            if literal and start < content_start:
                if mm.find(string, content_start, content_end) != -1:
                    yield idx
            elif start >= content_start and query_end <= content_end:
                yield idx

    def locate(self, string : str) -> set:
        t_start = time.perf_counter() if self.debug else None
        if not self.parsed:
            self._build_map()
        if not self.string_offsets:
            return set()
        located_idx = set(self._match_string_index(string))
        self._debug_log("locate", t_start, len(located_idx))
        return located_idx
        
