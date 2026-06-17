from findrefs.locator.base_locator import BaseLocator
import struct
import re

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
        string_ids_off, string_ids_size = self.header.strings
        stridx_map = self.stridx_map
        buf = self.buf
        # might buggy.. r8 not specify the first string data off is the begging of all string data off, but usually it was...
        self.strdata_start = _STRUCT_I.unpack_from(buf, string_ids_off)[0]
        for idx in range(string_ids_size):
            data_offset = _STRUCT_I.unpack_from(buf, string_ids_off)[0]
            string_ids_off += 4
            stridx_map[data_offset] = idx
        self.strdata_end = data_offset
        self.parsed = True

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
        if not self.parsed:
            self._build_map()
        stridx_map = self.stridx_map
        located_idx = set()
        for offset in self._match_string_offset(string):
            located_idx.add(stridx_map[offset] - 1)
        # return set for O(1) lookup
        return located_idx
        
