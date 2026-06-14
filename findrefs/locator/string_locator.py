from findrefs.locator.base_locator import BaseLocator

# Auth: MG1937
_STRUCT_I = struct.Struct('<I')

# r8 using MUTF8 to handle string payload,
# so 0x00 will be encoded to 0xC0 0x80
class StringLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.stridx_map = {} # {string_data_off : string_idx}
    
    def _build_map(self):
        string_ids_off, string_ids_size = self.header.strings
        stridx_map = self.stridx_map
        buf = self.buf
        for idx in range(string_ids_size):
            data_offset = _STRUCT_I.unpack_from(buf, string_ids_off)
            string_ids_off += 4
            stridx_map[data_offset] = idx

    def locate(self, offsets : list):
        
