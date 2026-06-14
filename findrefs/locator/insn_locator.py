from findrefs.locator.base_locator import BaseLocator
from utils.leb128 import read_uleb128_fast, read_uleb128_len
from collections import defaultdict
import struct

# Auth MG1937
_STRUCT_I = struct.Struct('<I')
_STRUCT_H = struct.Struct('<H')

# +-----------------+
# | codeitem header | <-- register_size, ins_size... MUST hold 16 bytes!
# +-----------------+
# |  insn (ushort)  | <-- at least 1 insn for 2 bytes!
# +-----------------+
# | codeitem header |
# |       ...       |
# Each method's insn starts at codeitem offset + 16 (header size)
# Use insn_off >> 4 as bucket key
# methods are naturally bucketed.
# For methods spanning multiple buckets,
# fill all buckets from start to end. Achieves O(1) lookup.

# cover insn offset to method idx
class InsnLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.parsed = False
        # use 16 bytes dense table to achieve O(1) speed
        self.insn_maps = {} # {insn_off_bucket: midx, insn_off_bucket : [midx, midx2...]}
        # self.insn_offs = [] # for sort
        # self.method_map = defaultdict(list) # {insn_off : [midx, midx2...]}
        # self.insn_off_size = {} # {insn_off : insn_size}

    def _encoded_method_parse(self, data : bytes, pos, midx):
        if pos == 0:
            # code off == 0 means no method body, we dont need to locate it, ignore
            return
        insn_size = _STRUCT_I.unpack_from(data, pos + 12)[0]
        insn_off = pos + 16
        insn_maps = self.insn_maps
        # need to declare why do this...
        insn_bucket_start = insn_off >> 4
        insn_bucket_end = (insn_off + insn_size * 2 - 1) >> 4

        old = insn_maps.get(insn_bucket_start)
        if old:
            if isinstance(old, int):
                midx = [midx, old]
            else:
                # list
                midx = old + [midx]

        for i in range(insn_bucket_start, insn_bucket_end + 1):
            insn_maps[i] = midx
        # self.insn_offs.append(insn_off)
        # self.insn_off_size[insn_off] = insn_size
        # self.method_map[insn_off].append(midx)

    # return next class data item pos
    def _class_data_parse(self, data : bytes, pos):
        # reuse tinydex logic
        static_fields_size, c = read_uleb128_fast(data, pos); pos += c
        instance_fields_size, c = read_uleb128_fast(data, pos); pos += c
        direct_methods_size, c = read_uleb128_fast(data, pos); pos += c
        virtual_methods_size, c = read_uleb128_fast(data, pos); pos += c
        
        for _ in range(static_fields_size):
            pos += read_uleb128_len(data, pos)
            pos += read_uleb128_len(data, pos)
            
        for _ in range(instance_fields_size):
            pos += read_uleb128_len(data, pos)
            pos += read_uleb128_len(data, pos)
            
        method_idx = 0
        for _ in range(direct_methods_size):
            method_idx_diff, c = read_uleb128_fast(data, pos); pos += c
            method_idx += method_idx_diff
            c = read_uleb128_len(data, pos); pos += c
            code_off, c = read_uleb128_fast(data, pos); pos += c
            self._encoded_method_parse(data, code_off, method_idx)
            
        method_idx = 0
        for _ in range(virtual_methods_size):
            method_idx_diff, c = read_uleb128_fast(data, pos); pos += c
            method_idx += method_idx_diff
            c = read_uleb128_len(data, pos); pos += c
            code_off, c = read_uleb128_fast(data, pos); pos += c
            self._encoded_method_parse(data, code_off, method_idx)
        return pos
    
    def _build_map_bymap(self):
        # dont reuse tinydex, frequent lazy parser may cause bad performance
        # parse all items in one shot by map!
        mapsize = _STRUCT_I.unpack_from(self.buf, self.mapoff)[0]
        mapoff = self.mapoff + 4
        for i in range(mapsize):
            mtype = _STRUCT_H.unpack_from(self.buf, mapoff)[0]
            if mtype == 0x2000:
                break
            mapoff += 0xc
        if mtype != 0x2000:
            self._build_map_bydef()
            return None

        # skip type + unused
        class_data_size, class_data_off = struct.unpack_from("<II", self.buf, mapoff + 4)
        data = bytes(self.buf) # for performance
        for _ in range(class_data_size):
            class_data_off = self._class_data_parse(data, class_data_off)

    def _build_map_bydef(self):
        class_def_off, class_def_size = self.header.classes
        data = bytes(self.buf)
        for i in range(class_def_size):
            class_data_off = _STRUCT_I.unpack_from(self.buf, class_def_off + 24)[0]
            class_def_off += 0x20
            if class_data_off == 0:
                continue
            self._class_data_parse(data, class_data_off)
    
    def parse(self):
        self._build_map_bymap()
        self.parsed = True

    # insn offset to classdef + methodidx
    def locate(self, offsets : list):
        if not self.parsed:
            # parse timing controlled by manager
            return None
        ret_table = []
        insn_maps = self.insn_maps
        for off in offsets:
            ret_table.append(insn_maps.get(off))
        return ret_table
            
