from findrefs.locator.base_locator import BaseLocator
from utils.leb128 import read_uleb128_fast, read_uleb128_len
from collections import defaultdict
import struct

# Auth MG1937
_STRUCT_I = struct.Struct('<I')
_STRUCT_H = struct.Struct('<H')

class InsnLocator(BaseLocator):
    def __init__(self, dex):
        super().__init__(dex)
        self.insn_offs = [] # for sort
        self.method_map = defaultdict(list) # {insn_off : [midx, midx2...]}
        self.insn_off_size = {} # {insn_off : insn_size}

    def _encoded_method_parse(self, data : bytes, pos, midx):
        if pos == 0:
            # code off == 0 means no method body, we dont need to locate it, ignore
            return
        insn_size = _STRUCT_I.unpack_from(data, pos + 12)[0]
        insn_off = pos + 16
        self.insn_offs.append(insn_off)
        self.insn_off_size[insn_off] = insn_size
        self.method_map[insn_off].append(midx)

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
            # fallback to class def parsing
            return None

        # skip type + unused
        class_data_size, class_data_off = struct.unpack_from("<II", self.buf, mapoff + 4)
        data = bytes(self.buf) # for performance
        for _ in range(class_data_size):
            class_data_off = self._class_data_parse(data, class_data_off)

    # insn offset to classdef + methodidx
    def locate(self, offset):
       pass 
