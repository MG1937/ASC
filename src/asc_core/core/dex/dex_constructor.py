# Auth: MG1937
# Reconstruct DEX bytes, fill necessary fields

import array
import struct

from utils.leb128 import read_uleb128_fast, read_sleb128
from utils.leb128 import read_uleb128_len
from utils.dex_parser import parse_encoded_array, parse_debug_info, parse_annotation_item
from utils.tinydex import DEX

_STRUCT_I = struct.Struct('<I')
_STRUCT_H = struct.Struct('<H')

class DexHollower:
    # Extract All bytes of specfic item 
    # Hollow out all necessray fields, reconstruct it

    def __init__(self, dex : DEX, dex_buffer , clz_str : str, debug: bool = False):
        self.debug = debug
        if self.debug:
            import time
            t_start = time.perf_counter()
        self.dex = dex
        self._raw_cache = dex_buffer
        self.clz = dex.get_class(clz_str)
        if self.debug: t_get_class = time.perf_counter()
        self.clz_idx = self.clz.index
        if self.debug: t_index = time.perf_counter()

        # === hollow list ===
        self.clz_def_hlw_types = {} # {relative_offset:idx, ...}
        self.clz_def_hlw_strs = {} # {relative_offset:idx, ...}

        self.ifs_list_hlw_types = [] # [ifs_size, typeidx, ...]

        self.anno_dir_hlw_types = {} # {relative_offset:idx, ...}

        # hollow clz data wont help speed up build dex, just deprecated it 20260730
        self.clz_data_item_hlws = [] # [(relative_offset,HLW_TYPE,value,leb128len), ...]
        self.clz_data_item_bytes = None

        # adjust for builder
        self.code_item_hlws = {} # {method_idx: (code_item_bytes, try_item_bytes, tries_size)}
        self.code_item_metadata_hlws = {} # {method_idx: (debug_off_pos, encoded_catch_handler_list)}
        # self.code_item_hlws = [] # [(code_item_bytes, debug_off_pos, debug_off_value, method_idx), ...]
        
        self.static_values_elements = None
        self.debug_info_items = {} # { method_idx: debug_info_dict }
        self.annotation_directory = None
        self.annotation_sets = {} # { set_off: {"items": [annotation_off, ...]} }
        self.annotation_items = {} # { annotation_off: parsed_annotation_item }
        self.annotation_set_refs = {} # { ref_list_off: [annotation_set_off, ...] }
        
        # New generic hollow lists for parsing static values and debug info
        # LLM added it for static value parser, but I dont think we will need it hhhh 20260729
        self.hlw_strs = set()
        self.hlw_types = set()
        self.hlw_fields = set()
        self.hlw_methods = set()

        self.clz_def_offset = self.dex.header.classes[0] + self.clz_idx * 0x20
        self.clz_raw_byte = bytes(self._raw_cache[self.clz_def_offset :
                self.clz_def_offset + 0x20]) # class_def_item size == 0x20
        
        if self.debug:
            t_end = time.perf_counter()
            print(f"[DexHollower Init Profiler]")
            print(f"  get_class: {(t_get_class - t_start)*1000000:.2f} us")
            print(f"  clz_index: {(t_index - t_get_class)*1000000:.2f} us")
            print(f"  rest:      {(t_end - t_index)*1000000:.2f} us")

    def _hollow_interface_bytes(self, ifs_off):
        if ifs_off == 0:
            return 0
        # ifs size
        ifs_size = _STRUCT_I.unpack_from(self._raw_cache, ifs_off)[0] # int.from_bytes(self._raw_cache[ifs_off : ifs_off + 4], 'little')
        self.ifs_list_hlw_types.append(ifs_size)
        
        ifs_bytes = self._raw_cache[ifs_off + 4 : ifs_off + 4 + ifs_size * 2]
        arr = array.array('H')
        arr.frombytes(ifs_bytes)
        self.ifs_list_hlw_types.extend(arr)
        return ifs_size

    # LLM write too much hollow redundant logic, I rewrited it 20260730
    def _hollow_class_data_item_bytes(self, off : int):
        if off == 0: return 0
        data = self._raw_cache
        p = off
        
        # Header
        s_f_cnt, c = read_uleb128_fast(data, p); p += c
        i_f_cnt, c = read_uleb128_fast(data, p); p += c
        d_m_cnt, c = read_uleb128_fast(data, p); p += c
        v_m_cnt, c = read_uleb128_fast(data, p); p += c

        # Skip Fields
        for _ in range(s_f_cnt + i_f_cnt):
            p += read_uleb128_len(data, p)
            p += read_uleb128_len(data, p)

        # Direct Methods
        last_idx = 0
        for _ in range(d_m_cnt):
            diff, c = read_uleb128_fast(data, p)
            last_idx += diff
            p += c
            p += read_uleb128_len(data, p) # skip acc
            
            # code_off
            val, c = read_uleb128_fast(data, p)
            p += c
            
            if val > 0:
                # Let's align code_off to 4 bytes because Dalvik requires code_item to be 4-byte aligned
                # 20260429 LLM add it, I am not familiar with alignment details...
                # 20260607 leave the code here, document requires 4 bytes alignment
                # https://source.android.com/docs/core/runtime/dex-format?hl=zh-cn#type-id-item
                aligned_val = (val + 3) & ~3
                code_item_head = data[aligned_val : aligned_val + 16]
                # 20260827 bugfix for misuse of 2 bytes unpacker, debug_info_off should be 4 bytes..
                debug_val = _STRUCT_I.unpack_from(code_item_head, 8)[0] # int.from_bytes(code_item_head[8:12], 'little')
                tries_size = _STRUCT_H.unpack_from(code_item_head, 6)[0] # int.from_bytes(code_item_head[6:8], 'little')
                try_item_bytes = None
                encoded_catch_handler_list = None
                if tries_size != 0: # try catch bugfix 20260730
                    insns_size = _STRUCT_H.unpack_from(code_item_head, 12)[0] # int.from_bytes(code_item_head[12:16], 'little')
                    insns_end = aligned_val + 16 + insns_size * 2
                    try_off = (insns_end + 3) & ~3 # 4 bytes aligned
                    try_off_end = try_off + tries_size * 8
                    try_item_bytes = data[try_off : try_off_end]
                    encoded_catch_handler_list = self._hollow_encoded_catch_handler_list(data, try_off_end)
                self.code_item_hlws[last_idx] = (code_item_head, try_item_bytes, tries_size)
                self.code_item_metadata_hlws[last_idx] = (debug_val, encoded_catch_handler_list)                

        # Virtual Methods
        last_idx = 0
        for _ in range(v_m_cnt):
            diff, c = read_uleb128_fast(data, p)
            last_idx += diff
            p += c
            p += read_uleb128_len(data, p) # skip acc
            
            # code_off
            val, c = read_uleb128_fast(data, p)
            p += c
            
            if val > 0:
                aligned_val = (val + 3) & ~3
                code_item_head = data[aligned_val : aligned_val + 16]
                debug_val = _STRUCT_I.unpack_from(code_item_head, 8)[0]
                tries_size = _STRUCT_H.unpack_from(code_item_head, 6)[0]
                try_item_bytes = None
                encoded_catch_handler_list = None
                if tries_size != 0:
                    insns_size = _STRUCT_H.unpack_from(code_item_head, 12)[0]
                    insns_end = aligned_val + 16 + insns_size * 2
                    try_off = (insns_end + 3) & ~3 # 4 bytes aligned
                    try_off_end = try_off + tries_size * 8
                    try_item_bytes = data[try_off : try_off_end]
                    encoded_catch_handler_list = self._hollow_encoded_catch_handler_list(data, try_off_end)
                self.code_item_hlws[last_idx] = (code_item_head, try_item_bytes, tries_size)
                self.code_item_metadata_hlws[last_idx] = (debug_val, encoded_catch_handler_list)                
        # self.clz_data_item_bytes = data[off : p]

    # I dont handle try item and catch handler, so decompiler pesudo is not complete
    # change hollow flow to fix try catch issue 20260730
    def _hollow_encoded_catch_handler_list(self, data, off):
        # encoded_catch_handler_list struct [handler_off, size, encoded_catch_handler]
        base_off = off
        size, c = read_uleb128_fast(data, off)
        encoded_catch_handler_list = [size]
        off += c
        for _ in range(size):
            encoded_catch_handler = []
            encoded_catch_handler.append(off - base_off)
            h_size, c = read_sleb128(data, off)
            encoded_catch_handler.append(h_size)
            off += c
            for _ in range(abs(h_size)):
                type_idx, c = read_uleb128_fast(data, off)
                encoded_catch_handler.append(type_idx)
                off += c
                addr, c = read_uleb128_fast(data, off)
                encoded_catch_handler.append(addr)
                off += c
            if h_size <= 0:
                catch_all_addr, c = read_uleb128_fast(data, off)
                encoded_catch_handler.append(catch_all_addr)
                off += c
            encoded_catch_handler_list.append(encoded_catch_handler)
        return encoded_catch_handler_list

    def _hollow_annotation_set_item(self, off : int):
        if off == 0 or off in self.annotation_sets:
            return
        data = self._raw_cache
        size = _STRUCT_I.unpack_from(data, off)[0]
        items = []
        p = off + 4
        for _ in range(size):
            annotation_off = _STRUCT_I.unpack_from(data, p)[0]
            p += 4
            items.append(annotation_off)
            if annotation_off != 0 and annotation_off not in self.annotation_items:
                self.annotation_items[annotation_off] = parse_annotation_item(
                    data,
                    annotation_off,
                    self.hlw_strs,
                    self.hlw_types,
                    self.hlw_fields,
                    self.hlw_methods,
                )
        self.annotation_sets[off] = {
            'items': items,
        }

    def _hollow_annotation_set_ref_list(self, off : int):
        if off == 0 or off in self.annotation_set_refs:
            return
        data = self._raw_cache
        size = _STRUCT_I.unpack_from(data, off)[0]
        refs = []
        p = off + 4
        for _ in range(size):
            set_off = _STRUCT_I.unpack_from(data, p)[0]
            p += 4
            refs.append(set_off)
            self._hollow_annotation_set_item(set_off)
        self.annotation_set_refs[off] = refs

    def _hollow_annotation_directory_item(self, off : int):
        if off == 0:
            return
        data = self._raw_cache
        class_annotations_off, fields_size, methods_size, parameters_size = struct.unpack_from('<4I', data, off)
        self._hollow_annotation_set_item(class_annotations_off)

        p = off + 16
        field_annotations = []
        for _ in range(fields_size):
            field_idx, annotations_off = struct.unpack_from('<2I', data, p)
            p += 8
            field_annotations.append((field_idx, annotations_off))
            self.hlw_fields.add(field_idx)
            self._hollow_annotation_set_item(annotations_off)

        method_annotations = []
        for _ in range(methods_size):
            method_idx, annotations_off = struct.unpack_from('<2I', data, p)
            p += 8
            method_annotations.append((method_idx, annotations_off))
            self.hlw_methods.add(method_idx)
            self._hollow_annotation_set_item(annotations_off)

        parameter_annotations = []
        for _ in range(parameters_size):
            method_idx, annotations_off = struct.unpack_from('<2I', data, p)
            p += 8
            parameter_annotations.append((method_idx, annotations_off))
            self.hlw_methods.add(method_idx)
            self._hollow_annotation_set_ref_list(annotations_off)

        self.annotation_directory = {
            'class_annotations_off': class_annotations_off,
            'field_annotations': field_annotations,
            'method_annotations': method_annotations,
            'parameter_annotations': parameter_annotations,
        }

    def hollow(self):
        if self.debug:
            import time
            t_start = time.perf_counter()

        # WAIT A FUKING MINITE, I should write must of the parse logic by myself
        # I tell LLM to optimize debug info parser, LLM just rewrite whole parse logic and move it to dex_parser.py
        # Almost half of my handwritten logic gone, 
        # today when I try to fix try_item issue, I found my code is gone! FUCK! 20260729
        
        # === CLASS_DEF_ITEM ===
        # https://source.android.com/docs/core/runtime/dex-format#class-def-item
        clz_def_data = array.array('I', self.clz_raw_byte)
        self.clz_def_hlw_types[0] = clz_def_data[0] # class_idx
        self.clz_def_hlw_types[0x4 * 2] = clz_def_data[2] # superclass_idx
        self.clz_def_hlw_strs[0x4 * 4] = clz_def_data[4] # source_file_idx

        interfaces_off = clz_def_data[3]
        self._hollow_interface_bytes(interfaces_off)
        if self.debug: t_ifs = time.perf_counter()

        # === ANNOTATION ===
        annotations_off = clz_def_data[5]
        self._hollow_annotation_directory_item(annotations_off)

        # === CLASS_DATA ===
        class_data_off = clz_def_data[6]
        self._hollow_class_data_item_bytes(class_data_off)
        if self.debug: t_class_data = time.perf_counter()
        
        # === STATIC_VALUES ===
        static_values_off = clz_def_data[7]
        if static_values_off != 0:
            # which may never be executed, I tried many way to compile a java file contains static fields to dex, never meet static_value_off > 0
            # but LLM still generate this parse, IDK why.. 20260729
            self.static_values_elements = parse_encoded_array(self._raw_cache, static_values_off, self.hlw_strs, self.hlw_types, self.hlw_fields, self.hlw_methods)
        if self.debug: t_static = time.perf_counter()
            
        # === DEBUG_INFO ===
        for method_idx in self.code_item_hlws:
            debug_info_off = self.code_item_metadata_hlws[method_idx][0]
            if debug_info_off != 0:
                self.debug_info_items[method_idx] = parse_debug_info(self._raw_cache, debug_info_off, self.hlw_strs, self.hlw_types)
        if self.debug:
            t_debug = time.perf_counter()
            print(f"[DexHollower Profiler]")
            print(f"  Interfaces:  {(t_ifs - t_start)*1000000:.2f} us")
            print(f"  Class Data:  {(t_class_data - t_ifs)*1000000:.2f} us")
            print(f"  Static Vals: {(t_static - t_class_data)*1000000:.2f} us")
            print(f"  Debug Info:  {(t_debug - t_static)*1000000:.2f} us")
            print(f"  Total:       {(t_debug - t_start)*1000000:.2f} us")
