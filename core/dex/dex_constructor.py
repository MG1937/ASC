# Auth: MG1937
# Reconstruct DEX bytes, fill necessary fields

import array
from utils.leb128 import read_uleb128_fast
from utils.leb128 import read_uleb128_len
from utils.dex_parser import parse_encoded_array, parse_debug_info
from utils.tinydex import DEX

class DexHollower:
    # Extract All bytes of specfic item 
    # Hollow out all necessray fields, reconstruct it

    def __init__(self, dex : DEX, dex_buffer : bytearray, clz_str : str, debug: bool = False):
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

        self.clz_data_item_hlws = [] # [(relative_offset,HLW_TYPE,value,leb128len), ...]
        self.clz_data_item_bytes = None
        self.code_item_hlws = [] # [(code_item_bytes, debug_off_pos, debug_off_value, method_idx), ...]
        
        self.static_values_elements = None
        self.debug_info_items = {} # { method_idx: debug_info_dict }
        
        # New generic hollow lists for parsing static values and debug info
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
        ifs_size = int.from_bytes(self._raw_cache[ifs_off : ifs_off + 4], 'little')
        self.ifs_list_hlw_types.append(ifs_size)
        
        ifs_bytes = self._raw_cache[ifs_off + 4 : ifs_off + 4 + ifs_size * 2]
        arr = array.array('H')
        arr.frombytes(ifs_bytes)
        self.ifs_list_hlw_types.extend(arr)
        return ifs_size

    # This method gen By LLM, too complex, I dont want to write it
    def _hollow_class_data_item_bytes(self, off : int):
        if off == 0: return 0
        data = self._raw_cache
        p = off
        
        # 1. Header
        s_f_cnt, c = read_uleb128_fast(data, p); p += c
        i_f_cnt, c = read_uleb128_fast(data, p); p += c
        d_m_cnt, c = read_uleb128_fast(data, p); p += c
        v_m_cnt, c = read_uleb128_fast(data, p); p += c

        # 2. Static Fields
        last_idx = 0
        for _ in range(s_f_cnt):
            diff, c = read_uleb128_fast(data, p)
            last_idx += diff
            self.clz_data_item_hlws.append((p - off, 'F_IDX_D', last_idx, c))
            p += c
            p += read_uleb128_len(data, p)

        # 3. Instance Fields
        last_idx = 0
        for _ in range(i_f_cnt):
            diff, c = read_uleb128_fast(data, p)
            last_idx += diff
            self.clz_data_item_hlws.append((p - off, 'F_IDX_D', last_idx, c))
            p += c
            p += read_uleb128_len(data, p)

        # 4. Direct Methods
        last_idx = 0
        for _ in range(d_m_cnt):
            diff, c = read_uleb128_fast(data, p)
            last_idx += diff
            self.clz_data_item_hlws.append((p - off, 'M_IDX_D', last_idx, c))
            p += c
            p += read_uleb128_len(data, p) # skip acc
            
            # code_off
            val, c = read_uleb128_fast(data, p)
            self.clz_data_item_hlws.append((p - off, 'M_CODE_O', val, c))
            
            if val > 0:
                # Let's align code_off to 4 bytes because Dalvik requires code_item to be 4-byte aligned
                aligned_val = (val + 3) & ~3
                code_item_head = data[aligned_val : aligned_val + 16]
                debug_val = int.from_bytes(code_item_head[8:12], 'little')
                self.code_item_hlws.append((code_item_head, 8, debug_val, last_idx))
            p += c

        # 5. Virtual Methods
        last_idx = 0
        for _ in range(v_m_cnt):
            diff, c = read_uleb128_fast(data, p)
            last_idx += diff
            self.clz_data_item_hlws.append((p - off, 'M_IDX_D', last_idx, c))
            p += c
            p += read_uleb128_len(data, p)
            
            val, c = read_uleb128_fast(data, p)
            self.clz_data_item_hlws.append((p - off, 'M_CODE_O', val, c))
            
            if val > 0:
                aligned_val = (val + 3) & ~3
                code_item_head = data[aligned_val : aligned_val + 16]
                debug_val = int.from_bytes(code_item_head[8:12], 'little')
                self.code_item_hlws.append((code_item_head, 8, debug_val, last_idx))
            p += c

        self.clz_data_item_bytes = data[off : p]

    def hollow(self):
        if self.debug:
            import time
            t_start = time.perf_counter()
        
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
        # ignore annotaion, it is TOO FUCKING COMPLEX!!!
        # ignore it might be buggy or loss decompile precise
        annotations_off = clz_def_data[5]

        # === CLASS_DATA ===
        class_data_off = clz_def_data[6]
        self._hollow_class_data_item_bytes(class_data_off)
        if self.debug: t_class_data = time.perf_counter()
        
        # === STATIC_VALUES ===
        static_values_off = clz_def_data[7]
        if static_values_off != 0:
            self.static_values_elements = parse_encoded_array(self._raw_cache, static_values_off, self.hlw_strs, self.hlw_types, self.hlw_fields, self.hlw_methods)
        if self.debug: t_static = time.perf_counter()
            
        # === DEBUG_INFO ===
        for code_item in self.code_item_hlws:
            debug_info_off = code_item[2]
            method_idx = code_item[3]
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
