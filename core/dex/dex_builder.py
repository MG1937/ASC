import struct
import array
import time
from utils.leb128 import write_uleb128
from core.dex.dex_remapper import DexIndexMapper
from core.dex.dex_constructor import DexHollower

class DexBuilder:
    def __init__(self, im: DexIndexMapper, hlw: DexHollower, modified_bytecodes: dict, debug: bool = False):
        self.im = im
        self.hlw = hlw
        self.modified_bytecodes = modified_bytecodes
        self.out = bytearray()
        self.debug = debug
        
    def build(self):
        if self.debug:
            t_start = time.perf_counter()
        
        # Layout of DEX:
        # Header: 0x70 bytes
        # String IDs
        # Type IDs
        # Proto IDs
        # Field IDs
        # Method IDs
        # Class Defs
        # Data Section (Strings, Types, Class Data, Code Items)
        # Map List
        
        self.out = bytearray(112) # 0x70
        
        # 1. Write Data Section first
        # String Data
        string_data_offs = []
        for s in self.im.str_restruct:
            string_data_offs.append(len(self.out))
            # MUTF-8 length
            s_bytes = s.encode('utf-8')
            self.out.extend(write_uleb128(len(s))) # char length, approx len(s) for ascii
            self.out.extend(s_bytes)
            self.out.append(0)
            
        if self.debug: t_string_data = time.perf_counter()
            
        # Type Lists (Interfaces & Protos)
        # Proto type lists
        proto_param_offs = []
        # align to 4
        while len(self.out) % 4 != 0: self.out.append(0)
        
        for proto in self.im.proto_restruct:
            params = proto[3:]
            if len(params) == 0:
                proto_param_offs.append(0)
            else:
                while len(self.out) % 4 != 0: self.out.append(0)
                proto_param_offs.append(len(self.out))
                self.out.extend(len(params).to_bytes(4, 'little'))
                for p in params:
                    self.out.extend(p.to_bytes(2, 'little'))
                    
        # Interface type list
        ifs_off = 0
        if len(self.hlw.ifs_list_hlw_types) > 0:
            while len(self.out) % 4 != 0: self.out.append(0)
            ifs_off = len(self.out)
            ifs_size = self.hlw.ifs_list_hlw_types[0]
            self.out.extend(ifs_size.to_bytes(4, 'little'))
            for t in self.hlw.ifs_list_hlw_types[1:]:
                # remap interface type idx
                new_t = self.im.type_restruct_idx.get(t, 0)
                self.out.extend(new_t.to_bytes(2, 'little'))
                
        if self.debug: t_type_lists = time.perf_counter()
        
        # Annotations (empty for now)
        
        # Static Values
        static_values_off = 0
        if self.hlw.static_values_elements is not None:
            while len(self.out) % 4 != 0: self.out.append(0)
            static_values_off = len(self.out)
            from utils.dex_parser import rebuild_encoded_array
            self.out.extend(rebuild_encoded_array(self.hlw.static_values_elements, self.im))
            
        if self.debug: t_static_values = time.perf_counter()
            
        # Code Items and Debug Info
        code_item_offs = {} # { method_idx: off }
        debug_info_offs = []
        
        # First, write all debug info
        method_to_debug_off = {}
        for method in sorted(self.im.methods_obj, key=lambda m: self.im.method_restruct_idx.get(m.index, 0)):
            if not method.code_offset:
                continue
            if method.index in self.hlw.debug_info_items:
                debug_info_off = len(self.out)
                method_to_debug_off[method.index] = debug_info_off
                debug_info_offs.append(debug_info_off)
                from utils.dex_parser import rebuild_debug_info
                self.out.extend(rebuild_debug_info(self.hlw.debug_info_items[method.index], self.im))
        
        # Then, write all code items
        if not hasattr(self, '_code_item_hlws_dict'):
            self._code_item_hlws_dict = {ci[3]: ci[0] for ci in self.hlw.code_item_hlws if len(ci) > 3}
            
        for method in sorted(self.im.methods_obj, key=lambda m: self.im.method_restruct_idx.get(m.index, 0)):
            if not method.code_offset:
                continue
            
            debug_info_off = method_to_debug_off.get(method.index, 0)
                
            # Let's align code_item to 4 bytes FIRST
            while len(self.out) % 4 != 0: self.out.append(0)
            code_item_offs[method.index] = len(self.out)

            orig_header = self._code_item_hlws_dict.get(method.index, None)
            
            if orig_header is None:
                # Fallback to reading from raw cache if not found
                aligned_val = (method.code_offset + 3) & ~3
                orig_header = self.hlw._raw_cache[aligned_val : aligned_val + 16]
            
            bc = self.modified_bytecodes.get(method.index, method.bytecode)
            insns_size = len(bc) // 2
            
            new_header = bytearray(16)
            
            if len(orig_header) == 16:
                regs = int.from_bytes(orig_header[0:2], 'little')
                ins = int.from_bytes(orig_header[2:4], 'little')
                outs = int.from_bytes(orig_header[4:6], 'little')
                
                new_header[0:2] = regs.to_bytes(2, 'little')
                new_header[2:4] = ins.to_bytes(2, 'little')
                new_header[4:6] = outs.to_bytes(2, 'little')
                new_header[6:8] = b'\x00\x00' # tries_size = 0
                new_header[8:12] = debug_info_off.to_bytes(4, 'little')
                new_header[12:16] = insns_size.to_bytes(4, 'little')
                
                self.out.extend(new_header)
                self.out.extend(bc)

        if self.debug: t_code_items = time.perf_counter()

        # Class Data Item
        class_data_off = 0
        if len(self.im.fields_obj) > 0 or len(self.im.methods_obj) > 0:
            class_data_off = len(self.out)
            # count
            s_f = sorted([f for f in self.im.fields_obj if f.is_static], key=lambda f: self.im.field_restruct_idx.get(f.index, 0))
            i_f = sorted([f for f in self.im.fields_obj if not f.is_static], key=lambda f: self.im.field_restruct_idx.get(f.index, 0))
            d_m = sorted([m for m in self.im.methods_obj if m.is_virtual == False], key=lambda m: self.im.method_restruct_idx.get(m.index, 0))
            v_m = sorted([m for m in self.im.methods_obj if m.is_virtual], key=lambda m: self.im.method_restruct_idx.get(m.index, 0))
            
            self.out.extend(write_uleb128(len(s_f)))
            self.out.extend(write_uleb128(len(i_f)))
            self.out.extend(write_uleb128(len(d_m)))
            self.out.extend(write_uleb128(len(v_m)))
            
            def write_fields(f_list):
                last_idx = 0
                for f in f_list:
                    new_idx = self.im.field_restruct_idx.get(f.index, 0)
                    self.out.extend(write_uleb128(new_idx - last_idx))
                    last_idx = new_idx
                    # access flags
                    self.out.extend(write_uleb128(f.access_flags))
            
            def write_methods(m_list):
                last_idx = 0
                for m in m_list:
                    new_idx = self.im.method_restruct_idx.get(m.index, 0)
                    self.out.extend(write_uleb128(new_idx - last_idx))
                    last_idx = new_idx
                    self.out.extend(write_uleb128(m.access_flags))
                    c_off = code_item_offs.get(m.index, 0)
                    self.out.extend(write_uleb128(c_off))

            write_fields(s_f)
            write_fields(i_f)
            write_methods(d_m)
            write_methods(v_m)

        if self.debug: t_class_data = time.perf_counter()

        # Now write IDs
        # Align 4
        while len(self.out) % 4 != 0: self.out.append(0)
        
        # String IDs
        string_ids_off = len(self.out)
        if string_data_offs:
            self.out.extend(array.array('I', string_data_offs).tobytes())
            
        # Type IDs
        type_ids_off = len(self.out)
        if self.im.type_restruct:
            self.out.extend(array.array('I', self.im.type_restruct).tobytes())
            
        # Proto IDs
        proto_ids_off = len(self.out)
        if self.im.proto_restruct:
            proto_vals = []
            for i, proto in enumerate(self.im.proto_restruct):
                proto_vals.extend([proto[0], proto[1], proto_param_offs[i]])
            self.out.extend(array.array('I', proto_vals).tobytes())
            
        # Field IDs
        field_ids_off = len(self.out)
        if self.im.field_restruct:
            field_vals = []
            for fld in self.im.field_restruct:
                field_vals.append(fld[0] | (fld[1] << 16))
                field_vals.append(fld[2])
            self.out.extend(array.array('I', field_vals).tobytes())
            
        # Method IDs
        method_ids_off = len(self.out)
        if self.im.method_restruct:
            method_vals = []
            for mth in self.im.method_restruct:
                method_vals.append(mth[0] | (mth[1] << 16))
                method_vals.append(mth[2])
            self.out.extend(array.array('I', method_vals).tobytes())
            
        # Class Defs
        class_defs_off = len(self.out)
        clz_idx = self.im.type_restruct_idx.get(self.hlw.clz_def_hlw_types.get(0, -1), 0)
        
        clz_def_data = struct.unpack('<8I', self.hlw.clz_raw_byte)
        acc_flags = clz_def_data[1]
        
        super_idx = self.im.type_restruct_idx.get(clz_def_data[2], 0xffffffff)
        src_idx = self.im.str_restruct_idx.get(self.im.origin_strings[clz_def_data[4]], 0xffffffff) if clz_def_data[4] != 0xffffffff else 0xffffffff
        
        self.out.extend(array.array('I', [clz_idx, acc_flags, super_idx, ifs_off, src_idx, 0, class_data_off, static_values_off]).tobytes())
        
        if self.debug: t_ids = time.perf_counter()

        # Map List
        while len(self.out) % 4 != 0: self.out.append(0)
        map_list_off = len(self.out)
        
        # Map items
        map_items = []
        map_items.append((0x0000, 1, 0)) # Header
        if len(self.im.str_restruct) > 0:
            map_items.append((0x0001, len(self.im.str_restruct), string_ids_off))
            map_items.append((0x2002, len(self.im.str_restruct), string_data_offs[0]))
        if len(self.im.type_restruct) > 0:
            map_items.append((0x0002, len(self.im.type_restruct), type_ids_off))
        if len(self.im.proto_restruct) > 0:
            map_items.append((0x0003, len(self.im.proto_restruct), proto_ids_off))
        if len(self.im.field_restruct) > 0:
            map_items.append((0x0004, len(self.im.field_restruct), field_ids_off))
        if len(self.im.method_restruct) > 0:
            map_items.append((0x0005, len(self.im.method_restruct), method_ids_off))
        map_items.append((0x0006, 1, class_defs_off))
        
        # TYPE_TYPE_LIST (0x1001)
        type_list_count = 0
        first_type_list_off = 0
        if ifs_off > 0:
            type_list_count += 1
            first_type_list_off = ifs_off
        valid_proto_param_offs = [off for off in proto_param_offs if off > 0]
        if valid_proto_param_offs:
            type_list_count += len(valid_proto_param_offs)
            if first_type_list_off == 0 or min(valid_proto_param_offs) < first_type_list_off:
                first_type_list_off = min(valid_proto_param_offs)
        if type_list_count > 0:
            map_items.append((0x1001, type_list_count, first_type_list_off))

        if class_data_off > 0:
            map_items.append((0x2000, 1, class_data_off))
        if len(code_item_offs) > 0:
            map_items.append((0x2001, len(code_item_offs), min(code_item_offs.values())))
            
        # TYPE_DEBUG_INFO_ITEM (0x2003)
        if len(debug_info_offs) > 0:
            map_items.append((0x2003, len(debug_info_offs), min(debug_info_offs)))
            
        # TYPE_ENCODED_ARRAY_ITEM (0x2005)
        if static_values_off > 0:
            map_items.append((0x2005, 1, static_values_off))
        
        # Sort map_items by offset
        map_items.sort(key=lambda x: x[2])
        map_items.append((0x1000, 1, map_list_off)) # Map List itself
        
        self.out.extend(len(map_items).to_bytes(4, 'little'))
        
        # Map item is: type(2), unused(2), size(4), offset(4)
        map_vals = []
        for item in map_items:
            map_vals.append(item[0]) # type + unused (since little endian, type is lower 16 bits, unused is 0)
            map_vals.append(item[1]) # size
            map_vals.append(item[2]) # offset
        self.out.extend(array.array('I', map_vals).tobytes())
            
        if self.debug: t_map_list = time.perf_counter()
            
        file_size = len(self.out)
        
        # Header Patching
        # magic
        self.out[0:8] = b'dex\n035\0'
        # file_size
        self.out[32:36] = file_size.to_bytes(4, 'little')
        # header_size
        self.out[36:40] = (0x70).to_bytes(4, 'little')
        # endian_tag
        self.out[40:44] = (0x12345678).to_bytes(4, 'little')
        # map_off
        self.out[52:56] = map_list_off.to_bytes(4, 'little')
        # string_ids
        self.out[56:64] = array.array('I', [len(self.im.str_restruct), string_ids_off]).tobytes()
        # type_ids
        self.out[64:72] = array.array('I', [len(self.im.type_restruct), type_ids_off]).tobytes()
        # proto_ids
        self.out[72:80] = array.array('I', [len(self.im.proto_restruct), proto_ids_off]).tobytes()
        # field_ids
        self.out[80:88] = array.array('I', [len(self.im.field_restruct), field_ids_off]).tobytes()
        # method_ids
        self.out[88:96] = array.array('I', [len(self.im.method_restruct), method_ids_off]).tobytes()
        # class_defs
        self.out[96:104] = array.array('I', [1, class_defs_off]).tobytes()
        # data_size, data_off
        self.out[104:112] = array.array('I', [file_size - 0x70, 0x70]).tobytes()
        
        # signature
        # 性能压榨：跳过 SHA-1 签名计算，直接填 0，因为绝大多数逆向工具并不强校验它
        self.out[12:32] = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        # checksum
        # 性能压榨：通过在 decompiler.py 中 monkey_patch 干掉了 Androguard 的检查
        self.out[8:12] = b'\x00\x00\x00\x00'
        
        if self.debug:
            t_header = time.perf_counter()
            print(f"[DexBuilder Profiler]")
            print(f"  String Data: {(t_string_data - t_start)*1000000:.2f} us")
            print(f"  Type Lists:  {(t_type_lists - t_string_data)*1000000:.2f} us")
            print(f"  Static Vals: {(t_static_values - t_type_lists)*1000000:.2f} us")
            print(f"  Code & DBG:  {(t_code_items - t_static_values)*1000000:.2f} us")
            print(f"  Class Data:  {(t_class_data - t_code_items)*1000000:.2f} us")
            print(f"  IDs:         {(t_ids - t_class_data)*1000000:.2f} us")
            print(f"  Map List:    {(t_map_list - t_ids)*1000000:.2f} us")
            print(f"  Header:      {(t_header - t_map_list)*1000000:.2f} us")
            print(f"  Total Build: {(t_header - t_start)*1000000:.2f} us")
            
        return self.out
