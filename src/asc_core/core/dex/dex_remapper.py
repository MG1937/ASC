from utils.tinydex import DEX
from utils.tinydex import Type
from utils.tinydex import DexClass as Class

# Auth: MG1937

class DexOperator:
    # due to lief bugs... need to operate raw bytes in DEX ;(
    def __init__(self, dex : DEX, dex_buffer):
        # preheat for offset operate 
        self.dex = dex
        self._raw_cache = dex_buffer
        self.type_ids_off = self.dex.header.types[0]
        self.string_ids_off = self.dex.header.strings[0]
        self.method_ids_off = self.dex.header.methods[0]
        self.field_ids_off = self.dex.header.fields[0]
        self.proto_ids_off = self.dex.header.prototypes[0]

    def get_type_descidx(self, type_idx):
        # lief has bugs!!!!!! so we need this
        # https://source.android.com/docs/core/runtime/dex-format#type-codes
        offset = self.type_ids_off + (type_idx * 0x4) # type_id_item size == 4
        return int.from_bytes(self._raw_cache[offset:offset+4], 'little')

    def get_proto_shortidx(self, proto_idx):
        # lief cant access shortidx...
        offset = self.proto_ids_off + (proto_idx * 0xC)
        return int.from_bytes(self._raw_cache[offset:offset+4], 'little')

    def get_proto_rettypeidx(self, proto_idx):
        # lief cant access shortidx...
        offset = self.proto_ids_off + (proto_idx * 0xC) + 4 # uint == 4
        return int.from_bytes(self._raw_cache[offset:offset+4], 'little')

    def get_method_proto_idx(self, method_idx):
        # https://source.android.com/docs/core/runtime/dex-format#method-id-item
        offset = self.method_ids_off + (method_idx * 0x8) + 2 # ushort == 2 
        return int.from_bytes(self._raw_cache[offset:offset+2], 'little')

class DexIndexMapper:
    def __init__(self, mapper, dex : DEX, dex_buffer):
        # indexhandler mapper
        self.mapper = mapper
        self.dex = dex
        self.origin_strings = self.dex.strings
        # Cache dex operator methods for performance
        self.dex_operator = DexOperator(dex, dex_buffer)
        self._get_method_proto_idx = self.dex_operator.get_method_proto_idx
        self._get_proto_shortidx = self.dex_operator.get_proto_shortidx
        self._get_proto_rettypeidx = self.dex_operator.get_proto_rettypeidx
        
        self.str_restruct = [] # ["str", ...]
        self.str_restruct_pos = 0
        self.str_restruct_idx = {} # {"str":str_idx, ...}

        self.type_restruct = [] # [type.descriptor_idx, ...]
        self.type_restruct_pos = 0
        self.type_restruct_idx = {} # {origin_idx:new_idx, ...}

        self.proto_restruct = [] # [[shortidx, rettypeidx, paramsize, paramtype, ...], ...]
        self.proto_restruct_pos = 0
        self.proto_restruct_idx = {} # {origin_idx:new_idx, ...}

        self.field_restruct = [] # [[clz_typeidx, type_typeidx, name_stridx], ...]
        self.field_restruct_pos = 0
        self.field_restruct_idx = {} # {origin_idx:new_idx, ...}

        self.method_restruct = [] # [[clz_typeidx, proto_typeidx, name_stridx], ...]
        self.method_restruct_pos = 0
        self.method_restruct_idx = {} # {origin_idx:newidx, ...}
        
    def set_class(self, clz : Class):
        self.class_obj = clz
        self.methods_obj = self.class_obj.methods
        self.fields_obj = self.class_obj.fields

    def set_hollower(self, hollower):
        self.hollower = hollower

    def _fill_data_types(self):
        # fill data types may not necessary, but all dex need these base types... hh
        self.stridx_data_types = {}
        self.typeidx_data_types = {}
        
        primitives = [
            (Type.PRIMITIVES.VOID_T, 'V'),
            (Type.PRIMITIVES.BOOLEAN, 'Z'),
            (Type.PRIMITIVES.BYTE, 'B'),
            (Type.PRIMITIVES.SHORT, 'S'),
            (Type.PRIMITIVES.CHAR, 'C'),
            (Type.PRIMITIVES.INT, 'I'),
            (Type.PRIMITIVES.LONG, 'J'),
            (Type.PRIMITIVES.FLOAT, 'F'),
            (Type.PRIMITIVES.DOUBLE, 'D')
        ]
        
        for prim_type, char in primitives:
            str_idx = self._add_str_restruct(char)
            self.stridx_data_types[prim_type] = str_idx
            # We don't have an origin_idx for these primitives necessarily, 
            # but we can use the string's new index as a descriptor
            type_idx = self._add_type_restruct(str_idx, -1)
            self.typeidx_data_types[prim_type] = type_idx

    def _add_str_restruct(self, string):
        # return mapped string idx
        if string in self.str_restruct_idx:
            return self.str_restruct_idx[string]
        self.str_restruct.append(string)
        self.str_restruct_idx[string] = self.str_restruct_pos
        self.str_restruct_pos += 1
        return self.str_restruct_pos - 1

    def _add_type_restruct(self, desc_idx, origin_idx):
        # return mapped type idx
        if origin_idx == -1:
            origin_idx = tuple([desc_idx])        
        if origin_idx in self.type_restruct_idx:
            return self.type_restruct_idx[origin_idx]
        self.type_restruct.append(desc_idx)
        self.type_restruct_idx[origin_idx] = self.type_restruct_pos
        self.type_restruct_pos += 1
        return self.type_restruct_pos - 1

    def _add_proto_restruct(self, prototype : list, origin_idx):
        # return mapped proto idx
        if origin_idx == -1:
            origin_idx = tuple(prototype)
        if origin_idx in self.proto_restruct_idx:
            return self.proto_restruct_idx[origin_idx]
        self.proto_restruct.append(prototype)
        self.proto_restruct_idx[origin_idx] = self.proto_restruct_pos
        self.proto_restruct_pos += 1
        return self.proto_restruct_pos - 1

    def _add_field_restruct(self, field : list, origin_idx):
        # return mapped field idx
        if origin_idx == -1:
            origin_idx = tuple(field)        
        if origin_idx in self.field_restruct_idx:
            return self.field_restruct_idx[origin_idx]
        self.field_restruct.append(field)
        self.field_restruct_idx[origin_idx] = self.field_restruct_pos
        self.field_restruct_pos += 1
        return self.field_restruct_pos - 1        

    def _add_method_restruct(self, method : list, origin_idx):
        # return mapped method idx
        if origin_idx == -1:
            origin_idx = tuple(method)        
        if origin_idx in self.method_restruct_idx:
            return self.method_restruct_idx[origin_idx]
        self.method_restruct.append(method)
        self.method_restruct_idx[origin_idx] = self.method_restruct_pos
        self.method_restruct_pos += 1
        return self.method_restruct_pos - 1        

    def _append_origin_type(self, origin_type_idx):
        # assume the type never been added
        # return new_typeidx
        origin_desc_idx = self.dex_operator.get_type_descidx(origin_type_idx)
        string = self.origin_strings[origin_desc_idx]
        new_desc_idx = self._add_str_restruct(string)
        return self._add_type_restruct(new_desc_idx, origin_type_idx)

    def _append_string_to_types(self, string):
        # dont care about origin type idx, JUST DROP IT!
        # return new type idx
        desc_idx = self._add_str_restruct(string)
        return self._add_type_restruct(desc_idx, -1)

    def _type_to_descriptor(self, typ):
        if typ.type == Type.TYPES.PRIMITIVE:
            m = {
                Type.PRIMITIVES.VOID_T: 'V',
                Type.PRIMITIVES.BOOLEAN: 'Z',
                Type.PRIMITIVES.BYTE: 'B',
                Type.PRIMITIVES.SHORT: 'S',
                Type.PRIMITIVES.CHAR: 'C',
                Type.PRIMITIVES.INT: 'I',
                Type.PRIMITIVES.LONG: 'J',
                Type.PRIMITIVES.FLOAT: 'F',
                Type.PRIMITIVES.DOUBLE: 'D',
            }
            return m[typ.value]
        elif typ.type == Type.TYPES.ARRAY:
            return '[' * typ.dim + self._type_to_descriptor(typ.underlying_array_type)
        return str(typ)

    def handle(self):
        # === STRING IDX ===
        for i in range(len(self.mapper["STRING"])):
            if i in self.mapper["STRING"]:
                string = self.origin_strings[self.mapper["STRING"][i]]
                self._add_str_restruct(string)

        # === TYPE IDX ===
        for i in range(len(self.mapper["TYPE"])):
            if i in self.mapper["TYPE"]:
                origin_type_idx = self.mapper["TYPE"][i]
                self._append_origin_type(origin_type_idx)

        self._fill_data_types()

        # === FIELD IDX ===
        for i in range(len(self.mapper["FIELD"])):
            if i in self.mapper["FIELD"]:
                origin_field_idx = self.mapper["FIELD"][i]
                if origin_field_idx in self.field_restruct_idx:
                    continue
                field_obj = self.dex.fields[origin_field_idx]
                fld_clz_string = field_obj.cls.fullname
                fld_clz_typeidx = self._append_string_to_types(fld_clz_string)
                fld_type_string = self._type_to_descriptor(field_obj.type)
                fld_type_typeidx = self._append_string_to_types(fld_type_string)
                fld_name_string = field_obj.name
                fld_name_stridx = self._add_str_restruct(fld_name_string)
                new_field = [fld_clz_typeidx, fld_type_typeidx, fld_name_stridx]
                self._add_field_restruct(new_field, field_obj.index)

        # === METHOD IDX ===
        for i in range(len(self.mapper["METHOD"])):
            if i in self.mapper["METHOD"]:
                origin_method_idx = self.mapper["METHOD"][i]
                if origin_method_idx in self.method_restruct_idx:
                    continue
                origin_proto_idx = self._get_method_proto_idx(origin_method_idx)
                short_idx = self._get_proto_shortidx(origin_proto_idx)
                
                shorty = self.origin_strings[short_idx]
                short_idx = self._add_str_restruct(shorty)
                
                rettypeidx = self._get_proto_rettypeidx(origin_proto_idx)
                rettypeidx = self._append_origin_type(rettypeidx)
                
                method = self.dex.methods[origin_method_idx]
                params = method.prototype.parameters_type
                
                param_count = len(params)
                new_prototype = [short_idx, rettypeidx, param_count]

                for param in params:
                    if param.type == Type.TYPES.PRIMITIVE:
                        new_prototype.append(self.typeidx_data_types[param.value])
                        continue
                    param_clz_string = self._type_to_descriptor(param)
                    type_idx = self._append_string_to_types(param_clz_string)
                    new_prototype.append(type_idx)
                new_proto_idx = self._add_proto_restruct(new_prototype, origin_proto_idx)

                mth_cls_name_string = method.cls.fullname
                mth_cls_name_typeidx = self._append_string_to_types(mth_cls_name_string)
                mth_name_string = method.name
                mth_name_stridx = self._add_str_restruct(mth_name_string)
                new_mth = [mth_cls_name_typeidx, new_proto_idx, mth_name_stridx]
                self._add_method_restruct(new_mth, method.index)

        # === CLASS FIELD IDX ===
        for field_obj in self.fields_obj:
            if field_obj.index in self.field_restruct_idx:
                continue
            fld_clz_string = field_obj.cls.fullname
            fld_clz_typeidx = self._append_string_to_types(fld_clz_string)
            fld_type_string = self._type_to_descriptor(field_obj.type)
            fld_type_typeidx = self._append_string_to_types(fld_type_string)
            fld_name_string = field_obj.name
            fld_name_stridx = self._add_str_restruct(fld_name_string)
            new_field = [fld_clz_typeidx, fld_type_typeidx, fld_name_stridx]
            self._add_field_restruct(new_field, field_obj.index)

        # === CLASS METHOD IDX ===
        for method in self.methods_obj:
            if method.index in self.method_restruct_idx:
                continue
            origin_proto_idx = self._get_method_proto_idx(method.index)
            short_idx = self._get_proto_shortidx(origin_proto_idx)
            
            shorty = self.origin_strings[short_idx]
            short_idx = self._add_str_restruct(shorty)
            
            rettypeidx = self._get_proto_rettypeidx(origin_proto_idx)
            rettypeidx = self._append_origin_type(rettypeidx)
            
            params = method.prototype.parameters_type
            
            param_count = len(params)
            new_prototype = [short_idx, rettypeidx, param_count]

            for param in params:
                if param.type == Type.TYPES.PRIMITIVE:
                    new_prototype.append(self.typeidx_data_types[param.value])
                    continue
                param_clz_string = self._type_to_descriptor(param)
                type_idx = self._append_string_to_types(param_clz_string)
                new_prototype.append(type_idx)
            new_proto_idx = self._add_proto_restruct(new_prototype, origin_proto_idx)

            mth_cls_name_string = method.cls.fullname
            mth_cls_name_typeidx = self._append_string_to_types(mth_cls_name_string)
            mth_name_string = method.name
            mth_name_stridx = self._add_str_restruct(mth_name_string)
            new_mth = [mth_cls_name_typeidx, new_proto_idx, mth_name_stridx]
            self._add_method_restruct(new_mth, method.index)

        # === CLASS DEF IDX ===
        if hasattr(self, 'hollower'):
            # map source file
            src_idx = self.hollower.clz_def_hlw_strs.get(0x10)
            if src_idx is not None and src_idx != 0xffffffff:
                src_str = self.origin_strings[src_idx]
                self._add_str_restruct(src_str)
            # map class idx
            clz_idx = self.hollower.clz_def_hlw_types.get(0)
            if clz_idx is not None and clz_idx != 0xffffffff:
                self._append_origin_type(clz_idx)
            # map superclass idx
            super_idx = self.hollower.clz_def_hlw_types.get(0x8)
            if super_idx is not None and super_idx != 0xffffffff:
                self._append_origin_type(super_idx)
            # map interfaces
            ifs_list = self.hollower.ifs_list_hlw_types
            if len(ifs_list) > 0:
                for ifs_idx in ifs_list[1:]:
                    self._append_origin_type(ifs_idx)

            # map generic hollow lists from static values and debug info
            for s_idx in self.hollower.hlw_strs:
                if s_idx != 0xffffffff and s_idx < len(self.origin_strings):
                    self._add_str_restruct(self.origin_strings[s_idx])
            
            for t_idx in self.hollower.hlw_types:
                if t_idx != 0xffffffff:
                    self._append_origin_type(t_idx)
                    
            for f_idx in self.hollower.hlw_fields:
                if f_idx != 0xffffffff:
                    if f_idx not in self.field_restruct_idx:
                        field_obj = self.dex.fields[f_idx]
                        fld_clz_string = field_obj.cls.fullname
                        fld_clz_typeidx = self._append_string_to_types(fld_clz_string)
                        fld_type_string = self._type_to_descriptor(field_obj.type)
                        fld_type_typeidx = self._append_string_to_types(fld_type_string)
                        fld_name_string = field_obj.name
                        fld_name_stridx = self._add_str_restruct(fld_name_string)
                        new_field = [fld_clz_typeidx, fld_type_typeidx, fld_name_stridx]
                        self._add_field_restruct(new_field, field_obj.index)
                        
            for m_idx in self.hollower.hlw_methods:
                if m_idx != 0xffffffff:
                    if m_idx not in self.method_restruct_idx:
                        origin_proto_idx = self._get_method_proto_idx(m_idx)
                        short_idx = self._get_proto_shortidx(origin_proto_idx)
                        
                        shorty = self.origin_strings[short_idx]
                        short_idx = self._add_str_restruct(shorty)
                        
                        rettypeidx = self._get_proto_rettypeidx(origin_proto_idx)
                        rettypeidx = self._append_origin_type(rettypeidx)
                        
                        method = self.dex.methods[m_idx]
                        params = method.prototype.parameters_type
                        
                        param_count = len(params)
                        new_prototype = [short_idx, rettypeidx, param_count]
            
                        for param in params:
                            if param.type == Type.TYPES.PRIMITIVE:
                                new_prototype.append(self.typeidx_data_types[param.value])
                                continue
                            param_clz_string = self._type_to_descriptor(param)
                            type_idx = self._append_string_to_types(param_clz_string)
                            new_prototype.append(type_idx)
                        new_proto_idx = self._add_proto_restruct(new_prototype, origin_proto_idx)
            
                        mth_cls_name_string = method.cls.fullname
                        mth_cls_name_typeidx = self._append_string_to_types(mth_cls_name_string)
                        mth_name_string = method.name
                        mth_name_stridx = self._add_str_restruct(mth_name_string)
                        new_mth = [mth_cls_name_typeidx, new_proto_idx, mth_name_stridx]
                        self._add_method_restruct(new_mth, method.index)

        # === CODE ITEM TRY_ITEM CATCH HANDLER IDX ===
        for method_idx, metadata in self.hollower.code_item_metadata_hlws.items():
            debug_val, catch_handler_list = metadata
            if catch_handler_list:
                # catch_handler_list: [size, [old_off, h_size, type_idx, addr, ...], ...]
                for i in range(1, len(catch_handler_list)):
                    handler = catch_handler_list[i]
                    h_size = handler[1]
                    pos = 2
                    for _ in range(abs(h_size)):
                        old_type_idx = handler[pos]
                        new_type_idx = self._append_origin_type(old_type_idx)
                        handler[pos] = new_type_idx
                        pos += 2

