import struct
import io
from utils.leb128 import read_uleb128_fast
import bisect

_STRUCT_I = struct.Struct('<I')
_STRUCT_H = struct.Struct('<H')
_STRUCT_III = struct.Struct('<III')
_STRUCT_HHI = struct.Struct('<HHI')
_STRUCT_HHHHII = struct.Struct('<HHHHII')

class DEXHeader:
    def __init__(self, buf):
        # 0x3c offset == ids_off, 0x38 offset == ids_size
        self.strings = (_STRUCT_I.unpack_from(buf, 0x3C)[0], _STRUCT_I.unpack_from(buf, 0x38)[0])
        # 0x44 offset == ids_off, 0x40 offset == ids_size
        self.types = (_STRUCT_I.unpack_from(buf, 0x44)[0], _STRUCT_I.unpack_from(buf, 0x40)[0])
        self.prototypes = (_STRUCT_I.unpack_from(buf, 0x4C)[0], _STRUCT_I.unpack_from(buf, 0x48)[0])
        self.fields = (_STRUCT_I.unpack_from(buf, 0x54)[0], _STRUCT_I.unpack_from(buf, 0x50)[0])
        self.methods = (_STRUCT_I.unpack_from(buf, 0x5C)[0], _STRUCT_I.unpack_from(buf, 0x58)[0])
        self.classes = (_STRUCT_I.unpack_from(buf, 0x64)[0], _STRUCT_I.unpack_from(buf, 0x60)[0])

class PrimitiveTypes:
    VOID_T = 0
    BOOLEAN = 1
    BYTE = 2
    SHORT = 3
    CHAR = 4
    INT = 5
    LONG = 6
    FLOAT = 7
    DOUBLE = 8

class TypeTypes:
    PRIMITIVE = 1
    CLASS = 2
    ARRAY = 3

class Type:
    PRIMITIVES = PrimitiveTypes
    TYPES = TypeTypes

    def __init__(self, descriptor):
        self.descriptor = descriptor
        self.dim = 0
        self.underlying_array_type = None
        self.value = None
        self.type = None
        self._parse()

    def _parse(self):
        desc = self.descriptor
        while desc.startswith('['):
            self.dim += 1
            desc = desc[1:]
        
        if self.dim > 0:
            self.type = self.TYPES.ARRAY
            self.underlying_array_type = Type(desc)
            return

        if desc == 'V':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.VOID_T
        elif desc == 'Z':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.BOOLEAN
        elif desc == 'B':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.BYTE
        elif desc == 'S':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.SHORT
        elif desc == 'C':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.CHAR
        elif desc == 'I':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.INT
        elif desc == 'J':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.LONG
        elif desc == 'F':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.FLOAT
        elif desc == 'D':
            self.type = self.TYPES.PRIMITIVE
            self.value = self.PRIMITIVES.DOUBLE
        else:
            self.type = self.TYPES.CLASS
            self.value = desc

    def __str__(self):
        return self.descriptor

class DexString:
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return self.value

class DexPrototype:
    def __init__(self, dex, proto_idx):
        offset = dex.header.prototypes[0] + proto_idx * 12
        self.shorty_idx, self.return_type_idx, self.parameters_off = _STRUCT_III.unpack_from(dex.buf, offset)
        self.dex = dex

    @property
    def parameters_type(self):
        if not hasattr(self, '_parameters_type'):
            if self.parameters_off == 0:
                self._parameters_type = []
            else:
                size = _STRUCT_I.unpack_from(self.dex.buf, self.parameters_off)[0]
                params = []
                off = self.parameters_off + 4
                for _ in range(size):
                    type_idx = _STRUCT_H.unpack_from(self.dex.buf, off)[0]
                    off += 2
                    params.append(self.dex.get_type(type_idx))
                self._parameters_type = params
        return self._parameters_type

class DexField:
    def __init__(self, dex, field_idx):
        self.index = field_idx
        self.dex = dex
        offset = dex.header.fields[0] + field_idx * 8
        self.class_idx, self.type_idx, self.name_idx = _STRUCT_HHI.unpack_from(dex.buf, offset)
        self.access_flags = 0
        self.is_static = False

    @property
    def cls(self):
        if not hasattr(self, '_cls'):
            class Cls:
                def __init__(self, fullname):
                    self.fullname = fullname
            self._cls = Cls(self.dex.get_type(self.class_idx).descriptor)
        return self._cls

    @property
    def type(self):
        return self.dex.get_type(self.type_idx)

    @property
    def name(self):
        return self.dex.strings[self.name_idx]

class DexMethod:
    def __init__(self, dex, method_idx):
        self.index = method_idx
        self.dex = dex
        offset = dex.header.methods[0] + method_idx * 8
        self.class_idx, self.proto_idx, self.name_idx = _STRUCT_HHI.unpack_from(dex.buf, offset)
        self._bytecode = None
        self._code_off = 0
        self.access_flags = 0
        self.is_direct = False
        self.is_virtual = False

    @property
    def cls(self):
        if not hasattr(self, '_cls'):
            class Cls:
                def __init__(self, fullname):
                    self.fullname = fullname
            self._cls = Cls(self.dex.get_type(self.class_idx).descriptor)
        return self._cls

    @property
    def name(self):
        return self.dex.strings[self.name_idx]

    @property
    def prototype(self):
        if not hasattr(self, '_prototype'):
            self._prototype = DexPrototype(self.dex, self.proto_idx)
        return self._prototype

    @property
    def code_offset(self):
        return self._code_off

    @property
    def bytecode(self):
        if self._bytecode is not None:
            return self._bytecode
        if self._code_off == 0:
            return []
        
        # Parse code_item
        off = self._code_off
        registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = _STRUCT_HHHHII.unpack_from(self.dex.buf, off)
        off += 16
        
        insns_bytes = self.dex.buf[off : off + insns_size * 2]
        self._bytecode = list(insns_bytes)
        return self._bytecode

class DexClass:
    def __init__(self, dex, class_idx, class_def_off, class_index):
        self.dex = dex
        self.class_idx = class_idx
        self.index = class_index
        self._class_def_off = class_def_off
        
        self.class_data_off = _STRUCT_I.unpack_from(dex.buf, class_def_off + 24)[0]
        
        self._methods = []
        self._fields = []
        self._parsed = False

    @property
    def fullname(self):
        if not hasattr(self, '_fullname'):
            self._fullname = self.dex.get_type(self.class_idx).descriptor
        return self._fullname

    def _parse_class_data(self):
        if self._parsed:
            return
        self._parsed = True
        
        if self.class_data_off == 0:
            return
            
        data = self.dex.buf
        pos = self.class_data_off
        static_fields_size, c = read_uleb128_fast(data, pos); pos += c
        instance_fields_size, c = read_uleb128_fast(data, pos); pos += c
        direct_methods_size, c = read_uleb128_fast(data, pos); pos += c
        virtual_methods_size, c = read_uleb128_fast(data, pos); pos += c
        
        field_idx = 0
        for _ in range(static_fields_size):
            field_idx_diff, c = read_uleb128_fast(data, pos); pos += c
            field_idx += field_idx_diff
            access_flags, c = read_uleb128_fast(data, pos); pos += c
            f = DexField(self.dex, field_idx)
            f.access_flags = access_flags
            f.is_static = True
            self._fields.append(f)
            
        field_idx = 0
        for _ in range(instance_fields_size):
            field_idx_diff, c = read_uleb128_fast(data, pos); pos += c
            field_idx += field_idx_diff
            access_flags, c = read_uleb128_fast(data, pos); pos += c
            f = DexField(self.dex, field_idx)
            f.access_flags = access_flags
            f.is_static = False
            self._fields.append(f)
            
        method_idx = 0
        for _ in range(direct_methods_size):
            method_idx_diff, c = read_uleb128_fast(data, pos); pos += c
            method_idx += method_idx_diff
            access_flags, c = read_uleb128_fast(data, pos); pos += c
            code_off, c = read_uleb128_fast(data, pos); pos += c
            
            m = DexMethod(self.dex, method_idx)
            m._code_off = code_off
            m.access_flags = access_flags
            m.is_direct = True
            self._methods.append(m)
            
        method_idx = 0
        for _ in range(virtual_methods_size):
            method_idx_diff, c = read_uleb128_fast(data, pos); pos += c
            method_idx += method_idx_diff
            access_flags, c = read_uleb128_fast(data, pos); pos += c
            code_off, c = read_uleb128_fast(data, pos); pos += c
            
            m = DexMethod(self.dex, method_idx)
            m._code_off = code_off
            m.access_flags = access_flags
            m.is_direct = False
            m.is_virtual = True
            self._methods.append(m)

    @property
    def methods(self):
        self._parse_class_data()
        return self._methods

    @property
    def fields(self):
        self._parse_class_data()
        return self._fields

class DEX:
    @staticmethod
    def parse(buf, name=""):
        return DEX(buf, name)

    def __init__(self, buf, name=""):
        self.buf = memoryview(buf)
        self.name = name
        self.header = DEXHeader(self.buf)
        
        self._strings = None
        self._types = None
        self._methods = None
        self._fields = None
        self._classes = None

    # lazy parse
    def get_string(self, str_idx):
        if self._strings is None:
            self._strings = {}

        if str_idx in self._strings:
            return self._strings[str_idx]

        str_idx_off = self.header.strings[0]
        str_size = self.header.strings[1]
        string_off = _STRUCT_I.unpack_from(self.buf, str_idx_off + str_idx * 4)[0]
        utf16_size, c = read_uleb128_fast(self.buf, string_off)
        data_start = string_off + c
        end = data_start + utf16_size
        s = bytes(self.buf[data_start:end]).decode('utf-8', errors='replace')
        self._strings[str_idx] = s
        return s

#    def _init_string_offsets(self):
#        if not hasattr(self, '_string_offsets') or self._string_offsets is None:
#            off = self.header.strings[0]
#            size = self.header.strings[1]
#            if size > 0:
#                self._string_offsets = struct.unpack_from(f'<{size}I', self.buf, off)
#            else:
#                self._string_offsets = ()

    @property
    def strings(self):
        class StringsProxy:
            def __init__(self, dex):
                self.dex = dex
            def __getitem__(self, idx):
                return self.dex.get_string(idx)
            def __len__(self):
                return self.dex.header.strings[1]
        return StringsProxy(self)

    def get_type(self, type_idx):
        if self._types is None:
            self._types = {}
        
        if type_idx not in self._types:
            off = self.header.types[0]
            type_off = off + type_idx * 4
            str_idx = _STRUCT_I.unpack_from(self.buf, type_off)[0]
            self._types[type_idx] = Type(self.strings[str_idx])
            
        return self._types[type_idx]

    @property
    def types(self):
        class TypesProxy:
            def __init__(self, dex):
                self.dex = dex
            def __getitem__(self, idx):
                return self.dex.get_type(idx)
            def __len__(self):
                return self.dex.header.types[1]
        return TypesProxy(self)

    def get_method(self, method_idx):
        if self._methods is None:
            self._methods = {}
        if method_idx not in self._methods:
            self._methods[method_idx] = DexMethod(self, method_idx)
        return self._methods[method_idx]

    def get_field(self, field_idx):
        if self._fields is None:
            self._fields = {}
        if field_idx not in self._fields:
            self._fields[field_idx] = DexField(self, field_idx)
        return self._fields[field_idx]

    @property
    def methods(self):
        # We simulate the list access if someone does dex.methods[idx]
        class MethodsProxy:
            def __init__(self, dex):
                self.dex = dex
            def __getitem__(self, idx):
                return self.dex.get_method(idx)
            def __len__(self):
                return self.dex.header.methods[1]
        return MethodsProxy(self)

    @property
    def fields(self):
        class FieldsProxy:
            def __init__(self, dex):
                self.dex = dex
            def __getitem__(self, idx):
                return self.dex.get_field(idx)
            def __len__(self):
                return self.dex.header.fields[1]
        return FieldsProxy(self)

    @property
    def classes(self):
        if self._classes is None:
            self._classes = []
            off = self.header.classes[0]
            size = self.header.classes[1]
            
            for i in range(size):
                class_def_off = off + i * 32
                class_idx = _STRUCT_I.unpack_from(self.buf, class_def_off)[0]
                self._classes.append(DexClass(self, class_idx, class_def_off, i))
        return self._classes

    # only return uleb128 prefix byte, only fit class string
    # we dont care other situation!!!!
    def _get_uleb128_prefix(self, lens : int):
        if lens < 128:
            return bytes([lens])
        else:
            # class len never longer then 0x807f!!
            return bytes([lens | 0x80, lens >> 7])

    def get_class(self, fullname):
        raw_bytes = self.buf.obj if isinstance(self.buf, memoryview) else self.buf

        off = self.header.classes[0]
        size = self.header.classes[1]
        type_ids_off = self.header.types[0]
        type_ids_size = self.header.types[1]
        type_idx = -1

        left, right = 0, type_ids_size - 1
        while left <= right:
            mid = (left + right) // 2
            desc_idx = _STRUCT_I.unpack_from(raw_bytes, type_ids_off + mid * 0x4)[0]
            string = self.get_string(desc_idx)
            if string == fullname:
                type_idx = mid
                break
            elif string < fullname:
                left = mid + 1
            else:
                right = mid - 1
        
        if type_idx == -1:
            return None

        # I DONT GIVE SHIT ABOUT DATA MISALIGNMENT!!!
        # IF I CAN FIND STRING IDX, I MUST CAN FIND TYPE IDX!!!!
        # type_idx = (raw_bytes.find(desc_idx, type_ids_off) - type_ids_off) // 4 # type_id_item len == uint
        type_idx = type_idx.to_bytes(4, 'little')
        class_idx = (raw_bytes.find(type_idx, off) - off) // 0x20
        if class_idx == -1:
            return None
        if self._classes is None:
            self.classes
        return self._classes[class_idx]

