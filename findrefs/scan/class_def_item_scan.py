# Auth: MG193.7
# currently which is for subclass or subimplements finding 20261012

from ..locator.type_locator import TypeLocator
import re
import struct

_STRUCT_I = struct.Struct('<I')

class ClassDefItemScan:
    def __init__(self, type_locator: TypeLocator):
        self.type_locator = type_locator
        self.buf = type_locator.buf
        self.class_def_item_offset = type_locator.dex.header.classes[0]
        self.class_def_item_size = type_locator.dex.header.classes[1]
        self.submem = self.buf[self.class_def_item_offset:
                self.class_def_item_offset + 0x20 * self.class_def_item_size]

    # scan and return all classes that extends the target class
    # target class only accept precise dalvik format clz
    def scan_extends(self, target_clz: str) -> list:
        target_type_idx = self.type_locator._find_type_idx_precisely(target_clz)
        if target_type_idx == -1:
            return []

        pattern = re.compile(re.escape(_STRUCT_I.pack(target_type_idx)))
        ret = []
        for match in pattern.finditer(self.submem):
            class_def_off = match.start() - 0x8 # goto start offset of class_def_item
            if class_def_off & 0x1f: # check for 0x20 alignment
                continue
            class_idx = _STRUCT_I.unpack_from(self.submem, class_def_off)[0]
            ret.append(class_idx)
        return ret

    def scan_implements(self, target_clz: str) -> list:
        target_type_idx = self.type_locator._find_type_idx_precisely(target_clz)
        if target_type_idx == -1:
            return []

        ret = []
        # https://source.android.com/docs/core/runtime/dex-format#class-def-item
        # interfaces_off field offset inside a 0x20 class_def_item = 3 * 0x4
        for class_index in range(self.class_def_item_size):
            if _STRUCT_I.unpack_from(self.submem, class_index * 0x20 + 3 * 0x4)[0] == 0:
                continue
            clazz = self.type_locator.dex.classes[class_index]
            if target_type_idx in clazz.interface_type_idxs:
                ret.append(clazz.class_idx)

        return ret
