import re
import struct

from findrefs.locator.insn_locator import InsnLocator

# Auth: MG1937
# dont reuse dvmopcode, the opcode regex template is gen by LLM 20260614
# opcode pattern template is gen by LLM

# bytes regex template for dex opcodes
# "" means any 1 byte
# for the listed ref opcodes here, the FIRST referenced idx starts at byte offset +2

# -----------------------------
# single-op templates
# -----------------------------

# string idx
CONST_STRING = b"\x1a"              # 21c: op AA BBBB
CONST_STRING_JUMBO = b"\x1b"        # 31c: op AA BBBBBBBB

# type idx
CONST_CLASS = b"\x1c"               # 21c: op AA BBBB
CHECK_CAST = b"\x1f"                # 21c: op AA BBBB
INSTANCE_OF = b"\x20"               # 22c: op BA CCCC
NEW_INSTANCE = b"\x22"              # 21c: op AA BBBB
NEW_ARRAY = b"\x23"                 # 22c: op BA CCCC
FILLED_NEW_ARRAY = b"\x24"          # 35c: op AG BBBB FEDC
FILLED_NEW_ARRAY_RANGE = b"\x25"    # 3rc: op AA BBBB CCCC

# field idx
IGET = b"\x52"
IGET_WIDE = b"\x53"
IGET_OBJECT = b"\x54"
IGET_BOOLEAN = b"\x55"
IGET_BYTE = b"\x56"
IGET_CHAR = b"\x57"
IGET_SHORT = b"\x58"
IPUT = b"\x59"
IPUT_WIDE = b"\x5a"
IPUT_OBJECT = b"\x5b"
IPUT_BOOLEAN = b"\x5c"
IPUT_BYTE = b"\x5d"
IPUT_CHAR = b"\x5e"
IPUT_SHORT = b"\x5f"

SGET = b"\x60"
SGET_WIDE = b"\x61"
SGET_OBJECT = b"\x62"
SGET_BOOLEAN = b"\x63"
SGET_BYTE = b"\x64"
SGET_CHAR = b"\x65"
SGET_SHORT = b"\x66"
SPUT = b"\x67"
SPUT_WIDE = b"\x68"
SPUT_OBJECT = b"\x69"
SPUT_BOOLEAN = b"\x6a"
SPUT_BYTE = b"\x6b"
SPUT_CHAR = b"\x6c"
SPUT_SHORT = b"\x6d"

# method idx
INVOKE_VIRTUAL = b"\x6e"
INVOKE_SUPER = b"\x6f"
INVOKE_DIRECT = b"\x70"
INVOKE_STATIC = b"\x71"
INVOKE_INTERFACE = b"\x72"

INVOKE_VIRTUAL_RANGE = b"\x74"
INVOKE_SUPER_RANGE = b"\x75"
INVOKE_DIRECT_RANGE = b"\x76"
INVOKE_STATIC_RANGE = b"\x77"
INVOKE_INTERFACE_RANGE = b"\x78"

INVOKE_POLYMORPHIC = b"\xfa"        # first ref is meth@BBBB at +2
INVOKE_POLYMORPHIC_RANGE = b"\xfb"  # first ref is meth@BBBB at +2

# call_site idx
INVOKE_CUSTOM = b"\xfc"
INVOKE_CUSTOM_RANGE = b"\xfd"

# method_handle idx
CONST_METHOD_HANDLE = b"\xfe"

# proto idx
CONST_METHOD_TYPE = b"\xff"
# note:
# fa/fb also contain proto@HHHH, but that is NOT the first ref idx, so not covered by simple prefix+idx template

# -----------------------------
# grouped opcode classes
# -----------------------------

# \x1a const-string \x1b const-string/jumbo
STRINGIDX_OPS = re.compile(b"[\x1a\x1b]")

TYPEIDX_OPS = re.compile(b"[\x1c\x1f\x20\x22\x23\x24\x25]")

INSTANCE_FIELDIDX_OPS = re.compile(b"[\x52-\x5f]")

STATIC_FIELDIDX_OPS = re.compile(b"[\x60-\x6d]")

FIELDIDX_OPS = re.compile(b"[\x52-\x6d]")

METHODIDX_OPS = re.compile(b"[\x6e-\x72\x74-\x78\xfa\xfb]")

# for dex038+, such insn are used very infrequently, so we just ignore it for now... 20260617
CALLSITEIDX_OPS = re.compile(b"[\xfc-\xfd]")

METHODHANDLEIDX_OPS = re.compile(b"\xfe")

PROTOIDX_OPS = re.compile(b"\xff")
# fa/fb second proto idx cannot be expressed as OP + "" + idx directly

OPCODE_PATTERNS = {
        "method" : METHODIDX_OPS,
        "field" : FIELDIDX_OPS,
        "type" : TYPEIDX_OPS
        }

_STRUCT_I = struct.Struct('<I')
_STRUCT_H = struct.Struct('<H')
_UNPACK_I = _STRUCT_I.unpack_from
_UNPACK_H = _STRUCT_H.unpack_from

# scan type -> tuple of (opcode byte class, referenced idx width in bytes)
# the referenced idx always starts two bytes after its opcode byte
_IDX_GROUPS = {
        "string" : ((b"[\x1a]", 2), (b"[\x1b]", 4)),
        "type" : ((b"[\x1c\x1f\x20\x22\x23\x24\x25]", 2),),
        "field" : ((b"[\x52-\x6d]", 2),),
        "method" : ((b"[\x6e-\x72\x74-\x78\xfa\xfb]", 2),)
        }

_ANY_BYTE = b"[\x00-\xff]"
_CLASS_SPECIAL = frozenset(b"\\]^-[")


def _escape_class_byte(value : int) -> bytes:
    if value in _CLASS_SPECIAL:
        return b"\\" + bytes([value])
    return bytes([value])


def _byte_class(values) -> bytes:
    # compact regex character class matching exactly the given byte values
    values = sorted(set(values))
    total = len(values)
    if total == 256:
        return _ANY_BYTE
    out = bytearray(b"[")
    index = 0
    while index < total:
        last = index
        while last + 1 < total and values[last + 1] == values[last] + 1:
            last += 1
        if last - index >= 2:
            out += _escape_class_byte(values[index]) + b"-" + _escape_class_byte(values[last])
        else:
            for pos in range(index, last + 1):
                out += _escape_class_byte(values[pos])
        index = last + 1
    out += b"]"
    return bytes(out)


def _build_scan_pattern(opcode_class : bytes, idx_width : int, idxs):
    # the raw byte scan is a filter: requiring the bytes after the opcode to look
    # like a referenced idx lets the C regex engine drop almost every false
    # positive before python sees it. survivors are checked exactly by the caller.
    lookahead = _ANY_BYTE
    for shift in range(0, idx_width * 8, 8):
        lookahead += _byte_class({(idx >> shift) & 0xFF for idx in idxs})
    return re.compile(opcode_class + b"(?=" + lookahead + b")")


def _expand_class(opcode_class : bytes) -> bytes:
    # b"[\x52-\x6d]" -> the bytes it matches
    out = bytearray()
    index = 1
    end = len(opcode_class) - 1
    while index < end:
        if index + 2 < end and opcode_class[index + 1: index + 2] == b"-":
            out += bytes(range(opcode_class[index], opcode_class[index + 2] + 1))
            index += 3
        else:
            out.append(opcode_class[index])
            index += 1
    return bytes(out)


_OPCODE_VALUES = {}
for _groups in _IDX_GROUPS.values():
    for _class, _width in _groups:
        _OPCODE_VALUES[_class] = _expand_class(_class)

# CPython compiles a one character class to a literal and scans for it with memchr
# (measured 0.47 ns/byte); with two or more characters it falls back to the regex VM
# loop (3.5-6.5 ns/byte), which the translate prefilter below beats outright. So the
# switch is at two opcodes: the string type's two single-opcode groups keep the regex,
# every other class (7 type, 11 method, 28 field opcodes) uses the prefilter.
# Measured on a 3.21MB code region, regex vs prefilter: field 20.0 vs 10.1ms (-50%),
# method 10.4 vs 8.3ms (-20%), type 20.5 vs 18.1ms (-12%), string 3.0 vs 10.6ms.
_DENSE_OPCODE_COUNT = 2


def _mask_table(values) -> bytes:
    # 256 entry 0/1 table used by bytes.translate below
    wanted = set(values)
    return bytes([1 if byte in wanted else 0 for byte in range(256)])

class CodeItemScanner:
    # when we decide to scan code item, means we already build up the insn locator
    def __init__(self, insn_locator : InsnLocator):
        self.insn_locator = insn_locator
        self.off_start = self.insn_locator.code_item_start
        self.off_end = self.insn_locator.code_item_end
        self.buf = self.insn_locator.buf
        self.submem = self.buf[self.off_start: self.off_end]

    # dense opcode classes: a bytes.translate per byte position plus a bigint AND
    # replaces the regex charset scan. Only the opcode byte and the high idx byte are
    # masked: the low idx byte class is nearly the whole byte range for a realistic
    # target set, so masking it removed only a few thousand python iterations while
    # costing two more full passes over the region (measured -5% to -22% without it).
    # The exact idx check below still runs on every survivor.
    def _scan_code_item_dense(self, opcode_values : bytes, idxs : set, mark, matched_offset, mark_idx):
        off_start = self.off_start
        raw = self.submem.tobytes()
        # slicing the raw bytes by the idx offset aligns the low/high masks onto the
        # opcode position. A slice is a memcpy while the equivalent bigint shift walks
        # every limb of the region, which measured ~1ms extra per shift on 3.2MB.
        op_hits = int.from_bytes(raw.translate(_mask_table(opcode_values)), "little")
        hi_hits = int.from_bytes(raw[3:].translate(_mask_table((idx >> 8) & 0xFF for idx in idxs)), "little")
        hits = (op_hits & hi_hits).to_bytes(len(raw), "little")
        submem = self.submem
        start = hits.find(1)
        while start != -1:
            idx = _UNPACK_H(submem, start + 2)[0]
            if idx in idxs:
                matched_offset.append(start + off_start)
                if mark:
                    mark_idx.append(idx)
            start = hits.find(1, start + 1)

    # if mark is True, record correspond idx for offset
    def _scan_code_item(self, idx_type : str, idxs : set, mark):
        off_start = self.off_start
        submem = self.submem
        matched_offset = []
        mark_idx = []
        self.mark_idx = mark_idx

        groups = _IDX_GROUPS[idx_type]
        for opcode_class, idx_width in groups:
            opcode_values = _OPCODE_VALUES[opcode_class]
            if idx_width == 2 and len(opcode_values) >= _DENSE_OPCODE_COUNT:
                self._scan_code_item_dense(opcode_values, idxs, mark, matched_offset, mark_idx)
                continue
            pattern = _build_scan_pattern(opcode_class, idx_width, idxs)
            unpack_from = _UNPACK_I if idx_width == 4 else _UNPACK_H
            for match in pattern.finditer(submem):
                start = match.start()
                # the idx bytes were prefiltered in C, the exact value still
                # decides whether this opcode really references a target idx
                idx = unpack_from(submem, start + 2)[0]
                if idx not in idxs:
                    continue
                matched_offset.append(start + off_start)
                if mark:
                    mark_idx.append(idx)

        if len(groups) > 1:
            # separate scans per idx width break offset order, restore it
            order = sorted(range(len(matched_offset)), key=matched_offset.__getitem__)
            matched_offset = [matched_offset[i] for i in order]
            if mark:
                mark_idx[:] = [mark_idx[i] for i in order]
        return matched_offset

    # scan struct: {"string": {idx1, idx2...}, "field": ...,}
    # only handle with string idx, field idx, method idx, type idx
    # others such as proto, methodhandle is too FUCKING wired, leave it for now.. 20260617
    def scan(self, scan : dict, mark = False):
        for type_ in scan:
            if not scan[type_]:
                scan[type_] = []
                continue
            insn_offs = self._scan_code_item(type_, scan[type_], mark)
            mids = self.insn_locator.locate(insn_offs)
            scan[type_] = mids
