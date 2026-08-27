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

class CodeItemScanner:
    # when we decide to scan code item, means we already build up the insn locator
    def __init__(self, insn_locator : InsnLocator):
        self.insn_locator = insn_locator
        self.off_start = self.insn_locator.code_item_start
        self.off_end = self.insn_locator.code_item_end
        self.buf = self.insn_locator.buf
        self.submem = self.buf[self.off_start: self.off_end]

    # if mark is True, record correspond idx for offset
    def _scan_code_item(self, idx_type : str, idxs : set, mark):
        off_start = self.off_start
        submem = self.submem
        buf_len = len(submem)
        matched_offset = []
        mark_idx = []
        self.mark_idx = mark_idx

        if idx_type == "string":
            for match in STRINGIDX_OPS.finditer(submem):
                # buggy, might have oob issue 20260617
                idx_off = match.start() + 2
                if match.group() == b'\x1a':
                    if (idx_off + 2) > buf_len: # bugfix for oob, dont use try-except, bad performance.. 20260729
                        return matched_offset
                    idx = _STRUCT_H.unpack_from(submem, idx_off)[0]
                else: # const-string/jumbo
                    if (idx_off + 4) > buf_len:
                        return matched_offset
                    idx = _STRUCT_I.unpack_from(submem, idx_off)[0]
                if idx not in idxs:
                    continue
                matched_offset.append(idx_off + off_start - 2)
                if mark:
                    mark_idx.append(idx)
            return matched_offset
        else:
            for match in OPCODE_PATTERNS[idx_type].finditer(submem):
                # buggy, might have oob issue 20260617
                idx_off = match.start() + 2
                if (idx_off + 2) > buf_len:
                    return matched_offset
                idx = _STRUCT_H.unpack_from(submem, idx_off)[0]
                if idx not in idxs:
                    continue
                matched_offset.append(idx_off + off_start - 2)
                if mark:
                    mark_idx.append(idx)
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
