import re
import struct

# Auth: MG1937
# dont reuse dvmopcode, the opcode regex template is gen by LLM 20260614

# bytes regex template for dex opcodes
# "." means any 1 byte
# for the listed ref opcodes here, the FIRST referenced idx starts at byte offset +2

# -----------------------------
# single-op templates
# -----------------------------

# string idx
CONST_STRING = b"\x1a."              # 21c: op AA BBBB
CONST_STRING_JUMBO = b"\x1b."        # 31c: op AA BBBBBBBB

# type idx
CONST_CLASS = b"\x1c."               # 21c: op AA BBBB
CHECK_CAST = b"\x1f."                # 21c: op AA BBBB
INSTANCE_OF = b"\x20."               # 22c: op BA CCCC
NEW_INSTANCE = b"\x22."              # 21c: op AA BBBB
NEW_ARRAY = b"\x23."                 # 22c: op BA CCCC
FILLED_NEW_ARRAY = b"\x24."          # 35c: op AG BBBB FEDC
FILLED_NEW_ARRAY_RANGE = b"\x25."    # 3rc: op AA BBBB CCCC

# field idx
IGET = b"\x52."
IGET_WIDE = b"\x53."
IGET_OBJECT = b"\x54."
IGET_BOOLEAN = b"\x55."
IGET_BYTE = b"\x56."
IGET_CHAR = b"\x57."
IGET_SHORT = b"\x58."
IPUT = b"\x59."
IPUT_WIDE = b"\x5a."
IPUT_OBJECT = b"\x5b."
IPUT_BOOLEAN = b"\x5c."
IPUT_BYTE = b"\x5d."
IPUT_CHAR = b"\x5e."
IPUT_SHORT = b"\x5f."

SGET = b"\x60."
SGET_WIDE = b"\x61."
SGET_OBJECT = b"\x62."
SGET_BOOLEAN = b"\x63."
SGET_BYTE = b"\x64."
SGET_CHAR = b"\x65."
SGET_SHORT = b"\x66."
SPUT = b"\x67."
SPUT_WIDE = b"\x68."
SPUT_OBJECT = b"\x69."
SPUT_BOOLEAN = b"\x6a."
SPUT_BYTE = b"\x6b."
SPUT_CHAR = b"\x6c."
SPUT_SHORT = b"\x6d."

# method idx
INVOKE_VIRTUAL = b"\x6e."
INVOKE_SUPER = b"\x6f."
INVOKE_DIRECT = b"\x70."
INVOKE_STATIC = b"\x71."
INVOKE_INTERFACE = b"\x72."

INVOKE_VIRTUAL_RANGE = b"\x74."
INVOKE_SUPER_RANGE = b"\x75."
INVOKE_DIRECT_RANGE = b"\x76."
INVOKE_STATIC_RANGE = b"\x77."
INVOKE_INTERFACE_RANGE = b"\x78."

INVOKE_POLYMORPHIC = b"\xfa."        # first ref is meth@BBBB at +2
INVOKE_POLYMORPHIC_RANGE = b"\xfb."  # first ref is meth@BBBB at +2

# call_site idx
INVOKE_CUSTOM = b"\xfc."
INVOKE_CUSTOM_RANGE = b"\xfd."

# method_handle idx
CONST_METHOD_HANDLE = b"\xfe."

# proto idx
CONST_METHOD_TYPE = b"\xff."
# note:
# fa/fb also contain proto@HHHH, but that is NOT the first ref idx, so not covered by simple prefix+idx template

# -----------------------------
# grouped opcode classes
# -----------------------------

STRINGIDX16_OPS = b"(?:\x1a)."
STRINGIDX32_OPS = b"(?:\x1b)."

TYPEIDX_OPS = b"(?:\x1c|\x1f|\x20|\x22|\x23|\x24|\x25)."

INSTANCE_FIELDIDX_OPS = (
    b"(?:\x52|\x53|\x54|\x55|\x56|\x57|\x58|"
    b"\x59|\x5a|\x5b|\x5c|\x5d|\x5e|\x5f)."
)

STATIC_FIELDIDX_OPS = (
    b"(?:\x60|\x61|\x62|\x63|\x64|\x65|\x66|"
    b"\x67|\x68|\x69|\x6a|\x6b|\x6c|\x6d)."
)

FIELDIDX_OPS = (
    b"(?:\x52|\x53|\x54|\x55|\x56|\x57|\x58|"
    b"\x59|\x5a|\x5b|\x5c|\x5d|\x5e|\x5f|"
    b"\x60|\x61|\x62|\x63|\x64|\x65|\x66|"
    b"\x67|\x68|\x69|\x6a|\x6b|\x6c|\x6d)."
)

METHODIDX_OPS = b"(?:\x6e|\x6f|\x70|\x71|\x72|\x74|\x75|\x76|\x77|\x78|\xfa|\xfb)."

# for dex038+, such insn are used very infrequently, so we just ignore it for now... 20260617
CALLSITEIDX_OPS = b"(?:\xfc|\xfd)."

METHODHANDLEIDX_OPS = b"(?:\xfe)."

PROTOIDX_OPS = b"(?:\xff)."
# fa/fb second proto idx cannot be expressed as OP + "." + idx directly

# -----------------------------
# helpers
# -----------------------------

def idx16_pat(prefix: bytes, idx: int) -> bytes:
    return prefix + re.escape(struct.pack("<H", idx))

def idx32_pat(prefix: bytes, idx: int) -> bytes:
    return prefix + re.escape(struct.pack("<I", idx))

