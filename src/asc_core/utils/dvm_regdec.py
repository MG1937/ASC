import struct
from models.dvm_opcode import Format

# https://cs.android.com/android/platform/superproject/+/android-latest-release:art/libdexfile/dex/dex_instruction-inl.h

_STRUCT_H = struct.Struct("<H")
_STRUCT_h_SIGNED = struct.Struct("<h")
_STRUCT_i_SIGNED = struct.Struct("<i")
_STRUCT_I_UNSIGNED = struct.Struct("<I")
_STRUCT_Q_UNSIGNED = struct.Struct("<Q")

def get_index(bytecode_flow, dvm_op, pc):
    start = pc + 2 # index must in pos 2 of bytecode
    if dvm_op.fmt == Format.k31c:
        # op vAA, thing@BBBBBBBB        
        return bytecode_flow[start] | (bytecode_flow[start + 1] << 8) | (bytecode_flow[start + 2] << 16) | (bytecode_flow[start + 3] << 24)
    return bytecode_flow[start] | (bytecode_flow[start + 1] << 8)

def set_index(bytecode_flow, pc, new_idx, dvm_op):
    start = pc + 2 # index must in pos 2 of bytecode
    if dvm_op.fmt == Format.k31c:
        bytecode_flow[start] = new_idx & 0xFF
        bytecode_flow[start + 1] = (new_idx >> 8) & 0xFF
        bytecode_flow[start + 2] = (new_idx >> 16) & 0xFF
        bytecode_flow[start + 3] = (new_idx >> 24) & 0xFF
    else:
        bytecode_flow[start] = new_idx & 0xFF
        bytecode_flow[start + 1] = (new_idx >> 8) & 0xFF

def fetch16(bytecode_flow, pc, word_offset):
    start = pc + word_offset * 2
    return _STRUCT_H.unpack(bytes(bytecode_flow[start : start + 2]))[0]

def get_vreg_a(bytecode_flow, pc, dvm_op):
    fmt = dvm_op.fmt
    w0 = fetch16(bytecode_flow, pc, 0)
    
    if fmt in [Format.k10t, Format.k10x, Format.k11x, Format.k21c, Format.k21h, 
                Format.k21s, Format.k21t, Format.k22b, Format.k22x, Format.k23x, 
                Format.k31c, Format.k31i, Format.k31t, Format.k3rc, Format.k51l, Format.k4rcc]:
        return w0 >> 8
    if fmt in [Format.k11n, Format.k12x, Format.k22c, Format.k22s, Format.k22t]:
        return (w0 >> 8) & 0x0f
    if fmt == Format.k20t:
        return _STRUCT_h_SIGNED.unpack(bytes(bytecode_flow[pc + 2 : pc + 4]))[0]
    if fmt == Format.k30t:
        return _STRUCT_i_SIGNED.unpack(bytes(bytecode_flow[pc + 2 : pc + 6]))[0]
    if fmt == Format.k32x:
        return fetch16(bytecode_flow, pc, 1)
    if fmt in [Format.k35c, Format.k45cc]:
        return w0 >> 12
    return None

def get_vreg_b(bytecode_flow, pc, dvm_op):
    fmt = dvm_op.fmt
    w0 = fetch16(bytecode_flow, pc, 0)
    
    if fmt in [Format.k12x, Format.k22c, Format.k22s, Format.k22t]:
        return w0 >> 12
    if fmt == Format.k11n:
        val = w0 >> 12
        return (val - 16) if val > 7 else val
    if fmt in [Format.k21c, Format.k21h, Format.k21s, Format.k21t, Format.k22b, 
                Format.k22x, Format.k23x, Format.k35c, Format.k3rc, Format.k45cc, Format.k4rcc]:
        return fetch16(bytecode_flow, pc, 1)
    if fmt in [Format.k31c, Format.k31i, Format.k31t]:
        return _STRUCT_I_UNSIGNED.unpack(bytes(bytecode_flow[pc + 2 : pc + 6]))[0]
    if fmt == Format.k32x:
        return fetch16(bytecode_flow, pc, 2)
    if fmt == Format.k51l:
        return _STRUCT_Q_UNSIGNED.unpack(bytes(bytecode_flow[pc + 2 : pc + 10]))[0]
    return None

def get_vreg_c(bytecode_flow, pc, dvm_op):
    fmt = dvm_op.fmt
    if fmt in [Format.k22b, Format.k23x]:
        return fetch16(bytecode_flow, pc, 1) >> 8
    if fmt in [Format.k22c, Format.k22s, Format.k22t]:
        return fetch16(bytecode_flow, pc, 1)
    if fmt in [Format.k35c, Format.k45cc]:
        return fetch16(bytecode_flow, pc, 2) & 0x0f
    if fmt in [Format.k3rc, Format.k4rcc]:
        return fetch16(bytecode_flow, pc, 2)
    return None

def get_vreg_h(bytecode_flow, pc, dvm_op):
    if dvm_op.fmt in [Format.k45cc, Format.k4rcc]:
        return fetch16(bytecode_flow, pc, 3)
    return None

"""
def fetch16(bytecode, word_offset):
    return struct.unpack("<H", bytecode[word_offset*2 : word_offset*2+2])[0]

def get_vreg_a(bytecode, dvm_op):
    fmt = dvm_op.fmt
    w0 = fetch16(bytecode, 0)
    
    if fmt in [Format.k10t, Format.k10x, Format.k11x, Format.k21c, Format.k21h, 
                Format.k21s, Format.k21t, Format.k22b, Format.k22x, Format.k23x, 
                Format.k31c, Format.k31i, Format.k31t, Format.k3rc, Format.k51l, Format.k4rcc]:
        return w0 >> 8
    if fmt in [Format.k11n, Format.k12x, Format.k22c, Format.k22s, Format.k22t]:
        return (w0 >> 8) & 0x0f
    if fmt == Format.k20t:
        return struct.unpack("<h", bytecode[2:4])[0]
    if fmt == Format.k30t:
        return struct.unpack("<i", bytecode[2:6])[0]
    if fmt == Format.k32x:
        return fetch16(bytecode, 1)
    if fmt in [Format.k35c, Format.k45cc]:
        return w0 >> 12
    return None

def get_vreg_b(bytecode, dvm_op):
    fmt = dvm_op.fmt
    w0 = fetch16(bytecode, 0)
    
    if fmt in [Format.k12x, Format.k22c, Format.k22s, Format.k22t]:
        return w0 >> 12
    if fmt == Format.k11n:
        val = w0 >> 12
        return (val - 16) if val > 7 else val
    if fmt in [Format.k21c, Format.k21h, Format.k21s, Format.k21t, Format.k22b, 
                Format.k22x, Format.k23x, Format.k35c, Format.k3rc, Format.k45cc, Format.k4rcc]:
        return fetch16(bytecode, 1)
    if fmt in [Format.k31c, Format.k31i, Format.k31t]:
        return struct.unpack("<I", bytecode[2:6])[0]
    if fmt == Format.k32x:
        return fetch16(bytecode, 2)
    if fmt == Format.k51l:
        return struct.unpack("<Q", bytecode[2:10])[0]
    return None

def get_vreg_c(bytecode, dvm_op):
    fmt = dvm_op.fmt
    if fmt in [Format.k22b, Format.k23x]:
        return fetch16(bytecode, 1) >> 8
    if fmt in [Format.k22c, Format.k22s, Format.k22t]:
        return fetch16(bytecode, 1)
    if fmt in [Format.k35c, Format.k45cc]:
        return fetch16(bytecode, 2) & 0x0f
    if fmt in [Format.k3rc, Format.k4rcc]:
        return fetch16(bytecode, 2)
    return None

def get_vreg_h(bytecode, dvm_op):
    if dvm_op.fmt in [Format.k45cc, Format.k4rcc]:
        return fetch16(bytecode, 3)
    return None
"""
