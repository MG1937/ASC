from enum import IntFlag
from enum import Enum

# Auth: MG1937

vflags = [
    "kVerifyNothing", "kVerifyRegA", "kVerifyRegB", "kVerifyRegAWide",
    "kVerifyRegBWide", "kVerifyRegBString", "kVerifyRegBType", "kVerifyRegCType",
    "kVerifyRegBNewInstance", "kVerifyRegCNewArray", "kVerifyRegBFilledNewArray",
    "kVerifyVarArg", "kVerifyVarArgRange", "kVerifyArrayData", "kVerifyBranchTarget",
    "kVerifySwitchTargets", "kVerifyRegC", "kVerifyRegCWide", "kVerifyError",
    "kVerifyRegCField", "kVerifyRegBField", "kVerifyRegBMethod", "kVerifyVarArgNonZero",
    "kVerifyVarArgRangeNonZero", "kVerifyRegHPrototype", "kVerifyRegBCallSite",
    "kVerifyRegBMethodHandle", "kVerifyRegBPrototype"
]

VerifyFlag = IntFlag("VerifyFlag", vflags)

idxflags = [
    "kIndexNone", "kIndexStringRef", "kIndexTypeRef", "kIndexUnknown", 
    "kIndexFieldRef", "kIndexMethodRef", "kIndexMethodAndProtoRef", "kIndexCallSiteRef", 
    "kIndexMethodHandleRef", "kIndexProtoRef"
]

IndexFlag = Enum("IndexFlag", idxflags)

fmts = [
    "k10x",  # op
    "k12x",  # op vA, vB
    "k11n",  # op vA, #+B
    "k11x",  # op vAA
    "k10t",  # op +AA
    "k20t",  # op +AAAA
    "k22x",  # op vAA, vBBBB
    "k21t",  # op vAA, +BBBB
    "k21s",  # op vAA, #+BBBB
    "k21h",  # op vAA, #+BBBB00000[00000000]
    "k21c",  # op vAA, thing@BBBB
    "k23x",  # op vAA, vBB, vCC
    "k22b",  # op vAA, vBB, #+CC
    "k22t",  # op vA, vB, +CCCC
    "k22s",  # op vA, vB, #+CCCC
    "k22c",  # op vA, vB, thing@CCCC
    "k32x",  # op vAAAA, vBBBB
    "k30t",  # op +AAAAAAAA
    "k31t",  # op vAA, +BBBBBBBB
    "k31i",  # op vAA, #+BBBBBBBB
    "k31c",  # op vAA, thing@BBBBBBBB
    "k35c",  # op {vC, vD, vE, vF, vG}, thing@BBBB (B: count, A: vG)
    "k3rc",  # op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB
    "k51l",  # op vAA, #+BBBBBBBBBBBBBBBB
    # op {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH (A: count)
    # format: AG op BBBB FEDC HHHH
    "k45cc",

    # op {VCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH (AA: count)
    # format: AA op BBBB CCCC HHHH
    "k4rcc",  # op {VCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH (AA: count)
]

Format = Enum("Format", fmts)

class DvmOpcode:
    # V(opcode, instruction_code, name, format, index, flags, extended_flags, verifier_flags);
    def __init__(self, name, oplen, fmt, idx, vflag):
        self.name = name
        self.oplen = oplen
        self.fmt = fmt
        self.idx = idx
        self.vflag = vflag

opcodes = {
{opcodes}
}
