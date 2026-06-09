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
    0x00: DvmOpcode("nop", 1, Format.k10x, IndexFlag.kIndexNone, VerifyFlag.kVerifyNothing), 
    0x01: DvmOpcode("move", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x02: DvmOpcode("move/from16", 2, Format.k22x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x03: DvmOpcode("move/16", 3, Format.k32x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x04: DvmOpcode("move-wide", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0x05: DvmOpcode("move-wide/from16", 2, Format.k22x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0x06: DvmOpcode("move-wide/16", 3, Format.k32x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0x07: DvmOpcode("move-object", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x08: DvmOpcode("move-object/from16", 2, Format.k22x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x09: DvmOpcode("move-object/16", 3, Format.k32x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x0A: DvmOpcode("move-result", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x0B: DvmOpcode("move-result-wide", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide), 
    0x0C: DvmOpcode("move-result-object", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x0D: DvmOpcode("move-exception", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x0E: DvmOpcode("return-void", 1, Format.k10x, IndexFlag.kIndexNone, VerifyFlag.kVerifyNothing), 
    0x0F: DvmOpcode("return", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x10: DvmOpcode("return-wide", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide), 
    0x11: DvmOpcode("return-object", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x12: DvmOpcode("const/4", 1, Format.k11n, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x13: DvmOpcode("const/16", 2, Format.k21s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x14: DvmOpcode("const", 3, Format.k31i, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x15: DvmOpcode("const/high16", 2, Format.k21h, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x16: DvmOpcode("const-wide/16", 2, Format.k21s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide), 
    0x17: DvmOpcode("const-wide/32", 3, Format.k31i, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide), 
    0x18: DvmOpcode("const-wide", 5, Format.k51l, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide), 
    0x19: DvmOpcode("const-wide/high16", 2, Format.k21h, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide), 
    0x1A: DvmOpcode("const-string", 2, Format.k21c, IndexFlag.kIndexStringRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBString), 
    0x1B: DvmOpcode("const-string/jumbo", 3, Format.k31c, IndexFlag.kIndexStringRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBString), 
    0x1C: DvmOpcode("const-class", 2, Format.k21c, IndexFlag.kIndexTypeRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBType), 
    0x1D: DvmOpcode("monitor-enter", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x1E: DvmOpcode("monitor-exit", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x1F: DvmOpcode("check-cast", 2, Format.k21c, IndexFlag.kIndexTypeRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBType), 
    0x20: DvmOpcode("instance-of", 2, Format.k22c, IndexFlag.kIndexTypeRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCType), 
    0x21: DvmOpcode("array-length", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x22: DvmOpcode("new-instance", 2, Format.k21c, IndexFlag.kIndexTypeRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBNewInstance), 
    0x23: DvmOpcode("new-array", 2, Format.k22c, IndexFlag.kIndexTypeRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCNewArray), 
    0x24: DvmOpcode("filled-new-array", 3, Format.k35c, IndexFlag.kIndexTypeRef, VerifyFlag.kVerifyRegBFilledNewArray | VerifyFlag.kVerifyVarArg), 
    0x25: DvmOpcode("filled-new-array/range", 3, Format.k3rc, IndexFlag.kIndexTypeRef, VerifyFlag.kVerifyRegBFilledNewArray | VerifyFlag.kVerifyVarArgRange), 
    0x26: DvmOpcode("fill-array-data", 3, Format.k31t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyArrayData), 
    0x27: DvmOpcode("throw", 1, Format.k11x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA), 
    0x28: DvmOpcode("goto", 1, Format.k10t, IndexFlag.kIndexNone, VerifyFlag.kVerifyBranchTarget), 
    0x29: DvmOpcode("goto/16", 2, Format.k20t, IndexFlag.kIndexNone, VerifyFlag.kVerifyBranchTarget), 
    0x2A: DvmOpcode("goto/32", 3, Format.k30t, IndexFlag.kIndexNone, VerifyFlag.kVerifyBranchTarget), 
    0x2B: DvmOpcode("packed-switch", 3, Format.k31t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifySwitchTargets), 
    0x2C: DvmOpcode("sparse-switch", 3, Format.k31t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifySwitchTargets), 
    0x2D: DvmOpcode("cmpl-float", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x2E: DvmOpcode("cmpg-float", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x2F: DvmOpcode("cmpl-double", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0x30: DvmOpcode("cmpg-double", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0x31: DvmOpcode("cmp-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0x32: DvmOpcode("if-eq", 2, Format.k22t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyBranchTarget), 
    0x33: DvmOpcode("if-ne", 2, Format.k22t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyBranchTarget), 
    0x34: DvmOpcode("if-lt", 2, Format.k22t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyBranchTarget), 
    0x35: DvmOpcode("if-ge", 2, Format.k22t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyBranchTarget), 
    0x36: DvmOpcode("if-gt", 2, Format.k22t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyBranchTarget), 
    0x37: DvmOpcode("if-le", 2, Format.k22t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyBranchTarget), 
    0x38: DvmOpcode("if-eqz", 2, Format.k21t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyBranchTarget), 
    0x39: DvmOpcode("if-nez", 2, Format.k21t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyBranchTarget), 
    0x3A: DvmOpcode("if-ltz", 2, Format.k21t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyBranchTarget), 
    0x3B: DvmOpcode("if-gez", 2, Format.k21t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyBranchTarget), 
    0x3C: DvmOpcode("if-gtz", 2, Format.k21t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyBranchTarget), 
    0x3D: DvmOpcode("if-lez", 2, Format.k21t, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyBranchTarget), 
    0x44: DvmOpcode("aget", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x45: DvmOpcode("aget-wide", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x46: DvmOpcode("aget-object", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x47: DvmOpcode("aget-boolean", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x48: DvmOpcode("aget-byte", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x49: DvmOpcode("aget-char", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x4A: DvmOpcode("aget-short", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x4B: DvmOpcode("aput", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x4C: DvmOpcode("aput-wide", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x4D: DvmOpcode("aput-object", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x4E: DvmOpcode("aput-boolean", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x4F: DvmOpcode("aput-byte", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x50: DvmOpcode("aput-char", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x51: DvmOpcode("aput-short", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x52: DvmOpcode("iget", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x53: DvmOpcode("iget-wide", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x54: DvmOpcode("iget-object", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x55: DvmOpcode("iget-boolean", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x56: DvmOpcode("iget-byte", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x57: DvmOpcode("iget-char", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x58: DvmOpcode("iget-short", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x59: DvmOpcode("iput", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x5A: DvmOpcode("iput-wide", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x5B: DvmOpcode("iput-object", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x5C: DvmOpcode("iput-boolean", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x5D: DvmOpcode("iput-byte", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x5E: DvmOpcode("iput-char", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x5F: DvmOpcode("iput-short", 2, Format.k22c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegCField), 
    0x60: DvmOpcode("sget", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x61: DvmOpcode("sget-wide", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBField), 
    0x62: DvmOpcode("sget-object", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x63: DvmOpcode("sget-boolean", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x64: DvmOpcode("sget-byte", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x65: DvmOpcode("sget-char", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x66: DvmOpcode("sget-short", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x67: DvmOpcode("sput", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x68: DvmOpcode("sput-wide", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBField), 
    0x69: DvmOpcode("sput-object", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x6A: DvmOpcode("sput-boolean", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x6B: DvmOpcode("sput-byte", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x6C: DvmOpcode("sput-char", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x6D: DvmOpcode("sput-short", 2, Format.k21c, IndexFlag.kIndexFieldRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBField), 
    0x6E: DvmOpcode("invoke-virtual", 3, Format.k35c, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgNonZero), 
    0x6F: DvmOpcode("invoke-super", 3, Format.k35c, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgNonZero), 
    0x70: DvmOpcode("invoke-direct", 3, Format.k35c, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgNonZero), 
    0x71: DvmOpcode("invoke-static", 3, Format.k35c, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArg), 
    0x72: DvmOpcode("invoke-interface", 3, Format.k35c, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgNonZero), 
    0x74: DvmOpcode("invoke-virtual/range", 3, Format.k3rc, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgRangeNonZero), 
    0x75: DvmOpcode("invoke-super/range", 3, Format.k3rc, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgRangeNonZero), 
    0x76: DvmOpcode("invoke-direct/range", 3, Format.k3rc, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgRangeNonZero), 
    0x77: DvmOpcode("invoke-static/range", 3, Format.k3rc, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgRange), 
    0x78: DvmOpcode("invoke-interface/range", 3, Format.k3rc, IndexFlag.kIndexMethodRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgRangeNonZero), 
    0x7B: DvmOpcode("neg-int", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x7C: DvmOpcode("not-int", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x7D: DvmOpcode("neg-long", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0x7E: DvmOpcode("not-long", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0x7F: DvmOpcode("neg-float", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x80: DvmOpcode("neg-double", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0x81: DvmOpcode("int-to-long", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB), 
    0x82: DvmOpcode("int-to-float", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x83: DvmOpcode("int-to-double", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB), 
    0x84: DvmOpcode("long-to-int", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBWide), 
    0x85: DvmOpcode("long-to-float", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBWide), 
    0x86: DvmOpcode("long-to-double", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0x87: DvmOpcode("float-to-int", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x88: DvmOpcode("float-to-long", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB), 
    0x89: DvmOpcode("float-to-double", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB), 
    0x8A: DvmOpcode("double-to-int", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBWide), 
    0x8B: DvmOpcode("double-to-long", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0x8C: DvmOpcode("double-to-float", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBWide), 
    0x8D: DvmOpcode("int-to-byte", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x8E: DvmOpcode("int-to-char", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x8F: DvmOpcode("int-to-short", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0x90: DvmOpcode("add-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x91: DvmOpcode("sub-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x92: DvmOpcode("mul-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x93: DvmOpcode("div-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x94: DvmOpcode("rem-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x95: DvmOpcode("and-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x96: DvmOpcode("or-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x97: DvmOpcode("xor-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x98: DvmOpcode("shl-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x99: DvmOpcode("shr-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x9A: DvmOpcode("ushr-int", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0x9B: DvmOpcode("add-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0x9C: DvmOpcode("sub-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0x9D: DvmOpcode("mul-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0x9E: DvmOpcode("div-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0x9F: DvmOpcode("rem-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xA0: DvmOpcode("and-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xA1: DvmOpcode("or-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xA2: DvmOpcode("xor-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xA3: DvmOpcode("shl-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegC), 
    0xA4: DvmOpcode("shr-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegC), 
    0xA5: DvmOpcode("ushr-long", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegC), 
    0xA6: DvmOpcode("add-float", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0xA7: DvmOpcode("sub-float", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0xA8: DvmOpcode("mul-float", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0xA9: DvmOpcode("div-float", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0xAA: DvmOpcode("rem-float", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB | VerifyFlag.kVerifyRegC), 
    0xAB: DvmOpcode("add-double", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xAC: DvmOpcode("sub-double", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xAD: DvmOpcode("mul-double", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xAE: DvmOpcode("div-double", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xAF: DvmOpcode("rem-double", 2, Format.k23x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide | VerifyFlag.kVerifyRegCWide), 
    0xB0: DvmOpcode("add-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB1: DvmOpcode("sub-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB2: DvmOpcode("mul-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB3: DvmOpcode("div-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB4: DvmOpcode("rem-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB5: DvmOpcode("and-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB6: DvmOpcode("or-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB7: DvmOpcode("xor-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB8: DvmOpcode("shl-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xB9: DvmOpcode("shr-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xBA: DvmOpcode("ushr-int/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xBB: DvmOpcode("add-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xBC: DvmOpcode("sub-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xBD: DvmOpcode("mul-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xBE: DvmOpcode("div-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xBF: DvmOpcode("rem-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xC0: DvmOpcode("and-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xC1: DvmOpcode("or-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xC2: DvmOpcode("xor-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xC3: DvmOpcode("shl-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB), 
    0xC4: DvmOpcode("shr-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB), 
    0xC5: DvmOpcode("ushr-long/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegB), 
    0xC6: DvmOpcode("add-float/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xC7: DvmOpcode("sub-float/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xC8: DvmOpcode("mul-float/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xC9: DvmOpcode("div-float/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xCA: DvmOpcode("rem-float/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xCB: DvmOpcode("add-double/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xCC: DvmOpcode("sub-double/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xCD: DvmOpcode("mul-double/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xCE: DvmOpcode("div-double/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xCF: DvmOpcode("rem-double/2addr", 1, Format.k12x, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegAWide | VerifyFlag.kVerifyRegBWide), 
    0xD0: DvmOpcode("add-int/lit16", 2, Format.k22s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD1: DvmOpcode("rsub-int", 2, Format.k22s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD2: DvmOpcode("mul-int/lit16", 2, Format.k22s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD3: DvmOpcode("div-int/lit16", 2, Format.k22s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD4: DvmOpcode("rem-int/lit16", 2, Format.k22s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD5: DvmOpcode("and-int/lit16", 2, Format.k22s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD6: DvmOpcode("or-int/lit16", 2, Format.k22s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD7: DvmOpcode("xor-int/lit16", 2, Format.k22s, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD8: DvmOpcode("add-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xD9: DvmOpcode("rsub-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xDA: DvmOpcode("mul-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xDB: DvmOpcode("div-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xDC: DvmOpcode("rem-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xDD: DvmOpcode("and-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xDE: DvmOpcode("or-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xDF: DvmOpcode("xor-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xE0: DvmOpcode("shl-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xE1: DvmOpcode("shr-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xE2: DvmOpcode("ushr-int/lit8", 2, Format.k22b, IndexFlag.kIndexNone, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegB), 
    0xFA: DvmOpcode("invoke-polymorphic", 4, Format.k45cc, IndexFlag.kIndexMethodAndProtoRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgNonZero | VerifyFlag.kVerifyRegHPrototype), 
    0xFB: DvmOpcode("invoke-polymorphic/range", 4, Format.k4rcc, IndexFlag.kIndexMethodAndProtoRef, VerifyFlag.kVerifyRegBMethod | VerifyFlag.kVerifyVarArgRangeNonZero | VerifyFlag.kVerifyRegHPrototype), 
    0xFC: DvmOpcode("invoke-custom", 3, Format.k35c, IndexFlag.kIndexCallSiteRef, VerifyFlag.kVerifyRegBCallSite | VerifyFlag.kVerifyVarArg), 
    0xFD: DvmOpcode("invoke-custom/range", 3, Format.k3rc, IndexFlag.kIndexCallSiteRef, VerifyFlag.kVerifyRegBCallSite | VerifyFlag.kVerifyVarArgRange), 
    0xFE: DvmOpcode("const-method-handle", 2, Format.k21c, IndexFlag.kIndexMethodHandleRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBMethodHandle), 
    0xFF: DvmOpcode("const-method-type", 2, Format.k21c, IndexFlag.kIndexProtoRef, VerifyFlag.kVerifyRegA | VerifyFlag.kVerifyRegBPrototype), 

}
