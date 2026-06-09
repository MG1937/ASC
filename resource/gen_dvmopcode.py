import re

MACRO_PATTERN = r'V\((0x[0-9A-F]+),.+("[\w\/-]+"),\s(k(\d)[0-9a-z]+),\s(kIndex\w+),.+,\s(kVerify\w+(?:\s\|\s\w+)*)\)'

OPCODE_FILL = ""

OPCODE_TMP = open("dvmopcode_template.py").read()

with open("dex_instruction_list.h", "r") as file:
    macros = file.read().split("\n")
    for m in macros:
        if "kIndex" not in m or "kIndexUnknown" in m:
            continue
        opcode, name, fmt, oplen, idx, vflag = re.findall(MACRO_PATTERN, m)[0]
        idx = idx.replace("kIndex", "IndexFlag.kIndex")
        fmt = fmt.replace("k", "Format.k")
        vflag = vflag.replace("kVerify", "VerifyFlag.kVerify")
        OPCODE_FILL += "    " + opcode + ": DvmOpcode({}, {}, {}, {}, {})".format(
                name, oplen, fmt, idx, vflag
            ) + ", \n"
    file.close()

with open("../models/dvm_opcode.py", "w") as opfile:
    opfile.write(OPCODE_TMP.replace("{opcodes}", OPCODE_FILL))
    opfile.close()

print("Gen Done")
