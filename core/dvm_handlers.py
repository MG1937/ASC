from core.dvm_interpreter import DvmHandler
from models.dvm_opcode import VerifyFlag
from models.dvm_opcode import IndexFlag
from utils.dvm_regdec import get_index
from utils.dvm_regdec import set_index
from utils.dvm_regdec import get_vreg_b

# Auth: MG1937

# dvm_handlers response to deal how to handle bytecode

class IndexHandler(DvmHandler):

    TYPE_MAP = {
            IndexFlag.kIndexTypeRef: "TYPE",
            IndexFlag.kIndexStringRef: "STRING",
            IndexFlag.kIndexMethodRef: "METHOD",
            IndexFlag.kIndexFieldRef: "FIELD"
    }

    def __init__(self):
        super().__init__()
        self.mapper = {
            "CLASS": {},
            "METHOD": {},
            "FIELD": {},
            "TYPE": {},
            "STRING": {}
        }
        self.reverse_mapper = {
            "CLASS": {},
            "METHOD": {},
            "FIELD": {},
            "TYPE": {},
            "STRING": {}
        }
        
    def mapIndex(self, origin_idx, idx_type):
        rev = self.reverse_mapper[idx_type]
        if origin_idx not in rev:
            fwd = self.mapper[idx_type]
            new_idx = len(fwd)
            fwd[new_idx] = origin_idx
            rev[origin_idx] = new_idx
            return new_idx
        return rev[origin_idx]

    def getMapper(self):
        return self.mapper

    def setBytecode(self, bytecode):
        self.bytecode = bytecode
        self.pc_bound = 0xffff
        self.should_break = False

    # should call before BytecodeHandler 
    def call(self, dvmopcode, pc, result):
        idx_fmt = dvmopcode.idx
        
        if self.pc_bound <= pc:
            # Reached the data block boundary (e.g. switch data, array data)
            self.should_break = True
            return None
            
        if idx_fmt == IndexFlag.kIndexNone:
            if dvmopcode.vflag & VerifyFlag.kVerifySwitchTargets != 0 or dvmopcode.vflag & VerifyFlag.kVerifyArrayData != 0:
                # packed-switch/sparse-switch/fill-array-data issue
                # They all use +BBBBBBBB relative offset to data payloads at the end of the method
                # The offset is in 16-bit code units (so we multiply by 2 for byte offset)
                bound = pc + get_vreg_b(self.bytecode, pc, dvmopcode) * 2
                self.pc_bound = bound if bound < self.pc_bound else self.pc_bound
                # print("pc boundary >> " + str(bound))
            return None # dont care

        origin_idx = get_index(self.bytecode, dvmopcode, pc)
        new_idx = origin_idx

        idx_type = self.TYPE_MAP.get(idx_fmt)
        if idx_type:
            new_idx = self.mapIndex(origin_idx, idx_type)

        if new_idx != origin_idx:
            set_index(self.bytecode, pc, new_idx, dvmopcode)
        
        return new_idx
