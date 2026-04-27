import models.dvm_opcode as dvm_opcode
from models.dvm_opcode import DvmOpcode

# Auth: MG1937

# https://source.android.com/docs/core/runtime/instruction-formats
WORD = 2

class DvmHandler:
    # basic handler class
    def __init__(self):
        self.should_break = False

    def call(self, bvmopcode, pc, result):
        # result refer to last handler's result
        return None

class DvmInterpreter:
    # handlers
    def __init__(self):
        self.handlers = []

    def addHandler(self, handler : DvmHandler):
        self.handlers.append(handler)

    def interpret(self, bytecode):
        # only own bytecode's copy
        # only handler can operate origin bytecode flow
        bytecode = bytecode.copy()
        flow_len = len(bytecode)
        pc = 0
        while flow_len > pc:
            opcode =  bytecode[pc]
            if opcode not in dvm_opcode.opcodes:
                # We reached a payload data section (like array-data or switch-data)
                # This should only happen if the handler failed to bound the PC correctly,
                # or if we actually hit the data block. We should break here.
                break
                
            dvmopcode = dvm_opcode.opcodes[opcode]
            handler_result = None
            
            # Allow handlers to signal early termination
            for handler in self.handlers:
                handler_result = handler.call(dvmopcode, pc, handler_result)
                if handler.should_break:
                    break
                    
            # If any handler signaled a break, we terminate the interpretation loop
            if any(handler.should_break for handler in self.handlers):
                break
                
            pc += dvmopcode.oplen * WORD
