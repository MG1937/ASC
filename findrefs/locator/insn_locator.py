from findrefs.locator.base_locator import BaseLocator

# Auth MG193.7

class InsnLocator(BaseLocator):
    def _build_map(self):

    def __init__(self, buf : bytes):
        super().__init__(buf)
        self.code_offs = [] # for sort
        self.method_map = {} # {code_off : [midx, midx2...]}
        self.code_off_size = {} # {code_off : insn_size}

    # insn offset to classdef + methodidx
    def locate(self, offset):
        
