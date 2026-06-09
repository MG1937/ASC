import os
import time

from utils.tinydex import DEX
from core.dvm_interpreter import DvmInterpreter
from core.dvm_handlers import IndexHandler
from core.dex.dex_remapper import DexIndexMapper
from core.dex.dex_constructor import DexHollower
from core.dex.dex_builder import DexBuilder

# this part gen by LLM, I already build the infra, let LLM arrange this

class DexManager:
    def __init__(self, dex_path: str, debug: bool = False):
        self.dex_path = dex_path
        self.debug = debug
        self.dexraw = None
        self.dex = None
        
        self._load_dex()

    def _load_dex(self):
        t_start = time.perf_counter()
        
        size = os.path.getsize(self.dex_path)
        self.dexraw = bytearray(size)
        with open(self.dex_path, "rb") as f:
            f.readinto(self.dexraw)
            
        self.dex = DEX.parse(self.dexraw, os.path.basename(self.dex_path))
        
        if self.debug:
            t_end = time.perf_counter()
            print(f"[DEBUG] DexManager load_dex Time: {(t_end - t_start)*1000000:.2f} us")

    def extract_and_rebuild(self, dalvik_class_fmt: str):
        t_start = time.perf_counter()
        
        clazz = self.dex.get_class(dalvik_class_fmt)
        if not clazz:
            raise ValueError(f"Class {dalvik_class_fmt} not found in DEX.")

        idx_handler = IndexHandler()
        dvminterp = DvmInterpreter()
        dvminterp.addHandler(idx_handler)

        modified_bytecodes = {}
        
        t_setup_end = time.perf_counter()
        
        # 1. Execute interpreter to collect indices (optional modification step)
        t_interp_start = time.perf_counter()
        for method in clazz.methods:
            bytecode_raw = method.bytecode
            idx_handler.setBytecode(bytecode_raw)
            dvminterp.interpret(bytecode_raw)
            modified_bytecodes[method.index] = bytecode_raw
        t_interp_end = time.perf_counter()

        # 2. Hollow out necessary data from original DEX
        dexhlw = DexHollower(self.dex, self.dexraw, dalvik_class_fmt, debug=self.debug)
        dexhlw.hollow()
        t_hollow_end = time.perf_counter()

        # 3. Remap indices to create new continuous index tables
        indexmapper = DexIndexMapper(idx_handler.getMapper(), self.dex, self.dexraw)
        indexmapper.set_class(clazz)
        indexmapper.set_hollower(dexhlw)
        indexmapper.handle()
        t_remap_end = time.perf_counter()

        # 4. Build the new DEX
        builder = DexBuilder(indexmapper, dexhlw, modified_bytecodes, debug=self.debug)
        new_dex_bytes = builder.build()
        t_build_end = time.perf_counter()

        if self.debug:
            print(f"[DEBUG] Setup Time: {(t_setup_end - t_start)*1000000:.2f} us")
            print(f"[DEBUG] Interpreter Time: {(t_interp_end - t_interp_start)*1000000:.2f} us")
            print(f"[DEBUG] Hollower Time: {(t_hollow_end - t_interp_end)*1000000:.2f} us")
            print(f"[DEBUG] Remapper Time: {(t_remap_end - t_hollow_end)*1000000:.2f} us")
            print(f"[DEBUG] Builder Time: {(t_build_end - t_remap_end)*1000000:.2f} us")
            print(f"[DEBUG] Total Extraction Time: {(t_build_end - t_start)*1000000:.2f} us")
            
        return new_dex_bytes
