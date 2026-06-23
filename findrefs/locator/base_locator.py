from utils.tinydex import DEX 
import time

# Auth: MG1937

class BaseLocator:
    def __init__(self, dex : DEX):
        self.dex = dex
        self.buf = dex.buf
        self.header = dex.header
        self.mapoff = dex.header.mapoff
        self.debug = False

    def set_debug(self, debug : bool):
        self.debug = debug

    def _debug_log(self, stage : str, t_start, count = None):
        if not self.debug:
            return
        t_end = time.perf_counter()
        if count is None:
            print(f"[DEBUG] {self.__class__.__name__}.{stage} Time: {(t_end - t_start)*1000000:.2f} us")
        else:
            print(f"[DEBUG] {self.__class__.__name__}.{stage} Time: {(t_end - t_start)*1000000:.2f} us Count: {count}")

    def locate(self, obj):
        return None
