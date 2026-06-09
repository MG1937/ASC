from utils.tinydex import DEX 

# Auth: MG1937

class BaseLocator:
    def __init__(self, dex : DEX):
        self.dex = dex
        self.buf = dex.buf
        self.header = dex.header

    def locate(self, offset):
        return None
