import sys
class DummyClass: pass
class DummyModule:
    __path__ = []
    def __init__(self):
        self.APK = DummyClass
    def __getattr__(self, name): return DummyModule()
    def __iter__(self): return iter([])
    def __call__(self, *args, **kwargs): return DummyModule()
    

# The dummy import trick bascially gen by LLM 20260607

sys.modules['androguard.core.apk'] = DummyModule()
sys.modules['networkx'] = DummyModule()
sys.modules['pygments'] = DummyModule()
sys.modules['lxml'] = DummyModule()
sys.modules['asn1crypto'] = DummyModule()
sys.modules['asn1crypto.x509'] = DummyModule()
sys.modules['cryptography'] = DummyModule()
sys.modules['matplotlib'] = DummyModule()
sys.modules['pydot'] = DummyModule()
sys.modules['IPython'] = DummyModule()
sys.modules['colorama'] = DummyModule()
sys.modules['dateutil'] = DummyModule()
sys.modules['urllib3'] = DummyModule()
sys.modules['requests'] = DummyModule()
sys.modules['idna'] = DummyModule()
sys.modules['chardet'] = DummyModule()
sys.modules['certifi'] = DummyModule()
sys.modules['pkg_resources'] = DummyModule()

sys.modules['loguru'] = DummyModule()
sys.modules['loguru._logger'] = DummyModule()
sys.modules['click'] = DummyModule()
sys.modules['urllib'] = DummyModule()
sys.modules['urllib.request'] = DummyModule()
sys.modules['http.client'] = DummyModule()
sys.modules['email'] = DummyModule()
sys.modules['email.parser'] = DummyModule()
sys.modules['email.message'] = DummyModule()
sys.modules['multiprocessing'] = DummyModule()
sys.modules['multiprocessing.context'] = DummyModule()
sys.modules['multiprocessing.reduction'] = DummyModule()
sys.modules['xml.sax.saxutils'] = DummyModule()

sys.modules['tempfile'] = DummyModule()
sys.modules['bz2'] = DummyModule()
sys.modules['lzma'] = DummyModule()
sys.modules['shutil'] = DummyModule()
sys.modules['bisect'] = DummyModule()
sys.modules['random'] = DummyModule()
sys.modules['json'] = DummyModule()
sys.modules['json.scanner'] = DummyModule()
sys.modules['json.decoder'] = DummyModule()
sys.modules['json.encoder'] = DummyModule()
sys.modules['math'] = DummyModule()
sys.modules['weakref'] = DummyModule()

from androguard.core.dex import DEX
import androguard.core.dex as androguard_dex

original_header_init = androguard_dex.HeaderItem.__init__
def monkey_header_init(self, offset, buff, cm):
    try:
        original_header_init(self, offset, buff, cm)
    except ValueError as e:
        if "Adler32" in str(e):
            pass
        else:
            raise e
androguard_dex.HeaderItem.__init__ = monkey_header_init

from androguard.decompiler import decompile
from androguard.decompiler import util as androguard_util
from androguard.core.analysis.analysis import MethodAnalysis
import androguard.core.androconf as androconf
import functools

# --- Androguard String Operations & Type Parsing Optimizations ---
# Dalvik bytecode formatting and access flag resolution generates a massive amount
# of redundant string objects. We wrap them all in LRU caches.
androguard_util.get_type = functools.lru_cache(maxsize=4096)(androguard_util.get_type)
androguard_util.get_type_size = functools.lru_cache(maxsize=4096)(androguard_util.get_type_size)
androguard_util.get_access_class = functools.lru_cache(maxsize=256)(androguard_util.get_access_class)
androguard_util.get_access_method = functools.lru_cache(maxsize=256)(androguard_util.get_access_method)
androguard_util.get_access_field = functools.lru_cache(maxsize=256)(androguard_util.get_access_field)

# Cache the class name parsing which involves heavy rsplit/replace operations
@functools.lru_cache(maxsize=4096)
def _fast_parse_class_info(raw_name):
    if '/' in raw_name:
        pckg, name = raw_name.rsplit('/', 1)
        package = pckg[1:].replace('/', '.')
        return package, name[:-1]
    return '', raw_name

# We Monkey Patch DvClass.__init__ to use our fast parser and avoid redundant allocations
_orig_dvclass_init = decompile.DvClass.__init__
def patched_dvclass_init(self, dvclass, vma):
    self.vma = vma
    self.methods = dvclass.get_methods()
    self.fields = dvclass.get_fields()
    self.code = []
    self.inner = False
    
    raw_name = dvclass.get_name()
    self.package, self.name = _fast_parse_class_info(raw_name)
    
    access = dvclass.get_access_flags()
    proto_fmt = '%s %s' if (0x200 & access) else '%s class %s'
    if (0x200 & access) and (access & 0x400):
        access -= 0x400
        
    self.access = androguard_util.get_access_class(access)
    self.prototype = proto_fmt % (' '.join(self.access), self.name)
    self.interfaces = dvclass.get_interfaces()
    self.superclass = dvclass.get_superclassname()
    self.thisclass = raw_name

decompile.DvClass.__init__ = patched_dvclass_init
# --- End of String/Type Optimizations ---

# We also completely disable ALL androguard loggers via python's standard logging module
# import logging

# Create a filter that blocks ALL records
# class BlockAllFilter(logging.Filter):
#     def filter(self, record):
#         return False

# block_filter = BlockAllFilter()

# for log_name in [
#     'androguard.decompiler.dataflow',
#     'androguard.decompiler.decompile',
#     'androguard.decompiler.opcode_ins',
#     'androguard.core.dex',
#     'androguard.core.analysis.analysis',
#     'androguard.core.bytecodes.dvm',
#     'androguard'
# ]:
#     log = logging.getLogger(log_name)
#     log.setLevel(logging.CRITICAL)
#     log.propagate = False
#     log.disabled = True
#     log.addFilter(block_filter)

# Hack: Fake Analysis to avoid slow initialization
class FakeAnalysis:
    def __init__(self, vm):
        self.methods = {}
        self.classes = {}
        self.vm = vm
        
    def get_method(self, method):
        if method not in self.methods:
            ma = MethodAnalysis(self.vm, method)
            self.methods[method] = ma
        return self.methods[method]

def decompile_dex_bytes(dex_bytes: bytearray, dalvik_class_fmt: str):
    """
    Take DEX bytes and a target class format, decompile it using Androguard DAD
    and return the source code.
    """

    # androguard requires bytes or bytearray
    d = DEX(bytes(dex_bytes))
    dx = FakeAnalysis(d)
    
    target_class = d.get_class(dalvik_class_fmt)
    if not target_class:
        return f"Error: Class {dalvik_class_fmt} not found in the reconstructed DEX."
        
    c = decompile.DvClass(target_class, dx)
    c.process()
    # Remove the Decompile only time debug output
    return c.get_source()
