import sys
import types


class DummyClass: pass
class DummyModule:
    __path__ = []
    def __init__(self):
        self.APK = DummyClass
    def __getattr__(self, name): return DummyModule()
    def __iter__(self): return iter([])
    def __call__(self, *args, **kwargs): return DummyModule()
    

# The dummy import trick bascially gen by LLM 20260607

# Install the stubs only for modules that are not already imported. Replacing a real,
# already imported module (multiprocessing in particular, which concurrent.futures pulls
# in) breaks every later `import` of it: a stub package has __path__ = [], so
# `import multiprocessing.connection` raises ModuleNotFoundError and callers that use the
# placeholder instead fail silently. Dropping a stub that is not needed anyway costs
# nothing, so this keeps the startup saving without clobbering live modules.
_STUBBED_MODULES = (
    'androguard.core.apk',
    'networkx',
    'pygments',
    'lxml',
    'asn1crypto',
    'asn1crypto.x509',
    'cryptography',
    'matplotlib',
    'pydot',
    'IPython',
    'colorama',
    'dateutil',
    'urllib3',
    'requests',
    'idna',
    'chardet',
    'certifi',
    'pkg_resources',
    'loguru',
    'loguru._logger',
    'click',
    'urllib',
    'urllib.request',
    'http.client',
    'email',
    'email.parser',
    'email.message',
    'multiprocessing',
    'multiprocessing.context',
    'multiprocessing.reduction',
    'xml.sax.saxutils',
    'tempfile',
    'bz2',
    'lzma',
    'shutil',
    'bisect',
    'random',
    'json',
    'json.scanner',
    'json.decoder',
    'json.encoder',
    'math',
    'weakref',
)
def _install_stub(name):
    existing = sys.modules.get(name)
    if existing is not None and not isinstance(existing, DummyModule):
        # a real module is already loaded: never clobber it with a placeholder
        return
    parent = sys.modules.get(name.split('.')[0])
    if isinstance(parent, types.ModuleType) and not isinstance(parent, DummyModule):
        # the real parent package is loaded, so this submodule must stay importable
        return
    sys.modules[name] = DummyModule()


for _name in _STUBBED_MODULES:
    _install_stub(_name)

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

@functools.lru_cache(maxsize=4096)
def _format_annotation_type(raw_name):
    if raw_name.startswith('L') and raw_name.endswith(';'):
        raw_name = raw_name[1:-1]
    raw_name = raw_name.replace('/', '.')
    return raw_name.rsplit('.', 1)[-1].replace('$', '.')

def _format_annotation_value(value):
    value_type = value.get_value_type()
    raw_value = value.get_value()
    if value_type == androguard_dex.VALUE_STRING:
        return '"%s"' % str(raw_value).encode("unicode-escape").decode("ascii")
    if value_type == androguard_dex.VALUE_TYPE:
        return "%s.class" % _format_annotation_type(str(raw_value))
    if value_type == androguard_dex.VALUE_ARRAY:
        return "{%s}" % ", ".join(_format_annotation_value(v) for v in raw_value.get_values())
    if value_type == androguard_dex.VALUE_ANNOTATION:
        return _format_encoded_annotation(raw_value)
    if value_type == androguard_dex.VALUE_BOOLEAN:
        return "true" if raw_value else "false"
    if value_type == androguard_dex.VALUE_NULL:
        return "null"
    return str(raw_value)

def _format_encoded_annotation(annotation):
    cm = annotation.CM
    name = _format_annotation_type(cm.get_type(annotation.get_type_idx()))
    elements = annotation.get_elements()
    if not elements:
        return "@%s" % name
    parts = []
    for element in elements:
        element_name = cm.get_raw_string(element.get_name_idx())
        parts.append("%s=%s" % (element_name, _format_annotation_value(element.get_value())))
    return "@%s(%s)" % (name, ", ".join(parts))

def _annotation_set_to_source(cm, annotations_off):
    if annotations_off == 0:
        return []
    annotation_set = cm.get_annotation_set_item(annotations_off)
    if annotation_set is None:
        return []
    ret = []
    for off_item in annotation_set.get_annotation_off_item():
        annotation_item = off_item.get_annotation_item()
        if annotation_item is None:
            continue
        ret.append(_format_encoded_annotation(annotation_item.get_annotation()))
    return ret

def _build_method_annotation_map(dvclass):
    directory = getattr(dvclass, "annotations_directory_item", None)
    if directory is None:
        return {}
    ret = {}
    cm = dvclass.CM
    for method_annotation in directory.get_method_annotations():
        annotations = _annotation_set_to_source(cm, method_annotation.get_annotations_off())
        if annotations:
            ret[method_annotation.get_method_idx()] = annotations
    return ret

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
    self._asc_method_annotations = _build_method_annotation_map(dvclass)

decompile.DvClass.__init__ = patched_dvclass_init

_orig_dvclass_process_method = decompile.DvClass.process_method
def patched_dvclass_process_method(self, num: int, doAST: bool = False) -> None:
    _orig_dvclass_process_method(self, num, doAST=doAST)
    method = self.methods[num]
    if isinstance(method, decompile.DvMethod):
        method_idx = method.method.get_method_idx()
        method._asc_annotations = self._asc_method_annotations.get(method_idx, [])

decompile.DvClass.process_method = patched_dvclass_process_method

_orig_dvmethod_get_source = decompile.DvMethod.get_source
def patched_dvmethod_get_source(self) -> str:
    source = _orig_dvmethod_get_source(self)
    annotations = getattr(self, "_asc_annotations", None)
    if not annotations or not source:
        return source
    return "".join("\n    %s" % annotation for annotation in annotations) + source

decompile.DvMethod.get_source = patched_dvmethod_get_source
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
