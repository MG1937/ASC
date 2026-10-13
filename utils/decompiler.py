from dadguard.core.dex import DEX
from dadguard.core.analysis.analysis import Analysis
import dadguard.core.dex as dadguard_dex

original_header_init = dadguard_dex.HeaderItem.__init__
def monkey_header_init(self, offset, buff, cm):
    try:
        original_header_init(self, offset, buff, cm)
    except ValueError as e:
        if "Adler32" in str(e):
            pass
        else:
            raise e
dadguard_dex.HeaderItem.__init__ = monkey_header_init

from dadguard.decompiler import decompile
from dadguard.decompiler import instruction as dadguard_instruction
from dadguard.decompiler import util as dadguard_util
from dadguard.decompiler import writer as dadguard_writer
from dadguard.core.analysis.analysis import MethodAnalysis
import dadguard.core.androconf as androconf
import functools

# --- dadguard String Operations & Type Parsing Optimizations ---
# Dalvik bytecode formatting and access flag resolution generates a massive amount
# of redundant string objects. We wrap them all in LRU caches.
dadguard_util.get_type = functools.lru_cache(maxsize=4096)(dadguard_util.get_type)
dadguard_util.get_type_size = functools.lru_cache(maxsize=4096)(dadguard_util.get_type_size)
dadguard_util.get_access_class = functools.lru_cache(maxsize=256)(dadguard_util.get_access_class)
dadguard_util.get_access_method = functools.lru_cache(maxsize=256)(dadguard_util.get_access_method)
dadguard_util.get_access_field = functools.lru_cache(maxsize=256)(dadguard_util.get_access_field)

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
    if value_type == dadguard_dex.VALUE_STRING:
        return '"%s"' % str(raw_value).encode("unicode-escape").decode("ascii")
    if value_type == dadguard_dex.VALUE_TYPE:
        return "%s.class" % _format_annotation_type(str(raw_value))
    if value_type == dadguard_dex.VALUE_ARRAY:
        return "{%s}" % ", ".join(_format_annotation_value(v) for v in raw_value.get_values())
    if value_type == dadguard_dex.VALUE_ANNOTATION:
        return _format_encoded_annotation(raw_value)
    if value_type == dadguard_dex.VALUE_BOOLEAN:
        return "true" if raw_value else "false"
    if value_type == dadguard_dex.VALUE_NULL:
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

    self.access = dadguard_util.get_access_class(access)
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
_orig_dvmethod_get_source_ext = decompile.DvMethod.get_source_ext
def patched_dvmethod_get_source_ext(self) -> list[tuple]:
    source = _orig_dvmethod_get_source_ext(self)
    annotations = getattr(self, "_asc_annotations", None)
    if not annotations:
        return source
    prefix = "".join("\n    %s" % annotation for annotation in annotations)
    return [("ASC_ANNOTATIONS", prefix)] + source

decompile.DvMethod.get_source_ext = patched_dvmethod_get_source_ext

# Preserve the declaring field on source tokens. dadguard's default Writer
# keeps the field name for instance accesses and only a combined text token for
# static accesses, but drops the field IR object containing clsdesc.
def patched_instance_expression_visit(self, visitor):
    return visitor.visit_get_instance(
        self.var_map[self.arg], self.name, data=self
    )


def patched_instance_instruction_visit(self, visitor):
    v_m = self.var_map
    return visitor.visit_put_instance(
        v_m[self.lhs], self.name, v_m[self.rhs], data=self
    )


def patched_writer_get_static(self, cls, name, data=None):
    value = f"{cls}.{name}"
    self.write(value)
    self.write_ext(("GET_STATIC", value, data))


def patched_static_expression_visit(self, visitor):
    return visitor.visit_get_static(self.cls, self.name, data=self)


def patched_writer_put_static(self, cls, name, rhs, data=None):
    self.write_ind()
    value = f"{cls}.{name}"
    self.write(value)
    self.write_ext(("PUT_STATIC", value, data))
    self.write(" = ")
    self.write_ext(("FIELD_ASSIGN", " = "))
    rhs.visit(self)
    self.end_ins()


def patched_static_instruction_visit(self, visitor):
    return visitor.visit_put_static(
        self.cls, self.name, self.var_map[self.rhs], data=self
    )


_orig_writer_visit_constant = decompile.Writer.visit_constant
def patched_writer_visit_constant(self, cst):
    if not isinstance(cst, str):
        return _orig_writer_visit_constant(self, cst)
    value = dadguard_writer.string(cst)
    self.write(value)
    self.write_ext(("CONSTANT_STRING", value, cst))


def patched_base_class_visit(self, visitor):
    return visitor.visit_base_class(self.cls, data=self.clsdesc or self.cls)


dadguard_instruction.InstanceExpression.visit = patched_instance_expression_visit
dadguard_instruction.InstanceInstruction.visit = patched_instance_instruction_visit
dadguard_instruction.StaticExpression.visit = patched_static_expression_visit
dadguard_instruction.StaticInstruction.visit = patched_static_instruction_visit
dadguard_instruction.BaseClass.visit = patched_base_class_visit
decompile.Writer.visit_get_static = patched_writer_get_static
decompile.Writer.visit_put_static = patched_writer_put_static
decompile.Writer.visit_constant = patched_writer_visit_constant
# --- End of String/Type Optimizations ---

# We also completely disable ALL dadguard loggers via python's standard logging module
# import logging

# Create a filter that blocks ALL records
# class BlockAllFilter(logging.Filter):
#     def filter(self, record):
#         return False

# block_filter = BlockAllFilter()

# for log_name in [
#     'dadguard.decompiler.dataflow',
#     'dadguard.decompiler.decompile',
#     'dadguard.decompiler.opcode_ins',
#     'dadguard.core.dex',
#     'dadguard.core.analysis.analysis',
#     'dadguard.core.bytecodes.dvm',
#     'dadguard'
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

def _decompile_class(dex_bytes: bytearray, dalvik_class_fmt: str):
    """
    Take DEX bytes and a target class format, decompile it using dadguard DAD
    and return the source code.
    """

    # dadguard requires bytes or bytearray
    d = DEX(bytes(dex_bytes))
    dx = Analysis(d)

    target_class = d.get_class(dalvik_class_fmt)
    if not target_class:
        return None

    c = decompile.DvClass(target_class, dx)
    c.process()
    return c


def _dalvik_class_name(name : str) -> str:
    name = (name or "").replace(".", "/")
    if not name.startswith("L"):
        name = "L" + name
    if not name.endswith(";"):
        name += ";"
    return name


def _dalvik_reference_class(name : str):
    name = (name or "").strip()
    while name.startswith("["):
        name = name[1:]
    while name.endswith("[]"):
        name = name[:-2]
    if not name or name in {
        "V", "Z", "B", "S", "C", "I", "J", "F", "D",
        "void", "boolean", "byte", "short", "char", "int", "long", "float", "double",
    }:
        return None
    return _dalvik_class_name(name)


# reuse dadguard daddecompiler's token type, we can extract source' semantics, enhance gui xref ability
# 20260921 we may extract daddecompiler from dadguard in future, for better development
def _source_with_member_references(source_ext):
    parts = []
    references = []
    offset = 0

    def append_tokens(tokens):
        nonlocal offset
        for token in tokens:
            if len(token) < 2:
                continue
            kind, value = token[0], token[1]
            if isinstance(value, list):
                append_tokens(value)
                continue
            value = str(value)
            start = offset
            parts.append(value)
            offset += len(value)

            if kind == "NAME_METHOD_PROTOTYPE" and len(token) >= 3:
                method = token[2]
                references.append((
                    start, offset, "method",
                    _dalvik_class_name(method.cls_name),
                    method.name,
                    method.triple[2],
                    True,
                ))
            elif kind == "NAME_METHOD_INVOKE" and len(token) >= 7:
                invoke = token[6]
                references.append((
                    start, offset, "method",
                    _dalvik_class_name(invoke.triple[0]),
                    invoke.name,
                    invoke.triple[2],
                    False,
                ))
            elif kind == "NAME_FIELD" and len(token) >= 4:
                field = token[3]
                references.append((
                    start, offset, "field",
                    field.get_class_name(),
                    field.get_name(),
                    field.get_descriptor(),
                    True,
                ))
            elif kind == "CONSTANT_STRING":
                raw_value = token[2] if len(token) >= 3 else value[1:-1]
                references.append((start, offset, "string", "", raw_value, "", False))
            elif kind in ("CHECKCAST", "NEW_ARRAY", "NEW_ARRAY_FILLED"):
                type_start = 2 if kind == "CHECKCAST" else 4
                type_end = value.find(") ", type_start) if kind == "CHECKCAST" else value.rfind("[")
                if kind == "NEW_ARRAY_FILLED":
                    type_end = value.rfind(" {")
                class_name = _dalvik_reference_class(value[type_start:type_end])
                if class_name is not None:
                    references.append((
                        start + type_start, start + type_end,
                        "class", class_name, "", "", False,
                    ))
            elif kind in (
                "VARIABLE_TYPE", "EXCEPTION_TYPE",
                "FIELD_TYPE", "ARG_TYPE", "PROTOTYPE_TYPE",
                "NAME_SUPERCLASS", "NAME_INTERFACE", "NAME_PROTOTYPE",
                "NAME_BASE_CLASS", "NAME_CLASS_NEW",
            ):
                raw_name = token[2] if len(token) >= 3 else value
                declaration = kind == "NAME_PROTOTYPE"
                if declaration and len(token) >= 3 and token[2]:
                    raw_name = f"{token[2]}.{value}"
                class_name = _dalvik_reference_class(raw_name)
                if class_name is not None:
                    references.append((
                        start, offset, "class", class_name, "", "", declaration,
                    ))
            elif kind in ("NAME_CLASS_INSTANCE", "NAME_CLASS_ASSIGNMENT") and len(token) >= 3:
                field = token[2]
                references.append((
                    start, offset, "field",
                    _dalvik_class_name(field.clsdesc),
                    field.name,
                    getattr(field, "ftype", getattr(field, "atype", "")),
                    False,
                ))
            elif kind in ("GET_STATIC", "PUT_STATIC") and len(token) >= 3:
                field = token[2]
                field_start = offset - len(field.name)
                class_name = _dalvik_class_name(field.clsdesc)
                if field_start > start:
                    references.append((
                        start, field_start - 1, "class", class_name, "", "", False,
                    ))
                references.append((
                    field_start, offset, "field",
                    class_name,
                    field.name,
                    field.ftype,
                    False,
                ))

    append_tokens(source_ext)
    return "".join(parts), references


def decompile_dex_bytes(dex_bytes: bytearray, dalvik_class_fmt: str):
    c = _decompile_class(dex_bytes, dalvik_class_fmt)
    if c is None:
        return f"Error: Class {dalvik_class_fmt} not found in the reconstructed DEX."
    # Remove the Decompile only time debug output
    return c.get_source()


def decompile_dex_bytes_with_metadata(dex_bytes: bytearray, dalvik_class_fmt: str):
    c = _decompile_class(dex_bytes, dalvik_class_fmt)
    if c is None:
        return f"Error: Class {dalvik_class_fmt} not found in the reconstructed DEX.", []
    return _source_with_member_references(c.get_source_ext())
