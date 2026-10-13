import os
import sys

if __package__ in (None, ""):
    import types

    _HERE = os.path.dirname(os.path.abspath(__file__))
    _PARENT = os.path.dirname(_HERE)
    if _PARENT not in sys.path:
        sys.path.insert(0, _PARENT)
    _pkg = types.ModuleType("asc_core")
    _pkg.__path__ = [_HERE]
    _pkg.__package__ = "asc_core"
    sys.modules["asc_core"] = _pkg
    __package__ = "asc_core"

import argparse
import time

t_start = time.perf_counter()


def _build_member_find(key : str, clz : str, clz_fuzzy : bool, name : str) -> dict:
    if clz == "":
        clz = None
    if name == "":
        name = None
    if clz is None and name is None:
        raise ValueError(f"{key} query needs at least one of class or {key} name")
    if clz is None:
        return {key: {"class": None, key: name}}
    return {key: {"class": [clz, not clz_fuzzy], key: name}}


def _get_find_query(args) -> tuple:
    if args.find_type == "string":
        return "string", {"string": args.value}
    if args.find_type == "type":
        return "type", {"type": args.value}
    if args.find_type == "extends":
        return "extends", {"extends": args.value}
    if args.find_type == "impl":
        return "impl", {"impl": args.value}
    if args.find_type == "method":
        return "method", _build_member_find("method", args.class_name, args.fuzzy_class, args.name)
    return "field", _build_member_find("field", args.class_name, args.fuzzy_class, args.name)


def _format_method(dex, midx : int) -> str:
    method = dex.methods[midx]
    return f"{method.cls.fullname}->{method.name}"


def _format_matched_name(dex, find_type : str, idx : int) -> str:
    if find_type == "string":
        return str(dex.strings[idx])
    if find_type == "type":
        return dex.types[idx].descriptor
    if find_type == "method":
        method = dex.methods[idx]
        return f"{method.cls.fullname}->{method.name}"
    field = dex.fields[idx]
    return f"{field.cls.fullname}->{field.name}"


def _print_findrefs(dex, find_type : str, mids : list, matched_idxs : list):
    for i in range(len(mids)):
        midx = mids[i]
        if midx is None:
            continue
        idx = matched_idxs[i]
        if isinstance(midx, list):
            midxs = midx
        else:
            midxs = [midx]
        for mid in midxs:
            print(f"{_format_method(dex, mid)} | matched=({_format_matched_name(dex, find_type, idx)})")


def _print_extends(dex, class_idxs : list):
    for class_idx in class_idxs:
        print(dex.types[class_idx].descriptor)


def _handle_getclass(args):
    from .core.dex.dex_manager import DexManager
    from .utils.decompiler import decompile_dex_bytes

    manager = DexManager(args.dex_path, debug=args.debug)
    new_dex_bytes = manager.extract_and_rebuild(args.dalvik_class)

    if args.debug:
        t_rebuild_end = time.perf_counter()
    source_code = decompile_dex_bytes(new_dex_bytes, args.dalvik_class)

    t_end = time.perf_counter()

    if args.debug:
        print(f"[DEBUG] Dex Decompile Time: {(t_end - t_rebuild_end)*1000000:.2f} us")
        print(f"[DEBUG] Total Execution Time: {(t_end - t_start)*1000000:.2f} us")
        print("-" * 50)

    print(source_code)


def _handle_findrefs(args):
    from .core.dex.dex_manager import DexManager
    from .findrefs.findrefs_manager import FindRefManager

    manager = DexManager(args.dex_path, debug=args.debug)
    find_type, find = _get_find_query(args)
    ref_manager = FindRefManager(manager.dex, args.debug)
    matched_idxs = ref_manager.find_ref(find, True)
    mids = find[find_type]

    if find_type == "extends" or find_type == "impl":
        _print_extends(manager.dex, mids)
    else:
        _print_findrefs(manager.dex, find_type, mids, matched_idxs)

    if args.debug:
        t_end = time.perf_counter()
        print(f"[DEBUG] Total Execution Time: {(t_end - t_start)*1000000:.2f} us")

def main():
    parser = argparse.ArgumentParser(description="DEX tooling entry.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    getclass_parser = subparsers.add_parser("getclass", help="Extract and rebuild one Dalvik class, then decompile it.")
    getclass_parser.add_argument("dex_path", help="Path to the input DEX file.")
    getclass_parser.add_argument("dalvik_class", help="The Dalvik format class name to extract (e.g., Lcom/poc/Main;).")
    getclass_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")

    findrefs_parser = subparsers.add_parser(
        "findrefs",
        help="Find code references or classes extending a target class.",
    )
    findrefs_parser.add_argument("--debug", action="store_true", help="Enable debug profiling output.")
    findrefs_parser.add_argument("dex_path", help="Path to the input DEX file.")
    find_subparsers = findrefs_parser.add_subparsers(dest="find_type", required=True)

    string_parser = find_subparsers.add_parser("string", help="Find references to a fuzzy string.")
    string_parser.add_argument("value", help="Fuzzy string pattern.")

    type_parser = find_subparsers.add_parser("type", help="Find references to a fuzzy type descriptor/name.")
    type_parser.add_argument("value", help="Fuzzy type pattern.")

    extends_parser = find_subparsers.add_parser("extends", help="Find classes that extend a precise class.")
    extends_parser.add_argument("value", help="Precise Dalvik superclass descriptor.")

    impl_parser = find_subparsers.add_parser("impl", help="Find classes that implement a precise interface.")
    impl_parser.add_argument("value", help="Precise Dalvik interface descriptor.")

    method_parser = find_subparsers.add_parser("method", help="Find references to methods.")
    method_parser.add_argument("name", nargs="?", default=None, help="Fuzzy method name.")
    method_parser.add_argument("--class", dest="class_name", default=None, help="Dalvik class or fuzzy class pattern.")
    method_parser.add_argument("--fuzzy-class", action="store_true", help="Treat --class as fuzzy match.")

    field_parser = find_subparsers.add_parser("field", help="Find references to fields.")
    field_parser.add_argument("name", nargs="?", default=None, help="Fuzzy field name.")
    field_parser.add_argument("--class", dest="class_name", default=None, help="Dalvik class or fuzzy class pattern.")
    field_parser.add_argument("--fuzzy-class", action="store_true", help="Treat --class as fuzzy match.")
    
    args = parser.parse_args()
    
    try:
        if args.command == "getclass":
            _handle_getclass(args)
        else:
            _handle_findrefs(args)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
