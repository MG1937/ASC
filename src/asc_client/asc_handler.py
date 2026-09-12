import copy
import importlib.util
import os
import sys
import types
from collections import defaultdict


_DexManager = None
_FindRefManager = None
_decompile_dex_bytes = None
_DEX = None


def _install_pure_python_mutf8_shim():
    if "mutf8.cmutf8" in sys.modules:
        return

    pkg_spec = importlib.util.find_spec("mutf8")
    if pkg_spec is None or not pkg_spec.submodule_search_locations:
        return

    pkg_dir = pkg_spec.submodule_search_locations[0]
    py_impl = os.path.join(pkg_dir, "mutf8.py")
    mod_spec = importlib.util.spec_from_file_location("_asc_client_mutf8_py", py_impl)
    if mod_spec is None or mod_spec.loader is None:
        return

    module = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(module)

    shim = types.ModuleType("mutf8.cmutf8")
    shim.decode_modified_utf8 = module.decode_modified_utf8
    shim.encode_modified_utf8 = module.encode_modified_utf8
    sys.modules["mutf8.cmutf8"] = shim


def _lazy_import():
    global _DexManager, _FindRefManager, _decompile_dex_bytes, _DEX
    if _DexManager is not None:
        return

    _install_pure_python_mutf8_shim()
    from src.asc_core.core.dex.dex_manager import DexManager
    from src.asc_core.findrefs.findrefs_manager import FindRefManager
    from src.asc_core.utils.tinydex import DEX
    from src.asc_core.utils.decompiler import decompile_dex_bytes

    _DexManager = DexManager
    _FindRefManager = FindRefManager
    _decompile_dex_bytes = decompile_dex_bytes
    _DEX = DEX


class AscHandler:
    def __init__(self, debug : bool = False):
        self.debug = debug

    def getclass(self, dex_buf : bytes, dalvik_class : str) -> str:
        _lazy_import()
        manager = _DexManager(memoryview(dex_buf), debug=self.debug)
        new_dex_bytes = manager.extract_and_rebuild(dalvik_class)
        return _decompile_dex_bytes(new_dex_bytes, dalvik_class)

    def _format_method(self, dex, midx : int) -> str:
        method = dex.methods[midx]
        return f"{method.cls.fullname}->{method.name}"

    def _format_matched_name(self, dex, find_type : str, idx : int) -> str:
        if find_type == "string":
            return str(dex.strings[idx])
        if find_type == "type":
            return dex.types[idx].descriptor
        if find_type == "method":
            method = dex.methods[idx]
            return f"{method.cls.fullname}->{method.name}"
        field = dex.fields[idx]
        return f"{field.cls.fullname}->{field.name}"

    def findrefs_hits(self, dex_name : str, dex_buf : bytes, find_type : str, find : dict, aggregate : bool = True) -> list:
        from src.asc_client.results import FindRefHit
        from src.asc_core.findrefs.findrefs_manager import FindRefManager
        from src.asc_core.utils.tinydex import DEX

        dex = DEX.parse(memoryview(dex_buf), dex_name)
        ref_manager = FindRefManager(dex)
        query = copy.deepcopy(find)
        matched_idxs = ref_manager.find_ref(query, True)
        mids = query[find_type]
        if not aggregate:
            ret = []
            for i in range(len(mids)):
                midx = mids[i]
                if midx is None:
                    continue
                idx = matched_idxs[i]
                if isinstance(midx, list):
                    midxs = midx
                else:
                    midxs = [midx]
                matched = (self._format_matched_name(dex, find_type, idx),)
                for mid in midxs:
                    method = dex.methods[mid]
                    ret.append(
                        FindRefHit(
                            dex_name=dex_name,
                            caller_class=method.cls.fullname,
                            caller_method=method.name,
                            matched=matched,
                        )
                    )
            return ret

        grouped = defaultdict(set)
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
                grouped[mid].add(idx)

        ret = []
        for mid in sorted(grouped):
            matched = tuple(
                self._format_matched_name(dex, find_type, idx)
                for idx in sorted(grouped[mid])
            )
            method = dex.methods[mid]
            ret.append(
                FindRefHit(
                    dex_name=dex_name,
                    caller_class=method.cls.fullname,
                    caller_method=method.name,
                    matched=matched,
                )
            )
        return ret

    def findrefs(self, dex_name : str, dex_buf : bytes, find_type : str, find : dict, aggregate : bool = True) -> list:
        from src.asc_client.results import format_findref_hit

        return [
            format_findref_hit(hit)
            for hit in self.findrefs_hits(dex_name, dex_buf, find_type, find, aggregate=aggregate)
        ]
