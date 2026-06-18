import importlib.util
import os
import sys
import types
from typing import Optional

from dex_agent.domain.models import ClassName
from dex_agent.domain.paths import WorkspacePaths
from dex_agent.infra.config_store import ConfigStore
from dex_agent.infra.fs import ensure_dir

_coredex_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))),
    "coredexwriter"
)

_DexManager = None
_decompile_dex_bytes = None


def _install_pure_python_mutf8_shim():
    if "mutf8.cmutf8" in sys.modules:
        return

    pkg_spec = importlib.util.find_spec("mutf8")
    if pkg_spec is None or not pkg_spec.submodule_search_locations:
        return

    pkg_dir = pkg_spec.submodule_search_locations[0]
    py_impl = os.path.join(pkg_dir, "mutf8.py")
    mod_spec = importlib.util.spec_from_file_location("_newtool_mutf8_py", py_impl)
    if mod_spec is None or mod_spec.loader is None:
        return

    module = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(module)

    shim = types.ModuleType("mutf8.cmutf8")
    shim.decode_modified_utf8 = module.decode_modified_utf8
    shim.encode_modified_utf8 = module.encode_modified_utf8
    sys.modules["mutf8.cmutf8"] = shim

def _lazy_import():
    global _DexManager, _decompile_dex_bytes
    if _DexManager is not None:
        return
    if _coredex_dir not in sys.path:
        sys.path.insert(0, _coredex_dir)
    _install_pure_python_mutf8_shim()
    from core.dex.dex_manager import DexManager
    from utils.decompiler import decompile_dex_bytes
    _DexManager = DexManager
    _decompile_dex_bytes = decompile_dex_bytes


def decompile_class(
    task_name: str,
    dex_file: str,
    clazz_name: str,
    paths: WorkspacePaths,
    config_store: ConfigStore
) -> Optional[str]:
    if not task_name or not dex_file or not clazz_name:
        print("ERROR: task_name, dex_file, and clazz_name must be specified", file=sys.stderr)
        sys.exit(1)

    clazz = ClassName(clazz_name)
    dalvik_fmt = clazz.formatted

    try:
        _lazy_import()
        manager = _DexManager(dex_file)
        new_dex_bytes = manager.extract_and_rebuild(dalvik_fmt)
        source_code = _decompile_dex_bytes(new_dex_bytes, dalvik_fmt)

        if source_code.startswith("Error:"):
            return None

        dex_file_name = os.path.basename(dex_file)
        java_path = paths.get_java_path(task_name, dex_file_name, clazz.to_dot_format())
        ensure_dir(os.path.dirname(java_path))
        with open(java_path, "w", encoding="utf-8") as f:
            f.write(source_code)

        config_store.add_java_record(task_name, java_path)

        return source_code

    except Exception as e:
        print(f"Decompile failed: {e}", file=sys.stderr)
        return None
