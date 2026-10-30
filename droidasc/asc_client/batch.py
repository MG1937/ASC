"""Decompile many classes with one APK pass.

``getclass`` reopens the APK and re-inflates DEX entries for every class. This
module inflates each DEX once, indexes the classes it defines, then decompiles
from those in-memory buffers.
"""
import mmap
import os

from droidasc.asc_client.apk.dex_reader import list_dex_classes
from droidasc.asc_client.apk.loader import _inflate_dex, _parse_cd_dex_entries
from droidasc.asc_client.asc_handler import AscHandler
from droidasc.asc_client.dex_container import iter_logical_dex_buffers


def _to_dalvik_class(name):
    if not name:
        raise ValueError("Class name cannot be empty")
    name = name.strip()
    if name.startswith("L") and name.endswith(";") and "/" in name:
        return name
    name = name.replace(".", "/")
    if not name.startswith("L"):
        name = "L" + name
    return name if name.endswith(";") else name + ";"


def class_output_path(dalvik_class):
    return dalvik_class[1:-1] + ".java"


def index_apk(apk_path, prefix=None, log=None):
    if prefix is not None:
        prefix = prefix.strip()
        if not prefix:
            raise ValueError("Class prefix cannot be empty")
        if not prefix.startswith("L"):
            prefix = "L" + prefix.replace(".", "/")
    prefix_bytes = prefix.encode("ascii") if prefix and prefix.isascii() else None

    index = {}
    with open(apk_path, "rb") as fp:
        mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            entries = _parse_cd_dex_entries(mm)
            if not entries:
                raise ValueError("No DEX entries found in APK")
            for entry in entries:
                data = _inflate_dex(mm, entry)
                if data is None:
                    continue
                for logical_name, buf in iter_logical_dex_buffers(entry[0], data):
                    if log is not None:
                        log(f"[APK] '{logical_name}' inflated={len(buf)} bytes")
                    try:
                        names = list_dex_classes(buf, prefix=prefix, prefix_bytes=prefix_bytes)
                    except ValueError:
                        # A malformed sibling DEX must not hide the classes that are fine.
                        continue
                    for name in names:
                        index.setdefault(name, buf)
            return index
        finally:
            mm.close()


def read_class_list(path):
    names = []
    with open(path, "r", encoding="utf-8", errors="replace") as fp:
        for line in fp:
            name = line.strip()
            if name and not name.startswith("#"):
                names.append(_to_dalvik_class(name))
    if not names:
        raise ValueError(f"{path}: no class names found")
    return names


def decompile(index, dalvik_class):
    return AscHandler().getclass(index[dalvik_class], dalvik_class)


def write_source(dest, source):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8", errors="replace", newline="\n") as fp:
        fp.write(source)
        if not source.endswith("\n"):
            fp.write("\n")
