"""Compatibility entry point for the shared DAD decompiler."""


def decompile_dex_bytes(dex_bytes: bytearray, dalvik_class_fmt: str):
    from src.asc_core.utils.decompiler import decompile_dex_bytes as decompile

    return decompile(dex_bytes, dalvik_class_fmt)
