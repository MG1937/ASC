"""Model Context Protocol server for Droid ASC.

The server deliberately calls the same in-process APIs as the CLI.  This keeps
the MCP surface small and avoids spawning a CLI subprocess for every request,
which matters when an APK contains many DEX files.

Run it with::

    python -m droidasc.mcp_server

or, after installation, with the ``droidasc-mcp`` console script.
"""

from __future__ import annotations

import argparse
import time
import zipfile
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from droidasc.cli import _build_member_find, _format_class_name


SERVER_NAME = "droidasc"
SERVER_VERSION = "0.1.0"
DEFAULT_THREADS = 8
MAX_THREADS = 32
DEFAULT_CLASS_LIMIT = 10_000
MAX_CLASS_LIMIT = 50_000
DEFAULT_REFERENCE_LIMIT = 5_000
MAX_REFERENCE_LIMIT = 25_000

ThreadCount = Annotated[
    int,
    Field(
        ge=1,
        le=MAX_THREADS,
        description="Worker count used while scanning DEX entries (1-32).",
    ),
]


class ClassResult(BaseModel):
    """A decompiled class and the DEX it came from."""

    class_name: str = Field(description="Normalized Dalvik descriptor.")
    dex_name: str = Field(description="APK entry containing the class.")
    source: str = Field(description="Decompiled Java-like source code.")
    elapsed_ms: float = Field(description="Elapsed server-side time in milliseconds.")


class ClassListResult(BaseModel):
    """Class listing with an explicit truncation signal."""

    apk_path: str
    classes: list[str]
    total: int = Field(description="Number of classes matching the prefix.")
    returned: int
    truncated: bool
    elapsed_ms: float


class ManifestResult(BaseModel):
    """Decoded Android manifest."""

    apk_path: str
    xml: str
    elapsed_ms: float


class ReferenceResult(BaseModel):
    """Reference matches returned by a cross-DEX search."""

    apk_path: str
    find_type: Literal["string", "type", "method", "field"]
    matches: list[str]
    total: int = Field(description="Number of matches found before the response cap.")
    returned: int
    truncated: bool
    dexes_scanned: int
    elapsed_ms: float


def _validated_apk_path(apk_path: str) -> tuple[Path, tuple[str, int, int]]:
    """Validate and canonicalize an input path.

    The cache key includes file metadata, so replacing an APK invalidates cached
    metadata without requiring a process restart.
    """

    if not isinstance(apk_path, str) or not apk_path.strip():
        raise ToolError("apk_path must be a non-empty path")

    path = Path(apk_path).expanduser()
    try:
        path = path.resolve(strict=True)
        stat = path.stat()
    except OSError as exc:
        raise ToolError(f"Cannot access APK: {exc}") from exc

    if not path.is_file():
        raise ToolError(f"APK path is not a file: {path}")

    # Opening the archive validates its central directory and turns a confusing
    # low-level error into an actionable MCP error. Do not call testzip() here:
    # it would read every compressed member before every request. Do not require
    # a .apk suffix: test fixtures and split APK workflows commonly use another
    # filename.
    try:
        with zipfile.ZipFile(path):
            pass
    except zipfile.BadZipFile as exc:
        raise ToolError(f"Input is not a valid APK/ZIP archive: {path}") from exc
    except OSError as exc:
        raise ToolError(f"Cannot read APK: {exc}") from exc

    return path, (str(path), stat.st_mtime_ns, stat.st_size)


@lru_cache(maxsize=8)
def _cached_manifest(path: str, mtime_ns: int, size: int) -> str:
    from droidasc.asc_client.manifest_handler import get_manifest_xml

    return get_manifest_xml(path, pretty=True)


@lru_cache(maxsize=8)
def _cached_classes(
    path: str,
    mtime_ns: int,
    size: int,
    prefix: str | None,
    threads: int,
) -> tuple[str, ...]:
    from droidasc.asc_client.apk_handler import ApkHandler

    return tuple(ApkHandler(path, max_workers=threads).list_classes(prefix))


def _friendly_tool_error(exc: Exception) -> ToolError:
    if isinstance(exc, ToolError):
        return exc
    if isinstance(exc, (OSError, ValueError, KeyError, IndexError, zipfile.BadZipFile)):
        return ToolError(str(exc) or exc.__class__.__name__)
    return ToolError(f"Droid ASC failed: {exc.__class__.__name__}")


server = MCPServer(
    name=SERVER_NAME,
    version=SERVER_VERSION,
    description=(
        "Read-only Android APK/DEX analysis through Droid ASC. "
        "Use these tools to inspect classes, manifests, and code references "
        "without inflating the entire APK into a persistent index."
    ),
    instructions=(
        "Paths are resolved on the machine running this server. "
        "Class names accept Java notation (com.example.Main) or Dalvik descriptors "
        "(Lcom/example/Main;). Reference searches are fuzzy unless a class query "
        "is explicitly normalized by the tool."
    ),
)

_READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)


@server.tool(
    name="decompile_class",
    title="Decompile one Android class",
    annotations=_READ_ONLY,
    description=(
        "Locate one class across all DEX entries in an APK, extract only its "
        "minimal self-contained DEX, and return decompiled source. Class names "
        "may be Java-style or Dalvik descriptors."
    ),
)
def decompile_class(
    apk_path: str,
    class_name: str,
    threads: ThreadCount = DEFAULT_THREADS,
) -> ClassResult:
    started = time.perf_counter()
    path, _key = _validated_apk_path(apk_path)
    if not class_name.strip():
        raise ToolError("class_name must be a non-empty class name")

    try:
        from droidasc.asc_client.apk_handler import ApkHandler
        from droidasc.asc_client.asc_handler import AscHandler

        dalvik_class = _format_class_name(class_name)
        hit = ApkHandler(str(path), max_workers=threads).get_class_dex(dalvik_class)
        if hit is None:
            raise ToolError(f"Class {dalvik_class} not found in APK")
        dex_name, dex_buf = hit
        source = AscHandler(False).getclass(dex_buf, dalvik_class)
    except Exception as exc:
        raise _friendly_tool_error(exc) from exc

    return ClassResult(
        class_name=dalvik_class,
        dex_name=dex_name,
        source=source,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
    )


@server.tool(
    name="list_classes",
    title="List classes in an APK",
    annotations=_READ_ONLY,
    description=(
        "List class descriptors in APK/DEX definition order. An optional prefix "
        "accepts Java package notation or a Dalvik prefix. Results are capped by "
        "limit and report whether truncation occurred."
    ),
)
def list_classes(
    apk_path: str,
    prefix: str | None = None,
    threads: ThreadCount = DEFAULT_THREADS,
    limit: Annotated[
        int | None,
        Field(ge=1, le=MAX_CLASS_LIMIT, description="Maximum classes to return."),
    ] = DEFAULT_CLASS_LIMIT,
) -> ClassListResult:
    started = time.perf_counter()
    path, key = _validated_apk_path(apk_path)
    if prefix is not None and not prefix.strip():
        raise ToolError("prefix cannot be empty when provided")

    try:
        names = _cached_classes(*key, prefix, threads)
    except Exception as exc:
        raise _friendly_tool_error(exc) from exc

    total = len(names)
    returned_names = list(names[:limit] if limit is not None else names)
    return ClassListResult(
        apk_path=str(path),
        classes=returned_names,
        total=total,
        returned=len(returned_names),
        truncated=len(returned_names) < total,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
    )


@server.tool(
    name="decode_manifest",
    title="Decode AndroidManifest.xml",
    annotations=_READ_ONLY,
    description="Decode an APK's binary AndroidManifest.xml and return readable XML.",
)
def decode_manifest(apk_path: str) -> ManifestResult:
    started = time.perf_counter()
    path, key = _validated_apk_path(apk_path)
    try:
        xml = _cached_manifest(*key)
    except Exception as exc:
        raise _friendly_tool_error(exc) from exc
    return ManifestResult(
        apk_path=str(path),
        xml=xml,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
    )


@server.tool(
    name="find_references",
    title="Find Android code references",
    annotations=_READ_ONLY,
    description=(
        "Search all DEX entries for string, type, method, or field references. "
        "For method/field searches, provide a name, class_name, or both; set "
        "fuzzy_class when class_name is a pattern instead of an exact class."
    ),
)
def find_references(
    apk_path: str,
    find_type: Literal["string", "type", "method", "field"],
    value: str | None = None,
    name: str | None = None,
    class_name: str | None = None,
    fuzzy_class: bool = False,
    threads: ThreadCount = DEFAULT_THREADS,
    aggregate: bool = True,
    max_results: Annotated[
        int | None,
        Field(ge=1, le=MAX_REFERENCE_LIMIT, description="Maximum matches to return."),
    ] = DEFAULT_REFERENCE_LIMIT,
) -> ReferenceResult:
    started = time.perf_counter()
    path, _key = _validated_apk_path(apk_path)

    if find_type in ("string", "type"):
        if not value or not value.strip():
            raise ToolError(f"{find_type} searches require a non-empty value")
        find = {find_type: value}
    else:
        if value is not None and name is None:
            name = value
        try:
            find = _build_member_find(find_type, class_name, fuzzy_class, name)
        except ValueError as exc:
            raise ToolError(str(exc)) from exc

    try:
        from droidasc.asc_client.apk_handler import ApkHandler

        matches: list[str] = []
        total = 0
        dexes_scanned = 0
        handler = ApkHandler(str(path), max_workers=threads)
        for _dex_name, lines in handler.for_each_findrefs(find_type, find):
            dexes_scanned += 1
            total += len(lines)
            if max_results is None:
                matches.extend(lines)
            elif len(matches) < max_results:
                matches.extend(lines[: max_results - len(matches)])
    except Exception as exc:
        raise _friendly_tool_error(exc) from exc

    return ReferenceResult(
        apk_path=str(path),
        find_type=find_type,
        matches=matches,
        total=total,
        returned=len(matches),
        truncated=max_results is not None and total > max_results,
        dexes_scanned=dexes_scanned,
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
    )


def main() -> None:
    """Start the MCP stdio transport."""

    # argparse gives ``--help`` to humans launching the console script while
    # keeping the normal no-argument invocation a pure MCP stdio process.
    parser = argparse.ArgumentParser(description="Droid ASC MCP server")
    parser.add_argument(
        "--transport",
        choices=("stdio",),
        default="stdio",
        help="MCP transport (stdio is currently supported).",
    )
    parser.parse_args()
    server.run("stdio")


if __name__ == "__main__":
    main()
