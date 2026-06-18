import os
import time
import mmap
import struct
import threading
import zlib
from concurrent.futures import ThreadPoolExecutor, FIRST_COMPLETED, wait
from typing import Optional, List, Tuple, Callable

from dex_agent.domain.models import TaskName, ClassName
from dex_agent.domain.paths import WorkspacePaths
from dex_agent.infra.fs import ensure_dir

_U16 = struct.Struct("<H")
_U32 = struct.Struct("<I")
_U16_FROM = _U16.unpack_from
_U32_FROM = _U32.unpack_from
_CD_SIG = b"PK\x01\x02"
_LH_SIG = b"PK\x03\x04"
_EOCD_SIG = b"PK\x05\x06"
_DEX_SUFFIX = b".dex"
_SLASH = ord("/")
_DEFLATE_CHUNK = 1 << 19


def _noop_log(msg: str):
    pass


def _skip_uleb128(buf, off: int) -> int:
    while buf[off] & 0x80:
        off += 1
    return off + 1


def _read_string_data_bytes(buf, str_off: int) -> bytes:
    ptr = _skip_uleb128(buf, str_off)
    end = buf.find(b"\x00", ptr)
    if end < 0:
        raise ValueError("unterminated string_data_item")
    return buf[ptr:end]


def _find_type_idx(buf, target_bytes: bytes) -> int:
    if len(buf) < 0x70 or buf[:3] != b"dex":
        return -1

    string_ids_size = _U32_FROM(buf, 0x38)[0]
    string_ids_off = _U32_FROM(buf, 0x3C)[0]
    type_ids_size = _U32_FROM(buf, 0x40)[0]
    type_ids_off = _U32_FROM(buf, 0x44)[0]

    if string_ids_size == 0 or type_ids_size == 0:
        return -1
    if string_ids_off + string_ids_size * 4 > len(buf):
        raise ValueError("bad string_ids range")
    if type_ids_off + type_ids_size * 4 > len(buf):
        raise ValueError("bad type_ids range")

    left = 0
    right = type_ids_size - 1
    while left <= right:
        mid = (left + right) >> 1
        str_idx = _U32_FROM(buf, type_ids_off + mid * 4)[0]
        if str_idx >= string_ids_size:
            raise ValueError("bad type_id->string_idx")
        str_off = _U32_FROM(buf, string_ids_off + str_idx * 4)[0]
        if str_off >= len(buf):
            raise ValueError("bad string_data_off")

        cls_bytes = _read_string_data_bytes(buf, str_off)
        if cls_bytes == target_bytes:
            return mid
        if cls_bytes < target_bytes:
            left = mid + 1
        else:
            right = mid - 1

    return -1


def _class_defs_contains_type_idx(buf, type_idx: int) -> bool:
    class_defs_size = _U32_FROM(buf, 0x60)[0]
    class_defs_off = _U32_FROM(buf, 0x64)[0]

    if class_defs_size == 0:
        return False
    class_defs_end = class_defs_off + class_defs_size * 32
    if class_defs_end > len(buf):
        raise ValueError("bad class_defs range")

    needle = type_idx.to_bytes(4, "little")
    pos = buf.find(needle, class_defs_off, class_defs_end)
    while pos != -1:
        rel = pos - class_defs_off
        if (rel & 31) == 0:
            return True
        pos = buf.find(needle, pos + 1, class_defs_end)

    return False


def _dex_defines_class(buf, target_bytes: bytes) -> bool:
    type_idx = _find_type_idx(buf, target_bytes)
    if type_idx < 0:
        return False
    return _class_defs_contains_type_idx(buf, type_idx)


def _get_class_def_idx(buf, target_bytes: bytes) -> int:
    type_idx = _find_type_idx(buf, target_bytes)
    if type_idx < 0:
        return -1

    class_defs_size = _U32_FROM(buf, 0x60)[0]
    class_defs_off = _U32_FROM(buf, 0x64)[0]
    class_defs_end = class_defs_off + class_defs_size * 32
    needle = type_idx.to_bytes(4, "little")
    pos = buf.find(needle, class_defs_off, class_defs_end)
    while pos != -1:
        rel = pos - class_defs_off
        if (rel & 31) == 0:
            return rel >> 5
        pos = buf.find(needle, pos + 1, class_defs_end)
    return -1


def _find_eocd(mm: mmap.mmap) -> int:
    search_start = max(0, len(mm) - 65536 - 22)
    return mm.rfind(_EOCD_SIG, search_start)


def _parse_cd_dex_entries(
    mm: mmap.mmap,
    on_disk_names: set[bytes],
) -> List[Tuple[str, int, int, int, int]]:
    eocd_idx = _find_eocd(mm)
    if eocd_idx < 0:
        raise ValueError("EOCD not found")

    cd_size = _U32_FROM(mm, eocd_idx + 12)[0]
    cd_off = _U32_FROM(mm, eocd_idx + 16)[0]
    cd_end = cd_off + cd_size
    entries: List[Tuple[str, int, int, int, int]] = []
    seen_names: set[bytes] = set()
    pos = cd_off

    # Fast path: DEX entries are root-level classes*.dex. Search the raw
    # central directory bytes for the filename prefix instead of walking every
    # entry in Python.
    while True:
        pos = mm.find(b"classes", pos, cd_end)
        if pos < 0:
            break
        header_off = pos - 46
        pos += 7
        if header_off < cd_off or mm[header_off:header_off + 4] != _CD_SIG:
            continue

        name_len = _U16_FROM(mm, header_off + 28)[0]
        name_end = pos - 7 + name_len
        if name_end > cd_end:
            continue

        name_bytes = mm[pos - 7:name_end]
        if (
            not name_bytes.endswith(_DEX_SUFFIX)
            or _SLASH in name_bytes
            or name_bytes in on_disk_names
            or name_bytes in seen_names
        ):
            continue

        comp_method = _U16_FROM(mm, header_off + 10)[0]
        comp_size = _U32_FROM(mm, header_off + 20)[0]
        uncomp_size = _U32_FROM(mm, header_off + 24)[0]
        local_header_off = _U32_FROM(mm, header_off + 42)[0]
        seen_names.add(name_bytes)
        entries.append((
            name_bytes.decode("utf-8", errors="ignore"),
            uncomp_size,
            comp_size,
            local_header_off,
            comp_method,
        ))

    if entries:
        return entries

    # Conservative fallback for unexpected APK layouts.
    ptr = cd_off
    while ptr + 46 <= cd_end:
        if mm[ptr:ptr + 4] != _CD_SIG:
            break

        comp_method = _U16_FROM(mm, ptr + 10)[0]
        comp_size = _U32_FROM(mm, ptr + 20)[0]
        uncomp_size = _U32_FROM(mm, ptr + 24)[0]
        name_len = _U16_FROM(mm, ptr + 28)[0]
        extra_len = _U16_FROM(mm, ptr + 30)[0]
        comment_len = _U16_FROM(mm, ptr + 32)[0]
        local_header_off = _U32_FROM(mm, ptr + 42)[0]

        name_start = ptr + 46
        name_end = name_start + name_len
        name_bytes = mm[name_start:name_end]
        if (
            name_bytes.endswith(_DEX_SUFFIX)
            and _SLASH not in name_bytes
            and name_bytes not in on_disk_names
        ):
            entries.append((
                name_bytes.decode("utf-8", errors="ignore"),
                uncomp_size,
                comp_size,
                local_header_off,
                comp_method,
            ))

        ptr = name_end + extra_len + comment_len

    return entries


def _inflate_deflate_chunks(comp_view: memoryview, stop_event: threading.Event) -> Optional[bytes]:
    decomp = zlib.decompressobj(-15)
    out = bytearray()
    pos = 0
    total = len(comp_view)
    while pos < total:
        if stop_event.is_set():
            return None
        end = min(pos + _DEFLATE_CHUNK, total)
        out.extend(decomp.decompress(comp_view[pos:end]))
        pos = end
    out.extend(decomp.flush())
    if stop_event.is_set():
        return None
    return bytes(out)


def _inflate_and_scan(
    mm: mmap.mmap,
    name: str,
    uncomp_size: int,
    comp_size: int,
    local_header_off: int,
    comp_method: int,
    target_bytes: bytes,
    stop_event: threading.Event,
    log,
):
    tid = threading.get_ident() & 0xFFFF
    if stop_event.is_set():
        log(f"  [T{tid:04x}] skip   '{name}' (stop_event set before inflate)")
        return False, None

    t0 = time.time()
    if mm[local_header_off:local_header_off + 4] != _LH_SIG:
        raise ValueError("bad local header signature")
    name_len = _U16_FROM(mm, local_header_off + 26)[0]
    extra_len = _U16_FROM(mm, local_header_off + 28)[0]
    data_off = local_header_off + 30 + name_len + extra_len
    t1 = time.time()

    comp_view = memoryview(mm)[data_off:data_off + comp_size]
    if comp_method == 0:
        data = bytes(comp_view)
    elif comp_method == 8:
        data = _inflate_deflate_chunks(comp_view, stop_event)
        if data is None:
            log(f"  [T{tid:04x}] skip   '{name}' (stop_event set during inflate)")
            return False, None
    else:
        raise ValueError(f"unsupported compression method: {comp_method}")
    t2 = time.time()

    if stop_event.is_set():
        log(f"  [T{tid:04x}] skip   '{name}' (stop_event set after inflate)")
        return False, None

    if uncomp_size and len(data) != uncomp_size:
        raise ValueError(f"size mismatch: expect {uncomp_size}, got {len(data)}")

    hit = _dex_defines_class(data, target_bytes)
    t3 = time.time()
    log(
        f"  [T{tid:04x}] inflate+scan '{name}' "
        f"lhdr={1000*(t1-t0):.1f}ms inflate={1000*(t2-t1):.1f}ms "
        f"lookup={1000*(t3-t2):.1f}ms hit={hit}"
    )
    return hit, data


def _scan_disk_dex(dex_path: str, target_bytes: bytes, stop_event: threading.Event, log) -> bool:
    tid = threading.get_ident() & 0xFFFF
    name = os.path.basename(dex_path)
    if stop_event.is_set():
        log(f"  [T{tid:04x}] skip   '{name}' (stop_event set before start)")
        return False
    t0 = time.time()
    with open(dex_path, "rb") as f:
        buf = bytearray(f.read())
    t1 = time.time()
    if stop_event.is_set():
        log(f"  [T{tid:04x}] skip   '{name}' (stop_event set after read)")
        return False
    hit = _dex_defines_class(buf, target_bytes)
    t2 = time.time()
    log(f"  [T{tid:04x}] disk   '{name}' read={1000*(t1-t0):.1f}ms lookup={1000*(t2-t1):.1f}ms hit={hit}")
    return hit


def _persist_hit_dex(hit_name: str, hit_bytes: bytes, dexes_dir: str, log) -> str:
    out_path = os.path.join(dexes_dir, hit_name)
    t_w0 = time.time()
    with open(out_path, "wb") as f:
        f.write(hit_bytes)
    t_w1 = time.time()
    log(f"extract hit '{hit_name}' -> '{out_path}' write={1000*(t_w1-t_w0):.1f}ms size={len(hit_bytes)}")
    return out_path


def find_and_extract(
    apk_path: str,
    clazz_name: str,
    paths: WorkspacePaths,
    already_extracted: Optional[List[str]] = None,
    max_workers: int = 8,
    verbose: bool = False,
    on_hit: Optional[Callable[[str], None]] = None,
) -> Optional[str]:
    """Locate the DEX containing the target class and extract *only* that DEX
    to disk. Uses concurrent in-memory scan with early exit.

    Returns the on-disk path of the hit DEX, or None.
    """
    clazz = ClassName(clazz_name)
    target = clazz.formatted
    target_bytes = target.encode("utf-8")
    task = TaskName(apk_path)
    task_name = task.name
    dexes_dir = paths.dexes_dir(task_name)
    ensure_dir(dexes_dir)

    t_start = time.time()
    def log(msg: str):
        if verbose:
            print(f"[SCHED +{1000*(time.time()-t_start):7.1f}ms] {msg}", flush=True)
    if not verbose:
        log = _noop_log

    mtid = threading.get_ident() & 0xFFFF
    log(f"start find_and_extract target='{target}' workers={max_workers} main=T{mtid:04x}")

    stop_event = threading.Event()
    already_extracted = already_extracted or []

    # Phase 1: scan already-extracted disk DEX files first
    on_disk = [p for p in already_extracted if os.path.isfile(p)]
    if on_disk:
        on_disk.sort(key=lambda p: os.path.getsize(p))
        log(f"phase1: scan {len(on_disk)} on-disk DEX(s): {[os.path.basename(p) for p in on_disk]}")
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for p in on_disk:
                fut = ex.submit(_scan_disk_dex, p, target_bytes, stop_event, log)
                futures[fut] = p
                log(f"  submit disk  '{os.path.basename(p)}' size={os.path.getsize(p)}")
            while futures:
                done, _pending = wait(list(futures.keys()), return_when=FIRST_COMPLETED)
                for fut in done:
                    p = futures.pop(fut)
                    try:
                        if fut.result():
                            log(f"HIT (phase1): '{os.path.basename(p)}' -> stop_event.set(), cancel remaining={len(futures)}")
                            stop_event.set()
                            for f2 in futures:
                                f2.cancel()
                            log(f"done in {1000*(time.time()-t_start):.1f}ms")
                            return p
                    except Exception as e:
                        log(f"  error on '{os.path.basename(p)}': {e}")
        log(f"phase1: no hit, falling through to phase2")

    # Phase 2: scan remaining DEX entries from the APK with mmap + raw zlib
    on_disk_names = {os.path.basename(p).encode("utf-8") for p in on_disk}
    t_zip0 = time.time()
    apk_fp = open(apk_path, "rb")
    t_zip1 = time.time()
    mm = mmap.mmap(apk_fp.fileno(), 0, access=mmap.ACCESS_READ)
    t_zip2 = time.time()
    entries = _parse_cd_dex_entries(mm, on_disk_names)
    t_zip3 = time.time()
    entries.sort(key=lambda x: x[2])
    t_zip4 = time.time()
    log(
        "phase2 zip-meta: "
        f"file_open={1000*(t_zip1-t_zip0):.1f}ms "
        f"mmap={1000*(t_zip2-t_zip1):.1f}ms "
        f"cd_parse={1000*(t_zip3-t_zip2):.1f}ms "
        f"sort={1000*(t_zip4-t_zip3):.1f}ms"
    )
    log(f"phase2: apk has {len(entries)} dex entries (skipped on-disk={len(on_disk_names)}), sorted by compressed size")

    if not entries:
        mm.close()
        apk_fp.close()
        log(f"phase2: nothing to scan, done in {1000*(time.time()-t_start):.1f}ms")
        return None

    hit_name: Optional[str] = None
    hit_bytes: Optional[bytes] = None
    hit_path: Optional[str] = None

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            inflight = {}   # future -> (name, uncomp_size, t_submit)
            idx = 0
            cap = min(len(entries), max(6, min(max_workers, 12)))
            log(f"phase2: loop begin, cap_inflight={cap}")

            while idx < len(entries) or inflight:
                while idx < len(entries) and len(inflight) < cap and not stop_event.is_set():
                    name, uncomp_size, comp_size, local_header_off, comp_method = entries[idx]
                    idx += 1
                    fut = ex.submit(
                        _inflate_and_scan,
                        mm,
                        name,
                        uncomp_size,
                        comp_size,
                        local_header_off,
                        comp_method,
                        target_bytes,
                        stop_event,
                        log,
                    )
                    t_submit = time.time()
                    inflight[fut] = (name, uncomp_size, t_submit)
                    log(
                        f"  submit '{name}' usize={uncomp_size} csize={comp_size} "
                        f"method={comp_method} inflight={len(inflight)}/{cap}"
                    )

                if not inflight:
                    break

                done, _pending = wait(list(inflight.keys()), return_when=FIRST_COMPLETED)
                log(f"  wait returned: done={len(done)} pending={len(_pending)}")
                for fut in done:
                    name, _usize, t_submit = inflight.pop(fut)
                    latency = 1000 * (time.time() - t_submit)
                    try:
                        ok, data = fut.result()
                        log(f"  result  '{name}' latency={latency:.1f}ms hit={ok}")
                        if ok:
                            hit_name = name
                            hit_bytes = data
                            stop_event.set()
                            hit_path = _persist_hit_dex(hit_name, hit_bytes, dexes_dir, log)
                            if on_hit is not None:
                                on_hit(hit_path)
                            break
                    except Exception as e:
                        log(f"  error  '{name}': {e}")

                if hit_name is not None:
                    cancelled = 0
                    for f2 in inflight:
                        if f2.cancel():
                            cancelled += 1
                    log(f"HIT (phase2): '{hit_name}' -> stop_event.set(), cancel {cancelled}/{len(inflight)} inflight")
                    break
    finally:
        mm.close()
        apk_fp.close()

    if hit_name is None:
        log(f"phase2: scanned all entries, no hit, done in {1000*(time.time()-t_start):.1f}ms")
        return None

    log(f"done in {1000*(time.time()-t_start):.1f}ms")
    return hit_path
