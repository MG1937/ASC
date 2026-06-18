import atexit
import mmap
import os
import struct
import threading
import time
import zlib
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, FIRST_COMPLETED, wait


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

_WORKER_APK_PATH = None
_WORKER_APK_FP = None
_WORKER_APK_MM = None


def _skip_uleb128(buf, off : int) -> int:
    while buf[off] & 0x80:
        off += 1
    return off + 1


def _read_string_data_bytes(buf, str_off : int) -> bytes:
    ptr = _skip_uleb128(buf, str_off)
    end = buf.find(b"\x00", ptr)
    if end < 0:
        raise ValueError("unterminated string_data_item")
    return buf[ptr:end]


def _find_type_idx(buf, target_bytes : bytes) -> int:
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
        str_idx = _U32_FROM(buf, type_ids_off + (mid << 2))[0]
        if str_idx >= string_ids_size:
            raise ValueError("bad type_id->string_idx")
        str_off = _U32_FROM(buf, string_ids_off + (str_idx << 2))[0]
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


def _class_defs_contains_type_idx(buf, type_idx : int) -> bool:
    class_defs_size = _U32_FROM(buf, 0x60)[0]
    class_defs_off = _U32_FROM(buf, 0x64)[0]

    if class_defs_size == 0:
        return False

    class_defs_end = class_defs_off + (class_defs_size << 5)
    if class_defs_end > len(buf):
        raise ValueError("bad class_defs range")

    needle = type_idx.to_bytes(4, "little")
    pos = buf.find(needle, class_defs_off, class_defs_end)
    while pos != -1:
        if ((pos - class_defs_off) & 0x1F) == 0:
            return True
        pos = buf.find(needle, pos + 1, class_defs_end)
    return False


def _dex_defines_class(buf, target_bytes : bytes) -> bool:
    type_idx = _find_type_idx(buf, target_bytes)
    if type_idx < 0:
        return False
    return _class_defs_contains_type_idx(buf, type_idx)


def _find_eocd(mm : mmap.mmap) -> int:
    search_start = max(0, len(mm) - 65536 - 22)
    return mm.rfind(_EOCD_SIG, search_start)


def _parse_cd_dex_entries(mm : mmap.mmap):
    eocd_idx = _find_eocd(mm)
    if eocd_idx < 0:
        raise ValueError("EOCD not found")

    cd_size = _U32_FROM(mm, eocd_idx + 12)[0]
    cd_off = _U32_FROM(mm, eocd_idx + 16)[0]
    cd_end = cd_off + cd_size
    entries = []
    seen_names = set()
    pos = cd_off

    while True:
        pos = mm.find(b"classes", pos, cd_end)
        if pos < 0:
            break
        header_off = pos - 46
        pos += 7
        if header_off < cd_off or mm[header_off:header_off + 4] != _CD_SIG:
            continue

        name_len = _U16_FROM(mm, header_off + 28)[0]
        name_start = pos - 7
        name_end = name_start + name_len
        if name_end > cd_end:
            continue

        name_bytes = mm[name_start:name_end]
        if (
            not name_bytes.endswith(_DEX_SUFFIX)
            or _SLASH in name_bytes
            or name_bytes in seen_names
        ):
            continue

        seen_names.add(name_bytes)
        entries.append((
            name_bytes.decode("utf-8", errors="ignore"),
            _U32_FROM(mm, header_off + 24)[0],
            _U32_FROM(mm, header_off + 20)[0],
            _U32_FROM(mm, header_off + 42)[0],
            _U16_FROM(mm, header_off + 10)[0],
        ))

    if entries:
        return entries

    ptr = cd_off
    while ptr + 46 <= cd_end:
        if mm[ptr:ptr + 4] != _CD_SIG:
            break

        name_len = _U16_FROM(mm, ptr + 28)[0]
        extra_len = _U16_FROM(mm, ptr + 30)[0]
        comment_len = _U16_FROM(mm, ptr + 32)[0]
        name_start = ptr + 46
        name_end = name_start + name_len
        name_bytes = mm[name_start:name_end]
        if name_bytes.endswith(_DEX_SUFFIX) and _SLASH not in name_bytes:
            entries.append((
                name_bytes.decode("utf-8", errors="ignore"),
                _U32_FROM(mm, ptr + 24)[0],
                _U32_FROM(mm, ptr + 20)[0],
                _U32_FROM(mm, ptr + 42)[0],
                _U16_FROM(mm, ptr + 10)[0],
            ))

        ptr = name_end + extra_len + comment_len

    return entries


def _close_worker_apk():
    global _WORKER_APK_PATH, _WORKER_APK_FP, _WORKER_APK_MM

    mm = _WORKER_APK_MM
    fp = _WORKER_APK_FP
    _WORKER_APK_MM = None
    _WORKER_APK_FP = None
    _WORKER_APK_PATH = None

    if mm is not None:
        mm.close()
    if fp is not None:
        fp.close()


atexit.register(_close_worker_apk)


def _get_worker_apk_mm(apk_path : str):
    global _WORKER_APK_PATH, _WORKER_APK_FP, _WORKER_APK_MM

    mm = _WORKER_APK_MM
    if mm is not None and _WORKER_APK_PATH == apk_path:
        return mm

    _close_worker_apk()
    fp = open(apk_path, "rb")
    mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    _WORKER_APK_PATH = apk_path
    _WORKER_APK_FP = fp
    _WORKER_APK_MM = mm
    return mm


def _inflate_deflate_chunks(comp_view, stop_event):
    decomp = zlib.decompressobj(-15)
    out = bytearray()
    pos = 0
    total = len(comp_view)
    while pos < total:
        if stop_event is not None and stop_event.is_set():
            return None
        end = min(pos + _DEFLATE_CHUNK, total)
        out.extend(decomp.decompress(comp_view[pos:end]))
        pos = end
    out.extend(decomp.flush())
    if stop_event is not None and stop_event.is_set():
        return None
    return bytes(out)


def _inflate_dex(mm : mmap.mmap, entry, stop_event = None):
    name, uncomp_size, comp_size, local_header_off, comp_method = entry
    if mm[local_header_off:local_header_off + 4] != _LH_SIG:
        raise ValueError("bad local header signature")

    name_len = _U16_FROM(mm, local_header_off + 26)[0]
    extra_len = _U16_FROM(mm, local_header_off + 28)[0]
    data_off = local_header_off + 30 + name_len + extra_len
    comp_view = memoryview(mm)[data_off:data_off + comp_size]

    if comp_method == 0:
        data = bytes(comp_view)
    elif comp_method == 8:
        data = _inflate_deflate_chunks(comp_view, stop_event)
        if data is None:
            return None
    else:
        raise ValueError(f"unsupported compression method: {comp_method}")

    if uncomp_size and len(data) != uncomp_size:
        raise ValueError(f"size mismatch: expect {uncomp_size}, got {len(data)}")
    return data


def _findrefs_worker(apk_path : str, entry, find_type : str, find : dict):
    from src.asc_client.asc_handler import AscHandler

    mm = _get_worker_apk_mm(apk_path)
    t0 = time.perf_counter()
    data = _inflate_dex(mm, entry)
    t1 = time.perf_counter()
    lines = AscHandler(False).findrefs(entry[0], data, find_type, find)
    t2 = time.perf_counter()
    return (
        entry[0],
        lines,
        (t1 - t0) * 1000000,
        (t2 - t1) * 1000000,
        os.getpid(),
    )


def _inflate_and_hit(mm : mmap.mmap, entry, target_bytes : bytes, stop_event : threading.Event, log):
    tid = threading.get_ident() & 0xFFFF
    name = entry[0]
    if stop_event.is_set():
        return False, None

    t0 = time.perf_counter()
    data = _inflate_dex(mm, entry, stop_event)
    if data is None:
        return False, None
    t1 = time.perf_counter()
    if stop_event.is_set():
        return False, None

    hit = _dex_defines_class(data, target_bytes)
    t2 = time.perf_counter()
    if hit:
        stop_event.set()
    log(
        f"[APK] [T{tid:04x}] '{name}' inflate={(t1 - t0) * 1000000:.2f} us "
        f"lookup={(t2 - t1) * 1000000:.2f} us hit={hit}"
    )
    return hit, data


def _inflate_and_process(mm : mmap.mmap, entry, stop_event : threading.Event, processor, log):
    tid = threading.get_ident() & 0xFFFF
    name = entry[0]
    t0 = time.perf_counter()
    data = _inflate_dex(mm, entry, stop_event)
    t1 = time.perf_counter()
    ret = processor(name, data)
    t2 = time.perf_counter()
    log(
        f"[APK] [T{tid:04x}] '{name}' inflate={(t1 - t0) * 1000000:.2f} us "
        f"process={(t2 - t1) * 1000000:.2f} us"
    )
    return name, ret


class ApkHandler:
    def __init__(self, apk_path : str, debug : bool = False, max_workers : int = 8):
        self.apk_path = apk_path
        self.debug = debug
        self.max_workers = max_workers

    def _log(self, msg : str):
        if self.debug:
            print(msg)

    def _open_apk(self):
        fp = open(self.apk_path, "rb")
        mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        return fp, mm

    def get_class_dex(self, dalvik_class : str):
        target_bytes = dalvik_class.encode("utf-8")
        t_start = time.perf_counter()
        fp, mm = self._open_apk()
        try:
            entries = _parse_cd_dex_entries(mm)
            entries.sort(key=lambda x: x[2])
            if self.debug:
                t_ready = time.perf_counter()
                self._log(f"[APK] scan setup={(t_ready - t_start) * 1000000:.2f} us entries={len(entries)}")
            if not entries:
                return None

            stop_event = threading.Event()
            hit_name = None
            hit_data = None
            cap = min(len(entries), max(6, min(self.max_workers, 12)))

            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                inflight = {}
                idx = 0
                while idx < len(entries) or inflight:
                    while idx < len(entries) and len(inflight) < cap and not stop_event.is_set():
                        entry = entries[idx]
                        idx += 1
                        fut = ex.submit(_inflate_and_hit, mm, entry, target_bytes, stop_event, self._log)
                        inflight[fut] = entry

                    if not inflight:
                        break

                    done, _pending = wait(list(inflight.keys()), return_when=FIRST_COMPLETED)
                    for fut in done:
                        entry = inflight.pop(fut)
                        ok, data = fut.result()
                        if ok:
                            hit_name = entry[0]
                            hit_data = data
                            stop_event.set()
                            break

                    if hit_name is not None:
                        for fut in inflight:
                            fut.cancel()
                        break

            if self.debug:
                t_end = time.perf_counter()
                self._log(f"[APK] getclass total={(t_end - t_start) * 1000000:.2f} us")
            if hit_name is None:
                return None
            return hit_name, hit_data
        finally:
            mm.close()
            fp.close()

    def for_each_dex(self, processor):
        t_start = time.perf_counter()
        fp, mm = self._open_apk()
        try:
            entries = _parse_cd_dex_entries(mm)
            entries.sort(key=lambda x: x[2])
            stop_event = threading.Event()
            cap = min(len(entries), max(1, self.max_workers))
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = {}
                idx = 0
                while idx < len(entries) or futures:
                    while idx < len(entries) and len(futures) < cap:
                        entry = entries[idx]
                        idx += 1
                        fut = ex.submit(_inflate_and_process, mm, entry, stop_event, processor, self._log)
                        futures[fut] = entry[0]
                    if not futures:
                        break

                    done, _pending = wait(list(futures.keys()), return_when=FIRST_COMPLETED)
                    for fut in done:
                        futures.pop(fut)
                        yield fut.result()
            if self.debug:
                t_end = time.perf_counter()
                self._log(
                    f"[APK] for_each_dex total={(t_end - t_start) * 1000000:.2f} us "
                    f"count={len(entries)} inflight={cap}"
                )
        finally:
            mm.close()
            fp.close()

    def for_each_findrefs(self, find_type : str, find : dict):
        t_start = time.perf_counter()
        fp, mm = self._open_apk()
        try:
            entries = _parse_cd_dex_entries(mm)
            entries.sort(key=lambda x: x[2])
        finally:
            mm.close()
            fp.close()

        if not entries:
            return

        with ProcessPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {}
            for entry in entries:
                fut = ex.submit(_findrefs_worker, self.apk_path, entry, find_type, find)
                futures[fut] = entry[0]

            while futures:
                done, _pending = wait(list(futures.keys()), return_when=FIRST_COMPLETED)
                for fut in done:
                    futures.pop(fut)
                    dex_name, lines, inflate_us, process_us, pid = fut.result()
                    if self.debug:
                        self._log(
                            f"[APK] [P{pid}] '{dex_name}' inflate={inflate_us:.2f} us "
                            f"process={process_us:.2f} us"
                        )
                    yield dex_name, lines

        if self.debug:
            t_end = time.perf_counter()
            self._log(
                f"[APK] for_each_findrefs total={(t_end - t_start) * 1000000:.2f} us "
                f"count={len(entries)} workers={self.max_workers}"
            )
