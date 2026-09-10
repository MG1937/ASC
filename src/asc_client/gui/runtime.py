import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

from src.asc_client.apk_handler import _findrefs_worker, _inflate_dex, _parse_cd_dex_entries
from src.asc_client.dex_container import iter_logical_dex_buffers
from src.asc_core.findrefs.findrefs_manager import FindRefManager
from src.asc_core.utils.tinydex import DEX


_MAX_UI_RESULTS = 5000
_GUI_MP_LOCK = threading.Lock()
_REF_SEARCH_TYPES = {
    "string refs": "string",
    "type refs": "type",
    "method refs": "method",
    "field refs": "field",
}


def _debug_log(enabled : bool, scope : str, msg : str):
    if not enabled:
        return
    tid = threading.get_ident() & 0xFFFF
    now = time.perf_counter()
    print(f"[GUI DEBUG] [{scope}] [T{tid:04x}] {now:.6f} {msg}")


def _multiprocessing_state() -> str:
    mp_mod = sys.modules.get("multiprocessing")
    red_mod = sys.modules.get("multiprocessing.reduction")
    return (
        f"multiprocessing={type(mp_mod).__name__}"
        f" reduction={type(red_mod).__name__}"
    )


def _snapshot_sys_modules():
    return dict(sys.modules)


def _restore_sys_modules(snapshot):
    for name in tuple(sys.modules.keys()):
        if name not in snapshot:
            sys.modules.pop(name, None)
    sys.modules.update(snapshot)


def format_class_name(name : str) -> str:
    if not name:
        raise ValueError("Class name cannot be empty")
    if name.startswith("L") and name.endswith(";") and "/" in name:
        return name
    name = name.replace(".", "/")
    if not name.startswith("L"):
        name = f"L{name}"
    if not name.endswith(";"):
        name = f"{name};"
    return name


def dalvik_to_dot(name : str) -> str:
    if name.startswith("L") and name.endswith(";"):
        return name[1:-1].replace("/", ".")
    return name


def _normalize_class_query(name : str, fuzzy : bool):
    if name is None or name == "":
        return None
    if fuzzy:
        if "." in name and "/" not in name:
            return name.replace(".", "/")
        return name
    return format_class_name(name)


def build_find_query(find_type : str, value : str, class_name = None, fuzzy_class : bool = False):
    find_type = _REF_SEARCH_TYPES.get(find_type, find_type)
    if find_type == "string":
        return "string", {"string": value}
    if find_type == "type":
        return "type", {"type": value}

    class_name = _normalize_class_query(class_name, fuzzy_class)
    if class_name is None and not value:
        raise ValueError(f"{find_type} query needs at least one of class or {find_type} name")

    if class_name is None:
        return find_type, {find_type: {"class": None, find_type: value or None}}
    return find_type, {find_type: {"class": [class_name, not fuzzy_class], find_type: value or None}}


def parse_result_line(line : str):
    dex_name, method_text, matched_text = line.split(" | ", 2)
    class_name = method_text.split("->", 1)[0]
    return {
        "dex_name": dex_name,
        "class_name": class_name,
        "class_display": dalvik_to_dot(class_name),
        "method_text": method_text,
        "matched_text": matched_text,
        "line": line,
    }


def is_member_search(find_type : str) -> bool:
    return find_type in ("method", "field")


class GuiDexStore:
    def __init__(self, apk_path : str, max_workers : int = 20, debug : bool = False, search_executor = None):
        self.apk_path = apk_path
        self.max_workers = max_workers
        self.debug = debug
        self.search_executor = search_executor

        self.entries = []
        self.dex_buffers = {}
        self.class_to_dex = {}
        self.class_names = []
        self.package_children = {}
        self.package_classes = {}
        self.findref_managers = {}
        self.source_cache = {}
        self._source_lock = threading.Lock()

    def _open_apk(self):
        import mmap

        fp = open(self.apk_path, "rb")
        mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
        return fp, mm

    def load(self, progress_callback = None):
        fp, mm = self._open_apk()
        try:
            entries = _parse_cd_dex_entries(mm)
            entries.sort(key=lambda x: x[2])
            self.entries = entries
            total = len(entries)
            _debug_log(self.debug, "runtime", f"load start apk={self.apk_path} dex={total}")
            if total == 0:
                self.class_names = []
                return

            def load_entry(entry):
                data = _inflate_dex(mm, entry)
                logical = []
                for dex_name, dex_buf in iter_logical_dex_buffers(entry[0], data):
                    dex = DEX.parse(memoryview(dex_buf), dex_name)
                    classes = []
                    for class_idx in range(len(dex.classes)):
                        classes.append(dex.classes[class_idx].fullname)
                    logical.append((dex_name, dex_buf, dex, classes))
                return entry, logical

            done = 0
            class_count = 0
            with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                futures = [ex.submit(load_entry, entry) for entry in entries]
                for fut in as_completed(futures):
                    entry, logical = fut.result()
                    for dex_name, dex_buf, dex, classes in logical:
                        self.dex_buffers[dex_name] = dex_buf
                        self.findref_managers[dex_name] = FindRefManager(dex, self.debug)
                        for class_name in classes:
                            self.class_to_dex.setdefault(class_name, dex_name)
                        class_count += len(classes)
                    done += 1
                    if progress_callback is not None:
                        progress_callback(done, total, entry[0], class_count)

            self.class_names = sorted(self.class_to_dex.keys())
            self._build_package_index()
            _debug_log(
                self.debug,
                "runtime",
                f"load done dex={len(self.entries)} classes={len(self.class_names)}",
            )
        finally:
            mm.close()
            fp.close()

    def _build_package_index(self):
        package_children = {"": set()}
        package_classes = {}

        for class_name in self.class_names:
            body = class_name[1:-1] if class_name.startswith("L") and class_name.endswith(";") else class_name
            parts = body.split("/")
            pkg_path = ""

            for part in parts[:-1]:
                next_path = f"{pkg_path}/{part}" if pkg_path else part
                package_children.setdefault(pkg_path, set()).add(next_path)
                package_children.setdefault(next_path, set())
                pkg_path = next_path

            package_classes.setdefault(pkg_path, []).append(class_name)

        self.package_children = {
            pkg: sorted(children, key=lambda item: item.lower())
            for pkg, children in package_children.items()
        }
        self.package_classes = {}
        for pkg_path, classes in package_classes.items():
            classes.sort(key=lambda item: item.split("/")[-1].rstrip(";").lower())
            self.package_classes[pkg_path] = classes

    def iter_root_packages(self):
        return self.package_children.get("", [])

    def iter_child_packages(self, pkg_path : str):
        return self.package_children.get(pkg_path, [])

    def iter_package_classes(self, pkg_path : str):
        return self.package_classes.get(pkg_path, [])

    def iter_filtered_classes(self, keyword : str, limit : int):
        keyword = (keyword or "").strip().lower()
        if not keyword:
            return []

        ret = []
        for class_name in self.class_names:
            if keyword not in dalvik_to_dot(class_name).lower():
                continue
            ret.append(class_name)
            if len(ret) >= limit:
                break
        return ret

    def get_source(self, dalvik_class : str):
        with self._source_lock:
            old = self.source_cache.get(dalvik_class)
            if old is not None:
                _debug_log(self.debug, "runtime", f"source cache hit class={dalvik_class}")
                return old

        dex_name = self.class_to_dex.get(dalvik_class)
        if dex_name is None:
            raise ValueError(f"class not indexed: {dalvik_class}")

        dex_buf = self.dex_buffers[dex_name]
        _debug_log(
            self.debug,
            "runtime",
            f"source start class={dalvik_class} dex={dex_name} {_multiprocessing_state()}",
        )
        from src.asc_client.asc_handler import AscHandler

        with _GUI_MP_LOCK:
            snapshot = _snapshot_sys_modules()
            try:
                source = AscHandler(self.debug).getclass(dex_buf, dalvik_class)
            finally:
                _restore_sys_modules(snapshot)
        ret = (dex_name, source)
        with self._source_lock:
            self.source_cache[dalvik_class] = ret
        _debug_log(
            self.debug,
            "runtime",
            f"source done class={dalvik_class} dex={dex_name} {_multiprocessing_state()}",
        )
        return ret

    def search_members(self, find_type : str, value : str, limit : int = _MAX_UI_RESULTS):
        keyword = (value or "").strip()
        dex_names = [entry[0] for entry in self.entries]

        def search_dex(dex_name):
            manager = self.findref_managers.get(dex_name)
            if manager is None:
                return 0, []
            dex = manager.dex
            dex_rows = []
            if find_type == "method":
                locator = manager._get_method_locator(True)
                member_idxs = locator.locate({"class": None, "method": keyword})
                for midx in sorted(member_idxs):
                    method = dex.methods[midx]
                    class_name = method.cls.fullname
                    method_text = f"{class_name}->{method.name}"
                    dex_rows.append({
                        "dex_name": dex_name,
                        "class_name": class_name,
                        "class_display": dalvik_to_dot(class_name),
                        "method_text": method_text,
                        "matched_text": f"method=({method.name})",
                        "line": method_text,
                    })
                return len(member_idxs), dex_rows

            locator = manager._get_field_locator(True)
            member_idxs = locator.locate({"class": None, "field": keyword})
            for fidx in sorted(member_idxs):
                field = dex.fields[fidx]
                class_name = field.cls.fullname
                method_text = f"{class_name}->{field.name}"
                dex_rows.append({
                    "dex_name": dex_name,
                    "class_name": class_name,
                    "class_display": dalvik_to_dot(class_name),
                    "method_text": method_text,
                    "matched_text": f"field=({field.name})",
                    "line": method_text,
                })
            return len(member_idxs), dex_rows

        rows = []
        total_hits = 0
        workers = self.get_effective_search_workers()
        if len(dex_names) <= 1 or workers <= 1:
            results = [search_dex(dex_name) for dex_name in dex_names]
        else:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = [ex.submit(search_dex, dex_name) for dex_name in dex_names]
                results = [fut.result() for fut in futures]

        for hit_count, dex_rows in results:
            total_hits += hit_count
            if len(rows) < limit:
                rows.extend(dex_rows[:limit - len(rows)])

        return {
            "find_type": find_type,
            "query_value": value,
            "results": rows,
            "total_hits": total_hits,
            "workers": workers,
            "backend": "locator",
        }

    def get_effective_search_workers(self, requested = None):
        cpu = os.cpu_count() or 4
        workers = requested if requested is not None else self.max_workers
        if workers is None or workers <= 0:
            workers = cpu
        if len(self.entries) > 1:
            workers = max(2, workers)
        return min(len(self.entries), workers)

    def _search_with_process_pool(self, executor, workers, find_type, find, progress_callback, result_callback = None):
        total = len(self.entries)
        hit_count = 0
        shown = []
        with _GUI_MP_LOCK:
            _debug_log(
                self.debug,
                "runtime",
                f"search process start dex={total} workers={workers} {_multiprocessing_state()} executor={id(executor)}",
            )

            futures = {}
            for entry in self.entries:
                try:
                    _debug_log(self.debug, "runtime", f"submit dex={entry[0]}")
                    fut = executor.submit(_findrefs_worker, self.apk_path, entry, find_type, find, False)
                except Exception as e:
                    _debug_log(
                        self.debug,
                        "runtime",
                        f"submit failed dex={entry[0]} err={type(e).__name__}: {e} {_multiprocessing_state()}",
                    )
                    traceback.print_exc()
                    raise
                futures[fut] = entry[0]

        done = 0
        for fut in as_completed(futures):
            dex_name = futures.pop(fut)
            try:
                dex_name, lines, _inflate_us, _process_us, _pid = fut.result()
            except Exception as e:
                _debug_log(
                    self.debug,
                    "runtime",
                    f"result failed dex={dex_name} err={type(e).__name__}: {e} {_multiprocessing_state()}",
                )
                traceback.print_exc()
                raise
            done += 1
            hit_count += len(lines)
            _debug_log(
                self.debug,
                "runtime",
                f"result ok dex={dex_name} pid={_pid} hits={len(lines)} done={done}/{total}",
            )
            batch_rows = []
            if len(shown) < _MAX_UI_RESULTS:
                remain = _MAX_UI_RESULTS - len(shown)
                for line in lines[:remain]:
                    row = parse_result_line(line)
                    shown.append(row)
                    batch_rows.append(row)
            if batch_rows and result_callback is not None:
                result_callback(batch_rows, done, total, hit_count)
            if progress_callback is not None:
                progress_callback(done, total, hit_count)

        return hit_count, shown

    def _launch_subprocess_worker(self, entry, find_type, find):
        result_file = tempfile.NamedTemporaryFile(prefix="asc_gui_find_", suffix=".json", delete=False)
        result_path = result_file.name
        result_file.close()

        payload = {
            "apk_path": self.apk_path,
            "entry": list(entry),
            "find_type": find_type,
            "find": find,
            "result_path": result_path,
        }

        cmd = [sys.executable, "-m", "src.asc_client.gui.search_worker"]
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        proc = subprocess.Popen(
            cmd,
            cwd=os.getcwd(),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creationflags,
        )
        proc.stdin.write(json.dumps(payload))
        proc.stdin.close()
        return proc, result_path

    def _search_with_subprocess_pool(self, workers, find_type, find, progress_callback, result_callback = None):
        total = len(self.entries)
        hit_count = 0
        shown = []
        done = 0
        idx = 0
        running = []

        while idx < len(self.entries) or running:
            while idx < len(self.entries) and len(running) < workers:
                entry = self.entries[idx]
                idx += 1
                proc, result_path = self._launch_subprocess_worker(entry, find_type, find)
                running.append((proc, result_path, entry[0]))

            if not running:
                break

            # time.sleep(0.01)
            next_running = []
            for proc, result_path, dex_name in running:
                if proc.poll() is None:
                    next_running.append((proc, result_path, dex_name))
                    continue

                stderr_text = proc.stderr.read() if proc.stderr is not None else ""
                if proc.returncode != 0:
                    try:
                        os.unlink(result_path)
                    except OSError:
                        pass
                    raise RuntimeError(
                        f"Search worker failed for {dex_name}: {stderr_text.strip() or proc.returncode}"
                    )

                with open(result_path, "r", encoding="utf-8") as fp:
                    payload = json.load(fp)
                try:
                    os.unlink(result_path)
                except OSError:
                    pass

                lines = payload["lines"]
                done += 1
                hit_count += len(lines)
                batch_rows = []
                if len(shown) < _MAX_UI_RESULTS:
                    remain = _MAX_UI_RESULTS - len(shown)
                    for line in lines[:remain]:
                        row = parse_result_line(line)
                        shown.append(row)
                        batch_rows.append(row)
                if batch_rows and result_callback is not None:
                    result_callback(batch_rows, done, total, hit_count)
                if progress_callback is not None:
                    progress_callback(done, total, hit_count)

            running = next_running

        return hit_count, shown

    def search(
        self,
        find_type : str,
        value : str,
        class_name = None,
        fuzzy_class : bool = False,
        max_workers = None,
        progress_callback = None,
        result_callback = None,
    ):
        find_type, find = build_find_query(find_type, value, class_name, fuzzy_class)
        workers = self.get_effective_search_workers(max_workers)
        _debug_log(
            self.debug,
            "runtime",
            f"search request type={find_type} value={value!r} class={class_name!r} fuzzy={fuzzy_class} workers={workers}",
        )
        if self.search_executor is not None:
            backend = "process"
            hit_count, shown = self._search_with_process_pool(
                self.search_executor,
                workers,
                find_type,
                find,
                progress_callback,
                result_callback,
            )
        else:
            backend = "subprocess"
            hit_count, shown = self._search_with_subprocess_pool(
                workers,
                find_type,
                find,
                progress_callback,
                result_callback,
            )

        return {
            "find_type": find_type,
            "query_value": value,
            "results": shown,
            "total_hits": hit_count,
            # "truncated": hit_count > len(shown),
            "workers": workers,
            "backend": backend,
        }
