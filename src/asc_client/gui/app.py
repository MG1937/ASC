import os
import queue
import threading
import time
import traceback
import tkinter as tk
from tkinter import ttk

from src.asc_client.gui.runtime import GuiDexStore, dalvik_to_dot


_MAX_FILTER_CLASSES = 5000
_JAVA_KEYWORDS = {
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
    "const", "continue", "default", "do", "double", "else", "enum", "extends", "final",
    "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
    "interface", "long", "native", "new", "package", "private", "protected", "public",
    "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
    "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false",
    "null",
}


def _debug_log(enabled : bool, scope : str, msg : str):
    if not enabled:
        return
    tid = threading.get_ident() & 0xFFFF
    now = time.perf_counter()
    print(f"[GUI DEBUG] [{scope}] [T{tid:04x}] {now:.6f} {msg}")


def _pkg_label(pkg_path : str):
    if not pkg_path:
        return "(root)"
    return pkg_path.rsplit("/", 1)[-1]


def _class_label(dalvik_class : str):
    return dalvik_class.split("/")[-1].rstrip(";")


class SearchDialog:
    def __init__(self, app, find_type : str, value : str, class_name, fuzzy_class : bool):
        self.app = app
        self.find_type = find_type
        self.value = value
        self.class_name = class_name
        self.fuzzy_class = fuzzy_class
        self.rows = []

        self.win = tk.Toplevel(app.root)
        self.win.title("Search")
        self.win.geometry("1280x760")
        self.win.transient(app.root)

        self.status_var = tk.StringVar(value="Searching...")
        self.progress_var = tk.IntVar(value=0)

        self._build_ui()

    def _build_ui(self):
        self.win.columnconfigure(0, weight=1)
        self.win.rowconfigure(1, weight=1)

        top = ttk.Frame(self.win, padding=8)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(0, weight=1)

        ttk.Label(top, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(top, mode="determinate", variable=self.progress_var, maximum=100)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(8, 0))

        body = ttk.Frame(self.win, padding=(8, 0, 8, 8))
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            body,
            columns=("dex", "class", "method", "matched"),
            show="headings",
        )
        self.tree.heading("dex", text="DEX")
        self.tree.heading("class", text="Class")
        self.tree.heading("method", text="Method")
        self.tree.heading("matched", text="Matched")
        self.tree.column("dex", width=120, stretch=False)
        self.tree.column("class", width=320, stretch=False)
        self.tree.column("method", width=260, stretch=False)
        self.tree.column("matched", width=560, stretch=True)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Double-Button-1>", self._open_selected)

        ybar = ttk.Scrollbar(body, orient=tk.VERTICAL, command=self.tree.yview)
        ybar.grid(row=0, column=1, sticky="ns")
        xbar = ttk.Scrollbar(body, orient=tk.HORIZONTAL, command=self.tree.xview)
        xbar.grid(row=1, column=0, sticky="ew")
        self.tree.config(yscrollcommand=ybar.set, xscrollcommand=xbar.set)

    def update_progress(self, done : int, total : int, hit_count : int):
        percent = int((done / total) * 100) if total else 0
        self.progress_var.set(percent)
        self.status_var.set(f"Searching {done}/{total} dex, hits={hit_count}")

    def finish(self, payload):
        if not self.rows and payload["results"]:
            self.append_results(payload["results"])
        msg = f"Done. hits={payload['total_hits']} workers={payload['workers']} backend={payload['backend']}"
        # if payload["truncated"]:
            # msg += f" showing first {len(payload['results'])}"
        self.status_var.set(msg)
        self.progress_var.set(100)

    def append_results(self, rows):
        if not rows:
            return
        start_idx = len(self.rows)
        self.rows.extend(rows)
        for offset, row in enumerate(rows):
            method_name = row["method_text"].split("->", 1)[1]
            self.tree.insert(
                "",
                tk.END,
                iid=str(start_idx + offset),
                values=(row["dex_name"], row["class_display"], method_name, row["matched_text"]),
            )

    def fail(self, message : str):
        self.status_var.set(message)

    def _open_selected(self, _event = None):
        selection = self.tree.selection()
        if not selection:
            return
        row = self.rows[int(selection[0])]
        self.app.open_class(row["class_name"])


class AscGuiApp:
    def __init__(self, root, apk_path : str, max_workers : int = 8, debug : bool = False, search_executor = None):
        self.root = root
        self.apk_path = apk_path
        self.max_workers = max_workers
        self.debug = debug
        self.search_executor = search_executor

        self.store = None
        self.events = queue.Queue()
        self.search_dialog = None
        self.search_inflight = False

        self.class_filter_var = tk.StringVar()
        self.class_info_var = tk.StringVar(value="Classes")
        self.status_var = tk.StringVar(value="Loading APK...")
        self.search_type_var = tk.StringVar(value="string")
        self.search_value_var = tk.StringVar()
        self.search_class_var = tk.StringVar()
        self.fuzzy_class_var = tk.BooleanVar(value=False)
        self.editor_find_var = tk.StringVar()
        self.editor_find_status_var = tk.StringVar(value="")
        self._highlight_generation = 0
        self._highlight_apply_batch = 400
        self._highlight_apply_job = None

        self._build_ui()
        self._bind_editor_shortcuts()
        self._set_controls_enabled(False)
        self._start_load()
        self.root.after(50, self._drain_events)
        _debug_log(
            self.debug,
            "app",
            f"init apk={self.apk_path} workers={self.max_workers} executor={id(self.search_executor)}",
        )

    def _ensure_search_executor(self):
        if self.search_executor is not None:
            return self.search_executor
        from concurrent.futures import ProcessPoolExecutor

        self.search_executor = ProcessPoolExecutor(max_workers=self.max_workers)
        if self.store is not None:
            self.store.search_executor = self.search_executor
        _debug_log(self.debug, "app", f"create search executor workers={self.max_workers}")
        return self.search_executor

    def _dispose_search_executor(self):
        executor = self.search_executor
        self.search_executor = None
        if self.store is not None:
            self.store.search_executor = None
        if executor is None:
            return
        _debug_log(self.debug, "app", "dispose search executor")
        executor.shutdown(wait=False, cancel_futures=False)

    def _build_ui(self):
        self.root.title(f"ASC GUI Auth: MG1937 - {os.path.basename(self.apk_path)}")
        self.root.geometry("1500x920")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)

        top = ttk.Frame(self.root, padding=8)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="APK").grid(row=0, column=0, sticky="w")
        ttk.Label(top, text=self.apk_path).grid(row=0, column=1, sticky="ew", padx=(8, 0))
        ttk.Label(top, textvariable=self.status_var).grid(row=0, column=2, sticky="e", padx=(12, 0))

        body = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        body.grid(row=1, column=0, sticky="nsew")

        left = ttk.Frame(body, padding=8)
        right = ttk.Frame(body, padding=8)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        body.add(left, weight=1)
        body.add(right, weight=4)

        left_top = ttk.Frame(left)
        left_top.grid(row=0, column=0, sticky="ew")
        left_top.columnconfigure(1, weight=1)
        ttk.Label(left_top, textvariable=self.class_info_var).grid(row=0, column=0, sticky="w")
        self.class_filter_entry = ttk.Entry(left_top, textvariable=self.class_filter_var)
        self.class_filter_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        self.class_filter_entry.bind("<KeyRelease>", self._on_class_filter_changed)

        class_frame = ttk.Frame(left)
        class_frame.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        class_frame.columnconfigure(0, weight=1)
        class_frame.rowconfigure(0, weight=1)

        self.class_tree = ttk.Treeview(class_frame, show="tree")
        self.class_tree.grid(row=0, column=0, sticky="nsew")
        self.class_tree.bind("<<TreeviewOpen>>", self._on_tree_open)
        self.class_tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        class_scroll = ttk.Scrollbar(class_frame, orient=tk.VERTICAL, command=self.class_tree.yview)
        class_scroll.grid(row=0, column=1, sticky="ns")
        self.class_tree.config(yscrollcommand=class_scroll.set)

        controls = ttk.Frame(right)
        controls.grid(row=0, column=0, sticky="ew")
        for idx in range(7):
            controls.columnconfigure(idx, weight=0)
        controls.columnconfigure(2, weight=1)

        ttk.Label(controls, text="Search").grid(row=0, column=0, sticky="w")
        self.search_type_box = ttk.Combobox(
            controls,
            textvariable=self.search_type_var,
            values=("string", "type", "method", "field"),
            state="readonly",
            width=10,
        )
        self.search_type_box.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.search_type_box.bind("<<ComboboxSelected>>", self._on_search_type_changed)

        self.search_value_entry = ttk.Entry(controls, textvariable=self.search_value_var)
        self.search_value_entry.grid(row=0, column=2, sticky="ew", padx=(8, 0))

        ttk.Label(controls, text="Class").grid(row=0, column=3, sticky="w", padx=(8, 0))
        self.search_class_entry = ttk.Entry(controls, textvariable=self.search_class_var, width=30)
        self.search_class_entry.grid(row=0, column=4, sticky="w", padx=(4, 0))

        self.fuzzy_class_check = ttk.Checkbutton(controls, text="Fuzzy class", variable=self.fuzzy_class_var)
        self.fuzzy_class_check.grid(row=0, column=5, sticky="w", padx=(8, 0))

        self.search_button = ttk.Button(controls, text="Search", command=self._start_search)
        self.search_button.grid(row=0, column=6, sticky="e", padx=(8, 0))

        source_frame = ttk.Frame(right)
        source_frame.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        source_frame.columnconfigure(0, weight=1)
        source_frame.rowconfigure(1, weight=1)

        self.editor_find_frame = ttk.Frame(source_frame)
        self.editor_find_frame.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.editor_find_frame.columnconfigure(1, weight=1)
        ttk.Label(self.editor_find_frame, text="Find").grid(row=0, column=0, sticky="w")
        self.editor_find_entry = ttk.Entry(self.editor_find_frame, textvariable=self.editor_find_var)
        self.editor_find_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        self.editor_find_entry.bind("<Return>", self._on_editor_find_next)
        self.editor_find_entry.bind("<Shift-Return>", self._on_editor_find_prev)
        self.editor_find_entry.bind("<Escape>", self._hide_editor_find)
        self.editor_find_entry.bind("<KeyRelease>", self._on_editor_find_changed)
        ttk.Button(self.editor_find_frame, text="Next", command=self._editor_find_next).grid(
            row=0, column=2, sticky="e"
        )
        ttk.Button(self.editor_find_frame, text="Prev", command=self._editor_find_prev).grid(
            row=0, column=3, sticky="e", padx=(6, 0)
        )
        ttk.Button(self.editor_find_frame, text="Close", command=self._hide_editor_find).grid(
            row=0, column=4, sticky="e", padx=(6, 0)
        )
        ttk.Label(self.editor_find_frame, textvariable=self.editor_find_status_var).grid(
            row=0, column=5, sticky="e", padx=(12, 0)
        )

        self.source_text = tk.Text(source_frame, wrap="none", background="#ffffff", foreground="#1f1f1f")
        self.source_text.grid(row=1, column=0, sticky="nsew")
        src_y = ttk.Scrollbar(source_frame, orient=tk.VERTICAL, command=self.source_text.yview)
        src_y.grid(row=1, column=1, sticky="ns")
        src_x = ttk.Scrollbar(source_frame, orient=tk.HORIZONTAL, command=self.source_text.xview)
        src_x.grid(row=2, column=0, sticky="ew")
        self.source_text.config(yscrollcommand=src_y.set, xscrollcommand=src_x.set)
        self.source_text.tag_configure("java_keyword", foreground="#0000cc")
        self.source_text.tag_configure("java_comment", foreground="#008000")
        self.source_text.tag_configure("java_string", foreground="#a31515")
        self.source_text.tag_configure("java_annotation", foreground="#2b91af")
        self.source_text.tag_configure("find_match", background="#fff2a8", foreground="#1f1f1f")
        self.source_text.tag_configure("find_current", background="#ffc94d", foreground="#1f1f1f")
        self.editor_find_frame.grid_remove()
        self._on_search_type_changed()

    def _bind_editor_shortcuts(self):
        self.root.bind("<Control-f>", self._show_editor_find)
        self.root.bind("<Control-F>", self._show_editor_find)
        self.source_text.bind("<Escape>", self._hide_editor_find)

    def _set_controls_enabled(self, enabled : bool):
        state = tk.NORMAL if enabled else tk.DISABLED
        self.class_tree.config(selectmode="browse")
        self.search_button.config(state=state)
        self.search_value_entry.config(state=state)
        self.search_type_box.config(state="readonly" if enabled else tk.DISABLED)
        self.search_class_entry.config(state=state)
        self.fuzzy_class_check.config(state=state)
        self.class_filter_entry.config(state=state)

    def _drain_events(self):
        while True:
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            self._handle_event(event)
        self.root.after(50, self._drain_events)

    def _handle_event(self, event):
        kind = event[0]
        if kind == "load_progress":
            _kind, done, total, dex_name, class_count = event
            self.status_var.set(f"Indexing {done}/{total} dex, classes={class_count}, last={dex_name}")
            return
        if kind == "load_done":
            self.store = event[1]
            self._set_controls_enabled(True)
            self._refresh_class_tree()
            self.status_var.set(f"Ready. dex={len(self.store.entries)} classes={len(self.store.class_names)}")
            return
        if kind == "load_error":
            self.status_var.set(event[1])
            return
        if kind == "source_done":
            _kind, dalvik_class, dex_name, source = event
            self.source_text.delete("1.0", tk.END)
            self.source_text.insert("1.0", source)
            self._start_async_highlight(source)
            self._refresh_editor_find_marks(reset_cursor=True)
            self.status_var.set(f"Opened {dalvik_to_dot(dalvik_class)} from {dex_name}")
            return
        if kind == "highlight_ready":
            _kind, generation, spans = event
            self._apply_highlight_spans_async(generation, spans)
            return
        if kind == "source_error":
            self.status_var.set(event[1])
            return
        if kind == "search_progress" and self.search_dialog is not None:
            _kind, done, total, hit_count = event
            self.search_dialog.update_progress(done, total, hit_count)
            self.status_var.set(f"Searching {done}/{total} dex, hits={hit_count}")
            return
        if kind == "search_batch" and self.search_dialog is not None:
            _kind, rows, done, total, hit_count = event
            self.search_dialog.append_results(rows)
            self.search_dialog.update_progress(done, total, hit_count)
            self.status_var.set(f"Searching {done}/{total} dex, hits={hit_count}")
            return
        if kind == "search_done" and self.search_dialog is not None:
            payload = event[1]
            self.search_inflight = False
            self.search_button.config(state=tk.NORMAL)
            self.search_dialog.finish(payload)
            self.status_var.set(
                f"Search done. hits={payload['total_hits']} workers={payload['workers']} backend={payload['backend']}"
            )
            return
        if kind == "search_error" and self.search_dialog is not None:
            self.search_inflight = False
            self.search_button.config(state=tk.NORMAL)
            self.search_dialog.fail(event[1])
            self.status_var.set(event[1])

    def _start_load(self):
        def worker():
            try:
                _debug_log(self.debug, "app", "load worker start")
                store = GuiDexStore(
                    self.apk_path,
                    self.max_workers,
                    self.debug,
                    search_executor=self.search_executor,
                )
                store.load(
                    lambda done, total, dex_name, class_count: self.events.put(
                        ("load_progress", done, total, dex_name, class_count)
                    )
                )
                self.events.put(("load_done", store))
                _debug_log(self.debug, "app", "load worker done")
            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                self.events.put(("load_error", f"Load failed: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _reset_tree(self):
        self.class_tree.delete(*self.class_tree.get_children())

    def _insert_package_node(self, parent_id : str, pkg_path : str):
        item_id = f"pkg:{pkg_path}"
        if self.class_tree.exists(item_id):
            return item_id
        self.class_tree.insert(parent_id, tk.END, iid=item_id, text=_pkg_label(pkg_path), values=("pkg",))
        self.class_tree.insert(item_id, tk.END, iid=f"{item_id}:stub", text="...")
        return item_id

    def _populate_package_children(self, pkg_path : str):
        item_id = f"pkg:{pkg_path}"
        if not self.class_tree.exists(item_id):
            return
        children = self.class_tree.get_children(item_id)
        if len(children) == 1 and children[0] == f"{item_id}:stub":
            self.class_tree.delete(children[0])
        elif children:
            return

        for child_pkg in self.store.iter_child_packages(pkg_path):
            self._insert_package_node(item_id, child_pkg)
        for dalvik_class in self.store.iter_package_classes(pkg_path):
            class_id = f"cls:{dalvik_class}"
            self.class_tree.insert(item_id, tk.END, iid=class_id, text=_class_label(dalvik_class), values=("class",))

    def _refresh_class_tree(self):
        if self.store is None:
            return
        keyword = self.class_filter_var.get().strip()
        self._reset_tree()
        if keyword:
            matches = self.store.iter_filtered_classes(keyword, _MAX_FILTER_CLASSES)
            for dalvik_class in matches:
                self.class_tree.insert("", tk.END, iid=f"cls:{dalvik_class}", text=dalvik_to_dot(dalvik_class))
            total_text = f"Classes ({len(matches)} filtered)"
            if len(matches) >= _MAX_FILTER_CLASSES:
                total_text = f"Classes ({_MAX_FILTER_CLASSES}+ filtered)"
            self.class_info_var.set(total_text)
            return

        for pkg_path in self.store.iter_root_packages():
            self._insert_package_node("", pkg_path)
        for dalvik_class in self.store.iter_package_classes(""):
            self.class_tree.insert("", tk.END, iid=f"cls:{dalvik_class}", text=_class_label(dalvik_class))
        self.class_info_var.set(f"Packages / Classes ({len(self.store.class_names)})")

    def _on_class_filter_changed(self, _event = None):
        self._refresh_class_tree()

    def _on_tree_open(self, _event = None):
        selection = self.class_tree.focus()
        if not selection.startswith("pkg:"):
            return
        self._populate_package_children(selection[4:])

    def _on_tree_select(self, _event = None):
        selection = self.class_tree.selection()
        if not selection:
            return
        item_id = selection[0]
        if not item_id.startswith("cls:"):
            return
        self.open_class(item_id[4:])

    def _on_search_type_changed(self, _event = None):
        find_type = self.search_type_var.get()
        need_class = find_type in ("method", "field")
        class_state = tk.NORMAL if need_class and self.store is not None else tk.DISABLED
        fuzzy_state = tk.NORMAL if need_class and self.store is not None else tk.DISABLED
        self.search_class_entry.config(state=class_state)
        self.fuzzy_class_check.config(state=fuzzy_state)

    def _tag_range(self, tag_name : str, start : int, end : int):
        if end <= start:
            return
        self.source_text.tag_add(tag_name, f"1.0+{start}c", f"1.0+{end}c")

    def _clear_source_tags(self):
        for tag_name in ("java_keyword", "java_comment", "java_string", "java_annotation"):
            self.source_text.tag_remove(tag_name, "1.0", tk.END)

    def _collect_basic_java_highlight_spans(self, text : str):
        spans = {
            "java_keyword": [],
            "java_comment": [],
            "java_string": [],
            "java_annotation": [],
        }
        n = len(text)
        i = 0
        while i < n:
            ch = text[i]

            if ch == "/" and i + 1 < n:
                nxt = text[i + 1]
                if nxt == "/":
                    start = i
                    i += 2
                    while i < n and text[i] != "\n":
                        i += 1
                    spans["java_comment"].append((start, i))
                    continue
                if nxt == "*":
                    start = i
                    i += 2
                    while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                        i += 1
                    i = min(i + 2, n)
                    spans["java_comment"].append((start, i))
                    continue

            if ch == '"' or ch == "'":
                quote = ch
                start = i
                i += 1
                while i < n:
                    cur = text[i]
                    if cur == "\\":
                        i += 2
                        continue
                    if cur == quote:
                        i += 1
                        break
                    i += 1
                spans["java_string"].append((start, i))
                continue

            if ch == "@":
                start = i
                i += 1
                while i < n and (text[i].isalnum() or text[i] in "._$"):
                    i += 1
                spans["java_annotation"].append((start, i))
                continue

            if ch.isalpha() or ch == "_":
                start = i
                i += 1
                while i < n and (text[i].isalnum() or text[i] in "_$"):
                    i += 1
                token = text[start:i]
                if token in _JAVA_KEYWORDS:
                    spans["java_keyword"].append((start, i))
                continue

            i += 1
        return spans

    def _start_async_highlight(self, text : str):
        self._highlight_generation += 1
        generation = self._highlight_generation
        if self._highlight_apply_job is not None:
            try:
                self.root.after_cancel(self._highlight_apply_job)
            except tk.TclError:
                pass
            self._highlight_apply_job = None
        self._clear_source_tags()

        def worker():
            spans = self._collect_basic_java_highlight_spans(text)
            self.events.put(("highlight_ready", generation, spans))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_highlight_spans_async(self, generation : int, spans):
        if generation != self._highlight_generation:
            return
        work_items = []
        for tag_name in ("java_comment", "java_string", "java_annotation", "java_keyword"):
            for start, end in spans[tag_name]:
                work_items.append((tag_name, start, end))
        if not work_items:
            return

        def apply_chunk(offset : int = 0):
            if generation != self._highlight_generation:
                self._highlight_apply_job = None
                return
            end_offset = min(offset + self._highlight_apply_batch, len(work_items))
            for idx in range(offset, end_offset):
                tag_name, start, end = work_items[idx]
                self._tag_range(tag_name, start, end)
            if end_offset < len(work_items):
                self._highlight_apply_job = self.root.after(1, apply_chunk, end_offset)
            else:
                self._highlight_apply_job = None

        apply_chunk()

    def _show_editor_find(self, _event = None):
        self.editor_find_frame.grid()
        self.editor_find_entry.focus_set()
        self.editor_find_entry.selection_range(0, tk.END)
        self._refresh_editor_find_marks(reset_cursor=True)
        return "break"

    def _hide_editor_find(self, _event = None):
        self.editor_find_frame.grid_remove()
        self.source_text.tag_remove("find_match", "1.0", tk.END)
        self.source_text.tag_remove("find_current", "1.0", tk.END)
        self.editor_find_status_var.set("")
        self.source_text.focus_set()
        return "break"

    def _refresh_editor_find_marks(self, reset_cursor : bool = False):
        needle = self.editor_find_var.get()
        self.source_text.tag_remove("find_match", "1.0", tk.END)
        self.source_text.tag_remove("find_current", "1.0", tk.END)
        if reset_cursor:
            self.source_text.mark_set("insert", "1.0")
        if not needle:
            self.editor_find_status_var.set("")
            return 0

        count = tk.IntVar()
        pos = "1.0"
        hits = 0
        while True:
            idx = self.source_text.search(needle, pos, stopindex=tk.END, nocase=True, count=count)
            if not idx:
                break
            if count.get() <= 0:
                break
            end = f"{idx}+{count.get()}c"
            self.source_text.tag_add("find_match", idx, end)
            hits += 1
            pos = end
        self.editor_find_status_var.set(f"{hits} matches" if hits else "No match")
        return hits

    def _editor_find_step(self, backwards : bool):
        needle = self.editor_find_var.get()
        if not needle:
            self.editor_find_status_var.set("Empty query")
            return "break"

        self._refresh_editor_find_marks(reset_cursor=False)
        count = tk.IntVar()
        insert_idx = self.source_text.index("insert")
        if backwards:
            idx = self.source_text.search(
                needle, insert_idx, stopindex="1.0", backwards=True, nocase=True, count=count
            )
            if not idx:
                idx = self.source_text.search(
                    needle, tk.END, stopindex="1.0", backwards=True, nocase=True, count=count
                )
        else:
            idx = self.source_text.search(needle, insert_idx, stopindex=tk.END, nocase=True, count=count)
            if not idx:
                idx = self.source_text.search(needle, "1.0", stopindex=tk.END, nocase=True, count=count)
        if not idx or count.get() <= 0:
            self.editor_find_status_var.set("No match")
            return "break"

        end = f"{idx}+{count.get()}c"
        self.source_text.tag_remove("find_current", "1.0", tk.END)
        self.source_text.tag_add("find_current", idx, end)
        self.source_text.mark_set("insert", end if not backwards else idx)
        self.source_text.see(idx)
        self.editor_find_status_var.set(f"Match at {idx}")
        return "break"

    def _editor_find_next(self):
        return self._editor_find_step(False)

    def _editor_find_prev(self):
        return self._editor_find_step(True)

    def _on_editor_find_next(self, _event = None):
        return self._editor_find_next()

    def _on_editor_find_prev(self, _event = None):
        return self._editor_find_prev()

    def _on_editor_find_changed(self, _event = None):
        self._refresh_editor_find_marks(reset_cursor=True)

    def open_class(self, dalvik_class : str):
        if dalvik_class is None or self.store is None:
            return
        self.status_var.set(f"Decompiling {dalvik_to_dot(dalvik_class)}...")
        _debug_log(self.debug, "app", f"open class request class={dalvik_class}")

        def worker():
            try:
                _debug_log(self.debug, "app", f"open class worker start class={dalvik_class}")
                dex_name, source = self.store.get_source(dalvik_class)
                self.events.put(("source_done", dalvik_class, dex_name, source))
                _debug_log(self.debug, "app", f"open class worker done class={dalvik_class} dex={dex_name}")
            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                self.events.put(("source_error", f"Decompile failed: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _start_search(self):
        if self.store is None:
            return
        if self.search_inflight:
            self.status_var.set("Search is already running")
            return

        find_type = self.search_type_var.get()
        value = self.search_value_var.get().strip()
        class_name = self.search_class_var.get().strip()
        fuzzy_class = self.fuzzy_class_var.get()
        if find_type in ("string", "type") and not value:
            self.status_var.set("Search value is empty")
            return
        if find_type in ("method", "field") and not value and not class_name:
            self.status_var.set(f"{find_type} search needs class or name")
            return

        self.search_dialog = SearchDialog(
            self,
            find_type=find_type,
            value=value,
            class_name=class_name or None,
            fuzzy_class=fuzzy_class,
        )
        self.search_inflight = True
        self.search_button.config(state=tk.DISABLED)
        _debug_log(
            self.debug,
            "app",
            f"search request type={find_type} value={value!r} class={class_name!r} fuzzy={fuzzy_class}",
        )

        def worker():
            try:
                _debug_log(self.debug, "app", "search worker start")
                self._ensure_search_executor()
                payload = self.store.search(
                    find_type=find_type,
                    value=value,
                    class_name=class_name or None,
                    fuzzy_class=fuzzy_class,
                    max_workers=self.max_workers,
                    progress_callback=lambda done, total, hit_count: self.events.put(
                        ("search_progress", done, total, hit_count)
                    ),
                    result_callback=lambda rows, done, total, hit_count: self.events.put(
                        ("search_batch", rows, done, total, hit_count)
                    ),
                )
                self.events.put(("search_done", payload))
                _debug_log(
                    self.debug,
                    "app",
                    f"search worker done hits={payload['total_hits']} backend={payload['backend']}",
                )
            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                self.events.put(("search_error", f"Search failed: {e}"))
            finally:
                self._dispose_search_executor()

        threading.Thread(target=worker, daemon=True).start()


def launch_gui(apk_path : str, max_workers : int = 20, debug : bool = False):
    root = tk.Tk()

    _debug_log(debug, "app", f"launch gui apk={apk_path} workers={max_workers}")
    app = AscGuiApp(root, apk_path, max_workers=max_workers, debug=debug, search_executor=None)
    closed = False

    def on_close():
        nonlocal closed
        if closed:
            return
        closed = True
        _debug_log(debug, "app", "shutdown gui")
        app._dispose_search_executor()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    try:
        root.mainloop()
    finally:
        on_close()
