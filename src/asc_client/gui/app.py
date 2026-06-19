import os
import queue
import threading
import time
import traceback
import tkinter as tk
from tkinter import ttk

from src.asc_client.gui.runtime import GuiDexStore, dalvik_to_dot


_MAX_FILTER_CLASSES = 5000


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
        self.rows = payload["results"]
        self.tree.delete(*self.tree.get_children())
        for idx, row in enumerate(self.rows):
            method_name = row["method_text"].split("->", 1)[1]
            self.tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(row["dex_name"], row["class_display"], method_name, row["matched_text"]),
            )

        msg = f"Done. hits={payload['total_hits']} workers={payload['workers']} backend={payload['backend']}"
        if payload["truncated"]:
            msg += f" showing first {len(payload['results'])}"
        self.status_var.set(msg)
        self.progress_var.set(100)

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

        self.class_filter_var = tk.StringVar()
        self.class_info_var = tk.StringVar(value="Classes")
        self.status_var = tk.StringVar(value="Loading APK...")
        self.search_type_var = tk.StringVar(value="string")
        self.search_value_var = tk.StringVar()
        self.search_class_var = tk.StringVar()
        self.fuzzy_class_var = tk.BooleanVar(value=False)

        self._build_ui()
        self._set_controls_enabled(False)
        self._start_load()
        self.root.after(50, self._drain_events)
        _debug_log(
            self.debug,
            "app",
            f"init apk={self.apk_path} workers={self.max_workers} executor={id(self.search_executor)}",
        )

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
        source_frame.rowconfigure(0, weight=1)
        self.source_text = tk.Text(source_frame, wrap="none")
        self.source_text.grid(row=0, column=0, sticky="nsew")
        src_y = ttk.Scrollbar(source_frame, orient=tk.VERTICAL, command=self.source_text.yview)
        src_y.grid(row=0, column=1, sticky="ns")
        src_x = ttk.Scrollbar(source_frame, orient=tk.HORIZONTAL, command=self.source_text.xview)
        src_x.grid(row=1, column=0, sticky="ew")
        self.source_text.config(yscrollcommand=src_y.set, xscrollcommand=src_x.set)
        self._on_search_type_changed()

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
            self.status_var.set(f"Opened {dalvik_to_dot(dalvik_class)} from {dex_name}")
            return
        if kind == "source_error":
            self.status_var.set(event[1])
            return
        if kind == "search_progress" and self.search_dialog is not None:
            _kind, done, total, hit_count = event
            self.search_dialog.update_progress(done, total, hit_count)
            self.status_var.set(f"Searching {done}/{total} dex, hits={hit_count}")
            return
        if kind == "search_done" and self.search_dialog is not None:
            payload = event[1]
            self.search_dialog.finish(payload)
            self.status_var.set(
                f"Search done. hits={payload['total_hits']} workers={payload['workers']} backend={payload['backend']}"
            )
            return
        if kind == "search_error" and self.search_dialog is not None:
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
        _debug_log(
            self.debug,
            "app",
            f"search request type={find_type} value={value!r} class={class_name!r} fuzzy={fuzzy_class}",
        )

        def worker():
            try:
                _debug_log(self.debug, "app", "search worker start")
                payload = self.store.search(
                    find_type=find_type,
                    value=value,
                    class_name=class_name or None,
                    fuzzy_class=fuzzy_class,
                    max_workers=self.max_workers,
                    progress_callback=lambda done, total, hit_count: self.events.put(
                        ("search_progress", done, total, hit_count)
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

        threading.Thread(target=worker, daemon=True).start()


def launch_gui(apk_path : str, max_workers : int = 20, debug : bool = False):
    root = tk.Tk()
    from concurrent.futures import ProcessPoolExecutor

    _debug_log(debug, "app", f"launch gui apk={apk_path} workers={max_workers}")
    search_executor = ProcessPoolExecutor(max_workers=max_workers)
    app = AscGuiApp(root, apk_path, max_workers=max_workers, debug=debug, search_executor=search_executor)
    closed = False

    def on_close():
        nonlocal closed
        if closed:
            return
        closed = True
        _debug_log(debug, "app", "shutdown gui executor")
        search_executor.shutdown(wait=False, cancel_futures=True)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    try:
        root.mainloop()
    finally:
        on_close()
