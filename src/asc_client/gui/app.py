import os
import queue
import threading
import time
import traceback
import tkinter as tk
from tkinter import ttk

from src.asc_client.gui.runtime import GuiDexStore, dalvik_to_dot, is_member_search
from src.asc_client.gui.settings import SettingsDialog
from src.asc_client.gui.source_edit import (
    find_method_range,
    identifier_occurrences_in_range,
    index_to_offset,
    is_identifier,
    rename_identifier_in_range,
    token_at_offset,
)
from src.asc_client.gui.text_utils import decode_java_unicode_escapes
from src.asc_client.gui.theme import ThemeManager
from src.asc_client.gui.widgets import EditorTab, EditorTabBar
from src.asc_client.manifest_handler import get_manifest_xml


_MAX_FILTER_CLASSES = 5000
_COMMENT_GAP = "  "
_SOURCE_NAV_KEYS = {
    "Left", "Right", "Up", "Down", "Home", "End", "Prior", "Next",
    "Control_L", "Control_R", "Shift_L", "Shift_R", "Alt_L", "Alt_R",
}
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
        self.all_rows = []
        self.searching = True

        self.win = tk.Toplevel(app.root)
        self.win.title("Search")
        self.win.geometry("1280x760")
        self.win.transient(app.root)

        self.status_var = tk.StringVar(value="Searching...")
        self.progress_var = tk.IntVar(value=0)
        self.filter_var = tk.StringVar(value="")

        self._build_ui()

    def _build_ui(self):
        self.win.columnconfigure(0, weight=1)
        self.win.rowconfigure(1, weight=1)

        top = ttk.Frame(self.win, padding=8)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=0)
        top.columnconfigure(2, weight=1)

        ttk.Label(top, textvariable=self.status_var).grid(row=0, column=0, sticky="w")
        ttk.Label(top, text="Filter").grid(row=0, column=1, sticky="e", padx=(12, 0))
        self.filter_entry = ttk.Entry(top, textvariable=self.filter_var)
        self.filter_entry.grid(row=0, column=2, sticky="ew", padx=(8, 0))
        self.filter_entry.bind("<KeyRelease>", self._on_filter_changed)
        self.filter_entry.config(state=tk.DISABLED)
        self.progress = ttk.Progressbar(top, mode="determinate", variable=self.progress_var, maximum=100)
        self.progress.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(8, 0))

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
        self.apply_theme()

    def apply_theme(self):
        if self.win.winfo_exists():
            self.app.apply_theme_to_window(self.win)

    def update_progress(self, done : int, total : int, hit_count : int):
        percent = int((done / total) * 100) if total else 0
        self.progress_var.set(percent)
        self.status_var.set(f"Searching {done}/{total} dex, hits={hit_count}")

    def finish(self, payload):
        if not self.rows and payload["results"]:
            self.append_results(payload["results"])
        self.searching = False
        self.filter_entry.config(state=tk.NORMAL)
        msg = f"Done. hits={payload['total_hits']} workers={payload['workers']} backend={payload['backend']}"
        # if payload["truncated"]:
            # msg += f" showing first {len(payload['results'])}"
        self.status_var.set(msg)
        self.progress_var.set(100)

    def append_results(self, rows):
        if not rows:
            return
        self.all_rows.extend(rows)
        if self.searching:
            self._append_visible_rows(rows)
            return
        keyword = self.filter_var.get().strip().lower()
        if keyword:
            rows = [row for row in rows if self._row_matches_filter(row, keyword)]
        self._append_visible_rows(rows)

    def fail(self, message : str):
        self.searching = False
        self.filter_entry.config(state=tk.NORMAL)
        self.status_var.set(message)

    def _open_selected(self, _event = None):
        selection = self.tree.selection()
        if not selection:
            return
        row = self.rows[int(selection[0])]
        self.app.open_class(row["class_name"])

    def _append_visible_rows(self, rows):
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

    def _row_matches_filter(self, row, keyword : str):
        if not keyword:
            return True
        return (
            keyword in row["dex_name"].lower()
            or keyword in row["class_display"].lower()
            or keyword in row["method_text"].lower()
            or keyword in row["matched_text"].lower()
        )

    def _rebuild_filtered_rows(self):
        if self.searching:
            return
        keyword = self.filter_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        self.rows = []
        if not keyword:
            self._append_visible_rows(self.all_rows)
            return
        self._append_visible_rows([row for row in self.all_rows if self._row_matches_filter(row, keyword)])

    def _on_filter_changed(self, _event = None):
        if self.searching:
            return
        self._rebuild_filtered_rows()


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
        self.editor_tabs = []
        self.active_tab_idx = -1
        self.theme_manager = ThemeManager(root, "light")
        self.theme_name_var = tk.StringVar(value=self.theme_manager.name)
        self.theme = self.theme_manager.theme

        self.class_filter_var = tk.StringVar()
        self.class_info_var = tk.StringVar(value="Classes")
        self.status_var = tk.StringVar(value="Loading APK...")
        self.search_type_var = tk.StringVar(value="string refs")
        self.search_value_var = tk.StringVar()
        self.search_class_var = tk.StringVar()
        self.fuzzy_class_var = tk.BooleanVar(value=False)
        self.editor_find_var = tk.StringVar()
        self.editor_find_status_var = tk.StringVar(value="")
        self._last_editor_find_text = ""
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

    def _open_settings(self):
        SettingsDialog(self)

    def set_theme(self, name : str):
        self.theme_manager.set_theme(name)
        self.theme_name_var.set(self.theme_manager.name)
        self.theme = self.theme_manager.theme
        self.apply_theme()

    def apply_theme_to_window(self, win):
        self.theme_manager.apply_toplevel(win)

    def _configure_source_tags(self):
        t = self.theme
        self.theme_manager.apply_text(self.source_text)
        self.source_text.tag_configure("java_keyword", foreground=t["java_keyword"])
        self.source_text.tag_configure("java_comment", foreground=t["java_comment"])
        self.source_text.tag_configure("java_string", foreground=t["java_string"])
        self.source_text.tag_configure("java_annotation", foreground=t["java_annotation"])
        self.source_text.tag_configure("manifest_string", foreground=t["java_string"])
        self.source_text.tag_configure("user_comment", foreground=t["java_comment"], font=("Consolas", 10, "italic"))
        self.source_text.tag_configure("active_line", background=t["active_line"])
        self.source_text.tag_configure("symbol_match", background=t["symbol_match"])
        self.source_text.tag_configure("symbol_current", background=t["symbol_current"])
        self.source_text.tag_configure("find_match", background=t["find_match"], foreground=t["editor_fg"])
        self.source_text.tag_configure("find_current", background=t["find_current"], foreground=t["editor_fg"])

    def apply_theme(self):
        self.theme = self.theme_manager.theme
        self.theme_manager.apply_root(self.root)
        if hasattr(self, "source_text"):
            self._configure_source_tags()
        if hasattr(self, "editor_tab_bar"):
            self.editor_tab_bar.apply_theme()
        if self.search_dialog is not None and self.search_dialog.win.winfo_exists():
            self.search_dialog.apply_theme()

    def _build_ui(self):
        self.root.title(f"ASC GUI Auth: MG1937 - {os.path.basename(self.apk_path)}")
        self.root.geometry("1500x920")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.theme_manager.apply_root(self.root)

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
        self.manifest_button = ttk.Button(left_top, text="Manifest", command=self._open_manifest)
        self.manifest_button.grid(row=0, column=2, sticky="e", padx=(8, 0))

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
            values=("string refs", "type refs", "method refs", "field refs", "method", "field"),
            state="readonly",
            width=12,
        )
        self.search_type_box.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.search_type_box.bind("<<ComboboxSelected>>", self._on_search_type_changed)
        self.search_type_box.bind("<Return>", self._on_search_enter)

        self.search_value_entry = ttk.Entry(controls, textvariable=self.search_value_var)
        self.search_value_entry.grid(row=0, column=2, sticky="ew", padx=(8, 0))
        self.search_value_entry.bind("<Return>", self._on_search_enter)

        ttk.Label(controls, text="Class").grid(row=0, column=3, sticky="w", padx=(8, 0))
        self.search_class_entry = ttk.Entry(controls, textvariable=self.search_class_var, width=30)
        self.search_class_entry.grid(row=0, column=4, sticky="w", padx=(4, 0))
        self.search_class_entry.bind("<Return>", self._on_search_enter)

        self.fuzzy_class_check = ttk.Checkbutton(controls, text="Fuzzy class", variable=self.fuzzy_class_var)
        self.fuzzy_class_check.grid(row=0, column=5, sticky="w", padx=(8, 0))

        self.search_button = ttk.Button(controls, text="Search", command=self._start_search)
        self.search_button.grid(row=0, column=6, sticky="e", padx=(8, 0))

        source_frame = ttk.Frame(right)
        source_frame.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        source_frame.columnconfigure(0, weight=1)
        source_frame.rowconfigure(2, weight=1)

        self.editor_tab_bar = EditorTabBar(source_frame, self)
        self.editor_tab_bar.grid(row=0, column=0, columnspan=2, sticky="ew")

        self.editor_find_frame = ttk.Frame(source_frame)
        self.editor_find_frame.grid(row=1, column=0, sticky="ew", pady=(6, 6))
        self.editor_find_frame.columnconfigure(1, weight=1)
        ttk.Label(self.editor_find_frame, text="Find").grid(row=0, column=0, sticky="w")
        self.editor_find_entry = ttk.Entry(self.editor_find_frame, textvariable=self.editor_find_var)
        self.editor_find_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        self.editor_find_entry.bind("<Return>", self._on_editor_find_return)
        self.editor_find_entry.bind("<KP_Enter>", self._on_editor_find_return)
        self.editor_find_entry.bind("<Shift-Return>", self._on_editor_find_prev)
        self.editor_find_entry.bind("<Shift-KP_Enter>", self._on_editor_find_prev)
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

        self.source_text = tk.Text(source_frame, wrap="none")
        self.source_text.grid(row=2, column=0, sticky="nsew")
        src_y = ttk.Scrollbar(source_frame, orient=tk.VERTICAL, command=self.source_text.yview)
        src_y.grid(row=2, column=1, sticky="ns")
        src_x = ttk.Scrollbar(source_frame, orient=tk.HORIZONTAL, command=self.source_text.xview)
        src_x.grid(row=3, column=0, sticky="ew")
        self.source_text.config(yscrollcommand=src_y.set, xscrollcommand=src_x.set)
        self._configure_source_tags()
        self.apply_theme()
        self.editor_find_frame.grid_remove()
        self._show_empty_editor()
        self._on_search_type_changed()

    def _bind_editor_shortcuts(self):
        self.root.bind("<Control-f>", self._show_editor_find)
        self.root.bind("<Control-F>", self._show_editor_find)
        self.root.bind("<Control-w>", self._close_active_tab)
        self.root.bind("<Control-W>", self._close_active_tab)
        self.root.bind("<Control-Tab>", self._next_tab)
        self.root.bind("<Control-Shift-Tab>", self._prev_tab)
        self.source_text.bind("<Button-1>", self._set_editor_cursor_from_click)
        self.source_text.bind("<KeyPress>", self._on_source_key_press)
        self.source_text.bind("<KeyRelease>", self._on_source_key_release)
        self.source_text.bind("<<Paste>>", lambda _event: "break")
        self.source_text.bind("<<Cut>>", lambda _event: "break")
        self.source_text.bind("<<Clear>>", lambda _event: "break")
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
        if hasattr(self, "manifest_button"):
            self.manifest_button.config(state=state)

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
            self._finish_open_tab(dalvik_class, dex_name, source)
            return
        if kind == "text_tab_done":
            _kind, tab_id, title, source, dex_name = event
            self._open_text_tab(tab_id, title, source, dex_name=dex_name)
            self.status_var.set(f"Opened {title}")
            return
        if kind == "highlight_ready":
            _kind, generation, spans = event
            self._apply_highlight_spans_async(generation, spans)
            return
        if kind == "source_error":
            _kind, dalvik_class, message = event
            self._fail_open_tab(dalvik_class, message)
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

    def _open_manifest(self):
        self.status_var.set("Parsing AndroidManifest.xml...")

        def worker():
            try:
                xml = get_manifest_xml(self.apk_path, pretty=True)
                self.events.put(("text_tab_done", "manifest:AndroidManifest.xml", "AndroidManifest.xml", xml, "manifest"))
            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                self.events.put(("source_error", "manifest:AndroidManifest.xml", f"Manifest parse failed: {e}"))

        threading.Thread(target=worker, daemon=True).start()

    def _find_tab_index(self, dalvik_class : str):
        for idx, tab in enumerate(self.editor_tabs):
            if tab.dalvik_class == dalvik_class:
                return idx
        return None

    def _open_text_tab(self, tab_id : str, title : str, source : str, dex_name : str = ""):
        idx = self._find_tab_index(tab_id)
        if idx is None:
            self._remember_active_view()
            self.editor_tabs.append(EditorTab(dalvik_class=tab_id, title=title, kind="text"))
            idx = len(self.editor_tabs) - 1
        tab = self.editor_tabs[idx]
        tab.dex_name = dex_name
        tab.source = source
        tab.edited_source = ""
        tab.loading = False
        tab.error = ""
        self.activate_tab(idx)

    def _active_tab(self):
        if self.active_tab_idx < 0 or self.active_tab_idx >= len(self.editor_tabs):
            return None
        return self.editor_tabs[self.active_tab_idx]

    def _remember_active_view(self):
        tab = self._active_tab()
        if tab is None:
            return
        try:
            tab.yview = self.source_text.yview()
            tab.xview = self.source_text.xview()
            tab.insert_index = self.source_text.index("insert")
        except tk.TclError:
            pass

    def _set_source_text(self, text : str, reset_view : bool = True):
        self.source_text.config(state=tk.NORMAL)
        self.source_text.delete("1.0", tk.END)
        self.source_text.insert("1.0", text)
        if reset_view:
            self.source_text.mark_set("insert", "1.0")
            self.source_text.xview_moveto(0.0)
            self.source_text.yview_moveto(0.0)

    def _render_tab_source(self, tab : EditorTab):
        source = tab.edited_source or tab.source
        if not tab.comments:
            return source, []

        out = []
        comment_spans = []
        offset = 0
        lines = source.splitlines(keepends=True)
        for line_no, line in enumerate(lines, 1):
            newline = ""
            body = line
            if line.endswith("\r\n"):
                body = line[:-2]
                newline = "\r\n"
            elif line.endswith("\n"):
                body = line[:-1]
                newline = "\n"

            comment = tab.comments.get(line_no)
            if not comment:
                rendered = line
            else:
                pad = _COMMENT_GAP
                comment_text = f"{pad}// {comment}"
                start = offset + len(body) + len(pad)
                end = start + len(comment_text) - len(pad)
                rendered = f"{body}{comment_text}{newline}"
                comment_spans.append((start, end))
            out.append(rendered)
            offset += len(rendered)

        if not lines and tab.comments:
            comment = tab.comments.get(1, "")
            rendered = f"// {comment}"
            comment_spans.append((0, len(rendered)))
            return rendered, comment_spans

        return "".join(out), comment_spans

    def _comment_line_from_index(self, index : str):
        try:
            return int(str(index).split(".", 1)[0])
        except (TypeError, ValueError):
            return None

    def _highlight_active_line(self):
        self.source_text.tag_remove("active_line", "1.0", tk.END)
        try:
            line_no = self._comment_line_from_index(self.source_text.index("insert"))
        except tk.TclError:
            line_no = None
        if line_no is None:
            return
        self.source_text.tag_add("active_line", f"{line_no}.0", f"{line_no}.end+1c")
        self.source_text.tag_lower("active_line")

    def _set_editor_cursor_from_click(self, event):
        try:
            self.source_text.focus_set()
            index = self.source_text.index(f"@{event.x},{event.y}")
            self.source_text.mark_set("insert", index)
            self._highlight_active_line()
            self._highlight_related_identifier(index)
        except tk.TclError:
            pass

    def _on_source_key_press(self, event):
        if event.state & 0x0004:
            return None
        if event.keysym == "n":
            return self._show_rename_dialog()
        if event.char == ";":
            return self._show_line_comment_dialog()
        if event.keysym in _SOURCE_NAV_KEYS:
            return None
        return "break"

    def _on_source_key_release(self, event):
        if event.keysym in _SOURCE_NAV_KEYS:
            self._highlight_active_line()
            self._highlight_related_identifier(self.source_text.index("insert"))
        return None

    def _highlight_related_identifier(self, index : str):
        self.source_text.tag_remove("symbol_match", "1.0", tk.END)
        self.source_text.tag_remove("symbol_current", "1.0", tk.END)
        tab = self._active_tab()
        if tab is None or tab.kind != "class" or tab.loading or tab.error:
            return
        source = tab.edited_source or tab.source
        if not source:
            return
        offset = index_to_offset(source, index)
        token = token_at_offset(source, offset)
        if token is None:
            return
        start, end, name = token
        method_range = find_method_range(source, start)
        if method_range is None:
            method_range = (0, len(source))
        spans = identifier_occurrences_in_range(source, method_range[0], method_range[1], name)
        if len(spans) <= 1:
            return
        for span_start, span_end in spans:
            tag = "symbol_current" if span_start == start and span_end == end else "symbol_match"
            self._tag_range(tag, span_start, span_end)
        self.source_text.tag_raise("symbol_match")
        self.source_text.tag_raise("symbol_current")

    def _original_line_text(self, tab : EditorTab, line_no : int):
        lines = (tab.edited_source or tab.source).splitlines()
        if line_no < 1 or line_no > len(lines):
            return ""
        return lines[line_no - 1]

    def _show_empty_editor(self):
        self._highlight_generation += 1
        self._clear_source_tags()
        self.source_text.tag_remove("user_comment", "1.0", tk.END)
        self.source_text.tag_remove("active_line", "1.0", tk.END)
        self.source_text.tag_remove("symbol_match", "1.0", tk.END)
        self.source_text.tag_remove("symbol_current", "1.0", tk.END)
        self.source_text.tag_remove("find_match", "1.0", tk.END)
        self.source_text.tag_remove("find_current", "1.0", tk.END)
        self._set_source_text("Open a class from the package tree or search results.", reset_view=True)
        self.editor_find_status_var.set("")

    def _show_tab(self, tab : EditorTab):
        self._highlight_generation += 1
        self._clear_source_tags()
        self.source_text.tag_remove("user_comment", "1.0", tk.END)
        self.source_text.tag_remove("active_line", "1.0", tk.END)
        self.source_text.tag_remove("symbol_match", "1.0", tk.END)
        self.source_text.tag_remove("symbol_current", "1.0", tk.END)
        self.source_text.tag_remove("find_match", "1.0", tk.END)
        self.source_text.tag_remove("find_current", "1.0", tk.END)
        if tab.loading:
            self._set_source_text(f"Decompiling {dalvik_to_dot(tab.dalvik_class)}...", reset_view=True)
            return
        if tab.error:
            self._set_source_text(tab.error, reset_view=True)
            return

        rendered, comment_spans = self._render_tab_source(tab)
        self._set_source_text(rendered, reset_view=False)
        try:
            self.source_text.mark_set("insert", tab.insert_index)
            self.source_text.xview_moveto(tab.xview[0])
            self.source_text.yview_moveto(tab.yview[0])
        except tk.TclError:
            self.source_text.mark_set("insert", "1.0")
        for start, end in comment_spans:
            self._tag_range("user_comment", start, end)
        if tab.kind == "class":
            self._start_async_highlight(rendered)
        else:
            self._highlight_quoted_strings(rendered)
        self._refresh_editor_find_marks(reset_cursor=False)
        self._highlight_active_line()

    def activate_tab(self, index : int):
        if index < 0 or index >= len(self.editor_tabs):
            return
        if index == self.active_tab_idx:
            self.editor_tab_bar.ensure_visible(index)
            self.editor_tab_bar.redraw()
            return
        self._remember_active_view()
        self.active_tab_idx = index
        tab = self.editor_tabs[index]
        self._show_tab(tab)
        self.editor_tab_bar.ensure_visible(index)
        self.editor_tab_bar.redraw()
        if tab.loading:
            self.status_var.set(f"Decompiling {dalvik_to_dot(tab.dalvik_class)}...")
        elif tab.error:
            self.status_var.set(tab.error)
        else:
            if tab.kind == "class":
                self.status_var.set(f"Opened {dalvik_to_dot(tab.dalvik_class)} from {tab.dex_name}")
            else:
                self.status_var.set(f"Opened {tab.title}")
        if tab.kind == "class":
            self._select_class_in_tree(tab.dalvik_class)

    def close_tab(self, index : int):
        if index < 0 or index >= len(self.editor_tabs):
            return
        self._remember_active_view()
        was_active = index == self.active_tab_idx
        self.editor_tabs.pop(index)
        if not self.editor_tabs:
            self.active_tab_idx = -1
            self.editor_tab_bar.tab_scroll_index = 0
            self.editor_tab_bar.redraw()
            self._show_empty_editor()
            self.status_var.set("No class tab open")
            return
        if self.active_tab_idx > index:
            self.active_tab_idx -= 1
        elif was_active:
            self.active_tab_idx = min(index, len(self.editor_tabs) - 1)
            self._show_tab(self.editor_tabs[self.active_tab_idx])
        self.editor_tab_bar.ensure_visible(self.active_tab_idx)
        self.editor_tab_bar.redraw()

    def clear_tabs(self):
        if not self.editor_tabs:
            return
        self.editor_tabs = []
        self.active_tab_idx = -1
        self.editor_tab_bar.tab_scroll_index = 0
        self.editor_tab_bar.redraw()
        self._show_empty_editor()
        self.status_var.set("No class tab open")

    def _close_active_tab(self, _event = None):
        self.close_tab(self.active_tab_idx)
        return "break"

    def _cycle_tab(self, step : int):
        if not self.editor_tabs:
            return "break"
        self.activate_tab((self.active_tab_idx + step) % len(self.editor_tabs))
        return "break"

    def _next_tab(self, _event = None):
        return self._cycle_tab(1)

    def _prev_tab(self, _event = None):
        return self._cycle_tab(-1)

    def _finish_open_tab(self, dalvik_class : str, dex_name : str, source : str):
        idx = self._find_tab_index(dalvik_class)
        if idx is None:
            return
        tab = self.editor_tabs[idx]
        tab.dex_name = dex_name
        tab.source = decode_java_unicode_escapes(source)
        tab.edited_source = ""
        tab.loading = False
        tab.error = ""
        if idx == self.active_tab_idx:
            self._show_tab(tab)
        self.editor_tab_bar.ensure_visible(idx if idx == self.active_tab_idx else self.active_tab_idx)
        self.editor_tab_bar.redraw()
        self.status_var.set(f"Opened {dalvik_to_dot(dalvik_class)} from {dex_name}")

    def _fail_open_tab(self, dalvik_class : str, message : str):
        idx = self._find_tab_index(dalvik_class)
        if idx is None:
            self.status_var.set(message)
            return
        tab = self.editor_tabs[idx]
        tab.loading = False
        tab.error = message
        if idx == self.active_tab_idx:
            self._show_tab(tab)
        self.editor_tab_bar.redraw()
        self.status_var.set(message)

    def _select_class_in_tree(self, dalvik_class : str):
        item_id = f"cls:{dalvik_class}"
        if not self.class_tree.exists(item_id):
            return
        self.class_tree.selection_set(item_id)
        self.class_tree.focus(item_id)
        self.class_tree.see(item_id)

    def _on_search_type_changed(self, _event = None):
        find_type = self.search_type_var.get()
        need_class = find_type in ("method refs", "field refs")
        class_state = tk.NORMAL if need_class and self.store is not None else tk.DISABLED
        fuzzy_state = tk.NORMAL if need_class and self.store is not None else tk.DISABLED
        self.search_class_entry.config(state=class_state)
        self.fuzzy_class_check.config(state=fuzzy_state)

    def _on_search_enter(self, _event = None):
        self._start_search()
        return "break"

    def _tag_range(self, tag_name : str, start : int, end : int):
        if end <= start:
            return
        self.source_text.tag_add(tag_name, f"1.0+{start}c", f"1.0+{end}c")

    def _tag_ranges(self, tag_name : str, spans, batch_size : int = 512):
        for offset in range(0, len(spans), batch_size):
            args = []
            for start, end in spans[offset:offset + batch_size]:
                if end <= start:
                    continue
                args.append(f"1.0+{start}c")
                args.append(f"1.0+{end}c")
            if args:
                self.source_text.tag_add(tag_name, *args)

    def _offset_spans_to_index_spans(self, text : str, spans):
        line_starts = [0]
        pos = 0
        while True:
            pos = text.find("\n", pos)
            if pos < 0:
                break
            pos += 1
            line_starts.append(pos)

        def to_index(offset : int):
            left = 0
            right = len(line_starts)
            while left < right:
                mid = (left + right) >> 1
                if line_starts[mid] <= offset:
                    left = mid + 1
                else:
                    right = mid
            line_idx = left - 1
            return f"{line_idx + 1}.{offset - line_starts[line_idx]}"

        ret = {}
        for tag_name, tag_spans in spans.items():
            ret[tag_name] = [(to_index(start), to_index(end)) for start, end in tag_spans]
        return ret

    def _tag_index_ranges(self, tag_name : str, spans, batch_size : int = 512):
        for offset in range(0, len(spans), batch_size):
            args = []
            for start, end in spans[offset:offset + batch_size]:
                args.append(start)
                args.append(end)
            if args:
                self.source_text.tag_add(tag_name, *args)

    def _clear_source_tags(self):
        for tag_name in ("java_keyword", "java_comment", "java_string", "java_annotation", "manifest_string"):
            self.source_text.tag_remove(tag_name, "1.0", tk.END)

    def _highlight_quoted_strings(self, text : str):
        spans = []
        start = None
        escape = False
        line = 1
        col = 0
        for ch in text:
            if start is None:
                if ch == '"':
                    start = f"{line}.{col}"
                    escape = False
            else:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    spans.append((start, f"{line}.{col + 1}"))
                    start = None
            if ch == "\n":
                line += 1
                col = 0
            else:
                col += 1
        self._tag_index_ranges("manifest_string", spans)

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
            spans = self._offset_spans_to_index_spans(text, spans)
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
                self.source_text.tag_add(tag_name, start, end)
            if end_offset < len(work_items):
                self._highlight_apply_job = self.root.after(1, apply_chunk, end_offset)
            else:
                self.source_text.tag_raise("user_comment")
                self.source_text.tag_lower("active_line")
                self._highlight_apply_job = None

        apply_chunk()

    def _show_editor_find(self, _event = None):
        self.editor_find_frame.grid()
        self.editor_find_entry.focus_set()
        self.editor_find_entry.selection_range(0, tk.END)
        self._last_editor_find_text = self.editor_find_var.get()
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

        current_ranges = self.source_text.tag_ranges("find_current")
        current_start = str(current_ranges[0]) if current_ranges else None
        current_end = str(current_ranges[1]) if current_ranges else None
        self._refresh_editor_find_marks(reset_cursor=False)
        count = tk.IntVar()
        insert_idx = self.source_text.index("insert")
        if backwards:
            start_idx = current_start or insert_idx
            idx = self.source_text.search(
                needle, start_idx, stopindex="1.0", backwards=True, nocase=True, count=count
            )
            if not idx:
                idx = self.source_text.search(
                    needle, tk.END, stopindex="1.0", backwards=True, nocase=True, count=count
                )
        else:
            start_idx = current_end or insert_idx
            idx = self.source_text.search(needle, start_idx, stopindex=tk.END, nocase=True, count=count)
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

    def _on_editor_find_return(self, event = None):
        if event is not None and (event.state & 0x0001):
            return self._editor_find_prev()
        return self._editor_find_next()

    def _on_editor_find_changed(self, _event = None):
        if _event is not None and _event.keysym in (
            "Return", "KP_Enter", "Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R",
        ):
            return "break"
        current = self.editor_find_var.get()
        if current == self._last_editor_find_text:
            return
        self._last_editor_find_text = current
        self._refresh_editor_find_marks(reset_cursor=True)

    def _show_line_comment_dialog(self, _event = None):
        tab = self._active_tab()
        if tab is None or tab.kind != "class" or tab.loading or tab.error or not tab.source:
            return "break"

        line_no = self._comment_line_from_index(self.source_text.index("insert"))
        if line_no is None:
            return "break"
        source_line = self._original_line_text(tab, line_no)
        if source_line == "":
            return "break"

        win = tk.Toplevel(self.root)
        win.title(f"Comment line {line_no}")
        win.transient(self.root)
        win.resizable(True, False)
        self.apply_theme_to_window(win)

        width = 640
        x = self.root.winfo_rootx() + max(80, (self.root.winfo_width() - width) // 2)
        y = self.root.winfo_rooty() + 160
        win.geometry(f"{width}x118+{x}+{y}")
        win.minsize(420, 118)

        frame = ttk.Frame(win, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        win.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text=f"Line {line_no}").grid(row=0, column=0, sticky="w")
        preview = self._ellipsize_text(source_line.strip(), 92)
        ttk.Label(frame, text=preview).grid(row=0, column=1, sticky="ew", padx=(8, 0))

        comment_var = tk.StringVar(value=tab.comments.get(line_no, ""))
        ttk.Label(frame, text="Comment").grid(row=1, column=0, sticky="w", pady=(8, 0))
        entry = ttk.Entry(frame, textvariable=comment_var)
        entry.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=(8, 0))

        actions = ttk.Frame(frame)
        actions.grid(row=2, column=0, columnspan=2, sticky="e", pady=(10, 0))

        def save(_event = None):
            comment = comment_var.get().strip()
            self._set_line_comment(tab, line_no, comment)
            win.destroy()
            return "break"

        def delete_comment():
            self._set_line_comment(tab, line_no, "")
            win.destroy()

        ttk.Button(actions, text="Save", command=save).grid(row=0, column=0, sticky="e")
        ttk.Button(actions, text="Delete", command=delete_comment).grid(row=0, column=1, sticky="e", padx=(6, 0))
        ttk.Button(actions, text="Cancel", command=win.destroy).grid(row=0, column=2, sticky="e", padx=(6, 0))

        entry.bind("<Return>", save)
        entry.bind("<Escape>", lambda _event: win.destroy())
        entry.focus_set()
        entry.selection_range(0, tk.END)
        return "break"

    def _ellipsize_text(self, text : str, limit : int):
        if len(text) <= limit:
            return text
        return text[:max(0, limit - 3)] + "..."

    def _set_line_comment(self, tab : EditorTab, line_no : int, comment : str):
        if comment:
            tab.comments[line_no] = comment
        else:
            tab.comments.pop(line_no, None)
        tab.insert_index = f"{line_no}.0"
        try:
            tab.yview = self.source_text.yview()
            tab.xview = self.source_text.xview()
        except tk.TclError:
            pass
        self._show_tab(tab)
        self.status_var.set(f"Updated comment on line {line_no}")

    def _show_rename_dialog(self, _event = None):
        tab = self._active_tab()
        if tab is None or tab.kind != "class" or tab.loading or tab.error or not tab.source:
            return "break"

        source = tab.edited_source or tab.source
        try:
            cursor_index = self.source_text.index("insert")
        except tk.TclError:
            return "break"
        offset = index_to_offset(source, cursor_index)
        token = token_at_offset(source, offset)
        if token is None:
            self.status_var.set("No identifier at cursor")
            return "break"
        start, _end, old_name = token
        method_range = find_method_range(source, start)
        if method_range is None:
            self.status_var.set("Rename is only available inside a method body")
            return "break"

        win = tk.Toplevel(self.root)
        win.title(f"Rename {old_name}")
        win.transient(self.root)
        win.resizable(True, False)
        self.apply_theme_to_window(win)

        width = 520
        x = self.root.winfo_rootx() + max(80, (self.root.winfo_width() - width) // 2)
        y = self.root.winfo_rooty() + 160
        win.geometry(f"{width}x110+{x}+{y}")
        win.minsize(360, 110)

        frame = ttk.Frame(win, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")
        win.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="Rename").grid(row=0, column=0, sticky="w")
        name_var = tk.StringVar(value=old_name)
        entry = ttk.Entry(frame, textvariable=name_var)
        entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))

        actions = ttk.Frame(frame)
        actions.grid(row=1, column=0, columnspan=2, sticky="e", pady=(12, 0))

        def save(_event = None):
            new_name = name_var.get().strip()
            if not is_identifier(new_name):
                self.status_var.set("Invalid identifier")
                return "break"
            self._rename_identifier(tab, method_range, old_name, new_name)
            win.destroy()
            return "break"

        ttk.Button(actions, text="Rename", command=save).grid(row=0, column=0, sticky="e")
        ttk.Button(actions, text="Cancel", command=win.destroy).grid(row=0, column=1, sticky="e", padx=(6, 0))

        entry.bind("<Return>", save)
        entry.bind("<Escape>", lambda _event: win.destroy())
        entry.focus_set()
        entry.selection_range(0, tk.END)
        return "break"

    def _rename_identifier(self, tab : EditorTab, method_range, old_name : str, new_name : str):
        if old_name == new_name:
            return
        source = tab.edited_source or tab.source
        new_source, count = rename_identifier_in_range(
            source,
            method_range[0],
            method_range[1],
            old_name,
            new_name,
        )
        if count == 0:
            self.status_var.set(f"No occurrences of {old_name} in current method")
            return
        tab.edited_source = new_source
        try:
            tab.insert_index = self.source_text.index("insert")
            tab.yview = self.source_text.yview()
            tab.xview = self.source_text.xview()
        except tk.TclError:
            pass
        self._show_tab(tab)
        self.status_var.set(f"Renamed {count} occurrence(s) in current method")

    def open_class(self, dalvik_class : str):
        if dalvik_class is None or self.store is None:
            return
        idx = self._find_tab_index(dalvik_class)
        created = idx is None
        if idx is None:
            title = _class_label(dalvik_class)
            self._remember_active_view()
            self.editor_tabs.append(EditorTab(dalvik_class=dalvik_class, title=title))
            idx = len(self.editor_tabs) - 1
        self.activate_tab(idx)
        tab = self.editor_tabs[idx]
        if tab.loading and not created:
            return
        if not tab.error and tab.source:
            return
        tab.loading = True
        tab.error = ""
        tab.source = ""
        self._show_tab(tab)
        self.editor_tab_bar.redraw()

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
                self.events.put(("source_error", dalvik_class, f"Decompile failed: {e}"))

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
        if find_type in ("string refs", "type refs", "method", "field") and not value:
            self.status_var.set("Search value is empty")
            return
        if find_type in ("method refs", "field refs") and not value and not class_name:
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
                if is_member_search(find_type):
                    payload = self.store.search_members(
                        find_type=find_type,
                        value=value,
                    )
                    self.events.put(("search_batch", payload["results"], 1, 1, payload["total_hits"]))
                    self.events.put(("search_done", payload))
                    _debug_log(
                        self.debug,
                        "app",
                        f"member search worker done hits={payload['total_hits']}",
                    )
                    return

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
