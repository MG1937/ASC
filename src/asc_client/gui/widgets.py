import tkinter as tk
import tkinter.font as tkfont
from dataclasses import dataclass, field
from tkinter import ttk

from src.asc_client.gui.runtime import dalvik_to_dot


@dataclass
class EditorTab:
    dalvik_class : str
    title : str
    kind : str = "class"
    dex_name : str = ""
    source : str = ""
    edited_source : str = ""
    loading : bool = True
    error : str = ""
    yview : tuple = (0.0, 1.0)
    xview : tuple = (0.0, 1.0)
    insert_index : str = "1.0"
    comments : dict = field(default_factory=dict)


class EditorTabBar(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app
        self.tab_scroll_index = 0
        self.tab_rects = []
        self.hover_close_index = None
        self.popup = None
        self.popup_listbox = None
        self.popup_rows = []
        self.popup_filter_var = None
        self.popup_visible_tab_indexes = []
        self.popup_close_button = None
        self.popup_clear_button = None
        self.font = tkfont.nametofont("TkDefaultFont")
        self.close_font = tkfont.Font(family=self.font.actual("family"), size=9, weight="bold")

        self.columnconfigure(0, weight=1)
        self.canvas = tk.Canvas(self, height=22, highlightthickness=0, bd=0)
        self.canvas.grid(row=0, column=0, sticky="ew")
        self.more_button = tk.Button(
            self,
            text="",
            width=2,
            relief=tk.FLAT,
            bd=0,
            padx=0,
            pady=0,
            highlightthickness=0,
            command=self.show_tab_list,
        )
        self.more_button.grid(row=0, column=1, sticky="ns")
        self.more_button.config(state=tk.DISABLED)
        self.settings_button = tk.Button(
            self,
            text="⚙",
            width=2,
            relief=tk.FLAT,
            bd=0,
            padx=0,
            pady=0,
            highlightthickness=0,
            command=self.app._open_settings,
        )
        self.settings_button.grid(row=0, column=2, sticky="ns")

        self.canvas.bind("<Configure>", lambda _event: self.redraw())
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<Button-2>", self._on_middle_click)
        self.canvas.bind("<Button-3>", self._on_right_click)
        self.canvas.bind("<Motion>", self._on_motion)
        self.canvas.bind("<Leave>", self._on_leave)
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Button-4>", lambda _event: self.scroll_tabs(-1))
        self.canvas.bind("<Button-5>", lambda _event: self.scroll_tabs(1))
        self.apply_theme()

    def _theme(self):
        return self.app.theme

    def apply_theme(self):
        t = self._theme()
        self.configure(style="TFrame")
        self.canvas.configure(background=t["tabbar_bg"])
        self.more_button.configure(
            background=t["tabbar_bg"],
            activebackground=t["tab_hover"],
            foreground=t["muted_text"],
            activeforeground=t["text"],
            disabledforeground=t["tabbar_bg"],
        )
        self.settings_button.configure(
            background=t["tabbar_bg"],
            activebackground=t["tab_hover"],
            foreground=t["muted_text"],
            activeforeground=t["text"],
        )
        if self.popup is not None and self.popup.winfo_exists():
            self.app.apply_theme_to_window(self.popup)
            if self.popup_listbox is not None:
                self.app.theme_manager.apply_listbox(self.popup_listbox)
        self.redraw()

    def _tab_width(self, tab : EditorTab) -> int:
        return max(128, min(260, self.font.measure(tab.title) + 56))

    def _visible_capacity(self, start : int, width : int):
        tabs = self.app.editor_tabs
        used = 0
        visible = []
        for idx in range(start, len(tabs)):
            tab_width = self._tab_width(tabs[idx])
            if visible and used + tab_width > width:
                break
            if not visible and tab_width > width:
                tab_width = max(80, width)
            visible.append((idx, tab_width))
            used += tab_width
        return visible

    def _tabs_overflow(self, width : int) -> bool:
        if not self.app.editor_tabs:
            return False
        total = sum(self._tab_width(tab) for tab in self.app.editor_tabs)
        return total > max(1, width)

    def _more_button_width(self):
        width = self.more_button.winfo_width()
        if width <= 1:
            width = self.more_button.winfo_reqwidth()
        return max(24, width)

    def _settings_button_width(self):
        width = self.settings_button.winfo_width()
        if width <= 1:
            width = self.settings_button.winfo_reqwidth()
        return max(24, width)

    def _fixed_button_width(self):
        return self._more_button_width() + self._settings_button_width()

    def _available_tab_width(self):
        width = self.canvas.winfo_width()
        if width > 1:
            return width
        frame_width = self.winfo_width()
        if frame_width > 1:
            return max(1, frame_width - self._fixed_button_width())
        return 240

    def _sync_more_button(self):
        t = self._theme()
        full_width = max(1, self.winfo_width())
        overflow = self._tabs_overflow(full_width - self._fixed_button_width())
        if overflow:
            if self.more_button.cget("state") != tk.NORMAL or self.more_button.cget("text") != "...":
                self.more_button.config(text="...", state=tk.NORMAL, disabledforeground=t["muted_text"])
        else:
            if self.more_button.cget("state") != tk.DISABLED or self.more_button.cget("text") != "":
                self.more_button.config(text="", state=tk.DISABLED, disabledforeground=t["tabbar_bg"])
            self.tab_scroll_index = 0
        return overflow

    def ensure_visible(self, index : int):
        if index < 0:
            return
        self.update_idletasks()
        width = self._available_tab_width()
        if index < self.tab_scroll_index:
            self.tab_scroll_index = index
            return
        visible_indexes = [item[0] for item in self._visible_capacity(self.tab_scroll_index, width)]
        if visible_indexes and index in visible_indexes:
            return
        used = 0
        start = index
        for idx in range(index, -1, -1):
            tab_width = self._tab_width(self.app.editor_tabs[idx])
            if idx != index and used + tab_width > width:
                break
            used += tab_width
            start = idx
        self.tab_scroll_index = start

    def redraw(self):
        self._sync_more_button()
        self.canvas.delete("all")
        self.tab_rects = []
        tabs = self.app.editor_tabs
        t = self._theme()
        width = self._available_tab_width()
        height = max(22, self.canvas.winfo_height())

        self.canvas.create_rectangle(0, 0, width, height, fill=t["tabbar_bg"], outline="")
        self.canvas.create_line(0, height - 1, width, height - 1, fill=t["border"])
        if not tabs:
            return

        self.tab_scroll_index = max(0, min(self.tab_scroll_index, len(tabs) - 1))
        x = 0
        for index, tab_width in self._visible_capacity(self.tab_scroll_index, width):
            tab = tabs[index]
            active = index == self.app.active_tab_idx
            x2 = min(width, x + tab_width)
            fill = t["tab_active"] if active else t["tab_inactive"]
            outline = t["border"] if active else t["border_light"]
            text_fill = t["text"] if active else t["muted_text"]

            self.canvas.create_rectangle(x, 0, x2, height, fill=fill, outline=outline)
            if active:
                self.canvas.create_rectangle(x, 0, x2, 2, fill=t["accent"], outline=t["accent"])

            close_x1 = max(x + 78, x2 - 28)
            close_x2 = x2 - 8
            text_limit = max(22, close_x1 - x - 18)
            title = self._ellipsize(tab.title, text_limit)
            if tab.loading:
                title = self._ellipsize(f"{title} ...", text_limit)
            if tab.error:
                title = self._ellipsize(f"{title} !", text_limit)

            self.canvas.create_text(x + 12, height // 2 + 1, text=title, anchor="w", fill=text_fill, font=self.font)
            if self.hover_close_index == index:
                self.canvas.create_rectangle(close_x1, 3, close_x2, height - 4, fill=t["tab_hover"], outline="")
            self.canvas.create_text(
                (close_x1 + close_x2) // 2,
                height // 2,
                text="x",
                fill=t["close_text"],
                font=self.close_font,
            )

            self.tab_rects.append((index, x, x2, close_x1, close_x2))
            x = x2 - 1
        if self.popup is not None and self.popup.winfo_exists():
            self.refresh_tab_list()

    def _ellipsize(self, text : str, max_width : int) -> str:
        if self.font.measure(text) <= max_width:
            return text
        suffix = "..."
        low = 0
        high = len(text)
        while low < high:
            mid = (low + high + 1) // 2
            if self.font.measure(text[:mid] + suffix) <= max_width:
                low = mid
            else:
                high = mid - 1
        return text[:low] + suffix

    def _hit_test(self, x : int):
        for index, x1, x2, close_x1, close_x2 in self.tab_rects:
            if x1 <= x <= x2:
                return index, close_x1 <= x <= close_x2
        return None, False

    def _on_click(self, event):
        index, close_hit = self._hit_test(event.x)
        if index is None:
            return
        if close_hit:
            self.app.close_tab(index)
            return
        self.app.activate_tab(index)

    def _on_middle_click(self, event):
        index, _close_hit = self._hit_test(event.x)
        if index is not None:
            self.app.close_tab(index)

    def _on_right_click(self, _event):
        self.show_tab_list()

    def _on_motion(self, event):
        index, close_hit = self._hit_test(event.x)
        hover = index if close_hit else None
        if hover == self.hover_close_index:
            return
        self.hover_close_index = hover
        self.redraw()

    def _on_leave(self, _event):
        if self.hover_close_index is None:
            return
        self.hover_close_index = None
        self.redraw()

    def _on_mousewheel(self, event):
        if event.delta < 0:
            self.scroll_tabs(1)
        elif event.delta > 0:
            self.scroll_tabs(-1)
        return "break"

    def scroll_tabs(self, step : int):
        tabs = self.app.editor_tabs
        if not tabs:
            return "break"
        next_index = max(0, min(len(tabs) - 1, self.tab_scroll_index + step))
        if next_index != self.tab_scroll_index:
            self.tab_scroll_index = next_index
            self.redraw()
        return "break"

    def show_tab_list(self):
        if not self.app.editor_tabs:
            return
        if self.popup is not None and self.popup.winfo_exists():
            self.popup.lift()
            self.refresh_tab_list()
            return

        popup = tk.Toplevel(self)
        self.popup = popup
        popup.title("Open Tabs")
        popup.transient(self.winfo_toplevel())
        popup.resizable(True, True)

        rows = self._tab_list_rows()
        text_width = max(self.font.measure(row) for row in rows) if rows else 360
        screen_width = popup.winfo_screenwidth()
        width = max(360, min(max(640, text_width + 96), screen_width - 80))
        row_height = 24
        visible_rows = min(14, max(4, len(self.app.editor_tabs)))
        height = visible_rows * row_height + 68
        x = self.more_button.winfo_rootx() + self.more_button.winfo_width() - width
        y = self.more_button.winfo_rooty() + self.more_button.winfo_height()
        popup.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")
        popup.minsize(360, 150)

        frame = ttk.Frame(popup, padding=6)
        frame.grid(row=0, column=0, sticky="nsew")
        popup.columnconfigure(0, weight=1)
        popup.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(3, weight=0)

        filter_bar = ttk.Frame(frame)
        filter_bar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        filter_bar.columnconfigure(1, weight=1)
        ttk.Label(filter_bar, text="Filter").grid(row=0, column=0, sticky="w")
        self.popup_filter_var = tk.StringVar(value="")
        filter_entry = ttk.Entry(filter_bar, textvariable=self.popup_filter_var)
        filter_entry.grid(row=0, column=1, sticky="ew", padx=(8, 0))

        listbox = tk.Listbox(
            frame,
            activestyle="none",
            borderwidth=0,
            highlightthickness=1,
            font=self.font,
            exportselection=False,
        )
        listbox.grid(row=1, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=listbox.yview)
        yscroll.grid(row=1, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=listbox.xview)
        xscroll.grid(row=2, column=0, sticky="ew")
        listbox.config(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.popup_listbox = listbox

        actions = ttk.Frame(frame)
        actions.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        actions.columnconfigure(0, weight=1)
        self.popup_close_button = ttk.Button(actions, text="Close Tab")
        self.popup_close_button.grid(row=0, column=1, sticky="e")
        self.popup_clear_button = ttk.Button(actions, text="Clear Tabs")
        self.popup_clear_button.grid(row=0, column=2, sticky="e", padx=(6, 0))

        def choose(_event = None):
            selection = listbox.curselection()
            if not selection:
                return "break"
            index = self._tab_index_from_popup_selection(selection[0])
            if index is not None:
                self.app.activate_tab(index)
            return "break"

        def close_selected(_event = None):
            selection = listbox.curselection()
            if not selection:
                return "break"
            if not self.app.editor_tabs:
                return "break"
            index = self._tab_index_from_popup_selection(selection[0])
            if index is None:
                return "break"
            self.app.close_tab(index)
            self.refresh_tab_list(min(index, len(self.app.editor_tabs) - 1), force_see=True)
            return "break"

        def clear_tabs():
            self.app.clear_tabs()
            self.refresh_tab_list()

        def dismiss(_event = None):
            popup.destroy()
            self.popup = None
            self.popup_listbox = None
            self.popup_rows = []
            self.popup_filter_var = None
            self.popup_visible_tab_indexes = []
            self.popup_close_button = None
            self.popup_clear_button = None
            return "break"

        def on_destroy(event):
            if event.widget is popup:
                self.popup = None
                self.popup_listbox = None
                self.popup_rows = []
                self.popup_filter_var = None
                self.popup_visible_tab_indexes = []
                self.popup_close_button = None
                self.popup_clear_button = None

        def on_mousewheel(event):
            listbox.yview_scroll(-1 if event.delta > 0 else 1, "units")
            return "break"

        self.popup_close_button.config(command=close_selected)
        self.popup_clear_button.config(command=clear_tabs)
        popup.protocol("WM_DELETE_WINDOW", dismiss)
        popup.bind("<Destroy>", on_destroy, add="+")
        filter_entry.bind("<KeyRelease>", lambda _event: self.refresh_tab_list(force_see=True))
        filter_entry.bind("<Escape>", dismiss)
        listbox.bind("<Double-Button-1>", choose)
        listbox.bind("<Return>", choose)
        listbox.bind("<Delete>", close_selected)
        listbox.bind("<Escape>", dismiss)
        listbox.bind("<MouseWheel>", on_mousewheel)
        listbox.bind("<Button-4>", lambda _event: listbox.yview_scroll(-1, "units"))
        listbox.bind("<Button-5>", lambda _event: listbox.yview_scroll(1, "units"))
        self.app.apply_theme_to_window(popup)
        self.app.theme_manager.apply_listbox(listbox)
        filter_entry.focus_set()
        self.refresh_tab_list(force_see=True)

    def _tab_list_rows(self):
        rows = []
        indexes = []
        keyword = ""
        if self.popup_filter_var is not None:
            keyword = self.popup_filter_var.get().strip().lower()
        for idx, tab in enumerate(self.app.editor_tabs):
            state = "loading" if tab.loading else "error" if tab.error else tab.dex_name
            suffix = f"  [{state}]" if state else ""
            row = f"{dalvik_to_dot(tab.dalvik_class)}{suffix}"
            if keyword and keyword not in row.lower():
                continue
            rows.append(row)
            indexes.append(idx)
        self.popup_visible_tab_indexes = indexes
        return rows

    def _tab_index_from_popup_selection(self, selection_idx : int):
        if selection_idx < 0 or selection_idx >= len(self.popup_visible_tab_indexes):
            return None
        return self.popup_visible_tab_indexes[selection_idx]

    def refresh_tab_list(self, preferred_index = None, force_see : bool = False):
        if self.popup is None or self.popup_listbox is None:
            return
        if not self.popup.winfo_exists():
            self.popup = None
            self.popup_listbox = None
            self.popup_rows = []
            self.popup_filter_var = None
            self.popup_visible_tab_indexes = []
            self.popup_close_button = None
            self.popup_clear_button = None
            return
        listbox = self.popup_listbox
        rows = self._tab_list_rows()
        if not rows:
            rows = ["(no matching tabs)" if self.app.editor_tabs else "(no open tabs)"]
            listbox.config(state=tk.DISABLED)
            if self.popup_close_button is not None:
                self.popup_close_button.config(state=tk.DISABLED)
            if self.popup_clear_button is not None:
                self.popup_clear_button.config(state=tk.NORMAL if self.app.editor_tabs else tk.DISABLED)
        else:
            listbox.config(state=tk.NORMAL)
            if self.popup_close_button is not None:
                self.popup_close_button.config(state=tk.NORMAL)
            if self.popup_clear_button is not None:
                self.popup_clear_button.config(state=tk.NORMAL)
        if not self.app.editor_tabs or not self.popup_visible_tab_indexes:
            preferred_index = None
            force_see = False
        if preferred_index is not None and preferred_index < 0:
            preferred_index = None
        yview = listbox.yview()
        xview = listbox.xview()
        if rows != self.popup_rows:
            listbox.config(state=tk.NORMAL)
            listbox.delete(0, tk.END)
            for row in rows:
                listbox.insert(tk.END, row)
            self.popup_rows = rows
            if not self.app.editor_tabs or not self.popup_visible_tab_indexes:
                listbox.config(state=tk.DISABLED)
            if yview:
                listbox.yview_moveto(yview[0])
            if xview:
                listbox.xview_moveto(xview[0])
        if not self.app.editor_tabs or not self.popup_visible_tab_indexes:
            return
        if preferred_index is None:
            preferred_index = self.app.active_tab_idx
        if preferred_index is not None and preferred_index >= 0:
            listbox.selection_clear(0, tk.END)
            if preferred_index in self.popup_visible_tab_indexes:
                visible_index = self.popup_visible_tab_indexes.index(preferred_index)
            else:
                visible_index = 0
            visible_index = min(visible_index, len(rows) - 1)
            listbox.selection_set(visible_index)
            listbox.activate(visible_index)
            if force_see:
                listbox.see(visible_index)
