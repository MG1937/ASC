from tkinter import ttk


THEMES = {
    "light": {
        "window_bg": "#f3f4f6",
        "panel_bg": "#f7f8fa",
        "surface": "#ffffff",
        "surface_alt": "#edf0f5",
        "tabbar_bg": "#d8dce3",
        "tab_active": "#ffffff",
        "tab_inactive": "#edf0f5",
        "tab_hover": "#d6dbe3",
        "border": "#b8c0cc",
        "border_light": "#c5ccd6",
        "accent": "#3a7afe",
        "text": "#141922",
        "muted_text": "#4b5563",
        "close_text": "#5a6472",
        "editor_bg": "#ffffff",
        "editor_fg": "#1f1f1f",
        "selection_bg": "#cde2ff",
        "selection_fg": "#111827",
        "java_keyword": "#0000cc",
        "java_comment": "#008000",
        "java_string": "#a31515",
        "java_annotation": "#2b91af",
        "active_line": "#eef5ff",
        "find_match": "#fff2a8",
        "find_current": "#ffc94d",
        "symbol_match": "#e8f1ff",
        "symbol_current": "#b8d7ff",
    },
    "dark": {
        "window_bg": "#1f2126",
        "panel_bg": "#24272e",
        "surface": "#1e1f22",
        "surface_alt": "#2b2f38",
        "tabbar_bg": "#202329",
        "tab_active": "#2c313a",
        "tab_inactive": "#252932",
        "tab_hover": "#343a45",
        "border": "#414854",
        "border_light": "#343a45",
        "accent": "#5b9cff",
        "text": "#e6eaf0",
        "muted_text": "#aeb6c2",
        "close_text": "#c0c7d2",
        "editor_bg": "#1e1e1e",
        "editor_fg": "#d4d4d4",
        "selection_bg": "#264f78",
        "selection_fg": "#ffffff",
        "java_keyword": "#569cd6",
        "java_comment": "#6a9955",
        "java_string": "#ce9178",
        "java_annotation": "#4ec9b0",
        "active_line": "#263240",
        "find_match": "#5f5222",
        "find_current": "#8a6f23",
        "symbol_match": "#2b3b4f",
        "symbol_current": "#365f8f",
    },
}


class ThemeManager:
    def __init__(self, root, name : str = "light"):
        self.root = root
        self.style = ttk.Style(root)
        self.name = None
        self.theme = None
        self.set_theme(name)

    def names(self):
        return tuple(THEMES.keys())

    def set_theme(self, name : str):
        if name not in THEMES:
            name = "light"
        self.name = name
        self.theme = THEMES[name]
        self._apply_ttk()

    def _apply_ttk(self):
        t = self.theme
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.style.configure(".", background=t["panel_bg"], foreground=t["text"])
        self.style.configure("TFrame", background=t["panel_bg"])
        self.style.configure("TLabel", background=t["panel_bg"], foreground=t["text"])
        self.style.configure("TButton", background=t["surface_alt"], foreground=t["text"], padding=(5, 1))
        self.style.map(
            "TButton",
            background=[("active", t["tab_hover"]), ("disabled", t["panel_bg"])],
            foreground=[("disabled", t["muted_text"])],
        )
        self.style.configure("TCheckbutton", background=t["panel_bg"], foreground=t["text"], padding=(2, 1))
        self.style.map(
            "TCheckbutton",
            background=[("active", t["panel_bg"])],
            foreground=[("disabled", t["muted_text"])],
        )
        self.style.configure(
            "TEntry",
            fieldbackground=t["surface"],
            foreground=t["text"],
            insertcolor=t["text"],
            padding=(3, 1),
        )
        self.style.configure(
            "TCombobox",
            fieldbackground=t["surface"],
            background=t["surface_alt"],
            foreground=t["text"],
            arrowcolor=t["text"],
            padding=(3, 1),
        )
        self.style.map(
            "TCombobox",
            fieldbackground=[("readonly", t["surface"])],
            foreground=[("readonly", t["text"])],
        )
        self.style.configure("TPanedwindow", background=t["window_bg"])
        self.style.configure(
            "Treeview",
            background=t["surface"],
            fieldbackground=t["surface"],
            foreground=t["text"],
            bordercolor=t["border"],
            lightcolor=t["border_light"],
            darkcolor=t["border"],
        )
        self.style.map(
            "Treeview",
            background=[("selected", t["accent"])],
            foreground=[("selected", "#ffffff")],
        )
        self.style.configure(
            "Treeview.Heading",
            background=t["surface_alt"],
            foreground=t["text"],
            padding=(3, 1),
        )
        self.style.configure(
            "Horizontal.TScrollbar",
            background=t["surface_alt"],
            troughcolor=t["panel_bg"],
            bordercolor=t["border"],
            arrowcolor=t["text"],
        )
        self.style.configure(
            "Vertical.TScrollbar",
            background=t["surface_alt"],
            troughcolor=t["panel_bg"],
            bordercolor=t["border"],
            arrowcolor=t["text"],
        )
        self.style.configure(
            "Horizontal.TProgressbar",
            background="#22c55e",
            troughcolor=t["surface_alt"],
            bordercolor=t["border"],
            lightcolor="#22c55e",
            darkcolor="#16a34a",
        )

    def apply_root(self, widget):
        widget.configure(background=self.theme["window_bg"])

    def apply_toplevel(self, win):
        win.configure(background=self.theme["panel_bg"])

    def apply_text(self, text):
        t = self.theme
        text.configure(
            background=t["editor_bg"],
            foreground=t["editor_fg"],
            insertbackground=t["editor_fg"],
            selectbackground=t["selection_bg"],
            selectforeground=t["selection_fg"],
        )

    def apply_listbox(self, listbox):
        t = self.theme
        listbox.configure(
            background=t["surface"],
            foreground=t["text"],
            highlightbackground=t["border_light"],
            selectbackground=t["accent"],
            selectforeground="#ffffff",
        )
