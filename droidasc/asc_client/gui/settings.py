import tkinter as tk
from tkinter import ttk


class SettingsDialog:
    def __init__(self, app):
        self.app = app
        self.win = tk.Toplevel(app.root)
        self.win.title("Settings")
        self.win.transient(app.root)
        self.win.resizable(False, False)
        self.win.geometry("+%d+%d" % (app.root.winfo_rootx() + 96, app.root.winfo_rooty() + 96))
        self.theme_var = tk.StringVar(value=app.theme_name_var.get())

        self._build_ui()
        self.app.apply_theme_to_window(self.win)

    def _build_ui(self):
        body = ttk.Frame(self.win, padding=12)
        body.grid(row=0, column=0, sticky="nsew")
        body.columnconfigure(1, weight=1)

        ttk.Label(body, text="Theme").grid(row=0, column=0, sticky="w")
        combo = ttk.Combobox(
            body,
            textvariable=self.theme_var,
            values=self.app.theme_manager.names(),
            state="readonly",
            width=18,
        )
        combo.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        combo.bind("<<ComboboxSelected>>", self._on_theme_changed)

        actions = ttk.Frame(body)
        actions.grid(row=1, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(actions, text="Close", command=self.win.destroy).grid(row=0, column=0, sticky="e")

    def _on_theme_changed(self, _event = None):
        self.app.set_theme(self.theme_var.get())
