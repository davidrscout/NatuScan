import os
import json
import socket

import customtkinter as ctk

from .ui_constants import PALETTES, UI_FONT, UI_FONT_BOLD, Toast
from .context import AppContext
from .logger import AppLogger
from .panels import (
    ScannerPanel,
    ListenerPanel,
    PayloadsPanel,
    FuzzerPanel,
    UtilsPanel,
    CryptoPanel,
    LogsPanel,
    ViewerPanel,
)

CFG_PATH = os.path.join(os.path.expanduser("~"), ".cybernatu_theme.json")


class CyberNatuApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.logger = AppLogger()
        self.context = AppContext(logger=self.logger)
        self.theme = self.load_theme()
        self.c = PALETTES[self.theme]

        self.title("CyberNatu v2 - Startup Edition")
        self.geometry("1220x760")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.build_ui()

    def load_theme(self):
        if os.path.exists(CFG_PATH):
            try:
                with open(CFG_PATH, "r") as f:
                    data = json.load(f)
                    if data.get("theme") in PALETTES:
                        return data["theme"]
            except Exception:
                pass
        return "dark"

    def save_theme(self):
        try:
            with open(CFG_PATH, "w") as f:
                json.dump({"theme": self.theme}, f)
        except Exception:
            pass

    def build_ui(self):
        self.configure(fg_color=self.c["BG_MAIN"])

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, fg_color=self.c["BG_PANEL"], width=210, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(8, weight=1)

        ctk.CTkLabel(self.sidebar, text="⚡ CyberNatu", font=("Poppins", 18, "bold"), text_color=self.c["TEXT_PRIMARY"]).pack(pady=(18, 4))
        ctk.CTkLabel(self.sidebar, text="Startup Security", font=UI_FONT, text_color=self.c["TEXT_MUTED"]).pack(pady=(0, 14))

        self.theme_switch = ctk.CTkSegmentedButton(
            self.sidebar,
            values=["Dark", "Light"],
            command=self.toggle_theme,
            fg_color=self.c["BG_CARD"],
            selected_color=self.c["ACCENT"],
            text_color=self.c["TEXT_PRIMARY"]
        )
        self.theme_switch.set("Dark" if self.theme == "dark" else "Light")
        self.theme_switch.pack(pady=(0, 16), padx=12, fill="x")

        self.nav_buttons = {}
        nav_items = [
            ("🔍 Escáner", "scanner"),
            ("🎧 Listener", "listener"),
            ("💣 Payloads", "payloads"),
            ("🌐 Fuzzer", "fuzzer"),
            ("🛠 Utils", "utils"),
            ("🧬 Crypto", "crypto"),
            ("📜 Logs", "logs"),
            ("📂 Viewer", "viewer"),
        ]
        for text, key in nav_items:
            btn = ctk.CTkButton(self.sidebar, text=text, width=180, height=44,
                                fg_color="transparent", hover_color=self.c["ACCENT_HOVER"],
                                text_color=self.c["TEXT_MUTED"], corner_radius=10,
                                font=UI_FONT_BOLD,
                                command=lambda k=key: self.show_panel(k))
            btn.pack(pady=5, padx=12)
            self.nav_buttons[key] = btn

        ctk.CTkLabel(self.sidebar, text="v2.0", text_color=self.c["TEXT_MUTED"], font=UI_FONT).pack(pady=12)

        # Content
        self.content = ctk.CTkFrame(self, fg_color=self.c["BG_MAIN"])
        self.content.grid(row=0, column=1, sticky="nsew", padx=16, pady=16)
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        # Panels
        self.panels = {
            "scanner": ScannerPanel(self),
            "listener": ListenerPanel(self),
            "payloads": PayloadsPanel(self),
            "fuzzer": FuzzerPanel(self),
            "utils": UtilsPanel(self),
            "crypto": CryptoPanel(self),
            "logs": LogsPanel(self),
            "viewer": ViewerPanel(self),
        }
        for p in self.panels.values():
            p.grid(row=0, column=0, sticky="nsew")
        self.show_panel("scanner")

    def toggle_theme(self, value):
        self.theme = "dark" if value.lower() == "dark" else "light"
        self.c = PALETTES[self.theme]
        ctk.set_appearance_mode("Dark" if self.theme == "dark" else "Light")
        self.save_theme()
        for w in (self.sidebar, self.content):
            w.destroy()
        self.build_ui()
        Toast(self, f"Tema: {self.theme}", self.c)

    def show_panel(self, key):
        for k, panel in self.panels.items():
            panel.grid_remove()
            self.nav_buttons[k].configure(fg_color="transparent", text_color=self.c["TEXT_MUTED"])
        self.panels[key].grid()
        self.nav_buttons[key].configure(fg_color=self.c["ACCENT"], text_color=self.c["TEXT_PRIMARY"])
        if key == "fuzzer":
            self.panels["fuzzer"].sync_from_context()

    def obtener_ip_local(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip


def run_app():
    app = CyberNatuApp()
    app.mainloop()
