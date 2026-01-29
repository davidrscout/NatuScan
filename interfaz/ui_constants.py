import customtkinter as ctk

# Paletas estilo startup (toggle dark/light)
PALETTES = {
    "dark": {
        "BG_MAIN": "#08090d",
        "BG_PANEL": "#0e1016",
        "BG_CARD": "#12141d",
        "ACCENT": "#1f2937",          # negro azulado (sustituye azul)
        "ACCENT_HOVER": "#111827",    # negro más profundo
        "ACCENT_SECONDARY": "#2d2f3a", # gris oscuro (sustituye rosa)
        "TEXT_PRIMARY": "#e5e7eb",
        "TEXT_MUTED": "#9ca3af",
        "TEXT_SUCCESS": "#34d399",
        "TEXT_WARNING": "#fbbf24",
        "TEXT_DANGER": "#f87171",
        "BORDER": "#1c1f2a",
    },
    "light": {
        "BG_MAIN": "#f5f6f8",
        "BG_PANEL": "#eceef2",
        "BG_CARD": "#e4e6eb",
        "ACCENT": "#4b5563",          # gris (sustituye celeste)
        "ACCENT_HOVER": "#374151",    # gris más oscuro
        "ACCENT_SECONDARY": "#5b6070", # gris oscuro (sustituye rosa)
        "TEXT_PRIMARY": "#0f172a",
        "TEXT_MUTED": "#6b7280",
        "TEXT_SUCCESS": "#0ea371",
        "TEXT_WARNING": "#c26b0a",
        "TEXT_DANGER": "#b91c1c",
        "BORDER": "#d1d5db",
    },
}

MONO_FONT = ("Fira Code", 11)
UI_FONT = ("Segoe UI Rounded", 12)
UI_FONT_BOLD = ("Segoe UI Rounded", 12, "bold")


class Toast:
    def __init__(self, root, text, c):
        self.top = ctk.CTkToplevel(root)
        self.top.overrideredirect(True)
        self.top.attributes("-topmost", True)
        self.top.configure(fg_color=c["BG_CARD"])
        lbl = ctk.CTkLabel(self.top, text=text, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        lbl.pack(padx=12, pady=8)
        x = root.winfo_rootx() + root.winfo_width() - 260
        y = root.winfo_rooty() + root.winfo_height() - 120
        self.top.geometry(f"240x60+{x}+{y}")
        self.top.after(2000, self.top.destroy)
