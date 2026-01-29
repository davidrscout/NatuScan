import threading

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD


class ConfigPanel(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Configuración", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)
        ctk.CTkLabel(header, text="Rutas y comportamiento base", text_color=c["TEXT_MUTED"], font=UI_FONT).pack(side="left", padx=8, pady=14)

        wordlist_card = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        wordlist_card.pack(fill="x", pady=8)
        ctk.CTkLabel(wordlist_card, text="Carpeta de Wordlists", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=0, column=0, padx=12, pady=10, sticky="w")

        self.wordlist_root_entry = ctk.CTkEntry(wordlist_card, width=520, placeholder_text="Selecciona carpeta raíz",
                                                fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                                corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.wordlist_root_entry.grid(row=1, column=0, padx=12, pady=(0, 10), sticky="w")
        self._set_wordlist_entry()

        self.btn_wordlist_folder = ctk.CTkButton(wordlist_card, text="📂 Elegir", fg_color=c["BG_CARD"], hover_color=c["ACCENT_HOVER"],
                                                 corner_radius=10, font=UI_FONT_BOLD, command=self.choose_wordlist_root)
        self.btn_wordlist_folder.grid(row=1, column=1, padx=8, pady=(0, 10))

        self.btn_wordlist_scan = ctk.CTkButton(wordlist_card, text="Reindexar", fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                                               corner_radius=10, font=UI_FONT_BOLD, command=self.reindex_wordlists)
        self.btn_wordlist_scan.grid(row=1, column=2, padx=8, pady=(0, 10))

        self.wordlist_status = ctk.CTkLabel(wordlist_card, text="⏳ Sin indexar", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.wordlist_status.grid(row=2, column=0, padx=12, pady=(0, 10), sticky="w")
        if self.app.wordlists.ready and self.app.wordlists.index:
            self._finish_wordlist_scan(len(self.app.wordlists.index))

    def choose_wordlist_root(self):
        from tkinter import filedialog
        try:
            folder = filedialog.askdirectory(title="Selecciona carpeta de Wordlists")
            if not folder:
                if self.app.logger:
                    self.app.logger.utils("[⚠️] Selección de carpeta cancelada")
                return
                
            if self.app.logger:
                self.app.logger.utils(f"[⏳] Configurando wordlists en {folder}...")
                
            self.app.wordlists.set_roots([folder])
            self._set_wordlist_entry()
            self.reindex_wordlists()
            
            if self.app.logger:
                self.app.logger.utils(f"[✅] Carpeta configurada: {folder}")
        except Exception as e:
            if self.app.logger:
                self.app.logger.utils(f"[❌] Error configurando wordlists: {e}")

    def reindex_wordlists(self):
        if self.app.wordlists.scanning:
            if self.app.logger:
                self.app.logger.utils("[⚠️] Ya hay un indexado en progreso")
            return
        
        self.wordlist_status.configure(text="⏳ Indexando...")

        def run_scan():
            try:
                if self.app.logger:
                    self.app.logger.utils("[⏳] Iniciando reindexado de wordlists...")
                count = self.app.wordlists.scan()
                if self.app.logger:
                    self.app.logger.utils(f"[✅] Wordlists indexadas: {count}")
                self.after(0, lambda: self._finish_wordlist_scan(count))
            except Exception as e:
                error_msg = f"[❌] Error indexando wordlists: {e}"
                if self.app.logger:
                    self.app.logger.utils(error_msg)
                self.after(0, lambda: self.wordlist_status.configure(text=error_msg))

        threading.Thread(target=run_scan, daemon=True).start()

    def _finish_wordlist_scan(self, count):
        try:
            stats = self.app.wordlists.stats()
            summary = f"✅ Indexadas: {count} | web:{stats.get('web', 0)} pass:{stats.get('password', 0)} user:{stats.get('user', 0)} dns:{stats.get('dns', 0)}"
            self.wordlist_status.configure(text=summary)
            
            # Notify other panels of wordlist update
            try:
                if "fuzzer" in self.app.panels:
                    self.app.panels["fuzzer"].refresh_wordlist_status()
                if "crypto" in self.app.panels:
                    self.app.panels["crypto"].refresh_wordlist_status()
            except Exception as e:
                if self.app.logger:
                    self.app.logger.utils(f"[⚠️] Error notificando paneles: {e}")
        except Exception as e:
            error_msg = f"[❌] Error finalizando escaneo: {e}"
            if self.app.logger:
                self.app.logger.utils(error_msg)
            self.wordlist_status.configure(text=error_msg)

    def _set_wordlist_entry(self):
        roots = self.app.wordlists.roots or []
        text = roots[0] if roots else ""
        self.wordlist_root_entry.delete(0, "end")
        self.wordlist_root_entry.insert(0, text)
