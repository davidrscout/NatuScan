import os
import threading
import concurrent.futures
import urllib.parse

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT
from ..services import load_wordlist, check_url


class FuzzerPanel(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.wordlist_path = None
        self.fuzzing_active = False
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Web Fuzzer", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)

        form = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        form.pack(fill="x", pady=10, padx=4)
        ctk.CTkLabel(form, text="URL Base", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=0, column=0, padx=12, pady=10, sticky="e")
        self.fuzz_url_entry = ctk.CTkEntry(form, width=320, placeholder_text="http://192.168.1.X",
                                           fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                           corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.fuzz_url_entry.grid(row=0, column=1, padx=12, pady=10, sticky="w")

        ctk.CTkButton(form, text="📂 Diccionario", width=120,
                      command=self.load_wordlist, fg_color=c["BG_CARD"], hover_color=c["ACCENT_HOVER"],
                      corner_radius=10, font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=0, column=2, padx=10, pady=10)
        self.lbl_wordlist = ctk.CTkLabel(form, text="Ninguno seleccionado", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.lbl_wordlist.grid(row=1, column=1, sticky="w", padx=12, pady=(0, 10))

        self.btn_fuzz = ctk.CTkButton(self, text="Iniciar Fuzzing (50 hilos)", fg_color=c["ACCENT"],
                                      hover_color=c["ACCENT_HOVER"], corner_radius=12, font=UI_FONT_BOLD,
                                      command=self.start_fuzzing)
        self.btn_fuzz.pack(fill="x", padx=10, pady=12)

        self.fuzz_results = ctk.CTkTextbox(self, height=420, font=MONO_FONT,
                                           fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"])
        self.fuzz_results.pack(fill="both", expand=True, padx=10, pady=10)

    def set_target_url(self, url):
        self.fuzz_url_entry.delete(0, "end")
        self.fuzz_url_entry.insert(0, url)
        self.fuzz_url_entry.focus()

    def sync_from_context(self):
        current = self.fuzz_url_entry.get().strip()
        if current:
            return
        url = self.app.context.get_target_as_url()
        if url:
            self.set_target_url(url)

    def load_wordlist(self):
        from tkinter import filedialog
        filename = filedialog.askopenfilename(title="Selecciona Wordlist (txt)")
        if filename:
            self.wordlist_path = filename
            self.lbl_wordlist.configure(text=f"...{os.path.basename(filename)}")
            if self.app.logger:
                self.app.logger.fuzzer(f"Wordlist cargada: {filename}")

    def start_fuzzing(self):
        if self.fuzzing_active:
            self.fuzzing_active = False
            self.btn_fuzz.configure(text="Iniciar Fuzzing (50 hilos)", fg_color=self.app.c["ACCENT"], hover_color=self.app.c["ACCENT_HOVER"])
            self.log_fuzz("[-] Deteniendo...")
            if self.app.logger:
                self.app.logger.fuzzer("Deteniendo fuzzing...")
            return
        url = self.fuzz_url_entry.get()
        if not url and self.app.context.current_target:
            url = self.app.context.get_target_as_url()
            self.set_target_url(url)
        if not url or not self.wordlist_path:
            self.log_fuzz("[!] Falta URL o diccionario.")
            if self.app.logger:
                self.app.logger.warn("Falta URL o diccionario", tag="FUZZER")
            return
        if not url.startswith("http"):
            url = "http://" + url
        self._sync_target_from_url(url)
        self.app.context.clear_fuzzer_results()
        self.fuzzing_active = True
        self.btn_fuzz.configure(text="DETENER", fg_color=self.app.c["TEXT_DANGER"], hover_color="#dc2626")
        self.fuzz_results.delete("1.0", "end")
        self.log_fuzz(f"[*] Iniciando ataque a {url}")
        if self.app.logger:
            self.app.logger.fuzzer(f"Fuzzing iniciado: {url}")
        threading.Thread(target=self.run_fuzz_threads, args=(url,), daemon=True).start()

    def _sync_target_from_url(self, url):
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname:
                self.app.context.set_target(parsed.hostname)
        except Exception:
            pass

    def run_fuzz_threads(self, base_url):
        try:
            words = load_wordlist(self.wordlist_path)
        except Exception as e:
            self.log_fuzz(f"[!] Error leyendo archivo: {e}")
            if self.app.logger:
                self.app.logger.error(f"Error leyendo diccionario: {e}", tag="FUZZER")
            self.reset_fuzz_ui()
            return
        total = len(words)
        self.log_fuzz(f"[*] Diccionario cargado: {total} palabras.")
        if self.app.logger:
            self.app.logger.fuzzer(f"Diccionario cargado: {total} palabras")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for word in words:
                if not self.fuzzing_active:
                    break
                futures.append(executor.submit(self.check_url, base_url, word))
            concurrent.futures.wait(futures)
        self.log_fuzz("[*] Escaneo finalizado.")
        if self.app.logger:
            self.app.logger.fuzzer("Fuzzing finalizado")
        self.after(0, self.reset_fuzz_ui)

    def check_url(self, base_url, word):
        if not self.fuzzing_active:
            return
        try:
            code = check_url(base_url, word, timeout=3)
            if code is not None and code != 404:
                target = f"{base_url}/{word}"
                msg = f"[{code}] /{word}"
                self.app.context.add_fuzzer_path(target)
                if self.app.logger:
                    self.app.logger.fuzzer(f"Encontrado {code}: {target}")
                self.after(0, lambda: self.log_fuzz(msg))
        except Exception:
            pass

    def log_fuzz(self, msg, color=None):
        self.fuzz_results.insert("end", msg + "\n")
        self.fuzz_results.see("end")

    def reset_fuzz_ui(self):
        self.fuzzing_active = False
        self.btn_fuzz.configure(text="Iniciar Fuzzing (50 hilos)", fg_color=self.app.c["ACCENT"], hover_color=self.app.c["ACCENT_HOVER"])
