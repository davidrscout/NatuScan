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
        self.fuzz_found = 0
        self.fuzz_errors = 0
        self.auto_rotate = False
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

        self.wordlist_btn = ctk.CTkButton(form, text="📂 Diccionario", width=120,
                                          command=self.load_wordlist, fg_color=c["BG_CARD"], hover_color=c["ACCENT_HOVER"],
                                          corner_radius=10, font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"])
        self.wordlist_btn.grid(row=0, column=2, padx=10, pady=10)

        self.lbl_wordlist = ctk.CTkLabel(form, text="Auto (indexando...)", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.lbl_wordlist.grid(row=1, column=1, sticky="w", padx=12, pady=(0, 10))

        self.wordlist_mode = ctk.CTkSegmentedButton(
            form,
            values=["Auto", "Manual"],
            fg_color=c["BG_CARD"],
            selected_color=c["ACCENT"],
            text_color=c["TEXT_PRIMARY"],
            command=self.set_wordlist_mode,
        )
        self.wordlist_mode.set("Auto")
        self.wordlist_mode.grid(row=1, column=2, padx=10, pady=(0, 10))
        self.set_wordlist_mode("Auto")

        self.wordlist_size = ctk.CTkSegmentedButton(
            form,
            values=["Pequeña", "Media", "Grande"],
            fg_color=c["BG_CARD"],
            selected_color=c["ACCENT"],
            text_color=c["TEXT_PRIMARY"],
            command=self.set_wordlist_size,
        )
        self.wordlist_size.set("Pequeña")
        self.wordlist_size.grid(row=2, column=1, padx=12, pady=(0, 10), sticky="w")

        self.auto_rotate_check = ctk.CTkCheckBox(form, text="Auto probar más wordlists", text_color=c["TEXT_PRIMARY"],
                                                 fg_color=c["ACCENT"], command=self.toggle_auto_rotate)
        self.auto_rotate_check.grid(row=2, column=2, padx=10, pady=(0, 10))

        self.btn_fuzz = ctk.CTkButton(self, text="Iniciar Fuzzing (50 hilos)", fg_color=c["ACCENT"],
                                      hover_color=c["ACCENT_HOVER"], corner_radius=12, font=UI_FONT_BOLD,
                                      command=self.start_fuzzing)
        self.btn_fuzz.pack(fill="x", padx=10, pady=12)

        self.btn_open_first = ctk.CTkButton(self, text="Abrir primer resultado", fg_color=c["BG_PANEL"],
                                            hover_color=c["ACCENT_HOVER"], corner_radius=12, font=UI_FONT_BOLD,
                                            command=self.open_first_result, state="disabled")
        self.btn_open_first.pack(fill="x", padx=10, pady=(0, 8))

        self.fuzz_results = ctk.CTkTextbox(self, height=420, font=MONO_FONT,
                                           fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"])
        self.fuzz_results.pack(fill="both", expand=True, padx=10, pady=10)
        self.refresh_wordlist_status()

    def toggle_auto_rotate(self):
        self.auto_rotate = bool(self.auto_rotate_check.get())

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
            self.wordlist_mode.set("Manual")
            self.set_wordlist_mode("Manual")
            if self.app.logger:
                self.app.logger.fuzzer(f"Wordlist cargada: {filename}")

    def set_wordlist_mode(self, value):
        if value == "Manual":
            self.wordlist_btn.configure(state="normal")
        else:
            self.wordlist_btn.configure(state="disabled")
            self.refresh_wordlist_status()

    def set_wordlist_size(self, value):
        self.refresh_wordlist_status()

    def refresh_wordlist_status(self):
        if self.wordlist_mode.get() != "Auto":
            return
        if self.app.wordlists.scanning or not self.app.wordlists.ready:
            self.lbl_wordlist.configure(text="Auto (indexando...)")
            return
        if not self.app.wordlists.index:
            self.lbl_wordlist.configure(text="Auto: configura carpeta en Config")
            return
        size = self._map_size()
        path = self.app.wordlists.pick_for_task("web", size=size)
        if path:
            self.wordlist_path = path
            self.lbl_wordlist.configure(text=f"Auto: ...{os.path.basename(path)}")
        else:
            self.lbl_wordlist.configure(text="Auto: sin wordlist")

    def _map_size(self):
        value = self.wordlist_size.get()
        if value == "Grande":
            return "large"
        if value == "Media":
            return "medium"
        return "small"

    def start_fuzzing(self):
        if self.fuzzing_active:
            self.fuzzing_active = False
            self.btn_fuzz.configure(text="Iniciar Fuzzing (50 hilos)", fg_color=self.app.c["ACCENT"], hover_color=self.app.c["ACCENT_HOVER"])
            self.log_fuzz("[-] Deteniendo...")
            if self.app.logger:
                self.app.logger.fuzzer("Deteniendo fuzzing...")
            return
        url = self.fuzz_url_entry.get()
        if self.wordlist_mode.get() == "Auto":
            self.refresh_wordlist_status()
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
        self.fuzz_found = 0
        self.fuzz_errors = 0
        self.btn_fuzz.configure(text="DETENER", fg_color=self.app.c["TEXT_DANGER"], hover_color="#dc2626")
        self.fuzz_results.delete("1.0", "end")
        self.log_fuzz(f"[*] Iniciando ataque a {url}")
        self.btn_open_first.configure(state="disabled")
        if self.app.logger:
            self.app.logger.fuzzer(f"Fuzzing iniciado: {url}")
            if self.wordlist_path:
                self.app.logger.fuzzer(f"Wordlist: {self.wordlist_path}")
        threading.Thread(target=self._run_fuzz_series, args=(url,), daemon=True).start()

    def _sync_target_from_url(self, url):
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname:
                self.app.context.set_target(parsed.hostname)
        except Exception:
            pass

    def _run_fuzz_series(self, base_url):
        wordlists = [self.wordlist_path]
        if self.wordlist_mode.get() == "Auto" and self.auto_rotate:
            size = self._map_size()
            suggestions = self.app.wordlists.suggestions_for_task("web", size=size, limit=5)
            wordlists = suggestions if suggestions else wordlists
        for idx, wl in enumerate(wordlists, 1):
            if not self.fuzzing_active:
                break
            self.wordlist_path = wl
            self.log_fuzz(f"[*] Wordlist {idx}/{len(wordlists)}: {os.path.basename(wl)}")
            self._run_single_fuzz(base_url)
            if self.fuzz_found > 0 or not self.auto_rotate:
                break
        if self.fuzz_found == 0:
            self.log_fuzz("[*] Sin resultados.")
        self.log_fuzz(f"[*] Escaneo finalizado. Encontrados: {self.fuzz_found} | Errores: {self.fuzz_errors}")
        if self.app.logger:
            self.app.logger.fuzzer("Fuzzing finalizado")
        self.after(0, self.reset_fuzz_ui)

    def _run_single_fuzz(self, base_url):
        try:
            words = load_wordlist(self.wordlist_path)
        except Exception as e:
            self.log_fuzz(f"[!] Error leyendo archivo: {e}")
            if self.app.logger:
                self.app.logger.error(f"Error leyendo diccionario: {e}", tag="FUZZER")
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

    def check_url(self, base_url, word):
        if not self.fuzzing_active:
            return
        try:
            code = check_url(base_url, word, timeout=3)
            if code is not None and code != 404:
                target = f"{base_url}/{word}"
                msg = f"[{code}] /{word}"
                self.app.context.add_fuzzer_path(target)
                self.fuzz_found += 1
                if self.app.logger:
                    self.app.logger.fuzzer(f"Encontrado {code}: {target}")
                self.after(0, lambda: self.log_fuzz(msg))
                if self.fuzz_found == 1:
                    self.after(0, lambda: self.btn_open_first.configure(state="normal"))
            elif code is None:
                self.fuzz_errors += 1
        except Exception:
            pass

    def log_fuzz(self, msg, color=None):
        self.fuzz_results.insert("end", msg + "\n")
        self.fuzz_results.see("end")

    def reset_fuzz_ui(self):
        self.fuzzing_active = False
        self.btn_fuzz.configure(text="Iniciar Fuzzing (50 hilos)", fg_color=self.app.c["ACCENT"], hover_color=self.app.c["ACCENT_HOVER"])

    def open_first_result(self):
        paths = self.app.context.fuzzer_results.get("found_paths", [])
        if not paths:
            return
        url = paths[0]
        viewer = self.app.panels.get("viewer")
        if viewer:
            viewer.open_url(url)
            self.app.show_panel("viewer")
