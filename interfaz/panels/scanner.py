import threading
import urllib.parse
import webbrowser
import tkinter as tk

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, Toast
from ..services import scan_target


class ScannerPanel(ctk.CTkFrame):
    def __init__(self, app):
        self.app = app
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.build()

    def build(self):
        c = self.app.c
        hero = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        hero.pack(fill="x", pady=8)
        ctk.CTkLabel(hero, text="Escaneo de Red", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)
        self.status_indicator = ctk.CTkLabel(hero, text="OFFLINE", text_color=c["TEXT_DANGER"], font=UI_FONT_BOLD)
        self.status_indicator.pack(side="right", padx=16)

        form = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        form.pack(fill="x", pady=10)
        ctk.CTkLabel(form, text="Objetivo / IP", text_color=c["TEXT_PRIMARY"], font=UI_FONT_BOLD).grid(row=0, column=0, padx=14, pady=12, sticky="w")
        self.entry_ip = ctk.CTkEntry(form, width=260, placeholder_text="192.168.1.10",
                                     fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                     corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.entry_ip.grid(row=0, column=1, padx=10, pady=12, sticky="w")

        self.btn_scan = ctk.CTkButton(form, text="Iniciar Escaneo", width=170, height=42,
                                      fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                                      corner_radius=12, font=UI_FONT_BOLD,
                                      command=self.iniciar_escaneo_visual)
        self.btn_scan.grid(row=0, column=2, padx=14, pady=12)

        self.progress_bar = ctk.CTkProgressBar(form, width=360, progress_color=c["ACCENT"], fg_color=c["BG_CARD"], corner_radius=10)
        self.progress_bar.grid(row=1, column=0, columnspan=3, padx=14, pady=(0, 12))
        self.progress_bar.set(0)

        self.results_frame = ctk.CTkScrollableFrame(self, fg_color=c["BG_PANEL"], height=480)
        self.results_frame.pack(fill="both", expand=True, pady=10, padx=4)
        self.empty_label = ctk.CTkLabel(self.results_frame, text="Inicia un escaneo para ver puertos y servicios.",
                                        text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.empty_label.pack(pady=20)

    def iniciar_escaneo_visual(self):
        for w in self.results_frame.winfo_children():
            w.destroy()
        raw_target = self.entry_ip.get().strip()
        target = self.normalize_target(raw_target)
        if not target:
            Toast(self.app, "Objetivo inválido", self.app.c)
            if self.app.logger:
                self.app.logger.warn("Objetivo inválido", tag="SCAN")
            return
        self.app.context.set_target(target)
        if self.app.logger:
            self.app.logger.scan(f"Escaneo iniciado: {target}")
        self.btn_scan.configure(state="disabled", text="ESCANEANDO...")
        self.status_indicator.configure(text="SCANNING", text_color=self.app.c["TEXT_WARNING"])
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        threading.Thread(target=self.proceso_escaneo_backend, args=(target,), daemon=True).start()

    def normalize_target(self, text):
        if not text:
            return None
        if text.startswith("http://") or text.startswith("https://"):
            try:
                parsed = urllib.parse.urlparse(text)
                host = parsed.hostname
                return host
            except Exception:
                return None
        if "/" in text:
            try:
                parsed = urllib.parse.urlparse("http://" + text)
                return parsed.hostname
            except Exception:
                return None
        return text

    def proceso_escaneo_backend(self, target):
        try:
            datos = scan_target(target)
            if self.app.logger:
                self.app.logger.scan(f"Escaneo finalizado: {len(datos)} puertos abiertos en {target}")
            self.after(0, lambda: self.mostrar_resultados(datos))
        except RuntimeError as e:
            if self.app.logger:
                self.app.logger.error(str(e), tag="SCAN")
            self.after(0, self.reset_gui_error)
        except Exception as e:
            if self.app.logger:
                self.app.logger.error(f"Error escaneo {target}: {e}", tag="SCAN")
            self.after(0, self.reset_gui_error)

    def reset_gui_error(self):
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(0)
        self.btn_scan.configure(state="normal", text="ERROR - REVISAR")
        self.status_indicator.configure(text="ERROR", text_color=self.app.c["TEXT_DANGER"])

    def mostrar_resultados(self, datos):
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1)
        self.btn_scan.configure(state="normal", text="INICIAR ESCANEO")
        self.status_indicator.configure(text="ONLINE", text_color=self.app.c["TEXT_SUCCESS"])

        c = self.app.c
        self.app.context.clear_scan_results()
        for item in datos:
            try:
                self.app.context.add_scan_result(int(item["port"]), item["service"])
                if self.app.logger:
                    self.app.logger.scan(f"Puerto {item['port']} abierto ({item['service']}) {item['version']}")
            except Exception:
                pass
        if not datos:
            ctk.CTkLabel(self.results_frame, text="No se encontraron puertos abiertos.", text_color=c["TEXT_MUTED"]).pack(pady=12)
            Toast(self.app, "0 puertos abiertos", c)
            if self.app.logger:
                self.app.logger.scan("Sin puertos abiertos.")
            return

        header = ctk.CTkFrame(self.results_frame, fg_color=c["BG_CARD"], corner_radius=10)
        header.pack(fill="x", pady=4, padx=8)
        ctk.CTkLabel(header, text="PUERTO", width=90, font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=10, pady=8)
        ctk.CTkLabel(header, text="SERVICIO", width=150, font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=10, pady=8)
        ctk.CTkLabel(header, text="VERSIÓN", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=10, pady=8)

        for item in datos:
            fila = ctk.CTkFrame(self.results_frame, fg_color=c["BG_PANEL"])
            fila.pack(fill="x", pady=2, padx=6)
            color_p = c["TEXT_DANGER"] if item['port'] in ["22", "3389", "445"] else c["ACCENT_SECONDARY"]
            btn_port = ctk.CTkButton(fila, text=item['port'], width=90, fg_color=color_p,
                                     hover=False, corner_radius=10, font=UI_FONT_BOLD, text_color="#0b0b0b")
            btn_port.pack(side="left", padx=8, pady=4)
            btn_port.bind("<Button-3>", lambda e, p=item['port'], s=item['service']: self.ctx_menu(e, p, s))
            ctk.CTkLabel(fila, text=item['service'], width=150, anchor="w", text_color=c["TEXT_PRIMARY"], font=UI_FONT).pack(side="left", padx=8)
            ctk.CTkLabel(fila, text=item['version'], anchor="w", text_color=c["TEXT_MUTED"], font=UI_FONT).pack(side="left", padx=8)

    def ctx_menu(self, event, puerto, servicio):
        menu = tk.Menu(self, tearoff=0, bg="#1f1f2b", fg="white")
        menu.add_command(label=f"Puerto {puerto}", state="disabled")
        menu.add_separator()
        menu.add_command(label="Copiar puerto", command=lambda: self.clipboard_clear() or self.clipboard_append(puerto))
        if "http" in servicio or "80" in str(puerto) or "443" in str(puerto):
            menu.add_command(label="Abrir en navegador", command=lambda: webbrowser.open(self._build_http_url(puerto, servicio)))
            menu.add_command(label="Enviar a Fuzzer", command=lambda: self.send_to_fuzzer(puerto, servicio))
        menu.tk_popup(event.x_root, event.y_root)

    def _build_http_url(self, puerto, servicio):
        protocol = "https" if str(puerto) == "443" or "https" in servicio else "http"
        host = self.app.context.current_target or self.normalize_target(self.entry_ip.get().strip()) or "127.0.0.1"
        return f"{protocol}://{host}:{puerto}"

    def send_to_fuzzer(self, puerto, servicio):
        url = self._build_http_url(puerto, servicio)
        fuzzer = self.app.panels.get("fuzzer")
        if fuzzer:
            fuzzer.set_target_url(url)
        if self.app.logger:
            self.app.logger.scan(f"Enviando a Fuzzer: {url}")
        self.app.show_panel("fuzzer")
