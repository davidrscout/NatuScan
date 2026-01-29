import ctypes
import ipaddress
import os
import socket
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
        self.summary_label = ctk.CTkLabel(hero, text="Puertos: 0", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.summary_label.pack(side="right", padx=12)
        self.btn_raw = ctk.CTkButton(hero, text="Ver salida", fg_color=c["BG_PANEL"], hover_color=c["ACCENT_HOVER"],
                                     corner_radius=10, font=UI_FONT_BOLD, command=self.open_raw_output)
        self.btn_raw.pack(side="right", padx=8, pady=10)

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

        self.btn_cancel = ctk.CTkButton(form, text="Cancelar", width=120, height=42,
                                        fg_color=c["BG_PANEL"], hover_color=c["ACCENT_HOVER"],
                                        corner_radius=12, font=UI_FONT_BOLD,
                                        command=self.cancel_scan, state="disabled")
        self.btn_cancel.grid(row=0, column=3, padx=10, pady=12)

        ctk.CTkLabel(form, text="Modo:", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")
        self.scan_mode = ctk.CTkOptionMenu(
            form,
            values=["Rápido", "Normal", "Completo"],
            fg_color=c["BG_CARD"],
            button_color=c["ACCENT"],
            button_hover_color=c["ACCENT_HOVER"],
            dropdown_fg_color=c["BG_CARD"],
            dropdown_text_color=c["TEXT_PRIMARY"],
            text_color=c["TEXT_PRIMARY"],
            font=UI_FONT,
        )
        self.scan_mode.set("Normal")
        self.scan_mode.grid(row=1, column=1, padx=10, pady=(0, 10), sticky="w")

        ctk.CTkLabel(form, text="Puertos:", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(row=1, column=2, padx=10, pady=(0, 10), sticky="w")
        self.entry_ports = ctk.CTkEntry(
            form,
            width=180,
            placeholder_text="80,443,1-1024",
            fg_color=c["BG_CARD"],
            border_color=c["ACCENT_SECONDARY"],
            border_width=1,
            corner_radius=10,
            text_color=c["TEXT_PRIMARY"],
            font=UI_FONT,
        )
        self.entry_ports.grid(row=1, column=3, padx=10, pady=(0, 10), sticky="w")

        ctk.CTkLabel(form, text="Timeout (s):", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(
            row=2, column=0, padx=14, pady=(0, 10), sticky="w"
        )
        self.entry_timeout = ctk.CTkEntry(
            form,
            width=100,
            placeholder_text="300",
            fg_color=c["BG_CARD"],
            border_color=c["ACCENT_SECONDARY"],
            border_width=1,
            corner_radius=10,
            text_color=c["TEXT_PRIMARY"],
            font=UI_FONT,
        )
        self.entry_timeout.insert(0, "300")
        self.entry_timeout.grid(row=2, column=1, padx=10, pady=(0, 10), sticky="w")

        self.chk_no_dns = ctk.CTkCheckBox(
            form,
            text="No DNS (-n)",
            text_color=c["TEXT_PRIMARY"],
            fg_color=c["ACCENT"],
        )
        self.chk_no_dns.grid(row=2, column=2, padx=10, pady=(0, 10), sticky="w")

        self.chk_udp = ctk.CTkCheckBox(
            form,
            text="UDP (-sU)",
            text_color=c["TEXT_PRIMARY"],
            fg_color=c["ACCENT"],
        )
        self.chk_udp.grid(row=2, column=3, padx=10, pady=(0, 10), sticky="w")

        self.chk_os = ctk.CTkCheckBox(
            form,
            text="OS (-O)",
            text_color=c["TEXT_PRIMARY"],
            fg_color=c["ACCENT"],
        )
        self.chk_os.grid(row=3, column=0, padx=14, pady=(0, 10), sticky="w")

        self.chk_scripts = ctk.CTkCheckBox(
            form,
            text="Scripts (-sC)",
            text_color=c["TEXT_PRIMARY"],
            fg_color=c["ACCENT"],
        )
        self.chk_scripts.grid(row=3, column=1, padx=10, pady=(0, 10), sticky="w")

        self.progress_bar = ctk.CTkProgressBar(form, width=360, progress_color=c["ACCENT"], fg_color=c["BG_CARD"], corner_radius=10)
        self.progress_bar.grid(row=4, column=0, columnspan=4, padx=14, pady=(0, 12))
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
        scan_args, timeout = self._build_scan_args(target)
        if not scan_args:
            return
        if self.app.context.current_target == target:
            self.app.context.clear_scan_results()
        else:
            self.app.context.set_target(target)
        resolved = self._resolve_target(target)
        if self.app.logger:
            self.app.logger.scan(f"Escaneo iniciado: {target}")
            if resolved and resolved != target:
                self.app.logger.scan(f"Objetivo resuelto: {resolved}")
            self.app.logger.scan(f"CMD: nmap {scan_args} {target}")
            if timeout:
                self.app.logger.scan(f"Timeout: {timeout}s")
        self.btn_scan.configure(state="disabled", text="ESCANEANDO...")
        self.btn_cancel.configure(state="normal")
        self.status_indicator.configure(text="SCANNING", text_color=self.app.c["TEXT_WARNING"])
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        self._scan_running = True
        self._use_stats = True
        try:
            import time as _time
            self._scan_start_ts = _time.time()
        except Exception:
            self._scan_start_ts = 0
        self._start_scan_heartbeat()
        self._scan_cancel_event = threading.Event()
        threading.Thread(target=self.proceso_escaneo_backend, args=(target, scan_args, timeout), daemon=True).start()

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

    def proceso_escaneo_backend(self, target, scan_args, timeout):
        try:
            datos, raw = scan_target(
                target,
                return_raw=True,
                scan_args=scan_args,
                scan_timeout=timeout,
                stream_callback=self._log_nmap_stream,
                stats_interval=10,
                cancel_event=self._scan_cancel_event,
            )
            self.app.context.set_scan_raw_output(raw or "")
            if self.app.logger:
                self.app.logger.scan(f"Escaneo finalizado: {len(datos)} puertos abiertos en {target}")
            self.after(0, lambda: self.mostrar_resultados(datos))
        except RuntimeError as e:
            msg = str(e)
            if msg == "Escaneo cancelado":
                if self.app.logger:
                    self.app.logger.warn("Escaneo cancelado", tag="SCAN")
                self.after(0, self.finish_cancelled)
            else:
                if self.app.logger:
                    self.app.logger.error(msg, tag="SCAN")
                self.after(0, lambda: Toast(self.app, msg, self.app.c))
                self.after(0, self.reset_gui_error)
        except Exception as e:
            if self.app.logger:
                self.app.logger.error(f"Error escaneo {target}: {e}", tag="SCAN")
            self.after(0, self.reset_gui_error)
        finally:
            self._scan_running = False
            if getattr(self, "_scan_heartbeat_id", None):
                try:
                    self.after_cancel(self._scan_heartbeat_id)
                except Exception:
                    pass
                self._scan_heartbeat_id = None
            self.after(0, lambda: self.btn_cancel.configure(state="disabled"))

    def reset_gui_error(self):
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(0)
        self.btn_scan.configure(state="normal", text="ERROR - REVISAR")
        self.btn_cancel.configure(state="disabled")
        self.status_indicator.configure(text="ERROR", text_color=self.app.c["TEXT_DANGER"])
        self.summary_label.configure(text="Puertos: -")
        self._scan_running = False

    def finish_cancelled(self):
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(0)
        self.btn_scan.configure(state="normal", text="INICIAR ESCANEO")
        self.btn_cancel.configure(state="disabled")
        self.status_indicator.configure(text="CANCELADO", text_color=self.app.c["TEXT_WARNING"])
        self.summary_label.configure(text="Puertos: -")
        self._scan_running = False

    def mostrar_resultados(self, datos):
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1)
        self.btn_scan.configure(state="normal", text="INICIAR ESCANEO")
        self.btn_cancel.configure(state="disabled")
        self.status_indicator.configure(text="ONLINE", text_color=self.app.c["TEXT_SUCCESS"])
        ordered = sorted(datos, key=lambda x: int(x.get("port", 0)))
        self.summary_label.configure(text=f"Puertos: {len(ordered)}")
        self._scan_running = False

        c = self.app.c
        for item in ordered:
            try:
                self.app.context.add_scan_result(int(item["port"]), item["service"])
                if self.app.logger:
                    proto = item.get("proto", "tcp")
                    state = item.get("state", "open")
                    self.app.logger.scan(f"Puerto {item['port']}/{proto} {state} ({item['service']}) {item['version']}")
            except Exception:
                pass
        if not ordered:
            ctk.CTkLabel(self.results_frame, text="No se encontraron puertos abiertos.", text_color=c["TEXT_MUTED"]).pack(pady=12)
            Toast(self.app, "0 puertos abiertos", c)
            if self.app.logger:
                self.app.logger.scan("Sin puertos abiertos (posible filtrado o host inaccesible).")
            return

        header = ctk.CTkFrame(self.results_frame, fg_color=c["BG_CARD"], corner_radius=10)
        header.pack(fill="x", pady=4, padx=8)
        ctk.CTkLabel(header, text="PUERTO", width=90, font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=10, pady=8)
        ctk.CTkLabel(header, text="ESTADO", width=110, font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=10, pady=8)
        ctk.CTkLabel(header, text="SERVICIO", width=150, font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=10, pady=8)
        ctk.CTkLabel(header, text="VERSIÓN", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=10, pady=8)

        for item in ordered:
            fila = ctk.CTkFrame(self.results_frame, fg_color=c["BG_PANEL"])
            fila.pack(fill="x", pady=2, padx=6)
            color_p = c["TEXT_DANGER"] if item['port'] in ["22", "3389", "445"] else c["ACCENT_SECONDARY"]
            proto = item.get("proto", "tcp")
            state = item.get("state", "open")
            port_label = f"{item['port']}/{proto}" if proto != "tcp" else item["port"]
            btn_port = ctk.CTkButton(fila, text=port_label, width=90, fg_color=color_p,
                                     hover=False, corner_radius=10, font=UI_FONT_BOLD, text_color="#0b0b0b")
            btn_port.pack(side="left", padx=8, pady=4)
            btn_port.bind("<Button-3>", lambda e, p=item['port'], s=item['service']: self.ctx_menu(e, p, s))
            ctk.CTkLabel(fila, text=state, width=110, anchor="w", text_color=c["TEXT_PRIMARY"], font=UI_FONT).pack(side="left", padx=8)
            ctk.CTkLabel(fila, text=item['service'], width=150, anchor="w", text_color=c["TEXT_PRIMARY"], font=UI_FONT).pack(side="left", padx=8)
            ctk.CTkLabel(fila, text=item['version'], anchor="w", text_color=c["TEXT_MUTED"], font=UI_FONT).pack(side="left", padx=8)

    def _build_scan_args(self, target):
        base_args = ["-Pn", "-sV", "-T4", "--open"]
        mode = (self.scan_mode.get() or "Normal").strip()
        ports = self.entry_ports.get().strip()
        timeout = self._parse_timeout()
        if timeout:
            base_args.extend(["--host-timeout", f"{timeout}s"])
        if self.chk_no_dns.get():
            if self._is_ip(target):
                base_args.append("-n")
            else:
                Toast(self.app, "No DNS desactivado (objetivo es dominio)", self.app.c)
                if self.app.logger:
                    self.app.logger.warn("No DNS omitido: objetivo es dominio", tag="SCAN")
        if self.chk_scripts.get():
            base_args.append("-sC")
        if self.chk_os.get():
            if self._is_admin():
                base_args.append("-O")
            else:
                Toast(self.app, "OS detection requiere admin (se omite)", self.app.c)
                if self.app.logger:
                    self.app.logger.warn("OS detection requiere admin (omitido)", tag="SCAN")
        if self.chk_udp.get():
            base_args.extend(["-sU", "-sT"])
        if ports:
            if not self._validate_ports(ports):
                Toast(self.app, "Puertos inválidos", self.app.c)
                if self.app.logger:
                    self.app.logger.warn(f"Puertos inválidos: {ports}", tag="SCAN")
                return None, None
            base_args.extend(["-p", ports])
        else:
            if mode == "Rápido":
                base_args.append("-F")
            elif mode == "Completo":
                base_args.append("-p-")
        return " ".join(base_args), timeout

    def _validate_ports(self, text):
        cleaned = text.replace(" ", "")
        if not cleaned:
            return False
        for part in cleaned.split(","):
            if not part:
                continue
            if "-" in part:
                start, end = part.split("-", 1)
                if not start.isdigit() or not end.isdigit():
                    return False
                s = int(start)
                e = int(end)
                if s < 1 or e > 65535 or s > e:
                    return False
            else:
                if not part.isdigit():
                    return False
                val = int(part)
                if val < 1 or val > 65535:
                    return False
        return True

    def _parse_timeout(self):
        raw = self.entry_timeout.get().strip()
        if not raw:
            return None
        if not raw.isdigit():
            Toast(self.app, "Timeout inválido", self.app.c)
            if self.app.logger:
                self.app.logger.warn(f"Timeout inválido: {raw}", tag="SCAN")
            return None
        val = int(raw)
        if val < 5 or val > 7200:
            Toast(self.app, "Timeout fuera de rango (5-7200s)", self.app.c)
            if self.app.logger:
                self.app.logger.warn(f"Timeout fuera de rango: {val}", tag="SCAN")
            return None
        return val

    def _start_scan_heartbeat(self):
        if getattr(self, "_use_stats", False):
            return
        if getattr(self, "_scan_heartbeat_id", None):
            try:
                self.after_cancel(self._scan_heartbeat_id)
            except Exception:
                pass
        self._scan_heartbeat_id = self.after(20000, self._scan_heartbeat_tick)

    def _log_nmap_stream(self, kind, line):
        if not self.app.logger:
            return
        text = line.strip()
        if not text:
            return
        keywords = ("Stats:", "Nmap done", "Initiating", "Scanning", "Host is up", "Completed")
        if any(k in text for k in keywords):
            self.app.logger.scan(text)

    def cancel_scan(self):
        if getattr(self, "_scan_cancel_event", None) and self._scan_running:
            self._scan_cancel_event.set()
            if self.app.logger:
                self.app.logger.warn("Cancelando escaneo...", tag="SCAN")

    def _resolve_target(self, target):
        try:
            if self._is_ip(target):
                return target
            return socket.gethostbyname(target)
        except Exception:
            return None

    def _is_ip(self, text):
        try:
            ipaddress.ip_address(text)
            return True
        except Exception:
            return False

    def _scan_heartbeat_tick(self):
        if not getattr(self, "_scan_running", False):
            return
        try:
            import time as _time
            elapsed = int(_time.time() - (self._scan_start_ts or _time.time()))
        except Exception:
            elapsed = 0
        if self.app.logger:
            self.app.logger.scan(f"Escaneo en progreso... {elapsed}s")
        self._scan_heartbeat_id = self.after(20000, self._scan_heartbeat_tick)

    def _is_admin(self):
        try:
            if os.name == "nt":
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.geteuid() == 0
        except Exception:
            return False

    def ctx_menu(self, event, puerto, servicio):
        menu = tk.Menu(self, tearoff=0, bg="#1f1f2b", fg="white")
        menu.add_command(label=f"Puerto {puerto}", state="disabled")
        menu.add_separator()
        menu.add_command(label="Copiar puerto", command=lambda: self.clipboard_clear() or self.clipboard_append(puerto))
        if "http" in servicio or "80" in str(puerto) or "443" in str(puerto):
            menu.add_command(label="Abrir en navegador", command=lambda: webbrowser.open(self._build_http_url(puerto, servicio)))
            menu.add_command(label="Enviar a Fuzzer", command=lambda: self.send_to_fuzzer(puerto, servicio))
            menu.add_command(label="Abrir en Viewer", command=lambda: self.open_in_viewer(puerto, servicio))
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

    def open_raw_output(self):
        raw = self.app.context.scan_results.get("raw_output")
        if not raw:
            Toast(self.app, "Sin salida disponible", self.app.c)
            return
        viewer = self.app.panels.get("viewer")
        if viewer:
            viewer.open_content("nmap_output", raw)
            self.app.show_panel("viewer")

    def open_in_viewer(self, puerto, servicio):
        url = self._build_http_url(puerto, servicio)
        viewer = self.app.panels.get("viewer")
        if viewer:
            viewer.open_url(url)
            self.app.show_panel("viewer")
