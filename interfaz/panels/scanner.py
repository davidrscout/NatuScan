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
        form.pack(fill="x", pady=10, padx=14)
        ctk.CTkLabel(form, text="Objetivo (IP o Dominio)", text_color=c["TEXT_PRIMARY"], font=UI_FONT_BOLD).pack(side="left", padx=0, pady=12)
        self.entry_ip = ctk.CTkEntry(form, width=350, placeholder_text="192.168.1.1 o ejemplo.com",
                                     fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                     corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT)
        self.entry_ip.pack(side="left", padx=10, pady=12)

        self.btn_scan = ctk.CTkButton(form, text="▶ ESCANEAR", width=200, height=42,
                                      fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                                      corner_radius=12, font=UI_FONT_BOLD,
                                      command=self.iniciar_escaneo_visual)
        self.btn_scan.pack(side="left", padx=10, pady=12)

        self.btn_cancel = ctk.CTkButton(form, text="⏹ CANCELAR", width=150, height=42,
                                        fg_color=c["BG_PANEL"], hover_color=c["ACCENT_HOVER"],
                                        corner_radius=12, font=UI_FONT_BOLD,
                                        command=self.cancel_scan, state="disabled")
        self.btn_cancel.pack(side="left", padx=5, pady=12)

        self.progress_bar = ctk.CTkProgressBar(form, width=200, progress_color=c["ACCENT"], fg_color=c["BG_CARD"], corner_radius=10)
        self.progress_bar.pack(side="left", padx=10, pady=12)
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
            Toast(self.app, "IP o dominio inválido", self.app.c)
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
            self.app.logger.scan(f"🔍 Iniciando escaneo automático de: {target}")
            if resolved and resolved != target:
                self.app.logger.scan(f"   Resuelto a: {resolved}")
            self.app.logger.scan(f"   📋 Pasada 1: Puertos 1-10000 (rápido)")
            self.app.logger.scan(f"   📋 Pasada 2: Puertos 1-65535 (si Pasada 1 vacía)")
            self.app.logger.scan(f"   Comando: nmap {scan_args}")
        self.btn_scan.configure(state="disabled", text="⏳ ESCANEANDO...")
        self.btn_cancel.configure(state="normal")
        self.status_indicator.configure(text="ESCANEANDO", text_color=self.app.c["TEXT_WARNING"])
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
            # PASADA 1: Escaneo rápido de puertos comunes (1-10000)
            if self.app.logger:
                self.app.logger.scan("📊 Pasada 1/2: Escaneando puertos 1-10000...")
            
            datos, raw = scan_target(
                target,
                return_raw=True,
                scan_args=scan_args,
                scan_timeout=timeout,
                stream_callback=self._log_nmap_stream,
                stats_interval=5,
                cancel_event=self._scan_cancel_event,
            )
            self.app.context.set_scan_raw_output(raw or "")
            
            # Si no encuentra puertos, hacer pasada 2 más agresiva
            if not datos or len(datos) == 0:
                if self.app.logger:
                    self.app.logger.scan("❌ Pasada 1 sin resultados. Iniciando Pasada 2/2...")
                    self.app.logger.scan("📊 Pasada 2/2: Escaneando todos los puertos (1-65535)...")
                
                # Reiniciar la barra de progreso
                self.after(0, lambda: self._reset_progress_bar())
                
                # Pasada 2: Escaneo completo de todos los puertos
                scan_args_2 = "-Pn -sV -sC --open -T4 -p 1-65535"
                datos, raw = scan_target(
                    target,
                    return_raw=True,
                    scan_args=scan_args_2,
                    scan_timeout=timeout,
                    stream_callback=self._log_nmap_stream,
                    stats_interval=5,
                    cancel_event=self._scan_cancel_event,
                )
                self.app.context.set_scan_raw_output(raw or "")
                
                if self.app.logger:
                    if datos and len(datos) > 0:
                        self.app.logger.scan(f"✅ Pasada 2 completada: {len(datos)} puertos abiertos encontrados")
                    else:
                        self.app.logger.scan("❌ Pasada 2 completada: Sin puertos abiertos")
            else:
                if self.app.logger:
                    self.app.logger.scan(f"✅ Pasada 1 completada: {len(datos)} puertos abiertos encontrados")
            
            if self.app.logger:
                self.app.logger.scan(f"🏁 Escaneo finalizado: {len(datos)} puertos en total")
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
        self.progress_bar.set(1.0)
        self.btn_scan.configure(state="normal", text="▶ ESCANEAR")
        self.btn_cancel.configure(state="disabled")
        
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
                    self.app.logger.scan(f"   🔓 Puerto {item['port']}/{proto} {state} ({item['service']}) {item['version']}")
            except Exception:
                pass
        
        if not ordered:
            self.status_indicator.configure(text="SIN PUERTOS", text_color=c["TEXT_WARNING"])
            ctk.CTkLabel(self.results_frame, text="⚠️ No se encontraron puertos abiertos", text_color=c["TEXT_MUTED"], font=UI_FONT_BOLD).pack(pady=12)
            Toast(self.app, "0 puertos abiertos", c)
            if self.app.logger:
                self.app.logger.scan("❌ Sin puertos abiertos (posible filtrado o host inaccesible).")
            return

        self.status_indicator.configure(text="ONLINE", text_color=c["TEXT_SUCCESS"])
        
        # Header
        header = ctk.CTkFrame(self.results_frame, fg_color=c["BG_CARD"], corner_radius=10)
        header.pack(fill="x", pady=8, padx=8)
        
        col_headers = [
            ("PUERTO", 80),
            ("SERVICIO", 140),
            ("VERSIÓN", 250),
            ("ESTADO", 100)
        ]
        
        for title, width in col_headers:
            ctk.CTkLabel(header, text=title, width=width, font=UI_FONT_BOLD, text_color=c["ACCENT"]).pack(side="left", padx=12, pady=10)

        # Resultados
        for item in ordered:
            fila = ctk.CTkFrame(self.results_frame, fg_color=c["BG_CARD"], corner_radius=8)
            fila.pack(fill="x", pady=3, padx=8)
            
            # Puerto (color según riesgo)
            puerto = item['port']
            proto = item.get("proto", "tcp")
            puertos_riesgo = ["22", "3389", "445", "139", "135", "3306", "5432", "6379", "27017"]
            color_p = c["TEXT_DANGER"] if puerto in puertos_riesgo else c["ACCENT"]
            port_label = f"{puerto}/{proto}" if proto != "tcp" else puerto
            
            btn_port = ctk.CTkButton(
                fila, text=port_label, width=80, 
                fg_color=color_p, hover_color=color_p,
                corner_radius=6, font=UI_FONT_BOLD, text_color="#fff",
                command=lambda p=puerto, s=item['service']: self.ctx_menu(None, p, s)
            )
            btn_port.pack(side="left", padx=10, pady=8)
            
            # Servicio
            service = item['service'] or "desconocido"
            ctk.CTkLabel(fila, text=service, width=140, anchor="w", text_color=c["TEXT_PRIMARY"], font=UI_FONT).pack(side="left", padx=8)
            
            # Versión (con detección de tecnología)
            version = item.get('version', '').strip()
            if not version:
                version = "sin versión"
            version_display = version[:50] if len(version) > 50 else version
            ctk.CTkLabel(fila, text=version_display, width=250, anchor="w", text_color=c["TEXT_MUTED"], font=UI_FONT).pack(side="left", padx=8)
            
            # Estado
            state = item.get("state", "open").upper()
            state_color = c["TEXT_SUCCESS"] if state == "OPEN" else c["TEXT_WARNING"]
            ctk.CTkLabel(fila, text=state, width=100, anchor="w", text_color=state_color, font=UI_FONT_BOLD).pack(side="left", padx=8)

    def _build_scan_args(self, target):
        # Escaneo automático inteligente - Primera pasada: rápida
        base_args = ["-Pn", "-sV", "-sC", "--open", "-T4"]
        base_args.extend(["-p", "1-10000"])  # Puertos comunes
        return " ".join(base_args), None  # Sin timeout

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
        
        # Extraer información de progreso
        if "Stats:" in text:
            # Ejemplo: "Stats: 0:00:05 elapsed; 0 hosts completed (1 up)"
            self.app.logger.scan(f"⏱️ {text}")
            # Extraer porcentaje si está disponible
            import re
            progress_match = re.search(r'(\d+)%', text)
            if progress_match:
                progress = int(progress_match.group(1))
                self.after(0, lambda p=progress: self._update_progress(p))
        elif "Nmap done" in text:
            self.app.logger.scan(f"✅ {text}")
        elif "Initiating" in text:
            self.app.logger.scan(f"🔍 {text}")
        elif "Scanning" in text:
            self.app.logger.scan(f"🔎 {text}")
        elif "Host is up" in text:
            self.app.logger.scan(f"✓ {text}")
        elif "Completed" in text:
            # Mostrar progreso
            self.app.logger.scan(f"📊 {text}")
            import re
            progress_match = re.search(r'(\d+)%', text)
            if progress_match:
                progress = int(progress_match.group(1))
                self.after(0, lambda p=progress: self._update_progress(p))

    def _update_progress(self, percentage):
        """Actualizar la barra de progreso"""
        if not self._scan_running:
            return
        try:
            # Limitar entre 0 y 1
            progress = min(100, max(0, percentage))
            self.progress_bar.configure(mode="determinate")
            self.progress_bar.set(progress / 100.0)
            self.summary_label.configure(text=f"Progreso: {progress}%")
        except Exception:
            pass
    
    def _reset_progress_bar(self):
        """Reiniciar la barra de progreso para la pasada 2"""
        try:
            self.progress_bar.set(0)
            self.progress_bar.configure(mode="indeterminate")
            self.progress_bar.start()
        except Exception:
            pass

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
            elapsed_str = f"{elapsed//60}m {elapsed%60}s" if elapsed >= 60 else f"{elapsed}s"
        except Exception:
            elapsed_str = "?"
        if self.app.logger:
            self.app.logger.scan(f"⏳ Escaneo en progreso... {elapsed_str}")
        self._scan_heartbeat_id = self.after(15000, self._scan_heartbeat_tick)  # Cada 15 segundos

    def _is_admin(self):
        try:
            if os.name == "nt":
                # Windows
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Unix/Linux/Mac
                return os.geteuid() == 0
        except Exception:
            return False

    def ctx_menu(self, event, puerto, servicio):
        menu = tk.Menu(self, tearoff=0, bg="#1f1f2b", fg="white")
        menu.add_command(label=f"🔌 Puerto {puerto}", state="disabled")
        menu.add_separator()
        menu.add_command(label="📋 Copiar puerto", command=lambda: self.clipboard_clear() or self.clipboard_append(puerto))
        if "http" in servicio.lower() or "80" in str(puerto) or "443" in str(puerto):
            menu.add_command(label="🌐 Abrir en navegador", command=lambda: webbrowser.open(self._build_http_url(puerto, servicio)))
            menu.add_command(label="🔓 Enviar a Fuzzer", command=lambda: self.send_to_fuzzer(puerto, servicio))
            menu.add_command(label="👁️ Abrir en Viewer", command=lambda: self.open_in_viewer(puerto, servicio))
        if event:
            menu.tk_popup(event.x_root, event.y_root)
        else:
            # Mostrar en el centro
            menu.tk_popup(self.winfo_x() + 100, self.winfo_y() + 100)

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
