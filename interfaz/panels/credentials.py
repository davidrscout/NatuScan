import contextlib
import datetime
import io
import os
import threading

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT, Toast


class CredentialsPanel(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self._running = False
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(
            header,
            text="Auditoría de credenciales",
            font=("Poppins", 18, "bold"),
            text_color=c["TEXT_PRIMARY"],
        ).pack(side="left", padx=16, pady=14)
        ctk.CTkLabel(
            header,
            text="Datos locales del navegador",
            text_color=c["TEXT_MUTED"],
            font=UI_FONT,
        ).pack(side="left", padx=8, pady=14)

        actions = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        actions.pack(fill="x", pady=8)
        self.btn_analyze = ctk.CTkButton(
            actions,
            text="Analizar",
            fg_color=c["ACCENT"],
            hover_color=c["ACCENT_HOVER"],
            corner_radius=12,
            font=UI_FONT_BOLD,
            command=self.start_audit,
        )
        self.btn_analyze.grid(row=0, column=0, padx=12, pady=12)

        self.btn_clear = ctk.CTkButton(
            actions,
            text="Limpiar",
            fg_color=c["BG_CARD"],
            hover_color=c["ACCENT_HOVER"],
            corner_radius=12,
            font=UI_FONT_BOLD,
            command=self.clear_output,
        )
        self.btn_clear.grid(row=0, column=1, padx=8, pady=12)

        self.status = ctk.CTkLabel(actions, text="Listo.", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.status.grid(row=0, column=2, padx=12, pady=12, sticky="w")
        actions.grid_columnconfigure(2, weight=1)

        info = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        info.pack(fill="x", pady=8)
        ctk.CTkLabel(
            info,
            text="Aviso de seguridad",
            font=UI_FONT_BOLD,
            text_color=c["TEXT_WARNING"],
        ).pack(anchor="w", padx=12, pady=(10, 2))
        ctk.CTkLabel(
            info,
            text="Solo revisa esta información en un entorno seguro y bórrala al terminar.",
            font=UI_FONT,
            text_color=c["TEXT_MUTED"],
        ).pack(anchor="w", padx=12, pady=(0, 10))

        self.output = ctk.CTkTextbox(
            self,
            height=520,
            font=MONO_FONT,
            fg_color=c["BG_PANEL"],
            text_color=c["TEXT_PRIMARY"],
        )
        self.output.pack(fill="both", expand=True, padx=12, pady=12)
        self.output.insert("end", "Pulsa Analizar para ver resultados.\n")
        self.output.configure(state="disabled")

    def clear_output(self):
        try:
            self.output.configure(state="normal")
            self.output.delete("1.0", "end")
            self.output.insert("end", "Pulsa Analizar para ver resultados.\n")
            self.output.configure(state="disabled")
            if self.app.logger:
                self.app.logger.utils("[✅] Salida de auditoría limpiada")
        except Exception as e:
            if self.app.logger:
                self.app.logger.utils(f"[❌] Error limpiando salida: {e}")

    def start_audit(self):
        if self._running:
            if self.app.logger:
                self.app.logger.utils("[⚠️] Auditoría ya en progreso")
            return
        
        self._running = True
        self.btn_analyze.configure(state="disabled", text="ANALIZANDO...")
        self.status.configure(text="⏳ Analizando...", text_color=self.app.c["TEXT_WARNING"])
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", "🔐 Iniciando auditoría de credenciales...\n")
        self.output.configure(state="disabled")
        
        if self.app.logger:
            self.app.logger.utils("[⏳] Auditoría de credenciales iniciada")
        
        threading.Thread(target=self._audit_worker, daemon=True).start()

    def _audit_worker(self):
        try:
            if self.app.logger:
                self.app.logger.utils(f"[🔍] Sistema detectado: {os.name}")
            
            if os.name != "nt":
                result = "[⚠️] Este módulo solo funciona en Windows.\n\nUso: Requiere acceso a bases de datos de navegadores (SQLite) que están disponibles en Windows."
                self._finish_audit(result, warn=True)
                return
            
            try:
                from auditoria_credenciales.auditoria_credenciales import PasswordAuditor, WINDOWS
            except ImportError as exc:
                result = f"[❌] No se pudo cargar el módulo de auditoría:\n{exc}\n\nAsegúrate de que el módulo está instalado correctamente."
                self._finish_audit(result, warn=True)
                if self.app.logger:
                    self.app.logger.utils(f"[❌] ImportError: {exc}")
                return
            except Exception as exc:
                result = f"[❌] Error inesperado cargando módulo:\n{exc}"
                self._finish_audit(result, warn=True)
                if self.app.logger:
                    self.app.logger.utils(f"[❌] Error: {exc}")
                return

            if not WINDOWS:
                result = (
                    "[⚠️] Auditoría de credenciales no disponible\n\n"
                    "Requisitos:\n"
                    "- Windows (detectado: NO)\n"
                    "- win32crypt (parte de pywin32)\n"
                    "- pycryptodome\n\n"
                    "En Linux/Mac esta función no está disponible."
                )
                self._finish_audit(result, warn=True)
                if self.app.logger:
                    self.app.logger.utils("[⚠️] WINDOWS flag es False")
                return

            if self.app.logger:
                self.app.logger.utils("[🔍] Buscando navegadores...")
            
            auditor = PasswordAuditor()
            browsers = auditor.find_all_browsers()
            
            if self.app.logger:
                self.app.logger.utils(f"[📊] {len(browsers)} navegadores encontrados")
            
            if not browsers:
                result = "[ℹ️] No se encontraron navegadores con credenciales guardadas.\n\nVerifica que tengas navegadores como Chrome, Firefox, Edge, etc. con contraseñas guardadas."
                self._finish_audit(result)
                if self.app.logger:
                    self.app.logger.utils("[ℹ️] Sin navegadores detectados")
                return

            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
                for browser in browsers:
                    if self.app.logger:
                        self.app.logger.utils(f"[🔓] Extrayendo credenciales de {browser}...")
                    passwords = auditor.extract_browser_passwords(browser)
                    auditor.all_passwords.extend(passwords)

            if self.app.logger:
                self.app.logger.utils(f"[✅] {len(auditor.all_passwords)} credenciales extraídas")
            
            result = self._format_results(auditor.all_passwords, browsers, buffer.getvalue())
            self._finish_audit(result)
        except Exception as exc:
            result = f"[❌] Error inesperado:\n{exc}"
            self._finish_audit(result, warn=True)
            if self.app.logger:
                self.app.logger.utils(f"[❌] Excepción: {exc}")

    def _format_results(self, passwords, browsers, logs_text):
        lines = []
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines.append("=" * 70)
        lines.append("🔐 AUDITORÍA DE CREDENCIALES GUARDADAS")
        lines.append("=" * 70)
        lines.append(f"📅 Fecha: {ts}")
        lines.append(f"🌐 Navegadores detectados: {len(browsers)}")
        lines.append(f"🔓 Credenciales encontradas: {len(passwords)}")
        lines.append("=" * 70)
        lines.append("")

        if not passwords:
            lines.append("✅ No se encontraron credenciales en los perfiles detectados.")
        else:
            for idx, entry in enumerate(passwords, 1):
                browser = entry.get("browser", "Desconocido")
                profile = entry.get("profile", "Predeterminado")
                url = entry.get("url", "N/A")
                username = entry.get("username", "")
                password = entry.get("password", "")
                notes = entry.get("notes", "")
                
                lines.append(f"📍 [{idx}] {browser} ({profile})")
                lines.append(f"   🌐 URL: {url}")
                lines.append(f"   👤 Usuario: {username}")
                lines.append(f"   🔑 Contraseña: {password}")
                if notes:
                    lines.append(f"   📝 Notas: {notes}")
                lines.append("   " + "-" * 66)

        cleaned_logs = (logs_text or "").strip()
        if cleaned_logs:
            lines.append("")
            lines.append("📋 Detalles de ejecución:")
            lines.append(cleaned_logs)

        return "\n".join(lines)

    def _finish_audit(self, result_text, warn=False):
        def apply_result():
            try:
                self.output.configure(state="normal")
                self.output.delete("1.0", "end")
                self.output.insert("end", result_text + "\n")
                self.output.configure(state="disabled")
                self.btn_analyze.configure(state="normal", text="Analizar")
                
                if warn:
                    self.status.configure(text="⚠️ Revisa los mensajes", text_color=self.app.c["TEXT_WARNING"])
                else:
                    self.status.configure(text="✅ Listo", text_color=self.app.c["TEXT_MUTED"])
                
                self._running = False
                
                if warn:
                    Toast(self.app, "[⚠️] Revisa la salida de auditoría", self.app.c)
                
                if self.app.logger:
                    self.app.logger.utils(f"[{'✅' if not warn else '⚠️'}] Auditoría finalizada")
            except Exception as e:
                if self.app.logger:
                    self.app.logger.utils(f"[❌] Error finalizando auditoría: {e}")

        self.after(0, apply_result)
