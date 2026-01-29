import os
import re
import threading
import urllib.parse

import customtkinter as ctk
import requests

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT
from ..services import extract_links, analyze_html


class ViewerPanel(ctk.CTkFrame):
    def __init__(self, app):
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
            from ..ui_constants import Toast
            Toast(self.app, "[❌] URL requerida", self.app.c)
            if self.app.logger:
                self.app.logger.utils("[❌] Intento de cargar URL vacía")
            return
        
        # Add protocol if missing
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
            self.url_entry.delete(0, "end")
            self.url_entry.insert(0, url)
        
        if self.app.logger:
            self.app.logger.utils(f"[⏳] Cargando URL: {url}")

        def run():
            try:
                if self.app.logger:
                    self.app.logger.utils(f"[🌐] Conectando a {url}...")
                    
                resp = requests.get(url, timeout=10)
                content = resp.text
                
                self.after(0, lambda: self.add_tab(url, content))
                self.after(0, lambda: self.set_analysis(content))
                self.load_linked_files_async(url, content)
                
                if self.app.logger:
                    self.app.logger.utils(f"[✅] URL cargada: {resp.status_code} {url}")
            except requests.Timeout:
                error_msg = "[❌] Timeout: servidor tardó demasiado en responder"
                self.after(0, lambda: self.add_tab("error", error_msg))
                if self.app.logger:
                    self.app.logger.utils(error_msg)
            except requests.ConnectionError as e:
                error_msg = f"[❌] Error de conexión: {e}"
                self.after(0, lambda: self.add_tab("error", error_msg))
                if self.app.logger:
                    self.app.logger.utils(error_msg)
            except Exception as e:
                error_msg = f"[❌] Error al cargar URL: {e}"
                self.after(0, lambda: self.add_tab("error", error_msg))
                if self.app.logger:
                    self.app.logger.utils(error_msg)

        threading.Thread(target=run, daemon=True).start()

    def load_file(self):
        from tkinter import filedialog
        try:
            path = filedialog.askopenfilename(title="Selecciona archivo")
            if not path:
                if self.app.logger:
                    self.app.logger.utils("[⚠️] Selección de archivo cancelada")
                return
            
            if not os.path.isfile(path):
                from ..ui_constants import Toast
                Toast(self.app, "[❌] Archivo no existe", self.app.c)
                if self.app.logger:
                    self.app.logger.utils(f"[❌] Archivo no encontrado: {path}")
                return
            
            if self.app.logger:
                self.app.logger.utils(f"[⏳] Leyendo archivo: {path}")
            
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            
            self.add_tab(os.path.basename(path), content)
            self.set_analysis(content)
            
            if self.app.logger:
                self.app.logger.utils(f"[✅] Archivo cargado: {path} ({len(content)} bytes)")
        except IOError as e:
            error_msg = f"[❌] Error de lectura: {e}"
            self.add_tab("error", error_msg)
            if self.app.logger:
                self.app.logger.utils(error_msg)
        except Exception as e:
            error_msg = f"[❌] Error inesperado: {e}"
            self.add_tab("error", error_msg)
            if self.app.logger:
                self.app.logger.utils(error_msg)

    def add_tab(self, title, content):
        try:
            c = self.app.c
            tab_title = title if len(title) < 20 else title[:17] + "..."
            tab_title = self._unique_tab_title(tab_title)
            tab = self.tabs.add(tab_title)
            
            lines = content.splitlines()
            numbered = "\n".join(f"{i:>4} | {line}" for i, line in enumerate(lines, 1))
            txt = ctk.CTkTextbox(tab, font=MONO_FONT, fg_color="#1e1e1e", text_color="#d4d4d4")
            txt.pack(fill="both", expand=True, padx=4, pady=4)
            txt.insert("end", numbered)
            
            try:
                txt.tag_config("ln", foreground="#6b7280")
                txt.tag_config("tag", foreground="#569cd6")
                txt.tag_config("attr", foreground="#9cdcfe")
                txt.tag_config("string", foreground="#ce9178")
                txt.tag_config("comment", foreground="#6a9955")
                txt.tag_config("punct", foreground="#d4d4d4")

                for i, line in enumerate(lines, 1):
                    base = f"{i}.0"
                    txt.tag_add("ln", base, f"{i}.6")

                    content_start = 6
                    raw = line

                    for m in re.finditer(r"<!--.*?-->", raw):
                        s = content_start + m.start()
                        e = content_start + m.end()
                        txt.tag_add("comment", f"{i}.{s}", f"{i}.{e}")

                    for m in re.finditer(r"\"[^\"]*\"|'[^']*'", raw):
                        s = content_start + m.start()
                        e = content_start + m.end()
                        txt.tag_add("string", f"{i}.{s}", f"{i}.{e}")

                    for m in re.finditer(r"</?[\w:-]+", raw):
                        s = content_start + m.start()
                        e = content_start + m.end()
                        txt.tag_add("tag", f"{i}.{s}", f"{i}.{e}")

                    for m in re.finditer(r"\b[\w:-]+(?=\=)", raw):
                        s = content_start + m.start()
                        e = content_start + m.end()
                        txt.tag_add("attr", f"{i}.{s}", f"{i}.{e}")
            except Exception as e:
                # Syntax highlighting failed, but content is still visible
                if self.app.logger:
                    self.app.logger.utils(f"[⚠️] Error en colorizado: {e}")

            txt.configure(state="disabled")
            if self.app.logger:
                self.app.logger.utils(f"[✅] Pestaña creada: {tab_title} ({len(lines)} líneas)")
        except Exception as e:
            if self.app.logger:
                self.app.logger.utils(f"[❌] Error creando pestaña: {e}")

    def _unique_tab_title(self, title):
        existing = getattr(self.tabs, "_tab_dict", {})
        if title not in existing:
            return title
        base = title
        idx = 2
        while f"{base} ({idx})" in existing:
            idx += 1
        return f"{base} ({idx})"

    def load_linked_files(self, base_url, html):
        links = extract_links(html)
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

    def load_linked_files_async(self, base_url, html):
        def run():
            try:
                links = extract_links(html)
                if not links:
                    if self.app.logger:
                        self.app.logger.utils("[ℹ️] No se encontraron enlaces en el HTML")
                    return
                
                if self.app.logger:
                    self.app.logger.utils(f"[🔗] Cargando recursos vinculados... ({len(links)} encontrados)")
                
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
                            self.after(0, lambda n=name, t=r.text: self.add_tab(n, t))
                            count += 1
                            if self.app.logger:
                                self.app.logger.utils(f"[✅] Recurso cargado: {name}")
                    except Exception as e:
                        if self.app.logger:
                            self.app.logger.utils(f"[⚠️] Saltando recurso: {e}")
                        continue
                
                if self.app.logger:
                    self.app.logger.utils(f"[✅] {count} recursos cargados")
            except Exception as e:
                if self.app.logger:
                    self.app.logger.utils(f"[❌] Error cargando recursos: {e}")

        threading.Thread(target=run, daemon=True).start()

    def set_analysis(self, text):
        try:
            summary = analyze_html(text)
            self.analysis.configure(state="normal")
            self.analysis.delete("1.0", "end")
            self.analysis.insert("end", f"📊 Análisis de HTML:\n\n{summary}")
            self.analysis.configure(state="disabled")
            if self.app.logger:
                self.app.logger.utils("[✅] Análisis completado")
        except Exception as e:
            self.analysis.configure(state="normal")
            self.analysis.delete("1.0", "end")
            self.analysis.insert("end", f"[❌] Error en análisis: {e}")
            self.analysis.configure(state="disabled")
            if self.app.logger:
                self.app.logger.utils(f"[❌] Error analizando HTML: {e}")

    def open_content(self, title, content):
        self.add_tab(title, content)
        self.set_analysis(content)

    def open_url(self, url):
        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, url)
        self.load_url()
