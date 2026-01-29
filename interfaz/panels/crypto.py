import os
import shutil
import subprocess
import threading

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT
from ..services import (
    b64_encode,
    b64_decode,
    hash_text,
    text_to_bin,
    bin_to_text,
    text_to_hex,
    hex_to_text,
)


class CryptoPanel(ctk.CTkFrame):
    def __init__(self, app):
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

        self.wordlist_mode = ctk.CTkSegmentedButton(
            john_card,
            values=["Auto", "Manual"],
            fg_color=c["BG_CARD"],
            selected_color=c["ACCENT"],
            text_color=c["TEXT_PRIMARY"],
            command=self.set_wordlist_mode,
        )
        self.wordlist_mode.set("Auto")
        self.wordlist_mode.grid(row=2, column=2, padx=8, pady=6, sticky="w")

        self.wordlist_size = ctk.CTkSegmentedButton(
            john_card,
            values=["Pequeña", "Media", "Grande"],
            fg_color=c["BG_CARD"],
            selected_color=c["ACCENT"],
            text_color=c["TEXT_PRIMARY"],
            command=self.set_wordlist_size,
        )
        self.wordlist_size.set("Media")
        self.wordlist_size.grid(row=3, column=2, padx=8, pady=6, sticky="w")

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
        self.refresh_wordlist_status()

    def do_b64_encode(self):
        data = self.input_text.get("1.0", "end").strip()
        if not data:
            self._set_output("[❌] Error: Ingresa texto primero")
            return
        try:
            result = b64_encode(data)
            self._set_output(f"✅ Base64 Encoded:\n{result}")
            if self.app.logger:
                self.app.logger.crypto("✅ Base64 encode ejecutado")
        except Exception as e:
            self._set_output(f"[❌] Error: {e}")

    def do_b64_decode(self):
        data = self.input_text.get("1.0", "end").strip()
        if not data:
            self._set_output("[❌] Error: Ingresa Base64 primero")
            return
        try:
            result = b64_decode(data)
            self._set_output(f"✅ Base64 Decoded:\n{result}")
            if self.app.logger:
                self.app.logger.crypto("✅ Base64 decode ejecutado")
        except ValueError:
            self._set_output("[❌] Error: Base64 inválido")
            if self.app.logger:
                self.app.logger.warn("Base64 inválido", tag="CRYPTO")
        except Exception as e:
            self._set_output(f"[❌] Error: {e}")

    def do_hash(self, algo):
        data = self.input_text.get("1.0", "end").strip()
        if not data:
            self._set_output("[❌] Error: Ingresa texto primero")
            return
        try:
            result = hash_text(data, algo)
            self._set_output(f"✅ {algo.upper()} Hash:\n{result}")
            if self.app.logger:
                self.app.logger.crypto(f"✅ {algo} hash generado")
        except Exception as e:
            self._set_output(f"[❌] Error: {e}")

    def do_to_bin(self):
        data = self.input_text.get("1.0", "end").strip()
        if not data:
            self._set_output("[❌] Error: Ingresa texto primero")
            return
        try:
            result = text_to_bin(data)
            self._set_output(f"✅ Binario:\n{result}")
            if self.app.logger:
                self.app.logger.crypto("✅ Texto a binario")
        except Exception as e:
            self._set_output(f"[❌] Error: {e}")

    def do_hex(self):
        data = self.input_text.get("1.0", "end").strip()
        if not data:
            self._set_output("[❌] Error: Ingresa texto primero")
            return
        try:
            result = text_to_hex(data)
            self._set_output(f"✅ Hexadecimal:\n{result}")
            if self.app.logger:
                self.app.logger.crypto("✅ Texto a hex")
        except Exception as e:
            self._set_output(f"[❌] Error: {e}")

    def do_bin_to_text(self):
        data = self.input_text.get("1.0", "end").strip()
        if not data:
            self._set_output("[❌] Error: Ingresa binario primero")
            return
        try:
            result = bin_to_text(data)
            self._set_output(f"✅ Desde Binario:\n{result}")
            if self.app.logger:
                self.app.logger.crypto("✅ Binario a texto")
        except ValueError:
            self._set_output("[❌] Error: Binario inválido (usa 8 bits separados por espacio)")
            if self.app.logger:
                self.app.logger.warn("Binario inválido", tag="CRYPTO")
        except Exception as e:
            self._set_output(f"[❌] Error: {e}")

    def do_hex_to_text(self):
        data = self.input_text.get("1.0", "end").strip().replace(" ", "")
        if not data:
            self._set_output("[❌] Error: Ingresa hex primero")
            return
        try:
            result = hex_to_text(data)
            self._set_output(f"✅ Desde Hexadecimal:\n{result}")
            if self.app.logger:
                self.app.logger.crypto("✅ Hex a texto")
        except (ValueError, TypeError):
            self._set_output("[❌] Error: Hex inválido")
            if self.app.logger:
                self.app.logger.warn("Hex inválido", tag="CRYPTO")
        except Exception as e:
            self._set_output(f"[❌] Error: {e}")
            if self.app.logger:
                self.app.logger.crypto("Hex a texto")
        except ValueError:
            self._set_output("[!] Hex inválido")
            if self.app.logger:
                self.app.logger.warn("Hex inválido", tag="CRYPTO")

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
            if self.app.logger:
                self.app.logger.crypto(f"Hashfile seleccionado: {path}")

    def pick_wordlist(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="Selecciona wordlist")
        if path:
            self.wordlist = path
            self.lbl_wordlist.configure(text=os.path.basename(path))
            self.wordlist_mode.set("Manual")
            self.set_wordlist_mode("Manual")
            if self.app.logger:
                self.app.logger.crypto(f"Wordlist seleccionada: {path}")

    def run_john(self):
        self.john_output.delete("1.0", "end")
        if self.wordlist_mode.get() == "Auto":
            self.refresh_wordlist_status()
        if not self.hash_file or not self.wordlist:
            self.john_output.insert("end", "[❌] Error: Falta hashfile o wordlist.\n")
            if self.app.logger:
                self.app.logger.warn("Falta hashfile o wordlist", tag="CRYPTO")
            return
        john_bin = shutil.which("john")
        if not john_bin:
            self.john_output.insert("end", "[❌] Error: John the Ripper no está instalado (instala john).\n")
            if self.app.logger:
                self.app.logger.error("John the Ripper no está en PATH", tag="CRYPTO")
            return
        cmd = [john_bin, f"--wordlist={self.wordlist}"]
        fmt = self.john_format.get().strip()
        if fmt:
            cmd.append(f"--format={fmt}")
        cmd.append(self.hash_file)
        self.john_output.insert("end", f"🔓 John the Ripper iniciado\n")
        self.john_output.insert("end", f"   Hashfile: {os.path.basename(self.hash_file)}\n")
        self.john_output.insert("end", f"   Wordlist: {os.path.basename(self.wordlist)}\n")
        if fmt:
            self.john_output.insert("end", f"   Formato: {fmt}\n")
        self.john_output.insert("end", f"\n⏳ Ejecutando...\n\n")
        if self.app.logger:
            self.app.logger.crypto(f"🔓 John iniciado: {os.path.basename(self.hash_file)}")
        threading.Thread(target=self._run_john_proc, args=(cmd,), daemon=True).start()

    def set_wordlist_mode(self, value):
        if value == "Manual":
            pass
        else:
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
        path = self.app.wordlists.pick_for_task("password", size=size)
        if path:
            self.wordlist = path
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

    def _run_john_proc(self, cmd):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            out = res.stdout + ("\n" + res.stderr if res.stderr else "")
            self.after(0, lambda: self._append_john(out))
            if self.app.logger:
                self.app.logger.crypto("John finalizado")
        except Exception as e:
            self.after(0, lambda: self._append_john(f"[!] Error: {e}\n"))
            if self.app.logger:
                self.app.logger.error(f"Error John: {e}", tag="CRYPTO")

    def _append_john(self, text):
        self.john_output.insert("end", text)
        self.john_output.see("end")
