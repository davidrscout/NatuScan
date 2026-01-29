import base64
import datetime as dt
import json
import threading
from tkinter import filedialog

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT, Toast
from ..services.http_utils import build_raw_request, normalize_url, send_http_request, pretty_body
from ..services.proxy import ProxyController, ProxyItem
from ..services.certs import CertManager

try:
    from tkinterweb import HtmlFrame
except Exception:
    HtmlFrame = None


class BurpPanel(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.proxy = None
        self.cert_manager = CertManager()
        self.proxy_items = {}
        self.proxy_buttons = {}
        self.pending_ids = set()
        self.current_proxy_id = None
        self.build()

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Proxy Lab (Intercept + Repeater)", font=("Poppins", 18, "bold"),
                     text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)
        self.proxy_status = ctk.CTkLabel(header, text="OFFLINE", text_color=c["TEXT_DANGER"], font=UI_FONT_BOLD)
        self.proxy_status.pack(side="right", padx=16)

        tabs_shell = ctk.CTkFrame(self, fg_color=c["BG_PANEL"])
        tabs_shell.pack(fill="both", expand=True, padx=6, pady=8)

        self.tabs = ctk.CTkTabview(tabs_shell, fg_color=c["BG_PANEL"])
        self.tabs.pack(fill="both", expand=True, padx=6, pady=6)
        self.proxy_tab = self.tabs.add("Proxy")
        self.repeater_tab = self.tabs.add("Repeater")

        self._build_proxy_tab()
        self._build_repeater_tab()

    def _build_proxy_tab(self):
        c = self.app.c
        controls = ctk.CTkFrame(self.proxy_tab, fg_color=c["BG_CARD"])
        controls.pack(fill="x", padx=8, pady=8)
        controls.grid_columnconfigure(10, weight=1)

        ctk.CTkLabel(controls, text="Host:", font=UI_FONT, text_color=c["TEXT_PRIMARY"]).grid(
            row=0, column=0, padx=10, pady=10, sticky="w"
        )
        self.proxy_host = ctk.CTkEntry(controls, width=140, fg_color=c["BG_PANEL"], text_color=c["TEXT_PRIMARY"],
                                       corner_radius=10, font=UI_FONT)
        self.proxy_host.insert(0, "127.0.0.1")
        self.proxy_host.grid(row=0, column=1, padx=6, pady=10, sticky="w")

        ctk.CTkLabel(controls, text="Puerto:", font=UI_FONT, text_color=c["TEXT_PRIMARY"]).grid(
            row=0, column=2, padx=10, pady=10, sticky="w"
        )
        self.proxy_port = ctk.CTkEntry(controls, width=90, fg_color=c["BG_PANEL"], text_color=c["TEXT_PRIMARY"],
                                       corner_radius=10, font=UI_FONT)
        self.proxy_port.insert(0, "8080")
        self.proxy_port.grid(row=0, column=3, padx=6, pady=10, sticky="w")

        self.btn_proxy_toggle = ctk.CTkButton(
            controls, text="Iniciar Proxy", fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
            corner_radius=10, font=UI_FONT_BOLD, command=self.toggle_proxy
        )
        self.btn_proxy_toggle.grid(row=0, column=4, padx=10, pady=10)

        self.intercept_check = ctk.CTkCheckBox(
            controls, text="Interceptar", text_color=c["TEXT_PRIMARY"], fg_color=c["ACCENT"],
            command=self.toggle_intercept
        )
        self.intercept_check.grid(row=0, column=5, padx=10, pady=10, sticky="w")

        self.mitm_check = ctk.CTkCheckBox(
            controls, text="MITM HTTPS", text_color=c["TEXT_PRIMARY"], fg_color=c["ACCENT"],
            command=self.toggle_mitm
        )
        self.mitm_check.grid(row=0, column=6, padx=10, pady=10, sticky="w")

        self.queue_label = ctk.CTkLabel(controls, text="En cola: 0", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.queue_label.grid(row=0, column=7, padx=12, pady=10, sticky="w")

        self.btn_clear_proxy = ctk.CTkButton(
            controls, text="Limpiar", fg_color=c["BG_PANEL"], hover_color=c["ACCENT_HOVER"],
            corner_radius=10, font=UI_FONT_BOLD, command=self.clear_proxy_history
        )
        self.btn_clear_proxy.grid(row=0, column=8, padx=10, pady=10)

        self.btn_export_json = ctk.CTkButton(
            controls, text="Export JSON", fg_color=c["BG_PANEL"], hover_color=c["ACCENT_HOVER"],
            corner_radius=10, font=UI_FONT_BOLD, command=self.export_json
        )
        self.btn_export_json.grid(row=0, column=9, padx=6, pady=10)

        self.btn_export_har = ctk.CTkButton(
            controls, text="Export HAR", fg_color=c["BG_PANEL"], hover_color=c["ACCENT_HOVER"],
            corner_radius=10, font=UI_FONT_BOLD, command=self.export_har
        )
        self.btn_export_har.grid(row=0, column=10, padx=6, pady=10)

        ctk.CTkLabel(controls, text="Filtro URL:", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(
            row=1, column=0, padx=10, pady=(0, 8), sticky="w"
        )
        self.filter_host = ctk.CTkEntry(
            controls, width=200, fg_color=c["BG_PANEL"], text_color=c["TEXT_PRIMARY"],
            corner_radius=10, font=UI_FONT
        )
        self.filter_host.grid(row=1, column=1, padx=6, pady=(0, 8), sticky="w")
        self.filter_host.bind("<KeyRelease>", lambda e: self.refresh_proxy_list())

        ctk.CTkLabel(controls, text="Método:", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(
            row=1, column=2, padx=6, pady=(0, 8), sticky="w"
        )
        self.filter_method = ctk.CTkOptionMenu(
            controls,
            values=["ALL", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT"],
            fg_color=c["BG_PANEL"],
            button_color=c["ACCENT"],
            button_hover_color=c["ACCENT_HOVER"],
            dropdown_fg_color=c["BG_CARD"],
            dropdown_text_color=c["TEXT_PRIMARY"],
            text_color=c["TEXT_PRIMARY"],
            font=UI_FONT,
            command=lambda _: self.refresh_proxy_list(),
        )
        self.filter_method.set("ALL")
        self.filter_method.grid(row=1, column=3, padx=6, pady=(0, 8), sticky="w")

        ctk.CTkLabel(controls, text="Estado:", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(
            row=1, column=4, padx=6, pady=(0, 8), sticky="w"
        )
        self.filter_status = ctk.CTkOptionMenu(
            controls,
            values=["ALL", "Pending", "Error", "101", "2xx", "3xx", "4xx", "5xx"],
            fg_color=c["BG_PANEL"],
            button_color=c["ACCENT"],
            button_hover_color=c["ACCENT_HOVER"],
            dropdown_fg_color=c["BG_CARD"],
            dropdown_text_color=c["TEXT_PRIMARY"],
            text_color=c["TEXT_PRIMARY"],
            font=UI_FONT,
            command=lambda _: self.refresh_proxy_list(),
        )
        self.filter_status.set("ALL")
        self.filter_status.grid(row=1, column=5, padx=6, pady=(0, 8), sticky="w")

        ctk.CTkLabel(controls, text="Texto:", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(
            row=1, column=6, padx=6, pady=(0, 8), sticky="w"
        )
        self.filter_text = ctk.CTkEntry(
            controls, width=180, fg_color=c["BG_PANEL"], text_color=c["TEXT_PRIMARY"],
            corner_radius=10, font=UI_FONT
        )
        self.filter_text.grid(row=1, column=7, padx=6, pady=(0, 8), sticky="w")
        self.filter_text.bind("<KeyRelease>", lambda e: self.refresh_proxy_list())

        ctk.CTkLabel(
            controls,
            text="CA: instala el certificado para interceptar HTTPS.",
            text_color=c["TEXT_MUTED"],
            font=UI_FONT,
        ).grid(row=2, column=0, columnspan=7, padx=10, pady=(0, 8), sticky="w")

        self.btn_open_ca = ctk.CTkButton(
            controls, text="Ver CA", fg_color=c["BG_PANEL"], hover_color=c["ACCENT_HOVER"],
            corner_radius=10, font=UI_FONT_BOLD, command=self.open_ca_path
        )
        self.btn_open_ca.grid(row=2, column=7, padx=10, pady=(0, 8))

        body = ctk.CTkFrame(self.proxy_tab, fg_color=c["BG_PANEL"])
        body.pack(fill="both", expand=True, padx=8, pady=8)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color=c["BG_CARD"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ctk.CTkLabel(left, text="Historial", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).pack(
            anchor="w", padx=10, pady=(10, 6)
        )
        self.proxy_list = ctk.CTkScrollableFrame(left, fg_color=c["BG_PANEL"], width=280)
        self.proxy_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        right = ctk.CTkFrame(body, fg_color=c["BG_CARD"])
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_rowconfigure(3, weight=1)

        ctk.CTkLabel(right, text="Request (editable)", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(
            row=0, column=0, sticky="w", padx=10, pady=(10, 4)
        )
        self.proxy_request = ctk.CTkTextbox(right, height=160, font=MONO_FONT, fg_color=c["BG_PANEL"],
                                            text_color=c["TEXT_PRIMARY"])
        self.proxy_request.grid(row=1, column=0, padx=10, pady=(0, 8), sticky="nsew")

        actions = ctk.CTkFrame(right, fg_color=c["BG_CARD"])
        actions.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 6))
        self.btn_forward = ctk.CTkButton(actions, text="Forward", fg_color=c["ACCENT"],
                                         hover_color=c["ACCENT_HOVER"], corner_radius=10, font=UI_FONT_BOLD,
                                         command=self.forward_request)
        self.btn_forward.pack(side="left", padx=6, pady=6)
        self.btn_drop = ctk.CTkButton(actions, text="Drop", fg_color=c["TEXT_DANGER"],
                                      hover_color="#ef4444", corner_radius=10, font=UI_FONT_BOLD,
                                      command=self.drop_request)
        self.btn_drop.pack(side="left", padx=6, pady=6)
        self.btn_send_repeater = ctk.CTkButton(actions, text="Enviar a Repeater", fg_color=c["BG_PANEL"],
                                               hover_color=c["ACCENT_HOVER"], corner_radius=10, font=UI_FONT_BOLD,
                                               command=self.send_to_repeater)
        self.btn_send_repeater.pack(side="left", padx=6, pady=6)
        self.proxy_resp_status = ctk.CTkLabel(actions, text="Respuesta: -", text_color=c["TEXT_MUTED"], font=UI_FONT)
        self.proxy_resp_status.pack(side="right", padx=6)

        self.proxy_resp_tabs = ctk.CTkTabview(right, fg_color=c["BG_PANEL"])
        self.proxy_resp_tabs.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.proxy_resp_raw_tab = self.proxy_resp_tabs.add("Raw")
        self.proxy_resp_visual_tab = self.proxy_resp_tabs.add("Visual")

        self.proxy_response_raw = ctk.CTkTextbox(self.proxy_resp_raw_tab, font=MONO_FONT, fg_color=c["BG_PANEL"],
                                                 text_color=c["TEXT_PRIMARY"])
        self.proxy_response_raw.pack(fill="both", expand=True, padx=6, pady=6)
        self._build_visual_area(self.proxy_resp_visual_tab, target="proxy")

    def _build_repeater_tab(self):
        c = self.app.c
        form = ctk.CTkFrame(self.repeater_tab, fg_color=c["BG_CARD"])
        form.pack(fill="x", padx=8, pady=8)

        ctk.CTkLabel(form, text="Método:", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(
            row=0, column=0, padx=10, pady=10, sticky="w"
        )
        self.repeat_method = ctk.CTkOptionMenu(
            form,
            values=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
            fg_color=c["BG_PANEL"],
            button_color=c["ACCENT"],
            button_hover_color=c["ACCENT_HOVER"],
            dropdown_fg_color=c["BG_CARD"],
            dropdown_text_color=c["TEXT_PRIMARY"],
            text_color=c["TEXT_PRIMARY"],
            font=UI_FONT,
        )
        self.repeat_method.set("GET")
        self.repeat_method.grid(row=0, column=1, padx=6, pady=10, sticky="w")

        ctk.CTkLabel(form, text="URL:", text_color=c["TEXT_PRIMARY"], font=UI_FONT).grid(
            row=0, column=2, padx=10, pady=10, sticky="w"
        )
        self.repeat_url = ctk.CTkEntry(form, width=420, fg_color=c["BG_PANEL"], text_color=c["TEXT_PRIMARY"],
                                       corner_radius=10, font=UI_FONT)
        self.repeat_url.grid(row=0, column=3, padx=6, pady=10, sticky="w")

        self.btn_repeat_send = ctk.CTkButton(
            form, text="Enviar", fg_color=c["ACCENT"], hover_color=c["ACCENT_HOVER"],
            corner_radius=10, font=UI_FONT_BOLD, command=self.send_repeater
        )
        self.btn_repeat_send.grid(row=0, column=4, padx=10, pady=10)

        self.repeat_http2 = ctk.CTkCheckBox(
            form, text="HTTP/2", text_color=c["TEXT_PRIMARY"], fg_color=c["ACCENT"]
        )
        self.repeat_http2.grid(row=0, column=5, padx=10, pady=10, sticky="w")

        body = ctk.CTkFrame(self.repeater_tab, fg_color=c["BG_PANEL"])
        body.pack(fill="both", expand=True, padx=8, pady=8)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(body, text="Headers", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(
            row=0, column=0, sticky="w", padx=10, pady=(8, 4)
        )
        ctk.CTkLabel(body, text="Body", font=UI_FONT_BOLD, text_color=c["TEXT_PRIMARY"]).grid(
            row=0, column=1, sticky="w", padx=10, pady=(8, 4)
        )
        self.repeat_headers = ctk.CTkTextbox(body, height=180, font=MONO_FONT, fg_color=c["BG_CARD"],
                                             text_color=c["TEXT_PRIMARY"])
        self.repeat_headers.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.repeat_body = ctk.CTkTextbox(body, height=180, font=MONO_FONT, fg_color=c["BG_CARD"],
                                          text_color=c["TEXT_PRIMARY"])
        self.repeat_body.grid(row=1, column=1, padx=10, pady=(0, 10), sticky="nsew")

        self.repeater_resp_tabs = ctk.CTkTabview(body, fg_color=c["BG_PANEL"])
        self.repeater_resp_tabs.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=10, pady=(0, 10))
        self.repeater_req_tab = self.repeater_resp_tabs.add("Request")
        self.repeater_raw_tab = self.repeater_resp_tabs.add("Raw")
        self.repeater_visual_tab = self.repeater_resp_tabs.add("Visual")
        self.repeater_request_raw = ctk.CTkTextbox(self.repeater_req_tab, font=MONO_FONT, fg_color=c["BG_CARD"],
                                                   text_color=c["TEXT_PRIMARY"])
        self.repeater_request_raw.pack(fill="both", expand=True, padx=6, pady=6)
        self.repeater_response_raw = ctk.CTkTextbox(self.repeater_raw_tab, font=MONO_FONT, fg_color=c["BG_CARD"],
                                                    text_color=c["TEXT_PRIMARY"])
        self.repeater_response_raw.pack(fill="both", expand=True, padx=6, pady=6)
        self._build_visual_area(self.repeater_visual_tab, target="repeater")

    def _build_visual_area(self, parent, target):
        if HtmlFrame:
            frame = HtmlFrame(parent, messages_enabled=False)
            frame.pack(fill="both", expand=True, padx=6, pady=6)
            if target == "proxy":
                self.proxy_visual = frame
            else:
                self.repeater_visual = frame
            return
        txt = ctk.CTkTextbox(parent, font=MONO_FONT, fg_color=self.app.c["BG_CARD"], text_color=self.app.c["TEXT_PRIMARY"])
        txt.pack(fill="both", expand=True, padx=6, pady=6)
        txt.insert("end", "[*] Instala 'tkinterweb' para vista HTML real.\n")
        txt.configure(state="disabled")
        if target == "proxy":
            self.proxy_visual = txt
        else:
            self.repeater_visual = txt

    def toggle_proxy(self):
        if self.proxy and self.proxy.is_running():
            self.proxy.stop()
            self.proxy = None
            self.proxy_status.configure(text="OFFLINE", text_color=self.app.c["TEXT_DANGER"])
            self.btn_proxy_toggle.configure(text="Iniciar Proxy")
            if self.app.logger:
                self.app.logger.utils("Proxy detenido")
            return
        host = self.proxy_host.get().strip() or "127.0.0.1"
        port_text = self.proxy_port.get().strip() or "8080"
        try:
            port = int(port_text)
        except Exception:
            Toast(self.app, "Puerto inválido", self.app.c)
            return
        self.proxy = ProxyController(host, port, on_event=self._proxy_event, logger=self.app.logger)
        try:
            self.proxy.start()
        except Exception as exc:
            self.proxy = None
            Toast(self.app, f"No se pudo iniciar proxy: {exc}", self.app.c)
            return
        self.proxy_status.configure(text=f"ONLINE {host}:{port}", text_color=self.app.c["TEXT_SUCCESS"])
        self.btn_proxy_toggle.configure(text="Detener Proxy")
        self.toggle_intercept()
        self.toggle_mitm()
        if self.app.logger:
            self.app.logger.utils(f"Proxy iniciado en {host}:{port}")

    def toggle_intercept(self):
        enabled = bool(self.intercept_check.get())
        if self.proxy:
            self.proxy.set_intercept(enabled)
        if not enabled and self.pending_ids:
            for item_id in list(self.pending_ids):
                item = self.proxy_items.get(item_id)
                if not item:
                    continue
                item.action = "forward"
                item.event.set()
            self.pending_ids.clear()
            self._update_queue_label()

    def toggle_mitm(self):
        enabled = bool(self.mitm_check.get())
        if not self.proxy:
            return
        if enabled:
            try:
                self.cert_manager.ensure_ca()
            except Exception as exc:
                Toast(self.app, f"No se pudo preparar CA: {exc}", self.app.c)
                self.mitm_check.deselect()
                return
        self.proxy.set_mitm(enabled, cert_manager=self.cert_manager)
        if self.app.logger:
            self.app.logger.utils(f"MITM HTTPS {'activo' if enabled else 'desactivado'}")

    def open_ca_path(self):
        try:
            path = self.cert_manager.get_ca_cert_path()
        except Exception as exc:
            Toast(self.app, str(exc), self.app.c)
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(path)
            Toast(self.app, f"Ruta CA copiada: {path}", self.app.c)
        except Exception:
            Toast(self.app, f"CA en: {path}", self.app.c)

    def clear_proxy_history(self):
        self.proxy_items.clear()
        self.pending_ids.clear()
        self.current_proxy_id = None
        for btn in self.proxy_buttons.values():
            btn.destroy()
        self.proxy_buttons.clear()
        self.proxy_request.delete("1.0", "end")
        self.proxy_response_raw.delete("1.0", "end")
        self.proxy_resp_status.configure(text="Respuesta: -")
        self._update_queue_label()

    def _proxy_event(self, event):
        self.after(0, lambda: self._handle_proxy_event(event))

    def _handle_proxy_event(self, event):
        item = event.get("item")
        if not isinstance(item, ProxyItem):
            return
        ev_type = event.get("type")
        if ev_type == "request":
            self.proxy_items[item.id] = item
            if self.intercept_check.get():
                self.pending_ids.add(item.id)
            self.refresh_proxy_list()
            self._update_queue_label()
        elif ev_type == "response":
            self.proxy_items[item.id] = item
            self.pending_ids.discard(item.id)
            self.refresh_proxy_list()
            self._update_queue_label()
            if self.current_proxy_id == item.id:
                self._render_proxy_response(item)
        elif ev_type == "error":
            self.pending_ids.discard(item.id)
            self.refresh_proxy_list()
            self._update_queue_label()
            if self.current_proxy_id == item.id and item.error:
                self.proxy_response_raw.delete("1.0", "end")
                self.proxy_response_raw.insert("end", item.error)
                self.proxy_resp_status.configure(text="Respuesta: error")

    def refresh_proxy_list(self):
        for btn in self.proxy_buttons.values():
            try:
                btn.destroy()
            except Exception:
                pass
        self.proxy_buttons.clear()
        items = self._filtered_items()
        for item in items:
            self._add_proxy_button(item)
        if not items:
            self.current_proxy_id = None
            self.proxy_request.delete("1.0", "end")
            self.proxy_response_raw.delete("1.0", "end")
            self.proxy_resp_status.configure(text="Respuesta: -")
            return
        if self.current_proxy_id not in [i.id for i in items]:
            self.select_proxy_item(items[0].id)

    def _filtered_items(self):
        items = sorted(self.proxy_items.values(), key=lambda x: int(x.id))
        filtered = [item for item in items if self._match_filters(item)]
        return filtered

    def _match_filters(self, item: ProxyItem) -> bool:
        host_filter = (self.filter_host.get().strip().lower() if hasattr(self, "filter_host") else "")
        text_filter = (self.filter_text.get().strip().lower() if hasattr(self, "filter_text") else "")
        method_filter = self.filter_method.get() if hasattr(self, "filter_method") else "ALL"
        status_filter = self.filter_status.get() if hasattr(self, "filter_status") else "ALL"

        if host_filter and host_filter not in (item.url or "").lower():
            return False
        if text_filter and text_filter not in (item.raw or "").lower():
            return False
        if method_filter != "ALL" and item.method != method_filter:
            return False
        if status_filter != "ALL":
            if status_filter == "Pending" and item.id not in self.pending_ids:
                return False
            if status_filter == "Error" and not item.error:
                return False
            if status_filter == "101":
                if not item.response or item.response.status != 101:
                    return False
            if status_filter in ("2xx", "3xx", "4xx", "5xx"):
                if not item.response:
                    return False
                bucket = f"{item.response.status // 100}xx"
                if bucket != status_filter:
                    return False
        return True

    def _add_proxy_button(self, item: ProxyItem):
        label = self._format_item_label(item)
        btn = ctk.CTkButton(self.proxy_list, text=label, fg_color=self.app.c["BG_CARD"],
                            hover_color=self.app.c["ACCENT_HOVER"], corner_radius=10, font=UI_FONT,
                            command=lambda i=item.id: self.select_proxy_item(i))
        btn.pack(fill="x", padx=6, pady=4)
        self.proxy_buttons[item.id] = btn

    def _update_proxy_button(self, item: ProxyItem):
        btn = self.proxy_buttons.get(item.id)
        if not btn:
            return
        btn.configure(text=self._format_item_label(item))

    def _format_item_label(self, item: ProxyItem) -> str:
        url = item.url or ""
        short = url.replace("http://", "").replace("https://", "")
        if len(short) > 36:
            short = short[:33] + "..."
        if item.id in self.pending_ids:
            status = "⏸"
        elif item.response:
            status = str(item.response.status)
        elif item.error:
            status = "ERR"
        else:
            status = "…"
        return f"{status} {item.method} {short}"

    def _update_queue_label(self):
        self.queue_label.configure(text=f"En cola: {len(self.pending_ids)}")

    def select_proxy_item(self, item_id: str):
        item = self.proxy_items.get(item_id)
        if not item:
            return
        self.current_proxy_id = item_id
        self.proxy_request.delete("1.0", "end")
        self.proxy_request.insert("end", item.raw)
        self._render_proxy_response(item)

    def _render_proxy_response(self, item: ProxyItem):
        self.proxy_response_raw.delete("1.0", "end")
        if item.response:
            self.proxy_response_raw.insert("end", item.response.raw)
            self.proxy_resp_status.configure(text=f"Respuesta: {item.response.status} ({item.response.elapsed:.2f}s)")
            self._render_visual(self.proxy_visual, item.response)
        elif item.error:
            self.proxy_response_raw.insert("end", item.error)
            self.proxy_resp_status.configure(text="Respuesta: error")
        else:
            self.proxy_resp_status.configure(text="Respuesta: -")

    def forward_request(self):
        item = self._current_item()
        if not item:
            return
        if item.id not in self.pending_ids:
            return
        item.modified_raw = self.proxy_request.get("1.0", "end")
        item.action = "forward"
        item.event.set()
        self.pending_ids.discard(item.id)
        self._update_queue_label()

    def drop_request(self):
        item = self._current_item()
        if not item:
            return
        if item.id not in self.pending_ids:
            return
        item.action = "drop"
        item.event.set()
        self.pending_ids.discard(item.id)
        self._update_queue_label()

    def send_to_repeater(self):
        item = self._current_item()
        if not item:
            return
        self._load_item_into_repeater(item)
        self.tabs.set("Repeater")

    def _current_item(self):
        if not self.current_proxy_id:
            return None
        return self.proxy_items.get(self.current_proxy_id)

    def _load_item_into_repeater(self, item: ProxyItem):
        self.repeat_method.set(item.method)
        self.repeat_url.delete(0, "end")
        self.repeat_url.insert(0, item.url)
        self.repeat_headers.delete("1.0", "end")
        headers_text = "\n".join(f"{k}: {v}" for k, v in item.headers.items())
        self.repeat_headers.insert("end", headers_text)
        self.repeat_body.delete("1.0", "end")
        try:
            body_text = item.body.decode("utf-8")
        except Exception:
            body_text = item.body.decode("latin-1", errors="replace")
        self.repeat_body.insert("end", body_text)

    def send_repeater(self):
        method = self.repeat_method.get().strip().upper()
        url = self.repeat_url.get().strip()
        if not url:
            Toast(self.app, "URL inválida", self.app.c)
            return
        headers = self._parse_headers(self.repeat_headers.get("1.0", "end"))
        body = self.repeat_body.get("1.0", "end").rstrip("\n").encode("utf-8")
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        use_http2 = bool(self.repeat_http2.get()) if hasattr(self, "repeat_http2") else False

        def run():
            try:
                normalized = normalize_url(url, headers)
                raw_req = build_raw_request(method, normalized, headers, body)
                resp = send_http_request(method, normalized, headers, body, http2=use_http2)
                self.after(0, lambda: self._render_repeater_response(raw_req, resp))
                if self.app.logger:
                    self.app.logger.utils(f"Repeater {method} {normalized} -> {resp.status}")
            except Exception as exc:
                self.after(0, lambda: self._render_repeater_error(str(exc)))
                if self.app.logger:
                    self.app.logger.error(f"Repeater error: {exc}", tag="UTILS")

        threading.Thread(target=run, daemon=True).start()

    def _render_repeater_response(self, raw_req, response):
        self.repeater_request_raw.delete("1.0", "end")
        self.repeater_request_raw.insert("end", raw_req)
        self.repeater_response_raw.delete("1.0", "end")
        self.repeater_response_raw.insert("end", response.raw)
        self._render_visual(self.repeater_visual, response)

    def _render_repeater_error(self, msg):
        self.repeater_request_raw.delete("1.0", "end")
        self.repeater_response_raw.delete("1.0", "end")
        self.repeater_response_raw.insert("end", msg)

    def _render_visual(self, widget, response):
        body_text = pretty_body(response.body, response.headers)
        ctype = response.headers.get("Content-Type", "")
        if HtmlFrame and isinstance(widget, HtmlFrame):
            if "text/html" in ctype:
                widget.set_content(body_text)
                return
            escaped = body_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            widget.set_content(f"<pre>{escaped}</pre>")
            return
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", body_text)
        widget.configure(state="disabled")

    def _parse_headers(self, raw_text):
        headers = {}
        for line in raw_text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return headers

    def export_json(self):
        items = self._filtered_items()
        if not items:
            Toast(self.app, "No hay items para exportar", self.app.c)
            return
        path = filedialog.asksaveasfilename(
            title="Export JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        payload = [self._item_to_dict(item) for item in items]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        Toast(self.app, f"Exportado: {path}", self.app.c)
        if self.app.logger:
            self.app.logger.utils(f"Export JSON: {path}")

    def export_har(self):
        items = self._filtered_items()
        if not items:
            Toast(self.app, "No hay items para exportar", self.app.c)
            return
        path = filedialog.asksaveasfilename(
            title="Export HAR",
            defaultextension=".har",
            filetypes=[("HAR", "*.har")],
        )
        if not path:
            return
        entries = [self._item_to_har(item) for item in items]
        payload = {
            "log": {
                "version": "1.2",
                "creator": {"name": "CyberNatu", "version": "2.x"},
                "entries": entries,
            }
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        Toast(self.app, f"Exportado: {path}", self.app.c)
        if self.app.logger:
            self.app.logger.utils(f"Export HAR: {path}")

    def _item_to_dict(self, item: ProxyItem):
        body_text, body_enc = self._body_to_text(item.body)
        resp_body = b""
        if item.response and item.response.body:
            resp_body = item.response.body
        resp_text, resp_enc = self._body_to_text(resp_body)
        return {
            "id": item.id,
            "timestamp": item.created_at,
            "client": item.client,
            "method": item.method,
            "url": item.url,
            "headers": item.headers,
            "body": body_text,
            "body_encoding": body_enc,
            "raw_request": item.raw,
            "response": {
                "status": item.response.status if item.response else None,
                "reason": item.response.reason if item.response else "",
                "headers": item.response.headers if item.response else {},
                "body": resp_text,
                "body_encoding": resp_enc,
                "raw_response": item.response.raw if item.response else "",
                "elapsed": item.response.elapsed if item.response else 0,
            },
            "error": item.error,
        }

    def _item_to_har(self, item: ProxyItem):
        started = dt.datetime.fromtimestamp(item.created_at, tz=dt.timezone.utc).isoformat()
        req_body_text, req_body_enc = self._body_to_text(item.body)
        req_headers = [{"name": k, "value": v} for k, v in (item.headers or {}).items()]
        resp_headers = []
        resp_body = b""
        status = 0
        status_text = ""
        elapsed_ms = 0
        if item.response:
            resp_headers = [{"name": k, "value": v} for k, v in item.response.headers.items()]
            resp_body = item.response.body or b""
            status = item.response.status
            status_text = item.response.reason
            elapsed_ms = int(item.response.elapsed * 1000)
        resp_text, resp_enc = self._body_to_text(resp_body)
        content = {
            "size": len(resp_body),
            "mimeType": (item.response.headers.get("Content-Type", "") if item.response else ""),
            "text": resp_text,
        }
        if resp_enc:
            content["encoding"] = resp_enc
        post_data = None
        if req_body_text:
            post_data = {
                "mimeType": item.headers.get("Content-Type", "application/octet-stream"),
                "text": req_body_text,
            }
            if req_body_enc:
                post_data["encoding"] = req_body_enc
        return {
            "startedDateTime": started,
            "time": elapsed_ms,
            "request": {
                "method": item.method,
                "url": item.url,
                "httpVersion": "HTTP/1.1",
                "headers": req_headers,
                "queryString": [],
                "headersSize": -1,
                "bodySize": len(item.body or b""),
                "postData": post_data,
            },
            "response": {
                "status": status,
                "statusText": status_text,
                "httpVersion": "HTTP/1.1",
                "headers": resp_headers,
                "content": content,
                "headersSize": -1,
                "bodySize": len(resp_body),
            },
            "cache": {},
            "timings": {"send": 0, "wait": elapsed_ms, "receive": 0},
        }

    def _body_to_text(self, body: bytes):
        if not body:
            return "", None
        try:
            return body.decode("utf-8"), None
        except Exception:
            return base64.b64encode(body).decode("ascii"), "base64"
