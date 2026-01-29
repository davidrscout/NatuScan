import datetime

import customtkinter as ctk

from ..ui_constants import UI_FONT, UI_FONT_BOLD, MONO_FONT


class LogsPanel(ctk.CTkFrame):
    def __init__(self, app):
        super().__init__(app.content, fg_color=app.c["BG_MAIN"])
        self.app = app
        self.entries = []
        self.filter_value = "ALL"
        self.build()
        self._is_clean = False
        if getattr(self.app, "logger", None):
            self.app.logger.subscribe_structured(self.append_entry)

    def build(self):
        c = self.app.c
        header = ctk.CTkFrame(self, fg_color=c["BG_CARD"])
        header.pack(fill="x", pady=8)
        ctk.CTkLabel(header, text="Logs", font=("Poppins", 18, "bold"), text_color=c["TEXT_PRIMARY"]).pack(side="left", padx=16, pady=14)
        ctk.CTkLabel(header, text="Scrollable y copiables", text_color=c["TEXT_MUTED"], font=UI_FONT).pack(side="left", padx=8, pady=14)

        filters = ctk.CTkSegmentedButton(
            header,
            values=["ALL", "SCAN", "LISTENER", "SERVER", "FUZZER", "PAYLOADS", "CRYPTO", "UTILS", "AUDIT", "VIEWER", "CTX"],
            fg_color=c["BG_PANEL"],
            selected_color=c["ACCENT"],
            text_color=c["TEXT_PRIMARY"],
            command=self.set_filter,
        )
        filters.set("ALL")
        filters.pack(side="right", padx=12, pady=10)

        self.log_box = ctk.CTkTextbox(self, height=620, font=MONO_FONT, fg_color=c["BG_CARD"], text_color=c["TEXT_PRIMARY"])
        self.log_box.pack(fill="both", expand=True, padx=12, pady=12)
        self.log_box.insert("end", "[+] Aquí puedes pegar y revisar logs.\n")

    def append_entry(self, entry: dict):
        self.after(0, lambda e=entry: self._append_entry(e))

    def _append_entry(self, entry: dict):
        # Check if widget still exists
        if not self.winfo_exists():
            return
        if not self._is_clean:
            try:
                self.log_box.delete("1.0", "end")
            except:
                return
            self._is_clean = True
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        record = {
            "ts": ts,
            "message": entry.get("message", ""),
            "tag": entry.get("tag", ""),
            "level": entry.get("level", ""),
        }
        self.entries.append(record)
        if self._matches_filter(record):
            prefix = ""
            if record["level"]:
                prefix += f"{record['level']} "
            if record["tag"]:
                prefix += f"[{record['tag']}] "
            line = f"[{record['ts']}] {prefix}{record['message']}\n"
            try:
                self.log_box.insert("end", line)
                self.log_box.see("end")
            except:
                pass

    def _matches_filter(self, record):
        return self.filter_value == "ALL" or record.get("tag") == self.filter_value

    def set_filter(self, value):
        self.filter_value = value
        self._rebuild()

    def _rebuild(self):
        if not self.winfo_exists():
            return
        try:
            self.log_box.delete("1.0", "end")
        except:
            return
        self._is_clean = True
        for record in self.entries:
            if not self._matches_filter(record):
                continue
            prefix = ""
            if record["level"]:
                prefix += f"{record['level']} "
            if record["tag"]:
                prefix += f"[{record['tag']}] "
            line = f"[{record['ts']}] {prefix}{record['message']}\n"
            try:
                self.log_box.insert("end", line)
            except:
                pass
