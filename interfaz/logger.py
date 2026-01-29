class AppLogger:
    def __init__(self):
        self._subscribers = []
        self._structured_subscribers = []

    def subscribe(self, fn):
        if fn not in self._subscribers:
            self._subscribers.append(fn)

    def subscribe_structured(self, fn):
        if fn not in self._structured_subscribers:
            self._structured_subscribers.append(fn)

    def emit(self, message, tag=None, level=None):
        entry = {
            "message": message,
            "tag": tag or "",
            "level": level or "",
        }
        prefix = ""
        if level:
            prefix += f"{level} "
        if tag:
            prefix += f"[{tag}] "
        msg = f"{prefix}{message}"
        if not msg.endswith("\n"):
            msg += "\n"
        for fn in list(self._structured_subscribers):
            try:
                fn(entry)
            except Exception:
                continue
        for fn in list(self._subscribers):
            try:
                fn(msg)
            except Exception:
                continue

    def info(self, message, tag=None):
        self.emit(message, tag=tag, level="INFO")

    def warn(self, message, tag=None):
        self.emit(message, tag=tag, level="WARN")

    def error(self, message, tag=None):
        self.emit(message, tag=tag, level="ERROR")

    def scan(self, message):
        self.info(message, tag="SCAN")

    def listener(self, message):
        self.info(message, tag="LISTENER")

    def server(self, message):
        self.info(message, tag="SERVER")

    def fuzzer(self, message):
        self.info(message, tag="FUZZER")

    def payloads(self, message):
        self.info(message, tag="PAYLOADS")

    def crypto(self, message):
        self.info(message, tag="CRYPTO")

    def utils(self, message):
        self.info(message, tag="UTILS")

    def viewer(self, message):
        self.info(message, tag="VIEWER")

    def audit(self, message):
        self.info(message, tag="AUDIT")
