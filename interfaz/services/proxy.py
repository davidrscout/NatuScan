import select
import socket
import socketserver
import ssl
import urllib.parse
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional

from .http_utils import (
    build_raw_request,
    build_raw_response_bytes,
    parse_raw_request,
    send_http_request,
    normalize_url,
    HttpResponse,
)
from .certs import CertManager


@dataclass
class ProxyItem:
    id: str
    method: str
    url: str
    headers: dict
    body: bytes
    raw: str
    client: str
    created_at: float
    event: threading.Event = field(default_factory=threading.Event)
    action: str = "forward"
    modified_raw: Optional[str] = None
    response: Optional[HttpResponse] = None
    error: Optional[str] = None


class ProxyRequestHandler(BaseHTTPRequestHandler):
    server_version = "CyberNatuProxy/0.1"
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self):
        item = self.server.build_item("CONNECT", self.path, dict(self.headers), b"", client=self.client_address)
        self.server.emit("request", item)
        if self.server.intercept_enabled:
            item.event.wait()
            if item.action == "drop":
                self.send_error(403, "Blocked by proxy")
                return
        host, port = self._parse_connect_target(self.path)
        if not host:
            self.send_error(400, "Invalid CONNECT target")
            return
        if self.server.mitm_enabled:
            try:
                self._handle_mitm(host, port, item)
            except Exception as exc:
                item.error = str(exc)
                self.server.emit("error", item)
                self.send_error(502, f"MITM error: {exc}")
            return
        try:
            remote = socket.create_connection((host, port), timeout=8)
        except Exception as exc:
            self.send_error(502, f"CONNECT failed: {exc}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        item.response = HttpResponse(
            status=200,
            reason="Connection Established",
            headers={},
            body=b"",
            raw="HTTP/1.1 200 Connection Established\r\n\r\n",
            elapsed=0.0,
        )
        self.server.emit("response", item)
        self._tunnel(self.connection, remote)

    def do_GET(self):
        self._handle_http()

    def do_POST(self):
        self._handle_http()

    def do_PUT(self):
        self._handle_http()

    def do_DELETE(self):
        self._handle_http()

    def do_PATCH(self):
        self._handle_http()

    def do_HEAD(self):
        self._handle_http()

    def do_OPTIONS(self):
        self._handle_http()

    def log_message(self, fmt, *args):
        if self.server.logger:
            self.server.logger.utils(fmt % args)

    def _handle_http(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = self._read_chunked_body_file()
        else:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length > 0 else b""
        headers = dict(self.headers)
        url = self._build_full_url()
        raw = build_raw_request(self.command, url, headers, body)
        item = self.server.build_item(self.command, url, headers, body, raw=raw, client=self.client_address)
        self.server.emit("request", item)

        if self.server.intercept_enabled:
            item.event.wait()
            if item.action == "drop":
                self.send_error(403, "Blocked by proxy")
                return
            if item.modified_raw:
                try:
                    method, new_url, new_headers, new_body = parse_raw_request(item.modified_raw)
                    url = normalize_url(new_url, new_headers)
                    headers = new_headers
                    body = new_body
                    item.method = method
                    item.url = url
                    item.headers = headers
                    item.body = body
                    item.raw = item.modified_raw
                except Exception as exc:
                    item.error = f"Error parseando request editado: {exc}"
                    self.server.emit("error", item)
                    self.send_error(400, str(exc))
                    return
        if self._is_http2_upgrade(headers):
            item.error = "HTTP/2 no soportado en intercept (usa tunnel)."
            self.server.emit("error", item)
            self.send_error(501, "HTTP/2 not supported (use tunnel)")
            return
        if self._is_websocket(headers):
            self._handle_websocket_http(item, headers, body)
            return
        try:
            response = send_http_request(item.method, item.url, headers, body)
        except Exception as exc:
            item.error = str(exc)
            self.server.emit("error", item)
            self.send_error(502, f"Upstream error: {exc}")
            return
        item.response = response
        self.server.emit("response", item)
        self._send_response(response)

    def _send_response(self, response: HttpResponse):
        self.send_response(response.status, response.reason)
        for k, v in response.headers.items():
            try:
                self.send_header(k, v)
            except Exception:
                continue
        self.end_headers()
        if response.body:
            self.wfile.write(response.body)

    def _build_full_url(self) -> str:
        path = self.path
        if path.startswith("http://") or path.startswith("https://"):
            return path
        host = self.headers.get("Host", "")
        if not host:
            return path
        return f"http://{host}{path}"

    def _parse_connect_target(self, target: str):
        if ":" not in target:
            return None, None
        host, port = target.split(":", 1)
        try:
            return host, int(port)
        except Exception:
            return None, None

    def _parse_url_target(self, url: str):
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
        if not host:
            return None, None, None, None
        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme in ("https", "wss") else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return scheme, host, port, path

    def _is_websocket(self, headers: dict) -> bool:
        upgrade = headers.get("Upgrade", "") or headers.get("upgrade", "")
        conn = headers.get("Connection", "") or headers.get("connection", "")
        return "websocket" in upgrade.lower() or "upgrade" in conn.lower()

    def _is_http2_upgrade(self, headers: dict) -> bool:
        upgrade = headers.get("Upgrade", "") or headers.get("upgrade", "")
        if "h2c" in upgrade.lower():
            return True
        if "http2-settings" in (headers.get("Connection", "") or "").lower():
            return True
        return False

    def _build_origin_request_bytes(self, method: str, path: str, headers: dict, body: bytes) -> bytes:
        cleaned = {}
        for k, v in headers.items():
            if k.lower() == "proxy-connection":
                continue
            cleaned[k] = v
        lines = [f"{method} {path} HTTP/1.1"]
        for k, v in cleaned.items():
            lines.append(f"{k}: {v}")
        head = "\r\n".join(lines) + "\r\n\r\n"
        return head.encode("latin-1", errors="replace") + (body or b"")

    def _read_response_head(self, sock):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        if b"\r\n\r\n" not in data:
            return None, b""
        head, rest = data.split(b"\r\n\r\n", 1)
        return head, rest

    def _parse_response_head(self, head: bytes):
        lines = head.decode("latin-1", errors="replace").split("\r\n")
        if not lines:
            return 0, "", {}
        parts = lines[0].split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        reason = parts[2] if len(parts) > 2 else ""
        headers = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return status, reason, headers

    def _handle_websocket_http(self, item, headers, body):
        scheme, host, port, path = self._parse_url_target(item.url)
        if not host:
            self.send_error(400, "Invalid websocket target")
            return
        if scheme in ("https", "wss"):
            self.send_error(501, "WebSocket over TLS requiere CONNECT/MITM")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=8)
        except Exception as exc:
            item.error = str(exc)
            self.server.emit("error", item)
            self.send_error(502, f"Upstream error: {exc}")
            return
        req_bytes = self._build_origin_request_bytes(item.method, path, headers, body)
        upstream.sendall(req_bytes)
        head, rest = self._read_response_head(upstream)
        if not head:
            self.send_error(502, "Upstream no response")
            return
        status, reason, resp_headers = self._parse_response_head(head)
        raw = head + b"\r\n\r\n" + rest
        item.response = HttpResponse(
            status=status,
            reason=reason,
            headers=resp_headers,
            body=rest,
            raw=raw.decode("latin-1", errors="replace"),
            elapsed=0.0,
        )
        self.server.emit("response", item)
        self.wfile.write(raw)
        if status == 101:
            if rest:
                pass
            self._tunnel(self.connection, upstream)

    def _tunnel(self, client, remote):
        client.settimeout(0.2)
        remote.settimeout(0.2)
        sockets = [client, remote]
        try:
            while True:
                r, _, _ = select.select(sockets, [], [], 0.2)
                if not r:
                    continue
                for sock in r:
                    data = sock.recv(4096)
                    if not data:
                        return
                    if sock is client:
                        remote.sendall(data)
                    else:
                        client.sendall(data)
        finally:
            try:
                remote.close()
            except Exception:
                pass

    def _handle_mitm(self, host, port, connect_item):
        if not self.server.cert_manager:
            self.server.cert_manager = CertManager()
        cert_path, key_path = self.server.cert_manager.get_cert_for_host(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        self.send_response(200, "Connection Established")
        self.end_headers()
        connect_item.response = HttpResponse(
            status=200,
            reason="Connection Established",
            headers={},
            body=b"",
            raw="HTTP/1.1 200 Connection Established\r\n\r\n",
            elapsed=0.0,
        )
        self.server.emit("response", connect_item)

        tls_conn = context.wrap_socket(self.connection, server_side=True)
        tls_conn.settimeout(5.0)
        try:
            while True:
                req = self._read_http_request(tls_conn)
                if not req:
                    break
                if req[0] == "TIMEOUT":
                    continue
                method, path, version, headers, body = req
                if method == "HTTP2":
                    self._handle_mitm_http2(tls_conn, host, port, body)
                    break
                full_url = path if path.startswith("http") else f"https://{host}{path}"
                raw = build_raw_request(method, full_url, headers, body)
                item = self.server.build_item(method, full_url, headers, body, raw=raw, client=self.client_address)
                self.server.emit("request", item)
                if self.server.intercept_enabled:
                    item.event.wait()
                    if item.action == "drop":
                        err_resp = build_raw_response_bytes(403, "Blocked", {"Content-Length": "0"}, b"")
                        tls_conn.sendall(err_resp)
                        self.server.emit("response", item)
                        continue
                    if item.modified_raw:
                        method, new_url, new_headers, new_body = parse_raw_request(item.modified_raw)
                        full_url = normalize_url(new_url, new_headers)
                        headers = new_headers
                        body = new_body
                        item.method = method
                        item.url = full_url
                        item.headers = headers
                        item.body = body
                        item.raw = item.modified_raw
                if self._is_websocket(headers):
                    try:
                        self._handle_mitm_websocket(tls_conn, full_url, headers, body, item)
                    except Exception as exc:
                        item.error = str(exc)
                        self.server.emit("error", item)
                        err_resp = build_raw_response_bytes(502, "Upstream Error", {"Content-Length": "0"}, b"")
                        tls_conn.sendall(err_resp)
                    break
                try:
                    response = send_http_request(item.method, full_url, headers, body)
                except Exception as exc:
                    item.error = str(exc)
                    self.server.emit("error", item)
                    err_resp = build_raw_response_bytes(502, "Upstream Error", {"Content-Length": "0"}, b"")
                    tls_conn.sendall(err_resp)
                    continue
                item.response = response
                self.server.emit("response", item)
                payload = build_raw_response_bytes(response.status, response.reason, response.headers, response.body)
                tls_conn.sendall(payload)
                if headers.get("Connection", "").lower() == "close":
                    break
        finally:
            try:
                tls_conn.close()
            except Exception:
                pass

    def _open_upstream_tls(self, host: str, port: int):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=8)
        return context.wrap_socket(sock, server_hostname=host)

    def _handle_mitm_http2(self, tls_conn, host, port, preface: bytes):
        item = self.server.build_item(
            "HTTP2",
            f"https://{host}:{port}",
            {},
            b"",
            raw=preface.decode("latin-1", errors="replace"),
            client=self.client_address,
        )
        self.server.emit("request", item)
        try:
            upstream = self._open_upstream_tls(host, port)
            if preface:
                upstream.sendall(preface)
            item.response = HttpResponse(
                status=200,
                reason="H2 tunnel",
                headers={},
                body=b"",
                raw="",
                elapsed=0.0,
            )
            self.server.emit("response", item)
            self._tunnel(tls_conn, upstream)
        except Exception as exc:
            item.error = str(exc)
            self.server.emit("error", item)

    def _handle_mitm_websocket(self, tls_conn, full_url: str, headers: dict, body: bytes, item):
        scheme, host, port, path = self._parse_url_target(full_url)
        if not host:
            raise RuntimeError("Destino inválido")
        upstream = self._open_upstream_tls(host, port)
        req_bytes = self._build_origin_request_bytes(item.method, path, headers, body)
        upstream.sendall(req_bytes)
        head, rest = self._read_response_head(upstream)
        if not head:
            raise RuntimeError("Upstream no response")
        status, reason, resp_headers = self._parse_response_head(head)
        raw = head + b"\r\n\r\n" + rest
        item.response = HttpResponse(
            status=status,
            reason=reason,
            headers=resp_headers,
            body=rest,
            raw=raw.decode("latin-1", errors="replace"),
            elapsed=0.0,
        )
        self.server.emit("response", item)
        tls_conn.sendall(raw)
        if status == 101:
            self._tunnel(tls_conn, upstream)

    def _read_http_request(self, conn):
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return None
                data += chunk
        except socket.timeout:
            return ("TIMEOUT",)
        if data.startswith(b"PRI * HTTP/2.0"):
            return "HTTP2", "", "", {}, data
        head, rest = data.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1", errors="replace").split("\r\n")
        if not lines:
            return None
        parts = lines[0].split()
        if len(parts) < 2:
            return None
        method = parts[0]
        path = parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"
        headers = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        body = rest
        if headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = self._read_chunked_body(conn, rest)
        else:
            length = int(headers.get("Content-Length", 0) or 0)
            while len(body) < length:
                body += conn.recv(length - len(body))
        return method, path, version, headers, body

    def _read_chunked_body_file(self):
        body = b""
        while True:
            line = self.rfile.readline()
            if not line:
                break
            try:
                size = int(line.strip().split(b";")[0], 16)
            except Exception:
                break
            if size == 0:
                # consume trailing CRLF after last chunk
                self.rfile.readline()
                break
            chunk = self.rfile.read(size)
            body += chunk
            # consume CRLF
            self.rfile.read(2)
        return body

    def _read_chunked_body(self, conn, initial: bytes) -> bytes:
        data = initial
        body = b""
        while True:
            if b"\r\n" not in data:
                data += conn.recv(4096)
                continue
            line, data = data.split(b"\r\n", 1)
            try:
                size = int(line.strip().split(b";")[0], 16)
            except Exception:
                return body
            if size == 0:
                break
            while len(data) < size + 2:
                data += conn.recv(4096)
            body += data[:size]
            data = data[size + 2:]
        return body


class ThreadingHTTPProxyServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, logger=None, on_event: Optional[Callable] = None):
        super().__init__(server_address, ProxyRequestHandler)
        self.logger = logger
        self.on_event = on_event
        self.intercept_enabled = False
        self.mitm_enabled = False
        self.cert_manager = None
        self._counter = 0

    def emit(self, event_type: str, item: ProxyItem):
        if self.on_event:
            try:
                self.on_event({"type": event_type, "item": item})
            except Exception:
                pass

    def build_item(self, method: str, url: str, headers: dict, body: bytes, raw: Optional[str] = None, client=None) -> ProxyItem:
        self._counter += 1
        return ProxyItem(
            id=str(self._counter),
            method=method,
            url=url,
            headers=headers,
            body=body,
            raw=raw or build_raw_request(method, url, headers, body),
            client=f"{client[0]}:{client[1]}" if client else "",
            created_at=time.time(),
        )


class ProxyController:
    def __init__(self, host: str, port: int, on_event: Optional[Callable] = None, logger=None):
        self.host = host
        self.port = port
        self.on_event = on_event
        self.logger = logger
        self.server: Optional[ThreadingHTTPProxyServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.server = ThreadingHTTPProxyServer((self.host, self.port), logger=self.logger, on_event=self.on_event)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if not self.server:
            return
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass
        self.server = None

    def set_intercept(self, enabled: bool):
        if self.server:
            self.server.intercept_enabled = enabled

    def set_mitm(self, enabled: bool, cert_manager=None):
        if self.server:
            self.server.mitm_enabled = enabled
            if cert_manager:
                self.server.cert_manager = cert_manager

    def is_running(self) -> bool:
        return self.server is not None
