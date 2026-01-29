import json
from dataclasses import dataclass
from typing import Dict, Tuple

import requests
import urllib3

try:
    import httpx
except Exception:
    httpx = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


HOP_BY_HOP_HEADERS = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: Dict[str, str]
    body: bytes
    raw: str
    elapsed: float


def _decode_bytes(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("latin-1", errors="replace")


def _clean_headers(headers: Dict[str, str]) -> Dict[str, str]:
    cleaned = {}
    for k, v in headers.items():
        if k.lower() in HOP_BY_HOP_HEADERS:
            continue
        cleaned[k] = v
    return cleaned


def build_raw_request(method: str, url: str, headers: Dict[str, str], body: bytes) -> str:
    lines = [f"{method} {url} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    raw += _decode_bytes(body)
    return raw


def build_raw_response(status: int, reason: str, headers: Dict[str, str], body: bytes) -> str:
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = "\r\n".join(lines) + "\r\n\r\n"
    raw += _decode_bytes(body)
    return raw


def build_raw_response_bytes(status: int, reason: str, headers: Dict[str, str], body: bytes) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("latin-1", errors="replace") + (body or b"")


def parse_raw_request(raw: str) -> Tuple[str, str, Dict[str, str], bytes]:
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
        lines = head.split("\r\n")
    else:
        head, body = raw.split("\n\n", 1) if "\n\n" in raw else (raw, "")
        lines = head.splitlines()
    if not lines:
        raise ValueError("Raw request vacío.")
    first = lines[0].strip()
    parts = first.split()
    if len(parts) < 2:
        raise ValueError("Primera línea inválida.")
    method = parts[0].strip().upper()
    url = parts[1].strip()
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return method, url, headers, body.encode("latin-1", errors="replace")


def normalize_url(url: str, headers: Dict[str, str]) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return url
    host = headers.get("Host") or headers.get("host")
    if not host:
        raise ValueError("No se pudo inferir el Host.")
    return f"http://{host}{url}"


def send_http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: bytes,
    timeout: float = 18.0,
    http2: bool = False,
) -> HttpResponse:
    headers = _clean_headers(headers)
    if "Accept-Encoding" not in headers:
        headers["Accept-Encoding"] = "identity"
    if http2:
        if httpx is None:
            raise RuntimeError("httpx no esta instalado (HTTP/2 no disponible).")
        with httpx.Client(http2=True, verify=False, follow_redirects=False, timeout=timeout) as client:
            resp = client.request(method, url, headers=headers, content=body)
            body_bytes = resp.content or b""
            resp_headers = _clean_headers(dict(resp.headers))
            resp_headers["Content-Length"] = str(len(body_bytes))
            if "Content-Encoding" in resp_headers:
                resp_headers.pop("Content-Encoding", None)
            raw = build_raw_response(resp.status_code, resp.reason_phrase, resp_headers, body_bytes)
            return HttpResponse(
                status=resp.status_code,
                reason=resp.reason_phrase,
                headers=resp_headers,
                body=body_bytes,
                raw=raw,
                elapsed=resp.elapsed.total_seconds(),
            )
    resp = requests.request(
        method=method,
        url=url,
        headers=headers,
        data=body,
        timeout=timeout,
        allow_redirects=False,
        verify=False,
    )
    body_bytes = resp.content or b""
    resp_headers = _clean_headers(dict(resp.headers))
    resp_headers["Content-Length"] = str(len(body_bytes))
    if "Content-Encoding" in resp_headers:
        resp_headers.pop("Content-Encoding", None)
    raw = build_raw_response(resp.status_code, resp.reason, resp_headers, body_bytes)
    return HttpResponse(
        status=resp.status_code,
        reason=resp.reason,
        headers=resp_headers,
        body=body_bytes,
        raw=raw,
        elapsed=resp.elapsed.total_seconds(),
    )


def pretty_body(body: bytes, headers: Dict[str, str]) -> str:
    ctype = headers.get("Content-Type", "")
    text = _decode_bytes(body)
    if "application/json" in ctype:
        try:
            data = json.loads(text)
            return json.dumps(data, indent=2, ensure_ascii=False)
        except Exception:
            return text
    return text
