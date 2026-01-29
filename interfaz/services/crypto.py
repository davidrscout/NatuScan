import base64
import binascii
import hashlib


def b64_encode(text):
    return base64.b64encode(text.encode()).decode()


def b64_decode(text):
    try:
        return base64.b64decode(text).decode(errors="ignore")
    except binascii.Error as exc:
        raise ValueError("Base64 inválido") from exc


def hash_text(text, algo):
    h = hashlib.new(algo)
    h.update(text.encode())
    return h.hexdigest()


def text_to_bin(text):
    return " ".join(format(ord(c), "08b") for c in text)


def bin_to_text(text):
    try:
        chars = [chr(int(b, 2)) for b in text.split()]
        return "".join(chars)
    except Exception as exc:
        raise ValueError("Binario inválido (usa 8 bits separados por espacio)") from exc


def text_to_hex(text):
    return text.encode().hex()


def hex_to_text(text):
    try:
        return bytes.fromhex(text.replace(" ", "")).decode(errors="ignore")
    except Exception as exc:
        raise ValueError("Hex inválido") from exc
