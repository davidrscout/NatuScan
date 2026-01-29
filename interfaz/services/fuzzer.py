import requests


def load_wordlist(path):
    with open(path, 'r', errors='ignore') as f:
        return [line.strip() for line in f if line.strip()]


def check_url(base_url, word, timeout=3):
    target = f"{base_url}/{word}"
    try:
        r = requests.get(target, timeout=timeout)
        return r.status_code
    except Exception:
        return None
