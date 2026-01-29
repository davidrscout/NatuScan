import json
import os
import threading

DEFAULT_WORDLIST_ROOTS = []

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".cybernatu_settings.json")

TAG_KEYWORDS = {
    "web": (
        "dirb",
        "dirbuster",
        "web",
        "raft",
        "common",
        "directory-list",
        "gobuster",
        "fuzz",
        "content",
        "discover",
        "extensions",
        "files",
        "urls",
    ),
    "password": (
        "password",
        "rockyou",
        "john",
        "hash",
        "credential",
        "pass",
        "pwd",
    ),
    "user": (
        "user",
        "username",
        "login",
        "names",
    ),
    "dns": (
        "dns",
        "subdomain",
        "subdomains",
        "hosts",
    ),
}


def load_settings():
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                roots = data.get("wordlist_roots") or []
                if isinstance(roots, list) and roots:
                    return {"wordlist_roots": roots}
        except Exception:
            pass
    return {"wordlist_roots": DEFAULT_WORDLIST_ROOTS.copy()}


def save_settings(settings):
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f)
    except Exception:
        pass


def _size_bucket_size(size):
    if size <= 150_000:
        return "small"
    if size <= 1_500_000:
        return "medium"
    return "large"


def _match_keywords(path, keywords):
    name = os.path.basename(path).lower()
    full = path.lower()
    return any(k in name or k in full for k in keywords)


def _detect_tags(path):
    tags = set()
    for tag, keywords in TAG_KEYWORDS.items():
        if _match_keywords(path, keywords):
            tags.add(tag)
    if not tags:
        tags.add("generic")
    return tags


def _sort_for_size(entries, size):
    if size == "small":
        return sorted(entries, key=lambda e: e["size"])
    if size == "large":
        return sorted(entries, key=lambda e: e["size"], reverse=True)
    return sorted(entries, key=lambda e: abs(e["size"] - 600_000))


def _filter_for_task(entries, task):
    if task == "web":
        preferred = [e for e in entries if "web" in e["tags"]]
        if preferred:
            return preferred
        return [e for e in entries if "password" not in e["tags"] and "user" not in e["tags"]]
    if task == "password":
        preferred = [e for e in entries if "password" in e["tags"]]
        if preferred:
            return preferred
        return [e for e in entries if "web" not in e["tags"]]
    if task == "user":
        preferred = [e for e in entries if "user" in e["tags"]]
        return preferred if preferred else entries
    if task == "dns":
        preferred = [e for e in entries if "dns" in e["tags"]]
        return preferred if preferred else entries
    return entries


class WordlistManager:
    def __init__(self, logger=None):
        self.logger = logger
        settings = load_settings()
        self.roots = settings.get("wordlist_roots", DEFAULT_WORDLIST_ROOTS.copy())
        self.index = []
        self.scanning = False
        self.ready = False
        self.lock = threading.Lock()

    def set_roots(self, roots):
        self.roots = roots
        save_settings({"wordlist_roots": roots})

    def scan(self, max_files=8000):
        with self.lock:
            self.scanning = True
            self.ready = False
        entries = []
        for root in self.roots:
            if not root or not os.path.isdir(root):
                continue
            for dirpath, _, filenames in os.walk(root):
                for name in filenames:
                    if not name.lower().endswith(".txt"):
                        continue
                    path = os.path.join(dirpath, name)
                    try:
                        size = os.path.getsize(path)
                    except Exception:
                        size = 0
                    entries.append({
                        "path": path,
                        "size": size,
                        "size_bucket": _size_bucket_size(size),
                        "tags": _detect_tags(path),
                    })
                    if len(entries) >= max_files:
                        break
                if len(entries) >= max_files:
                    break
        with self.lock:
            self.index = entries
            self.scanning = False
            self.ready = True
        return len(entries)

    def stats(self):
        with self.lock:
            entries = list(self.index)
        counts = {"web": 0, "password": 0, "user": 0, "dns": 0, "generic": 0}
        for entry in entries:
            for tag in entry["tags"]:
                counts[tag] = counts.get(tag, 0) + 1
        return counts

    def pick_for_task(self, task, size="small"):
        with self.lock:
            entries = list(self.index)
        if not entries:
            return None
        filtered = _filter_for_task(entries, task)
        size_bucketed = [e for e in filtered if e["size_bucket"] == size]
        candidates = size_bucketed if size_bucketed else filtered
        ordered = _sort_for_size(candidates, size)
        return ordered[0]["path"] if ordered else None

    def suggestions_for_task(self, task, size="small", limit=5):
        with self.lock:
            entries = list(self.index)
        if not entries:
            return []
        filtered = _filter_for_task(entries, task)
        size_bucketed = [e for e in filtered if e["size_bucket"] == size]
        candidates = size_bucketed if size_bucketed else filtered
        ordered = _sort_for_size(candidates, size)
        return [e["path"] for e in ordered[:limit]]
