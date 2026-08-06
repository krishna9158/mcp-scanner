import json
import os
import re
import time

STORE_PATH = os.path.join(os.path.dirname(__file__), "scan_results.json")


def _normalize_repo_key(github_url):
    """
    Turns any reasonable form of a GitHub URL into one consistent key, so
    'https://github.com/x/y', 'https://github.com/x/y.git', and
    'github.com/x/y/' all map to the same stored result.
    """
    key = github_url.strip().lower()
    key = re.sub(r'^https?://', '', key)
    key = key.rstrip('/')
    if key.endswith('.git'):
        key = key[:-4]
    return key


def _load_store():
    if not os.path.exists(STORE_PATH):
        return {}
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_store(data):
    try:
        with open(STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass  # best-effort - a failed badge save should never break a scan


def save_scan_result(github_url, overall_score):
    data = _load_store()
    data[_normalize_repo_key(github_url)] = {
        "score": overall_score,
        "scanned_at": time.time(),
    }
    _save_store(data)


def get_last_scan_result(github_url):
    data = _load_store()
    return data.get(_normalize_repo_key(github_url))
