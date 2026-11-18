"""
Scan History & Continuous Monitoring Store.

Stores chronological scan records per repository (JSON/file-backed)
and computes diffs between consecutive scans:
- Score changes (e.g. 88 -> 72)
- New MCP tools discovered
- New hardcoded secrets introduced
- New vulnerable dependencies added
- Resolved / fixed security issues
"""
import os
import json
import time
import re

HISTORY_FILE = os.path.join(os.path.dirname(__file__), "scan_history.json")


def _normalize_repo_key(github_url):
    if not github_url or not isinstance(github_url, str):
        return "local_repo"
    key = github_url.strip().lower()
    key = re.sub(r'^https?://', '', key)
    key = key.rstrip('/')
    if key.endswith('.git'):
        key = key[:-4]
    return key


def _load_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_history(data):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def record_scan_history(github_url, scan_result):
    """
    Appends a new scan snapshot to the repository's audit history.
    """
    key = _normalize_repo_key(github_url)
    history = _load_history()
    repo_history = history.setdefault(key, [])

    snapshot = {
        "timestamp": time.time(),
        "scanned_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "score": scan_result.get("score", 100),
        "grade": scan_result.get("grade", "A"),
        "overall_score": scan_result.get("overall_score", "GREEN"),
        "tools_count": len(scan_result.get("report", [])),
        "secrets_count": len(scan_result.get("secrets", [])),
        "dependencies_count": len(scan_result.get("dependencies", {}).get("findings", []) if isinstance(scan_result.get("dependencies"), dict) else []),
        "appsec_count": len(scan_result.get("appsec_findings", [])),
        "attack_paths_count": len(scan_result.get("attack_paths", [])),
    }

    repo_history.append(snapshot)
    # Keep last 50 scans per repository
    if len(repo_history) > 50:
        history[key] = repo_history[-50:]

    _save_history(history)
    return snapshot


def get_scan_history(github_url):
    """Returns the list of historical scans for a repository."""
    key = _normalize_repo_key(github_url)
    history = _load_history()
    return history.get(key, [])


def get_latest_previous_scan(github_url):
    """Returns the previous scan record for score delta comparison."""
    history = get_scan_history(github_url)
    if len(history) >= 2:
        return history[-2]
    return None
