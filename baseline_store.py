"""
Security Baseline & Drift Store for TrustAudit Platform.


Allows users to "Set Current Version as Trusted Baseline":
Stores:
- Cryptographic fingerprints of tools & schemas
- Approved permissions and capability allocations
- Approved external network destinations
- Pinned dependency signatures
- Accepted findings and active regression tests

On subsequent scans, compares against baseline to detect security drift and regressions.
"""
import os
import json
import time
import re
from rug_pull_detector import create_baseline_fingerprint, detect_rug_pull_and_drift

BASELINE_DB_PATH = os.path.join(os.path.dirname(__file__), "security_baselines.json")


def _normalize_key(url_or_path):
    if not url_or_path:
        return "default"
    k = str(url_or_path).strip().lower()
    k = re.sub(r'^https?://', '', k).rstrip('/')
    if k.endswith('.git'):
        k = k[:-4]
    return k


def _load_baselines():
    if not os.path.exists(BASELINE_DB_PATH):
        return {}
    try:
        with open(BASELINE_DB_PATH, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}


def _save_baselines(data):
    try:
        with open(BASELINE_DB_PATH, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2)
    except Exception:
        pass


def set_security_baseline(repo_identifier, scan_result):
    """
    Saves the provided scan result as the official approved security baseline.
    """
    key = _normalize_key(repo_identifier)
    baselines = _load_baselines()

    tools_report = scan_result.get("report", [])
    fingerprint_map = create_baseline_fingerprint(tools_report, repo_identifier)

    baseline_record = {
        "repo": repo_identifier,
        "set_at": time.time(),
        "set_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "score": scan_result.get("score", 100),
        "grade": scan_result.get("grade", "A"),
        "fingerprints": fingerprint_map,
        "tools_count": len(tools_report),
        "secrets_count": len(scan_result.get("secrets", [])),
        "dependencies": scan_result.get("dependencies", {}),
        "attack_paths_count": len(scan_result.get("attack_paths", [])),
    }

    baselines[key] = baseline_record
    _save_baselines(baselines)
    return baseline_record


def get_security_baseline(repo_identifier):
    """Retrieves the approved baseline for a repository if set."""
    key = _normalize_key(repo_identifier)
    baselines = _load_baselines()
    return baselines.get(key)


def compute_baseline_drift(repo_identifier, current_scan_result):
    """
    Compares the current scan against the stored baseline and returns a detailed drift report.
    """
    baseline = get_security_baseline(repo_identifier)
    if not baseline:
        return {
            "has_baseline": False,
            "status": "NO_BASELINE",
            "message": "No baseline established. Click 'Set as Baseline' to start tracking drift."
        }

    tools_report = current_scan_result.get("report", [])
    rug_pull_report = detect_rug_pull_and_drift(tools_report, baseline.get("fingerprints", {}))

    score_drift = current_scan_result.get("score", 100) - baseline.get("score", 100)

    return {
        "has_baseline": True,
        "baseline_set_at": baseline.get("set_at_iso"),
        "baseline_score": baseline.get("score"),
        "current_score": current_scan_result.get("score"),
        "score_drift": score_drift,
        "rug_pull_alerts": rug_pull_report.get("rug_pull_alerts", []),
        "drift_events": rug_pull_report.get("drift_events", []),
        "is_clean": rug_pull_report.get("is_clean", True),
    }
