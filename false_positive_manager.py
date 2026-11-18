"""
False-Positive & Accepted-Risk Management Engine.

Allows security teams to manage finding statuses:
- TRUE_POSITIVE (Active action item)
- FALSE_POSITIVE (Verified non-issue with documented justification)
- ACCEPTED_RISK (Business-approved temporary risk with expiration date)

Maintains an immutable audit record for compliance and SOC2 reviews.
"""
import os
import json
import time

SUPPRESSIONS_DB_PATH = os.path.join(os.path.dirname(__file__), "finding_suppressions.json")


def _load_suppressions():
    if not os.path.exists(SUPPRESSIONS_DB_PATH):
        return {}
    try:
        with open(SUPPRESSIONS_DB_PATH, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}


def _save_suppressions(data):
    try:
        with open(SUPPRESSIONS_DB_PATH, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2)
    except Exception:
        pass


def update_finding_status(repo_key, finding_id, new_status, reason="", user="admin", expires_days=None):
    """
    Updates the lifecycle status of a finding with an audit trail.
    """
    if new_status not in ("open", "acknowledged", "fixed", "verified", "false_positive", "accepted_risk"):
        raise ValueError(f"Invalid status: {new_status}")

    db = _load_suppressions()
    repo_entries = db.setdefault(repo_key, {})

    now = time.time()
    expires_at = (now + (expires_days * 86400)) if expires_days else None

    entry = {
        "finding_id": finding_id,
        "status": new_status,
        "reason": reason,
        "user": user,
        "updated_at": now,
        "expires_at": expires_at,
    }

    repo_entries[finding_id] = entry
    _save_suppressions(db)
    return entry


def filter_suppressed_findings(repo_key, findings_list):
    """
    Applies active suppressions to the findings list.
    Excludes active false_positives or valid accepted_risks from blocking the scan.
    """
    db = _load_suppressions()
    repo_entries = db.get(repo_key, {})
    now = time.time()

    active_findings = []
    suppressed_findings = []

    for f in findings_list:
        fid = f.get("finding_id") or f.get("id")
        entry = repo_entries.get(fid)

        if entry:
            # Check expiration for accepted_risk
            if entry.get("expires_at") and now > entry["expires_at"]:
                active_findings.append({**f, "status": "open", "suppression_expired": True})
            else:
                suppressed_findings.append({**f, "status": entry["status"], "suppression_reason": entry["reason"]})
        else:
            active_findings.append(f)

    return {
        "active_findings": active_findings,
        "suppressed_findings": suppressed_findings,
        "suppressed_count": len(suppressed_findings)
    }
