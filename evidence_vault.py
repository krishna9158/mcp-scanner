"""
TrustAudit Evidence Vault & Multi-Tenant Document Management System.

Capabilities:
- Secure tenant-isolated document & screenshot uploads
- Control assignment (DPDP, SOC 2, ISO 27001, GDPR)
- Evidence owners, review dates, and automatic expiration tracking
- Cryptographic SHA-256 fingerprinting & version history
- Strict tenant access isolation (preventing cross-customer data exposure)
"""

import hashlib
import json
import os
import shutil
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

EVIDENCE_STORE_FILE = os.path.join(os.path.dirname(__file__), "data", "evidence_store.json")
EVIDENCE_FILES_DIR = os.path.join(os.path.dirname(__file__), "data", "evidence_vault")

os.makedirs(os.path.dirname(EVIDENCE_STORE_FILE), exist_ok=True)
os.makedirs(EVIDENCE_FILES_DIR, exist_ok=True)


def _load_evidence_data() -> Dict[str, Any]:
    if not os.path.exists(EVIDENCE_STORE_FILE):
        return {"evidence": {}}
    try:
        with open(EVIDENCE_STORE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"evidence": {}}


def _save_evidence_data(data: Dict[str, Any]):
    try:
        with open(EVIDENCE_STORE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[EVIDENCE_VAULT] Error saving evidence: {e}", flush=True)


def get_tenant_upload_dir(org_id: str) -> str:
    """Returns safe tenant-isolated directory, preventing path traversal."""
    safe_org = "".join(c for c in org_id if c.isalnum() or c in ("-", "_")).strip()
    if not safe_org:
        safe_org = "org-default"
    tenant_dir = os.path.join(EVIDENCE_FILES_DIR, safe_org)
    os.makedirs(tenant_dir, exist_ok=True)
    return tenant_dir


def create_evidence_item(
    org_id: str,
    title: str,
    control_id: str,
    framework: str,
    description: str = "",
    owner_name: str = "Compliance Lead",
    owner_email: str = "",
    review_cycle_days: int = 90,
    file_bytes: Optional[bytes] = None,
    filename: Optional[str] = None,
    content_type: str = "text/plain",
    tags: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Creates and stores a new evidence document or screenshot with cryptographic integrity hash.
    Ensures strict tenant isolation.
    """
    now = time.time()
    evidence_id = f"EV-{uuid.uuid4().hex[:10].upper()}"
    review_due_at = now + (review_cycle_days * 86400)

    file_info = None
    if file_bytes and filename:
        clean_filename = os.path.basename(filename).replace(" ", "_")
        tenant_dir = get_tenant_upload_dir(org_id)
        storage_filename = f"{evidence_id}_{clean_filename}"
        dest_path = os.path.join(tenant_dir, storage_filename)
        
        with open(dest_path, "wb") as f:
            f.write(file_bytes)

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        file_info = {
            "original_filename": clean_filename,
            "stored_filename": storage_filename,
            "file_size": len(file_bytes),
            "content_type": content_type,
            "sha256": sha256,
            "uploaded_at": now
        }

    evidence_record = {
        "id": evidence_id,
        "org_id": org_id,
        "title": title.strip(),
        "control_id": control_id.strip(),
        "framework": framework.upper().strip(),
        "description": description.strip(),
        "owner_name": owner_name.strip(),
        "owner_email": owner_email.strip(),
        "status": "ACTIVE",
        "created_at": now,
        "updated_at": now,
        "review_cycle_days": review_cycle_days,
        "review_due_at": review_due_at,
        "is_expired": False,
        "file": file_info,
        "tags": tags or [],
        "versions": [
            {
                "version": 1,
                "created_at": now,
                "notes": "Initial evidence creation",
                "file": file_info
            }
        ]
    }

    data = _load_evidence_data()
    data.setdefault("evidence", {})[evidence_id] = evidence_record
    _save_evidence_data(data)

    return evidence_record


def list_evidence_for_org(org_id: str, control_id: Optional[str] = None, framework: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Lists evidence records strictly filtered to the calling organization.
    Checks and updates expired evidence status dynamically.
    """
    data = _load_evidence_data()
    now = time.time()
    results = []

    for ev_id, ev in data.get("evidence", {}).items():
        if ev.get("org_id") != org_id:
            continue
        
        # Check expiration
        review_due = ev.get("review_due_at", 0)
        is_expired = review_due < now
        ev["is_expired"] = is_expired
        if is_expired and ev.get("status") == "ACTIVE":
            ev["status"] = "EXPIRED"

        if control_id and ev.get("control_id") != control_id:
            continue
        if framework and ev.get("framework") != framework.upper():
            continue

        results.append(ev)

    results.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    return results


def get_evidence_item(evidence_id: str, org_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an evidence item with organization tenant verification."""
    data = _load_evidence_data()
    ev = data.get("evidence", {}).get(evidence_id)
    if not ev or ev.get("org_id") != org_id:
        return None
    return ev


def update_evidence_item(
    evidence_id: str,
    org_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    owner_name: Optional[str] = None,
    review_due_at: Optional[float] = None,
    new_file_bytes: Optional[bytes] = None,
    new_filename: Optional[str] = None,
    content_type: str = "text/plain",
    version_notes: str = "Updated evidence version"
) -> Optional[Dict[str, Any]]:
    """Updates an evidence item and appends a version history entry if a new file is attached."""
    data = _load_evidence_data()
    ev = data.get("evidence", {}).get(evidence_id)
    if not ev or ev.get("org_id") != org_id:
        return None

    now = time.time()
    if title:
        ev["title"] = title.strip()
    if description is not None:
        ev["description"] = description.strip()
    if owner_name:
        ev["owner_name"] = owner_name.strip()
    if review_due_at:
        ev["review_due_at"] = review_due_at
        ev["is_expired"] = review_due_at < now

    if new_file_bytes and new_filename:
        clean_filename = os.path.basename(new_filename).replace(" ", "_")
        tenant_dir = get_tenant_upload_dir(org_id)
        current_v = len(ev.get("versions", [])) + 1
        storage_filename = f"{evidence_id}_v{current_v}_{clean_filename}"
        dest_path = os.path.join(tenant_dir, storage_filename)

        with open(dest_path, "wb") as f:
            f.write(new_file_bytes)

        sha256 = hashlib.sha256(new_file_bytes).hexdigest()
        file_info = {
            "original_filename": clean_filename,
            "stored_filename": storage_filename,
            "file_size": len(new_file_bytes),
            "content_type": content_type,
            "sha256": sha256,
            "uploaded_at": now
        }
        ev["file"] = file_info
        ev.setdefault("versions", []).append({
            "version": current_v,
            "created_at": now,
            "notes": version_notes,
            "file": file_info
        })

    ev["updated_at"] = now
    data["evidence"][evidence_id] = ev
    _save_evidence_data(data)
    return ev


def delete_evidence_item(evidence_id: str, org_id: str) -> bool:
    """Safely deletes an evidence item and its associated files."""
    data = _load_evidence_data()
    ev = data.get("evidence", {}).get(evidence_id)
    if not ev or ev.get("org_id") != org_id:
        return False

    # Remove stored physical files
    tenant_dir = get_tenant_upload_dir(org_id)
    for v in ev.get("versions", []):
        f = v.get("file")
        if f and f.get("stored_filename"):
            path = os.path.join(tenant_dir, f["stored_filename"])
            if os.path.exists(path):
                try:
                    os.remove(path)
                except Exception:
                    pass

    del data["evidence"][evidence_id]
    _save_evidence_data(data)
    return True
