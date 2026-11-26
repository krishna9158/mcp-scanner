"""
TrustAudit Evidence Vault & Multi-Tenant Document Management System.

Capabilities:
- Secure tenant-isolated document & screenshot uploads
- Strict extension whitelist, size limit, and magic-byte validation
- Control assignment (DPDP, SOC 2, ISO 27001, GDPR)
- Evidence owners, review workflow states, and automatic expiration tracking
- Cryptographic SHA-256 fingerprinting & version history
- Optional application-layer Fernet encryption when TRUSTAUDIT_DATA_KEY is configured
- Strict tenant access isolation and path-traversal protection
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from security_utils import (
    atomic_write_bytes,
    atomic_write_json,
    decrypt_bytes_if_encrypted,
    encrypt_bytes_if_configured,
    get_data_dir,
    safe_read_json,
    safe_resolve_under_dir,
    sanitize_plain_text,
    validate_uploaded_file,
)

EVIDENCE_STORE_FILE = os.path.join(get_data_dir(), "evidence_store.json")
EVIDENCE_FILES_DIR = os.path.join(get_data_dir(), "evidence_vault")

os.makedirs(os.path.dirname(EVIDENCE_STORE_FILE), exist_ok=True)
os.makedirs(EVIDENCE_FILES_DIR, exist_ok=True)

VALID_REVIEW_STATUSES = {
    "Uploaded",
    "Under Review",
    "Verified",
    "Needs Update",
    "Expired",
}


def _load_evidence_data() -> Dict[str, Any]:
    return safe_read_json(EVIDENCE_STORE_FILE, lambda: {"evidence": {}})


def _save_evidence_data(data: Dict[str, Any]) -> None:
    atomic_write_json(EVIDENCE_STORE_FILE, data)


def get_tenant_upload_dir(org_id: str) -> str:
    """Returns safe tenant-isolated directory, preventing path traversal."""
    safe_org = "".join(c for c in str(org_id or "") if c.isalnum() or c in ("-", "_")).strip()
    if not safe_org:
        safe_org = "org-default"
    os.makedirs(EVIDENCE_FILES_DIR, exist_ok=True)
    tenant_dir = safe_resolve_under_dir(EVIDENCE_FILES_DIR, safe_org)
    os.makedirs(tenant_dir, exist_ok=True)
    return tenant_dir


def _persist_validated_file(
    org_id: str,
    storage_prefix: str,
    filename: str,
    file_bytes: bytes,
) -> Dict[str, Any]:
    ok, err_msg, meta = validate_uploaded_file(filename, file_bytes)
    if not ok:
        raise ValueError(err_msg)

    tenant_dir = get_tenant_upload_dir(org_id)
    storage_filename = f"{storage_prefix}_{meta['safe_filename']}"
    dest_path = safe_resolve_under_dir(tenant_dir, storage_filename)

    stored_bytes, is_encrypted = encrypt_bytes_if_configured(bytes(file_bytes))
    atomic_write_bytes(dest_path, stored_bytes)

    return {
        "original_filename": meta["original_filename"],
        "safe_filename": meta["safe_filename"],
        "stored_filename": storage_filename,
        "file_size": meta["size_bytes"],
        "content_type": meta["mime_type"],
        "extension": meta["extension"],
        "previewable": meta["previewable"],
        "sha256": meta["sha256"],
        "encrypted": is_encrypted,
        "uploaded_at": time.time(),
    }


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
    tags: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Creates and stores a new evidence document or screenshot with cryptographic integrity hash.
    Enforces strict file validation and tenant isolation.
    """
    now = time.time()
    evidence_id = f"EV-{uuid.uuid4().hex[:10].upper()}"
    review_due_at = now + (max(1, int(review_cycle_days or 90)) * 86400)

    file_info = None
    if file_bytes is not None or filename is not None:
        if not file_bytes or not filename:
            raise ValueError("Both file content and filename are required when attaching a file.")
        file_info = _persist_validated_file(org_id, evidence_id, filename, file_bytes)

    evidence_record = {
        "id": evidence_id,
        "org_id": org_id,
        "title": sanitize_plain_text(title, 240),
        "control_id": sanitize_plain_text(control_id, 80),
        "framework": sanitize_plain_text(framework, 40).upper(),
        "description": sanitize_plain_text(description, 2000),
        "owner_name": sanitize_plain_text(owner_name, 120) or "Compliance Lead",
        "owner_email": sanitize_plain_text(owner_email, 160),
        "status": "ACTIVE",
        "review_status": "Uploaded",
        "created_at": now,
        "updated_at": now,
        "review_cycle_days": max(1, int(review_cycle_days or 90)),
        "review_due_at": review_due_at,
        "is_expired": False,
        "file": file_info,
        "tags": [sanitize_plain_text(t, 40) for t in (tags or []) if sanitize_plain_text(t, 40)],
        "versions": [
            {
                "version": 1,
                "created_at": now,
                "notes": "Initial evidence creation",
                "file": file_info,
            }
        ],
    }

    data = _load_evidence_data()
    data.setdefault("evidence", {})[evidence_id] = evidence_record
    _save_evidence_data(data)

    return evidence_record


def list_evidence_for_org(
    org_id: str,
    control_id: Optional[str] = None,
    framework: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Lists evidence records strictly filtered to the calling organization.
    Checks and updates expired evidence status dynamically.
    """
    data = _load_evidence_data()
    now = time.time()
    results = []

    for _, ev in data.get("evidence", {}).items():
        if ev.get("org_id") != org_id:
            continue

        review_due = ev.get("review_due_at", 0)
        is_expired = review_due > 0 and review_due < now
        ev["is_expired"] = is_expired
        if is_expired and ev.get("status") == "ACTIVE":
            ev["status"] = "EXPIRED"
            ev["review_status"] = "Expired"

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


def read_evidence_file_bytes(
    evidence_id: str,
    org_id: str,
    version: Optional[int] = None,
) -> Tuple[Optional[bytes], Optional[Dict[str, Any]]]:
    """
    Reads and decrypts physical file bytes belonging to org_id strictly.
    Returns (raw_bytes, file_meta) or (None, None) if unauthorized or missing.
    """
    ev = get_evidence_item(evidence_id, org_id)
    if not ev:
        return None, None

    file_meta = ev.get("file")
    if version is not None:
        for v in ev.get("versions", []):
            if v.get("version") == version:
                file_meta = v.get("file")
                break

    if not file_meta or not file_meta.get("stored_filename"):
        return None, None

    tenant_dir = get_tenant_upload_dir(org_id)
    dest_path = safe_resolve_under_dir(tenant_dir, file_meta["stored_filename"])
    if not os.path.exists(dest_path):
        return None, None

    with open(dest_path, "rb") as f:
        disk_bytes = f.read()

    raw_bytes = decrypt_bytes_if_encrypted(disk_bytes, bool(file_meta.get("encrypted")))
    return raw_bytes, file_meta


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
    version_notes: str = "Updated evidence version",
    review_status: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Updates an evidence item and appends a version history entry if a new file is attached."""
    data = _load_evidence_data()
    ev = data.get("evidence", {}).get(evidence_id)
    if not ev or ev.get("org_id") != org_id:
        return None

    now = time.time()
    if title:
        ev["title"] = sanitize_plain_text(title, 240)
    if description is not None:
        ev["description"] = sanitize_plain_text(description, 2000)
    if owner_name:
        ev["owner_name"] = sanitize_plain_text(owner_name, 120)
    if review_due_at:
        ev["review_due_at"] = review_due_at
        ev["is_expired"] = review_due_at < now
    if review_status and review_status in VALID_REVIEW_STATUSES:
        ev["review_status"] = review_status

    if new_file_bytes is not None or new_filename is not None:
        if not new_file_bytes or not new_filename:
            raise ValueError("Both file content and filename are required when uploading a new version.")
        current_v = len(ev.get("versions", [])) + 1
        file_info = _persist_validated_file(org_id, f"{evidence_id}_v{current_v}", new_filename, new_file_bytes)
        ev["file"] = file_info
        ev["review_status"] = "Uploaded"
        ev.setdefault("versions", []).append({
            "version": current_v,
            "created_at": now,
            "notes": sanitize_plain_text(version_notes, 500),
            "file": file_info,
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

    tenant_dir = get_tenant_upload_dir(org_id)
    for v in ev.get("versions", []):
        f = v.get("file")
        if f and f.get("stored_filename"):
            try:
                path = safe_resolve_under_dir(tenant_dir, f["stored_filename"])
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass

    del data["evidence"][evidence_id]
    _save_evidence_data(data)
    return True


def delete_all_org_evidence(org_id: str) -> int:
    """Deletes all evidence metadata and physical files belonging to org_id."""
    data = _load_evidence_data()
    targets = [ev_id for ev_id, ev in data.get("evidence", {}).items() if ev.get("org_id") == org_id]
    removed = 0
    for ev_id in targets:
        if delete_evidence_item(ev_id, org_id):
            removed += 1
    tenant_dir = get_tenant_upload_dir(org_id)
    try:
        if os.path.isdir(tenant_dir) and not os.listdir(tenant_dir):
            os.rmdir(tenant_dir)
    except Exception:
        pass
    return removed
