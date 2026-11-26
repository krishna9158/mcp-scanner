"""
TrustAudit Security Utilities, Atomic Storage, Upload Validation, Audit Logging,
Rate Limiting, and Backup/Restore Verification.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
import zipfile
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple


_LOCK_REGISTRY_GUARD = threading.RLock()
_FILE_LOCKS: Dict[str, threading.RLock] = {}


def _get_lock_for_path(path: str) -> threading.RLock:
    norm = os.path.abspath(path)
    with _LOCK_REGISTRY_GUARD:
        lock = _FILE_LOCKS.get(norm)
        if lock is None:
            lock = threading.RLock()
            _FILE_LOCKS[norm] = lock
        return lock


def get_data_dir(default_subdir: str = "data") -> str:
    env_dir = os.environ.get("TRUSTAUDIT_DATA_DIR", "").strip()
    if env_dir:
        return os.path.abspath(env_dir)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, default_subdir)


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_write_bytes(target_path: str, data: bytes) -> None:
    """
    Write bytes atomically using a temporary file in the same directory,
    flushing + fsyncing before os.replace().
    """
    abs_target = os.path.abspath(target_path)
    parent = os.path.dirname(abs_target)
    ensure_dir(parent)
    lock = _get_lock_for_path(abs_target)
    with lock:
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp_ta_", dir=parent)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except OSError:
                    pass
            # Retry briefly for Windows transient file locks
            for attempt in range(3):
                try:
                    os.replace(tmp_path, abs_target)
                    tmp_path = None
                    break
                except PermissionError:
                    if attempt == 2:
                        raise
                    time.sleep(0.02)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass


def atomic_write_json(target_path: str, payload: Any, indent: int = 2) -> None:
    serialized = json.dumps(payload, indent=indent, ensure_ascii=False, default=str).encode("utf-8")
    atomic_write_bytes(target_path, serialized)


def safe_read_json(target_path: str, default_factory: Callable[[], Any] = dict) -> Any:
    abs_target = os.path.abspath(target_path)
    lock = _get_lock_for_path(abs_target)
    with lock:
        if not os.path.exists(abs_target):
            return default_factory()
        try:
            with open(abs_target, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default_factory()


def safe_resolve_under_dir(base_dir: str, relative_path: str) -> str:
    """
    Resolve relative_path strictly underneath base_dir, preventing traversal
    or symlink escapes.
    """
    base_real = os.path.realpath(base_dir)
    if not relative_path or "\x00" in relative_path:
        raise ValueError("Invalid relative file path.")
    candidate = os.path.realpath(os.path.join(base_real, relative_path))
    if candidate == base_real:
        raise ValueError("Path cannot refer to the base directory itself.")
    if os.path.commonpath([base_real, candidate]) != base_real:
        raise ValueError("Path traversal outside base directory blocked.")
    return candidate


# ---------------------------------------------------------------------------
# Upload Validation & Safe MIME Handling
# ---------------------------------------------------------------------------

MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

ALLOWED_UPLOAD_EXTENSIONS = {
    ".pdf",
    ".png",
    ".jpg",
    ".jpeg",
    ".txt",
    ".csv",
    ".md",
    ".docx",
    ".xlsx",
    ".json",
}

BLOCKED_DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".sh", ".bash", ".msi", ".dll", ".so",
    ".dylib", ".py", ".pyc", ".js", ".mjs", ".cjs", ".html", ".htm", ".xhtml",
    ".svg", ".xml", ".php", ".phtml", ".asp", ".aspx", ".jsp", ".vbs", ".vbe",
    ".scr", ".jar", ".war", ".com", ".cpl", ".hta", ".reg", ".lnk",
}

EXTENSION_TO_MIME = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".json": "application/json; charset=utf-8",
}

PREVIEWABLE_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv", ".md", ".json"}


def sanitize_filename(raw_name: str) -> str:
    name = os.path.basename(str(raw_name or "").strip().replace("\\", "/"))
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", name).strip("._")
    if not name:
        return "evidence_file"
    if len(name) > 120:
        stem, ext = os.path.splitext(name)
        name = stem[: 120 - len(ext)] + ext
    return name


def validate_uploaded_file(
    filename: str,
    content_bytes: bytes,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validate file extension, blocked dangerous types, payload size, and magic bytes.
    Returns (ok, error_message, metadata).
    """
    if not filename or not str(filename).strip():
        return False, "Filename is required.", {}

    raw_base = os.path.basename(str(filename).strip().replace("\\", "/"))
    if raw_base.startswith("."):
        return False, "Hidden filenames starting with '.' are not allowed.", {}

    if not isinstance(content_bytes, (bytes, bytearray)) or len(content_bytes) == 0:
        return False, "Uploaded file is empty.", {}

    if len(content_bytes) > max_bytes:
        mb = round(max_bytes / (1024 * 1024), 1)
        return False, f"File exceeds the {mb} MB upload limit.", {}

    # Reject any hidden double dangerous extension like shell.php.png or payload.exe.txt
    lower_parts = raw_base.lower().split(".")
    if len(lower_parts) > 2:
        for mid_part in lower_parts[1:-1]:
            if f".{mid_part}" in BLOCKED_DANGEROUS_EXTENSIONS:
                return False, f"Dangerous compound filename pattern '.{mid_part}' is not permitted.", {}

    _, ext = os.path.splitext(raw_base)
    ext = ext.lower()
    if ext in BLOCKED_DANGEROUS_EXTENSIONS:
        return False, f"Executable or active script file type '{ext}' is blocked for security.", {}

    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        allowed_str = ", ".join(sorted(ALLOWED_UPLOAD_EXTENSIONS))
        return False, f"Unsupported file extension '{ext}'. Allowed types: {allowed_str}.", {}

    data = bytes(content_bytes)

    # Magic-byte verification per file type
    if ext == ".pdf":
        if not data.lstrip().startswith(b"%PDF-"):
            return False, "Invalid PDF file signature (magic bytes mismatch).", {}
    elif ext == ".png":
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            return False, "Invalid PNG file signature (magic bytes mismatch).", {}
    elif ext in {".jpg", ".jpeg"}:
        if not data.startswith(b"\xff\xd8\xff"):
            return False, "Invalid JPEG file signature (magic bytes mismatch).", {}
    elif ext in {".docx", ".xlsx"}:
        if not (data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06")):
            return False, f"Invalid {ext} Office ZIP archive signature.", {}
    elif ext == ".json":
        try:
            text = data.decode("utf-8")
            json.loads(text)
        except Exception:
            return False, "Uploaded JSON file is not valid UTF-8 JSON.", {}
    elif ext in {".txt", ".csv", ".md"}:
        if b"\x00" in data[:4096]:
            return False, "Binary content detected inside text file upload.", {}
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False, f"Uploaded {ext} file must be valid UTF-8 text.", {}

    safe_name = sanitize_filename(raw_base)
    if os.path.splitext(safe_name)[1].lower() != ext:
        safe_name = f"{os.path.splitext(safe_name)[0]}{ext}"

    sha256_hex = hashlib.sha256(data).hexdigest()
    return True, "", {
        "safe_filename": safe_name,
        "original_filename": raw_base[:180],
        "extension": ext,
        "mime_type": EXTENSION_TO_MIME.get(ext, "application/octet-stream"),
        "size_bytes": len(data),
        "sha256": sha256_hex,
        "previewable": ext in PREVIEWABLE_EXTENSIONS,
    }


# ---------------------------------------------------------------------------
# Optional Application-Layer Encryption Helper (Fernet when configured)
# ---------------------------------------------------------------------------

def _get_fernet():
    raw_key = os.environ.get("TRUSTAUDIT_DATA_KEY", "").strip()
    if not raw_key:
        return None
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None

    try:
        # Check if already a valid Fernet urlsafe base64 32-byte key
        return Fernet(raw_key.encode("utf-8"))
    except Exception:
        derived = base64.urlsafe_b64encode(hashlib.sha256(raw_key.encode("utf-8")).digest())
        return Fernet(derived)


def encrypt_bytes_if_configured(data: bytes) -> Tuple[bytes, bool]:
    fernet = _get_fernet()
    if fernet is None:
        return data, False
    return fernet.encrypt(data), True


def decrypt_bytes_if_encrypted(data: bytes, was_encrypted: bool) -> bytes:
    if not was_encrypted:
        return data
    fernet = _get_fernet()
    if fernet is None:
        raise RuntimeError("Encrypted evidence cannot be decrypted because TRUSTAUDIT_DATA_KEY is not configured.")
    return fernet.decrypt(data)


def encryption_status_summary() -> Dict[str, Any]:
    configured = _get_fernet() is not None
    return {
        "app_layer_encryption_configured": configured,
        "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)" if configured else "None (OS/volume disk encryption only)",
        "transport_security": "HTTPS enforced by Render edge proxy in production; local dev uses HTTP",
    }


# ---------------------------------------------------------------------------
# Input Sanitization & Prompt/Log Redaction
# ---------------------------------------------------------------------------

SENSITIVE_KEYS = {
    "password", "password_hash", "token", "access_token", "refresh_token",
    "reset_token", "session_token", "api_key", "secret", "mfa_secret",
    "otp", "authorization", "cookie",
}


def sanitize_plain_text(value: Any, max_len: int = 2000) -> str:
    if value is None:
        return ""
    text = str(value)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text.strip()[:max_len]


def redact_sensitive_dict(data: Any) -> Any:
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if str(k).strip().lower() in SENSITIVE_KEYS:
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_sensitive_dict(v)
        return out
    if isinstance(data, list):
        return [redact_sensitive_dict(item) for item in data[:100]]
    return data


def strip_pii_for_ai(text: str) -> str:
    """
    Minimize accidental personal emails, phone numbers, Aadhaar/PAN-like strings
    before sending user questions to any external AI provider.
    """
    if not text:
        return ""
    cleaned = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[EMAIL_REDACTED]", text)
    cleaned = re.sub(r"(?<!\d)(?:\+91[- ]?)?[6-9]\d{9}(?!\d)", "[PHONE_REDACTED]", cleaned)
    cleaned = re.sub(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "[ID_NUMBER_REDACTED]", cleaned)
    cleaned = re.sub(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "[TAX_ID_REDACTED]", cleaned)
    return cleaned


# ---------------------------------------------------------------------------
# Sliding-Window Rate Limiter
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._guard = threading.RLock()
        self._buckets: Dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - max(1, window_seconds)
        with self._guard:
            dq = self._buckets[key]
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= max_requests:
                retry_after = max(1, int(dq[0] + window_seconds - now) + 1)
                return False, retry_after
            dq.append(now)
            return True, 0

    def reset(self, prefix: Optional[str] = None) -> None:
        with self._guard:
            if not prefix:
                self._buckets.clear()
            else:
                for k in [k for k in self._buckets if k.startswith(prefix)]:
                    del self._buckets[k]


rate_limiter = SlidingWindowRateLimiter()


# ---------------------------------------------------------------------------
# Persistent Security & Compliance Audit Log
# ---------------------------------------------------------------------------

MAX_AUDIT_EVENTS = 5000


def get_audit_log_path() -> str:
    return os.path.join(get_data_dir(), "audit_logs.json")


def append_audit_log(
    org_id: str,
    action: str,
    resource_type: str,
    resource_id: str = "",
    actor_user_id: str = "",
    actor_email: str = "",
    actor_role: str = "",
    status: str = "success",
    details: Optional[Dict[str, Any]] = None,
    ip_address: str = "",
) -> Dict[str, Any]:
    path = get_audit_log_path()
    lock = _get_lock_for_path(path)
    event = {
        "id": f"AUD-{uuid.uuid4().hex[:12].upper()}",
        "timestamp": utc_now_iso(),
        "org_id": str(org_id or ""),
        "actor_user_id": str(actor_user_id or ""),
        "actor_email": sanitize_plain_text(actor_email, 160),
        "actor_role": sanitize_plain_text(actor_role, 40),
        "action": sanitize_plain_text(action, 100),
        "resource_type": sanitize_plain_text(resource_type, 80),
        "resource_id": sanitize_plain_text(resource_id, 120),
        "status": sanitize_plain_text(status, 40),
        "details": redact_sensitive_dict(details or {}),
        "ip_address": sanitize_plain_text(ip_address, 80),
    }
    with lock:
        store = safe_read_json(path, lambda: {"events": []})
        events = store.get("events", [])
        if not isinstance(events, list):
            events = []
        events.append(event)
        if len(events) > MAX_AUDIT_EVENTS:
            events = events[-MAX_AUDIT_EVENTS:]
        store["events"] = events
        atomic_write_json(path, store)
    return event


def get_audit_logs(org_id: str, limit: int = 100, action_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    path = get_audit_log_path()
    store = safe_read_json(path, lambda: {"events": []})
    events = store.get("events", [])
    filtered = [
        ev for ev in reversed(events)
        if ev.get("org_id") == org_id
        and (not action_filter or action_filter.lower() in str(ev.get("action", "")).lower())
    ]
    return copy.deepcopy(filtered[: max(1, min(limit, 500))])


# ---------------------------------------------------------------------------
# Backup Snapshot Creation & Integrity Verification
# ---------------------------------------------------------------------------

def create_backup_snapshot(data_dir: Optional[str] = None, backup_zip_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a verified ZIP snapshot of all workspace JSON stores and uploaded evidence
    files inside data_dir, recording SHA-256 checksums in backup_manifest.json.
    """
    src_dir = os.path.abspath(data_dir or get_data_dir())
    ensure_dir(src_dir)
    if not backup_zip_path:
        backups_dir = os.path.join(src_dir, "backups")
        ensure_dir(backups_dir)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_zip_path = os.path.join(backups_dir, f"trustaudit_backup_{stamp}_{uuid.uuid4().hex[:6]}.zip")

    abs_zip = os.path.abspath(backup_zip_path)
    ensure_dir(os.path.dirname(abs_zip))

    manifest: Dict[str, Any] = {
        "created_at": utc_now_iso(),
        "source_dir": os.path.basename(src_dir),
        "files": [],
    }

    with zipfile.ZipFile(abs_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(src_dir):
            # Never recurse into backups directory itself
            dirs[:] = [d for d in dirs if os.path.abspath(os.path.join(root, d)) != os.path.abspath(os.path.join(src_dir, "backups"))]
            for fname in sorted(files):
                full_path = os.path.join(root, fname)
                if os.path.abspath(full_path) == abs_zip:
                    continue
                rel_path = os.path.relpath(full_path, src_dir).replace("\\", "/")
                with open(full_path, "rb") as f:
                    raw = f.read()
                digest = hashlib.sha256(raw).hexdigest()
                zf.writestr(f"payload/{rel_path}", raw)
                manifest["files"].append({
                    "relative_path": rel_path,
                    "size_bytes": len(raw),
                    "sha256": digest,
                })
        zf.writestr("backup_manifest.json", json.dumps(manifest, indent=2).encode("utf-8"))

    return {
        "backup_path": abs_zip,
        "file_count": len(manifest["files"]),
        "created_at": manifest["created_at"],
    }


def restore_backup_snapshot(
    backup_zip_path: str,
    target_data_dir: str,
    verify_checksums: bool = True,
) -> Dict[str, Any]:
    """
    Safely restore a backup ZIP created by create_backup_snapshot into target_data_dir,
    blocking ZipSlip paths and verifying SHA-256 checksums against backup_manifest.json.
    """
    abs_zip = os.path.abspath(backup_zip_path)
    abs_target = os.path.abspath(target_data_dir)
    ensure_dir(abs_target)

    if not os.path.exists(abs_zip):
        raise FileNotFoundError("Backup archive does not exist.")

    restored = 0
    verified = 0
    with zipfile.ZipFile(abs_zip, "r") as zf:
        if "backup_manifest.json" not in zf.namelist():
            raise ValueError("Invalid TrustAudit backup: backup_manifest.json missing.")
        manifest = json.loads(zf.read("backup_manifest.json").decode("utf-8"))
        expected_hashes = {
            item["relative_path"]: item["sha256"]
            for item in manifest.get("files", [])
        }
        for rel_path, expected_hash in expected_hashes.items():
            archive_member = f"payload/{rel_path}"
            if archive_member not in zf.namelist():
                raise ValueError(f"Backup corrupted: missing member {archive_member}")
            raw = zf.read(archive_member)
            if verify_checksums:
                actual_hash = hashlib.sha256(raw).hexdigest()
                if actual_hash != expected_hash:
                    raise ValueError(f"Checksum mismatch for {rel_path}")
                verified += 1
            dest_path = safe_resolve_under_dir(abs_target, rel_path)
            atomic_write_bytes(dest_path, raw)
            restored += 1

    return {
        "target_dir": abs_target,
        "restored_files": restored,
        "verified_checksums": verified,
        "manifest_created_at": manifest.get("created_at"),
    }
