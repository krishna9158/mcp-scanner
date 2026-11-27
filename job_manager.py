"""
Background Task & Async Job Runner for TrustAudit.

Supports asynchronous execution for long-running operations without blocking HTTP threads:
- DPDP Website Privacy Checks (/api/dpdp/scanner/start?async=1)
- Document & Spreadsheet Discovery Extraction (/api/dpdp/extraction/upload?async=1)
- Multi-artifact PDF & Evidence Vault ZIP Bundles (/api/dpdp/reports/jobs)

Provides tenant-isolated job tracking, progress updates, idempotency deduplication,
and safe cooperative cancellation.
"""

import secrets
import threading
import time
from typing import Any, Callable, Dict, Optional

_JOBS_LOCK = threading.RLock()
_JOBS: Dict[str, Dict[str, Any]] = {}
_IDEMPOTENCY: Dict[str, str] = {}
MAX_RETAINED_JOBS = 250


def _prune_old_jobs() -> None:
    if len(_JOBS) <= MAX_RETAINED_JOBS:
        return
    ordered = sorted(_JOBS.items(), key=lambda kv: kv[1].get("created_at", 0))
    for jid, meta in ordered[: len(_JOBS) - MAX_RETAINED_JOBS]:
        _JOBS.pop(jid, None)
        idem = meta.get("idempotency_key")
        if idem and _IDEMPOTENCY.get(idem) == jid:
            _IDEMPOTENCY.pop(idem, None)


def submit_job(
    org_id: str,
    job_type: str,
    title: str,
    worker_fn: Callable[[Callable[[int, str], None], Callable[[], bool]], Any],
    idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Queues worker_fn(update_progress, is_cancelled) on a daemon thread and returns job metadata.
    If a matching active or recently completed job exists for (org_id, idempotency_key), reuses it cleanly.
    """
    now = time.time()
    scoped_idem = f"{org_id}::{job_type}::{idempotency_key}" if idempotency_key else None

    with _JOBS_LOCK:
        if scoped_idem and scoped_idem in _IDEMPOTENCY:
            existing_id = _IDEMPOTENCY[scoped_idem]
            existing = _JOBS.get(existing_id)
            if existing and existing.get("status") in ("QUEUED", "RUNNING", "COMPLETED"):
                # Reuse recent completed job within 20 seconds or still-running job
                if existing.get("status") != "COMPLETED" or (now - existing.get("finished_at", 0) < 20):
                    return dict(existing)

        job_id = f"job-{secrets.token_hex(6)}"
        record: Dict[str, Any] = {
            "job_id": job_id,
            "org_id": org_id,
            "job_type": job_type,
            "title": title,
            "status": "QUEUED",
            "progress": 0,
            "stage": "Queued for execution",
            "created_at": now,
            "started_at": None,
            "finished_at": None,
            "error": None,
            "result": None,
            "cancelled": False,
            "idempotency_key": scoped_idem,
        }
        _JOBS[job_id] = record
        if scoped_idem:
            _IDEMPOTENCY[scoped_idem] = job_id
        _prune_old_jobs()

    def update_progress(pct: int, stage_msg: str) -> None:
        with _JOBS_LOCK:
            rec = _JOBS.get(job_id)
            if rec and not rec.get("cancelled"):
                rec["progress"] = max(0, min(100, int(pct)))
                rec["stage"] = str(stage_msg)[:180]

    def is_cancelled() -> bool:
        with _JOBS_LOCK:
            rec = _JOBS.get(job_id)
            return bool(rec and rec.get("cancelled"))

    def runner() -> None:
        with _JOBS_LOCK:
            rec = _JOBS.get(job_id)
            if not rec or rec.get("cancelled"):
                return
            rec["status"] = "RUNNING"
            rec["started_at"] = time.time()
            rec["progress"] = max(rec["progress"], 10)
            rec["stage"] = "Running..."
        try:
            res = worker_fn(update_progress, is_cancelled)
            with _JOBS_LOCK:
                rec = _JOBS.get(job_id)
                if not rec:
                    return
                if rec.get("cancelled"):
                    rec["status"] = "CANCELLED"
                    rec["finished_at"] = time.time()
                else:
                    rec["status"] = "COMPLETED"
                    rec["progress"] = 100
                    rec["stage"] = "Completed"
                    rec["result"] = res
                    rec["finished_at"] = time.time()
        except Exception as exc:
            with _JOBS_LOCK:
                rec = _JOBS.get(job_id)
                if rec:
                    rec["status"] = "FAILED"
                    rec["error"] = str(exc)[:300]
                    rec["stage"] = "Failed"
                    rec["finished_at"] = time.time()

    threading.Thread(target=runner, daemon=True, name=f"ta-{job_type}").start()
    return dict(record)


def get_job(org_id: str, job_id: str) -> Optional[Dict[str, Any]]:
    """Returns tenant-isolated job state (without exposing heavy raw binary payloads directly)."""
    with _JOBS_LOCK:
        rec = _JOBS.get(job_id)
        if not rec or rec.get("org_id") != org_id:
            return None
        out = dict(rec)
        # Never serialize raw binary bytes inside JSON status responses
        res = out.get("result")
        if isinstance(res, dict) and "bytes" in res:
            clean_res = dict(res)
            clean_res["size_bytes"] = len(clean_res.pop("bytes") or b"")
            clean_res["download_ready"] = True
            out["result"] = clean_res
        return out


def get_job_download(org_id: str, job_id: str) -> Optional[Dict[str, Any]]:
    """Returns binary artifact metadata once a download job finishes."""
    with _JOBS_LOCK:
        rec = _JOBS.get(job_id)
        if not rec or rec.get("org_id") != org_id or rec.get("status") != "COMPLETED":
            return None
        res = rec.get("result")
        if isinstance(res, dict) and "bytes" in res:
            return dict(res)
        return None


def cancel_job(org_id: str, job_id: str) -> Optional[Dict[str, Any]]:
    with _JOBS_LOCK:
        rec = _JOBS.get(job_id)
        if not rec or rec.get("org_id") != org_id:
            return None
        rec["cancelled"] = True
        if rec.get("status") in ("QUEUED", "RUNNING"):
            rec["status"] = "CANCELLED"
            rec["stage"] = "Cancelled by user"
            rec["finished_at"] = time.time()
        return dict(rec)
