"""
TrustAudit Continuous Security Monitoring & Background Scheduler Engine.

Enables automated recurring scans (Daily, Weekly, Hourly, or Manual) for connected
startup assets (Websites, GitHub Repositories, MCP Systems) with tenant safety.
"""

import datetime
import os
import threading
import time
from typing import Any, Dict, List, Optional

import saas_store
import scan_manager
from delta_engine import compute_and_record_scan_delta

# Global scheduler state
_scheduler_thread: Optional[threading.Thread] = None
_scheduler_running = False
_scheduler_lock = threading.Lock()

# Default schedule intervals in seconds
SCHEDULE_INTERVALS = {
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
    "manual": None,
}


def calculate_next_run(frequency: str, from_time: Optional[float] = None) -> Optional[float]:
    """Calculates epoch timestamp for the next scheduled run."""
    base = from_time or time.time()
    interval = SCHEDULE_INTERVALS.get((frequency or "daily").lower())
    if interval is None:
        return None
    return base + interval


def set_project_schedule(
    project_id: str,
    frequency: str = "daily",
    enabled: bool = True,
    org_id: str = "org-default"
) -> Dict[str, Any]:
    """
    Configures continuous monitoring frequency and status for a project.
    """
    freq_clean = (frequency or "daily").lower()
    if freq_clean not in SCHEDULE_INTERVALS:
        freq_clean = "daily"

    now = time.time()
    next_run = calculate_next_run(freq_clean, now) if enabled and freq_clean != "manual" else None

    update_payload = {
        "monitoring_status": "ACTIVE" if enabled else "PAUSED",
        "scan_frequency": freq_clean,
        "next_scan_at": next_run,
        "updated_at": now,
    }

    updated = saas_store.update_project(project_id, update_payload, org_id=org_id)
    return updated or update_payload


def run_scheduled_project_scan(project: Dict[str, Any]) -> Optional[str]:
    """
    Triggers an asynchronous scan for a scheduled project and records timeline delta upon completion.
    """
    proj_id = project.get("id")
    org_id = project.get("org_id", "org-default")
    target_type = project.get("target_type", "website")
    target = project.get("website_url") if target_type == "website" else (project.get("repo_url") or project.get("website_url"))

    if not target:
        return None

    print(f"[SCHEDULER] Triggering continuous monitoring scan for project '{project.get('name')}' ({target})", flush=True)

    # Submit asynchronous scan job
    scan_id, record = scan_manager.submit_async_scan(
        target=target,
        scan_type=target_type,
        full_scan=False,
        org_id=org_id,
        auth_confirmed=True,
    )

    # Launch a watcher thread to record delta once scan finishes
    def _watch_and_record_delta():
        t0 = time.time()
        while time.time() - t0 < 300:  # Max 5 min wait
            time.sleep(2)
            job = scan_manager.get_scan_job(scan_id)
            if not job:
                break
            status = job.get("status")
            if status in ("COMPLETED", "COMPLETED_WITH_WARNINGS", "FAILED", "CANCELLED", "TIMEOUT"):
                if status in ("COMPLETED", "COMPLETED_WITH_WARNINGS") and job.get("result"):
                    scan_res = job["result"]
                    # Record project score and delta
                    saas_store.update_project(proj_id, {
                        "last_score": scan_res.get("score", 100),
                        "last_grade": scan_res.get("grade", "A"),
                        "last_scan": time.time(),
                        "open_findings": len(scan_res.get("findings", [])),
                        "critical_findings": sum(1 for f in scan_res.get("findings", []) if f.get("severity") == "CRITICAL"),
                    }, org_id=org_id)
                    # Compute What Changed delta
                    compute_and_record_scan_delta(proj_id, scan_res, org_id=org_id)
                break

    watcher = threading.Thread(target=_watch_and_record_delta, daemon=True)
    watcher.start()

    # Update project next run time
    freq = project.get("scan_frequency", "daily")
    next_run = calculate_next_run(freq, time.time())
    saas_store.update_project(proj_id, {
        "last_scan": time.time(),
        "next_scan_at": next_run,
    }, org_id=org_id)

    return scan_id


def _scheduler_loop(poll_interval: int = 15):
    """Background loop checking for scheduled scans."""
    global _scheduler_running
    print("[SCHEDULER] Continuous monitoring background worker started.", flush=True)

    while _scheduler_running:
        try:
            now = time.time()
            data = saas_store._load_data()
            projects = list(data.get("projects", {}).values())

            for proj in projects:
                status = proj.get("monitoring_status", "PAUSED")
                next_scan = proj.get("next_scan_at")
                if status == "ACTIVE" and next_scan and next_scan <= now:
                    run_scheduled_project_scan(proj)

        except Exception as e:
            print(f"[SCHEDULER] Error in scheduler loop: {e}", flush=True)

        time.sleep(poll_interval)


def start_scheduler(poll_interval: int = 15):
    """Starts the continuous monitoring scheduler background thread."""
    global _scheduler_thread, _scheduler_running
    with _scheduler_lock:
        if _scheduler_running:
            return
        _scheduler_running = True
        _scheduler_thread = threading.Thread(target=_scheduler_loop, args=(poll_interval,), daemon=True)
        _scheduler_thread.start()


def stop_scheduler():
    """Stops the scheduler background thread."""
    global _scheduler_running
    with _scheduler_lock:
        _scheduler_running = False


def get_monitoring_summary(org_id: str = "org-default") -> Dict[str, Any]:
    """Provides telemetry on monitored assets, scan cadence, and next scan schedule."""
    projects = saas_store.list_projects_for_org(org_id)
    monitored = [p for p in projects if p.get("monitoring_status") == "ACTIVE"]
    paused = [p for p in projects if p.get("monitoring_status") != "ACTIVE"]

    next_runs = [p.get("next_scan_at") for p in monitored if p.get("next_scan_at")]
    soonest_next = min(next_runs) if next_runs else None

    return {
        "total_projects": len(projects),
        "monitored_projects": len(monitored),
        "paused_projects": len(paused),
        "scheduler_active": _scheduler_running,
        "next_scheduled_scan": datetime.datetime.fromtimestamp(soonest_next, datetime.timezone.utc).isoformat() if soonest_next else None,
        "monitored_list": monitored,
    }
