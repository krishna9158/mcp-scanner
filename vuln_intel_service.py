"""
TrustAudit Background Vulnerability Intelligence Service.

Manages scheduled background synchronization across OSV, NVD CVE API 2.0,
and CISA KEV feeds, and coordinates continuous customer inventory correlation.
"""

import datetime
import os
import threading
import time
from typing import Any, Dict, List, Optional

import correlation_engine
import inventory_engine
import vuln_intel_sources
import vuln_intel_store

_intel_worker_thread: Optional[threading.Thread] = None
_intel_worker_running = False
_intel_worker_lock = threading.Lock()

# Configurable sync intervals in seconds (Defaults: KEV every 12h, NVD every 6h, OSV & Correlation on-demand & every 1h)
KEV_SYNC_INTERVAL = int(os.environ.get("TRUSTAUDIT_KEV_SYNC_INTERVAL", 43200))      # 12 hours
NVD_SYNC_INTERVAL = int(os.environ.get("TRUSTAUDIT_NVD_SYNC_INTERVAL", 21600))      # 6 hours
CORRELATION_INTERVAL = int(os.environ.get("TRUSTAUDIT_CORR_SYNC_INTERVAL", 3600))   # 1 hour


# ---------------------------------------------------------------------------
# Discrete Callable Jobs
# ---------------------------------------------------------------------------

def kev_sync() -> Dict[str, Any]:
    """Job: Synchronizes CISA Known Exploited Vulnerabilities catalog."""
    print("[INTEL WORKER] Executing CISA KEV catalog sync job...", flush=True)
    count, err = vuln_intel_sources.sync_cisa_kev_catalog()
    if err:
        vuln_intel_store.update_source_status("cisa_kev", status="Degraded", error=err)
    else:
        vuln_intel_store.update_source_status("cisa_kev", status="Healthy")
    return {"job": "kev_sync", "count": count, "error": err}


def nvd_sync(days_back: int = 1) -> Dict[str, Any]:
    """Job: Incremental synchronization with NVD CVE API 2.0."""
    print(f"[INTEL WORKER] Executing NVD incremental sync job (last {days_back} days)...", flush=True)
    records, err = vuln_intel_sources.sync_recent_nvd_cves(days_back=days_back)
    if records:
        created, updated = vuln_intel_store.upsert_vulnerabilities_batch(records, source_name="nvd")
        return {"job": "nvd_sync", "fetched": len(records), "created": created, "updated": updated, "error": None}
    elif err:
        vuln_intel_store.update_source_status("nvd", status="Degraded", error=err)
        return {"job": "nvd_sync", "fetched": 0, "error": err}
    else:
        vuln_intel_store.update_source_status("nvd", status="Healthy")
        return {"job": "nvd_sync", "fetched": 0, "error": None}


def customer_vulnerability_correlation(org_id: str = "org-default") -> Dict[str, Any]:
    """Job: Correlates entire organization software inventory against vulnerability database."""
    print(f"[INTEL WORKER] Running customer vulnerability correlation for org '{org_id}'...", flush=True)
    findings = correlation_engine.correlate_all_customer_inventory(org_id=org_id)
    return {"job": "customer_correlation", "findings_evaluated": len(findings), "status": "completed"}


def vulnerability_intelligence_sync(org_id: str = "org-default") -> Dict[str, Any]:
    """
    Job: Full intelligence sweep across KEV, NVD, and customer inventory correlation.
    """
    t0 = time.time()
    kev_res = kev_sync()
    nvd_res = nvd_sync(days_back=1)
    corr_res = customer_vulnerability_correlation(org_id=org_id)
    dur = round(time.time() - t0, 2)

    return {
        "status": "success",
        "duration_seconds": dur,
        "kev_sync": kev_res,
        "nvd_sync": nvd_res,
        "correlation": corr_res,
        "summary": vuln_intel_store.get_intelligence_sync_summary(),
    }


# ---------------------------------------------------------------------------
# Background Worker Daemon
# ---------------------------------------------------------------------------

def _intelligence_worker_loop():
    """Background continuous loop for vulnerability intelligence sync."""
    global _intel_worker_running
    print("[INTEL WORKER] Background vulnerability intelligence worker started.", flush=True)

    # Initial sync on startup
    try:
        kev_sync()
    except Exception as e:
        print(f"[INTEL WORKER] Initial KEV sync warning: {e}", flush=True)

    last_kev_sync = time.time()
    last_nvd_sync = time.time()
    last_corr_sync = time.time()

    while _intel_worker_running:
        try:
            now = time.time()

            # 1. CISA KEV Sync
            if now - last_kev_sync >= KEV_SYNC_INTERVAL:
                kev_sync()
                last_kev_sync = now

            # 2. NVD Incremental Sync
            if now - last_nvd_sync >= NVD_SYNC_INTERVAL:
                nvd_sync(days_back=1)
                last_nvd_sync = now

            # 3. Customer Correlation Sweep
            if now - last_corr_sync >= CORRELATION_INTERVAL:
                customer_vulnerability_correlation("org-default")
                last_corr_sync = now

        except Exception as e:
            print(f"[INTEL WORKER] Exception in worker loop: {e}", flush=True)

        time.sleep(30)  # Check every 30s


def start_vulnerability_intelligence_worker():
    """Starts the background vulnerability intelligence thread."""
    global _intel_worker_thread, _intel_worker_running
    with _intel_worker_lock:
        if _intel_worker_thread and _intel_worker_thread.is_alive():
            return
        _intel_worker_running = True
        _intel_worker_thread = threading.Thread(target=_intelligence_worker_loop, daemon=True)
        _intel_worker_thread.start()


def stop_vulnerability_intelligence_worker():
    """Stops the background worker thread."""
    global _intel_worker_running
    _intel_worker_running = False
