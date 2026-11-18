"""
TrustAudit Vulnerability Intelligence Storage & Sync State Engine.

Maintains an indexed local database of synchronized CVEs, OSV advisories,
and CISA KEV records with synchronization state tracking per source.
"""

import datetime
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

DATA_FILE = os.path.join(os.path.dirname(__file__), "vuln_intel_data.json")
_store_lock = threading.Lock()


def _get_default_store() -> Dict[str, Any]:
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "sources": {
            "osv": {
                "name": "OSV.dev API",
                "status": "Healthy",
                "last_successful_sync": now_iso,
                "last_attempted_sync": now_iso,
                "records_count": 0,
                "records_created": 0,
                "records_updated": 0,
                "errors": None,
            },
            "nvd": {
                "name": "NVD CVE API 2.0",
                "status": "Healthy",
                "last_successful_sync": now_iso,
                "last_attempted_sync": now_iso,
                "records_count": 0,
                "records_created": 0,
                "records_updated": 0,
                "errors": None,
            },
            "cisa_kev": {
                "name": "CISA KEV Catalog",
                "status": "Healthy",
                "last_successful_sync": now_iso,
                "last_attempted_sync": now_iso,
                "records_count": 0,
                "records_created": 0,
                "records_updated": 0,
                "errors": None,
            }
        },
        "vulnerabilities": {},
        "cve_index": {},
        "package_index": {}
    }


def _load_store() -> Dict[str, Any]:
    if not os.path.exists(DATA_FILE):
        initial = _get_default_store()
        try:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                json.dump(initial, f, indent=2)
        except Exception:
            pass
        return initial
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return _get_default_store()


def _save_store(data: Dict[str, Any]) -> None:
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[VULN_STORE] Save failed: {e}", flush=True)


def upsert_vulnerability(vuln_record: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Inserts or updates a vulnerability record in the intelligence store.
    Returns (record, is_new).
    """
    with _store_lock:
        store = _load_store()
        vid = vuln_record.get("id") or f"VULN-{vuln_record.get('cve_id') or vuln_record.get('source_id')}"
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        existing = store.get("vulnerabilities", {}).get(vid)
        is_new = existing is None

        if is_new:
            vuln_record["created_at"] = now_iso
            vuln_record["updated_at"] = now_iso
            store.setdefault("vulnerabilities", {})[vid] = vuln_record
        else:
            # Merge updates while preserving original created_at
            created_at = existing.get("created_at", now_iso)
            existing.update(vuln_record)
            existing["created_at"] = created_at
            existing["updated_at"] = now_iso
            vuln_record = existing
            store.setdefault("vulnerabilities", {})[vid] = existing

        # Update Indexes
        cve_id = vuln_record.get("cve_id")
        if cve_id:
            store.setdefault("cve_index", {})[cve_id.upper()] = vid

        pkg_name = vuln_record.get("package_name")
        eco = vuln_record.get("ecosystem")
        if pkg_name and eco:
            key = f"{eco.lower()}:{pkg_name.lower()}"
            vids = store.setdefault("package_index", {}).setdefault(key, [])
            if vid not in vids:
                vids.append(vid)

        _save_store(store)
        return vuln_record, is_new


def upsert_vulnerabilities_batch(records: List[Dict[str, Any]], source_name: str = "osv") -> Tuple[int, int]:
    """
    Batch inserts or updates vulnerability records and updates source sync stats.
    Returns (created_count, updated_count).
    """
    created_count = 0
    updated_count = 0
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    with _store_lock:
        store = _load_store()
        for vuln_record in records:
            vid = vuln_record.get("id") or f"VULN-{vuln_record.get('cve_id') or vuln_record.get('source_id')}"
            existing = store.get("vulnerabilities", {}).get(vid)
            if existing is None:
                vuln_record["created_at"] = now_iso
                vuln_record["updated_at"] = now_iso
                store.setdefault("vulnerabilities", {})[vid] = vuln_record
                created_count += 1
            else:
                created_at = existing.get("created_at", now_iso)
                existing.update(vuln_record)
                existing["created_at"] = created_at
                existing["updated_at"] = now_iso
                store.setdefault("vulnerabilities", {})[vid] = existing
                updated_count += 1

            cve_id = vuln_record.get("cve_id")
            if cve_id:
                store.setdefault("cve_index", {})[cve_id.upper()] = vid

            pkg_name = vuln_record.get("package_name")
            eco = vuln_record.get("ecosystem")
            if pkg_name and eco:
                key = f"{eco.lower()}:{pkg_name.lower()}"
                vids = store.setdefault("package_index", {}).setdefault(key, [])
                if vid not in vids:
                    vids.append(vid)

        # Update source metadata
        src_meta = store.setdefault("sources", {}).setdefault(source_name, {})
        src_meta["status"] = "Healthy"
        src_meta["last_successful_sync"] = now_iso
        src_meta["last_attempted_sync"] = now_iso
        src_meta["records_count"] = len(store.get("vulnerabilities", {}))
        src_meta["records_created"] = src_meta.get("records_created", 0) + created_count
        src_meta["records_updated"] = src_meta.get("records_updated", 0) + updated_count
        src_meta["errors"] = None

        _save_store(store)

    return created_count, updated_count


def update_source_status(source_name: str, status: str = "Healthy", error: Optional[str] = None) -> None:
    """Updates heartbeat and error message for an intelligence data source."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with _store_lock:
        store = _load_store()
        src = store.setdefault("sources", {}).setdefault(source_name, {})
        src["last_attempted_sync"] = now_iso
        src["status"] = status
        src["errors"] = error
        if status == "Healthy":
            src["last_successful_sync"] = now_iso
        _save_store(store)


def get_vulnerability_by_id(vuln_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single vulnerability record by ID or CVE ID."""
    store = _load_store()
    # 1. Direct ID lookup
    rec = store.get("vulnerabilities", {}).get(vuln_id)
    if rec:
        return rec
    # 2. CVE Index lookup
    clean_cve = vuln_id.strip().upper()
    cve_mapped_id = store.get("cve_index", {}).get(clean_cve)
    if cve_mapped_id:
        return store.get("vulnerabilities", {}).get(cve_mapped_id)
    return None


def get_vulnerabilities_by_package(package_name: str, ecosystem: str = "npm") -> List[Dict[str, Any]]:
    """Retrieves stored vulnerabilities matching package name and ecosystem."""
    store = _load_store()
    key = f"{ecosystem.lower()}:{package_name.lower()}"
    vids = store.get("package_index", {}).get(key, [])
    vulns = []
    for vid in vids:
        v = store.get("vulnerabilities", {}).get(vid)
        if v:
            vulns.append(v)
    return vulns


def get_all_vulnerabilities(
    limit: int = 100,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    ecosystem: Optional[str] = None,
    cve_or_keyword: Optional[str] = None,
    known_exploited_only: bool = False,
) -> List[Dict[str, Any]]:
    """Retrieves filtered vulnerability intelligence records."""
    store = _load_store()
    vulns = list(store.get("vulnerabilities", {}).values())

    filtered = []
    for v in vulns:
        if severity and v.get("severity", "").upper() != severity.upper():
            continue
        if source and v.get("source", "").lower() != source.lower():
            continue
        if ecosystem and v.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if known_exploited_only and not v.get("kev_status"):
            continue
        if cve_or_keyword:
            kw = cve_or_keyword.lower()
            title = (v.get("title") or "").lower()
            cve = (v.get("cve_id") or "").lower()
            pkg = (v.get("package_name") or "").lower()
            if kw not in title and kw not in cve and kw not in pkg:
                continue
        filtered.append(v)

    # Sort descending by published_at or created_at
    filtered.sort(key=lambda x: x.get("published_at") or x.get("created_at") or "", reverse=True)
    return filtered[:limit]


def get_intelligence_sync_summary() -> Dict[str, Any]:
    """Returns complete synchronization status and health statistics for all sources."""
    store = _load_store()
    vulns = store.get("vulnerabilities", {})
    sources = store.get("sources", {})

    total_vulns = len(vulns)
    crit_count = sum(1 for v in vulns.values() if v.get("severity") == "CRITICAL")
    high_count = sum(1 for v in vulns.values() if v.get("severity") == "HIGH")
    kev_count = sum(1 for v in vulns.values() if v.get("kev_status"))

    return {
        "sources": sources,
        "total_vulnerabilities": total_vulns,
        "critical_vulnerabilities": crit_count,
        "high_vulnerabilities": high_count,
        "known_exploited_count": kev_count,
        "last_updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
