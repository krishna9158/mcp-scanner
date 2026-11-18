"""
TrustAudit Vulnerability Intelligence Data Source Connectors.

Integrates official APIs and public security feeds:
1. OSV API (https://api.osv.dev/v1/query) - Primary package/version matching.
2. NVD CVE API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0) - NIST CVE intelligence & CVSS metrics.
3. CISA KEV (https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) - Active in-the-wild exploitation catalog.
"""

import datetime
import json
import os
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    requests = None

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-memory CISA KEV cache: {cve_id: kev_dict}
_CISA_KEV_CACHE: Dict[str, Dict[str, Any]] = {}
_CISA_KEV_METADATA: Dict[str, Any] = {"count": 0, "last_updated": None}

# NVD Rate Limiter State
_LAST_NVD_REQUEST_TIME = 0.0
_NVD_REQUEST_LOCK_INTERVAL = 6.5  # 6.5s delay without API key to comply with 5 req / 30s limit


def get_nvd_api_key() -> Optional[str]:
    """Retrieves configured NVD API key from environment variable."""
    return os.environ.get("NVD_API_KEY") or os.environ.get("TRUSTAUDIT_NVD_API_KEY")


# ---------------------------------------------------------------------------
# 1. OSV API Connector
# ---------------------------------------------------------------------------

def query_osv_package(package_name: str, version: Optional[str] = None, ecosystem: str = "PyPI", timeout: int = 8) -> List[Dict[str, Any]]:
    """
    Queries OSV API for vulnerabilities affecting a package and version.
    Returns normalized vulnerability advisory records.
    """
    if requests is None or not package_name:
        return []

    # Clean package name & ecosystem mapping
    eco_map = {
        "pypi": "PyPI",
        "python": "PyPI",
        "npm": "npm",
        "javascript": "npm",
        "node": "npm",
        "go": "Go",
        "golang": "Go",
        "maven": "Maven",
        "java": "Maven",
        "crates.io": "crates.io",
        "rust": "crates.io",
        "nuget": "NuGet",
        "rubygems": "RubyGems",
    }
    target_eco = eco_map.get(ecosystem.lower(), ecosystem)

    payload: Dict[str, Any] = {
        "package": {"name": package_name, "ecosystem": target_eco}
    }
    if version and version != "UNKNOWN VERSION":
        payload["version"] = version

    try:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=timeout)
        if resp.status_code != 200:
            return []
        data = resp.json()
        vulns = data.get("vulns", [])
        return [_normalize_osv_record(v, package_name, target_eco, installed_version=version) for v in vulns]
    except Exception as e:
        print(f"[OSV] Query failed for {package_name}@{version}: {e}", flush=True)
        return []


def query_osv_batch(packages: List[Dict[str, str]], timeout: int = 15) -> Dict[str, List[Dict[str, Any]]]:
    """
    Queries OSV API in batch for multiple package/version combinations.
    packages: [{'name': 'next', 'version': '15.2.0', 'ecosystem': 'npm'}, ...]
    Returns dict mapping 'ecosystem:package_name' -> list of vulnerability records.
    """
    if requests is None or not packages:
        return {}

    queries = []
    keys = []
    eco_map = {
        "pypi": "PyPI", "python": "PyPI", "npm": "npm",
        "go": "Go", "maven": "Maven", "crates.io": "crates.io"
    }

    for p in packages[:100]:  # Limit batch chunk to 100
        name = p.get("name") or p.get("package_name")
        ver = p.get("version")
        eco = eco_map.get((p.get("ecosystem") or "npm").lower(), p.get("ecosystem") or "npm")
        if not name:
            continue
        q: Dict[str, Any] = {"package": {"name": name, "ecosystem": eco}}
        if ver and ver != "UNKNOWN VERSION":
            q["version"] = ver
        queries.append(q)
        keys.append(f"{eco}:{name}")

    if not queries:
        return {}

    results_by_pkg: Dict[str, List[Dict[str, Any]]] = {}
    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            for idx, res_item in enumerate(data.get("results", [])):
                key = keys[idx]
                vulns = res_item.get("vulns", [])
                pkg_info = queries[idx]["package"]
                ver = queries[idx].get("version")
                results_by_pkg[key] = [
                    _normalize_osv_record(v, pkg_info["name"], pkg_info["ecosystem"], installed_version=ver)
                    for v in vulns
                ]
    except Exception as e:
        print(f"[OSV] Batch query error: {e}", flush=True)

    return results_by_pkg


def get_osv_vulnerability_details(osv_id: str, timeout: int = 8) -> Optional[Dict[str, Any]]:
    """Retrieves complete vulnerability metadata for a specific OSV/CVE identifier."""
    if requests is None or not osv_id:
        return None
    try:
        resp = requests.get(f"{OSV_VULN_URL}/{osv_id}", timeout=timeout)
        if resp.status_code == 200:
            v = resp.json()
            return _normalize_osv_record(v, "unknown", "unknown")
    except Exception:
        pass
    return None


def _normalize_osv_record(v: Dict[str, Any], package_name: str, ecosystem: str, installed_version: Optional[str] = None) -> Dict[str, Any]:
    """Normalizes an OSV JSON payload into a standardized TrustAudit Vulnerability object."""
    vid = v.get("id", "UNKNOWN")
    aliases = v.get("aliases", [])
    cve_id = next((a for a in aliases if a.startswith("CVE-")), vid if vid.startswith("CVE-") else None)
    osv_id = vid if not vid.startswith("CVE-") else (next((a for a in aliases if a.startswith("GHSA-") or a.startswith("PYSEC-")), vid))

    summary = v.get("summary") or v.get("details", "Security advisory published via OSV.")
    details = v.get("details", summary)

    # Extract CVSS Score and Severity
    cvss_score = 7.5
    cvss_vector = None
    severity = "HIGH"

    for sev_obj in v.get("severity", []):
        if isinstance(sev_obj, dict):
            score_str = sev_obj.get("score")
            if score_str and isinstance(score_str, str) and score_str.startswith("CVSS:"):
                cvss_vector = score_str
            elif isinstance(score_str, (int, float)):
                cvss_score = float(score_str)

    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Extract Affected Ranges and Fixed Versions
    affected_ranges = []
    fixed_versions = []
    affected_products = []

    for aff in v.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name"):
            affected_products.append(f"{pkg.get('ecosystem')}:{pkg.get('name')}")
        for r in aff.get("ranges", []):
            range_type = r.get("type", "ECOSYSTEM")
            events = r.get("events", [])
            introduced = None
            fixed = None
            for ev in events:
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
                    fixed_versions.append(fixed)
            range_str = f">={introduced or '0'}" + (f", <{fixed}" if fixed else "")
            affected_ranges.append(range_str)

    fixed_versions = list(dict.fromkeys(fixed_versions))
    affected_ranges = list(dict.fromkeys(affected_ranges))

    # Extract References
    refs = [ref.get("url") for ref in v.get("references", []) if isinstance(ref, dict) and ref.get("url")]
    refs.append(f"https://osv.dev/vulnerability/{vid}")
    if cve_id:
        refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

    return {
        "id": f"VULN-{cve_id or vid}",
        "source": "OSV",
        "source_id": vid,
        "cve_id": cve_id,
        "osv_id": osv_id or vid,
        "title": summary[:140] if summary else f"Vulnerability in {package_name}",
        "description": details[:800],
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published_at": v.get("published"),
        "modified_at": v.get("modified"),
        "package_name": package_name,
        "ecosystem": ecosystem,
        "affected_version_ranges": affected_ranges,
        "fixed_versions": fixed_versions,
        "affected_products": list(dict.fromkeys(affected_products)),
        "references": list(dict.fromkeys(refs))[:6],
        "installed_version": installed_version,
        "raw_source_metadata": {
            "osv_id": vid,
            "database_specific": v.get("database_specific", {}),
        }
    }


# ---------------------------------------------------------------------------
# 2. CISA KEV (Known Exploited Vulnerabilities) Connector
# ---------------------------------------------------------------------------

def sync_cisa_kev_catalog(timeout: int = 15) -> Tuple[int, Optional[str]]:
    """
    Downloads and caches the official CISA Known Exploited Vulnerabilities catalog.
    Returns (records_count, error_message).
    """
    global _CISA_KEV_CACHE, _CISA_KEV_METADATA
    if requests is None:
        return 0, "Python 'requests' package not available."

    try:
        resp = requests.get(CISA_KEV_URL, timeout=timeout)
        if resp.status_code != 200:
            return 0, f"CISA KEV HTTP error {resp.status_code}"

        data = resp.json()
        items = data.get("vulnerabilities", [])
        new_cache = {}

        for item in items:
            cve = item.get("cveID")
            if cve:
                new_cache[cve.upper()] = {
                    "cve_id": cve.upper(),
                    "vendor_project": item.get("vendorProject"),
                    "product": item.get("product"),
                    "vulnerability_name": item.get("vulnerabilityName"),
                    "date_added": item.get("dateAdded"),
                    "short_description": item.get("shortDescription"),
                    "required_action": item.get("requiredAction"),
                    "due_date": item.get("dueDate"),
                    "notes": item.get("notes"),
                    "is_known_exploited": True,
                }

        _CISA_KEV_CACHE = new_cache
        _CISA_KEV_METADATA["count"] = len(new_cache)
        _CISA_KEV_METADATA["last_updated"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        print(f"[CISA KEV] Synchronized {len(new_cache)} active exploited CVEs from official catalog.", flush=True)
        return len(new_cache), None
    except Exception as e:
        err = f"Failed to sync CISA KEV: {e}"
        print(f"[CISA KEV] {err}", flush=True)
        return 0, err


def lookup_cisa_kev(cve_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """
    Checks if a CVE ID is listed in the CISA Known Exploited Vulnerabilities catalog.
    """
    if not cve_id:
        return None
    clean_cve = cve_id.strip().upper()
    if not _CISA_KEV_CACHE:
        # Load initial sync if cache is cold
        sync_cisa_kev_catalog()
    return _CISA_KEV_CACHE.get(clean_cve)


def get_cisa_kev_stats() -> Dict[str, Any]:
    """Returns KEV catalog synchronization statistics."""
    return {
        "count": _CISA_KEV_METADATA.get("count", len(_CISA_KEV_CACHE)),
        "last_updated": _CISA_KEV_METADATA.get("last_updated"),
        "status": "Healthy" if _CISA_KEV_CACHE else "Uninitialized",
    }


# ---------------------------------------------------------------------------
# 3. NVD CVE API 2.0 Connector
# ---------------------------------------------------------------------------

def fetch_nvd_cve_details(cve_id: str, timeout: int = 12) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Queries official NIST NVD CVE API 2.0 for enriched CVE details and CVSS metrics.
    Complies with NIST rate limits and API terms.
    """
    global _LAST_NVD_REQUEST_TIME
    if requests is None or not cve_id or not cve_id.startswith("CVE-"):
        return None, "Invalid CVE ID or requests missing."

    api_key = get_nvd_api_key()
    headers = {"User-Agent": "TrustAudit-Security-Copilot/2.0"}
    if api_key:
        headers["apiKey"] = api_key
        interval = 0.8
    else:
        interval = _NVD_REQUEST_LOCK_INTERVAL

    # Rate limiting sleep
    elapsed = time.time() - _LAST_NVD_REQUEST_TIME
    if elapsed < interval:
        time.sleep(interval - elapsed)

    params = {"cveId": cve_id}
    try:
        _LAST_NVD_REQUEST_TIME = time.time()
        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=timeout)
        if resp.status_code == 403 or resp.status_code == 429:
            return None, f"NVD rate limit reached (HTTP {resp.status_code})."
        elif resp.status_code != 200:
            return None, f"NVD HTTP error {resp.status_code}."

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None, "CVE not found in NVD database."

        cve_item = vulns[0].get("cve", {})
        return _normalize_nvd_record(cve_item), None
    except Exception as e:
        return None, str(e)


def sync_recent_nvd_cves(days_back: int = 1, timeout: int = 15) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """
    Incremental synchronization with NVD API 2.0 for newly published or modified CVEs.
    """
    global _LAST_NVD_REQUEST_TIME
    if requests is None:
        return [], "Python 'requests' package not available."

    api_key = get_nvd_api_key()
    headers = {"User-Agent": "TrustAudit-Security-Copilot/2.0"}
    if api_key:
        headers["apiKey"] = api_key
        interval = 0.8
    else:
        interval = _NVD_REQUEST_LOCK_INTERVAL

    now = datetime.datetime.now(datetime.timezone.utc)
    start_dt = now - datetime.timedelta(days=days_back)
    start_str = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "lastModStartDate": start_str,
        "lastModEndDate": end_str,
        "resultsPerPage": 50,
    }

    elapsed = time.time() - _LAST_NVD_REQUEST_TIME
    if elapsed < interval:
        time.sleep(interval - elapsed)

    try:
        _LAST_NVD_REQUEST_TIME = time.time()
        resp = requests.get(NVD_API_URL, headers=headers, params=params, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            normalized = [_normalize_nvd_record(item.get("cve", {})) for item in vulns if item.get("cve")]
            print(f"[NVD] Incremental sync retrieved {len(normalized)} CVEs.", flush=True)
            return normalized, None
        else:
            return [], f"NVD sync HTTP error {resp.status_code}"
    except Exception as e:
        return [], str(e)


def _normalize_nvd_record(cve: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes an NVD JSON CVE item."""
    cve_id = cve.get("id", "CVE-UNKNOWN")
    descriptions = cve.get("descriptions", [])
    desc_text = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description available.")

    # CVSS metrics
    metrics = cve.get("metrics", {})
    cvss_score = 5.0
    cvss_vector = None
    severity = "MEDIUM"

    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", 5.0)
        cvss_vector = cvss_data.get("vectorString")
        severity = cvss_data.get("baseSeverity", "MEDIUM").upper()
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", 5.0)
        cvss_vector = cvss_data.get("vectorString")
        severity = cvss_data.get("baseSeverity", "MEDIUM").upper()
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore", 5.0)
        cvss_vector = cvss_data.get("vectorString")
        severity = "HIGH" if cvss_score >= 7.0 else ("MEDIUM" if cvss_score >= 4.0 else "LOW")

    refs = [r.get("url") for r in cve.get("references", []) if isinstance(r, dict) and r.get("url")]

    return {
        "id": f"VULN-{cve_id}",
        "source": "NVD",
        "source_id": cve_id,
        "cve_id": cve_id,
        "osv_id": None,
        "title": f"NVD Advisory: {cve_id}",
        "description": desc_text[:800],
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "published_at": cve.get("published"),
        "modified_at": cve.get("lastModified"),
        "package_name": "General Component",
        "ecosystem": "NVD",
        "affected_version_ranges": [],
        "fixed_versions": [],
        "affected_products": [],
        "references": refs[:5],
        "raw_source_metadata": {
            "vulnStatus": cve.get("vulnStatus"),
            "weaknesses": [w.get("description", [{}])[0].get("value") for w in cve.get("weaknesses", []) if w.get("description")],
        }
    }
