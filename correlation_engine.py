"""
TrustAudit Vulnerability Correlation & Risk Prioritization Engine.

Correlates newly disclosed CVEs, OSV advisories, and CISA KEV records
against customer software inventory (repositories, manifests, web perimeter).

Core Decision Logic:
- CONFIRMED_AFFECTED: Reliable package name, ecosystem, and installed version match within affected range.
- POTENTIALLY_AFFECTED: Technology/package matches but installed version cannot be verified (UNKNOWN VERSION).
- NOT_AFFECTED: Installed version is outside affected range or >= fixed version.
- UNKNOWN: Insufficient inventory information.

Find -> Fix -> Verify:
Rescans re-evaluate installed versions and automatically promote status to VERIFIED_FIXED.
"""

import datetime
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import alerts
import inventory_engine
import vuln_intel_sources
import vuln_intel_store
import saas_store

# Storage for Correlation Finding State & Overrides
CORRELATION_DATA_FILE = os.path.join(os.path.dirname(__file__), "correlation_findings.json")


def _load_correlation_store() -> Dict[str, Any]:
    if not os.path.exists(CORRELATION_DATA_FILE):
        return {"findings": {}}
    try:
        with open(CORRELATION_DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"findings": {}}


def _save_correlation_store(data: Dict[str, Any]) -> None:
    try:
        with open(CORRELATION_DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[CORRELATION] Save failed: {e}", flush=True)


# ---------------------------------------------------------------------------
# Semantic Version Comparison Utilities
# ---------------------------------------------------------------------------

def parse_semver_parts(ver_str: str) -> Optional[Tuple[int, int, int, str]]:
    """Extracts (major, minor, patch, prerelease) from version string."""
    if not ver_str or ver_str == "UNKNOWN VERSION":
        return None
    # Remove leading 'v' or 'V'
    clean = ver_str.lstrip("vV").strip()
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.\-+]+))?", clean)
    if not match:
        return None
    major = int(match.group(1))
    minor = int(match.group(2) or 0)
    patch = int(match.group(3) or 0)
    prerelease = match.group(4) or ""
    return (major, minor, patch, prerelease)


def compare_versions(v1: str, v2: str) -> int:
    """
    Compares two version strings.
    Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
    """
    p1 = parse_semver_parts(v1)
    p2 = parse_semver_parts(v2)
    if not p1 or not p2:
        return 0
    if p1[:3] < p2[:3]:
        return -1
    elif p1[:3] > p2[:3]:
        return 1
    # Prerelease comparison
    if p1[3] and not p2[3]:
        return -1  # 1.0.0-beta < 1.0.0
    elif not p1[3] and p2[3]:
        return 1
    return 0


def is_version_affected(installed_version: str, fixed_versions: List[str], affected_ranges: List[str]) -> str:
    """
    Evaluates installed version against fixed versions and affected ranges.
    Returns: 'CONFIRMED_AFFECTED', 'POTENTIALLY_AFFECTED', or 'NOT_AFFECTED'.
    """
    if not installed_version or installed_version == "UNKNOWN VERSION":
        return "POTENTIALLY_AFFECTED"

    # If any fixed version is available, check if installed is >= lowest fixed version
    if fixed_versions:
        # Sort fixed versions
        valid_fixed = [fv for fv in fixed_versions if parse_semver_parts(fv)]
        if valid_fixed:
            # If installed version >= the highest fixed version, it's patched
            for fv in valid_fixed:
                if compare_versions(installed_version, fv) < 0:
                    return "CONFIRMED_AFFECTED"
            return "NOT_AFFECTED"

    # Evaluate affected range strings e.g. ">=1.0.0, <1.2.4"
    if affected_ranges:
        for r_str in affected_ranges:
            if "<" in r_str:
                m_fixed = re.search(r"<([0-9A-Za-z.\-+]+)", r_str)
                if m_fixed:
                    cutoff = m_fixed.group(1)
                    if compare_versions(installed_version, cutoff) < 0:
                        return "CONFIRMED_AFFECTED"
                    else:
                        return "NOT_AFFECTED"

    # Default to confirmed if OSV explicitly returned this vulnerability for the version query
    return "CONFIRMED_AFFECTED"


# ---------------------------------------------------------------------------
# TrustAudit Multi-Factor Risk Prioritizer
# ---------------------------------------------------------------------------

def calculate_vulnerability_risk_priority(
    vuln: Dict[str, Any],
    component: Dict[str, Any],
    correlation_state: str
) -> Tuple[int, str, str]:
    """
    Computes TrustAudit Risk Priority score (0-100), severity level, and rationale.
    
    Weights:
    - CVSS base score (0-10) -> Up to 35 pts
    - CISA KEV (Active Exploitation) -> +25 pts
    - Internet Exposure / Public Facing -> +20 pts
    - Production Environment -> +10 pts
    - Confirmed Version Match -> +10 pts
    """
    cvss = float(vuln.get("cvss_score") or 7.0)
    is_kev = bool(vuln.get("kev_status") or vuln_intel_sources.lookup_cisa_kev(vuln.get("cve_id")))
    environment = (component.get("environment") or "Production").lower()
    is_prod = "prod" in environment or "source" in environment
    is_internet_exposed = is_prod or "web" in component.get("manifest_file", "").lower()
    is_confirmed = correlation_state == "CONFIRMED_AFFECTED"

    # Calculate Score
    score = int((cvss / 10.0) * 35)  # Max 35
    if is_kev:
        score += 25
    if is_internet_exposed:
        score += 20
    if is_prod:
        score += 10
    if is_confirmed:
        score += 10

    score = min(100, max(10, score))

    # Determine Severity Level
    if score >= 85:
        severity = "CRITICAL"
    elif score >= 65:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Generate Human-Readable Prioritization Rationale
    reasons = []
    if is_kev:
        reasons.append("the vulnerability is listed in CISA KEV as actively exploited in the wild")
    if is_confirmed:
        reasons.append(f"the affected component '{component.get('package_name')}' version is confirmed in your environment")
    if is_internet_exposed:
        reasons.append("the target is internet-facing in production")
    if cvss >= 8.5:
        reasons.append(f"the base CVSS score is severe ({cvss}/10)")

    if reasons:
        explanation = "Prioritized because " + ", and ".join(reasons) + "."
    else:
        explanation = f"Prioritized based on CVSS score of {cvss} and component criticality."

    return score, severity, explanation


# ---------------------------------------------------------------------------
# Correlation & Finding Lifecycle Manager
# ---------------------------------------------------------------------------

def correlate_component_vulnerabilities(
    component: Dict[str, Any],
    org_id: str = "org-default"
) -> List[Dict[str, Any]]:
    """
    Correlates a single software inventory component against OSV, NVD, and CISA KEV.
    Generates or updates normalized TrustAudit finding records.
    """
    pkg_name = component.get("package_name")
    ver = component.get("version")
    eco = component.get("ecosystem", "npm")
    project_id = component.get("project_id", "proj-default")
    asset_id = component.get("asset_id", "asset-default")

    if not pkg_name:
        return []

    # 1. Query OSV for live vulnerabilities
    vulns = vuln_intel_sources.query_osv_package(pkg_name, version=ver if ver != "UNKNOWN VERSION" else None, ecosystem=eco)

    # 2. Enrich each vulnerability with CISA KEV and NVD
    now = time.time()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    store = _load_correlation_store()
    generated_findings = []

    for v in vulns:
        cve_id = v.get("cve_id")
        kev_info = vuln_intel_sources.lookup_cisa_kev(cve_id)
        if kev_info:
            v["kev_status"] = kev_info

        # Upsert into centralized intelligence store
        vuln_intel_store.upsert_vulnerability(v)

        # Correlation State
        corr_state = is_version_affected(
            installed_version=ver or "UNKNOWN VERSION",
            fixed_versions=v.get("fixed_versions", []),
            affected_ranges=v.get("affected_version_ranges", [])
        )

        # Calculate Prioritized Risk Score & Rationale
        risk_score, calculated_sev, rationale = calculate_vulnerability_risk_priority(v, component, corr_state)

        # Deterministic Finding ID
        seed = f"{project_id}:{eco}:{pkg_name}:{cve_id or v['source_id']}"
        finding_id = f"VULN-INTEL-{hashlib.sha256(seed.encode('utf-8')).hexdigest()[:8].upper()}"

        existing_finding = store.get("findings", {}).get(finding_id)
        first_detected = existing_finding.get("first_detected", now) if existing_finding else now
        current_status = existing_finding.get("status", "NEW") if existing_finding else "NEW"

        # If previous was FIXED_PENDING_VERIFICATION and now confirmed fixed:
        if corr_state == "NOT_AFFECTED":
            current_status = "VERIFIED_FIXED"
        elif current_status in ("VERIFIED_FIXED", "NOT_AFFECTED") and corr_state == "CONFIRMED_AFFECTED":
            # Regression! Re-opened
            current_status = "OPEN"

        fixed_ver_str = ", ".join(v.get("fixed_versions", [])) or "latest secure release"
        remediation_action = f"Upgrade '{pkg_name}' from installed version {ver} to {fixed_ver_str}."

        finding_record = {
            "id": finding_id,
            "org_id": org_id,
            "project_id": project_id,
            "asset_id": asset_id,
            "component_id": component.get("id"),
            "package_name": pkg_name,
            "installed_version": ver,
            "ecosystem": eco,
            "manifest_file": component.get("manifest_file", "package.json"),
            "environment": component.get("environment", "Production"),
            "cve_id": cve_id,
            "osv_id": v.get("osv_id"),
            "title": f"[{cve_id or v['source_id']}] Vulnerability in {pkg_name} ({ver})",
            "summary": v.get("title") or v.get("description", "")[:140],
            "description": v.get("description"),
            "severity": calculated_sev,
            "risk_score": risk_score,
            "cvss_score": v.get("cvss_score", 7.0),
            "cvss_vector": v.get("cvss_vector"),
            "is_known_exploited": bool(v.get("kev_status")),
            "kev_details": v.get("kev_status"),
            "correlation_state": corr_state,  # CONFIRMED_AFFECTED, POTENTIALLY_AFFECTED, NOT_AFFECTED
            "status": current_status,          # NEW, OPEN, FIXED_PENDING_VERIFICATION, VERIFIED_FIXED
            "why_prioritized": rationale,
            "affected_version_ranges": v.get("affected_version_ranges", []),
            "fixed_versions": v.get("fixed_versions", []),
            "remediation": remediation_action,
            "ai_prompt": f"Fix vulnerability {cve_id or v['source_id']} in {pkg_name} by upgrading from version {ver} to {fixed_ver_str}.",
            "references": v.get("references", []),
            "source": "OSV / NVD / CISA KEV",
            "first_detected": first_detected,
            "last_detected": now,
        }

        store.setdefault("findings", {})[finding_id] = finding_record
        generated_findings.append(finding_record)

        # Trigger real-time alert for Critical or KEV findings
        if bool(v.get("kev_status")) or (calculated_sev == "CRITICAL" and corr_state == "CONFIRMED_AFFECTED"):
            try:
                _dispatch_vulnerability_alert(finding_record, org_id)
            except Exception:
                pass

    _save_correlation_store(store)
    return generated_findings


def correlate_all_customer_inventory(org_id: str = "org-default") -> List[Dict[str, Any]]:
    """
    Sweeps through all registered software inventory components for the organization
    and updates correlation findings.
    """
    components = inventory_engine.get_all_inventory_components(org_id=org_id)
    all_findings = []
    for comp in components:
        findings = correlate_component_vulnerabilities(comp, org_id=org_id)
        all_findings.extend(findings)
    return all_findings


def verify_component_fix_recheck(
    project_id: str,
    package_name: str,
    new_version: str,
    ecosystem: str = "npm",
    org_id: str = "org-default"
) -> Dict[str, Any]:
    """
    Find -> Fix -> Verify workflow:
    Evaluates new component version against all open findings for this package.
    Automatically marks findings VERIFIED_FIXED if the new version is secure.
    """
    store = _load_correlation_store()
    now = time.time()
    verified_count = 0
    remaining_open = 0
    updated_findings = []

    for fid, f in store.get("findings", {}).items():
        if f.get("project_id") == project_id and f.get("package_name") == package_name and f.get("ecosystem") == ecosystem:
            # Re-evaluate with new version
            fixed_vers = f.get("fixed_versions", [])
            ranges = f.get("affected_version_ranges", [])
            new_corr_state = is_version_affected(new_version, fixed_vers, ranges)

            if new_corr_state == "NOT_AFFECTED":
                f["status"] = "VERIFIED_FIXED"
                f["correlation_state"] = "NOT_AFFECTED"
                f["installed_version"] = new_version
                f["verified_at"] = now
                verified_count += 1
            else:
                f["status"] = "OPEN"
                f["correlation_state"] = new_corr_state
                f["installed_version"] = new_version
                remaining_open += 1

            f["last_detected"] = now
            updated_findings.append(f)

    _save_correlation_store(store)
    return {
        "status": "success",
        "verified_fixed_count": verified_count,
        "remaining_open_count": remaining_open,
        "updated_findings": updated_findings,
    }


def get_vulnerabilities_affecting_customer(
    org_id: str = "org-default",
    project_id: Optional[str] = None,
    include_fixed: bool = False
) -> List[Dict[str, Any]]:
    """
    Returns all vulnerability findings affecting or potentially affecting the customer.
    """
    store = _load_correlation_store()
    findings = list(store.get("findings", {}).values())

    filtered = [f for f in findings if f.get("org_id") == org_id]
    if project_id:
        filtered = [f for f in filtered if f.get("project_id") == project_id]
    if not include_fixed:
        filtered = [f for f in filtered if f.get("status") not in ("VERIFIED_FIXED", "NOT_AFFECTED", "FALSE_POSITIVE")]

    # Sort descending by risk score
    filtered.sort(key=lambda x: (x.get("is_known_exploited", False), x.get("risk_score", 0)), reverse=True)
    return filtered


def _dispatch_vulnerability_alert(finding: Dict[str, Any], org_id: str) -> None:
    """Dispatches a high-priority alert notification for critical or KEV vulnerabilities."""
    pkg = finding.get("package_name")
    ver = finding.get("installed_version")
    cve = finding.get("cve_id") or finding.get("osv_id")
    is_kev = finding.get("is_known_exploited")
    sev = finding.get("severity", "HIGH")
    proj_id = finding.get("project_id", "Default Project")

    title = f"{'🚨 KNOWN EXPLOITED ' if is_kev else ''}Vulnerability in {pkg}@{ver}"
    details = (
        f"CVE / Advisory: {cve}\n"
        f"Package: {pkg} (Installed: {ver})\n"
        f"Severity: {sev} (Risk Score: {finding.get('risk_score')}/100)\n"
        f"CISA KEV: {'YES (Actively Exploited)' if is_kev else 'No'}\n"
        f"Action: {finding.get('remediation')}"
    )
    alerts.dispatch_security_alert("NEW_VULNERABILITY", proj_id, title, details, severity=sev, org_id=org_id)
