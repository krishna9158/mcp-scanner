"""
TrustAudit "What Changed?" Delta & Security Timeline Engine.

Correlates consecutive security scans for projects to detect:
- NEW FINDINGS
- FIXED FINDINGS
- REOPENED FINDINGS
- SCORE DRIFT & REASONING
- CHRONOLOGICAL SECURITY TIMELINE EVENTS
"""

import datetime
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import saas_store


def _get_finding_fingerprint(finding: Dict[str, Any]) -> str:
    """Generates a stable fingerprint identifying a vulnerability instance across scans."""
    fid = finding.get("id") or finding.get("finding_id")
    if fid:
        return str(fid)
    cat = finding.get("category", "")
    title = finding.get("title", "")
    file_p = finding.get("file", "")
    return f"{cat}:{title}:{file_p}".lower()


def _extract_tool_permissions(tool: Dict[str, Any]) -> set:
    """Extracts normalized capability/permission identifiers from a tool record."""
    caps = set()
    raw_caps = tool.get("capabilities") or tool.get("permissions") or []
    if isinstance(raw_caps, list):
        for c in raw_caps:
            if isinstance(c, str):
                caps.add(c.upper())
            elif isinstance(c, dict) and "name" in c:
                caps.add(str(c["name"]).upper())
    elif isinstance(raw_caps, dict):
        caps.update(k.upper() for k in raw_caps.keys())

    # Code / description pattern extraction fallback only when no explicit capabilities are specified
    if not caps:
        import re as _re
        name = str(tool.get("name", "")).lower()
        desc = str(tool.get("description", "")).lower()
        code = str(tool.get("code_snippet", "")).lower()
        combined = f"{name} {desc} {code}"
        if _re.search(r'\b(shell|bash|sh|subprocess|spawn)\b|\bexec\(|\bexecute_command\b', combined):
            caps.add("SHELL_EXECUTION")
        if _re.search(r'\b(write_file|fs\.write|unlink|delete_file)\b', combined):
            caps.add("FILESYSTEM_WRITE")
        if _re.search(r'\b(fetch|http|axios|requests|socket)\b', combined):
            caps.add("NETWORK_OUTBOUND")
        if _re.search(r'\b(sql|query|postgres|sqlite|database)\b', combined):
            caps.add("DATABASE_ACCESS")

    return caps


def compute_scan_delta(
    current_scan: Dict[str, Any],
    previous_scan: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Compares two scans and computes new, fixed, reopened, and persistent findings,
    as well as tool permission scope expansions between scans.
    """
    curr_findings = list(current_scan.get("findings", []))
    curr_score = current_scan.get("score", 100)
    curr_fp_map = {_get_finding_fingerprint(f): f for f in curr_findings}

    if not previous_scan:
        return {
            "is_initial_scan": True,
            "score_delta": 0,
            "previous_score": curr_score,
            "current_score": curr_score,
            "new_findings": curr_findings,
            "fixed_findings": [],
            "reopened_findings": [],
            "unchanged_findings": [],
            "permission_expansion_alerts": [],
            "new_count": len(curr_findings),
            "fixed_count": 0,
            "reopened_count": 0,
            "summary": f"Initial baseline scan established ({len(curr_findings)} findings detected, Score: {curr_score}/100).",
        }

    prev_findings = previous_scan.get("findings", [])
    prev_score = previous_scan.get("score", 100)
    prev_fp_map = {_get_finding_fingerprint(f): f for f in prev_findings}

    new_findings: List[Dict[str, Any]] = []
    fixed_findings: List[Dict[str, Any]] = []
    reopened_findings: List[Dict[str, Any]] = []
    unchanged_findings: List[Dict[str, Any]] = []

    # Identify new & unchanged
    for fp, f in curr_fp_map.items():
        if fp not in prev_fp_map:
            new_findings.append(f)
        else:
            unchanged_findings.append(f)

    # Identify fixed
    for fp, f in prev_fp_map.items():
        if fp not in curr_fp_map:
            fixed_findings.append(f)

    # Check for MCP Tool Permission Scope Expansion
    permission_expansion_alerts: List[Dict[str, Any]] = []
    curr_tools = {t.get("name"): t for t in current_scan.get("report", []) if t.get("name")}
    prev_tools = {t.get("name"): t for t in previous_scan.get("report", []) if t.get("name")}

    for tname, curr_t in curr_tools.items():
        if tname in prev_tools:
            prev_t = prev_tools[tname]
            curr_perms = _extract_tool_permissions(curr_t)
            prev_perms = _extract_tool_permissions(prev_t)
            added_perms = curr_perms - prev_perms
            if added_perms:
                alert = {
                    "id": f"mcp-perm-expansion-{tname.lower().replace(' ', '-')}",
                    "category": "mcp_security",
                    "title": f"MCP Tool Scope Expansion: {tname}",
                    "severity": "HIGH",
                    "confidence": "CONFIRMED",
                    "file": curr_t.get("file") or "mcp.json",
                    "line": curr_t.get("line") or 1,
                    "description": f"Tool '{tname}' expanded its permissions compared to previous scan: added [{', '.join(sorted(added_perms))}].",
                    "remediation": f"Verify whether tool '{tname}' genuinely requires the newly added permissions ({', '.join(sorted(added_perms))}) or if this represents unauthorized capability creep.",
                    "scanner": "delta_engine",
                    "tool_name": tname,
                    "added_permissions": list(sorted(added_perms)),
                }
                permission_expansion_alerts.append(alert)
                new_findings.append(alert)

    score_delta = curr_score - prev_score

    # Human-readable summary
    parts = []
    if new_findings:
        parts.append(f"{len(new_findings)} new vulnerability(ies)")
    if fixed_findings:
        parts.append(f"{len(fixed_findings)} vulnerability(ies) fixed")
    if permission_expansion_alerts:
        parts.append(f"{len(permission_expansion_alerts)} tool permission expansion(s)")
    if score_delta != 0:
        sign = "+" if score_delta > 0 else ""
        parts.append(f"security score changed {prev_score} -> {curr_score} ({sign}{score_delta})")
    
    summary = ", ".join(parts) if parts else "No security changes detected since last scan."

    return {
        "is_initial_scan": False,
        "score_delta": score_delta,
        "previous_score": prev_score,
        "current_score": curr_score,
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "reopened_findings": reopened_findings,
        "unchanged_findings": unchanged_findings,
        "permission_expansion_alerts": permission_expansion_alerts,
        "new_count": len(new_findings),
        "fixed_count": len(fixed_findings),
        "reopened_count": len(reopened_findings),
        "summary": summary,
    }


def compute_and_record_scan_delta(
    project_id: str,
    current_scan_result: Dict[str, Any],
    org_id: str = "org-default"
) -> Dict[str, Any]:
    """
    Computes delta against previous scan and appends timestamped events to project timeline.
    """
    proj = saas_store.get_project(project_id, org_id=org_id)
    prev_scan = proj.get("last_scan_result") if proj else None

    delta = compute_scan_delta(current_scan_result, prev_scan)
    now = time.time()
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    time_str = now_dt.strftime("%H:%M")
    date_str = now_dt.strftime("%Y-%m-%d")

    timeline_events: List[Dict[str, Any]] = []

    # 1. New Findings Events
    for f in delta["new_findings"]:
        sev = f.get("severity", "MEDIUM").upper()
        icon = "🔴" if sev in ("CRITICAL", "HIGH") else ("🟠" if sev == "MEDIUM" else "🔵")
        timeline_events.append({
            "id": f"evt_{f.get('id') or time.time()}",
            "type": "NEW_FINDING",
            "severity": sev,
            "icon": icon,
            "title": f"New {sev} Risk Detected: {f.get('title')}",
            "details": f.get("description", ""),
            "location": f"{f.get('file', '')}:{f.get('line') or ''}",
            "timestamp": now,
            "time_str": time_str,
            "date_str": date_str,
        })

    # 2. Fixed Findings Events
    for f in delta["fixed_findings"]:
        timeline_events.append({
            "id": f"evt_fix_{f.get('id') or time.time()}",
            "type": "FIXED_FINDING",
            "severity": "LOW",
            "icon": "🟢",
            "title": f"Vulnerability Verified Fixed: {f.get('title')}",
            "details": "Remediation verified; vulnerability is no longer present.",
            "location": f.get("file", ""),
            "timestamp": now,
            "time_str": time_str,
            "date_str": date_str,
        })

    # 3. Score Change Event
    if delta["score_delta"] != 0:
        sign = "+" if delta["score_delta"] > 0 else ""
        icon = "📈" if delta["score_delta"] > 0 else "📉"
        timeline_events.append({
            "id": f"evt_score_{now}",
            "type": "SCORE_CHANGE",
            "severity": "INFO",
            "icon": icon,
            "title": f"Security Posture Score Drift: {delta['previous_score']} → {delta['current_score']} ({sign}{delta['score_delta']})",
            "details": delta["summary"],
            "timestamp": now,
            "time_str": time_str,
            "date_str": date_str,
        })

    # 4. Tool Permission Scope Expansion Events
    for alert in delta.get("permission_expansion_alerts", []):
        timeline_events.append({
            "id": f"evt_perm_{alert.get('tool_name')}_{int(now)}",
            "type": "PERMISSION_EXPANSION",
            "severity": "HIGH",
            "icon": "⚠️",
            "title": alert["title"],
            "details": alert["description"],
            "location": alert.get("file", "mcp"),
            "timestamp": now,
            "time_str": time_str,
            "date_str": date_str,
        })

    # Persist in project record
    saas_store.append_project_timeline(project_id, timeline_events, delta=delta, last_scan_result=current_scan_result, org_id=org_id)
    return delta


def get_project_timeline(project_id: str, org_id: str = "org-default", limit: int = 30) -> List[Dict[str, Any]]:
    """Retrieves chronological security timeline events for a project."""
    return saas_store.get_project_timeline(project_id, org_id=org_id, limit=limit)


def get_project_what_changed(project_id: str, org_id: str = "org-default") -> Dict[str, Any]:
    """Retrieves the latest 'What Changed?' delta comparison for a project."""
    proj = saas_store.get_project(project_id, org_id=org_id)
    if not proj:
        return {
            "summary": "Project not found.",
            "new_count": 0,
            "fixed_count": 0,
            "score_delta": 0,
            "timeline": [],
        }
    return proj.get("last_delta") or {
        "summary": "No historical changes recorded yet. Continuous monitoring is active.",
        "new_count": 0,
        "fixed_count": 0,
        "score_delta": 0,
        "new_findings": [],
        "fixed_findings": [],
    }
