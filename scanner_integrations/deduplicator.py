"""
Finding Deduplication Layer for TrustAudit Platform.

Identifies and correlates duplicate or overlapping findings detected across
multiple security scanners (e.g., Gitleaks + Trivy for secrets, or OSV-Scanner + Trivy for CVEs)
and consolidates identical findings across multiple files into a single unified finding card
with an aggregated list of affected locations.

Merges duplicates while preserving all detecting tool names in `scanners: [...]`
and adopting the highest confidence and severity ratings.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

SEVERITY_RANKS = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
CONFIDENCE_RANKS = {"CONFIRMED": 3, "LIKELY": 2, "POSSIBLE": 1}


def get_dedup_key(finding: Dict[str, Any]) -> str:
    """
    Computes a deduplication group key for a normalized finding.
    Groups identical vulnerabilities across files together.
    """
    category = (finding.get("category") or "").lower()
    raw_cve = finding.get("cve")
    if isinstance(raw_cve, list):
        cve = (raw_cve[0] if raw_cve else "").upper()
    else:
        cve = str(raw_cve or "").upper()
    package = (finding.get("package") or "").lower()
    title = (finding.get("title") or "").strip().lower()

    # 1. Dependency findings: group by package + cve/title
    if category == "dependencies" and package:
        version = (finding.get("version") or "").lower()
        return f"dep:{package}:{version}:{cve or title}"

    # 2. Secret findings: group by secret title / type
    if category == "secrets":
        return f"sec:{title}"

    # 3. Code/AppSec/MCP findings: group by category + title
    if category in ("code_security", "api_security", "mcp_security", "prompt_injection", "iac_security", "website_security"):
        return f"rule:{category}:{title}"

    file_path = (finding.get("file") or "").lower().replace("\\", "/")
    line = str(finding.get("line") or "")
    if file_path:
        if line and line != "None":
            return f"item:{category}:{file_path}:{line}:{title}"
        return f"item:{category}:{file_path}:{title}"

    return finding.get("fingerprint") or f"{category}:{title}"


def merge_findings(primary: Dict[str, Any], duplicate: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merges two overlapping findings into a single consolidated finding record
    with an aggregated list of affected locations.
    """
    merged = dict(primary)

    # 1. Combine scanners / detected_by list
    scanners = list(dict.fromkeys(
        (primary.get("detected_by") or primary.get("scanners") or [primary.get("scanner", "unknown")]) +
        (duplicate.get("detected_by") or duplicate.get("scanners") or [duplicate.get("scanner", "unknown")])
    ))
    merged["scanners"] = scanners
    merged["detected_by"] = scanners
    merged["scanner"] = scanners[0]
    merged["source_engine"] = scanners[0]

    # 2. Upgrade to higher severity
    p_sev = str(primary.get("severity", "MEDIUM")).upper()
    d_sev = str(duplicate.get("severity", "MEDIUM")).upper()
    if SEVERITY_RANKS.get(d_sev, 0) > SEVERITY_RANKS.get(p_sev, 0):
        merged["severity"] = d_sev

    # 3. Upgrade to higher confidence
    p_conf = str(primary.get("confidence", "LIKELY")).upper()
    d_conf = str(duplicate.get("confidence", "LIKELY")).upper()
    if CONFIDENCE_RANKS.get(d_conf, 0) > CONFIDENCE_RANKS.get(p_conf, 0):
        merged["confidence"] = d_conf

    # 4. Aggregate unique affected locations
    loc1 = primary.get("locations") or ([{"file": primary.get("file"), "line": primary.get("line"), "evidence": primary.get("evidence")}] if primary.get("file") else [])
    loc2 = duplicate.get("locations") or ([{"file": duplicate.get("file"), "line": duplicate.get("line"), "evidence": duplicate.get("evidence")}] if duplicate.get("file") else [])

    combined_locs: List[Dict[str, Any]] = []
    seen_locs: Set[Tuple[str, Optional[int]]] = set()

    for loc in (loc1 + loc2):
        if loc and loc.get("file"):
            f = str(loc.get("file")).replace("\\", "/")
            l = loc.get("line")
            k = (f.lower(), l)
            if k not in seen_locs:
                seen_locs.add(k)
                combined_locs.append({
                    "file": f,
                    "line": l,
                    "evidence": loc.get("evidence") or "",
                })

    merged["locations"] = combined_locs
    merged["affected_locations_count"] = len(combined_locs) if combined_locs else 1

    # 5. Fill in missing fields from duplicate if absent in primary
    for field in ("cve", "package", "version", "file", "line", "remediation", "eli5_explanation", "ai_fix_prompt"):
        if not merged.get(field) and duplicate.get(field):
            merged[field] = duplicate[field]

    # 6. Merge references
    refs = list(dict.fromkeys((primary.get("references") or []) + (duplicate.get("references") or [])))
    merged["references"] = refs

    return merged


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicates a list of normalized findings and aggregates locations.
    Pass 1: Correlates overlapping scanner detections on the exact same location.
    Pass 2: Groups identical finding rules across multiple files into a single card with multi-locations.
    """
    if not findings:
        return []

    # Filter out suppressed or info placeholder items
    clean_findings = [
        f for f in findings
        if f and not f.get("is_suppressed") and not (f.get("is_placeholder") and f.get("severity") == "INFO")
    ]

    # Pass 1: Deduplicate identical locations across different scanners
    loc_grouped: Dict[Any, Dict[str, Any]] = {}
    for f in clean_findings:
        f_copy = dict(f)
        if "locations" not in f_copy and f_copy.get("file"):
            f_copy["locations"] = [{"file": f_copy.get("file"), "line": f_copy.get("line"), "evidence": f_copy.get("evidence", "")}]
            f_copy["affected_locations_count"] = 1

        cat = (f_copy.get("category") or "").lower()
        fp = (f_copy.get("file") or "").lower().replace("\\", "/")
        line = str(f_copy.get("line") or "")
        loc_key = (cat, fp, line)
        if fp and line and loc_key in loc_grouped:
            loc_grouped[loc_key] = merge_findings(loc_grouped[loc_key], f_copy)
        else:
            k = loc_key if (fp and line) else f_copy.get("id") or str(id(f_copy))
            loc_grouped[k] = f_copy

    # Pass 2: Group identical findings across multiple files
    title_grouped: Dict[str, Dict[str, Any]] = {}
    ordered_keys: List[str] = []

    for f in loc_grouped.values():
        key = get_dedup_key(f)
        if key in title_grouped:
            title_grouped[key] = merge_findings(title_grouped[key], f)
        else:
            title_grouped[key] = dict(f)
            if "scanners" not in title_grouped[key]:
                title_grouped[key]["scanners"] = [title_grouped[key].get("scanner", "unknown")]
            ordered_keys.append(key)

    return [title_grouped[k] for k in ordered_keys]
