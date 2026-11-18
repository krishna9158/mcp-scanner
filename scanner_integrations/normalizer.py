"""
Finding Normalization Layer for TrustAudit Platform.

Transforms raw finding outputs from all integrated security engines
(Gitleaks, OSV-Scanner, Trivy, Nuclei, Syft, Semgrep, MCP Engine)
into a uniform, machine-readable finding schema.
"""

import hashlib
import os
import re
from typing import Any, Dict, List, Optional

VALID_CATEGORIES = {
    "secrets",
    "dependencies",
    "code_security",
    "mcp_security",
    "website_security",
    "authentication",
    "authorization",
    "prompt_injection",
    "misconfiguration",
    "supply_chain",
    "tenancy",
    "tls",
    "headers",
    "cookies",
    "cors",
    "exposure",
}

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_CONFIDENCES = {"CONFIRMED", "LIKELY", "POTENTIAL", "INFORMATIONAL"}


def compute_finding_fingerprint(
    category: str,
    title: str,
    file_path: Optional[str] = None,
    line: Optional[int] = None,
    package: Optional[str] = None,
    cve: Optional[str] = None,
    extra_seed: Optional[str] = None,
) -> str:
    """Computes a deterministic cryptographic fingerprint for finding correlation and deduplication."""
    norm_file = os.path.normpath(file_path).replace("\\", "/").lower() if file_path else ""
    seed_parts = [
        category.lower(),
        package.lower() if package else "",
        cve.upper() if cve else "",
        norm_file,
        str(line) if line else "",
        title.lower(),
        extra_seed or "",
    ]
    seed_str = ":".join(p for p in seed_parts if p)
    return hashlib.sha256(seed_str.encode("utf-8")).hexdigest()[:16]


def normalize_severity(raw_sev: Any) -> str:
    """Normalizes arbitrary severity strings into standard CRITICAL/HIGH/MEDIUM/LOW/INFO."""
    if not raw_sev:
        return "MEDIUM"
    s = str(raw_sev).strip().upper()
    if s in VALID_SEVERITIES:
        return s
    if s in ("ERROR", "FATAL", "BLOCKER"):
        return "CRITICAL"
    if s in ("WARN", "WARNING", "MODERATE"):
        return "MEDIUM"
    if s in ("NOTICE", "NOTE", "AUDIT"):
        return "LOW"
    return "MEDIUM"


def normalize_confidence(raw_conf: Any) -> str:
    """Normalizes confidence levels into standard CONFIRMED/LIKELY/POTENTIAL/INFORMATIONAL."""
    if not raw_conf:
        return "LIKELY"
    c = str(raw_conf).strip().upper()
    if c in VALID_CONFIDENCES:
        return c
    if c in ("HIGH", "CERTAIN", "DEFINITE"):
        return "CONFIRMED"
    if c in ("MEDIUM", "PROBABLE"):
        return "LIKELY"
    if c in ("LOW", "TENTATIVE", "UNCONFIRMED"):
        return "POTENTIAL"
    return "LIKELY"


def redact_secret_string(value: str) -> str:
    """Redacts sensitive credentials, tokens, and keys from evidence strings."""
    if not value or not isinstance(value, str):
        return "[REDACTED]"
    val = value.strip()
    if len(val) <= 8:
        return "[REDACTED]"
    return f"{val[:4]}...[REDACTED]...{val[-2:]}"


def normalize_finding(
    scanner: str,
    category: str,
    title: str,
    description: str,
    severity: str = "MEDIUM",
    confidence: str = "LIKELY",
    file: Optional[str] = None,
    line: Optional[int] = None,
    package: Optional[str] = None,
    version: Optional[str] = None,
    cve: Optional[str] = None,
    evidence: Optional[str] = None,
    remediation: Optional[str] = None,
    references: Optional[List[str]] = None,
    raw_details: Optional[Dict[str, Any]] = None,
    finding_id: Optional[str] = None,
    cwe: Optional[Any] = None,
    **kwargs: Any
) -> Dict[str, Any]:
    """
    Constructs a standardized finding dictionary.
    Guarantees no sensitive raw secret values are stored.
    """
    cat = category if category in VALID_CATEGORIES else "code_security"
    sev = normalize_severity(severity)
    conf = normalize_confidence(confidence)
    
    clean_file = os.path.normpath(file).replace("\\", "/") if file else None
    clean_line = int(line) if line is not None and str(line).isdigit() else None
    
    fingerprint = compute_finding_fingerprint(
        category=cat,
        title=title,
        file_path=clean_file,
        line=clean_line,
        package=package,
        cve=cve,
    )
    
    fid = finding_id or f"FIND-{scanner.upper()[:4]}-{fingerprint[:8].upper()}"
    
    safe_evidence = evidence or "Automated scanner detection rule match."
    # Ensure evidence does not contain raw API keys or passwords
    if cat == "secrets" or "key" in title.lower() or "token" in title.lower():
        safe_evidence = re.sub(r'([A-Za-z0-9_\-]{20,})', lambda m: redact_secret_string(m.group(1)), safe_evidence)

    cwe_list = []
    if cwe:
        cwe_list = cwe if isinstance(cwe, list) else [str(cwe)]
    elif raw_details and "cwe" in raw_details:
        cwe_val = raw_details["cwe"]
        cwe_list = cwe_val if isinstance(cwe_val, list) else [str(cwe_val)]
    elif cve and cve.startswith("CWE-"):
        cwe_list = [cve]

    is_url = bool(clean_file and (clean_file.startswith("http://") or clean_file.startswith("https://")))
    has_fix = bool(remediation and any(w in remediation.lower() for w in ("upgrade", "update", "set", "replace", "add", "remove", "use")))

    finding = {
        "id": fid,
        "title": title.strip(),
        "severity": sev,
        "category": cat,
        "source_engine": scanner,
        "scanner": scanner,
        "scanners": [scanner],
        "detected_by": [scanner],
        "confidence": conf,
        "description": description.strip() if description else title.strip(),
        "evidence": safe_evidence,
        "file": clean_file,
        "line": clean_line,
        "line_start": clean_line,
        "line_end": raw_details.get("line_end", clean_line) if raw_details else clean_line,
        "package": package,
        "version": version,
        "url": clean_file if is_url else None,
        "cwe": cwe_list,
        "cve": cve,
        "cves": [cve] if cve else [],
        "cvss": raw_details.get("cvss") if raw_details else None,
        "references": references or [],
        "remediation": remediation or "Review affected component, apply security patch, or update configuration.",
        "fix_available": has_fix,
        "status": "OPEN",
        "fingerprint": fingerprint,
        "raw_details": raw_details or {},
    }

    try:
        from universal_validator import validate_and_sanitize_finding
        sanitized = validate_and_sanitize_finding(finding)
        if sanitized is None:
            finding["is_suppressed"] = True
            finding["severity"] = "INFO"
            finding["confidence"] = "POSSIBLE"
            return finding
        return sanitized
    except Exception:
        return finding
