"""
TrustAudit Unified Remediation Centre & Compliance Task Management Engine.

Provides for every security and compliance finding:
1. What is wrong (Plain English + Technical description)
2. Why it matters (Business & Legal Risk)
3. What needs to be changed
4. Step-by-step technical instructions
5. Required evidence to satisfy compliance auditors
6. Responsible owner assignment & priority
7. SLA Deadlines (e.g. Critical = 7 days, High = 14 days, Medium = 30 days)
8. Current status tracking (OPEN, IN_PROGRESS, RESOLVED, VERIFIED, RISK_ACCEPTED)
9. Automated verification procedure
10. Unified task deduplication across multiple frameworks (DPDP, SOC 2, ISO 27001, GDPR)

IMPORTANT:
Does not assume one technical fix automatically satisfies an entire compliance requirement.
"""

import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from compliance_frameworks import map_finding_to_compliance_frameworks

REMEDIATION_STORE_FILE = os.path.join(os.path.dirname(__file__), "data", "remediation_tasks.json")
os.makedirs(os.path.dirname(REMEDIATION_STORE_FILE), exist_ok=True)

DEFAULT_SLAS_DAYS = {
    "CRITICAL": 7,
    "HIGH": 14,
    "MEDIUM": 30,
    "LOW": 60,
    "INFO": 90
}


def _load_remediation_data() -> Dict[str, Any]:
    if not os.path.exists(REMEDIATION_STORE_FILE):
        return {"tasks": {}}
    try:
        with open(REMEDIATION_STORE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"tasks": {}}


def _save_remediation_data(data: Dict[str, Any]):
    try:
        with open(REMEDIATION_STORE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[REMEDIATION_CENTRE] Error saving tasks: {e}", flush=True)


def generate_remediation_task_for_finding(finding: Dict[str, Any], org_id: str = "org-default") -> Dict[str, Any]:
    """
    Transforms any raw or normalized scanner finding into an audit-ready, unified remediation task.
    """
    fid = finding.get("id") or finding.get("finding_id") or f"FIND-{uuid.uuid4().hex[:8].upper()}"
    title = finding.get("title", "Untitled Vulnerability")
    severity = (finding.get("severity") or "MEDIUM").upper()
    category = finding.get("category", "code_security")
    file_path = finding.get("file") or finding.get("affected_file_or_url") or "Global Configuration"
    line = finding.get("line")
    evidence = finding.get("evidence") or finding.get("scanner_evidence") or "Pattern match in repository."

    # SLA Deadline calculation
    sla_days = DEFAULT_SLAS_DAYS.get(severity, 30)
    now = time.time()
    deadline = now + (sla_days * 86400)

    # Multi-framework mappings
    framework_mappings = map_finding_to_compliance_frameworks(finding)

    # Technical instructions & step-by-step guidance
    step_instructions = []
    required_evidence = []
    verification_procedure = ""

    if category == "secrets":
        what_is_wrong = f"Hardcoded credential or API secret found in '{file_path}' (line {line or 'N/A'})."
        why_it_matters = "Anyone with read access to this code or backup images can impersonate your system, access production databases, or incur substantial cloud compute costs. Legally, this violates statutory safeguards under DPDP Section 8(5) (read with Rule 6) and SOC 2 CC6.1."
        what_to_change = "Revoke the exposed key immediately, store new keys in a secret manager, and reference them via environment variables."
        step_instructions = [
            f"1. Open '{file_path}' and locate line {line or 1}.",
            "2. Immediately log in to the provider console (e.g. AWS, Stripe, Slack) and REVOKE the compromised token.",
            "3. Generate a new secret key with least-privilege scoping.",
            "4. Add the secret to your environment manager (e.g. AWS Secrets Manager, Doppler, or Render Environment Variables).",
            f"5. Replace the hardcoded string in '{file_path}' with `os.environ.get('YOUR_SECRET_KEY')`.",
            "6. Ensure '.env' is included in your '.gitignore' file so local test keys are never committed.",
            "7. Run TrustAudit rescan to verify that zero active secrets remain in the repository."
        ]
        required_evidence = [
            "Screenshot of provider revocation timestamp and newly provisioned key.",
            "Git commit diff showing removal of plaintext key and replacement with environment variable.",
            "Clean TrustAudit secret scanner re-verification report."
        ]
        verification_procedure = "Run TrustAudit secret scan (`secret_detector.py`) on the updated commit. The finding must transition to VERIFIED_FIXED."

    elif category in ("tls", "headers", "cookies"):
        what_is_wrong = f"Missing or permissive HTTP security configuration on endpoint '{file_path}'."
        why_it_matters = "Without strict transport security (HSTS) and anti-clickjacking headers, users can be tricked into man-in-the-middle attacks or cross-origin data theft. Violates SOC 2 CC6.6 and ISO 27001 Control A.8.20."
        what_to_change = "Configure web application server (Nginx, Cloudflare, or Flask middleware) to emit standard security headers."
        step_instructions = [
            "1. In your web server or edge CDN configuration, enable 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
            "2. Add header 'X-Content-Type-Options: nosniff'.",
            "3. Add header 'X-Frame-Options: DENY' or configure a strict 'Content-Security-Policy'.",
            "4. Ensure all session and authentication cookies specify 'Secure; HttpOnly; SameSite=Lax'.",
            "5. Re-run TrustAudit website perimeter scan against the target URL."
        ]
        required_evidence = [
            "HTTP response header dump showing active HSTS, CSP, and Secure cookie attributes.",
            "Clean TrustAudit perimeter scan verification report."
        ]
        verification_procedure = "Trigger live HTTP header probe using `website_scanner.py`. Verify that security header score exceeds 90/100."

    elif category == "dependencies":
        pkg = finding.get("package") or "vulnerable component"
        cve = finding.get("cve") or "known CVE"
        what_is_wrong = f"Dependency '{pkg}' contains a known security vulnerability ({cve})."
        why_it_matters = "Known component vulnerabilities provide attackers with public exploit code for remote code execution, denial of service, or data exfiltration. Violates SOC 2 CC7.1 and ISO 27001 Control A.8.8."
        what_to_change = f"Upgrade '{pkg}' to the latest secure patched release."
        step_instructions = [
            f"1. Inspect your package manifest (`requirements.txt` or `package.json`) for '{pkg}'.",
            f"2. Run package manager update to safe version: `pip install --upgrade {pkg}` or `npm update {pkg}`.",
            "3. Run automated unit test suite to verify no backwards-incompatible breaking changes.",
            "4. Commit the updated dependency lockfile (`package-lock.json` or `requirements.txt`).",
            "5. Trigger TrustAudit dependency re-scan."
        ]
        required_evidence = [
            "Updated dependency manifest commit hash.",
            "Automated test run passing log.",
            "Clean dependency scan verification report."
        ]
        verification_procedure = "Run `dependency_check.py` or OSV-Scanner on the project manifest. Confirm zero high or critical CVEs."

    elif category == "mcp_security" or "prompt_injection" in category:
        what_is_wrong = f"MCP Tool definition in '{file_path}' exposes risky capabilities or unvalidated directives."
        why_it_matters = "AI assistants connecting to this MCP server could be manipulated via prompt injection into running arbitrary shell commands, accessing the host filesystem, or exfiltrating user chat context."
        what_to_change = "Constrain MCP tool permissions to least privilege and sanitize tool descriptions."
        step_instructions = [
            f"1. Open tool definition file '{file_path}'.",
            "2. Align declared description with actual code capabilities. Remove any manipulative prompting prefixes.",
            "3. If the tool does not strictly require shell or subprocess execution, remove `subprocess` / `os.system` calls.",
            "4. Apply the TrustAudit MCP runtime firewall policy to restrict directory traversal and loopback network calls.",
            "5. Re-run TrustAudit MCP analyzer."
        ]
        required_evidence = [
            "Source code commit diff constraining tool arguments and scope.",
            "TrustAudit permission graph report showing verified least-privilege boundary."
        ]
        verification_procedure = "Run `tool_analyzer.py` and `mcp_auth_analyzer.py`. Verify that blast radius is downgraded to LOW."

    else:
        what_is_wrong = f"Security vulnerability identified in '{file_path}': {title}."
        why_it_matters = "Unresolved security issues degrade system posture, fail compliance audits, and increase breach likelihood."
        what_to_change = "Apply code patch or configuration update as recommended."
        step_instructions = [
            f"1. Review source code in '{file_path}'.",
            "2. Apply secure coding guidelines addressing the underlying weakness.",
            "3. Test application locally to ensure proper function.",
            "4. Commit fix and trigger TrustAudit verification scan."
        ]
        required_evidence = [
            "Git commit hash resolving the issue.",
            "Clean TrustAudit scanner execution report."
        ]
        verification_procedure = "Run TrustAudit repository re-scan on target asset."

    task_id = f"REM-{fid.replace('FIND-', '')}"

    task = {
        "task_id": task_id,
        "org_id": org_id,
        "finding_id": fid,
        "title": f"Remediate: {title}",
        "severity": severity,
        "category": category,
        "affected_asset": finding.get("affected_asset") or finding.get("source_engine", "Repository"),
        "affected_file_or_url": file_path,
        "line": line,
        "evidence": evidence,
        "what_is_wrong": what_is_wrong,
        "why_it_matters": why_it_matters,
        "what_needs_to_be_changed": what_to_change,
        "step_by_step_instructions": step_instructions,
        "required_evidence": required_evidence,
        "responsible_person": "Unassigned (Security Lead)",
        "priority": "P0 - Blocker" if severity == "CRITICAL" else ("P1 - High" if severity == "HIGH" else "P2 - Normal"),
        "deadline_timestamp": deadline,
        "deadline_human": time.strftime("%Y-%m-%d", time.gmtime(deadline)),
        "status": "OPEN",  # OPEN, IN_PROGRESS, RESOLVED, VERIFIED, RISK_ACCEPTED
        "verification_procedure": verification_procedure,
        "framework_mappings": framework_mappings,
        "created_at": now,
        "updated_at": now
    }

    return task


def sync_remediation_tasks_from_findings(findings: List[Dict[str, Any]], org_id: str = "org-default") -> List[Dict[str, Any]]:
    """
    Synchronizes tasks in the Remediation Centre with findings from scans.
    Reuses existing task states (e.g. if already assigned or in-progress).
    """
    data = _load_remediation_data()
    existing_tasks = data.get("tasks", {})
    synced_tasks = []

    for f in findings:
        fid = f.get("id") or f.get("finding_id")
        if not fid:
            continue
        task_id = f"REM-{fid.replace('FIND-', '')}"

        if task_id in existing_tasks and existing_tasks[task_id].get("org_id") == org_id:
            # Preserve existing user assignment and progress status
            task = existing_tasks[task_id]
            task["severity"] = (f.get("severity") or task.get("severity", "MEDIUM")).upper()
            task["updated_at"] = time.time()
        else:
            task = generate_remediation_task_for_finding(f, org_id=org_id)
            existing_tasks[task_id] = task

        synced_tasks.append(task)

    data["tasks"] = existing_tasks
    _save_remediation_data(data)
    return synced_tasks


def list_remediation_tasks_for_org(org_id: str = "org-default", status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists remediation tasks for organization, optionally filtered by status."""
    data = _load_remediation_data()
    tasks = [t for t in data.get("tasks", {}).values() if t.get("org_id") == org_id]
    if status:
        tasks = [t for t in tasks if t.get("status") == status.upper()]
    tasks.sort(key=lambda x: (0 if x.get("severity") == "CRITICAL" else (1 if x.get("severity") == "HIGH" else 2), x.get("deadline_timestamp", 0)))
    return tasks


def update_remediation_task(
    task_id: str,
    org_id: str = "org-default",
    status: Optional[str] = None,
    responsible_person: Optional[str] = None,
    notes: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Updates remediation task progress, ownership, or resolution notes."""
    data = _load_remediation_data()
    task = data.get("tasks", {}).get(task_id)
    if not task or task.get("org_id") != org_id:
        return None

    if status:
        task["status"] = status.upper()
    if responsible_person:
        task["responsible_person"] = responsible_person.strip()
    if notes is not None:
        task["notes"] = notes.strip()
    task["updated_at"] = time.time()

    data["tasks"][task_id] = task
    _save_remediation_data(data)
    return task
