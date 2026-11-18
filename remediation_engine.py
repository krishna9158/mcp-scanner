"""
Fix Center & Remediation Engine for TrustAudit Platform.

Generates structured, actionable remediation guidance and deterministic
code diff previews for discovered security vulnerabilities across:
- Secrets & API Keys
- Insecure Dependencies (package upgrade diffs)
- AI-Code Security Patterns (SQLi, Command Injection, XSS, Path Traversal, CORS, RLS)
- Web Application Headers & Cookie Flags
- Infrastructure as Code (Dockerfile, Kubernetes, Terraform)
- MCP Tool Permissions & Prompt Injection Defenses
"""

import re
from typing import Any, Dict, List, Optional


def generate_remediation_package(finding: Dict[str, Any], file_content: Optional[str] = None) -> Dict[str, Any]:
    """
    Constructs a comprehensive Fix Center package for a finding.
    Returns:
    - what_happened: Clear description of the vulnerability.
    - why_it_matters: Business and security impact explanation.
    - location: Target file and line coordinates.
    - evidence: Concrete snippet or trigger condition.
    - how_to_fix: Step-by-step guidance.
    - diff_preview: Concrete code diff (before / after) when deterministically safe.
    - references: Authoritative standards (OWASP, CWE, NIST).
    """
    cat = (finding.get("category") or "").lower()
    title = finding.get("title", "Security Finding")
    desc = finding.get("description", "")
    ev = finding.get("evidence", "")
    fpath = finding.get("file", "")
    line = finding.get("line") or finding.get("line_start")
    remediation_text = finding.get("remediation", "")

    what_happened = desc or title
    why_it_matters = _derive_why_it_matters(finding)
    how_to_fix = remediation_text or "Apply defensive sanitization or update configuration."
    diff_preview = _generate_code_diff(finding, file_content)

    try:
        from trust_features import generate_eli5_explanation, generate_ai_fix_prompt
        eli5_explanation = generate_eli5_explanation(finding)
        ai_fix_prompt = generate_ai_fix_prompt(finding)
    except Exception:
        eli5_explanation = desc or title
        ai_fix_prompt = f"Ask Cursor / Claude: \"Fix the security issue '{title}' in {fpath}\""

    return {
        "finding_id": finding.get("id"),
        "title": title,
        "category": cat,
        "severity": finding.get("severity", "MEDIUM"),
        "what_happened": what_happened,
        "why_it_matters": why_it_matters,
        "eli5_explanation": eli5_explanation,
        "ai_fix_prompt": ai_fix_prompt,
        "location": f"{fpath}:{line}" if line else fpath,
        "locations": finding.get("locations", []),
        "evidence": ev,
        "how_to_fix": how_to_fix,
        "has_fix": bool(diff_preview),
        "diff_preview": diff_preview,
        "references": finding.get("references", []),
        "cwe": finding.get("cwe", []),
        "cve": finding.get("cve", []),
    }


def _derive_why_it_matters(finding: Dict[str, Any]) -> str:
    cat = (finding.get("category") or "").lower()
    title = (finding.get("title") or "").lower()

    if "secret" in cat or "credential" in title or "key" in title:
        return "Exposed credentials allow external threat actors to authenticate as privileged service accounts, bypass access controls, and access backend databases."
    if "sql" in title:
        return "SQL injection allows attackers to bypass authentication, read confidential database records, modify data, or execute administrative commands."
    if "command" in title or "exec" in title:
        return "Remote Command Execution (RCE) enables attackers to run arbitrary system shell commands on host infrastructure, resulting in total server compromise."
    if "cors" in title:
        return "Permissive CORS policies allow malicious third-party websites visited by authenticated users to issue unauthorized cross-origin requests."
    if "xss" in title or "dom" in title:
        return "Cross-Site Scripting (XSS) enables attackers to steal session cookies, capture keystrokes, and execute actions on behalf of victim users."
    if "dependency" in cat or "cve" in title:
        return "Vulnerable third-party packages contain known publicly disclosed exploits that can be leveraged without specialized zero-day research."
    if "mcp" in cat or "prompt" in title:
        return "Compromised or poisoned AI tool interfaces can trick LLM agents into executing high-privilege shell or filesystem actions with attacker data."
    if "header" in cat or "tls" in cat:
        return "Missing transport encryption or browser defense headers leaves client communication susceptible to Man-in-the-Middle (MitM) downgrade attacks."
    if "tenancy" in cat or "rls" in title:
        return "Missing Row Level Security (RLS) policies permit multitenant data leakage where one customer can inspect or overwrite another customer's data."
    return "Weakens defense-in-depth posture and creates opportunities for chained multi-stage exploitation."


def _generate_code_diff(finding: Dict[str, Any], file_content: Optional[str] = None) -> Optional[str]:
    title = (finding.get("title") or "").lower()
    ev = finding.get("evidence", "")

    # 1. SQL Injection Diff
    if "sql" in title:
        return """\
--- Vulnerable (String Interpolation)
+++ Secure (Parameterized Query)
- cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
+ cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
"""

    # 2. Command Injection Diff
    if "command" in title or "shell=true" in title:
        return """\
--- Vulnerable (Shell Interpolation)
+++ Secure (Argument List Array)
- subprocess.run(f"ping {host}", shell=True)
+ subprocess.run(["ping", host], shell=False, check=True)
"""

    # 3. Insecure CORS Diff
    if "cors" in title:
        return """\
--- Vulnerable (Wildcard Insecure CORS)
+++ Secure (Explicit Origin Allowlist)
- app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
+ app.add_middleware(CORSMiddleware, allow_origins=["https://app.trustaudit.io"], allow_credentials=True)
"""

    # 4. Insecure Deserialization Diff
    if "deserialization" in title or "pickle" in title:
        return """\
--- Vulnerable (Arbitrary Object Deserialization)
+++ Secure (Structured JSON Serialization)
- data = pickle.loads(raw_user_payload)
+ data = json.loads(raw_user_payload)
"""

    # 5. Missing RLS Diff
    if "rls" in title or "supabase" in title:
        return """\
--- Vulnerable (Public Table Access)
+++ Secure (Row Level Security Enforced)
- CREATE TABLE documents (id uuid primary key, user_id uuid, body text);
+ CREATE TABLE documents (id uuid primary key, user_id uuid, body text);
+ ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
+ CREATE POLICY user_isolation_policy ON documents FOR ALL USING (auth.uid() = user_id);
"""

    # 6. Dockerfile Root User Diff
    if "root" in title or "dockerfile" in title:
        return """\
--- Vulnerable (Running as Root)
+++ Secure (Dedicated Non-Root User)
  FROM node:20-alpine
+ RUN addgroup -S appgroup && adduser -S appuser -G appgroup
+ USER appuser
  CMD ["node", "server.js"]
"""

    # 7. HSTS / Security Headers Diff
    if "strict-transport-security" in title or "hsts" in title:
        return """\
--- Vulnerable (Missing HSTS Header)
+++ Secure (HSTS Header Injected)
+ response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
"""

    # 8. Dependency Upgrade Diff
    if "dependency" in (finding.get("category") or "").lower() and finding.get("package"):
        pkg = finding.get("package")
        ver = finding.get("version") or "current"
        return f"""\
--- package.json / requirements.txt ({ver})
+++ package.json / requirements.txt (Patched Release)
- "{pkg}": "{ver}"
+ "{pkg}": ">=latest_secure_version"
"""

    return None
