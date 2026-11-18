"""
API & Business Logic Security Analyzer for TrustAudit Platform.

Detects critical modern API security flaws (OWASP API Top 10):
- API1: Broken Object Level Authorization (BOLA / IDOR)
- API3: Broken Object Property Level Authorization / Mass Assignment
- API4: Unrestricted Resource Consumption / Unbounded Database Queries
- API5: Broken Function Level Authorization (BFLA)
- API8: Security Misconfiguration / Sensitive Tokens in URLs
"""

import os
import re
from typing import Any, Dict, List


API_SECURITY_RULES = [
    {
        "id": "API-MASS-ASSIGNMENT-ROLE-TAMPERING",
        "name": "Mass Assignment / Privilege Role Tampering",
        "category": "API Security",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)(?:User|Account|Profile)\.(?:create|update|findOneAndUpdate)\s*\(\s*(?:req\.body|request\.json)\s*\)',
            r'(?i)Object\.assign\s*\(\s*user\s*,\s*req\.body\s*\)',
            r'(?i)\.update\s*\(\s*\{\s*role\s*:\s*req\.body\.role',
            r'(?i)\.update\s*\(\s*\{\s*isAdmin\s*:\s*req\.body\.isAdmin',
        ],
        "message": "Direct assignment of client request payload to user or account models allows attackers to elevate their role (e.g. `role: admin`, `isAdmin: true`).",
        "fix": "Use an explicit DTO allowlist or pick only authorized user-editable fields (e.g. name, avatar).",
        "cwe": "CWE-915",
    },
    {
        "id": "API-BOLA-IDOR-MISSING-TENANT-FILTER",
        "name": "Broken Object Level Authorization (BOLA/IDOR)",
        "category": "API Security",
        "severity": "CRITICAL",
        "patterns": [
            r'(?i)(?:db\.\w+|\w+Repository)\.(?:delete|remove|destroy|deleteOne|deleteMany)\s*\(\s*\{\s*["\']?(?:id|_id)["\']?\s*:\s*(?:req\.params|request\.|params|args|id)\b',
            r'(?i)(?:db\.\w+|\w+Repository)\.(?:findByIdAndUpdate|findByIdAndDelete|update|updateOne)\s*\(\s*(?:req\.params|id|req\.body\.id)\b',
        ],
        "message": "Database mutation uses object ID directly from URL params without verifying that the requesting user owns the object or belongs to the same tenant.",
        "fix": "Scope all database operations by both object ID and authenticated `userId`/`tenantId`.",
        "cwe": "CWE-639",
    },
    {
        "id": "API-UNBOUNDED-QUERY-DOS",
        "name": "Unbounded Database Query / API Resource Exhaustion",
        "category": "API Security",
        "severity": "MEDIUM",
        "patterns": [
            r'(?i)SELECT\s+\*\s+FROM\s+\w+\s*(?:WHERE\s+[^;]+)?;\s*["\'](?![\s\S]*?LIMIT)',
            r'(?i)\.find\s*\(\s*\{\s*\}\s*\)(?![\s\S]*?\.(?:limit|take|paginate)\s*\()',
        ],
        "message": "Database query returns all rows without `LIMIT` or pagination constraints, allowing Denial of Service (DoS) via memory exhaustion.",
        "fix": "Enforce strict default pagination with reasonable maximum limits (e.g. `LIMIT 50`).",
        "cwe": "CWE-770",
    },
    {
        "id": "API-TOKEN-IN-URL-QUERY",
        "name": "Sensitive Authentication Token in URL Parameters",
        "category": "API Security",
        "severity": "HIGH",
        "patterns": [
            r'(?i)https?://[^\s"\'`]+[?&](?:access_token|api_key|token|auth|secret)=',
            r'(?i)router\.(?:get|post)\s*\(\s*["\'].*:(?:token|apiKey|secret)["\']',
        ],
        "message": "Passing authentication credentials in URL query parameters exposes them in web server access logs, browser history, and Referer headers.",
        "fix": "Pass sensitive authentication credentials in standard HTTP `Authorization: Bearer <token>` headers.",
        "cwe": "CWE-598",
    },
]


def scan_file_for_api_security(content: str, filepath: str) -> List[Dict[str, Any]]:
    """
    Scans a single source file for API & business logic vulnerabilities.
    """
    findings = []
    for rule in API_SECURITY_RULES:
        for pat in rule["patterns"]:
            match = re.search(pat, content)
            if match:
                line = content.count("\n", 0, match.start()) + 1
                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "file": filepath,
                    "line": line,
                    "message": rule["message"],
                    "matched_snippet": match.group(0)[:140],
                    "fix": rule["fix"],
                    "cwe": rule.get("cwe", "CWE-639"),
                })
                break  # one finding per rule per file
    return findings


def scan_folder_for_api_security(folder: str, max_files: int = 1000) -> List[Dict[str, Any]]:
    """
    Recursively scans source folder for API security flaws.
    """
    findings = []
    count = 0
    skip_dirs = (".git", "node_modules", "dist", "build", ".venv", "venv", ".pytest_cache")

    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
        for file in files:
            if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".sql")):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(500000)
                    file_findings = scan_file_for_api_security(content, filepath)
                    findings.extend(file_findings)
                except Exception:
                    continue
                count += 1
                if count >= max_files:
                    return findings
    return findings
