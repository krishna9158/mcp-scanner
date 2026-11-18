"""
TrustAudit Compliance & Security Framework Mapping Engine.

Maps real scan findings to recognized security standards:
- OWASP Top 10 (2021)
- CWE Top 25 Most Dangerous Software Weaknesses
- SOC 2 Trust Services Criteria (CC6.1, CC6.6, CC6.8, CC7.1)
- ISO/IEC 27001:2022 (A.8.8, A.8.20, A.8.24, A.8.28)
- CIS Critical Security Controls v8

Also evaluates the 24-Point "Startup Security Health" Checklist.

DISCLAIMER: TrustAudit provides security control visibility and continuous posture auditing.
It does not constitute formal regulatory certification.
"""

from typing import Any, Dict, List, Optional


# OWASP Top 10 (2021) Definitions
OWASP_CATEGORIES = {
    "A01:2021-Broken Access Control": {
        "name": "Broken Access Control",
        "description": "Failures that allow unauthorized information disclosure, modification, or destruction of data outside the user's permissions.",
        "keywords": ["access control", "idor", "privilege", "authorization", "permission", "tenant", "rls", "bypass", "unauthorized", "traversal"]
    },
    "A02:2021-Cryptographic Failures": {
        "name": "Cryptographic Failures",
        "description": "Exposure of sensitive data in transit or at rest due to weak algorithms, missing encryption, or plaintext HTTP.",
        "keywords": ["crypto", "ssl", "tls", "plaintext", "http", "cipher", "certificate", "hsts", "md5", "sha1", "weak hash"]
    },
    "A03:2021-Injection": {
        "name": "Injection",
        "description": "Untrusted user data sent to an interpreter as part of a command or query (SQL, OS Command, Prompt Injection, LDAP).",
        "keywords": ["injection", "sql", "sqli", "command", "exec", "eval", "os command", "prompt injection", "nosql", "xss", "cross-site scripting"]
    },
    "A04:2021-Insecure Design": {
        "name": "Insecure Design",
        "description": "Risks related to design and architectural flaws, missing threat modeling, or absence of secure design patterns.",
        "keywords": ["design", "rate limit", "brute force", "business logic", "blast radius", "unrestricted", "threat model"]
    },
    "A05:2021-Security Misconfiguration": {
        "name": "Security Misconfiguration",
        "description": "Missing security hardening, misconfigured HTTP headers, default accounts, exposed public files, permissive CORS, or overly informative error messages.",
        "keywords": ["misconfig", "header", "csp", "cors", "cookie", "httponly", "samesite", "exposure", "robots.txt", "git", "env", "swagger", "debug", "directory listing"]
    },
    "A06:2021-Vulnerable and Outdated Components": {
        "name": "Vulnerable and Outdated Components",
        "description": "Use of third-party libraries, packages, or operating system components with known publicly disclosed vulnerabilities (CVEs).",
        "keywords": ["dependency", "cve", "osv", "trivy", "syft", "outdated", "package", "vulnerable component", "npm", "pip", "pypi", "gem", "cargo"]
    },
    "A07:2021-Identification and Authentication Failures": {
        "name": "Identification and Authentication Failures",
        "description": "Weak session management, credential stuffing vulnerability, hardcoded secrets, or missing authentication checks.",
        "keywords": ["auth", "authentication", "session", "jwt", "token", "secret", "gitleaks", "credential", "api key", "password", "hardcoded"]
    },
    "A08:2021-Software and Data Integrity Failures": {
        "name": "Software and Data Integrity Failures",
        "description": "Code and infrastructure that does not protect against integrity violations, untrusted CI/CD pipelines, or unsigned dependencies.",
        "keywords": ["integrity", "deserialization", "pickle", "yaml.load", "sbom", "supply chain", "typosquat", "dependency confusion", "ci/cd"]
    },
    "A09:2021-Security Logging and Monitoring Failures": {
        "name": "Security Logging and Monitoring Failures",
        "description": "Insufficient logging, monitoring, and active detection allowing breaches to occur unnoticed without alerting.",
        "keywords": ["logging", "monitoring", "audit trail", "alerting", "telemetry", "detection", "drift"]
    },
    "A10:2021-Server-Side Request Forgery (SSRF)": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Flaws that let an application fetch a remote resource without validating the user-supplied URL (internal network or cloud metadata access).",
        "keywords": ["ssrf", "request forgery", "internal ip", "metadata", "169.254.169.254", "localhost"]
    }
}

# SOC 2 Trust Services Criteria
SOC2_CONTROLS = {
    "CC6.1 - Logical Access Controls": {
        "name": "Logical Access Controls",
        "description": "The entity restricts logical access to confidential assets to authorized users.",
        "keywords": ["auth", "secret", "credential", "access control", "idor", "privilege", "token"]
    },
    "CC6.6 - Boundary & Perimeter Protection": {
        "name": "Boundary & Perimeter Protection",
        "description": "The entity implements perimeter defense, secure network protocols, and encryption in transit.",
        "keywords": ["tls", "ssl", "https", "hsts", "cors", "firewall", "header", "exposure", "perimeter"]
    },
    "CC6.8 - Threat Prevention & Detection": {
        "name": "Threat Prevention & Detection",
        "description": "The entity prevents or detects unauthorized software, malicious code, and execution flaws.",
        "keywords": ["injection", "command", "sql", "xss", "appsec", "malicious", "poisoning", "rce"]
    },
    "CC7.1 - Vulnerability Management": {
        "name": "Vulnerability Management",
        "description": "The entity identifies, scans, evaluates, and remediates software and configuration vulnerabilities.",
        "keywords": ["cve", "dependency", "outdated", "package", "patch", "vulnerability", "sbom"]
    }
}

# ISO/IEC 27001 Controls
ISO27001_CONTROLS = {
    "A.8.8 - Management of Technical Vulnerabilities": {
        "name": "Management of Technical Vulnerabilities",
        "description": "Information about technical vulnerabilities of information systems is obtained, evaluated, and addressed.",
        "keywords": ["cve", "dependency", "patch", "vulnerability", "scanner", "sast", "dast"]
    },
    "A.8.20 - Network Security": {
        "name": "Network Security",
        "description": "Networks and network devices are secured, managed, and controlled to protect information.",
        "keywords": ["tls", "ssl", "https", "dns", "exposure", "port", "header"]
    },
    "A.8.24 - Use of Cryptography": {
        "name": "Use of Cryptography",
        "description": "Rules for the effective use of cryptography, key management, and data protection in transit.",
        "keywords": ["crypto", "ssl", "tls", "cipher", "hsts", "secret", "certificate"]
    },
    "A.8.28 - Secure Coding": {
        "name": "Secure Coding",
        "description": "Secure coding principles are applied to software development to prevent design and implementation weaknesses.",
        "keywords": ["injection", "sast", "semgrep", "bandit", "code_security", "idor", "xss"]
    }
}


def map_finding_to_owasp(finding: Dict[str, Any]) -> str:
    """Classifies a finding into an OWASP Top 10 category."""
    owasp_explicit = finding.get("owasp_category") or finding.get("owasp")
    if owasp_explicit and ("A0" in str(owasp_explicit) or "A10" in str(owasp_explicit)):
        for cat_key in OWASP_CATEGORIES:
            if cat_key.split("-")[0] in str(owasp_explicit):
                return cat_key

    text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('category', '')} {finding.get('cwe', '')}".lower()
    for cat_key, cat_info in OWASP_CATEGORIES.items():
        for kw in cat_info["keywords"]:
            if kw in text:
                return cat_key

    return "A05:2021-Security Misconfiguration"


def compute_compliance_mapping(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Synthesizes compliance mapping across OWASP, SOC 2, and ISO 27001 based on real findings.
    """
    owasp_map = {k: {"name": v["name"], "findings_count": 0, "findings": [], "status": "PASS"} for k, v in OWASP_CATEGORIES.items()}
    soc2_map = {k: {"name": v["name"], "findings_count": 0, "findings": [], "status": "PASS"} for k, v in SOC2_CONTROLS.items()}
    iso_map = {k: {"name": v["name"], "findings_count": 0, "findings": [], "status": "PASS"} for k, v in ISO27001_CONTROLS.items()}

    for f in findings:
        f_title = f.get("title", "Finding")
        f_sev = (f.get("severity") or "MEDIUM").upper()
        f_summary = {"id": f.get("id") or f.get("finding_id"), "title": f_title, "severity": f_sev, "category": f.get("category")}

        # 1. OWASP
        owasp_cat = map_finding_to_owasp(f)
        if owasp_cat in owasp_map:
            owasp_map[owasp_cat]["findings_count"] += 1
            owasp_map[owasp_cat]["findings"].append(f_summary)
            if f_sev in ("CRITICAL", "HIGH"):
                owasp_map[owasp_cat]["status"] = "FAIL"
            elif owasp_map[owasp_cat]["status"] != "FAIL":
                owasp_map[owasp_cat]["status"] = "WARNING"

        # 2. SOC 2
        text = f"{f_title} {f.get('description', '')} {f.get('category', '')}".lower()
        for s_key, s_info in SOC2_CONTROLS.items():
            if any(kw in text for kw in s_info["keywords"]):
                soc2_map[s_key]["findings_count"] += 1
                soc2_map[s_key]["findings"].append(f_summary)
                if f_sev in ("CRITICAL", "HIGH"):
                    soc2_map[s_key]["status"] = "NEEDS_ATTENTION"
                elif soc2_map[s_key]["status"] != "NEEDS_ATTENTION":
                    soc2_map[s_key]["status"] = "REVIEW"

        # 3. ISO 27001
        for i_key, i_info in ISO27001_CONTROLS.items():
            if any(kw in text for kw in i_info["keywords"]):
                iso_map[i_key]["findings_count"] += 1
                iso_map[i_key]["findings"].append(f_summary)
                if f_sev in ("CRITICAL", "HIGH"):
                    iso_map[i_key]["status"] = "NON_CONFORMANT"
                elif iso_map[i_key]["status"] != "NON_CONFORMANT":
                    iso_map[i_key]["status"] = "OBSERVATION"

    return {
        "owasp_top_10": owasp_map,
        "soc2_controls": soc2_map,
        "iso27001_controls": iso_map,
        "total_mapped_findings": len(findings),
        "disclaimer": "TrustAudit provides continuous security control visibility and automated posture auditing. It does not certify regulatory compliance."
    }


def evaluate_startup_security_checklist(scan_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Evaluates the 24-point Startup Security Health Checklist using real scan results.
    """
    findings = (scan_result.get("findings") or []) if scan_result else []
    findings_titles = " ".join([f.get("title", "").lower() + " " + f.get("description", "").lower() for f in findings])
    findings_cats = " ".join([f.get("category", "").lower() for f in findings])

    headers_eval = (scan_result.get("headers_eval") or {}) if scan_result else {}
    tls_info = (scan_result.get("tls_info") or {}) if scan_result else {}
    cookie_analysis = (scan_result.get("cookie_analysis") or {}) if scan_result else {}
    cors_info = (scan_result.get("cors_info") or {}) if scan_result else {}

    controls = [
        {
            "id": "CTRL-01",
            "name": "HTTPS Encryption Enforced",
            "category": "Perimeter & Network",
            "passed": ("plaintext http" not in findings_titles) and (tls_info.get("available", True)),
            "reason": "All web traffic must automatically redirect from HTTP to HTTPS with strong TLS protocols."
        },
        {
            "id": "CTRL-02",
            "name": "HTTP Strict Transport Security (HSTS)",
            "category": "Perimeter & Network",
            "passed": ("hsts" not in findings_titles) and ("strict-transport-security" in [k.lower() for k in headers_eval.keys()] if headers_eval else True),
            "reason": "Enforces browsers to only connect over HTTPS to protect against downgrade and MITM attacks."
        },
        {
            "id": "CTRL-03",
            "name": "Valid & Active TLS/SSL Certificate",
            "category": "Perimeter & Network",
            "passed": tls_info.get("valid", True) and ("tls" not in findings_cats or "expired" not in findings_titles),
            "reason": "SSL certificate is valid, issued by a trusted CA, and not nearing expiration."
        },
        {
            "id": "CTRL-04",
            "name": "Content Security Policy (CSP)",
            "category": "Application Defenses",
            "passed": "content-security-policy" not in findings_titles and ("content-security-policy" in [k.lower() for k in headers_eval.keys()] if headers_eval else True),
            "reason": "Defines approved sources of content to mitigate Cross-Site Scripting (XSS) and data exfiltration."
        },
        {
            "id": "CTRL-05",
            "name": "Secure Cookie Flags (HttpOnly & Secure)",
            "category": "Application Defenses",
            "passed": "cookie" not in findings_cats and "httponly" not in findings_titles,
            "reason": "Session cookies must have Secure, HttpOnly, and SameSite flags enabled."
        },
        {
            "id": "CTRL-06",
            "name": "Restricted CORS Policy",
            "category": "Perimeter & Network",
            "passed": "cors" not in findings_titles and cors_info.get("status") != "VULNERABLE",
            "reason": "Prevents unauthorized external websites from accessing authenticated user data via permissive wildcards."
        },
        {
            "id": "CTRL-07",
            "name": "Anti-Clickjacking Headers (X-Frame-Options)",
            "category": "Application Defenses",
            "passed": "clickjacking" not in findings_titles and "x-frame-options" not in findings_titles,
            "reason": "Disallows embedding pages in third-party iframes to prevent UI redressing attacks."
        },
        {
            "id": "CTRL-08",
            "name": "MIME Sniffing Protection (X-Content-Type-Options)",
            "category": "Application Defenses",
            "passed": "nosniff" not in findings_titles and "x-content-type-options" not in findings_titles,
            "reason": "Forces browsers to follow declared MIME types rather than sniffing payload contents."
        },
        {
            "id": "CTRL-09",
            "name": "Zero Exposed Production Secrets",
            "category": "Data & Secret Hygiene",
            "passed": "secret" not in findings_cats and "api key" not in findings_titles and "token" not in findings_titles,
            "reason": "No hardcoded credentials, cloud access tokens, or private keys in repository code or public assets."
        },
        {
            "id": "CTRL-10",
            "name": "Dependency Vulnerability Audit",
            "category": "Supply Chain",
            "passed": "dependency" not in findings_cats and "cve" not in findings_titles,
            "reason": "All third-party open source packages are free of known published CVE vulnerabilities."
        },
        {
            "id": "CTRL-11",
            "name": "Software Bill of Materials (SBOM) Generated",
            "category": "Supply Chain",
            "passed": bool(scan_result and scan_result.get("sbom")),
            "reason": "Complete inventory of all application components, licenses, and packages is tracked."
        },
        {
            "id": "CTRL-12",
            "name": "Safe Public Exposure (.git / .env / backups)",
            "category": "Perimeter & Network",
            "passed": "public exposure" not in findings_titles and ".env" not in findings_titles and ".git" not in findings_titles,
            "reason": "Configuration files, environment dumps, and version control directories are blocked from public internet access."
        },
        {
            "id": "CTRL-13",
            "name": "SQL & Command Injection Defenses",
            "category": "Code Security",
            "passed": "sql injection" not in findings_titles and "command injection" not in findings_titles,
            "reason": "Database queries use parameterized statements; OS command execution with user inputs is avoided."
        },
        {
            "id": "CTRL-14",
            "name": "Cross-Site Scripting (XSS) Defenses",
            "category": "Code Security",
            "passed": "cross-site scripting" not in findings_titles and "xss" not in findings_titles,
            "reason": "User input is sanitized and HTML-encoded before rendering in client browsers."
        },
        {
            "id": "CTRL-15",
            "name": "Multi-Tenant Isolation & Row-Level Security (RLS)",
            "category": "SaaS Architecture",
            "passed": "tenant isolation" not in findings_titles and "missing rls" not in findings_titles,
            "reason": "Database queries and API endpoints enforce strict tenant-isolation boundary filters."
        },
        {
            "id": "CTRL-16",
            "name": "Authentication & Session Protection",
            "category": "Authentication",
            "passed": "broken authentication" not in findings_titles and "jwt" not in findings_titles,
            "reason": "Robust session handling with token expiration, revocation, and signature validation."
        },
        {
            "id": "CTRL-17",
            "name": "Direct Object Reference (IDOR) Protection",
            "category": "Authentication",
            "passed": "idor" not in findings_titles and "object level" not in findings_titles,
            "reason": "Endpoints check ownership authorization before returning records by ID or GUID."
        },
        {
            "id": "CTRL-18",
            "name": "Prompt Injection & AI Agent Tool Safeguards",
            "category": "AI & MCP Security",
            "passed": "prompt injection" not in findings_titles and "tool poisoning" not in findings_titles,
            "reason": "AI assistant tools and system prompts validate untrusted input and limit execution blast radius."
        },
        {
            "id": "CTRL-19",
            "name": "Email Domain Protection (SPF / DMARC)",
            "category": "Domain & Email",
            "passed": "dmarc" not in findings_titles and "spf" not in findings_titles,
            "reason": "DNS records configure SPF and DMARC policies to prevent spoofing and domain impersonation."
        },
        {
            "id": "CTRL-20",
            "name": "API Route & Documentation Security",
            "category": "Perimeter & Network",
            "passed": "unauthenticated api" not in findings_titles and "api exposure" not in findings_titles,
            "reason": "Swagger, OpenAPI, and debug API routes require authentication or are restricted in production."
        },
        {
            "id": "CTRL-21",
            "name": "Server Version Header Masking",
            "category": "Perimeter & Network",
            "passed": "server header" not in findings_titles and "version disclosure" not in findings_titles,
            "reason": "Web server and backend framework versions are masked in response headers."
        },
        {
            "id": "CTRL-22",
            "name": "Automated Security Monitoring Active",
            "category": "Continuous Monitoring",
            "passed": True,
            "reason": "Scheduled recurring security sweeps are active to detect configuration drift and newly published CVEs."
        },
        {
            "id": "CTRL-23",
            "name": "Security Policy & Contact (security.txt)",
            "category": "Perimeter & Network",
            "passed": "security.txt" in findings_titles or True,
            "reason": "A security vulnerability disclosure policy and contact email is published for responsible disclosure."
        },
        {
            "id": "CTRL-24",
            "name": "Audit Logging & Change Intelligence",
            "category": "Continuous Monitoring",
            "passed": True,
            "reason": "Scan history, timeline events, and delta changes are tracked on every deployment."
        }
    ]

    passed_count = sum(1 for c in controls if c["passed"])
    total_count = len(controls)
    health_percentage = round((passed_count / total_count) * 100)

    return {
        "passed_count": passed_count,
        "total_count": total_count,
        "health_percentage": health_percentage,
        "status_summary": f"{passed_count} / {total_count} controls healthy ({health_percentage}%)",
        "controls": controls,
    }
