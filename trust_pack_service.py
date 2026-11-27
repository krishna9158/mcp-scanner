"""
TrustAudit Enterprise Trust Pack Generation Service.

Generates approved, versioned, transparent security and compliance documentation
bundles for customer vendor assessments and compliance reviews.
"""

import io
import json
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple

DOCUMENT_METADATA = {
    "version": "2.4.0",
    "last_reviewed": "18 November 2026",
    "classification": "Public / Customer Assessment Document",
    "disclaimer": (
        "This document contains TrustAudit technical security disclosures, control mappings, "
        "and architectural documentation. It does not constitute formal legal counsel, an issued "
        "SOC 2 examination report by a CPA firm, or accredited ISO 27001 certification. "
        "Statutory compliance remains the legal responsibility of the customer organization."
    )
}

APPROVED_DOCUMENTS = {
    "overview": {
        "id": "overview",
        "title": "TrustAudit Security Overview & Posture Statement",
        "filename": "01_TrustAudit_Security_Overview.md",
        "description": "Executive overview of TrustAudit security philosophy, threat modeling, and posture."
    },
    "dpdp": {
        "id": "dpdp",
        "title": "DPDP Act 2023 & DPDP Rules 2025 Readiness Mapping",
        "filename": "02_DPDP_2023_Readiness_Mapping.md",
        "description": "Statutory mapping to India's DPDP Act 2023 & Rules 2025 with commencement timeline."
    },
    "soc2": {
        "id": "soc2",
        "title": "SOC 2 Trust Services Criteria Control Mapping (2017 TSC / 2022 Focus)",
        "filename": "03_SOC2_Control_Mapping.md",
        "description": "Technical mapping across CC6.1, CC6.6, CC6.8, CC7.1, and CC8.1."
    },
    "iso27001": {
        "id": "iso27001",
        "title": "ISO/IEC 27001:2022 Technical Controls Mapping",
        "filename": "04_ISO27001_Control_Mapping.md",
        "description": "Annex A technological controls mapping (A.8.8, A.8.20, A.8.24, A.8.25, A.8.28)."
    },
    "retention": {
        "id": "retention",
        "title": "Data Processing & Retention Schedule",
        "filename": "05_Data_Processing_and_Retention_Summary.md",
        "description": "Detailed disclosures on data processing, ephemeral repository clones, and retention limits."
    },
    "subprocessors": {
        "id": "subprocessors",
        "title": "Official Third-Party Subprocessor Register",
        "filename": "06_Subprocessor_List.md",
        "description": "Complete list of infrastructure providers, processing locations, and purposes."
    },
    "disclosure": {
        "id": "disclosure",
        "title": "Coordinated Vulnerability Disclosure & Safe Harbor Policy",
        "filename": "07_Vulnerability_Disclosure_Policy.md",
        "description": "Guidelines for security researchers, reporting instructions, and 24-hour response SLA."
    },
    "architecture": {
        "id": "architecture",
        "title": "Technical Security Architecture & Isolation Model",
        "filename": "08_Security_Architecture_Overview.md",
        "description": "Deep-dive into multi-tenant partitioning, secret masking, and AST static analysis."
    }
}


def generate_document_content(doc_id: str) -> str:
    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    meta_header = f"""# {APPROVED_DOCUMENTS[doc_id]['title']}
**Document Version:** {DOCUMENT_METADATA['version']}  
**Classification:** {DOCUMENT_METADATA['classification']}  
**Generated On:** {now_str}  
**Last Reviewed:** {DOCUMENT_METADATA['last_reviewed']}  

> **Notice & Disclaimer:** {DOCUMENT_METADATA['disclaimer']}

---
"""

    if doc_id == "overview":
        return meta_header + """
## 1. Platform Purpose & Security Principles
TrustAudit is a continuous application security and compliance management platform engineered for startups, high-growth SaaS businesses, and regulated technology enterprises. 

Our core architectural commitments:
1. **Zero False Execution Reporting:** Scanner engines are monitored for health; tools missing from the runtime environment are explicitly marked as UNAVAILABLE and never reported as clean scans.
2. **Deterministic Evidence Mappings:** Automated technical checks are mapped to specific technological controls, never conflated with full organizational compliance.
3. **Ephemeral Code Processing:** Scanned source code repositories are cloned into isolated temporary directories and deleted immediately post-analysis. Full codebases are never permanently stored.
4. **Verified Tenant Isolation:** Multi-tenant boundaries are enforced on the server side with session token authorization and verified through automated negative penetration tests.

---
## 2. Platform Architecture Summary
- **Compute Layer:** Sandboxed AST parsing, Semgrep semantic analysis, and deterministic heuristic vulnerability scanners.
- **Data Stores:** Tenant-partitioned JSON stores with atomic writes; Evidence Vault uploads are validated by extension, size (5 MB), and magic bytes, fingerprinted with SHA-256 upon ingestion, and optionally encrypted using Fernet (`TRUSTAUDIT_DATA_KEY`) on top of Render-managed persistent disk storage.
- **Authentication & Sessions:** PBKDF2-HMAC-SHA256 password hashing with 600,000 iterations (OWASP work factor with automatic legacy rehash-on-login), 16-byte per-user salts, SHA-256 hashed persistent session tokens in HttpOnly SameSite cookies, and optional RFC 6238 TOTP MFA.
"""

    elif doc_id == "dpdp":
        return meta_header + """
## India's Digital Personal Data Protection Act, 2023 & DPDP Rules, 2025

### Statutory Commencement Timeline (as of 18 November 2026)
- **Already in force:** Section 6(9) and Rule 4 concerning the registration and operation of Consent Managers commenced on **13 November 2026**.
- **Scheduled commencement:** Substantive Data Fiduciary obligations (including Sections 5, 8, 9, 10) and Rules 3, 5–16 are scheduled to commence on **13 May 2027**.
- **Statutory Notice:** TrustAudit is a security and compliance evaluation platform and is *not* a registered statutory Consent Manager under Section 6(9). Future statutory requirements are evaluated for readiness and never represented as existing legal violations.

### Control Mappings & Technical Coverage
1. **Section 5 & Rule 3 (Notice Requirements):**
   - *Requirement:* Itemized notice before requesting consent, specifying data categories, purpose, rights withdrawal, and grievance officer details.
   - *TrustAudit Checks:* Passive website inspection for cookie consent banners, privacy policy links, and header configurations.
   - *Status:* Readiness assessment.
2. **Section 6(9) & Rule 4 (Consent Manager Integration):**
   - *Requirement:* Interoperability readiness to interface with registered Consent Managers.
   - *Status:* Already in force (13 Nov 2026).
3. **Section 8(1) (General Fiduciary Responsibility):**
   - *Requirement:* General Data Fiduciary accountability for all processing undertaken by it or on its behalf.
   - *Status:* Readiness assessment.
4. **Section 8(4) (Technical & Organisational Measures):**
   - *Requirement:* Implementation of appropriate technical and organizational measures to ensure effective observance.
   - *TrustAudit Checks:* Continuous CI/CD security quality gates, dependency vulnerability tracking, and role-based access validation.
   - *Status:* Readiness assessment.
5. **Section 8(5) & Rule 6 (Reasonable Security Safeguards):**
   - *Requirement:* Mandatory technical safeguards to prevent personal data breach.
   - *TrustAudit Checks:* Hardcoded credential scanning, TLS 1.3/1.2 transit encryption checks, and OWASP Top 10 SAST.
   - *Status:* Readiness assessment (IT Act 43A baseline currently in force).
6. **Section 8(6) & Rule 7 (Intimation of Personal Data Breach):**
   - *Requirement:* Mandatory notification to the Data Protection Board of India and affected Data Principals upon personal data breach.
   - *TrustAudit Checks:* Incident response policy evidence tracking and credential exposure alerting.
   - *Status:* Readiness assessment.
7. **Section 9(1) & Rules (Children & Persons with Lawful Guardians):**
   - *Requirement:* Verifiable consent of the parent or lawful guardian before processing personal data of children (<18) or persons with disabilities who have lawful guardians (clarified by S.O. 5458(E)); strict prohibition on behavioral profiling and targeted ads directed at children.
   - *Status:* Readiness assessment (Exempt/Not applicable for B2B API software).
8. **Section 10 (Significant Data Fiduciary Obligations):**
   - *Requirement:* India-based DPO, statutory data auditor, and periodic DPIA upon government designation.
   - *Status:* Requires legal review.
"""

    elif doc_id == "soc2":
        return meta_header + """
## SOC 2 Trust Services Criteria Control Mapping (AICPA 2017 TSC with 2022 Focus)

> **Auditing Disclaimer:** TrustAudit tracks control readiness and automated evidence collection for selected technical criteria. Automated technical mappings do not constitute complete SOC 2 coverage, an issued SOC 2 examination report, or CPA attestation. Formal SOC 2 Type 1 and Type 2 reports require an independent examination by a licensed CPA firm.

### Selected Technical Criteria Mappings
1. **CC6.1 (Logical Access Security):**
   - *AICPA Focus:* The entity implements logical access security software, infrastructure, and architectures over protected information assets.
   - *TrustAudit Technical Verification:* Continuous secret detection across git repositories, flagging hardcoded API keys and tokens before production deployment.
   - *Status:* Verified by Automated Tests.
2. **CC6.6 (Protection Against Threats Originating Outside System Boundaries):**
   - *AICPA Focus:* Boundary protection against network-based attacks and unauthorized remote intrusion.
   - *TrustAudit Technical Verification:* Verification of TLS encryption (1.2/1.3), modern security headers (HSTS, CSP, X-Frame-Options), and exposure detection.
   - *Status:* Verified by Automated Tests.
3. **CC6.8 (Prevention, Detection, and Remediation of Malicious Software):**
   - *AICPA Focus:* Controls to prevent or detect the introduction of unauthorized software or malicious code.
   - *TrustAudit Technical Verification:* AST-level MCP tool capability boundary auditing, prompt injection pattern detection, and typosquatting defense.
   - *Status:* Verified by Automated Tests.
4. **CC7.1 (Monitoring Configuration Changes & Vulnerability Susceptibility):**
   - *AICPA Focus:* Ongoing detection procedures to identify configuration changes introducing vulnerabilities and monitor susceptibility to newly discovered vulnerabilities.
   - *TrustAudit Technical Verification:* Continuous integration with CISA Known Exploited Vulnerabilities (KEV) catalog and OSV.dev vulnerability databases.
   - *Status:* Verified by Automated Tests.
5. **CC8.1 (Authorized Change Management & CI/CD Security):**
   - *AICPA Focus:* Authorization, testing, approval, and documentation of software changes prior to deployment.
   - *TrustAudit Technical Verification:* Automated PR scanning via `ci_scan.py` and GitHub Actions quality gates.
   - *Status:* Customer-Provided Evidence Required.
"""

    elif doc_id == "iso27001":
        return meta_header + """
## ISO/IEC 27001:2022 Annex A Control Mapping (including AMD 1:2024 Climate action)

> **Certification Disclaimer:** Automated technical testing covers selected technological controls in Annex A. It does not establish full ISMS conformity or accredited ISO 27001 certification, which requires formal Stage 1 & Stage 2 audits by an accredited Certification Body.

### Annex A Technological Controls
1. **Control A.8.8 (Management of Technical Vulnerabilities):**
   - *Official Scope:* Obtaining information on technical vulnerabilities, evaluating exposure, and taking appropriate remedial measures.
   - *TrustAudit Implementation:* Static code analysis (Semgrep / AST), dependency vulnerability scanning, and SLA-based remediation tracking.
2. **Control A.8.20 (Networks Security):**
   - *Official Scope:* Securing, managing, and controlling network devices, traffic, and boundaries.
   - *TrustAudit Implementation:* Web perimeter analysis, CORS misconfiguration detection, and exposed administrative interface discovery.
3. **Control A.8.24 (Use of Cryptography):**
   - *Official Scope:* Rules for the effective use of cryptography and cryptographic key management.
   - *TrustAudit Implementation:* Verification of cipher suite strengths, TLS protocols, and detection of exposed cryptographic private keys in code.
4. **Control A.8.25 (Secure Development Life Cycle):**
   - *Official Scope:* Establishing and applying rules for secure development of software and systems.
   - *TrustAudit Implementation:* Automated security quality gates embedded in pull requests and CI/CD pipelines.
5. **Control A.8.28 (Secure Coding):**
   - *Official Scope:* Applying secure coding principles to software development to prevent design and implementation defects.
   - *TrustAudit Implementation:* AST and pattern-based SAST detecting SQL injection, command execution, path traversal, and prompt injection vulnerabilities.
"""

    elif doc_id == "retention":
        return meta_header + """
## Data Processing, Classification & Retention Schedule

TrustAudit operates under a strict principle of data minimization:

| Data Category | Specific Data Elements | Processing Purpose | Storage Mechanism | Retention Period | Deletion Procedure |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Customer Source Code** | Cloned git repository source files | Static AST & SAST security scanning | Ephemeral sandboxed temp directory | **0 Days** (Immediately wiped upon scan completion) | Automated `shutil.rmtree` upon scanner worker completion |
| **Vulnerability Findings** | CWE IDs, severity, masked code previews, file paths & line numbers | Security posture reporting & historical drift tracking | Tenant-partitioned database | **12 Months** | Customer self-deletion via console or account closure |
| **User Registration Data** | Name, work email, organization, country, password hash | Account authentication & access control | Encrypted database volume (PBKDF2-HMAC-SHA256) | Active subscription duration | Purged within 30 days of account termination |
| **Evidence Vault Files** | Uploaded audit screenshots, PDF policies, configuration exports | Compliance audit evidence management | Tenant-isolated storage volume (SHA-256 hashed) | Until deleted by customer | Self-service deletion via API / Console; purged upon tenant closure |
| **Security Audit Logs** | Timestamps, user IDs, IP addresses, scan trigger events | Security monitoring & access traceability | Append-only structured JSON log | **90 Days** | Automated log rotation & purging |
| **Threat Feeds Cache** | Public CVEs, CISA KEV entries, OSV advisories | Vulnerability correlation | Local memory cache & JSON store | Ingested continuously from public APIs | Refreshed hourly; stale entries overwritten |
"""

    elif doc_id == "subprocessors":
        return meta_header + """
## Official Third-Party Subprocessor Register

TrustAudit engages a minimal set of vetted, SOC 2 and ISO 27001-certified infrastructure subprocessors to provide our service:

| Provider Name | Corporate Entity | Service Provided | Processing Location | Security & Privacy Certifications |
| :--- | :--- | :--- | :--- | :--- |
| **Render** | Render Services, Inc. | Application compute, container runtime, and volume storage | United States (Oregon / Ohio / Virginia) | SOC 2 Type II, ISO 27001, GDPR DPA |
| **Amazon Web Services (AWS)** | Amazon Web Services, Inc. | Underlying cloud infrastructure and hypervisor storage | United States regions | SOC 1/2/3, ISO/IEC 27001, FedRAMP, HIPAA |
| **CISA (U.S. DHS)** | Cybersecurity & Infrastructure Security Agency | Public Known Exploited Vulnerabilities catalog (Feed only; no customer data sent) | United States (Public API) | U.S. Federal Government Open Data |
| **NIST NVD** | National Institute of Standards and Technology | National Vulnerability Database API 2.0 (Feed only; no customer data sent) | United States (Public API) | U.S. Department of Commerce Open Data |
| **Google Open Source (OSV)** | Google LLC | OSV.dev package vulnerability intelligence (Feed only; no customer data sent) | United States (Public API) | Public Open-Source Vulnerability Database |

> **AI Processing Transparency:** Core website scanning and grounded guidance run on server CPU using verified DPDP rules. When optional Google Gemini API enhancement is enabled (`GEMINI_API_KEY`), questions are stripped of personal email, phone, and tax/ID strings prior to calling Gemini, while uploaded Evidence Vault files and Customer Data Lists remain stored locally on TrustAudit.
"""

    elif doc_id == "disclosure":
        return meta_header + """
## Coordinated Vulnerability Disclosure & Safe Harbor Policy

### 1. Our Commitment
TrustAudit takes the security of our platform and customer data seriously. We value the contributions of the cybersecurity research community and encourage responsible, coordinated vulnerability reporting.

### 2. How to Report a Vulnerability
If you believe you have discovered a security vulnerability in the TrustAudit platform or APIs, please email:
**`security@trustaudit.io`**

Please include:
- A detailed description of the vulnerability and attack vector.
- Step-by-step reproduction instructions or a minimal proof-of-concept (PoC).
- Potential business and technical impact.
- Your contact information for coordination and attribution.

### 3. Response SLAs
- **Initial Acknowledgment:** Within **24 business hours**.
- **Triage & Severity Assessment:** Within **3 business days**.
- **Remediation SLA:** 
  - Critical Severity: Within **7 calendar days**.
  - High Severity: Within **14 calendar days**.
  - Medium/Low: Within **30 calendar days**.

### 4. Safe Harbor Guarantee
TrustAudit will *not* pursue legal action against security researchers who:
- Conduct testing in good faith without intent to compromise or disrupt service.
- Avoid accessing, modifying, or downloading real customer data.
- Avoid executing Denial of Service (DoS/DDoS) attacks.
- Provide reasonable time for remediation prior to any public disclosure.
"""

    elif doc_id == "architecture":
        return meta_header + """
## Technical Security Architecture & Tenant Isolation Model

### 1. Multi-Tenant Partitioning
TrustAudit enforces multi-tenancy at every architectural layer:
- **Tenant Context Extraction:** Every incoming API request is evaluated by `get_current_tenant_and_user()`, extracting the verified organization identifier (`org_id`) from cryptographic session tokens.
- **Database Partitioning:** All data queries (`saas_store.py`) strictly filter projects, timelines, and findings by `org_id`.
- **Evidence Storage Isolation:** Uploaded documents are stored in dedicated tenant directories (`data/evidence_vault/<org_id>/`), isolated from other tenants with path traversal protections.
- **Negative Test Verification:** The test suite `TestTenantIsolationAndNegativeAccessControl` programmatically tests cross-tenant access attempts and confirms that unauthorized requests receive HTTP 404.

### 2. Secret Redaction Pipeline
When scanning source code, credential patterns are processed through `redact_secret()`:
- Strings matching known API key signatures or high Shannon entropy thresholds are masked to safe preview strings (e.g. `sk-t...[REDACTED]...6789`).
- Gitleaks CLI integrations sanitize raw finding outputs prior to memory persistence.
- Masked previews prevent credential leakage across scan logs, database records, and web user interfaces.

### 3. Ephemeral Sandbox Lifecycle
```
[GitHub Repo] -> [Clone to Sandboxed Temp Dir] -> [Run AST/SAST Analyzers]
                                                             |
[Directory Deleted via shutil.rmtree] <- [Normalize Findings]
```
- Temporary directories created using `tempfile.mkdtemp`.
- Upon scan completion, temporary working directories are wiped using `shutil.rmtree(temp_dir, ignore_errors=True)`.
- Verified 0-day disk retention for scanned source code.
"""

    return meta_header + "\n## Content\nApproved documentation for TrustAudit compliance evaluation."


def build_trust_pack_zip(selected_doc_ids: Optional[List[str]] = None) -> bytes:
    """Builds an in-memory zip archive containing the selected approved Trust Pack documents."""
    if not selected_doc_ids:
        selected_doc_ids = list(APPROVED_DOCUMENTS.keys())

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Include manifest
        manifest = {
            "title": "TrustAudit Enterprise Trust Pack",
            "version": DOCUMENT_METADATA["version"],
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "included_documents": [APPROVED_DOCUMENTS[d]["title"] for d in selected_doc_ids if d in APPROVED_DOCUMENTS],
            "disclaimer": DOCUMENT_METADATA["disclaimer"]
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        for doc_id in selected_doc_ids:
            if doc_id in APPROVED_DOCUMENTS:
                doc_info = APPROVED_DOCUMENTS[doc_id]
                content = generate_document_content(doc_id)
                zf.writestr(doc_info["filename"], content)

    return buf.getvalue()


def build_trust_pack_consolidated_markdown(selected_doc_ids: Optional[List[str]] = None) -> str:
    """Builds a single consolidated Markdown/text document containing all selected documents."""
    if not selected_doc_ids:
        selected_doc_ids = list(APPROVED_DOCUMENTS.keys())

    parts = [
        f"# TrustAudit Enterprise Trust Pack Bundle (v{DOCUMENT_METADATA['version']})",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"> **Notice:** {DOCUMENT_METADATA['disclaimer']}",
        "\n===============================================================================\n"
    ]

    for doc_id in selected_doc_ids:
        if doc_id in APPROVED_DOCUMENTS:
            parts.append(generate_document_content(doc_id))
            parts.append("\n\n---\n\n")

    return "\n".join(parts)
