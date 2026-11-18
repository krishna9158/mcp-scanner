# TrustAudit — Final Pre-Launch Security, Compliance & Architecture Audit

**Document Version:** 3.0.0  
**Audit Date:** 19 November 2026  
**Auditor:** Principal SaaS Architect, Senior AppSec & DevSecOps Engineer, GRC Architect  
**Classification:** Internal Pre-Launch Technical Verification & Remediation Dossier  
**Target Platform:** TrustAudit Security & Compliance Platform  
**Live Application URL:** https://mcp-scanner.onrender.com/  
**Trust Centre URL:** https://mcp-scanner.onrender.com/trust  
**Dashboard URL:** https://mcp-scanner.onrender.com/dashboard  

---

## 1. Executive Summary & Audit Methodology

This document establishes the comprehensive pre-launch audit of the TrustAudit platform. In accordance with strict truth-in-advertising and engineering integrity rules:
- **Zero Simulation:** Features are evaluated against actual backend source-code execution, not UI appearance.
- **Evidence-Driven Claims:** All public statements on the website and Trust Centre must map to validated implementations, automated tests, or provider contractual terms.
- **Dual-Perspective Audit:** Identifies working components, partial components, security risks (P0, P1, P2), performance bottlenecks, and required remediation before public enterprise onboarding.

---

## 2. Comprehensive Subsystem & Feature Audit Table

### 2.1 Authentication & Session Management
- **Implementation Location:** `saas_store.py`, `app.py`
- **Actual Functionality:** User registration, email/password login, cryptographic session generation (`secrets.token_urlsafe(32)`), session cookie issuance, session validation, logout token invalidation.
- **Backend Dependencies:** Standard library `secrets`, `hashlib`, `time`, `uuid`.
- **Frontend Dependencies:** Session cookie `trustaudit_session` or `Authorization: Bearer <token>` in header.
- **API Endpoints:** `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`.
- **Database Dependencies:** `saas_data.json` (`users`, `organizations`), `_ACTIVE_SESSIONS` memory store.
- **Test Coverage:** `tests/test_compliance_and_remediation_platform.py::TestPhase11AuthAndSessionSecurity`.
- **Execution Status:** **PARTIAL / NEEDS HARDENING**.
- **Known Limitations:**
  - `_ACTIVE_SESSIONS` is stored exclusively in process memory; server restarts invalidate active user sessions.
  - `validate_session()` contained a demo fallback returning `usr-default` / `org-default` when tokens were absent or invalid.
- **Security Risks:**
  - **P0:** Unauthenticated requests or forged tokens silently mapped to `org-default` admin, violating multi-tenant boundaries.
  - **P1:** Session cookies set without explicit `secure=True` flag in HTTPS production.
  - **P1:** Missing rate limiting on `/api/auth/login` permitting credential brute-forcing.
  - **P1:** Missing password reset workflow (`forgot-password` / `reset-password`).
  - **P2:** Missing Multi-Factor Authentication (MFA / TOTP) for tenant administrators.
- **Required Corrections:**
  1. Remove automatic demo fallback from authenticated API routes; reject invalid/forged tokens with HTTP 401.
  2. Enforce `secure=True`, `httponly=True`, `samesite="Lax"` on session cookies.
  3. Implement sliding-window login rate limiting (max 5 failed attempts per IP/account per minute).
  4. Implement secure time-bounded password reset token workflow (RFC-compliant 1-hour expiration).
  5. Implement standard RFC 6238 TOTP MFA for organization owners and administrators.

---

### 2.2 Password Hashing & OWASP Alignment
- **Implementation Location:** `saas_store.py` (`_hash_password`, `_verify_password`)
- **Actual Functionality:** Salted PBKDF2-HMAC-SHA256 password hashing.
- **Current Parameters:** 100,000 iterations with 16-byte random hex salt.
- **OWASP Guidance Review:** Current OWASP recommendation for PBKDF2-HMAC-SHA256 is 600,000 iterations (or Argon2id where native C-bindings are supported). Argon2id is not in standard library and not installed.
- **Hardware Benchmark:**
  - 100,000 iterations: ~39.85 ms
  - 300,000 iterations: ~113.14 ms
  - 600,000 iterations: ~257.08 ms (ideal target: ~250ms for web login).
- **Execution Status:** **OPERATIONAL BUT SUB-OPTIMAL WORK FACTOR**.
- **Known Limitations:** Hash storage lacks algorithm identifier and iteration metadata prefix, making parameter upgrades difficult without structured versioning. Hardcoded demo passwords present in authentication fallback.
- **Security Risks:**
  - **P1:** 100,000 iterations is below current 2024/2026 OWASP guidance of 600,000 for SHA-256.
  - **P1:** Hardcoded credentials (`trustaudit`, `TrustAudit2026!`, `admin123`) present in `authenticate_user`.
- **Required Corrections:**
  1. Upgrade work factor to 600,000 iterations of PBKDF2-HMAC-SHA256.
  2. Implement backward-compatible migration plan: store algorithm metadata (`pbkdf2_sha256$600000$salt$hash`).
  3. Implement `rehash-on-login`: legacy 100,000 iteration hashes are verified and transparently upgraded to 600,000 iterations upon successful login.
  4. Remove hardcoded demo passwords from production authentication paths.

---

### 2.3 Multi-Tenant Isolation & Role Authorization
- **Implementation Location:** `saas_store.py`, `app.py`, `evidence_vault.py`
- **Actual Functionality:** Organizations are identified by `org-<hex8>` UUIDs. Projects, findings, evidence, and compliance profiles are stored under organization context.
- **Test Coverage:** Automated negative tests in `TestTenantIsolationAndNegativeAccessControl` verify cross-tenant evidence GET, download, DELETE, and project access return HTTP 404.
- **Execution Status:** **VERIFIED BY TEST**.
- **Known Limitations:** Single-file JSON storage (`saas_data.json`) suitable for single-node deployment; requires PostgreSQL row-level security for large-scale enterprise clusters.
- **Security Risks:**
  - **P1:** Need strict server-side authorization check ensuring user's session token strictly matches the target organization ID; never trust client-supplied `org_id` parameters.
- **Required Corrections:**
  1. Audit all 71 API routes: ensure `get_current_tenant_and_user()` validates the session token and rejects unauthorized tenant context.
  2. Maintain automated negative test assertions in CI.

---

### 2.4 Website Security Scanner & SSRF Defenses
- **Implementation Location:** `website_scanner.py`, `connectivity.py`
- **Actual Functionality:** Dual-stack DNS resolution, HTTP/HTTPS connectivity checks, SSL/TLS certificate chain evaluation, security headers inspection (HSTS, CSP, X-Frame-Options, etc.), cookie flags analysis, and privacy indicators detection.
- **Backend Dependencies:** `socket`, `ssl`, `requests`, `urllib.parse`.
- **API Endpoints:** `POST /api/scan/website`, `POST /api/public/quick-check`.
- **Execution Status:** **PARTIAL / CRITICAL SECURITY GAP IN INPUT VALIDATION**.
- **Known Limitations:** Passive checks only by default; active vulnerability probes require authentication.
- **Security Risks:**
  - **P0 CRITICAL SSRF:** `normalize_target_url` in `connectivity.py` did not restrict private IPv4/IPv6 addresses, loopback addresses (`127.0.0.1`), or cloud metadata services (`169.254.169.254`). Unrestricted users could potentially use the scanner to probe local services or cloud infrastructure.
  - **P1:** Redirect chains were followed without re-validating whether intermediate destinations resolved to private IPs (DNS rebinding / redirect SSRF).
- **Required Corrections:**
  1. Build dedicated `ssrf_protection.py` module enforcing:
     - Scheme whitelist (`http`, `https` only; reject `file`, `data`, `ftp`, `gopher`).
     - Port whitelist (80, 443, 8080, 8443).
     - Credentials in URL rejection (`user:pass@host`).
     - Pre-connection DNS resolution of all A and AAAA records.
     - Strict rejection of loopback (`127.0.0.0/8`, `::1`), private RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), multicast, and cloud metadata (`169.254.169.254`, `metadata.google.internal`).
     - Re-validation of destination IP on every HTTP redirect hop.
     - Strict timeout (3.0s connect, 4.0s read) and maximum response size cap (512 KB).

---

### 2.5 Scanner Integrations & Tool Health Management
- **Implementation Location:** `scanner_integrations/` (`tool_health.py`, `orchestrator.py`, `normalizer.py`, `deduplicator.py`, `bandit.py`, `semgrep.py`, `gitleaks.py`, `osv_scanner.py`, `trivy.py`, `nuclei.py`, `syft.py`, `zap.py`)
- **Actual Functionality:** Evaluates available external security scanner CLI binaries, detects versions, executes scanners with strict timeouts, and captures execution telemetry (start time, end time, exit code, duration, stderr, findings count).
- **Local / Worker Tool Statuses:**
  - Semgrep SAST: **OPERATIONAL** (v1.172.0)
  - Nuclei Scanner: **OPERATIONAL** (v3.11.1)
  - OWASP ZAP: **OPERATIONAL** (v2.17.0 Local)
  - Proprietary MCP Engine: **OPERATIONAL** (v2.0 Built-in)
  - Passive Web & TLS Engine: **OPERATIONAL** (v2.0 Built-in)
  - Gitleaks, Bandit, Checkov, OSV-Scanner, Trivy, Syft: **NOT INSTALLED** (gracefully skipped with accurate status recording).
- **Execution Status:** **OPERATIONAL**.
- **Known Limitations:** Render web containers lack root access to install certain Go/binary utilities during standard python runtime unless pre-baked into container or installed in user space.
- **Security Risks:**
  - **P1:** Never display "Passed" or "Successful" for engines that failed, timed out, or are not installed.
- **Required Corrections:**
  1. Scanner health telemetry must display exact tool execution states: `OPERATIONAL`, `NOT INSTALLED`, `FAILED`, `TIMED OUT`.

---

### 2.6 Secret Detection & Preview Redaction Pipeline
- **Implementation Location:** `secret_detector.py`, `universal_validator.py`
- **Actual Functionality:** Regex detection for 50+ secret formats (AWS keys, GitHub tokens, Slack webhooks, Stripe keys, private keys, JWT secrets) combined with Shannon entropy analysis. `redact_secret()` masks tokens to safe previews (e.g. `sk-proj-78...[REDACTED]...9902`).
- **Execution Status:** **VERIFIED BY TEST**.
- **Known Limitations:** Redaction is heuristic pattern masking; extremely novel custom secret formats may evade regex.
- **Security Risks:**
  - **P2:** Marketing promises such as "Zero Secret Leakage Guarantee" or "100% Cryptographically Redacted" were legally and technically unsupportable.
- **Required Corrections:**
  1. Remove absolute guarantees.
  2. Clearly state: "Verified preview masking with Shannon entropy detection and regex sanitization prior to log or finding persistence."

---

### 2.7 AI Security Advisor & AI Remediation Engine
- **Implementation Location:** `ai_analyst.py`, `ai_remediation.py`, `ai_appsec_analyzer.py`
- **Actual Functionality:**
  - `ai_analyst.py`: Deterministic analysis engine calculating risk scores, finding grade distribution, and blast radius.
  - `ai_remediation.py`: Pre-built deterministic playbooks for secrets, dependencies, typosquatting, MCP transports, and prompt injections.
  - `ai_appsec_analyzer.py`: AST and regex pattern analyzer detecting 10 AI-generated code flaw categories.
- **External Network Calls:** **ZERO**. Codebase inspection confirmed that no customer source code, findings, or evidence are sent to OpenAI, Anthropic, Gemini, or any cloud LLM.
- **Execution Status:** **OPERATIONAL (100% LOCAL & DETERMINISTIC)**.
- **Known Limitations:** Anthropic API constants were defined in `ai_remediation.py` header, which could mislead an auditor into thinking external LLM transmission occurs.
- **Security Risks:** None from external leakage, but public copy must be consistent with reality.
- **Required Corrections:**
  1. Remove unused external API constants or clearly mark them as optional experimental extensions.
  2. Explicitly disclose in Trust Centre and Privacy Policy: "TrustAudit does NOT send customer source code or vulnerability findings to third-party AI models. All remediation playbooks and AST analysis are executed locally and deterministically."

---

### 2.8 Compliance Centre & Regulatory Frameworks
- **Implementation Location:** `compliance_frameworks.py`, `compliance_engine.py`
- **Supported Frameworks:**
  1. **India DPDP Act, 2023 & DPDP Rules, 2025**
  2. **AICPA SOC 2 (2017 TSC with 2022 Points of Focus)**
  3. **ISO/IEC 27001:2022 + AMD 1:2024**
  4. **EU GDPR**
- **Statutory DPDP Accuracy:**
  - Section 6(9) & Rule 4 (Consent Managers): Commenced on **13 November 2026**.
  - Substantive Data Fiduciary requirements (Section 5, Section 8(1)-(7), Section 9, Rules 3 & 5–16): Commencing **13 May 2027**.
  - Reasonable Security Safeguards: Mapped to Section 8(5) & Rule 6 (baseline IT Act 43A).
  - Consent Withdrawal Workflow: Mapped to Section 6(4)-(6).
- **Required Disclaimers:**
  - TrustAudit provides automated technical gap analysis and evidence management.
  - Does not issue certified SOC 2 Type II examination reports (requires CPA firm).
  - Does not issue accredited ISO/IEC 27001 certifications (requires accredited certification body).
  - TrustAudit is not a registered statutory Consent Manager.
- **Execution Status:** **VERIFIED BY TEST**.

---

### 2.9 Evidence Vault & File Integrity
- **Implementation Location:** `evidence_vault.py`, `data/evidence_store.json`, `data/evidence_files/`
- **Actual Functionality:** Upload, store, retrieve, and delete compliance evidence files. Computes SHA-256 integrity checksums, validates file MIME types, limits file size to 15 MB, and enforces strict organization-scoped isolation.
- **Execution Status:** **VERIFIED BY TEST**.
- **Known Limitations:** In local deployment, files are stored on local persistent disk; in enterprise cloud, requires S3-compatible private bucket with presigned URLs.

---

### 2.10 Vulnerability Intelligence & CISA KEV Engine
- **Implementation Location:** `vuln_intel_sources.py`, `vuln_intel_store.py`, `vuln_intel_service.py`, `vuln_intel_data.json`
- **Actual Functionality:** Background worker synchronizes the official CISA Known Exploited Vulnerabilities (KEV) catalog on startup and on recurring schedules. Stores 1,782 actively exploited CVEs with title, vendor, product, date added, and required remediation action.
- **API Endpoints:** `GET /api/vuln-intel/status`, `GET /api/public/trust-status`.
- **Execution Status:** **OPERATIONAL**.
- **Known Limitations:** CISA KEV is an intelligence catalog; not every vulnerability in a dependency is necessarily actively exploitable in a specific application context without reachable call paths.

---

### 2.11 Data Retention, Ephemeral Processing & Customer Deletion
- **Implementation Location:** `download_repo.py`, `app.py`, `saas_store.py`
- **Actual Functionality:**
  - **Source Code Lifecycle:** Repositories are cloned to `tempfile.mkdtemp` within sandboxed directory. Upon scan completion, directories are deleted via `shutil.rmtree(temp_dir, ignore_errors=True)`.
  - **Retention Duration:** 0-day disk retention for source code files. Normalized findings metadata and scan metrics are retained in tenant database.
- **Required Customer Deletion Workflow:**
  - Add `POST /api/account/delete` to allow organizations to trigger full account erasure (user records, project metadata, findings history, evidence files, audit trails).
- **Execution Status:** **OPERATIONAL / DELETION WORKFLOW NEEDS FORMAL API**.

---

### 2.12 India Hosting & Subprocessor Assessment
- **Current Production Hosting:** Render.com (AWS US-West / Oregon region or Frankfurt, Germany).
- **Database:** PostgreSQL / Render persistent disk.
- **India Region Architecture Assessment:**
  - AWS Asia Pacific (Mumbai) — `ap-south-1` is technically viable for dedicated enterprise tenant deployments.
  - **Truth-in-Advertising Disclosure:** TrustAudit's shared SaaS platform currently runs on Render (US/EU). India Region must be labeled **"INDIA REGION — PLANNED / ENTERPRISE DEDICATED ONLY"**.
  - **DPDP Section 16 Clarification:** DPDP Act does not prohibit cross-border data transfer unless restricted by Central Government notification.
- **Subprocessors Register:**
  1. Render Services, Inc. (Cloud Compute & Infrastructure) — USA
  2. Neon / AWS RDS (Database Services) — USA
  3. GitHub, Inc. (OAuth & Repository Integration) — USA
- **Threat Intel Sources (NOT Subprocessors):** CISA (USA), OSV / Google, NVD / NIST.

---

### 2.13 Governance, RFC 9116 & Grievance Redressal
- **Public Contacts:**
  - Privacy & Grievance: `grievance@trustaudit.io`
  - Security: `security@trustaudit.io`
- **Role Disclosure:** Designated as "Privacy & Grievance Contact" (not a statutory Data Protection Officer unless appointed under DPDP Section 10).
- **RFC 9116 Security File:** Needs `/.well-known/security.txt` containing contact, canonical URL, encryption, preferred languages, and policy link.
- **Operational Grievance Workflow:** Database store and workflow tracking grievance reference, submission date, status, investigator, resolution notes.

---

## 3. Summary of Security Risks & Prioritization

| ID | Severity | Subsystem | Description | Status |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-P0-01** | **P0 (Critical)** | Website Scanner | Missing SSRF validation allows requests to private IPs, loopback, and cloud metadata (`169.254.169.254`). | **TO REMEDIATE** |
| **SEC-P0-02** | **P0 (Critical)** | Auth & Session | `validate_session()` fallback to `org-default` on invalid/forged tokens allows unauthorized tenant access. | **TO REMEDIATE** |
| **SEC-P1-01** | **P1 (High)** | Password Security | PBKDF2 iteration count is 100,000 instead of current OWASP standard of 600,000. | **TO REMEDIATE** |
| **SEC-P1-02** | **P1 (High)** | Auth & Session | Missing rate limiting on `/api/auth/login`. | **TO REMEDIATE** |
| **SEC-P1-03** | **P1 (High)** | Session Cookies | Cookies set without explicit `secure=True` flag in production HTTPS. | **TO REMEDIATE** |
| **SEC-P1-04** | **P1 (High)** | Auth | Hardcoded backdoor demo passwords in `authenticate_user`. | **TO REMEDIATE** |
| **SEC-P1-05** | **P1 (High)** | Account Security | Missing password reset token generation and reset endpoint. | **TO REMEDIATE** |
| **SEC-P1-06** | **P1 (High)** | GitHub CI/CD | Hardcoded `http://127.0.0.1:5000` curl snippet in dashboard template. | **TO REMEDIATE** |
| **SEC-P2-01** | **P2 (Medium)** | Multi-Factor Auth | Missing TOTP MFA support for organization administrators. | **TO REMEDIATE** |
| **SEC-P2-02** | **P2 (Medium)** | Compliance / Deletion | Missing self-service organization data deletion workflow API. | **TO REMEDIATE** |
| **SEC-P2-03** | **P2 (Medium)** | Governance | Missing `/.well-known/security.txt` conforming to RFC 9116. | **TO REMEDIATE** |
| **SEC-P2-04** | **P2 (Medium)** | Governance | Missing operational grievance redressal ticket tracking workflow. | **TO REMEDIATE** |

---

## 4. Conclusion & Action Plan

All 12 identified items must be systematically addressed, tested, and validated with zero regressions before public pre-launch release.
