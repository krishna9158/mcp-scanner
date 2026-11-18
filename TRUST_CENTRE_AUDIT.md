# TrustAudit Trust Centre Implementation & Claims Audit
**Date:** November 18, 2026  
**Audited Target:** `/trust` (TrustAudit Public Security & Compliance Portal)  
**Auditor:** Senior Cybersecurity Architect, AppSec Engineer, GRC & Privacy Specialist  

---

### Executive Audit Summary

A comprehensive line-by-line inspection of the public `/trust` page, backend APIs, data stores, scanner orchestrators, and framework engines was conducted. The audit revealed multiple legal inaccuracies in statutory citations, inaccurate control descriptions for SOC 2 and ISO 27001, unsupported absolute marketing claims regarding secret leakage and tenant isolation, and a misconception of CISA KEV as containing exclusively "zero-day" vulnerabilities.

This document records each public claim, its technical and legal verification verdict, code citations, and required remediations.

---

### Detailed Findings & Claims Matrix

| # | Public Claim on `/trust` | Verdict | Implementation Reality & Legal Analysis | Source Code Location |
|---|---|---|---|---|
| **1** | **DPDP Reasonable Security Safeguards under Section 8(1)** | **Legally Inaccurate** | Under the **Digital Personal Data Protection Act, 2023**, Section 8(1) is the *general responsibility* of the Data Fiduciary to comply with the Act. Reasonable security safeguards to prevent personal data breach are prescribed under **Section 8(5)** read with **Rule 6 of the DPDP Rules, 2025**. Technical and organizational measures are under **Section 8(4)**. Personal data breach notification is **Section 8(6)** read with **Rule 7**. | `compliance_frameworks.py:128-154`, `app.py:1807-1810`, `remediation_centre.py:85` |
| **2** | **DPDP Legal Commencement Timeline** | **Legally Inaccurate / Incomplete** | The page claimed general "Phased Commencement Preparedness" without distinguishing enacted from future dates. As of **18 November 2026**: Section 6(9) and Rule 4 (Consent Managers) commenced on **13 November 2026**. Substantive Data Fiduciary provisions and Rules 3, 5–16 are scheduled to commence on **13 May 2027**. TrustAudit must clarify it is *not* a registered statutory Consent Manager. | `compliance_frameworks.py:27-36`, `app.py:1809` |
| **3** | **SOC 2 CC7.1 Described as "Patch SLAs"** | **Technically Inaccurate** | In the **AICPA Trust Services Criteria (2017 with 2022 Points of Focus)**, CC7.1 is officially: *"The entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities."* Describing CC7.1 as simply "Patch SLAs" oversimplifies the criterion. | `compliance_frameworks.py:342-367`, `app.py:1815` |
| **4** | **SOC 2 CC6.1, CC6.6, CC6.8 Control Titles** | **Technically Inaccurate** | CC6.1 is *"Logical access security"*; CC6.6 is *"Protection against threats originating outside system boundaries"*; CC6.8 is *"Prevention, detection and remediation of unauthorised or malicious software"*. The Trust Centre used loose colloquial descriptions. | `compliance_frameworks.py:262-340`, `app.py:1814-1817` |
| **5** | **ISO/IEC 27001:2022 Control Mappings (A.8.28)** | **Technically Inaccurate** | The page described A.8.28 as *"secure development life cycle controls"*. In **ISO/IEC 27001:2022**, Control **A.8.28 is Secure Coding**. Control **A.8.25 is Secure Development Life Cycle**. Describing A.8.28 as SDLC is incorrect. Control A.8.25 was also missing from the framework database. | `compliance_frameworks.py:477-501`, `app.py:1821-1823` |
| **6** | **"Zero Secret Leakage Guarantee" / "100% Cryptographically Redacted"** | **Legally & Technically Inaccurate** | Absolute statements create strict legal warranties. In `secret_detector.py:254`, `redact_secret` masks middle characters (`prefix...[REDACTED]...suffix`), which is preview masking, not 100% cryptographic hashing (like SHA-256). Furthermore, raw Gitleaks outputs in `gitleaks.py` temporarily held raw secret strings in internal dicts. | `secret_detector.py:244-257`, `scanner_integrations/gitleaks.py:128`, `app.py:1828-1831` |
| **7** | **"Zero cross-customer data leakage" / Multi-Tenant Isolation** | **Unsupported Absolute Claim** | While `saas_store.py` and `evidence_vault.py` partition data by `org_id`, an organization ID alone is an identifier, not a cryptographic boundary. Data access must be bound to authenticated server-side sessions. Absolute zero-leakage claims must be removed and replaced with verified architectural controls. | `saas_store.py:197-202`, `evidence_vault.py:45-53`, `app.py:1835-1838` |
| **8** | **CISA KEV Exclusively "Zero-Day" Vulnerabilities** | **Technically Inaccurate** | The CISA Known Exploited Vulnerabilities catalog lists known vulnerabilities that have been exploited in the wild, regardless of whether a patch exists. Most entries have known CVEs and existing remediation instructions, so describing KEV as exclusively "zero-days" is factually incorrect. | `app.py:1843-1845`, `correlation_engine.py:143-185`, `vuln_intel_sources.py:252-296` |
| **9** | **CISA KEV Sync Hardcoded Status** | **Partially Implemented** | The page statically rendered "Status: Live Automated Sync Active" without querying the live synchronization metadata from `vuln_intel_sources.get_cisa_kev_stats()` or `vuln_intel_store.py`. | `app.py:1844`, `vuln_intel_sources.py:311-318` |
| **10** | **Customer Data Transparency & Subprocessors** | **Not Implemented** | The Trust Centre did not provide required disclosures on processed customer data, repository handling (transient cloning vs persistent finding metadata), subprocessors, AI processing, hosting regions, retention schedules, or deletion procedures. | Missing from `/trust` |
| **11** | **Customer Scanning Authorization** | **Not Implemented** | The page did not clearly explain what permissions GitHub App / PAT requires, the scope of passive vs active scanning, or require explicit authorization for active network probes. | Missing from `/trust` |
| **12** | **Security Posture & Independent Certification Disclaimers** | **Partially Implemented** | The footer disclaimer existed, but explicit clarity on internal controls (encryption in transit TLS 1.3/1.2, encryption at rest on hosting provider, MFA roadmap status, vulnerability disclosure contact `security@trustaudit.io`) was absent. | `app.py:1849-1851` |

---

### Required Remediations

1. **Update Statutory References in `compliance_frameworks.py`, `remediation_centre.py`, and `app.py`:**
   - Map reasonable security safeguards to **Section 8(5)** and **Rule 6 (DPDP Rules 2025)**.
   - Map technical and organizational measures to **Section 8(4)**.
   - Map general Data Fiduciary compliance responsibility to **Section 8(1)**.
   - Map breach notification to **Section 8(6)** and **Rule 7**.
   - Map notice requirements to **Section 5** and **Rule 3**.
   - Map child data to **Section 9** and applicable Rules.
   - Implement the legal timeline: Section 6(9) and Rule 4 (Consent Managers) commenced on **13 November 2026**; substantive Data Fiduciary provisions & Rules 3, 5–16 scheduled for **13 May 2027**.
   - Disclaim statutory Consent Manager registration.

2. **Standardize SOC 2 Framework Controls:**
   - CC6.1: Logical access security.
   - CC6.6: Protection against threats originating outside system boundaries.
   - CC6.8: Prevention, detection and remediation of unauthorised or malicious software.
   - CC7.1: Monitoring of configuration changes and susceptibility to newly discovered vulnerabilities.
   - Present as readiness & evidence management based on AICPA 2017 TSC with 2022 points of focus.

3. **Standardize ISO/IEC 27001:2022 Controls:**
   - A.8.8: Management of technical vulnerabilities.
   - A.8.20: Networks security.
   - A.8.24: Use of cryptography.
   - A.8.25: Secure development life cycle (add to database).
   - A.8.28: Secure coding (correct title and description).
   - Reference ISO/IEC 27001:2022 including AMD 1:2024 (Climate action).

4. **Correct CISA KEV Intelligence:**
   - Accurate wording: *"TrustAudit enriches identified software vulnerabilities with entries from CISA's Known Exploited Vulnerabilities catalogue, helping organisations prioritise vulnerabilities known to have been exploited in the wild."*
   - Query live sync telemetry: records count, last successful sync timestamp, sync health status, and data source URL.

5. **Sanitize Secret Handling & Claims:**
   - Sanitize `raw_findings` in `gitleaks.py` so raw secrets are not retained in memory.
   - Remove "Zero Secret Leakage Guarantee" and "100% Cryptographically Redacted".
   - Use verified technical descriptions of regex/entropy masking and preview redaction.

6. **Verify Multi-Tenant Isolation with Automated Negative Tests:**
   - Write automated negative test cases asserting that Tenant A cannot access Tenant B's projects, evidence items, files, or remediation tasks.
   - Ensure server-side session token validation guards tenant access.

7. **Add Comprehensive Trust Centre Sections:**
   - Customer Data Transparency (10 transparency disclosures).
   - Scanning Authorization & Scope (GitHub permissions, passive vs active testing).
   - Platform Security & Trust Information (encryption, auth, MFA roadmap, logging, vulnerability disclosure, incident response).
   - Professional SaaS UI with transparent status badges (`Verified`, `Operational`, `Customer-provided evidence`, `Self-attested`, `Pending verification`, `Not implemented`).
