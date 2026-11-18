"""
TrustAudit Comprehensive Compliance Frameworks & GRC Intelligence Engine.

Covers:
1. India's Digital Personal Data Protection (DPDP) Act 2023 & Rules
2. SOC 2 Trust Services Criteria (Readiness & Evidence Management)
3. ISO/IEC 27001:2022 Information Security Management
4. General Data Protection Regulation (GDPR)

IMPORTANT LEGAL & ARCHITECTURAL PRINCIPLES:
- Never claim guaranteed legal compliance or formal certification.
- Distinguish DPDP provisions currently enacted from rules pending commencement.
- SOC 2 is presented strictly as readiness and evidence management, not an issued SOC 2 report.
- ISO 27001 assesses implementation posture without asserting conformity.
- Missing evidence documents are classified as evidence gaps, never automatically marked as legal violations.
"""

import time
from typing import Any, Dict, List, Optional


# ==============================================================================
# 1. STRUCTURED FRAMEWORK DATABASE
# ==============================================================================

FRAMEWORK_METADATA = {
    "DPDP": {
        "name": "Digital Personal Data Protection Act, 2023 & DPDP Rules, 2025 (India)",
        "short_name": "DPDP Act 2023 & Rules 2025",
        "jurisdiction": "India",
        "authority": "Data Protection Board of India (DPBI) / Ministry of Electronics and Information Technology (MeitY)",
        "version": "DPDP Act, 2023 (Act No. 22 of 2023) & DPDP Rules, 2025",
        "status": "Phased Statutory Commencement",
        "description": "Comprehensive statutory framework governing the processing of digital personal data in India. Establishes legal accountability for Data Fiduciaries, statutory safeguards, breach notification, and Data Principal rights.",
        "disclaimer": "TrustAudit provides automated technical gap analysis, evidence tracking, and readiness evaluation. It does not replace formal legal counsel or statutory audit by DPBI. TrustAudit is not a registered statutory Consent Manager under Section 6(9).",
        "commencement_timeline": {
            "consent_managers_in_force": "Section 6(9) & Rule 4 (Registration and operation of Consent Managers) commenced on 13 November 2026.",
            "substantive_fiduciary_scheduled": "Substantive Data Fiduciary obligations (including Sections 5, 8, 9, 10) and Rules 3, 5–16 are scheduled to commence on 13 May 2027.",
            "status_distinction": "Delineates controls as: Already in force, Scheduled to commence, Readiness assessment, Not applicable, or Requires legal review. Future statutory requirements are assessed for preparedness and never represented as existing legal violations."
        }
    },
    "SOC2": {
        "name": "SOC 2 Trust Services Criteria",
        "short_name": "SOC 2 (Readiness & Evidence Management)",
        "jurisdiction": "Global / North America (AICPA)",
        "authority": "American Institute of Certified Public Accountants (AICPA)",
        "version": "2017 TSC with 2022 Points of Focus (Published Criteria)",
        "status": "Active Auditing Criteria",
        "description": "AICPA Trust Services Criteria ensuring service organizations establish rigorous technical and operational controls across Security, Availability, Processing Integrity, Confidentiality, and Privacy.",
        "disclaimer": "SOC 2 tracking in TrustAudit represents readiness evaluation and evidence management. Automated mappings cover selected technical criteria and do not constitute complete SOC 2 coverage, an issued SOC 2 examination report, or CPA attestation."
    },
    "ISO27001": {
        "name": "ISO/IEC 27001:2022 (including AMD 1:2024 Climate action)",
        "short_name": "ISO/IEC 27001:2022",
        "jurisdiction": "International",
        "authority": "International Organization for Standardization (ISO) / International Electrotechnical Commission (IEC)",
        "version": "ISO/IEC 27001:2022 + AMD 1:2024",
        "status": "Active International Standard",
        "description": "Global Information Security Management System (ISMS) standard prescribing organizational, people, physical, and technological security controls.",
        "disclaimer": "TrustAudit evaluates technical control posture across selected Annex A controls. Automated technical scans do not establish full ISMS conformity or accredited ISO 27001 certification, which requires accredited third-party certification body audits."
    },
    "GDPR": {
        "name": "General Data Protection Regulation (Regulation (EU) 2016/679)",
        "short_name": "EU GDPR",
        "jurisdiction": "European Union / EEA",
        "authority": "European Data Protection Board (EDPB) & National Data Protection Authorities",
        "version": "Regulation (EU) 2016/679",
        "status": "Fully Enacted & Enforceable",
        "description": "Regulation protecting fundamental rights and freedoms of natural persons regarding the processing of personal data and free movement of such data.",
        "disclaimer": "TrustAudit provides automated technical control checks and record-keeping tools. Statutory compliance remains the legal responsibility of the Data Controller."
    }
}


CONTROLS_DATABASE: Dict[str, List[Dict[str, Any]]] = {
    # --------------------------------------------------------------------------
    # INDIA DPDP ACT 2023 & DPDP RULES 2025
    # --------------------------------------------------------------------------
    "DPDP": [
        {
            "control_id": "DPDP-SEC-05",
            "section": "Section 5 & Rule 3",
            "title": "Notice-Related Requirements for Data Processing",
            "official_ref": "DPDP Act 2023, Section 5 read with DPDP Rules 2025, Rule 3",
            "description": "Every request for consent must be accompanied or preceded by an itemised notice informing the Data Principal of the personal data to be processed, specified purpose, manner of exercising rights, and grievance redressal mechanism.",
            "applicability": "Applies to all Data Fiduciaries processing personal data under consent.",
            "enforcement_phase": "SCHEDULED_TO_COMMENCE",
            "effective_date": "13 May 2027 (Scheduled commencement)",
            "status_display": "Readiness assessment",
            "category": "Consent & Transparency",
            "assessment_questions": [
                "Does your website or application present an itemized notice before capturing user personal data?",
                "Is the notice accessible in English and any of the 22 languages specified in the Eighth Schedule to the Constitution of India?",
                "Does the notice explicitly explain how users can withdraw consent or raise a grievance?"
            ],
            "evidence_requirements": [
                "Screenshot / URL of current Privacy Notice and Consent banner.",
                "Copy of multilingual consent notice texts.",
                "Application log format demonstrating notice version presented before consent."
            ],
            "recommended_actions": [
                "Deploy an itemized consent banner that lists each data category and specific purpose separately.",
                "Provide direct links to grievance officer details in the notice text."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["website_security", "privacy_headers", "cookies"]
        },
        {
            "control_id": "DPDP-SEC-06",
            "section": "Section 6(9) & Rule 4",
            "title": "Consent Architecture & Consent Manager Integration",
            "official_ref": "DPDP Act 2023, Section 6(9) read with DPDP Rules 2025, Rule 4",
            "description": "Data Principals may give, manage, review, or withdraw consent through registered Consent Managers accountable to the DPBI. TrustAudit tracks organizational technical readiness to interface with registered Consent Managers and does not self-attest as a registered Consent Manager.",
            "applicability": "Mandatory for all consent-based processing ecosystems.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "13 November 2026 (In Force)",
            "status_display": "Already in force",
            "category": "Consent Architecture",
            "assessment_questions": [
                "Can users withdraw their consent easily via account settings with equal ease to giving consent?",
                "Is your data architecture prepared to process standard interoperable consent tokens from registered Consent Managers?"
            ],
            "evidence_requirements": [
                "Documentation or UI workflow showing the self-service consent withdrawal flow.",
                "Consent lifecycle database schema or audit trail format."
            ],
            "recommended_actions": [
                "Implement a dedicated 'Manage Privacy Preferences' portal in user dashboard.",
                "Ensure withdrawal of consent cascades downstream to data processors and third-party vendors."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["cookies", "cors", "api_discovery"]
        },
        {
            "control_id": "DPDP-SEC-08-1",
            "section": "Section 8(1)",
            "title": "General Data Fiduciary Responsibility",
            "official_ref": "DPDP Act 2023, Section 8(1)",
            "description": "A Data Fiduciary shall be responsible for complying with the provisions of this Act and the rules made thereunder in respect of any processing undertaken by it or on its behalf by a Data Processor.",
            "applicability": "Mandatory for all entities acting as Data Fiduciaries.",
            "enforcement_phase": "SCHEDULED_TO_COMMENCE",
            "effective_date": "13 May 2027 (Scheduled commencement)",
            "status_display": "Readiness assessment",
            "category": "Governance & Accountability",
            "assessment_questions": [
                "Has your organization established formal data governance policies covering processors acting on your behalf?",
                "Do Data Processor contracts mandate strict compliance with DPDP standards?"
            ],
            "evidence_requirements": [
                "Data Protection Governance Charter.",
                "Standard Data Processing Addendum (DPA) executed with third-party vendors."
            ],
            "recommended_actions": [
                "Execute Data Processing Addenda with all cloud and SaaS vendors handling user personal data.",
                "Designate an executive lead accountable for personal data processing compliance."
            ],
            "expert_review_required": True,
            "technical_scan_checks": []
        },
        {
            "control_id": "DPDP-SEC-08-4",
            "section": "Section 8(4)",
            "title": "Technical and Organisational Measures",
            "official_ref": "DPDP Act 2023, Section 8(4)",
            "description": "A Data Fiduciary shall implement appropriate technical and organisational measures to ensure effective observance of the provisions of this Act and the rules made thereunder.",
            "applicability": "Mandatory for all personal data processing systems.",
            "enforcement_phase": "SCHEDULED_TO_COMMENCE",
            "effective_date": "13 May 2027 (Scheduled commencement)",
            "status_display": "Readiness assessment",
            "category": "Technical & Organisational Measures",
            "assessment_questions": [
                "Are role-based access controls (RBAC) and least privilege enforced across internal databases?",
                "Are regular automated security assessments, dependency audits, and SAST scans embedded in CI/CD?"
            ],
            "evidence_requirements": [
                "Access control policy and quarterly privilege review records.",
                "TrustAudit automated CI/CD security audit reports."
            ],
            "recommended_actions": [
                "Enforce multi-tenant access controls and least-privilege scoping across all database queries.",
                "Embed TrustAudit automated PR security checks in build pipelines."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["code_security", "dependencies", "mcp_security"]
        },
        {
            "control_id": "DPDP-SEC-08-5",
            "section": "Section 8(5) & Rule 6",
            "title": "Reasonable Security Safeguards to Prevent Personal Data Breach",
            "official_ref": "DPDP Act 2023, Section 8(5) read with DPDP Rules 2025, Rule 6",
            "description": "A Data Fiduciary must protect personal data in its possession or under its control by taking reasonable security safeguards including encryption, secret protection, perimeter defense, and vulnerability patching to prevent personal data breach.",
            "applicability": "Mandatory for all entities processing digital personal data.",
            "enforcement_phase": "SCHEDULED_TO_COMMENCE",
            "effective_date": "13 May 2027 (Scheduled commencement; IT Act Section 43A baseline in force)",
            "status_display": "Readiness assessment",
            "category": "Security Safeguards & Breach Prevention",
            "assessment_questions": [
                "Are all production credentials, database passwords, and API keys excluded from repositories and stored in secure key vaults?",
                "Is all personal data encrypted in transit using modern TLS (1.2/1.3) with HSTS enforced?",
                "Are automated vulnerability scans conducted regularly across repositories, APIs, and web perimeters?"
            ],
            "evidence_requirements": [
                "TrustAudit Secret Detection report confirming 0 active exposed production secrets.",
                "TLS certificate verification and perimeter security header audit report.",
                "Data-at-rest and in-transit encryption architecture documentation."
            ],
            "recommended_actions": [
                "Revoke and rotate any hardcoded credentials detected in source code.",
                "Enforce HTTPS with HSTS on all personal-data-ingesting endpoints."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["secrets", "tls", "headers", "dependencies", "code_security", "mcp_security"]
        },
        {
            "control_id": "DPDP-SEC-08-6",
            "section": "Section 8(6) & Rule 7",
            "title": "Intimation of Personal Data Breach to DPBI & Data Principals",
            "official_ref": "DPDP Act 2023, Section 8(6) read with DPDP Rules 2025, Rule 7",
            "description": "In the event of a personal data breach, the Data Fiduciary shall give the Data Protection Board of India and each affected Data Principal intimation in such form, manner, and time as prescribed under Rule 7.",
            "applicability": "Mandatory for all personal data breaches.",
            "enforcement_phase": "SCHEDULED_TO_COMMENCE",
            "effective_date": "13 May 2027 (Scheduled commencement)",
            "status_display": "Readiness assessment",
            "category": "Incident Response",
            "assessment_questions": [
                "Do you maintain an active Incident Response Plan with defined DPBI breach notification procedures?",
                "Can your system identify which users' personal data was accessed or compromised within 24 hours of breach detection?"
            ],
            "evidence_requirements": [
                "Incident Response Policy document detailing DPBI reporting thresholds and templates.",
                "Breach drill / tabletop simulation report from past 12 months."
            ],
            "recommended_actions": [
                "Establish automated alert rules for anomalous credential dumps or data exfiltration attempts.",
                "Draft pre-approved notification templates for Data Principals and DPBI."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["exposure", "api_discovery", "logging"]
        },
        {
            "control_id": "DPDP-SEC-08-7",
            "section": "Section 8(7) & 8(8)",
            "title": "Data Erasure and Purpose Limitation",
            "official_ref": "DPDP Act 2023, Section 8(7) & 8(8)",
            "description": "A Data Fiduciary must erase personal data upon consent withdrawal or as soon as it is reasonable to assume that the specified purpose for which personal data was collected is no longer being served, unless retention is required by law.",
            "applicability": "Mandatory for all personal data processing.",
            "enforcement_phase": "SCHEDULED_TO_COMMENCE",
            "effective_date": "13 May 2027 (Scheduled commencement)",
            "status_display": "Readiness assessment",
            "category": "Data Retention & Erasure",
            "assessment_questions": [
                "Do you have an automated data retention and scheduled purging mechanism for inactive or deleted accounts?",
                "Are backup archives purged or sanitized according to retention limits?"
            ],
            "evidence_requirements": [
                "Data Retention & Erasure Schedule policy.",
                "Database cron / cleanup script configuration logs demonstrating periodic erasure."
            ],
            "recommended_actions": [
                "Define explicit retention timeframes per data category (e.g. 180 days post-account closure).",
                "Implement database soft-deletion followed by permanent hard-purge."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["database_access", "exposure"]
        },
        {
            "control_id": "DPDP-SEC-09",
            "section": "Section 9 & applicable Rules",
            "title": "Processing of Personal Data of Children",
            "official_ref": "DPDP Act 2023, Section 9 read with applicable DPDP Rules 2025",
            "description": "A Data Fiduciary must obtain verifiable consent of the parent or lawful guardian before processing personal data of a child. Must not undertake tracking or behavioral monitoring of children or targeted advertising directed at children.",
            "applicability": "Applies to businesses offering goods or services to minors (<18 years in India).",
            "enforcement_phase": "SCHEDULED_TO_COMMENCE",
            "effective_date": "13 May 2027 (Scheduled commencement)",
            "status_display": "Readiness assessment",
            "category": "Child Protection",
            "assessment_questions": [
                "Do your products or AI tools process personal data of individuals under 18 years of age?",
                "If applicable, is verifiable parental consent obtained prior to account creation?",
                "Are tracking cookies and behavioral profiling scripts disabled for child accounts?"
            ],
            "evidence_requirements": [
                "Age-gating verification flow screenshots or code logic.",
                "Parental consent verification mechanism documentation."
            ],
            "recommended_actions": [
                "Implement age verification gate at onboarding.",
                "Disable all tracking cookies and analytics pixels for accounts registered to minors."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["cookies", "headers"]
        },
        {
            "control_id": "DPDP-SEC-10",
            "section": "Section 10",
            "title": "Additional Obligations of Significant Data Fiduciaries (SDF)",
            "official_ref": "DPDP Act 2023, Section 10(1) & (2)",
            "description": "Central Government may notify any Data Fiduciary as SDF based on volume, sensitivity, and risk. SDFs must appoint a Data Protection Officer based in India, an independent data auditor, and conduct periodic Data Protection Impact Assessments (DPIA).",
            "applicability": "Applies to entities designated as Significant Data Fiduciaries.",
            "enforcement_phase": "PENDING_NOTIFICATION",
            "effective_date": "Upon Government Notification",
            "status_display": "Requires legal review",
            "category": "Governance & SDF Obligations",
            "assessment_questions": [
                "Has your organization evaluated whether its user base or data volume meets SDF classification criteria?",
                "Have you appointed a Data Protection Officer (DPO) based in India?",
                "Do you conduct periodic Data Protection Impact Assessments (DPIA)?"
            ],
            "evidence_requirements": [
                "DPO appointment letter and public contact details.",
                "Latest Data Protection Impact Assessment (DPIA) report."
            ],
            "recommended_actions": [
                "Designate an India-based DPO with direct reporting to the Board.",
                "Establish annual third-party security and privacy audit schedule."
            ],
            "expert_review_required": True,
            "technical_scan_checks": []
        }
    ],

    # --------------------------------------------------------------------------
    # SOC 2 TRUST SERVICES CRITERIA (READINESS & EVIDENCE MANAGEMENT)
    # --------------------------------------------------------------------------
    "SOC2": [
        {
            "control_id": "SOC2-CC6.1",
            "section": "CC6.1",
            "title": "Logical Access Security",
            "official_ref": "AICPA TSC 2017 CC6.1 (2022 Focus)",
            "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
            "applicability": "Mandatory for SOC 2 Security Category.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active AICPA Published Criteria",
            "status_display": "Readiness assessment",
            "category": "Logical Access",
            "assessment_questions": [
                "Are all repository secrets, API keys, and database passwords excluded from source code and managed via dedicated secret stores?",
                "Is Multi-Factor Authentication (MFA) strictly enforced for all developer accounts, cloud consoles, and Git repositories?",
                "Are user access permissions reviewed on at least a quarterly basis?"
            ],
            "evidence_requirements": [
                "TrustAudit automated Secret Scan report demonstrating 0 active exposed keys.",
                "MFA enforcement screenshots from identity provider (Okta/Google Workspace/GitHub).",
                "Quarterly access review sign-off sheets."
            ],
            "recommended_actions": [
                "Remove and rotate any hardcoded API keys detected in codebases.",
                "Enforce GitHub organization-wide MFA and signed commits."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["secrets", "authentication", "authorization", "mcp_security"]
        },
        {
            "control_id": "SOC2-CC6.6",
            "section": "CC6.6",
            "title": "Protection Against Threats Originating Outside System Boundaries",
            "official_ref": "AICPA TSC 2017 CC6.6 (2022 Focus)",
            "description": "The entity implements logical boundaries and network protections against threats originating outside system boundaries.",
            "applicability": "Mandatory for SOC 2 Security Category.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active AICPA Published Criteria",
            "status_display": "Readiness assessment",
            "category": "Network & Perimeter Security",
            "assessment_questions": [
                "Is all network traffic to web applications encrypted in transit using TLS 1.2 or TLS 1.3 with strong cipher suites?",
                "Are modern HTTP security headers (HSTS, CSP, X-Frame-Options) properly configured on public perimeter endpoints?",
                "Are internal debug, actuator, or swagger interfaces restricted from unauthenticated public exposure?"
            ],
            "evidence_requirements": [
                "TrustAudit Website Perimeter & TLS Analysis report.",
                "Cloud firewall / security group configuration export showing restricted ingress ports."
            ],
            "recommended_actions": [
                "Enable HSTS with minimum 1-year max-age on production domains.",
                "Restrict administrative API endpoints behind private VPN or IP allowlists."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["tls", "headers", "cors", "exposure", "website_security"]
        },
        {
            "control_id": "SOC2-CC6.8",
            "section": "CC6.8",
            "title": "Prevention, Detection, and Remediation of Unauthorised or Malicious Software",
            "official_ref": "AICPA TSC 2017 CC6.8 (2022 Focus)",
            "description": "The entity implements controls to prevent, detect, and remediate the introduction of unauthorized software, malicious code, or compromised agent integrations.",
            "applicability": "Mandatory for SOC 2 Security Category.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active AICPA Published Criteria",
            "status_display": "Readiness assessment",
            "category": "Application Security & Tool Control",
            "assessment_questions": [
                "Do all AI agents and MCP tools operate under least-privilege permission boundaries?",
                "Are MCP tools audited for description mismatch, prompt injection poisoning, and typosquatted dependencies?",
                "Is runtime firewalling or execution approval enforced before AI agents run system shell commands?"
            ],
            "evidence_requirements": [
                "TrustAudit MCP Security & Blast Radius report.",
                "Antivirus / EDR configuration report for developer workstations."
            ],
            "recommended_actions": [
                "Implement TrustAudit runtime MCP firewall rules restricting shell and raw socket execution.",
                "Audit package manifest for typosquatted open-source dependencies."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["mcp_security", "prompt_injection", "supply_chain", "code_security"]
        },
        {
            "control_id": "SOC2-CC7.1",
            "section": "CC7.1",
            "title": "Monitoring of Configuration Changes and Susceptibility to Newly Discovered Vulnerabilities",
            "official_ref": "AICPA TSC 2017 CC7.1 (2022 Focus)",
            "description": "The entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities.",
            "applicability": "Mandatory for SOC 2 Security Category.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active AICPA Published Criteria",
            "status_display": "Readiness assessment",
            "category": "Vulnerability Management",
            "assessment_questions": [
                "Are automated dependency vulnerability scans executed on every pull request and continuous build?",
                "Is there a formal Service Level Agreement (SLA) for patching critical vulnerabilities (e.g. 7 days for CRITICAL)?",
                "Does the team monitor CISA KEV or national vulnerability databases for actively exploited component vulnerabilities?"
            ],
            "evidence_requirements": [
                "TrustAudit Dependency & SBOM Scan report.",
                "Vulnerability Patching Policy document specifying remediation timelines by severity.",
                "Pull Request / CI security gate build logs."
            ],
            "recommended_actions": [
                "Configure automated Dependabot / Renovate / TrustAudit CI security checks.",
                "Upgrade dependencies with known high-severity CVEs."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["dependencies", "code_security", "supply_chain"]
        },
        {
            "control_id": "SOC2-CC8.1",
            "section": "CC8.1",
            "title": "Authorized Change Management & CI/CD Security Gates",
            "official_ref": "AICPA TSC 2017 CC8.1 (2022 Focus)",
            "description": "The entity authorizes, designs, tests, approves, and documents changes to infrastructure, applications, and configurations prior to production deployment.",
            "applicability": "Mandatory for SOC 2 Security Category.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active AICPA Published Criteria",
            "status_display": "Readiness assessment",
            "category": "Change Management",
            "assessment_questions": [
                "Are direct commits to the production branch blocked via branch protection rules?",
                "Is peer code review required and enforced before merging code changes?",
                "Are automated security tests and regression tests required to pass before deployment?"
            ],
            "evidence_requirements": [
                "GitHub / GitLab branch protection rule settings screenshot.",
                "CI/CD workflow pipeline definition file (`.github/workflows/*.yml`).",
                "Sample Pull Request showing peer approval and automated security check pass."
            ],
            "recommended_actions": [
                "Wire TrustAudit CI quality gate (`ci_scan.py`) into GitHub Actions pipeline.",
                "Enforce minimum 1 peer code review on all pull requests."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["code_security"]
        }
    ],

    # --------------------------------------------------------------------------
    # ISO/IEC 27001:2022 ANNEX A CONTROLS (INCLUDING AMD 1:2024)
    # --------------------------------------------------------------------------
    "ISO27001": [
        {
            "control_id": "ISO-A.8.8",
            "section": "Control A.8.8",
            "title": "Management of Technical Vulnerabilities",
            "official_ref": "ISO/IEC 27001:2022 Annex A.8.8",
            "description": "Information about technical vulnerabilities of information systems in use shall be obtained, the organization's exposure evaluated, and appropriate measures taken to address the associated risk.",
            "applicability": "Mandatory technical control in Statement of Applicability (SoA).",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active ISO/IEC 27001:2022 Standard",
            "status_display": "Readiness assessment",
            "category": "Technological Controls",
            "assessment_questions": [
                "Does the organization conduct continuous static and dynamic vulnerability assessments across all production assets?",
                "Are vulnerabilities prioritized based on exploitability, threat intelligence (CISA KEV), and asset criticality?"
            ],
            "evidence_requirements": [
                "TrustAudit Comprehensive Security Audit Report.",
                "Documented Vulnerability Management Procedure."
            ],
            "recommended_actions": [
                "Establish weekly continuous monitoring scans across repositories and public web assets.",
                "Maintain remediation tracking SLA for critical and high findings."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["code_security", "dependencies", "website_security", "mcp_security"]
        },
        {
            "control_id": "ISO-A.8.20",
            "section": "Control A.8.20",
            "title": "Networks Security",
            "official_ref": "ISO/IEC 27001:2022 Annex A.8.20",
            "description": "Networks and network devices shall be secured, managed, and controlled to protect the information in systems and applications.",
            "applicability": "Mandatory technical control in SoA.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active ISO/IEC 27001:2022 Standard",
            "status_display": "Readiness assessment",
            "category": "Technological Controls",
            "assessment_questions": [
                "Are public perimeter web servers hardened against cross-origin data theft (CORS) and clickjacking?",
                "Are network-exposed services authenticated with zero unauthenticated remote procedure calls?"
            ],
            "evidence_requirements": [
                "Perimeter network security scan report.",
                "Firewall & CORS configuration review."
            ],
            "recommended_actions": [
                "Replace wildcard `Access-Control-Allow-Origin: *` with specific trusted origin allowlists.",
                "Ensure MCP servers with network transports enforce bearer token authentication."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["cors", "headers", "website_security", "exposure"]
        },
        {
            "control_id": "ISO-A.8.24",
            "section": "Control A.8.24",
            "title": "Use of Cryptography",
            "official_ref": "ISO/IEC 27001:2022 Annex A.8.24",
            "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
            "applicability": "Mandatory technical control in SoA.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active ISO/IEC 27001:2022 Standard",
            "status_display": "Readiness assessment",
            "category": "Technological Controls",
            "assessment_questions": [
                "Is deprecated cryptography (TLS 1.0/1.1, MD5, SHA-1) phased out across all application endpoints?",
                "Are cryptographic API keys and private keys protected against source code repository leakage?"
            ],
            "evidence_requirements": [
                "TrustAudit TLS Configuration & Cryptographic Analysis report.",
                "Secret detection zero-leakage scan verification."
            ],
            "recommended_actions": [
                "Enforce TLS 1.2+ minimum and disable obsolete legacy cipher suites.",
                "Rotate any secrets previously committed to git history."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["tls", "secrets"]
        },
        {
            "control_id": "ISO-A.8.25",
            "section": "Control A.8.25",
            "title": "Secure Development Life Cycle",
            "official_ref": "ISO/IEC 27001:2022 Annex A.8.25",
            "description": "Rules for the secure development of software and systems shall be established and applied to developments within the organization.",
            "applicability": "Mandatory for all software engineering organizations.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active ISO/IEC 27001:2022 Standard",
            "status_display": "Readiness assessment",
            "category": "Technological Controls",
            "assessment_questions": [
                "Are security requirements identified and addressed across all phases of the software development lifecycle?",
                "Are automated security gates enforced in continuous integration and deployment (CI/CD) pipelines?"
            ],
            "evidence_requirements": [
                "Documented Secure Software Development Life Cycle (S-SDLC) policy.",
                "CI/CD build pipeline logs demonstrating automated security testing gates."
            ],
            "recommended_actions": [
                "Formalize an S-SDLC policy incorporating automated static analysis and vulnerability scans.",
                "Enforce branch protection rules and automated security gate passing before production deployment."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["code_security"]
        },
        {
            "control_id": "ISO-A.8.28",
            "section": "Control A.8.28",
            "title": "Secure Coding",
            "official_ref": "ISO/IEC 27001:2022 Annex A.8.28",
            "description": "Secure coding principles shall be applied to software development.",
            "applicability": "Mandatory for all software engineering organizations.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "Active ISO/IEC 27001:2022 Standard",
            "status_display": "Readiness assessment",
            "category": "Technological Controls",
            "assessment_questions": [
                "Are developers provided with secure coding guidelines addressing OWASP Top 10 vulnerabilities?",
                "Are static code analysis (SAST) checks automated before merging code into production?"
            ],
            "evidence_requirements": [
                "Static Application Security Testing (SAST) build reports.",
                "Secure Coding Policy and developer training records."
            ],
            "recommended_actions": [
                "Remediate command injection, SQL injection, and path traversal vectors identified in SAST audit.",
                "Implement parameterization and parameterized database query builders."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["code_security", "mcp_security", "prompt_injection"]
        }
    ],

    # --------------------------------------------------------------------------
    # GDPR (REGULATION (EU) 2016/679)
    # --------------------------------------------------------------------------
    "GDPR": [
        {
            "control_id": "GDPR-ART-25",
            "section": "Article 25",
            "title": "Data Protection by Design and by Default",
            "official_ref": "EU GDPR Article 25(1) & (2)",
            "description": "The controller shall implement appropriate technical and organizational measures, such as pseudonymisation, designed to implement data-protection principles effectively and integrate necessary safeguards into processing.",
            "applicability": "Applies to any system processing EU/EEA personal data.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "May 25, 2018",
            "category": "Privacy Engineering",
            "assessment_questions": [
                "Are privacy-enhancing measures (least privilege, tenant isolation, pseudonymization) designed into application schemas?",
                "Are default settings configured to collect only personal data necessary for each specific purpose?"
            ],
            "evidence_requirements": [
                "Architectural Data Flow Diagram (DFD) and schema design review.",
                "Multi-tenancy isolation audit report."
            ],
            "recommended_actions": [
                "Isolate tenant databases or apply Row-Level Security (RLS) on personal data tables.",
                "Disable default telemetry tracking on user sessions."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["tenancy", "exposure"]
        },
        {
            "control_id": "GDPR-ART-32",
            "section": "Article 32",
            "title": "Security of Processing (Technical & Organizational Measures)",
            "official_ref": "EU GDPR Article 32(1)",
            "description": "Taking into account the state of the art, costs of implementation, and nature of processing, the controller and processor shall implement technical measures including encryption, integrity, confidentiality, and regular testing of security effectiveness.",
            "applicability": "Mandatory for all controllers and processors.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "May 25, 2018",
            "category": "Technical Security",
            "assessment_questions": [
                "Is personal data encrypted both in transit and at rest using modern encryption standards?",
                "Does the organization have a process for regularly testing, assessing, and evaluating the effectiveness of technical measures?"
            ],
            "evidence_requirements": [
                "Regular automated vulnerability scanning and code audit reports.",
                "Encryption in transit and at rest configuration verification."
            ],
            "recommended_actions": [
                "Run periodic automated SAST and DAST scans with verified audit trail records.",
                "Enforce HTTPS with secure cookie attributes (`Secure`, `HttpOnly`, `SameSite`)."
            ],
            "expert_review_required": False,
            "technical_scan_checks": ["secrets", "tls", "headers", "cookies", "code_security", "dependencies"]
        },
        {
            "control_id": "GDPR-ART-33",
            "section": "Article 33",
            "title": "Notification of a Personal Data Breach to Supervisory Authority",
            "official_ref": "EU GDPR Article 33(1)",
            "description": "In the case of a personal data breach, the controller shall without undue delay and, where feasible, not later than 72 hours after having become aware of it, notify the competent supervisory authority.",
            "applicability": "Mandatory for all EU data controllers.",
            "enforcement_phase": "IN_FORCE_SUBSTANTIVE",
            "effective_date": "May 25, 2018",
            "category": "Incident Response",
            "assessment_questions": [
                "Does your Incident Response procedure mandate 72-hour formal notification to the relevant Lead Supervisory Authority?",
                "Are security incidents logged in an immutable audit trail?"
            ],
            "evidence_requirements": [
                "Documented Data Breach Notification Procedure with 72-hour timeline.",
                "Incident triage log template."
            ],
            "recommended_actions": [
                "Configure immediate automated alerts for detected credential exposures or perimeter breaches.",
                "Maintain contact channels with the designated European Data Protection Authority."
            ],
            "expert_review_required": True,
            "technical_scan_checks": ["exposure", "logging"]
        }
    ]
}


# ==============================================================================
# 2. CENTRAL FINDING-TO-FRAMEWORK MAPPING ENGINE
# ==============================================================================

def map_finding_to_compliance_frameworks(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Computes verified, legally justified compliance control mappings for a specific finding.
    Does NOT assert complete compliance; explicitly records the violation or risk justification.
    """
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    desc = str(finding.get("description", "")).lower()
    cwe = str(finding.get("cwe", "")).lower()
    cve = str(finding.get("cve", "")).lower()
    evidence = str(finding.get("evidence", "")).lower()

    text_corpus = f"{category} {title} {desc} {cwe} {cve} {evidence}"
    mappings = []

    # 1. Hardcoded Secrets & Token Exposures
    if category == "secrets" or any(k in text_corpus for k in ["secret", "token", "api key", "password", "credential", "private key"]):
        mappings.append({
            "framework": "DPDP",
            "control_id": "DPDP-SEC-08-5",
            "official_ref": "Section 8(5) & Rule 6 - Reasonable Security Safeguards",
            "status": "AT_RISK",
            "justification": "Exposing production credentials or cryptographic keys in code violates the statutory obligation to implement reasonable security safeguards to prevent personal data breach."
        })
        mappings.append({
            "framework": "DPDP",
            "control_id": "DPDP-SEC-08-1",
            "official_ref": "Section 8(1) - General Data Fiduciary Responsibility",
            "status": "AT_RISK",
            "justification": "Exposing production credentials directly compromises the Data Fiduciary's general statutory compliance responsibility under Section 8(1)."
        })
        mappings.append({
            "framework": "SOC2",
            "control_id": "SOC2-CC6.1",
            "official_ref": "CC6.1 - Logical Access Security",
            "status": "AT_RISK",
            "justification": "Hardcoded keys bypass logical access separation and credential rotation controls required under SOC 2 Common Criteria."
        })
        mappings.append({
            "framework": "ISO27001",
            "control_id": "ISO-A.8.24",
            "official_ref": "Control A.8.24 - Use of Cryptography",
            "status": "AT_RISK",
            "justification": "Insecure key storage in repositories directly conflicts with ISO 27001 cryptographic key management rules."
        })
        mappings.append({
            "framework": "GDPR",
            "control_id": "GDPR-ART-32",
            "official_ref": "Article 32(1) - Security of Processing",
            "status": "AT_RISK",
            "justification": "Credential exposure jeopardizes the ongoing confidentiality and integrity of personal data processing environments."
        })

    # 2. TLS, Plaintext HTTP, Missing Security Headers
    elif category in ("tls", "headers", "cookies") or any(k in text_corpus for k in ["hsts", "tls", "ssl", "plaintext", "cors", "cookie", "httponly"]):
        mappings.append({
            "framework": "DPDP",
            "control_id": "DPDP-SEC-08-5",
            "official_ref": "Section 8(5) & Rule 6 - Reasonable Security Safeguards",
            "status": "AT_RISK",
            "justification": "Unencrypted transit or weak perimeter headers expose user traffic to eavesdropping and data interception."
        })
        mappings.append({
            "framework": "SOC2",
            "control_id": "SOC2-CC6.6",
            "official_ref": "CC6.6 - Protection Against Threats Outside System Boundaries",
            "status": "AT_RISK",
            "justification": "Missing perimeter encryption or security headers fails boundary protection controls against network interception."
        })
        mappings.append({
            "framework": "ISO27001",
            "control_id": "ISO-A.8.20",
            "official_ref": "Control A.8.20 - Networks Security",
            "status": "AT_RISK",
            "justification": "Permissive cross-origin configurations or insecure transit violate network boundary control standards."
        })
        mappings.append({
            "framework": "GDPR",
            "control_id": "GDPR-ART-32",
            "official_ref": "Article 32(1)(a) - Encryption of Personal Data",
            "status": "AT_RISK",
            "justification": "GDPR Article 32 explicitly requires robust encryption of personal data in transit over public networks."
        })

    # 3. Vulnerable Dependencies & Outdated Third-Party Packages
    elif category == "dependencies" or any(k in text_corpus for k in ["cve-", "dependency", "outdated", "vulnerable package"]):
        mappings.append({
            "framework": "SOC2",
            "control_id": "SOC2-CC7.1",
            "official_ref": "CC7.1 - Vulnerability Detection & Configuration Monitoring",
            "status": "AT_RISK",
            "justification": "Deploying components with known published vulnerabilities indicates inadequate configuration monitoring and patch management."
        })
        mappings.append({
            "framework": "ISO27001",
            "control_id": "ISO-A.8.8",
            "official_ref": "Control A.8.8 - Management of Technical Vulnerabilities",
            "status": "AT_RISK",
            "justification": "Using packages with unpatched security advisories contravenes vulnerability management procedures."
        })
        mappings.append({
            "framework": "DPDP",
            "control_id": "DPDP-SEC-08-5",
            "official_ref": "Section 8(5) & Rule 6 - Reasonable Security Safeguards",
            "status": "AT_RISK",
            "justification": "Known exploitable flaws in third-party libraries present an unacceptable risk of personal data breach."
        })

    # 4. MCP Tool Capability Creep, Prompt Injection, Remote Shell
    elif category == "mcp_security" or "prompt_injection" in category or any(k in text_corpus for k in ["mcp", "prompt injection", "shell_execution", "tool scope"]):
        mappings.append({
            "framework": "SOC2",
            "control_id": "SOC2-CC6.8",
            "official_ref": "CC6.8 - Prevention, Detection & Remediation of Unauthorized Software",
            "status": "AT_RISK",
            "justification": "Undisclosed or expanded AI agent permissions enable arbitrary command execution without authorized safeguards."
        })
        mappings.append({
            "framework": "ISO27001",
            "control_id": "ISO-A.8.28",
            "official_ref": "Control A.8.28 - Secure Coding",
            "status": "AT_RISK",
            "justification": "Prompt injection susceptibility and unauthorized tool capabilities violate secure AI engineering standards."
        })
        mappings.append({
            "framework": "ISO27001",
            "control_id": "ISO-A.8.25",
            "official_ref": "Control A.8.25 - Secure Development Life Cycle",
            "status": "AT_RISK",
            "justification": "Failure to bound AI agent capabilities in the development lifecycle violates secure design controls."
        })
        mappings.append({
            "framework": "DPDP",
            "control_id": "DPDP-SEC-08-5",
            "official_ref": "Section 8(5) & Rule 6 - Reasonable Security Safeguards",
            "status": "AT_RISK",
            "justification": "Unvalidated AI tool execution exposes personal data records to unauthorized AI-driven data extraction."
        })

    # 5. Sensitive File Exposure (.git, .env, swagger, actuator)
    elif category in ("exposure", "website_security") or any(k in text_corpus for k in [".git", ".env", "actuator", "exposure", "directory listing"]):
        mappings.append({
            "framework": "DPDP",
            "control_id": "DPDP-SEC-08-5",
            "official_ref": "Section 8(5) & Rule 6 - Reasonable Security Safeguards",
            "status": "AT_RISK",
            "justification": "Public exposure of server configuration or internal environment variables enables direct unauthorized system intrusion."
        })
        mappings.append({
            "framework": "SOC2",
            "control_id": "SOC2-CC6.6",
            "official_ref": "CC6.6 - Protection Against Threats Outside System Boundaries",
            "status": "AT_RISK",
            "justification": "Exposing internal files on the public internet breaches boundary isolation requirements."
        })
        mappings.append({
            "framework": "ISO27001",
            "control_id": "ISO-A.8.20",
            "official_ref": "Control A.8.20 - Networks Security",
            "status": "AT_RISK",
            "justification": "Unrestricted access to administrative configuration files violates access control policies."
        })
        mappings.append({
            "framework": "GDPR",
            "control_id": "GDPR-ART-32",
            "official_ref": "Article 32 - Security of Processing",
            "status": "AT_RISK",
            "justification": "Public configuration leaks compromise the technical perimeter protecting personal data."
        })

    # Default fallback mapping
    if not mappings:
        mappings.append({
            "framework": "ISO27001",
            "control_id": "ISO-A.8.8",
            "official_ref": "Control A.8.8 - Technical Vulnerability Management",
            "status": "AT_RISK",
            "justification": "Identified security flaw requires tracking and remediation under vulnerability management procedures."
        })
        mappings.append({
            "framework": "SOC2",
            "control_id": "SOC2-CC7.1",
            "official_ref": "CC7.1 - Vulnerability Identification",
            "status": "AT_RISK",
            "justification": "Unresolved security finding requires assessment under continuous vulnerability monitoring controls."
        })

    return mappings


# ==============================================================================
# 3. ONBOARDING & ORGANISATION ASSESSMENT ENGINE (PHASE 4)
# ==============================================================================

ONBOARDING_QUESTIONS = [
    {
        "id": "company_name",
        "label": "Company / Organisation Legal Name",
        "type": "text",
        "required": True,
        "placeholder": "e.g. Acme Technologies Private Limited"
    },
    {
        "id": "country",
        "label": "Country of Incorporation / Primary Operations",
        "type": "select",
        "options": ["India", "United States", "European Union / UK", "Singapore", "Other"],
        "required": True
    },
    {
        "id": "industry",
        "label": "Industry / Sector",
        "type": "select",
        "options": ["SaaS / B2B Software", "FinTech / Payments", "HealthTech", "E-Commerce / Consumer", "AI & Developer Tools", "EdTech", "Other"],
        "required": True
    },
    {
        "id": "employee_count",
        "label": "Company Size / Employee Count",
        "type": "select",
        "options": ["1-10 (Early Stage)", "11-50 (Seed/Series A)", "51-200 (Growth)", "201+ (Enterprise)"],
        "required": True
    },
    {
        "id": "customer_types",
        "label": "Types of Customers Served",
        "type": "multiselect",
        "options": ["Indian Consumers (B2C)", "Indian Businesses (B2B)", "US / Global Businesses", "European Union Users / Customers", "Minors / Children (<18 years)"],
        "required": True
    },
    {
        "id": "personal_data_categories",
        "label": "Categories of Personal Data Handled",
        "type": "multiselect",
        "options": [
            "Basic Contact Data (Name, Email, Phone)",
            "Financial & Payment Records",
            "Health & Biometric Data",
            "Government Identifiers (Aadhaar, PAN, SSN)",
            "Location / GPS Data",
            "Behavioral & Usage Telemetry",
            "No Personal Data (Only Anonymized Logs)"
        ],
        "required": True
    },
    {
        "id": "infrastructure",
        "label": "Primary Cloud & Hosting Infrastructure",
        "type": "multiselect",
        "options": ["AWS (India / Mumbai)", "AWS (US / Global)", "Google Cloud Platform", "Microsoft Azure", "Render / Vercel / PaaS", "On-Premises / Hybrid"],
        "required": True
    },
    {
        "id": "vendors",
        "label": "Third-Party Processors & Critical Vendors",
        "type": "multiselect",
        "options": ["OpenAI / Anthropic (LLM APIs)", "Stripe / Razorpay (Payment Gateways)", "SendGrid / Resend (Transactional Email)", "Segment / Mixpanel (Product Analytics)", "Datadog / Sentry (Monitoring & Logs)"],
        "required": False
    },
    {
        "id": "selected_frameworks",
        "label": "Compliance Frameworks to Audit & Track",
        "type": "multiselect",
        "options": ["DPDP", "SOC2", "ISO27001", "GDPR"],
        "required": True
    }
]


def evaluate_framework_applicability(profile: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Evaluates applicability of compliance frameworks based on the organization's onboarding profile.
    """
    country = profile.get("country", "")
    customer_types = profile.get("customer_types", [])
    selected_fws = profile.get("selected_frameworks") or ["DPDP", "SOC2", "ISO27001"]

    applicability = {}

    # DPDP
    dpdp_applicable = (
        country == "India" or
        "Indian Consumers (B2C)" in customer_types or
        "Indian Businesses (B2B)" in customer_types or
        "DPDP" in selected_fws
    )
    applicability["DPDP"] = {
        "applicable": dpdp_applicable,
        "reason": "Entity operates in India or processes digital personal data of Indian Data Principals (Section 3)." if dpdp_applicable else "Entity has no documented Indian personal data nexus.",
        "enforcement_note": "Substantive security requirements apply immediately; notice and consent provisions will commence upon MeitY rule notification."
    }

    # SOC 2
    soc2_applicable = (
        "US / Global Businesses" in customer_types or
        "SOC2" in selected_fws or
        "SaaS / B2B Software" in profile.get("industry", "")
    )
    applicability["SOC2"] = {
        "applicable": soc2_applicable,
        "reason": "B2B customers and enterprise buyers require SOC 2 Trust Services Criteria verification." if soc2_applicable else "Optional standard for consumer-only applications.",
        "enforcement_note": "Readiness and evidence tracking only. Requires independent CPA audit for formal report issuance."
    }

    # ISO 27001
    iso_applicable = "ISO27001" in selected_fws or profile.get("employee_count") in ["51-200 (Growth)", "201+ (Enterprise)"]
    applicability["ISO27001"] = {
        "applicable": iso_applicable,
        "reason": "Global enterprise clients and government tenders require ISO/IEC 27001 ISMS baseline." if iso_applicable else "Recommended best-practice security baseline for tech startups.",
        "enforcement_note": "Posture evaluation only. Formal certification requires accredited Certification Body audit."
    }

    # GDPR
    gdpr_applicable = "European Union Users / Customers" in customer_types or "GDPR" in selected_fws
    applicability["GDPR"] = {
        "applicable": gdpr_applicable,
        "reason": "Processing personal data of individuals located within the European Union (Article 3 territorial scope)." if gdpr_applicable else "Entity does not target EU/EEA users.",
        "enforcement_note": "Fully enforceable under EU law with substantial statutory non-compliance penalties."
    }

    return applicability


def generate_organization_assessment(
    profile: Dict[str, Any],
    findings: List[Dict[str, Any]],
    evidence_records: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Generates an organisation-specific compliance assessment.
    
    Status classifications per control:
    - IMPLEMENTED_REVIEWED: Technical controls passed AND verified evidence document reviewed.
    - IMPLEMENTED_EVIDENCE_MISSING: Technical scanner indicates control in place, but supporting policy/audit document not yet uploaded.
    - GAP_IDENTIFIED: Scanner identified active vulnerabilities violating this control, or manual check flagged a gap.
    - NOT_ASSESSED: Control has not yet had assessment questionnaire completed or scanner run.
    - NOT_APPLICABLE: Control excluded based on organization intake profile (e.g. Child Protection for B2B API company).
    - REQUIRES_EXPERT_REVIEW: Legal/governance control requiring qualified legal counsel, auditor, or DPO sign-off.
    """
    evidence_records = evidence_records or []
    applicability = evaluate_framework_applicability(profile)
    selected_fws = profile.get("selected_frameworks") or ["DPDP", "SOC2", "ISO27001"]

    # Index evidence by control_id
    evidence_by_control: Dict[str, List[Dict[str, Any]]] = {}
    for ev in evidence_records:
        cid = ev.get("control_id")
        if cid:
            evidence_by_control.setdefault(cid, []).append(ev)

    # Index findings by control_id
    findings_by_control: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        f_mappings = map_finding_to_compliance_frameworks(f)
        for m in f_mappings:
            cid = m.get("control_id")
            if cid:
                findings_by_control.setdefault(cid, []).append(f)

    assessment_results: Dict[str, Any] = {
        "organization_name": profile.get("company_name", "Acme AI Labs"),
        "country": profile.get("country", "India"),
        "assessed_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "applicability": applicability,
        "frameworks": {}
    }

    for fw_key in ["DPDP", "SOC2", "ISO27001", "GDPR"]:
        if fw_key not in selected_fws and not applicability.get(fw_key, {}).get("applicable"):
            continue

        fw_meta = FRAMEWORK_METADATA.get(fw_key, {})
        controls = CONTROLS_DATABASE.get(fw_key, [])
        control_evaluations = []

        total_controls = len(controls)
        gap_count = 0
        implemented_count = 0
        evidence_missing_count = 0
        expert_review_count = 0
        not_applicable_count = 0

        for ctrl in controls:
            cid = ctrl["control_id"]
            ctrl_findings = findings_by_control.get(cid, [])
            ctrl_evidence = evidence_by_control.get(cid, [])

            # Check applicability overrides
            is_na = False
            if fw_key == "DPDP" and cid == "DPDP-SEC-09":
                if "Minors / Children (<18 years)" not in profile.get("customer_types", []):
                    is_na = True

            if is_na:
                status = "NOT_APPLICABLE"
                status_label = "Not Applicable"
                not_applicable_count += 1
                rationale = "Excluded based on business profile: organization does not offer goods or services directed at minors."

            elif ctrl_findings:
                # Active technical vulnerabilities exist
                status = "GAP_IDENTIFIED"
                status_label = "Security Gap Identified"
                gap_count += 1
                rationale = f"{len(ctrl_findings)} active security finding(s) directly threaten this control. See remediation center."

            elif ctrl.get("expert_review_required") and not ctrl_evidence:
                status = "REQUIRES_EXPERT_REVIEW"
                status_label = "Requires Expert Review"
                expert_review_count += 1
                rationale = "This is a governance or legal control that cannot be validated purely via technical scans. Supporting documentation and legal sign-off required."

            elif ctrl_evidence:
                # Evidence has been uploaded and no technical findings violate it
                status = "IMPLEMENTED_REVIEWED"
                status_label = "Implemented & Evidence Reviewed"
                implemented_count += 1
                rationale = f"Technical checks passed and {len(ctrl_evidence)} supporting evidence document(s) uploaded."

            else:
                # Technical checks clean, but no policy document uploaded yet
                status = "IMPLEMENTED_EVIDENCE_MISSING"
                status_label = "Implemented (Evidence Missing)"
                evidence_missing_count += 1
                rationale = "Technical scanner checks passed with 0 related vulnerabilities, but formal policy or audit document has not yet been uploaded to Evidence Vault."

            control_evaluations.append({
                "control_id": cid,
                "section": ctrl.get("section"),
                "title": ctrl.get("title"),
                "official_ref": ctrl.get("official_ref"),
                "description": ctrl.get("description"),
                "category": ctrl.get("category"),
                "enforcement_phase": ctrl.get("enforcement_phase", "ACTIVE"),
                "effective_date": ctrl.get("effective_date"),
                "status": status,
                "status_label": status_label,
                "rationale": rationale,
                "evidence_count": len(ctrl_evidence),
                "active_findings_count": len(ctrl_findings),
                "assessment_questions": ctrl.get("assessment_questions", []),
                "evidence_requirements": ctrl.get("evidence_requirements", []),
                "recommended_actions": ctrl.get("recommended_actions", []),
                "expert_review_required": ctrl.get("expert_review_required", False)
            })

        applicable_count = total_controls - not_applicable_count
        readiness_score = int(round(((implemented_count * 1.0 + evidence_missing_count * 0.7) / max(applicable_count, 1)) * 100)) if applicable_count > 0 else 100

        assessment_results["frameworks"][fw_key] = {
            "metadata": fw_meta,
            "applicable": applicability.get(fw_key, {}).get("applicable", True),
            "readiness_score": readiness_score,
            "readiness_grade": "A" if readiness_score >= 85 else ("B" if readiness_score >= 70 else ("C" if readiness_score >= 50 else "D")),
            "total_controls": total_controls,
            "implemented_count": implemented_count,
            "evidence_missing_count": evidence_missing_count,
            "gap_count": gap_count,
            "expert_review_count": expert_review_count,
            "not_applicable_count": not_applicable_count,
            "controls": control_evaluations
        }

    return assessment_results
