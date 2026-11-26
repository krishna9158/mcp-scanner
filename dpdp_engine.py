"""
TrustAudit — DPDP Legal Requirements & Assessment Engine
=========================================================
Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023)
Digital Personal Data Protection Rules, 2025 (G.S.R. / Gazette Notifications)
Updated with October 2026 Removal of Difficulties Order & Current Statutory Timelines.

Legal Status / Commencement Status Definitions:
- In force (IN_FORCE): Commenced on 13 November 2025 (Preliminary & Board framework)
- In force (COMMENCED_NOV_2026): Commenced on 13 November 2026 (Section 6(9) & Rule 4 Consent Managers)
- Scheduled (SCHEDULED_MAY_2027): Scheduled to commence on 13 May 2027 (Substantive Data Fiduciary obligations)
- Not yet commenced: General provisions not yet formally notified with dates
- Not applicable: Provisions exempted under Section 17 / Rule 13
- Requires legal review: Sector-specific or Significant Data Fiduciary conditionally evaluated
"""

from typing import Dict, List, Any, Optional, Tuple
import datetime
import re

LEGAL_DATABASE_VERSION = "2026.11.4"
LAST_LEGAL_REVIEW = "2026-11-26"

STATUTORY_TIMELINE = [
    {
        "date": "11 August 2023",
        "title": "DPDP Act, 2023 Enacted",
        "description": "Received assent of the President of India and published in the Official Gazette as Act No. 22 of 2023.",
        "status": "COMPLETED",
        "badge": "Enacted"
    },
    {
        "date": "13 November 2025",
        "title": "DPDP Rules Notified (G.S.R. 846(E)) & Commencement Notification (G.S.R. 843(E))",
        "description": "Ministry of Electronics and Information Technology (MeitY) notified the DPDP Rules, 2025 under G.S.R. 846(E) alongside commencement notification G.S.R. 843(E), bringing preliminary and Data Protection Board institutional provisions into force (Sections 1, 2, 18–26, 33–35, 40).",
        "status": "COMPLETED",
        "badge": "In Force"
    },
    {
        "date": "October 2026",
        "title": "S.O. 5458(E) Removal of Difficulties Order, 2026",
        "description": "Official Gazette Order S.O. 5458(E) clarifying wording in Section 9(1) and changing the Section 10(2)(c)(ii) reference from 'audit' to 'data audit'.",
        "status": "COMPLETED",
        "badge": "Gazette Order"
    },
    {
        "date": "13 November 2026",
        "title": "Consent Manager Provisions Commenced",
        "description": "Section 6(9), Section 27(1)(d), and Rule 4 provisions governing Consent Manager registration and obligations commenced.",
        "status": "COMPLETED",
        "badge": "In Force"
    },
    {
        "date": "13 May 2027",
        "title": "Substantive Data Fiduciary Obligations Scheduled",
        "description": "General obligations of Data Fiduciaries (Sections 3–17 and substantive Rules 3, 5–16, 22–23 covering Notice, Consent, Section 8 safeguards & breach intimations, Retention, Children's Data, SDFs, and Data Principal Rights) scheduled to take effect.",
        "status": "SCHEDULED",
        "badge": "Scheduled Commencement"
    }
]

# ==============================================================================
# STRUCTURED DPDP LEGAL REQUIREMENTS DATABASE (FULL PHASE 4 SCHEMA)
# ==============================================================================

DPDP_REQUIREMENTS: List[Dict[str, Any]] = [
    {
        "id": "DPDP-SEC-03",
        "rule_id": "DPDP-SEC-03",
        "section": "Section 3",
        "legal_reference": "Section 3, Rule 2",
        "rule_ref": "Rule 2",
        "title": "Applicability & Material Scope",
        "rule_title": "Applicability & Material Scope",
        "description": "Processing of digital personal data within the territory of India where collected in digital form or digitised subsequently; and processing outside India if in connection with offering goods or services to Data Principals within India.",
        "explanation": "Establishes territorial and material applicability under the DPDP Act 2023. Governs all digital personal records collected online, via mobile apps, or converted from paper files into software databases.",
        "applicability_conditions": ["processes_digital_personal_data"],
        "industry_conditions": ["all", "hospitals", "clinics", "diagnostic_centres", "saas", "ecommerce", "professional_services", "education"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Lawful processing",
        "readiness_category": "Governance & Scoping",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec3_scope",
                "question": "Does your organisation process personal data in digital form or convert non-digital personal records into digital format?",
                "type": "boolean",
                "weight": "high"
            },
            {
                "qid": "q_sec3_territory",
                "question": "Do you offer goods, healthcare services, educational facilities, or SaaS to individuals located in India?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Data Processing Scope Document",
            "Personal Data Inventory & Asset Register",
            "Applicability Assessment Sign-off"
        ],
        "recommended_action": "Establish a documented perimeter defining all digital personal data collected, stored, or processed across your applications, clinics, billing desks, and third-party vendors.",
        "remediation_guidance": "Establish a documented perimeter defining all digital personal data collected, stored, or processed across your applications, clinics, billing desks, and third-party vendors.",
        "verification_procedure": "Verify that all systems processing Indian resident data are cataloged with clear processing perimeters.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "The Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023), Section 3; S.O. 5064(E)",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-04-06",
        "rule_id": "DPDP-SEC-04-06",
        "section": "Sections 4 & 6",
        "legal_reference": "Sections 4 & 6, Rule 3",
        "rule_ref": "Rules 3 & 4",
        "title": "Valid Consent & Itemised Architecture",
        "rule_title": "Valid Consent & Itemised Consent Architecture",
        "description": "Personal data may be processed only for lawful purposes with affirmative, unbundled, free, specific, informed, and unconditional consent of the Data Principal.",
        "explanation": "Prohibits pre-ticked consent checkboxes, bundled terms of service, and conditional service access. Consent must be granular, itemised by purpose, and explicitly affirmed.",
        "applicability_conditions": ["relies_on_consent"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Consent management",
        "readiness_category": "Consent Architecture",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "detection_method": "HYBRID",
        "assessment_questions": [
            {
                "qid": "q_sec6_affirmative",
                "question": "Are all consent checkboxes un-ticked by default on your public forms and apps?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec6_unbundled",
                "question": "Is consent requested separately from general Terms of Service or Privacy Policy acceptances?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Consent Capture Wireframes & Screenshots",
            "Consent Database Log Schema (Timestamp, IP, Version)",
            "Itemised Purpose Checkbox Specification"
        ],
        "recommended_action": "Unbundle consent from Terms of Service. Ensure checkboxes default to unchecked and consent logs record timestamp, notice version, and specific purpose.",
        "remediation_guidance": "Unbundle consent from Terms of Service. Ensure checkboxes default to unchecked and consent logs record timestamp, notice version, and specific purpose.",
        "verification_procedure": "Inspect website forms and registration APIs to confirm checkboxes are unticked and logs store immutable audit records.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 4 & Section 6(1)-(3); DPDP Rules 2025, Rule 3",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-05",
        "rule_id": "DPDP-SEC-05",
        "section": "Section 5",
        "legal_reference": "Section 5(1), Rule 3",
        "rule_ref": "Rule 3",
        "title": "Privacy Notice in Plain Language & 8th Schedule",
        "rule_title": "Itemised Privacy Notice in Plain Language & 8th Schedule Availability",
        "description": "Every consent request must be preceded or accompanied by an itemised notice stating the personal data to be collected, purpose, rights, and Grievance Officer details, available in English and 22 Eighth Schedule languages.",
        "explanation": "Requires clear, standalone privacy notices specifying personal data categories, exact purpose of use, instructions on how to withdraw consent or exercise rights, and details of the Grievance Redressal Officer.",
        "applicability_conditions": ["collects_personal_data"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Privacy notices",
        "readiness_category": "Transparency & Notices",
        "severity": "HIGH",
        "confidence": "HIGH",
        "detection_method": "PASSIVE_WEB_CRAWLER",
        "assessment_questions": [
            {
                "qid": "q_sec5_notice_present",
                "question": "Do you present a clear notice to individuals at or before the time of collecting personal data?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec5_grievance_contact",
                "question": "Does your notice explicitly name a designated Grievance Officer and contact mechanism?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Published Section 5 Privacy Notice Document",
            "Multi-lingual (Eighth Schedule) Notice Translations",
            "Form-level Notice Link Screen Captures"
        ],
        "recommended_action": "Draft and publish a Section 5 notice specifying personal data collected, specific processing purposes, rights mechanisms, and designated Grievance Officer email.",
        "remediation_guidance": "Draft and publish a Section 5 notice specifying personal data collected, specific processing purposes, rights mechanisms, and designated Grievance Officer email.",
        "verification_procedure": "Crawl public website to verify privacy policy presence, contact email, grievance officer designation, and itemised purpose breakdown.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 5; DPDP Rules 2025, Rule 3",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-06-04",
        "rule_id": "DPDP-SEC-06-04",
        "section": "Section 6(4)-(6)",
        "legal_reference": "Section 6(4)-(6), Rule 3(4)",
        "rule_ref": "Rule 3(4)",
        "title": "Consent Withdrawal & Processor Cascading",
        "rule_title": "Consent Withdrawal & Processor Cascading",
        "description": "Data Principals have the statutory right to withdraw consent with the same ease with which it was given; processing must cease and cascade to third-party processors unless retention is required by other Indian laws.",
        "explanation": "Enforces frictionless consent withdrawal. Upon receiving withdrawal, processing must immediately cease and instructions must cascade down to all external processors (e.g. labs, SMS gateways, cloud providers).",
        "applicability_conditions": ["relies_on_consent"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Consent management",
        "readiness_category": "Consent Architecture",
        "severity": "HIGH",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec6_withdrawal_ease",
                "question": "Can customers or patients withdraw their consent through a 1-click or single web/email interface?",
                "type": "boolean",
                "weight": "high"
            },
            {
                "qid": "q_sec6_cascade",
                "question": "Do you have automated procedures or contractual SLA to notify third-party processors when consent is withdrawn?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Consent Withdrawal Standard Operating Procedure",
            "Processor Notification API / Dispatch Records",
            "Exception Registry for Statutory Retentions"
        ],
        "recommended_action": "Establish an automated or structured workflow allowing individuals to revoke consent with equivalent ease, notifying downstream software vendors and labs.",
        "remediation_guidance": "Establish an automated or structured workflow allowing individuals to revoke consent with equivalent ease, notifying downstream software vendors and labs.",
        "verification_procedure": "Audit consent withdrawal desk and test processor cascading notifications.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 6(4)-(6); DPDP Rules 2025, Rule 3(4)",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-07",
        "rule_id": "DPDP-SEC-07",
        "section": "Section 7",
        "legal_reference": "Section 7(a)-(i)",
        "rule_ref": "Statutory Bases",
        "title": "Legitimate Uses (Statutory Non-Consent Grounds)",
        "rule_title": "Legitimate Uses (Statutory Non-Consent Grounds)",
        "description": "Processing personal data without consent strictly restricted to statutorily enumerated grounds: voluntary provision, legal obligations, medical emergency, epidemics, public order, and employment.",
        "explanation": "No open-ended legitimate interest exists under DPDP. Non-consent processing is lawful solely under Section 7 grounds like medical emergency threat to life (7(e)), legal duty (7(c)), or employment (7(i)).",
        "applicability_conditions": ["processes_without_consent"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Lawful processing",
        "readiness_category": "Legal Bases & RoPA",
        "severity": "HIGH",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec7_grounds",
                "question": "Are all processing streams without consent strictly mapped to Section 7 statutory grounds (e.g., medical emergency, employment, legal compliance)?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Record of Processing Activities (RoPA) with Section 7 Mapping",
            "Emergency Medical Data Processing Protocol",
            "Employee Data Notice & Legitimate Use Memo"
        ],
        "recommended_action": "Audit all data processing streams that do not obtain consent and map them to explicit Section 7 statutory grounds.",
        "remediation_guidance": "Audit all data processing streams that do not obtain consent and map them to explicit Section 7 statutory grounds.",
        "verification_procedure": "Inspect RoPA register to confirm every non-consent processing activity has a verified statutory clause citation.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 7",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-08-01",
        "rule_id": "DPDP-SEC-08-01",
        "section": "Section 8(1) & 8(2)",
        "legal_reference": "Section 8(1)-(2), Act",
        "rule_ref": "Section 8(1)-(2)",
        "title": "Data Fiduciary Accountability & Vendor DPA Contracts",
        "rule_title": "Data Fiduciary Responsibility & Data Processor Agreement (DPA) Execution",
        "description": "The Data Fiduciary remains accountable for all processing by Data Processors and may engage processors only under valid contracts binding them to DPDP standards.",
        "explanation": "Mandates that external vendors, cloud services, laboratories, and billing software may only process data under a legally binding Data Processing Agreement with clear breach notification and erasure terms.",
        "applicability_conditions": ["uses_third_party_processors"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Data processor management",
        "readiness_category": "Vendor & Processor Governance",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec8_dpa_contracts",
                "question": "Do you have signed Data Processing Agreements (DPA) with all cloud hosting, diagnostic software, and payment vendors?",
                "type": "boolean",
                "weight": "critical"
            }
        ],
        "evidence_required": [
            "Executed Data Processing Agreements (DPAs)",
            "Third-Party Vendor Risk Assessment Register",
            "Vendor Security & Breach Indemnity Addendums"
        ],
        "recommended_action": "Review all vendor contracts (HMS, LIMS, AWS, Razorpay, SMS gateways) and execute DPDP-compliant Data Processing Agreements.",
        "remediation_guidance": "Review all vendor contracts (HMS, LIMS, AWS, Razorpay, SMS gateways) and execute DPDP-compliant Data Processing Agreements.",
        "verification_procedure": "Verify presence of executed DPAs in the Evidence Vault covering all cataloged third-party processors.",
        "last_reviewed_date": "2026-11-26",
        "rule_version": "v2.2",
        "official_source_reference": "DPDP Act 2023, Section 8(1)-(2)",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-08-03",
        "rule_id": "DPDP-SEC-08-03",
        "section": "Section 8(3)",
        "legal_reference": "Section 8(3), Act",
        "rule_ref": "Section 8(3)",
        "title": "Data Quality, Accuracy & Consistency",
        "rule_title": "Data Quality, Completeness & Accuracy Assurance",
        "description": "Ensure personal data processed is accurate, complete, and consistent if used to make decisions affecting the Data Principal or shared with another Data Fiduciary.",
        "explanation": "Applies especially to diagnostic results, clinical records, credit evaluations, and employment decisions where inaccurate data can directly harm the individual.",
        "applicability_conditions": ["makes_decisions_affecting_principals"],
        "industry_conditions": ["hospitals", "clinics", "diagnostic_centres", "fintech", "education"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Documentation and accountability",
        "readiness_category": "Data Quality & Operations",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec8_accuracy",
                "question": "Do you implement validation controls ensuring diagnostic reports and billing identities are verified before distribution?",
                "type": "boolean",
                "weight": "medium"
            }
        ],
        "evidence_required": [
            "Data Quality & Verification Standard Operating Procedure",
            "Pathology / Clinical Sign-off Policy",
            "Customer Data Correction Log"
        ],
        "recommended_action": "Implement dual-verification checks on diagnostic reports and customer identity records before sharing.",
        "remediation_guidance": "Implement dual-verification checks on diagnostic reports and customer identity records before sharing.",
        "verification_procedure": "Review data quality procedures and error-correction turnaround times.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 8(3)",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-08-05",
        "rule_id": "DPDP-SEC-08-05",
        "section": "Section 8(5)",
        "legal_reference": "Section 8(5), Rule 6",
        "rule_ref": "Rule 6",
        "title": "Reasonable Security Safeguards to Prevent Breaches",
        "rule_title": "Implementation of Reasonable Security Safeguards",
        "description": "Every Data Fiduciary must implement reasonable security safeguards, including encryption, access control, regular vulnerability assessment, and audit logging to prevent personal data breaches.",
        "explanation": "Statutory duty under Section 8(5) carrying the highest penalty ceiling (up to ₹250 crore) under Schedule to the Act. Requires technical and organizational measures to safeguard data against loss, leak, or breach.",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Reasonable security safeguards",
        "readiness_category": "Technical & Security Safeguards",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "detection_method": "HYBRID",
        "assessment_questions": [
            {
                "qid": "q_sec8_encryption",
                "question": "Is digital personal data protected in transit (HTTPS/TLS) and stored safely using appropriate technical controls (encryption, obfuscation, or access controls)?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec8_rbac",
                "question": "Do you enforce role-based access control (RBAC) and Multi-Factor Authentication (MFA) for staff accessing sensitive data?",
                "type": "boolean",
                "weight": "critical"
            }
        ],
        "evidence_required": [
            "Information Security Policy Document",
            "Reasonable Security Safeguards & Encryption Standards (Rule 6)",
            "Vulnerability Assessment & Penetration Testing (VAPT) Report",
            "MFA & RBAC Access Audit Logs"
        ],
        "recommended_action": "Implement reasonable security safeguards under Section 8(5) and Rule 6: HTTPS transport security, appropriate encryption/obfuscation, access control, backup, and logging.",
        "remediation_guidance": "Implement reasonable security safeguards under Section 8(5) and Rule 6: HTTPS transport security, appropriate encryption/obfuscation, access control, backup, and logging.",
        "verification_procedure": "Inspect TLS certificates, security response headers, password hashing algorithms, and vulnerability assessment certifications.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 8(5); DPDP Rules 2025, Rule 6; Schedule Item 1",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-08-06",
        "rule_id": "DPDP-SEC-08-06",
        "section": "Section 8(6)",
        "legal_reference": "Section 8(6), Rule 7",
        "rule_ref": "Rule 7",
        "title": "Breach Management & Dual-Stage Board Intimation",
        "rule_title": "Personal Data Breach Management & Dual-Stage Notification",
        "description": "In the event of a personal data breach, intimate the Data Protection Board of India and each affected Data Principal via dual-stage intimation (initial without delay; detailed supplementary within 72 hours).",
        "explanation": "Requires an established incident response process capable of detecting breaches, containing impact, and drafting dual-stage intimations (Form A initial report + Form B 72-hour comprehensive report).",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Personal data breach response",
        "readiness_category": "Incident & Breach Response",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec8_breach_sop",
                "question": "Do you have an operational Incident Response Procedure to notify the Board and individuals within 72 hours of a personal data breach?",
                "type": "boolean",
                "weight": "critical"
            }
        ],
        "evidence_required": [
            "Data Breach Incident Response Standard Operating Procedure",
            "Rule 7 Form A Draft Notification Template",
            "Data Principal Breach Notice Formats"
        ],
        "recommended_action": "Establish a dual-stage breach response workflow with predefined Board notification templates and customer alert drafts.",
        "remediation_guidance": "Establish a dual-stage breach response workflow with predefined Board notification templates and customer alert drafts.",
        "verification_procedure": "Review operational incident response desk and simulate Tabletop Breach notification exercise.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 8(6); DPDP Rules 2025, Rule 7; Schedule Item 2",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-08-07",
        "rule_id": "DPDP-SEC-08-07",
        "section": "Section 8(7) & 8(8)",
        "legal_reference": "Section 8(7)-(8), Rule 8",
        "rule_ref": "Rule 8",
        "title": "Data Retention & Purpose-Cessation Erasure",
        "rule_title": "Data Retention Limits & Purpose-Cessation Erasure",
        "description": "Erase personal data upon the purpose of collection being served or upon withdrawal of consent, whichever is earlier, unless retention is mandated by another Indian statute.",
        "explanation": "Strict data minimization rule. Prohibits indefinite storage of customer or patient records. Requires documented retention schedules with automated or verified purging.",
        "applicability_conditions": ["retains_personal_data"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Data retention and erasure",
        "readiness_category": "Data Lifecycle & Retention",
        "severity": "HIGH",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec8_retention_schedule",
                "question": "Do you maintain a documented Data Retention Schedule defining specific years for each category before deletion?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Data Retention & Disposal Policy Document",
            "Database Automated Purge Configuration",
            "Cryptographic Data Deletion Certificates"
        ],
        "recommended_action": "Document specific retention periods for all data categories (e.g., 5 years for clinical records, 8 years for invoices) and configure automated disposal.",
        "remediation_guidance": "Document specific retention periods for all data categories (e.g., 5 years for clinical records, 8 years for invoices) and configure automated disposal.",
        "verification_procedure": "Examine retention schedule in RoPA register against sector-specific statutory retention requirements.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 8(7)-(8); DPDP Rules 2025, Rule 8",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-08-10",
        "rule_id": "DPDP-SEC-08-10",
        "section": "Section 8(10) & 8(11)",
        "legal_reference": "Section 8(10)-(11), Rule 9",
        "rule_ref": "Rule 9",
        "title": "Grievance Redressal Mechanism & DPO Contact",
        "rule_title": "Grievance Redressal Mechanism & DPO / Contact Person Designation",
        "description": "Establish a readily accessible grievance redressal mechanism and publish the business contact details of a designated Grievance Officer on all public portals.",
        "explanation": "Every business collecting digital data must provide an easy grievance escalation channel (email/portal) to resolve customer privacy disputes before external complaints to the DPBI.",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Grievance redressal",
        "readiness_category": "Grievance Redressal",
        "severity": "HIGH",
        "confidence": "HIGH",
        "detection_method": "PASSIVE_WEB_CRAWLER",
        "assessment_questions": [
            {
                "qid": "q_sec8_grievance_officer",
                "question": "Is a designated Grievance Officer explicitly named with contact email and physical address on your public website?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Grievance Redressal Standard Operating Procedure",
            "Public Website Grievance Contact Page URL",
            "Grievance Ticket Management Log"
        ],
        "recommended_action": "Designate a Grievance Officer and publish their official contact email and postal address in your privacy policy and website footer.",
        "remediation_guidance": "Designate a Grievance Officer and publish their official contact email and postal address in your privacy policy and website footer.",
        "verification_procedure": "Crawl target website footer and privacy notice for grievance email patterns and officer designations.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 8(10)-(11); DPDP Rules 2025, Rule 9",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-09",
        "rule_id": "DPDP-SEC-09",
        "section": "Section 9",
        "legal_reference": "Section 9, Rule 10",
        "rule_ref": "Rule 10",
        "title": "Children's Personal Data & Verifiable Parental Consent",
        "rule_title": "Processing of Children's & Disabled Persons' Personal Data",
        "description": "Obtain verifiable parental consent before processing personal data of children under 18; strict ban on behavioral monitoring, tracking, or targeted advertising directed at children.",
        "explanation": "Special protections for minors. Requires verifiable guardian consent before handling pediatric or student data, and strictly bans ad-targeting or behavioral profiling.",
        "applicability_conditions": ["processes_minor_data"],
        "industry_conditions": ["hospitals", "clinics", "diagnostic_centres", "education", "gaming", "ecommerce"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Children's personal data",
        "readiness_category": "Special Protections",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "detection_method": "HYBRID",
        "assessment_questions": [
            {
                "qid": "q_sec9_parental_consent",
                "question": "Do you obtain verifiable consent from parents or legal guardians before creating minor patient or student profiles?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec9_no_tracking",
                "question": "Can you verify that no third-party behavioral analytics or advertising pixels are active on child-accessible portals?",
                "type": "boolean",
                "weight": "critical"
            }
        ],
        "evidence_required": [
            "Verifiable Parental Consent Verification Flow",
            "Child Safeguard Policy & Pediatric Protocol",
            "Tracker Blacklist Verification on Minor Pages"
        ],
        "recommended_action": "Deploy verifiable guardian consent workflows for minors under 18, and ensure all ad trackers and analytics pixels are disabled on minor-facing portals.",
        "remediation_guidance": "Deploy verifiable guardian consent workflows for minors under 18, and ensure all ad trackers and analytics pixels are disabled on minor-facing portals.",
        "verification_procedure": "Inspect website scanner trackers and test minor registration / pediatric intake forms for guardian consent steps.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 9 (clarified under S.O. 5458(E) Removal of Difficulties Order, 2026); G.S.R. 846(E) Rule 10; Schedule Item 3",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-10",
        "rule_id": "DPDP-SEC-10",
        "section": "Section 10",
        "legal_reference": "Section 10 (read with S.O. 5458(E) Removal of Difficulties Order, Oct 2026)",
        "rule_ref": "Section 10 & Rule 11",
        "title": "Significant Data Fiduciary (SDF) Obligations",
        "rule_title": "Significant Data Fiduciary Obligations (DPO, DPIA & Periodic Data Audits)",
        "description": "Entities notified as Significant Data Fiduciaries must appoint a resident Data Protection Officer, engage an independent data auditor (updated from 'audit' to 'data audit' in Section 10(2)(c)(ii) via S.O. 5458(E)), and conduct periodic Data Protection Impact Assessments (DPIA).",
        "explanation": "Applies conditionally to high-volume or high-risk entities designated by the Central Government based on data volume, sensitivity, and risk to sovereignty.",
        "applicability_conditions": ["designated_as_sdf"],
        "industry_conditions": ["hospitals", "large_diagnostic_chains", "fintech", "large_saas", "telecom"],
        "effective_date": "13 May 2027",
        "commencement_status": "Requires legal review",
        "legal_status": "CONDITIONAL",
        "obligation_type": "Upcoming obligation",
        "category": "Significant Data Fiduciary obligations",
        "readiness_category": "Special Protections",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec10_dpo_appointed",
                "question": "Has your Board formally appointed an India-resident Data Protection Officer reporting to senior leadership?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Data Protection Officer (DPO) Appointment Resolution",
            "Data Protection Impact Assessment (DPIA) Report",
            "Independent Privacy Audit Certificate"
        ],
        "recommended_action": "Assess threshold criteria for Significant Data Fiduciary designation and prepare DPIA frameworks if operating large healthcare networks or fin-tech systems.",
        "remediation_guidance": "Assess threshold criteria for Significant Data Fiduciary designation and prepare DPIA frameworks if operating large healthcare networks or fin-tech systems.",
        "verification_procedure": "Examine entity scale and confirm if designated under Section 10 notification.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 10; DPDP Rules 2025, Rule 11; Schedule Item 4",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-11-14",
        "rule_id": "DPDP-SEC-11-14",
        "section": "Sections 11–14",
        "legal_reference": "Sections 11–14, Rule 14",
        "rule_ref": "Rule 14",
        "title": "Data Principal Rights Management Desk",
        "rule_title": "Data Principal Rights (Access, Correction, Erasure & Nomination)",
        "description": "Establish workflows to process Data Principal requests for information access, correction of inaccurate data, purpose-cessation erasure, and nominee designation.",
        "explanation": "Statutory rights desk ensuring individuals can query what personal data is held, request updates, demand deletion, and appoint a nominee.",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Data Principal rights",
        "readiness_category": "Data Principal Rights",
        "severity": "HIGH",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec11_rights_portal",
                "question": "Do you offer a self-service or ticketing mechanism for users to request access or correction of their personal records?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Data Principal Rights Request Handling Procedure",
            "Rights Ticket Management System Logs",
            "Nomination Registration Format"
        ],
        "recommended_action": "Set up a customer privacy request intake channel and track grievances and rights requests cleanly with published timelines and verification steps.",
        "remediation_guidance": "Set up a customer privacy request intake channel and track grievances and rights requests cleanly with published timelines and verification steps.",
        "verification_procedure": "Audit customer privacy requests ticketing desk and measure resolution SLA performance.",
        "last_reviewed_date": "2026-11-26",
        "rule_version": "v2.2",
        "official_source_reference": "DPDP Act 2023, Sections 11, 12, 13, 14; DPDP Rules 2025, Rule 14",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-16",
        "rule_id": "DPDP-SEC-16",
        "section": "Section 16",
        "legal_reference": "Section 16, Rule 13",
        "rule_ref": "Rule 13",
        "title": "Cross-Border Transfer Controls (Negative List Compliance)",
        "rule_title": "Cross-Border Personal Data Transfer Verification",
        "description": "Ensure personal data is not transferred to any foreign country or territory restricted under Central Government negative list notifications.",
        "explanation": "DPDP Act follows a negative list approach (transfers allowed to most countries unless explicitly blacklisted by MeitY gazette orders).",
        "applicability_conditions": ["transfers_data_outside_india"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled",
        "legal_status": "SCHEDULED_MAY_2027",
        "obligation_type": "Upcoming obligation",
        "category": "Documentation and accountability",
        "readiness_category": "Cross-Border & Governance",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "detection_method": "ORGANISATIONAL_ASSESSMENT",
        "assessment_questions": [
            {
                "qid": "q_sec16_crossborder",
                "question": "Do your cloud systems (AWS, Azure, Google Cloud) store personal data exclusively in Indian regions (e.g. Mumbai / Hyderabad)?",
                "type": "boolean",
                "weight": "medium"
            }
        ],
        "evidence_required": [
            "Data Residency & Cloud Storage Location Architecture",
            "Subprocessor Cross-Border Transfer Assessment",
            "Vendor Data Localization Attestation"
        ],
        "recommended_action": "Verify cloud regions in AWS, GCP, Azure, or vendor contracts to ensure patient and customer databases reside in India or compliant territories.",
        "remediation_guidance": "Verify cloud regions in AWS, GCP, Azure, or vendor contracts to ensure patient and customer databases reside in India or compliant territories.",
        "verification_procedure": "Inspect vendor storage regions and cloud infrastructure resource locations.",
        "last_reviewed_date": "2026-11-22",
        "rule_version": "v2.1",
        "official_source_reference": "DPDP Act 2023, Section 16; DPDP Rules 2025, Rule 13",
        "expert_review_required": False
    }
]

# ==============================================================================
# 7 INDUSTRY PRE-CONFIGURED TEMPLATES (PHASE 9)
# ==============================================================================

INDUSTRY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "hospitals": {
        "name": "Hospitals & Multi-Speciality Medical Centres",
        "description": "Tailored for hospitals handling inpatient records, surgical charts, emergency admissions (Section 7(e)), health insurance TPA claims, minor pediatric consent, and hospital management software.",
        "departments": ["Inpatient & ICU Wards", "Emergency Care & Triage", "Operation Theatres & Surgery", "Pathology & Radiodiagnostics", "Billing, TPA Insurance & Cashless", "Medical Records Department (MRD)", "Hospital Administration & HR"],
        "typical_principals": ["Inpatients & Outpatients", "Minors / Pediatric Patients (Parents / Legal Guardians)", "Emergency Patients (Sec 7(e) Legitimate Use)", "Consulting Doctors & Medical Officers", "Nursing Staff & Technicians", "Insurance TPAs & Third-Party Auditors"],
        "sample_data_inventory": [
            {
                "category": "Patient Demographic Information",
                "principal_type": "Patients",
                "source": "Reception Desk Registration / Web Appointment",
                "purpose": "Patient identification, contact, appointment scheduling",
                "legal_basis": "DPDP Section 6 (Consent) & Section 5 Notice",
                "collection_method": "Registration Paper Form / Tablet UI",
                "storage_system": "Clinic Management Software (Local & Cloud Backup)",
                "department": "Reception & Patient Intake",
                "owner": "Clinic Frontdesk Manager",
                "external_recipients": "SMS Gateway Provider (Appointment alerts)",
                "processor": "Hospital Management System (HMS) SaaS",
                "retention_period": "3 years from last consultation (Clinical Establishments Act)",
                "deletion_method": "Automated soft-archive, database purging after retention",
                "international_transfer": "None (Domestic India AWS Mumbai ap-south-1)"
            },
            {
                "category": "Medical & Clinical Diagnostic Reports",
                "principal_type": "Patients",
                "source": "Laboratory Analyzers & Radiologist Assessment",
                "purpose": "Medical diagnosis, pathology analysis, treatment planning",
                "legal_basis": "DPDP Section 6 (Consent) & Section 7(e) Medical Emergency",
                "collection_method": "Direct LIMS System / Physician Entry",
                "storage_system": "Picture Archiving & Communication System (PACS) / LIMS",
                "department": "Laboratory & Diagnostics",
                "owner": "Chief Pathologist / Medical Director",
                "external_recipients": "Referring Physician, Patient via Secure Link",
                "processor": "Cloud Diagnostics Software Provider",
                "retention_period": "5 years (Clinical Establishment Records Rules)",
                "deletion_method": "Cryptographic file shredding after statutory period",
                "international_transfer": "None (India hosted)"
            },
            {
                "category": "Billing, Invoice & Insurance Records",
                "principal_type": "Patients",
                "source": "Patient Billing Counter",
                "purpose": "Invoice generation, payment reconciliation, insurance TPA claims",
                "legal_basis": "DPDP Section 7(c) (Legal Obligation) & Section 6",
                "collection_method": "POS Terminal / Accounting Software",
                "storage_system": "Tally / Cloud ERP Billing Database",
                "department": "Billing & Accounts",
                "owner": "Finance Officer",
                "external_recipients": "Insurance Third Party Administrators (TPAs), GSTN",
                "processor": "Payment Gateway / Accounting Cloud",
                "retention_period": "8 years (Income Tax Act & GST Regulations)",
                "deletion_method": "Physical shredding of paper bills, DB record purge",
                "international_transfer": "None"
            },
            {
                "category": "Employee & Medical Staff Records",
                "principal_type": "Doctors & Staff",
                "source": "HR Onboarding & Medical Council Credentials",
                "purpose": "Employment administration, salary processing, medical credentialing",
                "legal_basis": "DPDP Section 7(i) (Employment purposes)",
                "collection_method": "Employment Contract / KYC Submission",
                "storage_system": "HRMS Cloud System",
                "department": "Human Resources & Staff",
                "owner": "HR Manager",
                "external_recipients": "PF / ESI Department, Payroll Bank",
                "processor": "HRMS Software Provider",
                "retention_period": "Duration of employment + 7 years",
                "deletion_method": "Secure digital destruction upon expiry",
                "international_transfer": "None"
            }
        ],
        "key_remediation_templates": [
            "Hospital Inpatient Privacy Notice & Itemised Consent",
            "Emergency Medical Care Processing Protocol (Section 7(e))",
            "Insurance TPA Data Processing Agreement",
            "Medical Records Retention & Purging Schedule",
            "Pediatric Verifiable Parental Consent Workflow (Section 9)"
        ]
    },
    "clinics": {
        "name": "Outpatient Clinics & Group Practices",
        "description": "Tailored for medical practitioners, dental clinics, polyclinics, and outpatient specialists handling appointments, prescriptions, diagnostic referrals, and patient SMS notifications.",
        "departments": ["Reception & Patient Intake", "Doctor Consultation Chamber", "Pharmacy & Prescription Dispensing", "Billing & Fee Collection", "Website & Telehealth Booking"],
        "typical_principals": ["Outpatients", "Minor Patients (Guardians)", "Attending Doctors", "Clinic Reception Staff"],
        "sample_data_inventory": [
            {
                "category": "Patient Demographic Information",
                "principal_type": "Patients",
                "source": "Reception Desk Registration / Web Appointment",
                "purpose": "Patient identification, contact, appointment scheduling",
                "legal_basis": "DPDP Section 6 (Consent) & Section 5 Notice",
                "collection_method": "Registration Paper Form / Tablet UI",
                "storage_system": "Clinic Management Software (Local & Cloud Backup)",
                "department": "Reception & Patient Intake",
                "owner": "Clinic Frontdesk Manager",
                "external_recipients": "SMS Gateway Provider (Appointment alerts)",
                "processor": "Hospital Management System (HMS) SaaS",
                "retention_period": "3 years from last consultation (Clinical Establishments Act)",
                "deletion_method": "Automated soft-archive, database purging after retention",
                "international_transfer": "None (Domestic India AWS Mumbai ap-south-1)"
            },
            {
                "category": "Medical & Clinical Diagnostic Reports",
                "principal_type": "Patients",
                "source": "Laboratory Analyzers & Radiologist Assessment",
                "purpose": "Medical diagnosis, pathology analysis, treatment planning",
                "legal_basis": "DPDP Section 6 (Consent) & Section 7(e) Medical Emergency",
                "collection_method": "Direct LIMS System / Physician Entry",
                "storage_system": "Picture Archiving & Communication System (PACS) / LIMS",
                "department": "Laboratory & Diagnostics",
                "owner": "Chief Pathologist / Medical Director",
                "external_recipients": "Referring Physician, Patient via Secure Link",
                "processor": "Cloud Diagnostics Software Provider",
                "retention_period": "5 years (Clinical Establishment Records Rules)",
                "deletion_method": "Cryptographic file shredding after statutory period",
                "international_transfer": "None (India hosted)"
            },
            {
                "category": "Billing, Invoice & Insurance Records",
                "principal_type": "Patients",
                "source": "Patient Billing Counter",
                "purpose": "Invoice generation, payment reconciliation, insurance TPA claims",
                "legal_basis": "DPDP Section 7(c) (Legal Obligation) & Section 6",
                "collection_method": "POS Terminal / Accounting Software",
                "storage_system": "Tally / Cloud ERP Billing Database",
                "department": "Billing & Accounts",
                "owner": "Finance Officer",
                "external_recipients": "Insurance Third Party Administrators (TPAs), GSTN",
                "processor": "Payment Gateway / Accounting Cloud",
                "retention_period": "8 years (Income Tax Act & GST Regulations)",
                "deletion_method": "Physical shredding of paper bills, DB record purge",
                "international_transfer": "None"
            },
            {
                "category": "Employee & Medical Staff Records",
                "principal_type": "Doctors & Staff",
                "source": "HR Onboarding & Medical Council Credentials",
                "purpose": "Employment administration, salary processing, medical credentialing",
                "legal_basis": "DPDP Section 7(i) (Employment purposes)",
                "collection_method": "Employment Contract / KYC Submission",
                "storage_system": "HRMS Cloud System",
                "department": "Human Resources & Staff",
                "owner": "HR Manager",
                "external_recipients": "PF / ESI Department, Payroll Bank",
                "processor": "HRMS Software Provider",
                "retention_period": "Duration of employment + 7 years",
                "deletion_method": "Secure digital destruction upon expiry",
                "international_transfer": "None"
            }
        ],
        "key_remediation_templates": [
            "Clinic Patient Privacy Notice & Itemised Consent Form",
            "Appointment Booking Form Notice & Checkbox Configuration",
            "Clinic Management Software Vendor DPA",
            "Prescription Data Protection SOP"
        ]
    },
    "diagnostic_centres": {
        "name": "Diagnostic Centres & Pathology Laboratories",
        "description": "Tailored for diagnostic chains, blood testing laboratories, and radiology scanning centres handling test orders, pathology results, PACS imaging, home sample collection, and PDF report dispatch.",
        "departments": [
            "Home Sample Phlebotomy & Collection",
            "Sample Receiving & Barcoding",
            "Pathology & Biochemistry Testing",
            "Radiology & Ultrasound Imaging (PACS)",
            "Report Dispatch & Patient Portal",
            "Billing & Diagnostic Partner Referrals"
        ],
        "typical_principals": [
            "Diagnostic Test Patients",
            "Home Collection Clients",
            "Referring Doctors & Clinics",
            "Laboratory Technicians & Pathologists"
        ],
        "sample_data_inventory": [
            {
                "category": "Blood & Pathology Test Results",
                "principal_type": "Diagnostic Patients",
                "source": "Laboratory Automated Analyzers & LIMS",
                "purpose": "Clinical biochemical diagnosis, doctor referral reporting",
                "legal_basis": "DPDP Section 6 (Consent) & Section 5 Notice",
                "collection_method": "Analyzer Direct LIMS Interface",
                "storage_system": "Laboratory Information Management System (LIMS) Cloud",
                "department": "Pathology & Biochemistry Testing",
                "owner": "Chief Pathologist",
                "external_recipients": "Patient via encrypted PDF link, Referring Doctor",
                "processor": "LIMS Cloud Software Vendor",
                "retention_period": "5 years (Clinical Establishment Rules & NABL requirements)",
                "deletion_method": "Automated database purge with SHA-256 certificate",
                "international_transfer": "None (India hosted)"
            },
            {
                "category": "Radiology Scans & PACS DICOM Images",
                "principal_type": "Diagnostic Patients",
                "source": "MRI / CT / X-Ray Medical Scanners",
                "purpose": "Radiological diagnosis and reporting",
                "legal_basis": "DPDP Section 6 (Consent)",
                "collection_method": "DICOM Network Protocol",
                "storage_system": "Cloud PACS Storage (AWS Mumbai)",
                "department": "Radiology & Imaging",
                "owner": "Head Radiologist",
                "external_recipients": "Patient, Consultant Radiologist",
                "processor": "PACS Cloud Provider",
                "retention_period": "5 years",
                "deletion_method": "Secure cloud bucket object lifecycle expiration",
                "international_transfer": "None"
            },
            {
                "category": "Patient Demographic & Specimen Intake Logs",
                "principal_type": "Diagnostic Patients",
                "source": "Front-desk Registration & Phlebotomy Barcode Scan",
                "purpose": "Patient identification, sample matching, SMS report alerts",
                "legal_basis": "DPDP Section 6 (Consent) & Section 5 Notice",
                "collection_method": "Registration Desk UI / Mobile App",
                "storage_system": "Diagnostic ERP Database",
                "department": "Sample Receiving & Barcoding",
                "owner": "Operations Supervisor",
                "external_recipients": "SMS & WhatsApp notification gateway",
                "processor": "Telecom Messaging Partner",
                "retention_period": "3 years",
                "deletion_method": "Automated ledger archiving",
                "international_transfer": "None"
            },
            {
                "category": "Billing, TPA Insurance & Referral Invoices",
                "principal_type": "Diagnostic Patients & Referring Doctors",
                "source": "Billing Desk & Cashless Insurance Desk",
                "purpose": "Payment collection, insurance reimbursement, tax filing",
                "legal_basis": "DPDP Section 7(c) (Legal Obligation: Income Tax Act)",
                "collection_method": "Point-of-Sale Billing Software",
                "storage_system": "Accounting Ledger & ERP",
                "department": "Billing & Referrals",
                "owner": "Finance Manager",
                "external_recipients": "Chartered Accountant, Income Tax Portal",
                "processor": "Cloud Accounting SaaS",
                "retention_period": "8 years per Income Tax Act Section 44AB",
                "deletion_method": "Cryptographic ledger purge after audit closure",
                "international_transfer": "None"
            }
        ],
        "key_remediation_templates": [
            "Diagnostic Centre Privacy Notice & Digital Consent",
            "LIMS & Cloud PACS Data Processor Agreement",
            "Home Collection Phlebotomy Privacy SOP",
            "NABL-Compliant Diagnostic Retention Policy"
        ]
    },
    "saas": {
        "name": "SaaS & Technology Startups",
        "description": "Tailored for software companies managing customer accounts, user telemetry, billing, and cloud subprocessors.",
        "departments": [
            "Product & Engineering",
            "Customer Support",
            "Sales & Marketing",
            "Finance & Billing",
            "Human Resources"
        ],
        "typical_principals": [
            "App Users / Account Owners",
            "Prospective Leads",
            "Support Inquirers",
            "Employees & Contractors"
        ],
        "sample_data_inventory": [
            {
                "category": "User Account Profile & Authentication Credentials",
                "principal_type": "App Users",
                "source": "App Signup Form & OAuth",
                "purpose": "Account creation, authentication, role-based access control",
                "legal_basis": "DPDP Section 6 (Consent)",
                "collection_method": "Web App UI / OAuth 2.0",
                "storage_system": "PostgreSQL Cloud DB (AWS ap-south-1)",
                "department": "Product & Engineering",
                "owner": "Engineering Lead",
                "external_recipients": "Transactional Email Gateway",
                "processor": "Cloud Infrastructure Provider (Render / AWS)",
                "retention_period": "Account lifetime + 30 days post-deletion",
                "deletion_method": "0-day soft-delete, 30-day snapshot purge",
                "international_transfer": "None / Encrypted"
            },
            {
                "category": "Application Usage Telemetry & Audit Logs",
                "principal_type": "App Users",
                "source": "Application SDK & API Gateway",
                "purpose": "Security monitoring, bug diagnosis, audit compliance",
                "legal_basis": "DPDP Section 8(5) (Reasonable Security Safeguards)",
                "collection_method": "Automated log collector",
                "storage_system": "CloudWatch / Elasticsearch Log Cluster",
                "department": "Product & Engineering",
                "owner": "DevOps Engineer",
                "external_recipients": "Security SIEM Provider",
                "processor": "Cloud Logging Provider",
                "retention_period": "180 days per CERT-In Cyber Security Directions",
                "deletion_method": "Automated log stream TTL expiration",
                "international_transfer": "None"
            },
            {
                "category": "Subscription Billing, Invoicing & GST Records",
                "principal_type": "Account Billing Admins",
                "source": "Checkout Form & Payment Gateway Webhook",
                "purpose": "Subscription payment processing, GST e-invoicing",
                "legal_basis": "DPDP Section 7(c) (Legal Obligation: GST Act)",
                "collection_method": "Payment Gateway Tokenized Iframe",
                "storage_system": "Billing Database & Stripe Vault",
                "department": "Finance & Billing",
                "owner": "Finance Controller",
                "external_recipients": "GST Portal & Tax Auditors",
                "processor": "Stripe / Razorpay Payment Aggregator",
                "retention_period": "8 years per statutory tax requirements",
                "deletion_method": "Encrypted ledger archive",
                "international_transfer": "PCI-DSS Level 1 Encrypted"
            },
            {
                "category": "Customer Support Tickets & Recorded Feedback",
                "principal_type": "Support Inquirers",
                "source": "Zendesk Help Desk / Live Chat Widget",
                "purpose": "Technical troubleshooting, customer inquiry resolution",
                "legal_basis": "DPDP Section 6 (Consent) & Section 7(a) Voluntary Provision",
                "collection_method": "Support Portal Form",
                "storage_system": "Helpdesk SaaS Cloud",
                "department": "Customer Support",
                "owner": "Customer Success Manager",
                "external_recipients": "Support Engineers",
                "processor": "Helpdesk SaaS Vendor",
                "retention_period": "2 years post-ticket resolution",
                "deletion_method": "Automated customer record anonymization",
                "international_transfer": "Standard Contractual Clauses"
            }
        ],
        "key_remediation_templates": [
            "SaaS App Privacy Notice & Cookie Disclaimer",
            "Subprocessor Management Register & DPA Terms",
            "Account Deletion & Erasure Workflow",
            "CERT-In 180-Day Log Retention Protocol"
        ]
    },
    "ecommerce": {
        "name": "E-Commerce & Retail Stores",
        "description": "Built for online merchants handling buyer delivery addresses, order histories, payment logs, and customer support queries.",
        "departments": [
            "Checkout & Orders",
            "Logistics & Delivery",
            "Customer Support",
            "Marketing & Promotions",
            "Finance"
        ],
        "typical_principals": [
            "Shoppers / Buyers",
            "Third-Party Sellers",
            "Delivery Personnel"
        ],
        "sample_data_inventory": [
            {
                "category": "Customer Delivery Address & Contact Numbers",
                "principal_type": "Shoppers / Buyers",
                "source": "Order Checkout Page",
                "purpose": "Package fulfillment, shipping updates, invoice delivery",
                "legal_basis": "DPDP Section 6 (Consent) & Section 7(a) Voluntary Provision",
                "collection_method": "Checkout Web Form",
                "storage_system": "E-Commerce Storefront DB",
                "department": "Checkout & Orders",
                "owner": "E-Commerce Operations Manager",
                "external_recipients": "Logistics & Courier Partners",
                "processor": "Shipping Aggregator API",
                "retention_period": "3 years from last transaction",
                "deletion_method": "Automated address scrubbing post delivery confirmation",
                "international_transfer": "None"
            },
            {
                "category": "Checkout Payment Token References & Order History",
                "principal_type": "Shoppers / Buyers",
                "source": "Payment Gateway Callback",
                "purpose": "Order confirmation, payment settlement, audit compliance",
                "legal_basis": "DPDP Section 7(c) (Statutory Legal Obligation)",
                "collection_method": "Server-to-Server Webhook",
                "storage_system": "Transactional Order Store",
                "department": "Finance",
                "owner": "Chief Financial Officer",
                "external_recipients": "Bank Merchant Account, Tax Authorities",
                "processor": "Payment Gateway Partner",
                "retention_period": "8 years per Income Tax Act",
                "deletion_method": "Cryptographic financial record purge",
                "international_transfer": "None"
            },
            {
                "category": "Shopping Cart, Wishlist & Browsing Telemetry",
                "principal_type": "Shoppers / Buyers",
                "source": "Storefront Web Session Cookies",
                "purpose": "Cart persistence, personalized product discovery",
                "legal_basis": "DPDP Section 6 (Consent via Cookie Banner)",
                "collection_method": "Client Browser Session Storage",
                "storage_system": "Redis Cache & Analytics Store",
                "department": "Marketing & Promotions",
                "owner": "Growth Marketing Lead",
                "external_recipients": "Analytics Cloud Vendor",
                "processor": "Web Analytics Provider",
                "retention_period": "90 days post session",
                "deletion_method": "Automated TTL cache purge",
                "international_transfer": "None"
            },
            {
                "category": "Customer Returns, Refunds & Bank Account Details",
                "principal_type": "Shoppers / Buyers",
                "source": "Return / Exchange Portal",
                "purpose": "Refund processing, product pickup coordination",
                "legal_basis": "DPDP Section 6 (Consent)",
                "collection_method": "Self-Service Returns UI",
                "storage_system": "Customer Support ERP",
                "department": "Customer Support",
                "owner": "Support Operations Lead",
                "external_recipients": "Payout Gateway Partner",
                "processor": "Banking Partner API",
                "retention_period": "1 year post-refund completion",
                "deletion_method": "Database row cryptographic scrub",
                "international_transfer": "None"
            }
        ],
        "key_remediation_templates": [
            "E-Commerce Privacy Notice & Unbundled Consent",
            "Courier & Logistics Data Processor Agreement",
            "Marketing Opt-Out & Erasure Mechanism",
            "Cookie Preference Management Protocol"
        ]
    },
    "professional_services": {
        "name": "Professional Services (Legal, CA, Advisory & Consulting)",
        "description": "Tailored for law firms, chartered accounting practices, management consultants, and tax advisors handling confidential client financial data, KYC, director details, and employee payroll.",
        "departments": [
            "Client Intake & Engagement",
            "Tax & Audit Advisory",
            "Corporate Secretarial & KYC",
            "Billing, Retainers & Accounts",
            "HR & Partner Operations"
        ],
        "typical_principals": [
            "Client Founders & Directors",
            "Individual Tax Clients",
            "Client Employees (Payroll data)",
            "Firm Partners & Associates"
        ],
        "sample_data_inventory": [
            {
                "category": "Client KYC, PAN & Director Verification Records",
                "principal_type": "Client Directors & Taxpayers",
                "source": "Client Onboarding Form & Tax Returns",
                "purpose": "Statutory audit, tax filing, MCA compliance",
                "legal_basis": "DPDP Section 7(c) (Legal Obligation) & Engagement Contract",
                "collection_method": "Encrypted Client Portal Upload",
                "storage_system": "Cloud Document Management System (Google Workspace / MS 365)",
                "department": "Tax & Audit Advisory",
                "owner": "Managing Partner",
                "external_recipients": "Income Tax Portal, Ministry of Corporate Affairs (MCA)",
                "processor": "Tax Software SaaS Provider",
                "retention_period": "8 years (Income Tax & Companies Act requirements)",
                "deletion_method": "Secure digital shredding post statutory period",
                "international_transfer": "None"
            },
            {
                "category": "Financial Statements, Audit Workpapers & Tax Returns",
                "principal_type": "Corporate Clients",
                "source": "Client ERP Ledgers & Bank Statements",
                "purpose": "Statutory audit reporting, tax computation",
                "legal_basis": "DPDP Section 7(c) (Statutory Obligation: Companies Act)",
                "collection_method": "Encrypted SFTP / Cloud Share",
                "storage_system": "Audit Management Suite",
                "department": "Tax & Audit Advisory",
                "owner": "Engagement Partner",
                "external_recipients": "Statutory Regulators, ICAI Quality Review Board",
                "processor": "Audit Cloud SaaS",
                "retention_period": "8 years",
                "deletion_method": "Cryptographic file deletion with certificate",
                "international_transfer": "None"
            },
            {
                "category": "Corporate Advisory Contracts & Legal Submissions",
                "principal_type": "Client Representatives",
                "source": "Client Engagement Correspondence",
                "purpose": "Commercial drafting, dispute resolution, legal defense",
                "legal_basis": "DPDP Section 6 (Consent) & Legal Professional Privilege",
                "collection_method": "Corporate Email & Portal",
                "storage_system": "Firm Document Repository",
                "department": "Client Intake & Engagement",
                "owner": "Senior Advocate / Partner",
                "external_recipients": "Tribunals & High Courts",
                "processor": "Legal Practice Software",
                "retention_period": "10 years post-matter resolution",
                "deletion_method": "Secure archive purging",
                "international_transfer": "None"
            },
            {
                "category": "Retainer Invoices, Billing Ledgers & Bank Statements",
                "principal_type": "Clients & Vendor Partners",
                "source": "Firm Accounting Department",
                "purpose": "Fee invoicing, GST filing, payment reconciliation",
                "legal_basis": "DPDP Section 7(c) (Statutory Obligation)",
                "collection_method": "Internal Accounting System",
                "storage_system": "Tally / QuickBooks Cloud",
                "department": "Billing, Retainers & Accounts",
                "owner": "Accounts Head",
                "external_recipients": "GSTN Portal",
                "processor": "Cloud Accounting Provider",
                "retention_period": "8 years",
                "deletion_method": "Secure ledger cleanup",
                "international_transfer": "None"
            }
        ],
        "key_remediation_templates": [
            "Professional Services Privacy Notice & Engagement Addendum",
            "Client KYC & Confidential Document Protection SOP",
            "Cloud Document Storage Subprocessor Agreement",
            "8-Year Tax Document Retention Policy"
        ]
    },
    "education": {
        "name": "Education (Schools, Colleges & EdTech)",
        "description": "Configured for academic institutions handling student admissions, parent communications, academic records, and children's data safeguards under Section 9.",
        "departments": [
            "Admissions & Registration",
            "Academic Affairs & Exams",
            "Student Welfare & Infirmary",
            "Accounts & Fee Management",
            "Administration & Staff"
        ],
        "typical_principals": [
            "Students (Minors)",
            "Parents & Legal Guardians",
            "Teachers & Faculty",
            "Administrative Personnel"
        ],
        "sample_data_inventory": [
            {
                "category": "Student Enrollment, Minor Profile & Academic Records",
                "principal_type": "Students (Minors)",
                "source": "Admission Application Form",
                "purpose": "Enrollment, curriculum tracking, exam certification",
                "legal_basis": "DPDP Section 9 (Verifiable Parental Consent)",
                "collection_method": "Online Admission Portal / Paper Form",
                "storage_system": "School ERP Database",
                "department": "Admissions & Registration",
                "owner": "Registrar",
                "external_recipients": "State Education Board, Exam Controllers",
                "processor": "School Management SaaS",
                "retention_period": "Permanent for TC/Certificates, 5 years for general records",
                "deletion_method": "Secure DB record purge post retention",
                "international_transfer": "None"
            },
            {
                "category": "Verifiable Parental Consent & Guardian Contacts",
                "principal_type": "Parents & Legal Guardians",
                "source": "Guardian Consent Attestation Form",
                "purpose": "Parental identity verification, emergency intimation, consent recording",
                "legal_basis": "DPDP Section 9 (Parental Consent Verification)",
                "collection_method": "Digital Signature / SMS OTP Consent",
                "storage_system": "Parent Consent Ledger",
                "department": "Admissions & Registration",
                "owner": "Vice Principal",
                "external_recipients": "Emergency Medical Services if required",
                "processor": "Consent Management System",
                "retention_period": "Duration of student enrollment + 3 years",
                "deletion_method": "Automated purge after graduation",
                "international_transfer": "None"
            },
            {
                "category": "Campus Biometric Attendance & CCTV Access Logs",
                "principal_type": "Students & Staff",
                "source": "Campus Turnstiles & CCTV Cameras",
                "purpose": "Campus physical security, student safety",
                "legal_basis": "DPDP Section 8(5) (Reasonable Security Safeguards)",
                "collection_method": "Biometric Scanner Terminal",
                "storage_system": "Local School Access Controller NVR",
                "department": "Administration & Staff",
                "owner": "Campus Security Officer",
                "external_recipients": "Local Police Authorities (upon statutory request)",
                "processor": "Biometric Hardware Vendor",
                "retention_period": "30-90 days for CCTV footage",
                "deletion_method": "Automated FIFO footage overwriting",
                "international_transfer": "None"
            },
            {
                "category": "Tuition Fee Invoices & Financial Assistance Records",
                "principal_type": "Parents & Legal Guardians",
                "source": "Fee Collection Counter & Online Payment Gateway",
                "purpose": "Tuition billing, receipt generation, scholarship tracking",
                "legal_basis": "DPDP Section 7(c) (Statutory Obligation: Tax and Auditing)",
                "collection_method": "ERP Online Fee Payment Gateway",
                "storage_system": "School Accounts Ledger",
                "department": "Accounts & Fee Management",
                "owner": "Chief Accounts Officer",
                "external_recipients": "Statutory Auditors",
                "processor": "Banking Gateway Partner",
                "retention_period": "8 years per Income Tax Act",
                "deletion_method": "Cryptographic ledger purge post audit closure",
                "international_transfer": "None"
            }
        ],
        "key_remediation_templates": [
            "Parental Consent Form for Minor Students (Section 9)",
            "Educational Record Privacy Notice",
            "EdTech Learning Software Vendor Agreement",
            "Minor Data Protection & Anti-Profiling Policy"
        ]
    }
}

INDUSTRY_TEMPLATES["healthcare"] = INDUSTRY_TEMPLATES["clinics"]

# ==============================================================================
# AI DPDP ASSISTANT GROUNDED KNOWLEDGE BASE
# ==============================================================================

AI_KNOWLEDGE_BASE = [
    {
        "keywords": ["notice", "section 5", "privacy notice", "language", "8th schedule", "itemised"],
        "section": "Section 5 of DPDP Act, 2023 read with Rule 3 of DPDP Rules, 2025",
        "effective_status": "Scheduled to commence on 13 May 2027 (Readiness Assessment active)",
        "answer": (
            "Under Section 5 of the DPDP Act, 2023, every Data Fiduciary must give Data Principals an "
            "itemised notice before or at the time of seeking consent. The notice must clearly describe: "
            "(1) the personal data sought to be collected, (2) the specific purpose of processing, "
            "(3) how the Data Principal may exercise their rights of access, correction, or withdrawal, "
            "and (4) the business contact details of the Grievance Officer. Under Rule 3, the notice must "
            "be in clear, comprehensible language and must be accessible in English and any of the 22 languages "
            "specified in the Eighth Schedule to the Constitution of India."
        ),
        "source": "DPDP Act, 2023, Section 5; DPDP Rules, 2025, Rule 3",
        "expert_review": "Recommended for customer-facing clinic / SaaS notice customization."
    },
    {
        "keywords": ["consent", "section 6", "withdraw", "withdrawal", "affirmative", "bundled"],
        "section": "Section 6 of DPDP Act, 2023 read with Rules 3 & 4 of DPDP Rules, 2025",
        "effective_status": "Section 6(9) & Rule 4 Consent Managers in force (13 Nov 2026); Substantive consent (Section 6(1)-(8)) scheduled 13 May 2027",
        "answer": (
            "Section 6 mandates that consent must be free, specific, informed, unconditional, and unambiguous, "
            "conveyed through a clear affirmative action. Bundling consent with general terms of service or "
            "making access conditional on providing excessive personal data is prohibited. Under Section 6(4)-(6), "
            "Data Principals have the statutory right to withdraw consent with the same ease with which it was given. "
            "Upon withdrawal, the Data Fiduciary and its Data Processors must cease processing unless retention is "
            "specifically required by another statutory law (such as clinical record retention or tax laws)."
        ),
        "source": "DPDP Act, 2023, Section 6(1)-(6); Rule 4",
        "expert_review": "Standard consent workflows do not require legal review; custom withdrawal exceptions do."
    },
    {
        "keywords": ["legitimate use", "section 7", "emergency", "employment", "without consent"],
        "section": "Section 7 of DPDP Act, 2023",
        "effective_status": "Scheduled to commence on 13 May 2027",
        "answer": (
            "Unlike GDPR, the DPDP Act does not contain a generic 'legitimate interest' exception. "
            "Section 7 defines an exhaustive list of 'Certain Legitimate Uses' where personal data may be "
            "processed without consent: (a) voluntary provision for a specified purpose without expressing non-consent, "
            "(b) State subsidies and benefits, (c) legal obligations under Indian law, (d) compliance with court judgments, "
            "(e) responding to a medical emergency involving a threat to the life or immediate health of the individual, "
            "(f) taking measures to provide medical treatment during an epidemic or public health breakdown, "
            "(g) safety measures during disaster or breakdown of public order, and (i) employment purposes and safeguarding employers."
        ),
        "source": "DPDP Act, 2023, Section 7(a)-(i)",
        "expert_review": "Legal counsel review required when relying on non-consent grounds."
    },
    {
        "keywords": ["breach", "section 8(6)", "rule 7", "data protection board", "intimation", "72 hours"],
        "section": "Section 8(6) of DPDP Act, 2023 read with Rule 7 of DPDP Rules, 2025",
        "effective_status": "Scheduled to commence on 13 May 2027",
        "answer": (
            "Section 8(6) and Rule 7 require every Data Fiduciary to notify the Data Protection Board of India "
            "and each affected Data Principal of any personal data breach. The procedure involves: "
            "(1) an initial intimation submitted without delay upon confirming a breach containing description, "
            "nature, and immediate containment measures, and (2) a detailed supplementary intimation within the "
            "prescribed 72-hour period detailing affected data categories, estimated number of individuals, forensic "
            "findings, and remedial actions taken, unless extended by the Board in writing."
        ),
        "source": "DPDP Act, 2023, Section 8(6); DPDP Rules, 2025, Rule 7",
        "expert_review": "Mandatory management and legal sign-off required prior to submitting any breach intimation."
    },
    {
        "keywords": ["children", "child", "section 9", "guardian", "parental consent", "minor", "under 18"],
        "section": "Section 9 of DPDP Act, 2023 read with Rule 10 & October 2026 Removal of Difficulties Order",
        "effective_status": "Scheduled to commence on 13 May 2027",
        "answer": (
            "Section 9 strictly governs the processing of personal data of children (defined as under 18 years of age) "
            "and persons with disabilities. Data Fiduciaries must obtain verifiable parental consent before processing "
            "such data. They are prohibited from undertaking tracking, behavioral monitoring, or targeted advertising "
            "directed at children, or any processing likely to cause detrimental effect on a child's well-being. "
            "The October 2026 Removal of Difficulties Order provides statutory textual and cross-reference alignment "
            "relating to Section 9 and Section 10 without altering the core duty to verify parent/guardian consent."
        ),
        "source": "DPDP Act, 2023, Section 9; Rule 10; October 2026 Removal of Difficulties Order",
        "expert_review": "Required for platforms offering pediatric or minor services."
    },
    {
        "keywords": ["rights", "data principal", "access", "correction", "erasure", "nomination", "sections 11-14"],
        "section": "Sections 11, 12, 13 and 14 of DPDP Act, 2023 read with Rule 14",
        "effective_status": "Scheduled to commence on 13 May 2027",
        "answer": (
            "Data Principals enjoy four core statutory rights under the DPDP Act: "
            "(1) Right to Access (Section 11): Summary of personal data processed, processing activities, and identities of Data Fiduciaries/Processors shared with; "
            "(2) Right to Correction and Erasure (Section 12): Correction of inaccurate data, completion of incomplete data, updating, and erasure where retention is not legally required; "
            "(3) Right of Grievance Redressal (Section 13): Readily accessible mechanism with mandatory prior exhaustion before approaching the Data Protection Board; and "
            "(4) Right to Nominate (Section 14): Right to designate a nominee to exercise rights in the event of death or incapacity."
        ),
        "source": "DPDP Act, 2023, Sections 11-14; Rule 14",
        "expert_review": "Standard workflow verification."
    },
    {
        "keywords": ["vendor", "processor", "section 8(1)", "section 8(2)", "dpa", "contract"],
        "section": "Section 8(1) and 8(2) of DPDP Act, 2023",
        "effective_status": "Scheduled to commence on 13 May 2027",
        "answer": (
            "Under Section 8(1)-(2), the Data Fiduciary remains fully accountable for DPDP compliance even when "
            "processing is performed by a third-party Data Processor (e.g., cloud host, diagnostic lab software, "
            "payroll provider). A Data Fiduciary may engage a Data Processor only under a valid contract (Data "
            "Processing Agreement) requiring reasonable security safeguards and erasure on completion of purpose."
        ),
        "source": "DPDP Act, 2023, Section 8(1)-(2)",
        "expert_review": "Contract review recommended."
    },
    {
        "keywords": ["retention", "erasure", "section 8(7)", "rule 8", "how long", "deletion"],
        "section": "Section 8(7) & 8(8) of DPDP Act, 2023 read with Rule 8",
        "effective_status": "Scheduled to commence on 13 May 2027",
        "answer": (
            "Section 8(7) requires a Data Fiduciary to erase personal data as soon as the specified purpose is no "
            "longer served or when consent is withdrawn, whichever is earlier. However, under Section 8(8), "
            "erasure is not required if retention is mandated by another Indian law. For example, clinics must "
            "retain clinical case sheets for 3 to 5 years under State Clinical Establishment Acts, and financial "
            "records must be retained for 7 to 8 years under the Income Tax Act and GST rules."
        ),
        "source": "DPDP Act, 2023, Section 8(7)-(8); Rule 8",
        "expert_review": "Review against applicable sector-specific retention statutes."
    }
]

# ==============================================================================
# HELPER QUERY & CALCULATION FUNCTIONS (PHASE 4 & 6)
# ==============================================================================

def get_all_rules() -> List[Dict[str, Any]]:
    """Returns all structured DPDP requirements."""
    return DPDP_REQUIREMENTS

def get_rule_by_id(rule_id: str) -> Optional[Dict[str, Any]]:
    """Finds a DPDP requirement rule by its rule_id or id."""
    for r in DPDP_REQUIREMENTS:
        if r["id"] == rule_id or r.get("rule_id") == rule_id:
            return r
    return None

def get_rules_by_category(category: str) -> List[Dict[str, Any]]:
    """Filters rules by core assessment category."""
    cat_lower = category.lower().strip()
    return [
        r for r in DPDP_REQUIREMENTS
        if cat_lower in r.get("category", "").lower() or
           cat_lower in r.get("readiness_category", "").lower() or
           ("consent" in cat_lower and "consent" in r.get("category", "").lower()) or
           ("notice" in cat_lower and "notice" in r.get("category", "").lower()) or
           ("right" in cat_lower and "right" in r.get("category", "").lower()) or
           ("breach" in cat_lower and "breach" in r.get("category", "").lower()) or
           ("security" in cat_lower and "security" in r.get("category", "").lower())
    ]

def get_rules_by_commencement_status(status: str) -> List[Dict[str, Any]]:
    """Filters rules by commencement status or effective date (e.g. 'In force', 'Scheduled', '13 May 2027')."""
    stat_lower = status.lower().strip()
    return [
        r for r in DPDP_REQUIREMENTS
        if stat_lower in r.get("commencement_status", "").lower() or
           stat_lower in r.get("legal_status", "").lower() or
           stat_lower in r.get("effective_date", "").lower() or
           ("scheduled" in stat_lower and "scheduled" in r.get("commencement_status", "").lower()) or
           ("13 may 2027" in stat_lower and "2027" in r.get("effective_date", "")) or
           ("may 2027" in stat_lower and "2027" in r.get("effective_date", ""))
    ]

def get_industry_template(industry: str) -> Dict[str, Any]:
    """Retrieves an industry-specific pre-configured template."""
    ind_key = (industry or "clinics").lower().strip()
    if ind_key in INDUSTRY_TEMPLATES:
        base = INDUSTRY_TEMPLATES[ind_key]
        sector_id = ind_key
    elif "hosp" in ind_key:
        base = INDUSTRY_TEMPLATES["hospitals"]
        sector_id = "hospitals"
    elif "diag" in ind_key or "lab" in ind_key:
        base = INDUSTRY_TEMPLATES["diagnostic_centres"]
        sector_id = "diagnostic_centres"
    elif "health" in ind_key or "clinic" in ind_key:
        base = INDUSTRY_TEMPLATES["clinics"]
        sector_id = "clinics"
    elif "tech" in ind_key or "saas" in ind_key:
        base = INDUSTRY_TEMPLATES["saas"]
        sector_id = "saas"
    elif "shop" in ind_key or "retail" in ind_key or "ecom" in ind_key:
        base = INDUSTRY_TEMPLATES["ecommerce"]
        sector_id = "ecommerce"
    elif "legal" in ind_key or "consult" in ind_key or "prof" in ind_key or "ca" in ind_key:
        base = INDUSTRY_TEMPLATES["professional_services"]
        sector_id = "professional_services"
    elif "school" in ind_key or "college" in ind_key or "ed" in ind_key:
        base = INDUSTRY_TEMPLATES["education"]
        sector_id = "education"
    else:
        base = INDUSTRY_TEMPLATES["clinics"]
        sector_id = "clinics"

    tpl = dict(base)
    tpl["sector_id"] = sector_id
    tpl["sector_name"] = tpl.get("name")
    tpl["sample_inventory"] = tpl.get("sample_data_inventory", [])
    tpl["priority_controls"] = tpl.get("key_remediation_templates", [])
    tpl.setdefault("suggested_retention", {
        "medical_and_clinical_records": "3-5 years per Clinical Establishments Act and NABL",
        "financial_ledgers_and_invoices": "7-8 years under Income Tax Act Section 44AB",
        "employee_personnel_files": "5 years following termination of service",
        "web_access_telemetry_logs": "180 days per CERT-In Cyber Security Directions"
    })
    return tpl

def list_industry_templates() -> List[Dict[str, Any]]:
    """Lists all available industry templates with keys and titles."""
    unique_keys = ["hospitals", "clinics", "diagnostic_centres", "saas", "ecommerce", "professional_services", "education"]
    return [
        {"key": k, "sector_id": k, "name": INDUSTRY_TEMPLATES[k]["name"], "description": INDUSTRY_TEMPLATES[k]["description"]}
        for k in unique_keys
    ]

def calculate_dpdp_readiness_score(controls: Any = None, evidence_items: Any = None, has_critical_gap: bool = False) -> Dict[str, Any]:
    """
    Deterministic score calculation methodology:
    - Base weight per control = 100 / total controls
    - Status weighting:
      - SELF_ATTESTED_IMPLEMENTED: 0.70x credit
      - VERIFIED_WITH_EVIDENCE: 1.00x credit
      - IN_PROGRESS: 0.35x credit
      - GAP_IDENTIFIED: 0.00x credit
    - Coverage % = (controls evaluated) / total applicable controls
    - Confidence level determined by percentage of controls supported by verified evidence artifacts.
    """
    if isinstance(controls, (int, float)):
        implemented_count = int(controls)
        total_count = int(evidence_items or 15)
        score = int(round((implemented_count / total_count) * 100)) if total_count else 0
        if has_critical_gap:
            band = "Critical Security Gap - Non-Compliant"
        elif score >= 90:
            band = "Audit-Ready (High Posture)"
        elif score >= 60:
            band = "Moderate Readiness (Actionable Gaps)"
        else:
            band = "Substantial Action Needed"

        return {
            "readiness_score": score,
            "score_band": band,
            "statutory_penalty_context": "Maximum statutory penalty ceiling under DPDP Schedule up to ₹250 crore determined by DPBI on a case-by-case basis.",
            "coverage_pct": 100,
            "confidence": "HIGH" if (not has_critical_gap and score >= 80) else "MEDIUM"
        }

    controls = controls or []
    evidence_items = evidence_items or []
    total = len(controls) or len(DPDP_REQUIREMENTS)
    if total == 0:
        return {
            "readiness_score": 0, "coverage_pct": 0, "confidence": "PRELIMINARY",
            "score_band": "Not Evaluated",
            "statutory_penalty_context": "Schedule statutory ceiling up to ₹250 crore determined by DPBI."
        }

    evidence_by_control: Dict[str, int] = {}
    for ev in evidence_items:
        cid = ev.get("control_id")
        if cid:
            evidence_by_control[cid] = evidence_by_control.get(cid, 0) + 1

    total_points = 0.0
    evaluated_count = 0
    verified_count = 0
    has_critical = has_critical_gap

    for c in controls:
        st = c.get("status", "GAP_IDENTIFIED")
        cid = c.get("requirement_id") or c.get("id")
        has_evidence = evidence_by_control.get(cid, 0) > 0
        sev = c.get("severity", "MEDIUM")

        if st != "NOT_EVALUATED":
            evaluated_count += 1

        if st == "SELF_ATTESTED_IMPLEMENTED":
            if has_evidence:
                total_points += 1.0
                verified_count += 1
            else:
                total_points += 0.70
        elif st == "VERIFIED_WITH_EVIDENCE":
            total_points += 1.0
            verified_count += 1
        elif st == "IN_PROGRESS":
            total_points += 0.35
        elif st == "GAP_IDENTIFIED":
            total_points += 0.0
            if sev in ("CRITICAL", "HIGH"):
                has_critical = True

    score = int(round((total_points / total) * 100))
    coverage = int(round((evaluated_count / total) * 100))

    if verified_count >= 8:
        confidence = "HIGH (Evidence-Verified)"
    elif verified_count >= 4 or score >= 60:
        confidence = "MEDIUM (Partially Verified)"
    else:
        confidence = "PRELIMINARY (Self-Attested)"

    if has_critical:
        band = "Critical Security Gap - Non-Compliant"
    elif score >= 90:
        band = "Audit-Ready (High Posture)"
    elif score >= 60:
        band = "Moderate Readiness (Actionable Gaps)"
    else:
        band = "Substantial Action Needed"

    return {
        "readiness_score": min(score, 100),
        "score_band": band,
        "statutory_penalty_context": "Maximum statutory penalty ceiling under DPDP Schedule up to ₹250 crore determined by DPBI on a case-by-case basis.",
        "coverage_pct": min(coverage, 100),
        "confidence": confidence,
        "controls_evaluated": evaluated_count,
        "total_controls": total,
        "verified_evidence_count": len(evidence_items),
        "calculation_method": "Weighted statutory controls (70% self-attestation, 100% verified evidence, 35% in-progress, 0% gaps)"
    }


def query_dpdp_assistant(query: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Retrieval-grounded DPDP Assistant.
    Evaluates queries against statutory Act, Rules, gazette orders, and customer assessment context.
    Provides legal citations, effective status, and clear non-legal advice disclaimers.
    100% deterministic & local execution: zero customer data leakage.
    """
    cleaned_query = query.lower().strip()
    words = set(re.findall(r'\b\w+\b', cleaned_query))
    
    best_match = None
    best_score = 0
    
    for entry in AI_KNOWLEDGE_BASE:
        score = sum(1 for kw in entry["keywords"] if kw in cleaned_query or any(w in kw for w in words))
        if score > best_score:
            best_score = score
            best_match = entry
            
    disclaimer = (
        "Disclaimer: This guidance is provided for compliance planning and informational purposes under the "
        "Digital Personal Data Protection Act, 2023 and DPDP Rules, 2025. It does not constitute formal legal counsel. "
        "Organisations should seek qualified legal review for specific regulatory filings."
    )
    
    if best_match and best_score > 0:
        return {
            "query": query,
            "matched_section": best_match["section"],
            "effective_status": best_match["effective_status"],
            "response": best_match["answer"],
            "source_document": best_match["source"],
            "expert_review_guidance": best_match["expert_review"],
            "confidence": "HIGH" if best_score >= 2 else "MEDIUM",
            "disclaimer": disclaimer,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        
    return {
        "query": query,
        "matched_section": "Digital Personal Data Protection Act, 2023 (General Overview)",
        "effective_status": "Initial provisions in force (Nov 2025/2026); Substantive obligations scheduled for 13 May 2027",
        "response": (
            "The Digital Personal Data Protection Act, 2023 regulates the processing of digital personal data in India. "
            "Key requirements center around: (1) Section 5 itemised notices in plain language and 8th Schedule languages, "
            "(2) Section 6 affirmative, unbundled consent with easy withdrawal, (3) Section 7 strictly enumerated legitimate uses, "
            "(4) Section 8(5) reasonable security safeguards, (5) Section 8(6) mandatory dual-stage breach intimations, "
            "(6) Section 8(7) purpose-cessation data erasure, and (7) Sections 11-14 Data Principal rights. "
            "You can ask about specific topics like notices, consent withdrawal, breach notification, child data, or vendor contracts."
        ),
        "source": "DPDP Act, 2023 & DPDP Rules, 2025",
        "expert_review_guidance": "Consult qualified Indian privacy counsel for organisation-specific legal determinations.",
        "confidence": "GENERAL_FRAMEWORK",
        "disclaimer": disclaimer,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
