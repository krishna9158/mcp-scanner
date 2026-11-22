"""
TrustAudit — DPDP Legal Requirements & Assessment Engine
=========================================================
Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023)
Digital Personal Data Protection Rules, 2025 (G.S.R. / Gazette Notifications)
Updated with October 2026 Removal of Difficulties Order & Current Statutory Timelines.

Legal Status Definitions:
- IN_FORCE: Commenced on 13 November 2025 (Initial provisions & Board framework)
- COMMENCED_NOV_2026: Commenced on 13 November 2026 (Section 6(9) & Rule 4 Consent Managers)
- SCHEDULED_MAY_2027: Scheduled to commence on 13 May 2027 (Substantive Data Fiduciary obligations)
- CONDITIONAL: Applies conditionally upon designation (e.g. Significant Data Fiduciary)
- EXEMPT_CONDITIONAL: Applies conditionally upon exemption criteria (Section 17 / Rule 13)
"""

from typing import Dict, List, Any, Optional
import datetime
import re

LEGAL_DATABASE_VERSION = "2026.11.2"
LAST_LEGAL_REVIEW = "2026-11-20"

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
        "title": "DPDP Rules Notified & Phase 1 Commencement",
        "description": "Ministry of Electronics and Information Technology (MeitY) notified DPDP Rules, 2025 and commenced institutional provisions (Data Protection Board constitution, appellate tribunal procedures, search and inquiry rules).",
        "status": "COMPLETED",
        "badge": "In Force"
    },
    {
        "date": "October 2026",
        "title": "Removal of Difficulties Order",
        "description": "Order issued clarifying operational scope of verifiable parental consent under Section 9 for educational and healthcare platforms, and criteria for Significant Data Fiduciary designations.",
        "status": "COMPLETED",
        "badge": "Gazette Order"
    },
    {
        "date": "13 November 2026",
        "title": "Consent Manager Framework Commenced",
        "description": "Section 6(9) and Rule 4 provisions governing the registration, technical architecture, and accountability of registered Consent Managers became operational.",
        "status": "COMPLETED",
        "badge": "In Force"
    },
    {
        "date": "13 May 2027",
        "title": "Substantive Data Fiduciary Obligations Scheduled",
        "description": "General obligations of Data Fiduciaries (Section 8 safeguards, Section 5 itemised notices, Section 6 consent records, Section 8(6) breach notifications, Section 11-14 rights management, and Section 10 SDF requirements) scheduled to take full regulatory effect.",
        "status": "SCHEDULED",
        "badge": "Scheduled Commencement"
    }
]

# ==============================================================================
# STRUCTURED DPDP LEGAL REQUIREMENTS DATABASE
# ==============================================================================

DPDP_REQUIREMENTS: List[Dict[str, Any]] = [
    {
        "id": "DPDP-SEC-03",
        "section": "Section 3",
        "rule_ref": "Rule 2",
        "title": "Applicability & Material Scope",
        "description": "Processing of digital personal data within the territory of India where collected in digital form or digitised subsequently; and processing outside India if in connection with offering goods or services to Data Principals within India.",
        "applicability_conditions": ["processes_digital_personal_data"],
        "industry_conditions": ["all"],
        "effective_date": "13 November 2025",
        "legal_status": "IN_FORCE",
        "readiness_category": "Governance & Scoping",
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
        "remediation_guidance": "Establish a documented perimeter defining all digital personal data collected, stored, or processed across your applications, clinics, billing desks, and third-party vendors.",
        "source_document": "DPDP Act 2023, Section 3",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-04-06",
        "section": "Sections 4 & 6",
        "rule_ref": "Rules 3 & 4",
        "title": "Valid Consent & Itemised Consent Architecture",
        "description": "Personal data may only be processed for a lawful purpose with free, specific, informed, unconditional, and unambiguous consent with a clear affirmative action, limited to necessary personal data.",
        "applicability_conditions": ["collects_personal_data"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Consent & Notices",
        "assessment_questions": [
            {
                "qid": "q_sec6_affirmative",
                "question": "Is consent collected via an explicit affirmative action (e.g. unticked checkbox, signed registration form) rather than pre-selected boxes or silence?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec6_purpose_limit",
                "question": "Is consent strictly limited to the specified purpose and not bundled with unrelated service terms or conditioned on excessive data?",
                "type": "boolean",
                "weight": "critical"
            }
        ],
        "evidence_required": [
            "Consent Collection Forms / UI Screenshots",
            "Itemised Purpose Specification Matrix",
            "Consent Ledger / Audit Trail Architecture"
        ],
        "remediation_guidance": "Unbundle consent from Terms of Service. Provide granular consent toggles per processing purpose (e.g. consultation vs marketing updates) and record cryptographic timestamped consent logs.",
        "source_document": "DPDP Act 2023, Section 6(1)-(3); Rule 3",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-05",
        "section": "Section 5",
        "rule_ref": "Rule 3",
        "title": "Itemised Notice in Plain Language & 8th Schedule Availability",
        "description": "Before or at the time of seeking consent, the Data Fiduciary must give the Data Principal an itemised notice specifying personal data collected, processing purpose, manner of exercising rights, and grievance redressal contact, available in English and any of the 22 Eighth Schedule languages.",
        "applicability_conditions": ["collects_personal_data"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Consent & Notices",
        "assessment_questions": [
            {
                "qid": "q_sec5_itemised_notice",
                "question": "Does your organisation provide an itemised privacy notice before collecting personal data (at reception, web forms, or onboarding)?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec5_multilingual",
                "question": "Is the notice available in plain, comprehensible language and prepared for accessibility in required 8th Schedule languages (e.g. Hindi, regional languages)?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Patient / User Privacy Notice Document",
            "Itemised Data & Purpose Table",
            "Grievance Officer Designation in Notice",
            "Multilingual Notice Translations (where applicable)"
        ],
        "remediation_guidance": "Draft a clear, itemised notice detailing specific data points (e.g., patient phone, medical report), exact operational purpose (e.g., diagnostic consultation), rights procedure, and contact details of the Grievance Officer.",
        "source_document": "DPDP Act 2023, Section 5; Rule 3",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-06-04",
        "section": "Section 6(4)-(6)",
        "rule_ref": "Rule 3(4)",
        "title": "Consent Withdrawal & Processor Cascading",
        "description": "Data Principals have the statutory right to withdraw consent at any time with the same ease with which it was given. Upon withdrawal, the Data Fiduciary must cease processing and instruct all Data Processors to cease processing unless retention is mandated by law.",
        "applicability_conditions": ["processes_on_consent_basis"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Rights & Consent Workflows",
        "assessment_questions": [
            {
                "qid": "q_sec6_withdrawal_ease",
                "question": "Can individuals withdraw consent as easily as giving it (e.g., via simple online form, email request, or reception desk form)?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec6_processor_cascade",
                "question": "Does your organisation have an operational procedure to cascade consent withdrawal to diagnostic software, cloud hosts, and vendors within reasonable timelines?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Consent Withdrawal Procedure SOP",
            "Vendor / Processor Cease-Processing Notification Protocol",
            "Consent Withdrawal Audit Log"
        ],
        "remediation_guidance": "Implement a standardized Consent Withdrawal Request workflow that automatically flags the individual's record, checks statutory retention exceptions (e.g. tax records, clinical establishment laws), and issues automated or tracked notices to processors.",
        "source_document": "DPDP Act 2023, Section 6(4)-(6)",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-07",
        "section": "Section 7",
        "rule_ref": "Statutory Bases",
        "title": "Legitimate Uses (Statutory Non-Consent Grounds)",
        "description": "Processing personal data without explicit consent is strictly limited to specified statutory grounds: voluntary provision for a specified purpose, State subsidies/benefits, legal obligation, compliance with court orders/judgments, medical emergency involving threat to life, medical treatment during epidemic/outbreak, and employment purposes.",
        "applicability_conditions": ["relies_on_legitimate_use"],
        "industry_conditions": ["healthcare", "all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Legal Bases & Data Inventory",
        "assessment_questions": [
            {
                "qid": "q_sec7_grounds_mapping",
                "question": "Are all non-consent processing activities mapped strictly to Section 7 statutory grounds (e.g., medical emergency, employment, legal compliance) rather than generic business interest?",
                "type": "boolean",
                "weight": "critical"
            }
        ],
        "evidence_required": [
            "Legal Basis Justification Register",
            "Employment Privacy Policy & Notice",
            "Medical Emergency Processing Protocol"
        ],
        "remediation_guidance": "Audit all data processing grounds. DPDP does not contain an open-ended GDPR-style 'legitimate interest' clause. Ensure each processing stream is classified under Section 6 consent or a specific Section 7 statutory clause.",
        "source_document": "DPDP Act 2023, Section 7",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-08-01",
        "section": "Section 8(1) & 8(2)",
        "rule_ref": "Rule 5",
        "title": "Data Fiduciary Responsibility & Processor Oversight",
        "description": "The Data Fiduciary remains fully responsible for complying with the Act regardless of any processing undertaken on its behalf by a Data Processor. Data may only be engaged with a Data Processor under a valid contract.",
        "applicability_conditions": ["engages_data_processors"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Vendor & Processor Management",
        "assessment_questions": [
            {
                "qid": "q_sec8_processor_contracts",
                "question": "Do you have formal Data Processing Agreements (DPAs) or written clauses with all software vendors, cloud hosts, diagnostic labs, and IT services handling personal data?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec8_vendor_register",
                "question": "Do you maintain a centralized register of all vendors and processors with their data categories, storage regions, and agreement dates?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Vendor & Data Processor Register",
            "Executed Data Processing Agreements (DPAs)",
            "Third-Party Security Review Reports"
        ],
        "remediation_guidance": "Execute DPDP-compliant DPAs with all third-party software, cloud storage providers, and billing vendors binding them to process data solely on instruction and implement safeguards.",
        "source_document": "DPDP Act 2023, Section 8(1)-(2)",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-08-03",
        "section": "Section 8(3)",
        "rule_ref": "Rule 5",
        "title": "Data Accuracy & Consistency",
        "description": "Ensure personal data processed is accurate, complete, and consistent if it is used to make a decision that affects the Data Principal or disclosed to another Data Fiduciary.",
        "applicability_conditions": ["makes_decisions_affecting_principals"],
        "industry_conditions": ["healthcare", "education", "financial"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Data Quality & Operations",
        "assessment_questions": [
            {
                "qid": "q_sec8_accuracy_controls",
                "question": "Are there verification checkpoints to ensure patient medical reports, diagnostic records, or employee profiles are accurately recorded and updated?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Data Quality & Record Verification SOP",
            "Record Correction Audit Trail"
        ],
        "remediation_guidance": "Implement verification mechanisms at data entry (e.g. mobile OTP verification, doctor review before report release) to maintain clinical and personal record accuracy.",
        "source_document": "DPDP Act 2023, Section 8(3)",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-08-05",
        "section": "Section 8(5)",
        "rule_ref": "Rule 6",
        "title": "Reasonable Security Safeguards",
        "description": "Implement reasonable security safeguards to prevent personal data breach, protecting personal data in its possession or under its control, including that processed by Data Processors.",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Security Safeguards",
        "assessment_questions": [
            {
                "qid": "q_sec8_encryption",
                "question": "Is personal data encrypted both in transit (TLS 1.2/1.3) and at rest (AES-256 or equivalent) across databases, backups, and file storage?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec8_access_control",
                "question": "Is role-based access control (RBAC) enforced with Multi-Factor Authentication (MFA) for administrative and medical staff accessing personal records?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec8_backups",
                "question": "Are periodic secure backups maintained and tested for disaster recovery and operational resilience?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Information Security Policy Document",
            "Encryption Configuration Records",
            "RBAC Role Matrix & MFA Verification Records",
            "Backup & Disaster Recovery Procedures"
        ],
        "remediation_guidance": "Enforce TLS in transit, AES-256 encryption at rest, mandatory MFA on administrative dashboards, and periodic access reviews to meet Rule 6 reasonable safeguards.",
        "source_document": "DPDP Act 2023, Section 8(5); Rule 6",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-08-06",
        "section": "Section 8(6)",
        "rule_ref": "Rule 7",
        "title": "Personal Data Breach Intimation",
        "description": "In the event of a personal data breach, the Data Fiduciary must give intimation of the breach to the Data Protection Board and to each affected Data Principal in the prescribed form and manner.",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Breach Management",
        "assessment_questions": [
            {
                "qid": "q_sec8_breach_sop",
                "question": "Does your organisation have a documented Incident Response & Breach Management Procedure to detect, investigate, and notify breaches without delay?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec8_breach_intimation_drafts",
                "question": "Are standardized notification templates prepared for initial intimation to the Board without delay, followed by detailed reporting within the prescribed 72-hour period?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Incident Response & Breach SOP",
            "Data Protection Board Intimation Template (Form A / Rule 7)",
            "Data Principal Breach Notification Template",
            "Breach Incident Register & Audit Log"
        ],
        "remediation_guidance": "Establish a dual-stage breach response workflow: (1) Immediate preliminary intimation to Data Protection Board upon confirmation, (2) Detailed forensic intimation within 72 hours, with direct communication to affected Data Principals.",
        "source_document": "DPDP Act 2023, Section 8(6); Rule 7",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-08-07",
        "section": "Section 8(7) & 8(8)",
        "rule_ref": "Rule 8",
        "title": "Data Retention & Purpose Cessation Erasure",
        "description": "Erase personal data upon the Data Principal withdrawing consent, or as soon as it is reasonable to assume that the specified purpose is no longer being served, unless retention is necessary for compliance with any law.",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Retention & Erasure",
        "assessment_questions": [
            {
                "qid": "q_sec8_retention_schedule",
                "question": "Do you have documented data retention schedules for each category of personal data (e.g., patient records 3-5 years per clinical rules, accounting records 7-8 years)?",
                "type": "boolean",
                "weight": "high"
            },
            {
                "qid": "q_sec8_erasure_workflow",
                "question": "Is there a routine process to safely delete or anonymise digital records once their legal retention period or clinical purpose has expired?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Data Retention Schedule & Policy",
            "Purpose Cessation Review Records",
            "Secure Deletion / Scrubbing Certificates"
        ],
        "remediation_guidance": "Define retention rules per data category. Link medical records to Clinical Establishments Act retention rules, financial records to Income Tax Act, and configure automated alerts for records reaching scheduled disposal dates.",
        "source_document": "DPDP Act 2023, Section 8(7)-(8); Rule 8",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-08-10",
        "section": "Section 8(10) & 8(11)",
        "rule_ref": "Rule 9",
        "title": "Grievance Redressal Mechanism & Officer Contact",
        "description": "Establish an effective mechanism to redress the grievances of Data Principals and publish the business contact details of a Grievance Officer or authorized representative in a prominent manner.",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Grievance & Contacts",
        "assessment_questions": [
            {
                "qid": "q_sec8_grievance_officer",
                "question": "Have you designated a Grievance Officer / Privacy Contact with name, email, and address published on your website and clinic notices?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec8_grievance_tracking",
                "question": "Do you have a ticketing system or register to log, investigate, and respond to grievance submissions within statutory timelines?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Grievance Officer Designation Letter / Board Resolution",
            "Public Grievance Contact Publication (Website / Clinic Notice)",
            "Grievance Log & Resolution SOP"
        ],
        "remediation_guidance": "Designate a dedicated Grievance Officer (e.g. grievance@company.com), publish the contact in the privacy notice, and implement a ticketing workflow that resolves complaints before escalation to the Data Protection Board.",
        "source_document": "DPDP Act 2023, Section 8(10)-(11); Rule 9",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-09",
        "section": "Section 9",
        "rule_ref": "Rule 10",
        "title": "Processing of Children's Personal Data & Persons with Disabilities",
        "description": "Obtain verifiable consent of the parent or lawful guardian before processing personal data of a child (under 18 years); refrain from tracking, behavioral monitoring, or targeted advertising directed at children, or processing likely to cause detrimental effect, subject to exemptions under the October 2026 Order.",
        "applicability_conditions": ["processes_children_data"],
        "industry_conditions": ["healthcare", "education", "all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Children's Data Protection",
        "assessment_questions": [
            {
                "qid": "q_sec9_parental_consent",
                "question": "Do you obtain verifiable consent from parents/guardians before treating minor patients (under 18) or registering student records?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec9_no_tracking",
                "question": "Do your systems strictly avoid behavioral profiling, targeted marketing, or analytics tracking on children's personal data?",
                "type": "boolean",
                "weight": "critical"
            }
        ],
        "evidence_required": [
            "Verifiable Parental Consent SOP & Registration Forms",
            "Age Verification Checkpoint Documentation",
            "Exemption Mapping (October 2026 Removal of Difficulties Order)"
        ],
        "remediation_guidance": "Implement parental verification workflows (e.g. guardian ID check during clinic registration) and configure systems to disable any behavioral analytics or promotional messaging for individuals flagged under 18.",
        "source_document": "DPDP Act 2023, Section 9; Rule 10; Oct 2026 Order",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-10",
        "section": "Section 10",
        "rule_ref": "Rule 11",
        "title": "Significant Data Fiduciary (SDF) Obligations",
        "description": "Applicable only to entities designated as Significant Data Fiduciaries by the Central Government: appoint a resident Data Protection Officer (DPO), appoint an independent data auditor, undertake periodic Data Protection Impact Assessments (DPIAs), and periodic compliance audits.",
        "applicability_conditions": ["designated_sdf"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "CONDITIONAL",
        "readiness_category": "SDF Governance",
        "assessment_questions": [
            {
                "qid": "q_sec10_sdf_status",
                "question": "Has your organisation been designated as a Significant Data Fiduciary by Central Government notification, or do you handle massive volumes of sensitive health/financial records crossing notified thresholds?",
                "type": "boolean",
                "weight": "high"
            },
            {
                "qid": "q_sec10_dpo_appointed",
                "question": "If designated or preparing for SDF thresholds, have you appointed an India-resident Data Protection Officer reporting directly to the Board of Directors?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "SDF Threshold & Designation Assessment",
            "DPO Appointment Documentation",
            "Data Protection Impact Assessment (DPIA) Report",
            "Independent Data Audit Plan"
        ],
        "remediation_guidance": "Assess organization processing volume against Central Government notification criteria. Small clinics and startups are generally exempt from Section 10 unless specifically notified.",
        "source_document": "DPDP Act 2023, Section 10; Rule 11",
        "expert_review_required": True
    },
    {
        "id": "DPDP-SEC-11-14",
        "section": "Sections 11–14",
        "rule_ref": "Rule 12",
        "title": "Data Principal Rights (Access, Correction, Erasure & Nomination)",
        "description": "Data Principals have statutory rights to: (1) obtain a summary of personal data processed and identities of Data Fiduciaries shared with; (2) correction, completion, updating, and erasure; (3) grievance redressal; and (4) nomination of another individual in the event of death or incapacity.",
        "applicability_conditions": ["all"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Data Principal Rights",
        "assessment_questions": [
            {
                "qid": "q_sec11_access_workflow",
                "question": "Can patients or users request a summary of their personal data, medical reports, and third parties with whom data was shared?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec12_correction_erasure",
                "question": "Is there a standard procedure to correct inaccurate data or request erasure where no statutory retention law applies?",
                "type": "boolean",
                "weight": "critical"
            },
            {
                "qid": "q_sec14_nomination",
                "question": "Do registration forms or patient profiles provide an option to nominate a representative in the event of death or incapacity?",
                "type": "boolean",
                "weight": "medium"
            }
        ],
        "evidence_required": [
            "Data Principal Rights Request SOP",
            "Rights Request Portal / Form (Access, Correction, Erasure)",
            "Nomination Record Facility Documentation",
            "Rights Fulfillment Audit Log"
        ],
        "remediation_guidance": "Deploy a Data Principal Rights workflow to receive, verify identities, coordinate internal system updates, and fulfill access/correction/erasure requests within statutory timeframes.",
        "source_document": "DPDP Act 2023, Sections 11, 12, 13, 14; Rule 12",
        "expert_review_required": False
    },
    {
        "id": "DPDP-SEC-16",
        "section": "Section 16",
        "rule_ref": "Rule 13",
        "title": "Cross-Border Transfer of Personal Data",
        "description": "Personal data may be transferred outside India for processing except to countries or territories restricted or blacklisted by the Central Government via official notification.",
        "applicability_conditions": ["transfers_cross_border"],
        "industry_conditions": ["all"],
        "effective_date": "13 May 2027",
        "legal_status": "SCHEDULED_MAY_2027",
        "readiness_category": "Data Flow & International",
        "assessment_questions": [
            {
                "qid": "q_sec16_overseas_storage",
                "question": "Do any of your cloud hosting providers, diagnostic software vendors, or analytics tools store personal data on servers located outside India?",
                "type": "boolean",
                "weight": "high"
            },
            {
                "qid": "q_sec16_blacklist_check",
                "question": "Do you verify that international storage locations do not include any restricted jurisdictions notified by the Central Government?",
                "type": "boolean",
                "weight": "high"
            }
        ],
        "evidence_required": [
            "Cross-Border Data Transfer Inventory",
            "Cloud Storage Region Documentation",
            "Vendor Jurisdictional Assessment"
        ],
        "remediation_guidance": "Document server regions for all cloud systems (e.g. AWS Mumbai ap-south-1 vs US-East). Ensure no transfers occur to blacklisted jurisdictions and verify compliance with sector-specific localisation rules (e.g. RBI payments data directive).",
        "source_document": "DPDP Act 2023, Section 16",
        "expert_review_required": True
    }
]

# ==============================================================================
# INDUSTRY PRE-CONFIGURED TEMPLATES
# ==============================================================================

INDUSTRY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "healthcare": {
        "name": "Healthcare (Clinics, Diagnostic Centres & Hospitals)",
        "description": "Tailored for medical establishments handling patient consultations, appointment booking, diagnostic reports, and medical billing.",
        "departments": [
            "Reception & Registration",
            "OPD Consultation",
            "Laboratory & Diagnostics",
            "Billing & Accounts",
            "Human Resources & Staff",
            "Website & Digital Enquiries"
        ],
        "typical_principals": [
            "Patients",
            "Legal Guardians (Minors)",
            "Doctors & Specialists",
            "Clinic Staff & Nurses",
            "Diagnostic Partners"
        ],
        "sample_data_inventory": [
            {
                "category": "Patient Demographic Information",
                "principal_type": "Patients",
                "source": "Reception Desk Registration / Web Appointment",
                "purpose": "Patient identification, contact, appointment scheduling",
                "legal_basis": "DPDP Section 6 (Consent) & Section 5 Notice",
                "collection_method": "Registration Paper Form / Tablet UI",
                "storage_system": "Clinic Management Software (Local & Cloud Backup)",
                "department": "Reception & Registration",
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
            "Patient Privacy Notice & Itemised Consent Form (English & Hindi)",
            "Diagnostic Laboratory Data Processor Agreement (DPA)",
            "Emergency Medical Processing Protocol (Section 7(e))",
            "Medical Records Retention & Purging Schedule",
            "Minor Patient Verifiable Parental Consent Workflow (Section 9)"
        ]
    },
    "education": {
        "name": "Education (Schools, Colleges & EdTech)",
        "description": "Configured for academic institutions handling student admissions, parent communications, academic records, and children's data safeguards.",
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
                "category": "Student Enrollment & Academic Data",
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
            }
        ],
        "key_remediation_templates": [
            "Parental Consent Form for Minor Students (Section 9)",
            "Educational Record Privacy Notice",
            "EdTech Learning Software Vendor Agreement"
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
                "category": "User Account & Authentication Data",
                "principal_type": "App Users",
                "source": "App Signup Form",
                "purpose": "Account creation, authentication, service delivery",
                "legal_basis": "DPDP Section 6 (Consent)",
                "collection_method": "Web App UI / OAuth",
                "storage_system": "PostgreSQL Cloud DB (AWS ap-south-1)",
                "department": "Product & Engineering",
                "owner": "Engineering Lead",
                "external_recipients": "Transactional Email Gateway",
                "processor": "Cloud Infrastructure Provider (Render / AWS)",
                "retention_period": "Account lifetime + 30 days post-deletion",
                "deletion_method": "0-day soft-delete, 30-day snapshot purge",
                "international_transfer": "None / Encrypted"
            }
        ],
        "key_remediation_templates": [
            "SaaS App Privacy Notice & Cookie Disclaimer",
            "Subprocessor Management Register & DPA Terms",
            "Account Deletion & Erasure Workflow"
        ]
    },
    "ecommerce": {
        "name": "E-Commerce & Retail",
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
                "category": "Customer Delivery Address & Contact",
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
            }
        ],
        "key_remediation_templates": [
            "E-Commerce Privacy Notice & Unbundled Consent",
            "Courier & Logistics Data Processor Agreement",
            "Marketing Opt-Out & Erasure Mechanism"
        ]
    }
}

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
        "section": "Section 6 of DPDP Act, 2023 read with Rule 4 of DPDP Rules, 2025",
        "effective_status": "Section 6(9) Consent Managers in force (13 Nov 2026); Substantive consent scheduled 13 May 2027",
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
            "The October 2026 Removal of Difficulties Order clarifies operational standards for age verification and "
            "exemptions for essential pediatric healthcare and verified educational record management."
        ),
        "source": "DPDP Act, 2023, Section 9; Rule 10; October 2026 Gazette Order",
        "expert_review": "Required for platforms offering pediatric or minor services."
    },
    {
        "keywords": ["rights", "data principal", "access", "correction", "erasure", "nomination", "sections 11-14"],
        "section": "Sections 11, 12, 13 and 14 of DPDP Act, 2023 read with Rule 12",
        "effective_status": "Scheduled to commence on 13 May 2027",
        "answer": (
            "Data Principals enjoy four core statutory rights under the DPDP Act: "
            "(1) Right to Access (Section 11): Summary of personal data processed, processing activities, and identities of Data Fiduciaries/Processors shared with; "
            "(2) Right to Correction and Erasure (Section 12): Correction of inaccurate data, completion of incomplete data, updating, and erasure where retention is not legally required; "
            "(3) Right of Grievance Redressal (Section 13): Readily accessible mechanism with mandatory prior exhaustion before approaching the Data Protection Board; and "
            "(4) Right to Nominate (Section 14): Right to designate a nominee to exercise rights in the event of death or incapacity."
        ),
        "source": "DPDP Act, 2023, Sections 11-14; Rule 12",
        "expert_review": "Standard workflow verification."
    },
    {
        "keywords": ["vendor", "processor", "section 8(1)", "section 8(2)", "dpa", "contract"],
        "section": "Section 8(1) and 8(2) of DPDP Act, 2023 read with Rule 5",
        "effective_status": "Scheduled to commence on 13 May 2027",
        "answer": (
            "Under Section 8(1)-(2), the Data Fiduciary remains fully liable for DPDP compliance even if "
            "processing is delegated to a third-party Data Processor (e.g., cloud host, diagnostic lab software, "
            "payroll provider). A Data Fiduciary may only engage a Data Processor under a valid contract (Data "
            "Processing Agreement). The contract must bind the processor to process data only upon instruction, "
            "maintain reasonable security safeguards under Rule 6, assist in breach intimation, and erase data "
            "upon instruction or contract termination."
        ),
        "source": "DPDP Act, 2023, Section 8(1)-(2); Rule 5",
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
        
    # Fallback to general statutory framework summary
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
