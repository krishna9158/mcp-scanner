"""
TrustAudit - Central Version-Controlled DPDP Statutory Penalty Registry.
Authoritative statutory mapping system based strictly on the Schedule to the
Digital Personal Data Protection Act, 2023.

Schedule Maximum Ceilings (Section 33):
Item 1: Failure to take reasonable security safeguards under Section 8(5) -> Up to ₹250 crore
Item 2: Failure to notify personal data breach under Section 8(6) -> Up to ₹200 crore
Item 3: Breach of children's data obligations under Section 9 -> Up to ₹200 crore
Item 4: Breach of Significant Data Fiduciary obligations under Section 10 -> Up to ₹150 crore
Item 5: Breach of duties of Data Principal under Section 15 -> Up to ₹10,000
Item 6: Breach of any other provision of Act or Rules -> Up to ₹50 crore

Statutory Caveat:
These amounts are maximum statutory ceilings determined by the Data Protection Board
of India (DPBI) on a case-by-case basis under Section 33. They are NOT automatic fines.
"""

from typing import Dict, Any, Optional

PENALTY_ENGINE_VERSION = "v3.1.0"
LAST_REVIEWED_DATE = "2026-11-26"
OFFICIAL_SOURCE = "The Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023), Schedule read with Section 33"

STATUTORY_PENALTY_DISCLAIMER = (
    "Statutory penalty ceilings are maximum amounts specified in the DPDP Act, 2023. "
    "They are not automatic fines, predicted penalties, or actual penalties. "
    "The Data Protection Board of India determines penalties case by case under Section 33."
)

SECTION_33_FACTORS = [
    {
        "clause": "Section 33(2)(a)",
        "title": "Nature, gravity and duration of the breach",
        "plain_english": "How serious the breach was, what went wrong, and how long it lasted.",
    },
    {
        "clause": "Section 33(2)(b)",
        "title": "Type and nature of personal data affected",
        "plain_english": "Whether sensitive, financial, health, children's, or everyday contact details were exposed.",
    },
    {
        "clause": "Section 33(2)(c)",
        "title": "Repetitive nature of the breach",
        "plain_english": "Whether the organisation has repeated similar violations before.",
    },
    {
        "clause": "Section 33(2)(d)",
        "title": "Gain realised or loss avoided",
        "plain_english": "Whether the business profited from the breach or avoided spending on required safeguards.",
    },
    {
        "clause": "Section 33(2)(e)",
        "title": "Mitigation actions and timeliness",
        "plain_english": "What steps were taken quickly to fix the issue and reduce harm to individuals.",
    },
    {
        "clause": "Section 33(2)(f)",
        "title": "Proportionate and effective deterrence",
        "plain_english": "Whether the penalty amount is fair, proportionate, and enough to ensure compliance.",
    },
    {
        "clause": "Section 33(2)(g)",
        "title": "Likely impact on the person",
        "plain_english": "How severely the monetary penalty would affect the organisation's financial viability.",
    },
]


def get_section_33_factors():
    return list(SECTION_33_FACTORS)

DPDP_STATUTORY_PENALTIES: Dict[str, Dict[str, Any]] = {
    "SEC_08_05": {
        "schedule_item": 1,
        "section": "Section 8(5)",
        "violation_category": "Reasonable Security Safeguards",
        "contravention": "Breach in observing obligation to take reasonable security safeguards to prevent personal data breach under sub-section (5) of section 8",
        "max_penalty_inr": 2500000000,
        "max_penalty_text": "Up to ₹250 crore",
        "commencement_status": "Scheduled to commence",
        "effective_date": "13 May 2027",
        "applicability": "All Data Fiduciaries and Data Processors holding digital personal data",
        "explanation": (
            "Highest statutory ceiling tier under the Schedule to the DPDP Act, 2023. Covers reasonable technical and "
            "organisational safeguards (such as transport encryption, appropriate encryption/obfuscation, access control, "
            "logging, data backup, and regular security review under Section 8(5) and Rule 6) to prevent personal data breaches."
        ),
        "legal_source": OFFICIAL_SOURCE,
        "last_reviewed_date": LAST_REVIEWED_DATE,
        "rule_engine_version": PENALTY_ENGINE_VERSION,
        "statutory_disclaimer": STATUTORY_PENALTY_DISCLAIMER
    },
    "SEC_08_06": {
        "schedule_item": 2,
        "section": "Section 8(6)",
        "violation_category": "Personal Data Breach Notification",
        "contravention": "Breach in observing the obligation to give the Board or affected Data Principal notice of a personal data breach under sub-section (6) of section 8",
        "max_penalty_inr": 2000000000,
        "max_penalty_text": "Up to ₹200 crore",
        "commencement_status": "Scheduled to commence",
        "effective_date": "13 May 2027",
        "applicability": "All Data Fiduciaries experiencing a confirmed or suspected personal data breach",
        "explanation": (
            "Applies when an organization fails to notify the Data Protection Board or affected Data Principals "
            "in the prescribed dual-stage form and timeline upon discovering a personal data breach."
        ),
        "legal_source": OFFICIAL_SOURCE,
        "last_reviewed_date": LAST_REVIEWED_DATE,
        "rule_engine_version": PENALTY_ENGINE_VERSION,
        "statutory_disclaimer": STATUTORY_PENALTY_DISCLAIMER
    },
    "SEC_09": {
        "schedule_item": 3,
        "section": "Section 9",
        "violation_category": "Children's & Persons with Disabilities Personal Data",
        "contravention": "Breach in observance of additional obligations in relation to children under section 9",
        "max_penalty_inr": 2000000000,
        "max_penalty_text": "Up to ₹200 crore",
        "commencement_status": "Scheduled to commence",
        "effective_date": "13 May 2027",
        "applicability": "Entities processing personal data of individuals under 18 years of age or persons with disabilities",
        "explanation": (
            "Applies to failures in parental/guardian consent verification, tracking or behavioural monitoring, or targeted "
            "advertising directed at children under 18 or persons with disabilities with lawful guardians. Subject to textual "
            "clarifications in Section 9(1) issued under S.O. 5458(E) (Removal of Difficulties Order, October 2026)."
        ),
        "legal_source": OFFICIAL_SOURCE,
        "last_reviewed_date": LAST_REVIEWED_DATE,
        "rule_engine_version": PENALTY_ENGINE_VERSION,
        "statutory_disclaimer": STATUTORY_PENALTY_DISCLAIMER
    },
    "SEC_10": {
        "schedule_item": 4,
        "section": "Section 10",
        "violation_category": "Significant Data Fiduciary Obligations",
        "contravention": "Breach in observance of additional obligations of Significant Data Fiduciary under section 10",
        "max_penalty_inr": 1500000000,
        "max_penalty_text": "Up to ₹150 crore",
        "commencement_status": "Scheduled to commence",
        "effective_date": "13 May 2027 (Conditional upon SDF designation)",
        "applicability": "Entities officially designated as Significant Data Fiduciaries by Central Government",
        "explanation": (
            "Applies to entities designated as SDFs based on volume, sensitivity, national sovereignty risk, or public order. "
            "Covers Data Protection Officer appointment, Data Protection Impact Assessments (DPIA), and independent data audits "
            "(S.O. 5458(E) Removal of Difficulties Order, October 2026 updated Section 10(2)(c)(ii) reference from 'audit' to 'data audit')."
        ),
        "legal_source": OFFICIAL_SOURCE,
        "last_reviewed_date": LAST_REVIEWED_DATE,
        "rule_engine_version": PENALTY_ENGINE_VERSION,
        "statutory_disclaimer": STATUTORY_PENALTY_DISCLAIMER
    },
    "SEC_15": {
        "schedule_item": 5,
        "section": "Section 15",
        "violation_category": "Duties of Data Principal",
        "contravention": "Breach in observance of the duties of Data Principal under section 15",
        "max_penalty_inr": 10000,
        "max_penalty_text": "Up to ₹10,000",
        "commencement_status": "Scheduled to commence",
        "effective_date": "13 May 2027",
        "applicability": "Data Principals exercising statutory rights or submitting grievances",
        "explanation": (
            "Nominal statutory ceiling against individuals submitting frivolous grievances, false claims, "
            "or impersonating another person when registering complaints or requests."
        ),
        "legal_source": OFFICIAL_SOURCE,
        "last_reviewed_date": LAST_REVIEWED_DATE,
        "rule_engine_version": PENALTY_ENGINE_VERSION,
        "statutory_disclaimer": STATUTORY_PENALTY_DISCLAIMER
    },
    "SEC_32": {
        "schedule_item": None,
        "section": "Section 32 (Voluntary Undertaking)",
        "violation_category": "Breach of Accepted Voluntary Undertaking",
        "contravention": "Failure to adhere to a voluntary undertaking accepted by the Data Protection Board under Section 32",
        "max_penalty_inr": None,
        "max_penalty_text": "Extent up to the maximum penalty specified for the underlying breach in the Schedule",
        "commencement_status": "Scheduled to commence / Linked to substantive proceedings",
        "effective_date": "Linked to substantive DPBI adjudication (13 May 2027)",
        "applicability": "Any person or Data Fiduciary whose voluntary undertaking was accepted by the Board",
        "explanation": (
            "Under Section 32(3), failure to adhere to any term of a voluntary undertaking accepted by the Board constitutes "
            "a breach under the Act and exposes the entity to penalties up to the extent applicable to the underlying breach."
        ),
        "legal_source": OFFICIAL_SOURCE,
        "last_reviewed_date": LAST_REVIEWED_DATE,
        "rule_engine_version": PENALTY_ENGINE_VERSION,
        "statutory_disclaimer": STATUTORY_PENALTY_DISCLAIMER,
    },
    "GENERAL_CONTRAVENTION": {
        "schedule_item": 6,
        "section": "General (Schedule Item 6)",
        "violation_category": "General Statutory Contravention",
        "contravention": "Breach of any other provision of this Act or the rules made thereunder",
        "max_penalty_inr": 500000000,
        "max_penalty_text": "Up to ₹50 crore",
        "commencement_status": "Scheduled to commence",
        "effective_date": "13 May 2027",
        "applicability": "All Data Fiduciaries for non-compliance not specifically listed under Schedule Items 1–5",
        "explanation": (
            "Applies to general contraventions of the Act and Rules where no specific higher ceiling is enumerated, "
            "including Section 5 (Notice), Section 6 (Consent & Withdrawal), Section 8(2) (Processor DPA), "
            "Section 8(7) (Retention & Erasure), and Sections 11–14 (Data Principal Rights)."
        ),
        "legal_source": OFFICIAL_SOURCE,
        "last_reviewed_date": LAST_REVIEWED_DATE,
        "rule_engine_version": PENALTY_ENGINE_VERSION,
        "statutory_disclaimer": STATUTORY_PENALTY_DISCLAIMER
    }
}


def map_statutory_penalty(section_or_control: str) -> Dict[str, Any]:
    """
    Deterministically maps a legal section or finding control to its exact Schedule entry.
    If the control cannot be mapped reliably to a statutory penalty, returns
    'Penalty mapping requires legal review.' with zero invented amount.
    """
    key = (section_or_control or "").upper().strip()

    # Direct match in penalty dictionary
    if key in DPDP_STATUTORY_PENALTIES:
        return dict(DPDP_STATUTORY_PENALTIES[key])

    # Pattern matching for Section 8(5) - Safeguards / Security / HTTPS / Encryption
    if any(k in key for k in ("8(5)", "8-5", "8_05", "SAFEGUARD", "ENCRYPT", "SECURITY_SAFEGUARDS", "HTTPS")):
        return dict(DPDP_STATUTORY_PENALTIES["SEC_08_05"])

    # Pattern matching for Section 8(6) - Breach Notification
    if any(k in key for k in ("8(6)", "8-6", "8_06", "BREACH_NOTIFICATION", "INCIDENT_INTIMATION")):
        return dict(DPDP_STATUTORY_PENALTIES["SEC_08_06"])

    # Pattern matching for Section 9 - Children's Data
    if any(k in key for k in ("SEC_09", "SEC-09", "SECTION 9", "CHILD", "MINOR", "PARENTAL_CONSENT")):
        return dict(DPDP_STATUTORY_PENALTIES["SEC_09"])

    # Pattern matching for Section 10 - Significant Data Fiduciary
    if any(k in key for k in ("SEC_10", "SEC-10", "SECTION 10", "SDF", "SIGNIFICANT_DATA_FIDUCIARY", "DPO")):
        return dict(DPDP_STATUTORY_PENALTIES["SEC_10"])

    # Pattern matching for Section 15 - Data Principal duties
    if any(k in key for k in ("SEC_15", "SEC-15", "SECTION 15", "PRINCIPAL_DUTIES", "FRIVOLOUS")):
        return dict(DPDP_STATUTORY_PENALTIES["SEC_15"])

    if any(k in key for k in ("SEC_32", "SEC-32", "SECTION 32", "VOLUNTARY_UNDERTAKING")):
        return dict(DPDP_STATUTORY_PENALTIES["SEC_32"])

    # Pattern matching for General Contraventions under Item 6 of Schedule
    # Sections 4, 5, 6, 7, 8(1)-(4), 8(7)-(11), 11, 12, 13, 14, 16, 17
    general_sections = [
        "SEC-03", "SEC-04", "SEC-05", "SEC-06", "SEC-07", "SEC-08-01", "SEC-08-02",
        "SEC-08-07", "SEC-08-10", "SEC-11", "SEC-12", "SEC-13", "SEC-14", "SEC-16",
        "SECTION 3", "SECTION 4", "SECTION 5", "SECTION 6", "SECTION 7", "SECTION 8",
        "SECTION 11", "SECTION 12", "SECTION 13", "SECTION 14", "SECTION 16", "SECTIONS 11",
        "NOTICE", "CONSENT", "ROPA", "INVENTORY", "RETENTION", "RIGHTS", "GRIEVANCE",
        "VENDOR", "PROCESSOR", "DPA", "TRANSFER"
    ]
    if any(g in key for g in general_sections):
        return dict(DPDP_STATUTORY_PENALTIES["GENERAL_CONTRAVENTION"])

    # Unmapped / Advisory / Internal Governance
    return {
        "schedule_item": None,
        "section": section_or_control,
        "violation_category": "Internal Governance / Advisory",
        "contravention": "Advisory control or internal procedure not specifically enumerated in Schedule",
        "max_penalty_inr": None,
        "max_penalty_text": "Specific penalty mapping requires legal review.",
        "commencement_status": "Requires legal review",
        "effective_date": "N/A",
        "applicability": "Requires organizational legal review",
        "explanation": "This finding relates to internal governance or organizational best practices. Statutory penalty ceiling is not directly specified in the Schedule.",
        "legal_source": OFFICIAL_SOURCE,
        "last_reviewed_date": LAST_REVIEWED_DATE,
        "rule_engine_version": PENALTY_ENGINE_VERSION,
        "statutory_disclaimer": STATUTORY_PENALTY_DISCLAIMER
    }
