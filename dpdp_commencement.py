"""
TrustAudit - Central Legal Commencement Registry.
Authoritative phased commencement tracker for the Digital Personal Data Protection Act, 2023
and the Digital Personal Data Protection Rules, 2025.

Current Reference Date: 22 November 2026.

Official Phased Commencement Milestones:
1. 13 November 2025:
   - S.O. 4880(E) & Ministry Notification: Preliminary & institutional provisions commenced.
   - Sections 1, 2, 18-26 (Establishment of Data Protection Board of India), Sections 33-35, 40.
2. 13 November 2026:
   - S.O. 5122(E): Consent Manager registration and foundational provisions commenced.
   - Section 6(9) (Registration & obligations of Consent Managers), Section 27(1)(d), Rule 4.
3. 13 May 2027:
   - Substantive corporate obligations scheduled to commence (Sections 3–17, Rules 3, 5–16, 22–23).
   - Notice (Sec 5), Consent (Sec 6), Reasonable Security Safeguards (Sec 8(5)), Breach Intimation (Sec 8(6)),
     Retention & Erasure (Sec 8(7)), Children's Data (Sec 9), Significant Data Fiduciaries (Sec 10),
     Data Principal Rights (Sec 11-14).
"""

from typing import Dict, Any, List

COMMENCEMENT_ENGINE_VERSION = "v3.0.0"
LAST_REVIEWED_DATE = "2026-11-22"

OFFICIAL_SOURCES = {
    "ACT": "The Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023), Gazette of India Extraordinary",
    "RULES_2025": "Digital Personal Data Protection Rules, 2025, Ministry of Electronics and Information Technology (MeitY)",
    "NOTIF_PHASE_1": "Gazette Notification S.O. 4880(E) dated 13 November 2025",
    "NOTIF_PHASE_2": "Gazette Notification S.O. 5122(E) dated 13 November 2026",
    "REMOVAL_OF_DIFFICULTIES": "Digital Personal Data Protection (Removal of Difficulties) Order, October 2026"
}

COMMENCEMENT_MILESTONES = [
    {
        "milestone_date": "13 November 2025",
        "phase_name": "Phase 1: Institutional & Preliminary Commencement",
        "status": "In force",
        "description": "Establishment and composition of the Data Protection Board of India (DPBI), jurisdiction, search powers, and preliminary institutional mechanisms.",
        "sections": ["Section 1", "Section 2", "Sections 18–26", "Sections 33–35", "Section 40"],
        "source": OFFICIAL_SOURCES["NOTIF_PHASE_1"]
    },
    {
        "milestone_date": "13 November 2026",
        "phase_name": "Phase 2: Consent Managers & Registration Architecture",
        "status": "In force",
        "description": "Commencement of statutory Consent Manager registration mechanisms under Section 6(9), Section 27(1)(d), and Rule 4.",
        "sections": ["Section 6(9)", "Section 27(1)(d)", "Rule 4"],
        "source": OFFICIAL_SOURCES["NOTIF_PHASE_2"]
    },
    {
        "milestone_date": "13 May 2027",
        "phase_name": "Phase 3: Substantive Business & Fiduciary Obligations",
        "status": "Scheduled to commence",
        "description": "Full enforcement of corporate privacy operations: Section 5 notices, Section 6 unbundled consent, Section 8 security safeguards & breach intimations, Section 8(7) retention limits, Section 9 child data protections, and Sections 11–14 Data Principal rights.",
        "sections": ["Section 3", "Section 4", "Section 5", "Section 6(1)-(8)", "Section 7", "Section 8", "Section 9", "Section 10", "Sections 11–17", "Rules 3, 5–16, 22–23"],
        "source": OFFICIAL_SOURCES["RULES_2025"]
    }
]

# Central registry of statutory controls with commencement statuses
SECTION_COMMENCEMENT_REGISTRY: Dict[str, Dict[str, Any]] = {
    # Phase 1 & 2 (In force)
    "SEC_01": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_02": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_06_09": {"status": "In force", "date": "13 November 2026", "enforceable_now": True},
    "SEC_18": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_19": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_20": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_21": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_22": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_23": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_24": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_25": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_26": {"status": "In force", "date": "13 November 2025", "enforceable_now": True},
    "SEC_27_01_D": {"status": "In force", "date": "13 November 2026", "enforceable_now": True},
    "RULE_04": {"status": "In force", "date": "13 November 2026", "enforceable_now": True},
    
    # Phase 3 (Scheduled to commence: 13 May 2027)
    "SEC_03": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_04": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_05": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_06": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_07": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_08": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_08_01": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_08_02": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_08_05": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_08_06": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_08_07": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_08_10": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_09": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_10": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_11": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_12": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_13": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_14": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_15": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_16": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "SEC_17": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "RULE_03": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "RULE_05": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "RULE_07": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "RULE_08": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False},
    "RULE_14": {"status": "Scheduled to commence", "date": "13 May 2027", "enforceable_now": False}
}


import re

def get_statutory_commencement(section_str: str) -> Dict[str, Any]:
    """
    Returns commencement information for a given section or rule string.
    Maps to one of the 5 canonical statuses:
    1. 'In force'
    2. 'Scheduled to commence'
    3. 'Not yet commenced'
    4. 'Not applicable'
    5. 'Requires legal review'
    """
    raw = (section_str or "").strip()
    upper = raw.upper()

    # Special case: Consent Manager Section 6(9) & Rule 4
    if ("6(9)" in raw or "6 (9)" in raw or "6_9" in upper or "CONSENT_MANAGER" in upper or "RULE 4" in upper or "RULE_04" in upper):
        return {
            "commencement_status": "In force",
            "effective_date": "13 November 2026",
            "enforceable_now": True,
            "official_source": OFFICIAL_SOURCES["NOTIF_PHASE_2"]
        }

    # Match Section numbers
    sec_match = re.search(r'(?:SECTION|SEC)[-_\s]*([0-9]{1,2})', upper)
    if sec_match:
        sec_num = int(sec_match.group(1))
        # Phase 1: In force since 13 Nov 2025
        if sec_num in (1, 2, 18, 19, 20, 21, 22, 23, 24, 25, 26, 33, 34, 35, 40):
            return {
                "commencement_status": "In force",
                "effective_date": "13 November 2025",
                "enforceable_now": True,
                "official_source": OFFICIAL_SOURCES["NOTIF_PHASE_1"]
            }
        # Phase 3: Scheduled to commence 13 May 2027
        if sec_num in (3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17):
            return {
                "commencement_status": "Scheduled to commence",
                "effective_date": "13 May 2027",
                "enforceable_now": False,
                "official_source": OFFICIAL_SOURCES["RULES_2025"]
            }

    # Match Rule numbers
    rule_match = re.search(r'RULE[-_\s]*([0-9]{1,2})', upper)
    if rule_match:
        rule_num = int(rule_match.group(1))
        if rule_num == 4:
            return {
                "commencement_status": "In force",
                "effective_date": "13 November 2026",
                "enforceable_now": True,
                "official_source": OFFICIAL_SOURCES["NOTIF_PHASE_2"]
            }
        if rule_num in (3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 22, 23):
            return {
                "commencement_status": "Scheduled to commence",
                "effective_date": "13 May 2027",
                "enforceable_now": False,
                "official_source": OFFICIAL_SOURCES["RULES_2025"]
            }

    # Fallback to dictionary matching
    for reg_key, info in SECTION_COMMENCEMENT_REGISTRY.items():
        if reg_key in upper:
            return {
                "commencement_status": info["status"],
                "effective_date": info["date"],
                "enforceable_now": info["enforceable_now"],
                "official_source": OFFICIAL_SOURCES["RULES_2025"] if "2027" in info["date"] else OFFICIAL_SOURCES["NOTIF_PHASE_1"]
            }

    return {
        "commencement_status": "Requires legal review",
        "effective_date": "Pending statutory determination",
        "enforceable_now": False,
        "official_source": OFFICIAL_SOURCES["ACT"]
    }


def is_currently_enforceable(section_str: str) -> bool:
    """Returns True if the obligation is in force as of today (22 Nov 2026)."""
    return get_statutory_commencement(section_str).get("enforceable_now", False)
