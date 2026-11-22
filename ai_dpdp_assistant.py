"""
TrustAudit - AI DPDP Assistant Service.
Retrieval-Augmented Generation (RAG) assistant grounded in official Indian statutory sources:
1. Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023)
2. Digital Personal Data Protection Rules, 2025
3. Gazette Commencement Notifications (Nov 2025, Nov 2026)
4. Removal of Difficulties Orders (October 2026)

Key Capabilities:
- Full statutory source grounding with verified citations.
- Strict distinction between current enforceable obligations (e.g. Sec 6(9)) and scheduled future requirements (13 May 2027).
- Organisation-aware context injection (industry, data inventory streams, active vendors, identified gaps).
- Strict multi-tenant isolation: zero cross-organisation context leakage.
- Optional Gemini API integration (when GEMINI_API_KEY is configured) with graceful deterministic fallback.
"""

import os
import re
import json
import urllib.request
import urllib.error
import datetime
from typing import Dict, Any, List, Optional
import dpdp_store
import dpdp_commencement
import dpdp_penalties

# Expanded RAG statutory knowledge base
DPDP_KNOWLEDGE_CORPUS: List[Dict[str, Any]] = [
    {
        "id": "KB-SEC-04-06",
        "section": "Section 4 & Section 6",
        "rules": ["Rule 3", "Rule 4"],
        "title": "Grounds for Processing & Valid Consent Architecture",
        "effective_date": "13 May 2027 (Substantive obligations) / 13 Nov 2026 (Consent Managers)",
        "commencement_status": "Scheduled to commence",
        "keywords": ["consent", "unbundled", "freely given", "specific", "informed", "unconditional", "affirmative", "checkbox", "pre-ticked", "bundled"],
        "summary": (
            "Under Section 6(1), consent must be free, specific, informed, unconditional, and unambiguous with clear affirmative action. "
            "Under Section 6(2), consent must not be bundled with unnecessary terms. Pre-ticked checkboxes and forced consent violate Section 6. "
            "Under Section 6(4), Data Principals have the statutory right to withdraw consent with comparable ease to granting it. "
            "Upon withdrawal, the Data Fiduciary must cease processing and instruct all Data Processors to stop processing under Section 6(6)."
        ),
        "source_doc": "DPDP Act 2023 Section 6 & Rules 2025 Rule 3",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹50 crore (Schedule Item 6: General Contravention)",
        "action_guidance": "Audit all website forms, registration flows, and mobile UIs to ensure consent checkboxes are un-checked by default and segregated by purpose."
    },
    {
        "id": "KB-SEC-05",
        "section": "Section 5",
        "rules": ["Rule 3"],
        "title": "Itemised Privacy Notice in Plain Language & 8th Schedule",
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "keywords": ["notice", "privacy policy", "itemised", "language", "hindi", "english", "8th schedule", "grievance officer", "purpose"],
        "summary": (
            "Under Section 5(1), every request for consent must be accompanied or preceded by an itemised notice informing the Data Principal of: "
            "(i) the personal data and the specific purpose for which it is to be processed, (ii) the manner in which they may exercise rights under Section 11-14, "
            "and (iii) the contact details of the Data Protection Officer or Grievance Officer. "
            "Under Section 5(3), the notice must be available in English or any of the 22 languages specified in the Eighth Schedule to the Constitution of India."
        ),
        "source_doc": "DPDP Act 2023 Section 5 & Rules 2025 Rule 3",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹50 crore (Schedule Item 6: General Contravention)",
        "action_guidance": "Draft and publish a Section 5 notice specifying personal data collected, specific processing purposes, rights mechanisms, and designated Grievance Officer email in English and Hindi/regional language."
    },
    {
        "id": "KB-SEC-07",
        "section": "Section 7",
        "rules": [],
        "title": "Certain Legitimate Uses for Processing Personal Data",
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "keywords": ["legitimate use", "voluntary provision", "employment", "medical emergency", "epidemic", "disaster", "court order", "legal obligation"],
        "summary": (
            "Section 7 strictly enumerates legitimate grounds for processing without explicit Section 6 consent: "
            "(a) where the Data Principal voluntarily provides data without indicating objection, (b) for state subsidies or benefits, "
            "(c) for state performance of functions under law, (d) for compliance with any judgment or court order, "
            "(e) for responding to a medical emergency involving threat to life, (f) for taking measures to provide medical treatment during epidemic or outbreak, "
            "(g) for taking safety measures during disaster or breakdown of public order, and (h) for employment purposes and corporate espionage safeguards."
        ),
        "source_doc": "DPDP Act 2023 Section 7",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹50 crore (Schedule Item 6: General Contravention)",
        "action_guidance": "Verify that any data processing carried out without consent falls strictly within one of the eight clauses of Section 7."
    },
    {
        "id": "KB-SEC-08-05",
        "section": "Section 8(5)",
        "rules": ["Rule 6"],
        "title": "Reasonable Security Safeguards to Prevent Personal Data Breach",
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "keywords": ["security safeguards", "encryption", "tls", "aes-256", "firewall", "access control", "technical measures", "safeguard", "250 crore"],
        "summary": (
            "Section 8(5) establishes an absolute statutory duty: 'A Data Fiduciary shall protect personal data in its possession or under its control, "
            "including in respect of any processing undertaken by it or on its behalf by a Data Processor, by taking reasonable security safeguards to prevent personal data breach.' "
            "Carries the highest statutory penalty ceiling under the Act: Up to ₹250 crore (Schedule Item 1)."
        ),
        "source_doc": "DPDP Act 2023 Section 8(5) & Schedule Item 1",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹250 crore (Schedule Item 1)",
        "action_guidance": "Enforce TLS 1.3 in transit, AES-256 database encryption at rest, role-based access control, periodic vulnerability assessments, and dependency integrity verification."
    },
    {
        "id": "KB-SEC-08-06",
        "section": "Section 8(6)",
        "rules": ["Rule 7"],
        "title": "Mandatory Dual-Stage Personal Data Breach Intimation",
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "keywords": ["breach notification", "intimation", "data protection board", "dpbi", "cert-in", "incident", "leak", "200 crore"],
        "summary": (
            "Under Section 8(6), upon discovering a personal data breach, the Data Fiduciary must give the Data Protection Board of India "
            "and each affected Data Principal notice of such breach in such form and manner as prescribed under Rule 7. "
            "Rule 7 mandates a dual-stage protocol: (1) Initial preliminary intimation with nature and estimated scope, "
            "followed by (2) a comprehensive report detailing containment actions, root cause, and remedial steps. "
            "Failure to notify carries a maximum penalty ceiling of Up to ₹200 crore (Schedule Item 2)."
        ),
        "source_doc": "DPDP Act 2023 Section 8(6), Rules 2025 Rule 7 & Schedule Item 2",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹200 crore (Schedule Item 2)",
        "action_guidance": "Establish a dual-stage breach intimation runbook with pre-drafted Form A regulatory templates and customer notification workflows."
    },
    {
        "id": "KB-SEC-08-07",
        "section": "Section 8(7) & Section 8(8)",
        "rules": ["Rule 8"],
        "title": "Data Retention Limits & Mandatory Purpose-Cessation Erasure",
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "keywords": ["retention", "erasure", "deletion", "purpose cessation", "storage limit", "purge", "retention schedule"],
        "summary": (
            "Section 8(7) mandates that a Data Fiduciary must erase personal data upon: (a) the Data Principal withdrawing consent, or "
            "(b) as soon as it is reasonable to assume that the specified purpose is no longer being served, whichever is earlier, "
            "unless retention is necessary for compliance with any law. "
            "Under Rule 8, organizations must document retention schedules for each category of personal data."
        ),
        "source_doc": "DPDP Act 2023 Section 8(7) & Rules 2025 Rule 8",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹50 crore (Schedule Item 6: General Contravention)",
        "action_guidance": "Document retention schedules tied to specific statutory grounds (e.g. 8 years for tax, 3-5 years for clinical records, 180 days for web access logs)."
    },
    {
        "id": "KB-SEC-08-02",
        "section": "Section 8(2)",
        "rules": ["Rule 5"],
        "title": "Data Processor Engagement under Valid Binding Contract (DPA)",
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "keywords": ["processor", "vendor", "dpa", "contract", "third party", "subprocessor", "agreement"],
        "summary": (
            "Under Section 8(2), a Data Fiduciary may engage, appoint, use or involve a Data Processor to process personal data on its behalf "
            "only under a valid contract. The Data Fiduciary remains primarily liable to the Data Protection Board for compliance."
        ),
        "source_doc": "DPDP Act 2023 Section 8(2)",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹50 crore (Schedule Item 6: General Contravention)",
        "action_guidance": "Execute Data Processing Addenda (DPAs) with all cloud hosts, SaaS tools, and diagnostic labs incorporating confidentiality and security terms."
    },
    {
        "id": "KB-SEC-09",
        "section": "Section 9",
        "rules": ["Rule 9"],
        "title": "Processing of Personal Data of Children & Persons with Disabilities",
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "keywords": ["children", "minor", "under 18", "parental consent", "tracking", "behavioral monitoring", "targeted ads", "200 crore"],
        "summary": (
            "Section 9 mandates: (1) Verifiable parental consent before processing personal data of a child (under 18 years) or person with disability. "
            "(2) Prohibition on processing personal data that is likely to cause any detrimental effect on the well-being of a child. "
            "(3) Absolute prohibition on tracking, behavioral monitoring, or targeted advertising directed at children. "
            "Statutory penalty ceiling: Up to ₹200 crore (Schedule Item 3)."
        ),
        "source_doc": "DPDP Act 2023 Section 9 & Schedule Item 3",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹200 crore (Schedule Item 3)",
        "action_guidance": "Implement verifiable parental consent mechanisms and disable all behavioral tracking cookies and advertising analytics on minor interfaces."
    },
    {
        "id": "KB-SEC-10",
        "section": "Section 10",
        "rules": ["Rule 10", "Rule 11"],
        "title": "Significant Data Fiduciary (SDF) Obligations",
        "effective_date": "13 May 2027 (Conditional upon SDF designation)",
        "commencement_status": "Scheduled to commence",
        "keywords": ["significant data fiduciary", "sdf", "dpo", "dpia", "independent auditor", "periodic audit", "150 crore"],
        "summary": (
            "Section 10 applies to entities designated as Significant Data Fiduciaries by Central Government notifications. "
            "Obligations include: (a) Appointing a Data Protection Officer (DPO) based in India representing the entity to the Board, "
            "(b) Appointing an independent data auditor to evaluate compliance, (c) Conducting periodic Data Protection Impact Assessments (DPIA), "
            "and (d) Undertaking periodic statutory audits. Statutory penalty ceiling: Up to ₹150 crore (Schedule Item 4)."
        ),
        "source_doc": "DPDP Act 2023 Section 10 & Schedule Item 4",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹150 crore (Schedule Item 4)",
        "action_guidance": "Assess your data volume and risk profile against Section 10 criteria; maintain readiness for DPO designation and DPIA workflows."
    },
    {
        "id": "KB-SEC-11-14",
        "section": "Sections 11, 12, 13 & 14",
        "rules": ["Rule 12", "Rule 13", "Rule 14"],
        "title": "Data Principal Rights: Access, Correction, Erasure, Grievance & Nomination",
        "effective_date": "13 May 2027",
        "commencement_status": "Scheduled to commence",
        "keywords": ["data principal rights", "access", "correction", "erasure", "grievance", "redressal", "nomination", "dsr"],
        "summary": (
            "Sections 11–14 establish core individual privacy rights: "
            "Section 11: Right to access personal data, summary of processing, and identities of all entities with whom data has been shared. "
            "Section 12: Right to correction of inaccurate data, completion of incomplete data, and erasure of personal data. "
            "Section 13: Right of grievance redressal provided by the Data Fiduciary. Exhaustion of internal grievance mechanism is required before filing a complaint with the Data Protection Board. "
            "Section 14: Right to nominate an individual to exercise rights in the event of death or incapacity."
        ),
        "source_doc": "DPDP Act 2023 Sections 11–14 & Rules 2025 Rules 12–14",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹50 crore (Schedule Item 6: General Contravention)",
        "action_guidance": "Deploy an online Data Principal Rights and Grievance intake channel with tracking, verification, and audit trail logging."
    },
    {
        "id": "KB-SEC-06-09",
        "section": "Section 6(9) & Rule 4",
        "rules": ["Rule 4"],
        "title": "Consent Manager Registration & Architecture",
        "effective_date": "13 November 2026 (IN FORCE)",
        "commencement_status": "In force",
        "keywords": ["consent manager", "registration", "meity", "interoperable", "in force", "active", "rule 4"],
        "summary": (
            "Section 6(9) establishes the statutory framework for Consent Managers: entities registered with the Data Protection Board of India "
            "that act as a single point for Data Principals to give, manage, review and withdraw consent through an accessible, transparent, and interoperable platform. "
            "Commenced into force on 13 November 2026 under S.O. 5122(E)."
        ),
        "source_doc": "DPDP Act 2023 Section 6(9), DPDP Rules 2025 Rule 4 & Gazette S.O. 5122(E)",
        "source_url": "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
        "penalties": "Up to ₹50 crore (Schedule Item 6: General Contravention)",
        "action_guidance": "Understand that TrustAudit assists internal consent record keeping and is not a registered statutory Consent Manager under Section 6(9)."
    }
]

ASSISTANT_DISCLAIMER = (
    "Disclaimer: This guidance is generated for compliance planning and privacy operations under India's "
    "Digital Personal Data Protection Act, 2023 and DPDP Rules, 2025. It is source-grounded but does not constitute "
    "statutory legal counsel or regulatory certification. Organizations should consult qualified legal review for statutory filings."
)


def _get_tenant_context(org_id: str) -> Dict[str, Any]:
    """Safely retrieves tenant compliance profile without cross-tenant leakage."""
    profile = dpdp_store.get_onboarding_profile(org_id) or {}
    inventory = dpdp_store.get_data_inventory(org_id)
    vendors = dpdp_store.get_vendors(org_id)
    assessment = dpdp_store.get_assessment(org_id)
    
    return {
        "org_name": profile.get("company_name", "Your Organisation"),
        "industry": profile.get("industry", "Technology & Services"),
        "inventory_count": len(inventory),
        "inventory_categories": [i.get("category") for i in inventory[:5]],
        "vendor_count": len(vendors),
        "readiness_score": assessment.get("readiness_score", 0),
        "gaps_count": len(assessment.get("gaps", []))
    }


STOPWORDS = {"how", "do", "i", "a", "an", "the", "in", "on", "of", "for", "to", "and", "or", "is", "are", "what", "can", "my", "we", "our", "under", "with", "about", "should", "handle"}

def query_ai_dpdp_assistant(query: str, org_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Core RAG retrieval engine for the AI DPDP Assistant.
    Retrieves matching statutory knowledge, enriches with tenant context,
    and returns source-cited, legally accurate guidance.
    """
    clean_q = query.lower().strip()
    words = set(re.findall(r'\b[a-z]{3,}\b', clean_q)) - STOPWORDS
    org_id = org_id or "org-default"

    # 1. Retrieve top matching statutory corpus entries
    scored_entries = []
    for item in DPDP_KNOWLEDGE_CORPUS:
        score = 0
        # Check phrase matches
        for kw in item["keywords"]:
            kw_clean = kw.lower().strip()
            if " " in kw_clean and kw_clean in clean_q:
                score += 25
            elif kw_clean in clean_q:
                score += 10
            elif any(re.search(r'\b' + re.escape(w) + r'\b', kw_clean) for w in words):
                score += 3
        # Check Section matches
        if item["section"].lower() in clean_q or any(r.lower() in clean_q for r in item.get("rules", [])):
            score += 20
        if score > 0:
            scored_entries.append((score, item))

    scored_entries.sort(key=lambda x: x[0], reverse=True)
    best_entry = scored_entries[0][1] if scored_entries else DPDP_KNOWLEDGE_CORPUS[0]
    matched_entries = [e[1] for e in scored_entries[:3]] if scored_entries else [DPDP_KNOWLEDGE_CORPUS[0]]

    # 2. Extract tenant context
    tenant_ctx = _get_tenant_context(org_id)

    # 3. Determine commencement status
    commencement_info = dpdp_commencement.get_statutory_commencement(best_entry["section"])

    # 4. Determine penalty ceiling
    penalty_info = dpdp_penalties.map_statutory_penalty(best_entry["section"])

    # 5. Check for GEMINI_API_KEY for dynamic synthesis if available
    gemini_key = os.environ.get("GEMINI_API_KEY", "").strip()
    synthesized_answer = None
    ai_engine = "Deterministic Grounded RAG (Local Verified Knowledge Base)"

    if gemini_key:
        try:
            # Construct strict grounded prompt for Gemini
            grounding_text = "\n\n".join([f"[{m['section']}]: {m['summary']}\nRecommended Action: {m['action_guidance']}" for m in matched_entries])
            prompt_content = (
                f"You are the TrustAudit DPDP Compliance Assistant. Answer this user query strictly based on the following verified DPDP Act 2023 text:\n\n"
                f"{grounding_text}\n\n"
                f"Organisation Context: Name: {tenant_ctx['org_name']}, Industry: {tenant_ctx['industry']}, Inventory streams: {tenant_ctx['inventory_count']}.\n\n"
                f"User Question: {query}\n\n"
                f"Requirements: Explain the statutory requirement simply. Distinguish in-force obligations from May 2027 future requirements. "
                f"Never invent statutory penalties or guarantee compliance. Always cite exact Section numbers."
            )
            
            # Simple REST call to Gemini API
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
            req_data = json.dumps({"contents": [{"parts": [{"text": prompt_content}]}]}).encode("utf-8")
            req = urllib.request.Request(url, data=req_data, headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                candidates = resp_json.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        synthesized_answer = parts[0].get("text", "").strip()
                        ai_engine = "Gemini 1.5 Flash (Grounded on DPDP Act & Rules 2025)"
        except Exception:
            # Graceful fallback to deterministic synthesis
            synthesized_answer = None

    # Deterministic fallback answer construction
    if not synthesized_answer:
        synthesized_answer = (
            f"**Legal Citation:** {best_entry['section']} ({best_entry['title']})\n\n"
            f"**Statutory Commencement:** {commencement_info['commencement_status']} "
            f"({best_entry['effective_date']})\n\n"
            f"**Summary of Provision:**\n{best_entry['summary']}\n\n"
            f"**Maximum Statutory Penalty Ceiling:** {penalty_info['max_penalty_text']} "
            f"({penalty_info.get('contravention', 'Schedule to DPDP Act')})\n\n"
            f"**Recommended Action for {tenant_ctx['org_name']}:**\n{best_entry['action_guidance']}"
        )

    # Compile suggested questions
    suggested_questions = [
        "What are my itemised notice obligations under Section 5?",
        "How should consent withdrawal be handled under Section 6(4)?",
        "What are the dual-stage breach notification requirements under Section 8(6)?",
        "What are the restrictions on processing children's data under Section 9?",
        "When does the DPDP Act come into full force for Indian businesses?"
    ]

    return {
        "status": "success",
        "query": query,
        "answer": synthesized_answer,
        "matched_section": best_entry["section"],
        "effective_status": commencement_info["commencement_status"],
        "effective_date": best_entry["effective_date"],
        "enforceable_now": commencement_info["enforceable_now"],
        "max_penalty_ceiling": penalty_info["max_penalty_text"],
        "statutory_penalty_disclaimer": dpdp_penalties.STATUTORY_PENALTY_DISCLAIMER,
        "source_document": best_entry["source_doc"],
        "source_url": best_entry["source_url"],
        "recommended_action": best_entry["action_guidance"],
        "organization_context_applied": {
            "org_name": tenant_ctx["org_name"],
            "industry": tenant_ctx["industry"],
            "inventory_streams_mapped": tenant_ctx["inventory_count"],
            "active_vendors": tenant_ctx["vendor_count"]
        },
        "engine": ai_engine,
        "suggested_questions": [q for q in suggested_questions if q.lower() != clean_q][:4],
        "disclaimer": ASSISTANT_DISCLAIMER,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }
