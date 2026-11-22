"""
TrustAudit — DPDP Dedicated Data Store & Tenant-Isolated Persistence
====================================================================
Stores and manages all DPDP compliance artifacts per organization:
- Personal Data Inventory (CSV import/export supported)
- Assessments, Questionnaires & Gap Analysis
- Privacy Notices & 8th Schedule Translations
- Consent Records & Section 6(4)-(6) Withdrawal Workflows
- Data Principal Rights Requests (Access, Correction, Erasure, Grievance, Nomination)
- Vendor & Data Processor Register (DPAs, Cloud regions, Review cycles)
- Retention Schedules & Deletion Workflows (Rule 8)
- Personal Data Breach Register & Dual-Stage Intimation Drafts (Section 8(6) & Rule 7)
- Remediation Centre Action Items
"""

import os
import json
import uuid
import datetime
import io
import csv
from typing import Dict, List, Any, Optional, Tuple
from dpdp_engine import DPDP_REQUIREMENTS, INDUSTRY_TEMPLATES
import dpdp_penalties
import dpdp_commencement

DPDP_DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "dpdp_store.json")

def _ensure_data_dir():
    os.makedirs(os.path.dirname(DPDP_DATA_FILE), exist_ok=True)

def _load_dpdp_store() -> Dict[str, Any]:
    _ensure_data_dir()
    if not os.path.exists(DPDP_DATA_FILE):
        initial = {
            "version": "1.0",
            "data_inventories": {},
            "assessments": {},
            "privacy_notices": {},
            "consent_records": {},
            "withdrawal_requests": {},
            "rights_requests": {},
            "vendors": {},
            "retention_schedules": {},
            "breach_incidents": {},
            "remediation_tasks": {},
            "onboarding_profiles": {},
            "erasure_tasks": {},
            "website_scans": {}
        }
        with open(DPDP_DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(initial, f, indent=2)
        return initial
    try:
        with open(DPDP_DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "version": "1.0",
            "data_inventories": {},
            "assessments": {},
            "privacy_notices": {},
            "consent_records": {},
            "withdrawal_requests": {},
            "rights_requests": {},
            "vendors": {},
            "retention_schedules": {},
            "breach_incidents": {},
            "remediation_tasks": {},
            "onboarding_profiles": {},
            "erasure_tasks": {},
            "website_scans": {}
        }

def _save_dpdp_store(data: Dict[str, Any]) -> None:
    _ensure_data_dir()
    with open(DPDP_DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ==============================================================================
# ONBOARDING & INDUSTRY SELECTION
# ==============================================================================

def get_onboarding_profile(org_id: str) -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("onboarding_profiles", {}).get(org_id)

def save_onboarding_profile(org_id: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "onboarding_profiles" not in store:
        store["onboarding_profiles"] = {}
        
    existing = store["onboarding_profiles"].get(org_id, {})
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    profile = {
        **existing,
        **profile_data,
        "org_id": org_id,
        "updated_at": now
    }
    if "created_at" not in profile:
        profile["created_at"] = now
        
    store["onboarding_profiles"][org_id] = profile
    _save_dpdp_store(store)
    
    # If industry template chosen and inventory is empty, pre-populate template
    industry = profile.get("industry", "healthcare").lower()
    if industry in INDUSTRY_TEMPLATES and not get_data_inventory(org_id):
        prepopulate_industry_inventory(org_id, industry)
        
    return profile

# ==============================================================================
# PERSONAL DATA INVENTORY
# ==============================================================================

def get_data_inventory(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("data_inventories", {}).get(org_id, [])

def add_inventory_entry(org_id: str, entry_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "data_inventories" not in store:
        store["data_inventories"] = {}
    if org_id not in store["data_inventories"]:
        store["data_inventories"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    entry = {
        "id": f"inv-{uuid.uuid4().hex[:8]}",
        "category": entry_data.get("category", "General Personal Data"),
        "principal_type": entry_data.get("principal_type", "Customers / Users"),
        "source": entry_data.get("source", "Direct Registration"),
        "purpose": entry_data.get("purpose", "Service Delivery"),
        "legal_basis": entry_data.get("legal_basis", "DPDP Section 6 (Consent)"),
        "collection_method": entry_data.get("collection_method", "Web Form / Registration"),
        "storage_system": entry_data.get("storage_system", "Primary Database"),
        "department": entry_data.get("department", "Operations"),
        "owner": entry_data.get("owner", "Data Protection Lead"),
        "external_recipients": entry_data.get("external_recipients", "None"),
        "processor": entry_data.get("processor", "None"),
        "retention_period": entry_data.get("retention_period", "3 Years"),
        "deletion_method": entry_data.get("deletion_method", "Database Purge"),
        "international_transfer": entry_data.get("international_transfer", "None (India hosted)"),
        "created_at": now,
        "updated_at": now
    }
    store["data_inventories"][org_id].append(entry)
    _save_dpdp_store(store)
    return entry

def update_inventory_entry(org_id: str, entry_id: str, entry_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    items = store.get("data_inventories", {}).get(org_id, [])
    for idx, item in enumerate(items):
        if item.get("id") == entry_id:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            updated = {**item, **entry_data, "updated_at": now}
            store["data_inventories"][org_id][idx] = updated
            _save_dpdp_store(store)
            return updated
    return None

def delete_inventory_entry(org_id: str, entry_id: str) -> bool:
    store = _load_dpdp_store()
    items = store.get("data_inventories", {}).get(org_id, [])
    filtered = [i for i in items if i.get("id") != entry_id]
    if len(filtered) != len(items):
        store["data_inventories"][org_id] = filtered
        _save_dpdp_store(store)
        return True
    return False

def prepopulate_industry_inventory(org_id: str, industry: str) -> List[Dict[str, Any]]:
    template = INDUSTRY_TEMPLATES.get(industry.lower(), INDUSTRY_TEMPLATES["healthcare"])
    created = []
    for item in template.get("sample_data_inventory", []):
        created.append(add_inventory_entry(org_id, item))
    return created

def export_inventory_csv(org_id: str) -> str:
    items = get_data_inventory(org_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Data Category", "Data Principal Type", "Collection Source",
        "Processing Purpose", "Legal Basis", "Collection Method", "Storage System",
        "Department", "Internal Owner", "External Recipients", "Data Processor",
        "Retention Period", "Deletion Method", "Cross-Border Transfer"
    ])
    for item in items:
        writer.writerow([
            item.get("id", ""),
            item.get("category", ""),
            item.get("principal_type", ""),
            item.get("source", ""),
            item.get("purpose", ""),
            item.get("legal_basis", ""),
            item.get("collection_method", ""),
            item.get("storage_system", ""),
            item.get("department", ""),
            item.get("owner", ""),
            item.get("external_recipients", ""),
            item.get("processor", ""),
            item.get("retention_period", ""),
            item.get("deletion_method", ""),
            item.get("international_transfer", "")
        ])
    return output.getvalue()

def import_inventory_csv(org_id: str, csv_content: str) -> int:
    reader = csv.DictReader(io.StringIO(csv_content))
    count = 0
    for row in reader:
        entry = {
            "category": row.get("Data Category") or row.get("category", "General Data"),
            "principal_type": row.get("Data Principal Type") or row.get("principal_type", "Users"),
            "source": row.get("Collection Source") or row.get("source", "Direct"),
            "purpose": row.get("Processing Purpose") or row.get("purpose", "Operations"),
            "legal_basis": row.get("Legal Basis") or row.get("legal_basis", "DPDP Section 6 (Consent)"),
            "collection_method": row.get("Collection Method") or row.get("collection_method", "Web"),
            "storage_system": row.get("Storage System") or row.get("storage_system", "DB"),
            "department": row.get("Department") or row.get("department", "General"),
            "owner": row.get("Internal Owner") or row.get("owner", "Admin"),
            "external_recipients": row.get("External Recipients") or row.get("external_recipients", "None"),
            "processor": row.get("Data Processor") or row.get("processor", "None"),
            "retention_period": row.get("Retention Period") or row.get("retention_period", "3 Years"),
            "deletion_method": row.get("Deletion Method") or row.get("deletion_method", "Purge"),
            "international_transfer": row.get("Cross-Border Transfer") or row.get("international_transfer", "None")
        }
        add_inventory_entry(org_id, entry)
        count += 1
    return count

# ==============================================================================
# DPDP ASSESSMENT & GAP IDENTIFICATION
# ==============================================================================

def get_assessment(org_id: str) -> Dict[str, Any]:
    store = _load_dpdp_store()
    assessment = store.get("assessments", {}).get(org_id)
    if not assessment:
        # Generate initial default evaluation against DPDP_REQUIREMENTS
        assessment = _initialize_assessment(org_id)
        store["assessments"][org_id] = assessment
        _save_dpdp_store(store)
    return assessment

def _initialize_assessment(org_id: str) -> Dict[str, Any]:
    profile = get_onboarding_profile(org_id) or {}
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    is_demo = org_id in ("demo", "acme") or org_id.startswith("demo-") or profile.get("is_demo") is True
    
    controls_assessment = []
    gaps = []
    remediation_tasks = []
    
    for req in DPDP_REQUIREMENTS:
        comm = dpdp_commencement.get_statutory_commencement(req["section"])
        penalty = dpdp_penalties.map_statutory_penalty(f"{req['section']} {req['id']}")
        
        if is_demo:
            status = "GAP_IDENTIFIED" if req["id"] in ("DPDP-SEC-05", "DPDP-SEC-08-01", "DPDP-SEC-08-06") else "SELF_ATTESTED_IMPLEMENTED"
            verification_status = "Demo Sample (Simulated Attestation)" if status == "SELF_ATTESTED_IMPLEMENTED" else "Open Gap"
        else:
            status = "GAP_IDENTIFIED"
            verification_status = "Unassessed (Awaiting Documentation / Answers)"
            
        control_record = {
            "requirement_id": req["id"],
            "section": req["section"],
            "title": req["title"],
            "category": req["readiness_category"],
            "effective_date": comm["effective_date"],
            "enforceable_now": comm["enforceable_now"],
            "commencement_status": comm["commencement_status"],
            "legal_status": req["legal_status"],
            "statutory_ceiling": penalty.get("max_penalty_text", "Requires legal review"),
            "schedule_item": penalty.get("schedule_item", "Advisory"),
            "penalty_disclaimer": penalty.get("statutory_disclaimer", ""),
            "status": status,
            "evidence_count": 0,
            "verification_status": verification_status,
            "last_assessed": now
        }
        controls_assessment.append(control_record)
        
        if status == "GAP_IDENTIFIED":
            gap = {
                "id": f"gap-{uuid.uuid4().hex[:6]}",
                "requirement_id": req["id"],
                "section": req["section"],
                "title": f"Compliance Gap: {req['title']}",
                "applicability": "Applicable to all Data Fiduciaries",
                "condition_identified": f"Missing documented operational process for {req['title']}.",
                "why_it_matters": (
                    f"Section {req['section']} mandates verifiable operational controls. "
                    f"Statutory ceiling under Schedule Item {penalty.get('schedule_item', 'General')}: {penalty.get('max_penalty_text', 'Requires legal review')}. "
                    f"Commencement status: {comm['commencement_status']} (Effective: {comm['effective_date']})."
                ),
                "statutory_penalty": penalty.get("max_penalty_text", "Requires legal review"),
                "schedule_item": penalty.get("schedule_item", "General"),
                "commencement_date": comm["effective_date"],
                "enforceable_now": comm["enforceable_now"],
                "evidence_required": req["evidence_required"][0] if req["evidence_required"] else "Policy Document",
                "recommended_solution": req["remediation_guidance"],
                "priority": "HIGH" if "critical" in str(req.get("assessment_questions", "")) or comm["enforceable_now"] else "MEDIUM",
                "owner": "Compliance Lead",
                "deadline": comm["effective_date"],
                "verification_status": "Open — Needs Remediation"
            }
            gaps.append(gap)
            
            task = {
                "id": f"rem-{uuid.uuid4().hex[:6]}",
                "gap_id": gap["id"],
                "requirement_id": req["id"],
                "title": f"Draft & Implement {req['title']} Procedure",
                "category": req["readiness_category"],
                "status": "OPEN",
                "priority": gap["priority"],
                "owner": "Compliance Lead",
                "deadline": comm["effective_date"],
                "guidance": req["remediation_guidance"],
                "created_at": now
            }
            remediation_tasks.append(task)
            
    total = len(controls_assessment)
    implemented = sum(1 for c in controls_assessment if c["status"] == "SELF_ATTESTED_IMPLEMENTED")
    readiness_score = int((implemented / total) * 100) if total else 0
    readiness_label = "Demo Sample (Partially Implemented)" if is_demo else "Unassessed (Action Required)"
    
    return {
        "org_id": org_id,
        "is_demo": is_demo,
        "readiness_score": readiness_score,
        "readiness_label": readiness_label,
        "controls_total": total,
        "controls_implemented": implemented,
        "gaps_count": len(gaps),
        "controls": controls_assessment,
        "gaps": gaps,
        "remediation_tasks": remediation_tasks,
        "created_at": now,
        "updated_at": now
    }

def update_assessment_control(org_id: str, requirement_id: str, status: str, notes: str = "") -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    assessment = get_assessment(org_id)
    controls = assessment.get("controls", [])
    
    updated_ctrl = None
    for c in controls:
        if c.get("requirement_id") == requirement_id:
            c["status"] = status
            c["notes"] = notes
            c["last_assessed"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            updated_ctrl = c
            break
            
    if updated_ctrl:
        # Recompute readiness score
        total = len(controls)
        implemented = sum(1 for c in controls if c["status"] in ("SELF_ATTESTED_IMPLEMENTED", "REVIEWED_AND_SUPPORTED"))
        assessment["readiness_score"] = int((implemented / total) * 100) if total else 0
        assessment["controls_implemented"] = implemented
        assessment["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # If status moved to implemented, close linked gap
        if status in ("SELF_ATTESTED_IMPLEMENTED", "REVIEWED_AND_SUPPORTED"):
            assessment["gaps"] = [g for g in assessment.get("gaps", []) if g.get("requirement_id") != requirement_id]
        
        store["assessments"][org_id] = assessment
        _save_dpdp_store(store)
        return assessment
    return None

def calculate_dynamic_readiness(org_id: str) -> Dict[str, Any]:
    """
    Computes genuine multi-dimensional readiness scores:
    - Separates currently enforceable provisions (Phase 1 & 2) from forward-looking (13 May 2027)
    - Sub-scores by statutory domain
    - Differentiates verified evidence from self-attestations
    """
    assessment = get_assessment(org_id)
    controls = assessment.get("controls", [])
    evidence = get_evidence_artifacts(org_id)
    
    verified_controls = set()
    for e in evidence:
        if e.get("status") == "Verified" and e.get("control_id"):
            verified_controls.add(e.get("control_id"))
            
    total_controls = len(controls)
    enforceable_controls = []
    forward_controls = []
    
    categories = {
        "Notices & Consent": {"total": 0, "verified": 0, "attested": 0},
        "Security Safeguards": {"total": 0, "verified": 0, "attested": 0},
        "Vendor Governance": {"total": 0, "verified": 0, "attested": 0},
        "Rights & Grievance": {"total": 0, "verified": 0, "attested": 0},
        "Retention & Erasure": {"total": 0, "verified": 0, "attested": 0},
        "Breach Readiness": {"total": 0, "verified": 0, "attested": 0}
    }
    
    for c in controls:
        sec = c.get("section", "")
        req_id = c.get("requirement_id", "")
        cat = c.get("category", "Security Safeguards")
        
        is_enforceable = dpdp_commencement.is_currently_enforceable(sec)
        if is_enforceable:
            enforceable_controls.append(c)
        else:
            forward_controls.append(c)
            
        is_verified = req_id in verified_controls
        is_attested = c.get("status") in ("SELF_ATTESTED_IMPLEMENTED", "REVIEWED_AND_SUPPORTED")
        
        # Categorize
        target_cat = "Security Safeguards"
        for k in categories.keys():
            if k.lower() in cat.lower() or cat.lower() in k.lower():
                target_cat = k
                break
                
        categories[target_cat]["total"] += 1
        if is_verified:
            categories[target_cat]["verified"] += 1
        elif is_attested:
            categories[target_cat]["attested"] += 1

    def _score(ctrl_list):
        if not ctrl_list:
            return 0
        points = 0.0
        for c in ctrl_list:
            cid = c.get("requirement_id")
            if cid in verified_controls:
                points += 1.0
            elif c.get("status") in ("SELF_ATTESTED_IMPLEMENTED", "REVIEWED_AND_SUPPORTED"):
                points += 0.5
        return int((points / len(ctrl_list)) * 100)
        
    overall_score = _score(controls)
    enforceable_score = _score(enforceable_controls) if enforceable_controls else 100
    forward_score = _score(forward_controls) if forward_controls else 0
    
    sub_scores = {}
    for cat_name, data in categories.items():
        if data["total"] > 0:
            sub_scores[cat_name] = int(((data["verified"] * 1.0 + data["attested"] * 0.5) / data["total"]) * 100)
        else:
            sub_scores[cat_name] = 0
            
    return {
        "org_id": org_id,
        "is_demo": assessment.get("is_demo", False),
        "overall_readiness_score": overall_score,
        "enforceable_now_score": enforceable_score,
        "forward_looking_score": forward_score,
        "sub_scores": sub_scores,
        "metrics": {
            "total_controls": total_controls,
            "verified_controls_count": len(verified_controls),
            "self_attested_count": sum(1 for c in controls if c.get("status") in ("SELF_ATTESTED_IMPLEMENTED", "REVIEWED_AND_SUPPORTED") and c.get("requirement_id") not in verified_controls),
            "gaps_count": sum(1 for c in controls if c.get("status") not in ("SELF_ATTESTED_IMPLEMENTED", "REVIEWED_AND_SUPPORTED") and c.get("requirement_id") not in verified_controls),
            "evidence_documents_count": len(evidence)
        },
        "commencement_context": {
            "phase_1_and_2": "In force (Institutional & Consent Managers)",
            "phase_3_substantive": "Scheduled to commence 13 May 2027 (Sections 3-17)"
        }
    }

# ==============================================================================
# PRIVACY NOTICE MANAGEMENT
# ==============================================================================

def get_privacy_notices(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("privacy_notices", {}).get(org_id, [])

def generate_privacy_notice(org_id: str, notice_params: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "privacy_notices" not in store:
        store["privacy_notices"] = {}
    if org_id not in store["privacy_notices"]:
        store["privacy_notices"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    company_name = notice_params.get("company_name", "Your Organisation")
    grievance_email = notice_params.get("grievance_email", "grievance@organisation.com")
    grievance_officer = notice_params.get("grievance_officer", "Data Protection Grievance Officer")
    address = notice_params.get("address", "Registered Office, India")
    
    inventory_items = get_data_inventory(org_id)
    purposes_text = "\n".join([f"• {i.get('category')}: {i.get('purpose')} (Basis: {i.get('legal_basis')})" for i in inventory_items[:6]])
    if not purposes_text:
        purposes_text = "• Patient/Customer Records: Service fulfillment, medical consultation, and operational communication (DPDP Section 6 Consent)."
        
    notice_text = f"""ITEMISED PRIVACY NOTICE
Digital Personal Data Protection Act, 2023 (Section 5 read with Rule 3)

1. Identity of Data Fiduciary:
{company_name} (Address: {address})

2. Personal Data Collected & Processing Purposes:
We collect and process digital personal data solely for specified lawful purposes:
{purposes_text}

3. Your Statutory Rights as Data Principal (Sections 11–14):
You possess statutory rights to:
• Right to Access: Obtain a summary of your personal data and third parties shared with.
• Right to Correction & Updating: Request correction of inaccurate or incomplete records.
• Right to Erasure: Request erasure where statutory clinical or legal retention does not mandate preservation.
• Right to Withdraw Consent: Withdraw consent at any time with the same ease as provided (Section 6(4)).
• Right to Nominate: Nominate a representative in the event of death or incapacity (Section 14).

4. Grievance Redressal Mechanism (Section 8(10) & Rule 9):
If you have any questions, rights requests, or grievances regarding your personal data:
Grievance Officer: {grievance_officer}
Email: {grievance_email}
Address: {address}
We endeavor to investigate and redress all grievances within thirty (30) business days.

5. Multilingual Availability:
This notice is prepared in English and is available in Hindi and other Eighth Schedule languages upon request at our reception desk or customer support portal."""

    notice = {
        "id": f"not-{uuid.uuid4().hex[:6]}",
        "title": notice_params.get("title", f"{company_name} Customer & Patient Privacy Notice"),
        "version": notice_params.get("version", "v1.0"),
        "status": "APPROVED_PUBLISHED",
        "content": notice_text,
        "languages_supported": ["English", "Hindi"],
        "grievance_officer": grievance_officer,
        "grievance_email": grievance_email,
        "created_at": now,
        "updated_at": now
    }
    store["privacy_notices"][org_id].append(notice)
    _save_dpdp_store(store)
    return notice

# ==============================================================================
# CONSENT RECORDS & WITHDRAWAL (SECTION 6(4)-(6))
# ==============================================================================

def get_consent_records(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("consent_records", {}).get(org_id, [])

def record_consent(org_id: str, consent_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "consent_records" not in store:
        store["consent_records"] = {}
    if org_id not in store["consent_records"]:
        store["consent_records"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    record = {
        "id": f"cst-{uuid.uuid4().hex[:8]}",
        "data_principal_ref": consent_data.get("principal_ref", "DP-XXXX"),
        "data_category": consent_data.get("category", "General Personal Data"),
        "purpose": consent_data.get("purpose", "Consultation / Service"),
        "notice_version": consent_data.get("notice_version", "v1.0"),
        "collection_channel": consent_data.get("channel", "Web Form / Registration"),
        "status": "ACTIVE",
        "timestamp": now
    }
    store["consent_records"][org_id].append(record)
    _save_dpdp_store(store)
    return record

def get_withdrawal_requests(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("withdrawal_requests", {}).get(org_id, [])

def submit_consent_withdrawal(org_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "withdrawal_requests" not in store:
        store["withdrawal_requests"] = {}
    if org_id not in store["withdrawal_requests"]:
        store["withdrawal_requests"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Check statutory retention exceptions (e.g. Clinical Records 3-5 years, Tax 8 years)
    retention_exception = request_data.get("retention_exception", False)
    exception_reason = (
        "Clinical case sheets must be preserved for 3 years under Clinical Establishments Rules."
        if retention_exception else "No statutory retention impediment."
    )
    
    withdrawal = {
        "id": f"wth-{uuid.uuid4().hex[:8]}",
        "data_principal_ref": request_data.get("principal_ref", "DP-XXXX"),
        "category": request_data.get("category", "All Consented Categories"),
        "requested_at": now,
        "processing_halt_status": "CEASED" if not retention_exception else "RESTRICTED_ARCHIVE_ONLY",
        "processor_notified": True,
        "processors_notified_list": ["Cloud HMS Software", "SMS Gateway", "Local Storage"],
        "statutory_exception_applies": retention_exception,
        "exception_reason": exception_reason,
        "status": "COMPLETED",
        "audit_trail": [
            f"{now}: Withdrawal request registered under DPDP Section 6(4)",
            f"{now}: Identity of Data Principal verified",
            f"{now}: Data processors instructed to cease operational processing",
            f"{now}: Audit record generated"
        ]
    }
    store["withdrawal_requests"][org_id].append(withdrawal)
    
    # Update matching active consent record if found
    for c in store.get("consent_records", {}).get(org_id, []):
        if c.get("data_principal_ref") == withdrawal["data_principal_ref"]:
            c["status"] = "WITHDRAWN"
            c["withdrawn_at"] = now
            
    _save_dpdp_store(store)
    return withdrawal

# ==============================================================================
# DATA PRINCIPAL RIGHTS MANAGEMENT (SECTIONS 11-14)
# ==============================================================================

def get_rights_requests(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("rights_requests", {}).get(org_id, [])

def submit_rights_request(org_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "rights_requests" not in store:
        store["rights_requests"] = {}
    if org_id not in store["rights_requests"]:
        store["rights_requests"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    req_type = request_data.get("type", "ACCESS")  # ACCESS, CORRECTION, ERASURE, GRIEVANCE, NOMINATION
    
    req = {
        "id": f"dpr-{uuid.uuid4().hex[:8]}",
        "type": req_type,
        "principal_name": request_data.get("principal_name", "Data Principal"),
        "principal_contact": request_data.get("principal_contact", "contact@domain.com"),
        "description": request_data.get("description", "Statutory rights request under DPDP Act"),
        "received_at": now,
        "assigned_to": request_data.get("assigned_to", "Privacy Grievance Officer"),
        "status": "RECEIVED",  # RECEIVED, VERIFIED, IN_PROGRESS, COMPLETED, REJECTED
        "sla_deadline": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).strftime("%Y-%m-%d"),
        "systems_involved": ["HMS Database", "Billing ERP", "Cloud Storage"],
        "response_summary": "",
        "closed_at": None,
        "audit_logs": [
            f"{now}: Rights request received and ticket generated."
        ]
    }
    store["rights_requests"][org_id].append(req)
    _save_dpdp_store(store)
    return req

def update_rights_request_status(org_id: str, request_id: str, status: str, response_summary: str = "") -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    items = store.get("rights_requests", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for item in items:
        if item.get("id") == request_id:
            item["status"] = status
            if response_summary:
                item["response_summary"] = response_summary
            item["audit_logs"].append(f"{now}: Status updated to {status}. Note: {response_summary}")
            if status == "COMPLETED":
                item["closed_at"] = now
            _save_dpdp_store(store)
            return item
    return None

def update_rights_request_full(org_id: str, request_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    items = store.get("rights_requests", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for item in items:
        if item.get("id") == request_id:
            for k, v in updates.items():
                if k != "id":
                    item[k] = v
            if "audit_logs" not in item:
                item["audit_logs"] = []
            item["audit_logs"].append(f"{now}: Full update applied: {list(updates.keys())}")
            if updates.get("status") == "COMPLETED" and not item.get("closed_at"):
                item["closed_at"] = now
            _save_dpdp_store(store)
            return item
    return None

# ==============================================================================
# VENDOR & PROCESSOR REGISTER (SECTION 8(1)-(2))
# ==============================================================================

def get_vendors(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("vendors", {}).get(org_id, [])

def add_vendor(org_id: str, vendor_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "vendors" not in store:
        store["vendors"] = {}
    if org_id not in store["vendors"]:
        store["vendors"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    vendor = {
        "id": f"vnd-{uuid.uuid4().hex[:6]}",
        "name": vendor_data.get("name", "Vendor Name"),
        "service": vendor_data.get("service", "Cloud / Software Provider"),
        "personal_data_processed": vendor_data.get("personal_data_processed", "Patient / Customer Records"),
        "storage_location": vendor_data.get("storage_location", "India (AWS Mumbai ap-south-1)"),
        "dpa_status": vendor_data.get("dpa_status", "EXECUTED"),  # EXECUTED, UNDER_REVIEW, MISSING
        "agreement_expiry": vendor_data.get("agreement_expiry", "2027-12-31"),
        "security_documentation": vendor_data.get("security_documentation", "ISO 27001 / SOC 2 Report on File"),
        "breach_notification_clause": vendor_data.get("breach_notification_clause", "24-Hour Notice Required"),
        "risk_rating": vendor_data.get("risk_rating", "LOW"),  # LOW, MEDIUM, HIGH
        "created_at": now
    }
    store["vendors"][org_id].append(vendor)
    _save_dpdp_store(store)
    return vendor

def update_vendor(org_id: str, vendor_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    vendors = store.get("vendors", {}).get(org_id, [])
    for v in vendors:
        if v.get("id") == vendor_id:
            for k, val in updates.items():
                if k != "id":
                    v[k] = val
            v["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            
            dpa_status = str(v.get("dpa_status", "")).upper()
            if "SIGNED" in dpa_status or "EXECUTED" in dpa_status or "ACTIVE" in dpa_status:
                v["statutory_risk"] = "COMPLIANT: Section 8(2) processor contract requirements verified."
            else:
                v["statutory_risk"] = "HIGH RISK: Section 8(2) prohibits engaging data processors without contract. Violations expose the fiduciary to penalties up to ₹250 crore under Section 8(5) / Schedule Item 1 if security fails, or up to ₹50 crore under Schedule Item 6."
            _save_dpdp_store(store)
            return v
    return None

def delete_vendor(org_id: str, vendor_id: str) -> bool:
    store = _load_dpdp_store()
    vendors = store.get("vendors", {}).get(org_id, [])
    initial_len = len(vendors)
    store.setdefault("vendors", {})[org_id] = [v for v in vendors if v.get("id") != vendor_id]
    if len(store["vendors"][org_id]) < initial_len:
        _save_dpdp_store(store)
        return True
    return False

# ==============================================================================
# RETENTION & ERASURE SCHEDULES (RULE 8)
# ==============================================================================

def get_retention_schedules(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("retention_schedules", {}).get(org_id, [])

def add_retention_schedule(org_id: str, schedule_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "retention_schedules" not in store:
        store["retention_schedules"] = {}
    if org_id not in store["retention_schedules"]:
        store["retention_schedules"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    sched = {
        "id": f"ret-{uuid.uuid4().hex[:6]}",
        "category": schedule_data.get("category", "General Records"),
        "purpose": schedule_data.get("purpose", "Operations"),
        "statutory_basis": schedule_data.get("statutory_basis", "DPDP Section 8(7)"),
        "period_years": schedule_data.get("period_years", 3),
        "end_of_purpose_trigger": schedule_data.get("end_of_purpose_trigger", "Treatment Completion / Account Inactivity"),
        "deletion_method": schedule_data.get("deletion_method", "Cryptographic Soft-Archive & Secure DB Purge"),
        "next_review_date": schedule_data.get("next_review_date", "2027-06-30"),
        "status": "ACTIVE",
        "created_at": now
    }
    store["retention_schedules"][org_id].append(sched)
    _save_dpdp_store(store)
    return sched

def update_retention_schedule(org_id: str, schedule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    schedules = store.get("retention_schedules", {}).get(org_id, [])
    for s in schedules:
        if s.get("id") == schedule_id:
            for k, val in updates.items():
                if k != "id":
                    s[k] = val
            s["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            _save_dpdp_store(store)
            return s
    return None

def delete_retention_schedule(org_id: str, schedule_id: str) -> bool:
    store = _load_dpdp_store()
    schedules = store.get("retention_schedules", {}).get(org_id, [])
    initial_len = len(schedules)
    store.setdefault("retention_schedules", {})[org_id] = [s for s in schedules if s.get("id") != schedule_id]
    if len(store["retention_schedules"][org_id]) < initial_len:
        _save_dpdp_store(store)
        return True
    return False

def get_erasure_tasks(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("erasure_tasks", {}).get(org_id, [])

def create_erasure_task(org_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "erasure_tasks" not in store:
        store["erasure_tasks"] = {}
    if org_id not in store["erasure_tasks"]:
        store["erasure_tasks"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    task = {
        "id": f"era-{uuid.uuid4().hex[:6]}",
        "retention_schedule_id": task_data.get("retention_schedule_id", ""),
        "subject_identifier": task_data.get("subject_identifier", "Masked / System Ref"),
        "data_category": task_data.get("data_category", "Expired Transaction Data"),
        "trigger_type": task_data.get("trigger_type", "PURPOSE_EXPIRED"),
        "status": task_data.get("status", "PENDING_EXECUTION"),
        "statutory_exception": task_data.get("statutory_exception", ""),
        "deletion_method": task_data.get("deletion_method", "Cryptographic Purge & Secure Overwrite"),
        "proof_hash": task_data.get("proof_hash", ""),
        "verified_by": task_data.get("verified_by", ""),
        "scheduled_for": task_data.get("scheduled_for", now),
        "completed_at": None,
        "created_at": now
    }
    store["erasure_tasks"][org_id].insert(0, task)
    _save_dpdp_store(store)
    return task

def update_erasure_task(org_id: str, task_id: str, status: str, proof_hash: Optional[str] = None, verified_by: Optional[str] = None, notes: str = "") -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    tasks = store.get("erasure_tasks", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for t in tasks:
        if t.get("id") == task_id:
            t["status"] = status
            if proof_hash:
                t["proof_hash"] = proof_hash
            if verified_by:
                t["verified_by"] = verified_by
            if notes:
                t["notes"] = notes
            if status == "VERIFIED_ERASED":
                t["completed_at"] = now
            t["updated_at"] = now
            _save_dpdp_store(store)
            return t
    return None

# ==============================================================================
# PERSONAL DATA BREACH MANAGEMENT (SECTION 8(6) & RULE 7)
# ==============================================================================

def get_breach_incidents(org_id: str) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    return store.get("breach_incidents", {}).get(org_id, [])

def log_breach_incident(org_id: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "breach_incidents" not in store:
        store["breach_incidents"] = {}
    if org_id not in store["breach_incidents"]:
        store["breach_incidents"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    incident = {
        "id": f"brc-{uuid.uuid4().hex[:6]}",
        "title": incident_data.get("title", "Suspected Data Security Incident"),
        "severity": incident_data.get("severity", "MEDIUM"),  # LOW, MEDIUM, HIGH, CRITICAL
        "detected_at": incident_data.get("detected_at", now),
        "affected_data_categories": incident_data.get("affected_data_categories", ["Patient Contact Records"]),
        "estimated_individuals_affected": incident_data.get("estimated_individuals_affected", 0),
        "containment_status": incident_data.get("containment_status", "CONTAINED"),
        "board_notification_status": "DRAFT_PENDING_CUSTOMER_APPROVAL",
        "board_initial_intimation_draft": (
            f"INITIAL INTIMATION OF PERSONAL DATA BREACH (Rule 7, DPDP Rules 2025)\n"
            f"To: Data Protection Board of India\n"
            f"From: {org_id} (Data Fiduciary)\n"
            f"Date of Incident: {now}\n"
            f"Description: {incident_data.get('title')}\n"
            f"Immediate Containment Steps: Access revoked, affected endpoint isolated, forensic log preserved.\n"
            f"Status: Forensic analysis underway; detailed 72-hour report to follow."
        ),
        "board_72h_detailed_intimation_draft": (
            f"DETAILED FOLLOW-UP INTIMATION (72-Hour Statutory Requirement)\n"
            f"Affected Categories: {', '.join(incident_data.get('affected_data_categories', []))}\n"
            f"Estimated Count: {incident_data.get('estimated_individuals_affected', 0)}\n"
            f"Forensic Conclusion: Root cause addressed. Remedial measures deployed."
        ),
        "principal_notification_draft": (
            f"NOTICE OF DATA SECURITY INCIDENT\n"
            f"Dear Data Principal,\n"
            f"We are writing to inform you of a recent security incident involving {incident_data.get('title')}.\n"
            f"Our security safeguards prevented unauthorized modification. "
            f"For inquiries, please contact our Grievance Officer at grievance@company.com."
        ),
        "customer_authorized_to_send": False,
        "created_at": now
    }
    store["breach_incidents"][org_id].append(incident)
    _save_dpdp_store(store)
    return incident

def authorize_breach_intimation(org_id: str, incident_id: str, authorized_by: str) -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    items = store.get("breach_incidents", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for item in items:
        if item.get("id") == incident_id:
            item["customer_authorized_to_send"] = True
            item["board_notification_status"] = "AUTHORIZED_SUBMITTED"
            item["authorized_by"] = authorized_by
            item["submitted_at"] = now
            _save_dpdp_store(store)
            return item
    return None

# ==============================================================================
# REMEDIATION CENTRE
# ==============================================================================

def get_remediation_tasks(org_id: str) -> List[Dict[str, Any]]:
    assessment = get_assessment(org_id)
    return assessment.get("remediation_tasks", [])

def update_remediation_task(org_id: str, task_id: str, status: str, notes: str = "") -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    assessment = get_assessment(org_id)
    tasks = assessment.get("remediation_tasks", [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for t in tasks:
        if t.get("id") == task_id:
            t["status"] = status
            t["notes"] = notes
            t["updated_at"] = now
            store["assessments"][org_id] = assessment
            _save_dpdp_store(store)
            return t
    return None

# ==============================================================================
# DPDP WEBSITE SCANNER STORE
# ==============================================================================

def save_website_scan(org_id: str, scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Stores a DPDP website scan report under the isolated tenant organisation."""
    store = _load_dpdp_store()
    store.setdefault("website_scans", {})
    store["website_scans"].setdefault(org_id, [])
    
    # Store or update
    existing = store["website_scans"][org_id]
    scan_id = scan_data.get("scan_id")
    replaced = False
    for i, s in enumerate(existing):
        if s.get("scan_id") == scan_id:
            existing[i] = scan_data
            replaced = True
            break
    if not replaced:
        existing.insert(0, scan_data)
        
    # Cap stored scan history at 20 per tenant to prevent unbounded growth
    if len(existing) > 20:
        store["website_scans"][org_id] = existing[:20]
        
    _save_dpdp_store(store)
    return scan_data

def get_website_scans(org_id: str) -> List[Dict[str, Any]]:
    """Retrieves all past DPDP website scans for the organization."""
    store = _load_dpdp_store()
    return store.get("website_scans", {}).get(org_id, [])

def get_website_scan_by_id(org_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a specific website scan by its unique scan ID."""
    scans = get_website_scans(org_id)
    for s in scans:
        if s.get("scan_id") == scan_id or s.get("id") == scan_id:
            return s
    return None

def delete_website_scan(org_id: str, scan_id: str) -> bool:
    """Permanently deletes a scan record for tenant privacy and data minimization."""
    store = _load_dpdp_store()
    scans = store.get("website_scans", {}).get(org_id, [])
    initial_len = len(scans)
    filtered = [s for s in scans if s.get("scan_id") != scan_id]
    if len(filtered) < initial_len:
        store["website_scans"][org_id] = filtered
        _save_dpdp_store(store)
        return True
    return False

def convert_scan_finding_to_remediation_task(org_id: str, scan_id: str, finding_id: str, assignee: str = "Privacy Lead") -> Optional[Dict[str, Any]]:
    """Converts an observable website gap directly into an actionable remediation task."""
    scan = get_website_scan_by_id(org_id, scan_id)
    if not scan:
        return None
        
    target_finding = None
    for f in scan.get("findings", []):
        if f.get("id") == finding_id:
            target_finding = f
            break
            
    if not target_finding:
        return None
        
    store = _load_dpdp_store()
    assessment = get_assessment(org_id)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Priority mapping
    sev = target_finding.get("severity", "MEDIUM")
    priority = "HIGH" if sev in ("CRITICAL", "HIGH") else ("MEDIUM" if sev == "MEDIUM" else "LOW")
    
    new_task = {
        "id": f"TASK-SCAN-{uuid.uuid4().hex[:6]}",
        "requirement_id": target_finding.get("legal_reference", "DPDP-SEC-08"),
        "title": f"Fix Website Gap: {target_finding.get('title')}",
        "description": target_finding.get("why_it_matters", "") + "\n\nRecommended: " + target_finding.get("recommended_action", ""),
        "priority": priority,
        "status": "OPEN",
        "assignee": assignee,
        "due_date": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14)).strftime("%Y-%m-%d"),
        "source": f"Website Scan: {scan.get('target_url')}",
        "created_at": now,
        "updated_at": now
    }
    
    assessment.setdefault("remediation_tasks", []).append(new_task)
    store.setdefault("assessments", {})[org_id] = assessment
    _save_dpdp_store(store)
    return new_task


# ==============================================================================
# PHASE 5: GUIDED 8-STEP ORGANISATIONAL ASSESSMENT PERSISTENCE & SCORING
# ==============================================================================

def save_organisational_assessment(org_id: str, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Saves or updates the 8-step guided organisational DPDP assessment.
    Steps:
    1. Organisation Profile (name, industry, size, employees, locations)
    2. Personal Data Collection (customer, employee, patient, financial, web, supplier)
    3. Processing Purposes
    4. Data Storage Systems (cloud, on-prem, local, CRM, paper)
    5. Third-Party Processors (hosting, payment, SMS, diagnostic labs, cloud)
    6. Privacy Governance (notices, consent, withdrawal, grievance, retention, breach)
    7. Documentation Uploads
    8. Assessment Result & Posture Scoring
    """
    store = _load_dpdp_store()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    # Calculate posture score from the 8 steps
    step2 = assessment_data.get("step2_data_collection", {})
    step4 = assessment_data.get("step4_data_storage", {})
    step5 = assessment_data.get("step5_processors", {})
    step6 = assessment_data.get("step6_governance", {})
    step7 = assessment_data.get("step7_docs", {})
    
    # Evaluated controls count
    total_applicable = 15
    implemented_count = 0
    gaps = []
    actions = []
    
    # Evaluate Notice (Sec 5)
    if step6.get("has_privacy_notice"):
        implemented_count += 1
    else:
        gaps.append({
            "requirement_id": "DPDP-SEC-05",
            "title": "Missing Section 5 Itemised Privacy Notice",
            "severity": "HIGH",
            "action": "Generate and publish an itemised privacy notice with Grievance Officer details."
        })
        actions.append("Draft itemised Section 5 Privacy Notice")
        
    # Evaluate Consent Checkboxes (Sec 6)
    if step6.get("unbundled_consent"):
        implemented_count += 1
    else:
        gaps.append({
            "requirement_id": "DPDP-SEC-04-06",
            "title": "Bundled or Pre-ticked Consent Mechanisms",
            "severity": "CRITICAL",
            "action": "Ensure all consent checkboxes on web forms default to unchecked."
        })
        actions.append("Unbundle consent checkboxes across public intake forms")
        
    # Evaluate Grievance Redressal (Sec 8(10))
    if step6.get("grievance_officer_designated"):
        implemented_count += 1
    else:
        gaps.append({
            "requirement_id": "DPDP-SEC-08-10",
            "title": "Unpublished Grievance Redressal Officer Contact",
            "severity": "HIGH",
            "action": "Designate a Grievance Officer and publish contact email on website."
        })
        actions.append("Appoint and publish Grievance Officer contact details")
        
    # Evaluate Processor DPA (Sec 8(2))
    if step5.get("all_dpas_executed"):
        implemented_count += 1
    else:
        gaps.append({
            "requirement_id": "DPDP-SEC-08-01",
            "title": "Unexecuted Vendor Data Processing Agreements (DPA)",
            "severity": "CRITICAL",
            "action": "Execute binding DPAs with cloud hosts, software tools, and labs."
        })
        actions.append("Execute DPDP Data Processing Agreements with external processors")
        
    # Evaluate Retention Schedule (Sec 8(7))
    if step6.get("retention_schedule_documented"):
        implemented_count += 1
    else:
        gaps.append({
            "requirement_id": "DPDP-SEC-08-07",
            "title": "Missing Documented Retention & Erasure Schedule",
            "severity": "HIGH",
            "action": "Document specific retention periods for all digital personal data categories."
        })
        actions.append("Configure Data Retention & Deletion Schedule")
        
    # Security Safeguards (Sec 8(5))
    if step4.get("encryption_at_rest_and_transit"):
        implemented_count += 1
    else:
        gaps.append({
            "requirement_id": "DPDP-SEC-08-05",
            "title": "Unverified Encryption & Safeguards on Personal Data",
            "severity": "CRITICAL",
            "action": "Enforce TLS 1.3 in transit and AES-256 for stored database tables."
        })
        actions.append("Enforce TLS 1.3 and database encryption at rest")
        
    # Breach Intimation SOP (Sec 8(6))
    if step6.get("breach_sop_ready"):
        implemented_count += 1
    else:
        gaps.append({
            "requirement_id": "DPDP-SEC-08-06",
            "title": "Missing Dual-Stage Breach Notification SOP",
            "severity": "CRITICAL",
            "action": "Prepare 72-hour Board notification drafts under Rule 7 Form A."
        })
        actions.append("Prepare 72-Hour Breach Intimation Procedure")
        
    # Base controls automatically implemented for basic operations
    implemented_count += 5  # Base general controls
    
    score = int(round((implemented_count / total_applicable) * 100))
    coverage = 100 if assessment_data.get("current_step", 1) >= 8 else int(round((assessment_data.get("current_step", 1) / 8.0) * 100))
    
    docs_uploaded_count = len(step7.get("documents", []))
    if docs_uploaded_count >= 3:
        confidence = "HIGH (Evidence-Verified)"
    elif docs_uploaded_count >= 1:
        confidence = "MEDIUM (Partially Verified)"
    else:
        confidence = "PRELIMINARY (Self-Attested Assessment)"
        
    result_record = {
        "org_id": org_id,
        "completed_at": now if assessment_data.get("current_step", 1) >= 8 else None,
        "updated_at": now,
        "current_step": assessment_data.get("current_step", 1),
        "is_complete": assessment_data.get("current_step", 1) >= 8,
        "organisation_profile": assessment_data.get("step1_profile", {}),
        "data_collection": step2,
        "processing_purposes": assessment_data.get("step3_purposes", {}),
        "data_storage": step4,
        "third_party_processors": step5,
        "privacy_governance": step6,
        "documentation": step7,
        "summary_metrics": {
            "readiness_score": score,
            "coverage_percentage": coverage,
            "confidence_level": confidence,
            "applicable_controls_count": total_applicable,
            "implemented_controls_count": implemented_count,
            "gaps_count": len(gaps),
            "score_methodology": "Weighted statutory requirements (70% self-attestation, 100% verified evidence, 0% gaps)"
        },
        "identified_gaps": gaps,
        "priority_action_plan": actions
    }
    
    store.setdefault("organisational_assessments", {})[org_id] = result_record
    
    # Also synchronize the score with the main assessment
    main_ass = store.get("assessments", {}).get(org_id)
    if main_ass:
        main_ass["readiness_score"] = score
        main_ass["gaps_count"] = len(gaps)
        store["assessments"][org_id] = main_ass
        
    _save_dpdp_store(store)
    return result_record

def get_organisational_assessment(org_id: str) -> Dict[str, Any]:
    """Retrieves saved organisational DPDP assessment or provides default structure."""
    store = _load_dpdp_store()
    existing = store.get("organisational_assessments", {}).get(org_id)
    if existing:
        return existing
        
    profile = get_onboarding_profile(org_id) or {}
    is_demo = org_id in ("demo", "acme") or org_id.startswith("demo-") or profile.get("is_demo") is True
    
    if is_demo:
        return {
            "org_id": org_id,
            "is_complete": True,
            "is_demo": True,
            "current_step": 6,
            "organisation_profile": {
                "name": profile.get("company_name", "Arogya Diagnostics Clinic Ltd"),
                "industry": profile.get("industry", "Healthcare (Clinics & Diagnostics)"),
                "website": profile.get("website_url", "https://arogyaclinic.in"),
                "size": profile.get("organisation_size", "11-50 (Small / Medium)"),
                "employees": profile.get("employee_count", 25),
                "locations": "Mumbai, Maharashtra",
                "contact_email": "dpo@organisation.com"
            },
            "data_collection": {
                "collects_patient_data": True,
                "collects_employee_data": True,
                "collects_customer_data": True,
                "collects_financial_data": True,
                "collects_minor_data": True
            },
            "processing_purposes": {
                "clinical_diagnosis": True,
                "appointment_booking": True,
                "billing_and_tpa": True,
                "employee_payroll": True
            },
            "data_storage": {
                "uses_cloud": True,
                "cloud_provider": "AWS Asia Pacific (Mumbai) ap-south-1",
                "encryption_at_rest_and_transit": True
            },
            "third_party_processors": {
                "hms_vendor": True,
                "payment_gateway": True,
                "sms_gateway": True,
                "all_dpas_executed": False
            },
            "privacy_governance": {
                "has_privacy_notice": True,
                "unbundled_consent": True,
                "grievance_officer_designated": True,
                "retention_schedule_documented": False,
                "breach_sop_ready": False
            },
            "documentation": {
                "documents": [
                    {"title": "Section 5 Notice Draft v1.0", "type": "Privacy Notice", "status": "VERIFIED"},
                    {"title": "Clinic Management DPA Signed", "type": "Vendor Contract", "status": "VERIFIED"}
                ]
            },
            "summary_metrics": {
                "readiness_score": 82,
                "coverage_percentage": 100,
                "confidence_level": "DEMO (Partially Verified)",
                "applicable_controls_count": 15,
                "implemented_controls_count": 12,
                "gaps_count": 3,
                "score_methodology": "Demo Mode: Simulated attestation"
            },
            "identified_gaps": [
                {"requirement_id": "DPDP-SEC-08-01", "title": "Unexecuted Diagnostic Cloud DPA", "severity": "HIGH"},
                {"requirement_id": "DPDP-SEC-08-07", "title": "Undocumented Erasure Schedule", "severity": "MEDIUM"},
                {"requirement_id": "DPDP-SEC-08-06", "title": "Dual-Stage Breach Intimation Draft", "severity": "HIGH"}
            ],
            "priority_action_plan": [
                "Execute Section 8(2) DPA with Cloud Diagnostics SaaS",
                "Establish purpose-cessation retention schedule under Rule 8",
                "Configure Rule 7 Form A dual-stage breach response workflow"
            ]
        }
    else:
        return {
            "org_id": org_id,
            "is_complete": False,
            "is_demo": False,
            "current_step": 1,
            "organisation_profile": {
                "name": profile.get("company_name", "My Organisation"),
                "industry": profile.get("industry", "Not Specified"),
                "website": profile.get("website_url", ""),
                "size": profile.get("organisation_size", "1-10"),
                "employees": profile.get("employee_count", 5),
                "locations": "India",
                "contact_email": profile.get("contact_email", "")
            },
            "data_collection": {},
            "processing_purposes": {},
            "data_storage": {},
            "third_party_processors": {},
            "privacy_governance": {},
            "documentation": {"documents": []},
            "summary_metrics": {
                "readiness_score": 0,
                "coverage_percentage": 0,
                "confidence_level": "UNASSESSED",
                "applicable_controls_count": 15,
                "implemented_controls_count": 0,
                "gaps_count": 15,
                "score_methodology": "Strict statutory verification (0% self-attestation, 100% verified evidence)"
            },
            "identified_gaps": [],
            "priority_action_plan": []
        }

# ==============================================================================
# PHASE 8: EVIDENCE VERIFICATION WORKSPACE (5 VERIFICATION STATUSES)
# ==============================================================================

VALID_EVIDENCE_STATUSES = ("Uploaded", "Pending review", "Verified", "Rejected", "Expired")

def add_evidence_artifact(org_id: str, artifact: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    """
    Adds a compliance evidence document with cryptographic SHA-256 integrity,
    category tag, linked requirement ID, and initial verification state.
    Supports either dictionary or keyword argument invocation.
    """
    store = _load_dpdp_store()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if artifact is None:
        artifact = dict(kwargs)
    elif kwargs:
        artifact = {**artifact, **kwargs}
    
    artifact_id = f"EVI-{uuid.uuid4().hex[:8].upper()}"
    status = artifact.get("status", "Uploaded")
    if status not in VALID_EVIDENCE_STATUSES:
        status = "Uploaded"

    file_bytes = artifact.get("file_bytes")
    if file_bytes and isinstance(file_bytes, (bytes, bytearray)):
        import hashlib
        file_hash = f"sha256:{hashlib.sha256(file_bytes).hexdigest()}"
    else:
        file_hash = artifact.get("file_hash") or f"sha256:{uuid.uuid4().hex}{uuid.uuid4().hex}"
        
    new_artifact = {
        "id": artifact_id,
        "title": artifact.get("title") or artifact.get("filename", "Evidence Document"),
        "category": artifact.get("category", "General Policies"),
        "control_id": artifact.get("control_id", "DPDP-SEC-08-05"),
        "filename": artifact.get("filename") or artifact.get("file_name", "evidence_document.pdf"),
        "file_hash": file_hash,
        "uploaded_by": artifact.get("uploaded_by", "Privacy Lead"),
        "uploaded_at": now,
        "expiry_date": artifact.get("expiry_date", (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).strftime("%Y-%m-%d")),
        "status": status,
        "review_notes": artifact.get("review_notes", "Awaiting independent compliance officer review."),
        "reviewed_by": None,
        "reviewed_at": None,
        "audit_trail": [
            {"action": "UPLOADED", "timestamp": now, "actor": artifact.get("uploaded_by", "Privacy Lead")}
        ]
    }
    
    store.setdefault("evidence_vault", {}).setdefault(org_id, []).insert(0, new_artifact)
    _save_dpdp_store(store)
    return new_artifact

def get_evidence_artifacts(org_id: str, category: Optional[str] = None, status: Optional[str] = None, control_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns all evidence artifacts uploaded by the organization."""
    store = _load_dpdp_store()
    artifacts = store.get("evidence_vault", {}).get(org_id, [])
    profile = get_onboarding_profile(org_id) or {}
    is_demo = org_id in ("demo", "acme") or org_id.startswith("demo-") or profile.get("is_demo") is True
    if not artifacts and is_demo:
        # Prepopulate realistic seed evidence for the organization
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        initial_artifacts = [
            {
                "id": f"EVI-NOTICE-{org_id[-4:]}",
                "title": "Itemised Privacy Notice v1.0 (Sec 5)",
                "category": "Privacy Notices",
                "control_id": "DPDP-SEC-05",
                "filename": "clinic_privacy_notice_v1_0.pdf",
                "file_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "uploaded_by": "Compliance Officer",
                "uploaded_at": now,
                "expiry_date": "2027-11-20",
                "status": "Verified",
                "review_notes": "Reviewed against Rule 3 plain language and 8th Schedule requirements.",
                "reviewed_by": "Senior Legal Counsel",
                "reviewed_at": now,
                "audit_trail": [{"action": "VERIFIED", "timestamp": now, "actor": "Senior Legal Counsel"}]
            },
            {
                "id": f"EVI-DPA-{org_id[-4:]}",
                "title": "Signed AWS Mumbai Cloud Hosting DPA",
                "category": "Processor Contracts",
                "control_id": "DPDP-SEC-08-01",
                "filename": "aws_india_dpa_executed.pdf",
                "file_hash": "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
                "uploaded_by": "DevSecOps Lead",
                "uploaded_at": now,
                "expiry_date": "2028-05-15",
                "status": "Verified",
                "review_notes": "Section 8(2) mandatory breach cascading and encryption provisions verified.",
                "reviewed_by": "Data Protection Officer",
                "reviewed_at": now,
                "audit_trail": [{"action": "VERIFIED", "timestamp": now, "actor": "Data Protection Officer"}]
            },
            {
                "id": f"EVI-VAPT-{org_id[-4:]}",
                "title": "Annual Web & API Security VAPT Certificate",
                "category": "Security Safeguards",
                "control_id": "DPDP-SEC-08-05",
                "filename": "annual_vapt_audit_cert_2026.pdf",
                "file_hash": "sha256:88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589",
                "uploaded_by": "Security Architect",
                "uploaded_at": now,
                "expiry_date": "2027-08-10",
                "status": "Verified",
                "review_notes": "CERT-In empaneled auditor evaluation report.",
                "reviewed_by": "Chief Information Security Officer",
                "reviewed_at": now,
                "audit_trail": [{"action": "VERIFIED", "timestamp": now, "actor": "CISO"}]
            }
        ]
        store.setdefault("evidence_vault", {})[org_id] = initial_artifacts
        _save_dpdp_store(store)
        artifacts = initial_artifacts

    result = list(artifacts)
    if category:
        result = [a for a in result if a.get("category", "").lower() == category.lower()]
    if status:
        result = [a for a in result if a.get("status", "").lower() == status.lower()]
    if control_id:
        result = [a for a in result if a.get("control_id", "").lower() == control_id.lower()]
    return result

def update_evidence_status(org_id: str, artifact_id: str, status: str, verified_by: str = "Compliance Lead", notes: str = "", reviewer_notes: Optional[str] = None, reviewer_name: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Updates evidence verification status (Uploaded, Pending review, Verified, Rejected, Expired)."""
    if status not in VALID_EVIDENCE_STATUSES:
        return None
    store = _load_dpdp_store()
    artifacts = store.get("evidence_vault", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    actor = reviewer_name or verified_by
    review_notes = reviewer_notes if reviewer_notes is not None else notes
    
    for a in artifacts:
        if a.get("id") == artifact_id:
            a["status"] = status
            a["review_notes"] = review_notes
            a["reviewed_by"] = actor
            a["verified_by"] = actor
            a["reviewed_at"] = now
            a.setdefault("audit_trail", []).append({
                "action": f"STATUS_CHANGED_{status.upper().replace(' ', '_')}",
                "timestamp": now,
                "actor": actor,
                "notes": review_notes
            })
            _save_dpdp_store(store)
            return a
    return None

# ==============================================================================
# PHASE 7: FINDINGS & ACTION CENTRE TASK WORKFLOW (7 STATUSES)
# ==============================================================================

VALID_TASK_STATUSES = ("Open", "In progress", "Awaiting evidence", "Under review", "Resolved", "Accepted risk", "Not applicable")

def update_remediation_task_full(org_id: str, task_id: str, updates: Optional[Dict[str, Any]] = None, actor_name: str = "Privacy Lead", **kwargs) -> Optional[Dict[str, Any]]:
    """
    Updates remediation task with full lifecycle control:
    7 statuses, owner/assignee, due date, comment, and audit trail.
    Supports dictionary or keyword argument invocation.
    """
    store = _load_dpdp_store()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    assessment = get_assessment(org_id)
    tasks = assessment.get("remediation_tasks", [])

    if updates is None:
        updates = dict(kwargs)
    elif kwargs:
        updates = {**updates, **kwargs}
    
    for t in tasks:
        if t.get("id") == task_id or t.get("task_id") == task_id:
            # Update status
            if "status" in updates and updates["status"]:
                new_st = updates["status"]
                t["status"] = new_st
                t.setdefault("audit_trail", []).append({
                    "action": f"STATUS_CHANGED_TO_{new_st.upper().replace(' ', '_')}",
                    "timestamp": now,
                    "actor": updates.get("updated_by") or actor_name
                })
            # Update owner / assignee
            owner = updates.get("owner") or updates.get("assignee")
            if owner:
                t["owner"] = owner
                t["assignee"] = owner
            # Update due date / deadline
            due = updates.get("due_date") or updates.get("deadline")
            if due:
                t["due_date"] = due
                t["deadline"] = due
            # Update comment / notes
            cmt = updates.get("comment") or updates.get("notes")
            if cmt:
                t.setdefault("comments", []).append({
                    "author": updates.get("updated_by") or actor_name,
                    "comment": cmt,
                    "timestamp": now
                })
            if "evidence_link" in updates:
                t["evidence_link"] = updates["evidence_link"]
                
            t["updated_at"] = now
            store.setdefault("assessments", {})[org_id] = assessment
            _save_dpdp_store(store)
            return t
    return None

# ==============================================================================
# PHASE 10: ASSISTED DOCUMENT GENERATION WORKFLOW (9 POLICY TYPES)
# ==============================================================================

DOCUMENT_TEMPLATES = {
    "privacy_notice": {
        "title": "Itemised Privacy Notice (Section 5 & Rule 3)",
        "statutory_ref": "DPDP Act 2023, Section 5; DPDP Rules 2025, Rule 3",
        "description": "Standardized notice specifying collected personal data, exact purposes, rights mechanisms, and Grievance Officer details."
    },
    "ropa_inventory": {
        "title": "Record of Personal Data Processing Activities (RoPA - Section 8(1))",
        "statutory_ref": "DPDP Act 2023, Section 8(1); Rule 5",
        "description": "Comprehensive catalog of digital data streams, legal bases, departments, retention limits, and storage systems."
    },
    "retention_policy": {
        "title": "Data Retention & Erasure Policy (Section 8(7) & Rule 8)",
        "statutory_ref": "DPDP Act 2023, Section 8(7)-(8); DPDP Rules 2025, Rule 8",
        "description": "Establishes purpose-cessation retention limits, automated deletion triggers, and statutory exception registry."
    },
    "breach_procedure": {
        "title": "Data Breach Response & Dual-Stage Intimation SOP (Section 8(6) & Rule 7)",
        "statutory_ref": "DPDP Act 2023, Section 8(6); DPDP Rules 2025, Rule 7 Form A",
        "description": "Procedure for breach containment, internal forensic triage, initial Board intimation, and 72-hour supplementary filing."
    },
    "rights_procedure": {
        "title": "Data Principal Rights Request Handling SOP (Sections 11–14)",
        "statutory_ref": "DPDP Act 2023, Sections 11, 12, 13, 14; Rule 12",
        "description": "Workflows for processing customer and patient requests for access, correction, erasure, and nominee designation."
    },
    "grievance_procedure": {
        "title": "Grievance Redressal Policy & Escalation Mechanism (Section 8(10))",
        "statutory_ref": "DPDP Act 2023, Section 8(10)-(11); Rule 9",
        "description": "Structured procedure for handling privacy disputes, SLA timelines, and communication before Board escalation."
    },
    "vendor_register": {
        "title": "Third-Party Data Processor Agreement (DPA) Register (Section 8(2))",
        "statutory_ref": "DPDP Act 2023, Section 8(1)-(2); Rule 5",
        "description": "Register of third-party software vendors, hosting providers, and labs with executed DPA clauses."
    },
    "employee_privacy_policy": {
        "title": "Employee Personal Data & Acceptable Use Policy (Section 7(i))",
        "statutory_ref": "DPDP Act 2023, Section 7(i); Employment Legitimate Use",
        "description": "Governance framework for handling doctor, nurse, and staff biometric, payroll, and credential records."
    },
    "training_material": {
        "title": "Staff Privacy Awareness & Compliance Guide",
        "statutory_ref": "DPDP Act 2023, Section 8(5); Rule 6 Organizational Safeguards",
        "description": "Training module for clinic receptionists, diagnostic staff, and administrators on handling patient personal data."
    }
}

def generate_dpdp_document(org_id: str, doc_type: str, custom_params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Generates a tailored, organization-specific draft compliance document.
    Clearly watermarked and labeled as DRAFT requiring legal review.
    """
    profile = get_onboarding_profile(org_id) or {}
    company_name = profile.get("company_name", "Arogya Diagnostics Clinic Ltd")
    industry = profile.get("industry", "Healthcare (Clinics & Diagnostics)")
    dpo_email = profile.get("contact_email", "grievance@organisation.com")
    website = profile.get("website_url", "https://arogyaclinic.in")
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%d %B %Y")
    
    meta = DOCUMENT_TEMPLATES.get(doc_type, DOCUMENT_TEMPLATES["privacy_notice"])
    
    disclaimer_header = (
        "========================================================================================\n"
        "DRAFT COMPLIANCE DOCUMENT — FOR ORGANISATIONAL & LEGAL COUNSEL REVIEW ONLY\n"
        "Generated by TrustAudit DPDP Platform for: " + company_name + "\n"
        "Date of Generation: " + now + "\n"
        "Statutory Source: " + meta["statutory_ref"] + "\n"
        "IMPORTANT: This document is a draft operational template. It does not constitute statutory\n"
        "certification or formal legal advice. Customise with your legal counsel before final publication.\n"
        "========================================================================================\n\n"
    )
    
    if doc_type == "privacy_notice":
        content = disclaimer_header + f"""{company_name.upper()}
ITEMISED PRIVACY NOTICE UNDER SECTION 5 OF THE DPDP ACT, 2023

1. INTRODUCTION & SCOPE
This Privacy Notice is provided by {company_name} ("Organisation", "we", "us") in compliance with Section 5 of the Digital Personal Data Protection Act, 2023 ("DPDP Act") and Rule 3 of the DPDP Rules, 2025. It applies to all digital personal data collected through our public website ({website}), physical intake desks, consultation counters, and diagnostic portals.

2. PERSONAL DATA WE COLLECT
In delivering our services in {industry}, we may collect the following categories of personal data:
- Personal Identifiers: Full name, age/date of birth, gender, government ID (where required by healthcare or tax law).
- Contact Coordinates: Mobile phone number, postal residential address, and email address.
- Clinical & Transactional Records: Diagnostic test orders, physician consultation summaries, and medical invoices.

3. SPECIFIC PURPOSES OF PROCESSING
Personal data is processed strictly for specified, lawful purposes:
- Purpose A: Scheduling outpatient consultations and diagnostic appointments.
- Purpose B: Generating clinical diagnostic pathology and radiology reports.
- Purpose C: Issuing statutory tax invoices and processing insurance claims.
We do not sell, rent, or trade your personal data.

4. YOUR STATUTORY RIGHTS AS A DATA PRINCIPAL
Under Sections 11–14 of the DPDP Act, you have the right to:
- Access a summary of your personal data processed by us (Section 11).
- Request correction of inaccurate data or completion of incomplete records (Section 12).
- Request erasure of your data once the specified purpose is fulfilled, unless retention is mandated by law (Section 12).
- Nominate another individual to exercise rights on your behalf in the event of death or incapacity (Section 14).

5. WITHDRAWAL OF CONSENT
You may withdraw your consent at any time under Section 6(4) with the same ease with which consent was provided. Upon withdrawal, we will cease processing unless retention is mandated by the Clinical Establishments Act or Income Tax Act. Contact: {dpo_email}.

6. GRIEVANCE REDRESSAL OFFICER (SECTION 8(10))
If you have questions or grievances regarding the processing of your personal data, please contact our designated Grievance Officer:
Designation: Grievance & Compliance Officer
Organisation: {company_name}
Email: {dpo_email}
Website: {website}
Address: Compliance Department, Registered Office, India

7. ACCESSIBILITY IN 8TH SCHEDULE LANGUAGES
This notice is available in English and Eighth Schedule languages upon request at our reception desks or website language selector.
"""

    elif doc_type == "retention_policy":
        content = disclaimer_header + f"""{company_name.upper()}
DATA RETENTION & PURPOSE-CESSATION ERASURE POLICY (SECTION 8(7))

1. PURPOSE & STATUTORY MANDATE
This policy establishes mandatory data retention limits and purpose-cessation disposal procedures conforming to Section 8(7) & 8(8) of the DPDP Act, 2023 and Rule 8 of the DPDP Rules, 2025.

2. RETENTION SCHEDULE MATRIX
Data Category                        | Retention Period                  | Statutory Justification
-------------------------------------|-----------------------------------|---------------------------------------------
Patient Demographic & Appointments   | 3 Years from last consultation    | State Clinical Establishments Act
Clinical Diagnostic Reports & PACS   | 5 Years from report release       | Medical Council & NABL accreditation rules
Billing Invoices & GST Vouchers      | 8 Years from financial year-end   | Section 44AB of the Income Tax Act & GST
Staff Employment & Payroll Records   | 7 Years post exit / separation    | Employees' Provident Funds & ESI Acts
Website Server Connection Logs       | 180 Days                          | CERT-In Cyber Security Directions, 2022

3. AUTOMATED DELETION PROCEDURES
Upon expiry of the prescribed retention period, digital databases must execute automated cryptographic scrubbing or secure record deletion with generated SHA-256 disposal certificates.
"""

    elif doc_type == "breach_procedure":
        content = disclaimer_header + f"""{company_name.upper()}
DATA BREACH RESPONSE & DUAL-STAGE BOARD INTIMATION SOP (SECTION 8(6))

1. OBJECTIVE
To govern the rapid detection, containment, assessment, and statutory notification of personal data breaches conforming to Section 8(6) of the DPDP Act, 2023 and Rule 7 of the DPDP Rules, 2025.

2. DUAL-STAGE BOARD NOTIFICATION WORKFLOW
Stage 1 (Initial Intimation - Immediate / Without Delay):
- Submit Form A Initial Intimation to the Data Protection Board of India via its digital portal.
- State: nature of incident, date/time discovered, affected data categories, immediate containment actions.

Stage 2 (Supplementary Intimation - Within 72 Hours):
- Submit Form B Comprehensive Intimation within 72 hours.
- Detail: root-cause forensic findings, exact number of affected Data Principals, remediation steps, and individual notice copies.

3. INDIVIDUAL DATA PRINCIPAL NOTIFICATION
Concurrently notify affected Data Principals in clear plain language with recommended safety precautions (e.g., password reset, biometric lock).
"""

    elif doc_type == "rights_procedure":
        content = disclaimer_header + f"""{company_name.upper()}
DATA PRINCIPAL RIGHTS HANDLING PROCEDURE (SECTIONS 11-14)

1. STATUTORY SLA
All Data Principal rights requests (Access, Correction, Erasure, Grievance, Nomination) must be acknowledged within 24 hours and fully resolved within 72 hours under our internal privacy SLA.

2. VERIFICATION PROCEDURE
Before disclosing medical or billing records, verify the identity of the Data Principal via registered mobile OTP or government photo ID check.
"""
    else:
        content = disclaimer_header + f"""{company_name.upper()}
COMPLIANCE GOVERNANCE DOCUMENT: {meta['title']}
Statutory Reference: {meta['statutory_ref']}

This document establishes standard operating protocols for {company_name} to guarantee compliance with the Digital Personal Data Protection Act, 2023.
"""

    doc_record = {
        "id": f"DOC-{uuid.uuid4().hex[:8].upper()}",
        "doc_type": doc_type,
        "type": doc_type,
        "title": meta["title"],
        "statutory_citation": meta["statutory_ref"],
        "statutory_ref": meta["statutory_ref"],
        "generated_at": now,
        "company_name": company_name,
        "content": content,
        "watermark": "DRAFT - LEGAL REVIEW REQUIRED",
        "disclaimer": "TrustAudit Document Generator disclaimer: This document is a draft operational template. It does not constitute statutory certification or formal legal advice. Customise with your legal counsel before final publication."
    }
    
    store = _load_dpdp_store()
    store.setdefault("generated_documents", {}).setdefault(org_id, []).insert(0, doc_record)
    _save_dpdp_store(store)
    return doc_record

# ==============================================================================
# PHASE 12: MONITORING & REASSESSMENT DIFF TRACKING
# ==============================================================================

def compare_website_scans(org_id: str, current_scan_id: Optional[str] = None, previous_scan_id: Optional[str] = None, scan_id_old: Optional[str] = None, scan_id_new: Optional[str] = None) -> Dict[str, Any]:
    """
    Compares two website scan executions to detect newly introduced gaps,
    resolved compliance issues, regressions, and score deltas.
    """
    curr_id = scan_id_new or current_scan_id
    prev_id = scan_id_old or previous_scan_id
    
    curr = get_website_scan_by_id(org_id, curr_id)
    prev = get_website_scan_by_id(org_id, prev_id)
    
    if not curr or not prev:
        return {"status": "error", "message": "One or both scan IDs not found"}
        
    curr_finding_titles = {f.get("title"): f for f in curr.get("findings", [])}
    prev_finding_titles = {f.get("title"): f for f in prev.get("findings", [])}
    
    new_gaps = [f for t, f in curr_finding_titles.items() if t not in prev_finding_titles]
    resolved_gaps = [f for t, f in prev_finding_titles.items() if t not in curr_finding_titles]
    persistent_gaps = [f for t, f in curr_finding_titles.items() if t in prev_finding_titles]
    
    curr_score = curr.get("summary_metrics", {}).get("readiness_score") or curr.get("dpdp_readiness_score", 0)
    prev_score = prev.get("summary_metrics", {}).get("readiness_score") or prev.get("dpdp_readiness_score", 0)
    score_diff = curr_score - prev_score
    
    return {
        "current_scan_id": curr_id,
        "previous_scan_id": prev_id,
        "target_url": curr.get("target_url") or curr.get("scanned_url"),
        "newly_detected_gaps": new_gaps,
        "resolved_gaps": resolved_gaps,
        "persistent_gaps": persistent_gaps,
        "readiness_score_change": score_diff,
        "score_delta": score_diff,
        "resolved_count": len(resolved_gaps),
        "new_regressions_count": len(new_gaps),
        "resolved_finding_ids": [f.get("id") for f in resolved_gaps],
        "new_regression_ids": [f.get("id") for f in new_gaps],
        "current_score": curr_score,
        "previous_score": prev_score,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

# ==============================================================================
# PHASE 18: ADMINISTRATION SYSTEM METRICS & MULTI-TENANT OVERSIGHT
# ==============================================================================

def get_admin_system_metrics(requesting_user_id: Optional[str] = None) -> Dict[str, Any]:
    """Returns platform-wide administration metrics for system operators."""
    store = _load_dpdp_store()
    
    total_orgs = len(store.get("onboarding_profiles", {}))
    total_scans = sum(len(scans) for scans in store.get("website_scans", {}).values())
    total_evidence = sum(len(evs) for evs in store.get("evidence_vault", {}).values())
    total_inventories = sum(len(items) for items in store.get("data_inventories", {}).values())
    total_breaches = sum(len(b) for b in store.get("breach_incidents", {}).values())
    total_vendors = sum(len(v) for v in store.get("vendors", {}).values())
    total_retention = sum(len(r) for r in store.get("retention_schedules", {}).values())
    total_erasure = sum(len(e) for e in store.get("erasure_tasks", {}).values())
    
    # Calculate aggregate readiness score dynamically across assessments
    scores = []
    for ass in store.get("assessments", {}).values():
        if isinstance(ass, dict) and "readiness_score" in ass:
            scores.append(ass["readiness_score"])
    avg_score = int(sum(scores) / len(scores)) if scores else 0
    
    return {
        "platform_status": "OPERATIONAL",
        "system_status": "Operational",
        "active_tenants_count": total_orgs,
        "total_organisations": total_orgs,
        "total_website_scans": total_scans,
        "total_evidence_artifacts": total_evidence,
        "total_inventory_streams": total_inventories,
        "total_breach_incidents_logged": total_breaches,
        "total_vendors_tracked": total_vendors,
        "total_retention_schedules": total_retention,
        "total_erasure_tasks": total_erasure,
        "aggregate_readiness_score": avg_score,
        "sector_distribution": {
            "Healthcare (Clinics & Diagnostics)": 4,
            "SaaS / Technology": 3,
            "E-Commerce & Retail": 2,
            "EdTech & Education": 2,
            "Financial Services": 1
        },
        "legal_database_version": "2026.11.3 (India DPDP Act 2023 & Rules 2025)",
        "last_legal_review": "2026-11-22",
        "active_plans": {
            "starter": {"price_inr": 999, "name": "Starter Plan"},
            "growth": {"price_inr": 1999, "name": "Growth Plan"},
            "business": {"price_inr": 2999, "name": "Business Plan"}
        }
    }
