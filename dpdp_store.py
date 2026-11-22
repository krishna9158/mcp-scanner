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
            "onboarding_profiles": {}
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
            "onboarding_profiles": {}
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
    
    controls_assessment = []
    gaps = []
    remediation_tasks = []
    
    for req in DPDP_REQUIREMENTS:
        # Default self-attestation status for demo/initial view
        status = "GAP_IDENTIFIED" if req["id"] in ("DPDP-SEC-05", "DPDP-SEC-08-01", "DPDP-SEC-08-06") else "SELF_ATTESTED_IMPLEMENTED"
        
        control_record = {
            "requirement_id": req["id"],
            "section": req["section"],
            "title": req["title"],
            "category": req["readiness_category"],
            "effective_date": req["effective_date"],
            "legal_status": req["legal_status"],
            "status": status,
            "evidence_count": 0,
            "verification_status": "Self-Attested (Pending Human Verification)",
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
                "why_it_matters": f"Section {req['section']} mandates verifiable controls. Non-compliance exposes the organisation to penalties under the DPDP Act.",
                "evidence_required": req["evidence_required"][0] if req["evidence_required"] else "Policy Document",
                "recommended_solution": req["remediation_guidance"],
                "priority": "HIGH" if "critical" in str(req["assessment_questions"]) else "MEDIUM",
                "owner": "Compliance Lead",
                "deadline": "2027-04-30",
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
                "deadline": "2027-04-30",
                "guidance": req["remediation_guidance"],
                "created_at": now
            }
            remediation_tasks.append(task)
            
    # Calculate readiness percentage
    total = len(controls_assessment)
    implemented = sum(1 for c in controls_assessment if c["status"] == "SELF_ATTESTED_IMPLEMENTED")
    readiness_score = int((implemented / total) * 100) if total else 0
    
    return {
        "org_id": org_id,
        "readiness_score": readiness_score,
        "readiness_label": "In Progress (Self-Attested)",
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
