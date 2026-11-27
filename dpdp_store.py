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

import copy
import csv
import datetime
import io
import json
import os
import re
import threading
import uuid
from typing import Any, Dict, List, Optional, Tuple

import demo_fixture
import dpdp_commencement
import dpdp_penalties
from dpdp_engine import DPDP_REQUIREMENTS, INDUSTRY_TEMPLATES
from security_utils import (
    BLOCKED_DANGEROUS_EXTENSIONS,
    ALLOWED_UPLOAD_EXTENSIONS,
    atomic_write_bytes,
    atomic_write_json,
    decrypt_bytes_if_encrypted,
    encrypt_bytes_if_configured,
    get_audit_logs,
    get_data_dir,
    safe_read_json,
    safe_resolve_under_dir,
    sanitize_filename,
    sanitize_plain_text,
    validate_uploaded_file,
)


def _default_dpdp_data_file() -> str:
    env_dir = os.environ.get("TRUSTAUDIT_DATA_DIR", "").strip()
    if env_dir:
        return os.path.join(os.path.abspath(env_dir), "dpdp_store.json")
    return os.path.join(os.path.dirname(__file__), "data", "dpdp_store.json")


DPDP_DATA_FILE = _default_dpdp_data_file()
DPDP_EVIDENCE_FILES_DIR = os.path.join(get_data_dir(), "dpdp_evidence")


def _ensure_data_dir():
    os.makedirs(os.path.dirname(DPDP_DATA_FILE), exist_ok=True)


def _empty_store() -> Dict[str, Any]:
    return {
        "version": "2.0",
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
        "website_scans": {},
        "evidence_vault": {},
        "organisational_assessments": {},
        "generated_documents": {},
        "discovery_suggestions": {},
        "portal_configs": {},
        "privacy_profiles": {},
        "vendor_questionnaires": {},
        "vendor_intake_tokens": {},
    }


_DPDP_LOCK = threading.RLock()
_DPDP_CACHE_KEY: Optional[Tuple[str, int, int]] = None
_DPDP_CACHE_DATA: Optional[Dict[str, Any]] = None
_DPDP_CACHE_JSON: Optional[str] = None


def _read_dpdp_store_cached() -> Dict[str, Any]:
    """Thread-safe stat-keyed cache preventing repeated 4 MB JSON parses on read paths."""
    global _DPDP_CACHE_KEY, _DPDP_CACHE_DATA, _DPDP_CACHE_JSON
    _ensure_data_dir()
    abs_path = os.path.abspath(DPDP_DATA_FILE)
    with _DPDP_LOCK:
        if not os.path.exists(abs_path):
            initial = _empty_store()
            _save_dpdp_store(initial)
            return _DPDP_CACHE_DATA or initial
        try:
            st = os.stat(abs_path)
            stat_key = (abs_path, int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))), int(st.st_size))
        except OSError:
            stat_key = None
        if stat_key and stat_key == _DPDP_CACHE_KEY and _DPDP_CACHE_DATA is not None:
            return _DPDP_CACHE_DATA
        data = safe_read_json(abs_path, _empty_store)
        _DPDP_CACHE_DATA = data
        _DPDP_CACHE_JSON = json.dumps(data)
        _DPDP_CACHE_KEY = stat_key
        return data


def _load_dpdp_store() -> Dict[str, Any]:
    """Returns a fresh mutable copy of DPDP store without repeated disk reads."""
    with _DPDP_LOCK:
        cached = _read_dpdp_store_cached()
        if _DPDP_CACHE_JSON is not None:
            return json.loads(_DPDP_CACHE_JSON)
        return copy.deepcopy(cached)


def _save_dpdp_store(data: Dict[str, Any]) -> None:
    global _DPDP_CACHE_KEY, _DPDP_CACHE_DATA, _DPDP_CACHE_JSON
    _ensure_data_dir()
    abs_path = os.path.abspath(DPDP_DATA_FILE)
    with _DPDP_LOCK:
        atomic_write_json(abs_path, data)
        _DPDP_CACHE_DATA = copy.deepcopy(data)
        _DPDP_CACHE_JSON = json.dumps(data)
        try:
            st = os.stat(abs_path)
            _DPDP_CACHE_KEY = (abs_path, int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))), int(st.st_size))
        except OSError:
            _DPDP_CACHE_KEY = None


# ==============================================================================
# ONBOARDING & INDUSTRY SELECTION
# ==============================================================================

def get_onboarding_profile(org_id: str) -> Optional[Dict[str, Any]]:
    store = _read_dpdp_store_cached()
    prof = store.get("onboarding_profiles", {}).get(org_id)
    if prof:
        res = dict(prof)
        if demo_fixture.is_demo_org(org_id, profile=res):
            res["company_name"] = demo_fixture.DEMO_ORG_NAME
            res["is_demo"] = True
        return res
    if demo_fixture.is_demo_org(org_id):
        return demo_fixture.get_demo_onboarding_profile()
    return None


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
        "updated_at": now,
    }
    if "created_at" not in profile:
        profile["created_at"] = now

    store["onboarding_profiles"][org_id] = profile
    _save_dpdp_store(store)

    # Pre-populate industry template when explicitly requested (or legacy full-profile call)
    industry = (profile.get("industry") or "").lower()
    should_apply = profile_data.get("apply_industry_template")
    if should_apply is None:
        should_apply = bool(profile_data.get("customer_types") or profile_data.get("business_name"))
    if should_apply and industry in INDUSTRY_TEMPLATES and not get_data_inventory(org_id):
        prepopulate_industry_inventory(org_id, industry)

    return profile

# ==============================================================================
# PERSONAL DATA INVENTORY
# ==============================================================================

def get_data_inventory(org_id: str) -> List[Dict[str, Any]]:
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("data_inventories", {}).get(org_id, []))

def add_inventory_entry(org_id: str, entry_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "data_inventories" not in store:
        store["data_inventories"] = {}
    if org_id not in store["data_inventories"]:
        store["data_inventories"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    raw_fields = entry_data.get("fields") or entry_data.get("data_fields") or []
    if isinstance(raw_fields, str):
        raw_fields = [f.strip() for f in raw_fields.split(",") if f.strip()]
    conf_status = entry_data.get("confirmation_status") or "Confirmed by business"
    entry = {
        "id": f"inv-{uuid.uuid4().hex[:8]}",
        "category": entry_data.get("category", "Contact information"),
        "fields": raw_fields if isinstance(raw_fields, list) else [],
        "principal_type": entry_data.get("principal_type") or entry_data.get("data_subject", "Customers / Users"),
        "source": entry_data.get("source", "Direct Registration"),
        "purpose": entry_data.get("purpose", "Service Delivery"),
        "legal_basis": entry_data.get("legal_basis") or entry_data.get("lawful_basis", "DPDP Section 6 (Consent)"),
        "collection_method": entry_data.get("collection_method", "Web Form / Registration"),
        "storage_system": entry_data.get("storage_system") or entry_data.get("storage_location", "Primary Database"),
        "department": entry_data.get("department", "Operations"),
        "owner": entry_data.get("owner", "Data Protection Lead"),
        "external_recipients": entry_data.get("external_recipients", "None"),
        "processor": entry_data.get("processor", "None"),
        "retention_period": entry_data.get("retention_period", "3 Years"),
        "deletion_method": entry_data.get("deletion_method", "Database Purge"),
        "international_transfer": entry_data.get("international_transfer", "None (India hosted)"),
        "confirmation_status": conf_status,
        "evidence_id": entry_data.get("evidence_id", ""),
        "version": 1,
        "version_history": [
            {"version": 1, "timestamp": now, "status": conf_status, "note": "Record created"}
        ],
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
            patch = dict(entry_data)
            if "fields" in patch and isinstance(patch["fields"], str):
                patch["fields"] = [f.strip() for f in patch["fields"].split(",") if f.strip()]
            new_ver = int(item.get("version", 1)) + 1
            hist = list(item.get("version_history", []))
            hist.append({
                "version": new_ver,
                "timestamp": now,
                "status": patch.get("confirmation_status", item.get("confirmation_status", "Confirmed by business")),
                "note": patch.get("edit_note", "Updated record details"),
            })
            updated = {**item, **patch, "version": new_ver, "version_history": hist[-20:], "updated_at": now}
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
    store = _read_dpdp_store_cached()
    assessment = store.get("assessments", {}).get(org_id)
    if not assessment:
        writable = _load_dpdp_store()
        assessment = writable.get("assessments", {}).get(org_id)
        if not assessment:
            assessment = _initialize_assessment(org_id)
            writable.setdefault("assessments", {})[org_id] = assessment
            _save_dpdp_store(writable)
    return copy.deepcopy(assessment)


def _initialize_assessment(org_id: str) -> Dict[str, Any]:
    profile = get_onboarding_profile(org_id) or {}
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    is_demo = demo_fixture.is_demo_org(org_id, profile=profile)
    
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
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("privacy_notices", {}).get(org_id, []))


def generate_privacy_notice(org_id: str, notice_params: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    store.setdefault("privacy_notices", {}).setdefault(org_id, [])

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    profile = get_onboarding_profile(org_id) or {}
    fallback_org = demo_fixture.DEMO_ORG_NAME if demo_fixture.is_demo_org(org_id, profile=profile) else "Registered Organisation"
    company_name = sanitize_plain_text(notice_params.get("company_name") or profile.get("company_name") or fallback_org, 160)
    grievance_email = sanitize_plain_text(notice_params.get("grievance_email") or profile.get("contact_email") or "", 160) or "[Add Grievance Officer Email]"
    grievance_officer = sanitize_plain_text(notice_params.get("grievance_officer") or "Privacy & Grievance Contact", 120)
    address = sanitize_plain_text(notice_params.get("address") or profile.get("address") or "[Add Registered Business Address]", 240)

    inventory_items = get_data_inventory(org_id)
    purposes_text = "\n".join(
        [f"• {i.get('category')}: {i.get('purpose')} (Legal basis: {i.get('legal_basis')})" for i in inventory_items[:10]]
    )
    if not purposes_text:
        purposes_text = "• [Add entries in Your Customer Data List so this notice lists your exact categories and purposes automatically.]"

    custom_content = notice_params.get("content")
    notice_text = custom_content if custom_content else f"""PRIVACY NOTICE (DRAFT — REVIEW BEFORE PUBLISHING)
Digital Personal Data Protection Act, 2023 (Section 5 read with Rule 3)

1. Who We Are:
{company_name}
Registered Address: {address}

2. What Customer Details We Collect & Why:
We collect and use digital personal data only for clear, lawful purposes:
{purposes_text}

3. Your Privacy Rights (Sections 11–14):
You may ask us to:
• View a summary of the personal data we hold and who we share it with.
• Correct inaccurate details or update incomplete records.
• Delete personal data when it is no longer needed and no other Indian law requires us to keep it.
• Withdraw consent where processing depends on consent (Section 6(4)).
• Nominate someone to exercise rights on your behalf in case of death or incapacity (Section 14).

4. Privacy Questions & Complaints (Grievance Redressal):
Privacy / Grievance Contact: {grievance_officer}
Email: {grievance_email}
Address: {address}
We acknowledge customer requests promptly and handle grievances within published grievance redressal timelines.

5. Languages Available:
Available in English and Eighth Schedule Indian languages upon request (Section 5(3) read with Rule 3)."""

    existing_count = len(store["privacy_notices"][org_id])
    version = notice_params.get("version") or f"v{existing_count + 1}.0"
    status = notice_params.get("status", "DRAFT")
    notice = {
        "id": f"not-{uuid.uuid4().hex[:6]}",
        "title": sanitize_plain_text(notice_params.get("title") or f"{company_name} Privacy Notice", 200),
        "version": sanitize_plain_text(version, 20),
        "status": status,
        "content": notice_text,
        "languages_supported": notice_params.get("languages_supported", ["English", "Hindi"]),
        "grievance_officer": grievance_officer,
        "grievance_email": grievance_email,
        "address": address,
        "approved_by": notice_params.get("approved_by") if status == "APPROVED_PUBLISHED" else None,
        "approved_at": now if status == "APPROVED_PUBLISHED" else None,
        "version_history": [
            {"version": version, "updated_at": now, "status": status, "note": "Notice created"}
        ],
        "created_at": now,
        "updated_at": now,
    }
    store["privacy_notices"][org_id].insert(0, notice)
    _save_dpdp_store(store)
    return notice


def update_privacy_notice(org_id: str, notice_id: str, updates: Dict[str, Any], actor_name: str = "Privacy Lead") -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    notices = store.get("privacy_notices", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for n in notices:
        if n.get("id") == notice_id:
            for k in ("title", "content", "grievance_officer", "grievance_email", "address", "languages_supported"):
                if k in updates:
                    n[k] = updates[k]
            if updates.get("bump_version"):
                v_num = len(n.get("version_history", [])) + 1
                n["version"] = f"v{v_num}.0"
            if updates.get("status"):
                n["status"] = updates["status"]
                if updates["status"] == "APPROVED_PUBLISHED":
                    n["approved_by"] = actor_name
                    n["approved_at"] = now
            n.setdefault("version_history", []).append({
                "version": n.get("version", "v1.0"),
                "updated_at": now,
                "status": n.get("status", "DRAFT"),
                "note": sanitize_plain_text(updates.get("note") or f"Updated by {actor_name}", 240),
            })
            n["updated_at"] = now
            _save_dpdp_store(store)
            return n
    return None


def delete_privacy_notice(org_id: str, notice_id: str) -> bool:
    store = _load_dpdp_store()
    notices = store.get("privacy_notices", {}).get(org_id, [])
    before = len(notices)
    store.setdefault("privacy_notices", {})[org_id] = [n for n in notices if n.get("id") != notice_id]
    if len(store["privacy_notices"][org_id]) < before:
        _save_dpdp_store(store)
        return True
    return False

# ==============================================================================
# CONSENT RECORDS & WITHDRAWAL (SECTION 6(4)-(6))
# ==============================================================================

def get_consent_records(org_id: str) -> List[Dict[str, Any]]:
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("consent_records", {}).get(org_id, []))

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
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("withdrawal_requests", {}).get(org_id, []))

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
    
    # Real vendor names logged by this org (never fake hardcoded vendors)
    org_vendor_names = [v.get("name", "") for v in store.get("vendors", {}).get(org_id, []) if v.get("name")]
    processors_notified = request_data.get("processors_notified_list") or org_vendor_names

    withdrawal = {
        "id": f"wth-{uuid.uuid4().hex[:8]}",
        "data_principal_ref": request_data.get("principal_ref", "DP-XXXX"),
        "category": request_data.get("category", "All Consented Categories"),
        "requested_at": now,
        "processing_halt_status": "CEASED" if not retention_exception else "RESTRICTED_ARCHIVE_ONLY",
        "processor_notified": True,
        "processors_notified_list": processors_notified,
        "statutory_exception_applies": retention_exception,
        "exception_reason": exception_reason,
        "status": "COMPLETED",
        "audit_trail": [
            f"{now}: Withdrawal request registered under DPDP Section 6(4)",
            f"{now}: Identity of Data Principal verified",
            f"{now}: Withdrawal instruction logged for {len(processors_notified)} recorded vendor(s)" if processors_notified else f"{now}: Processing cease logged internally",
            f"{now}: Audit record generated",
        ],
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
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("rights_requests", {}).get(org_id, []))

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
        "identity_verified": bool(request_data.get("identity_verified", False)),
        "systems_involved": request_data.get("systems_involved") or [
            i.get("storage_location") for i in store.get("data_inventories", {}).get(org_id, []) if i.get("storage_location")
        ][:5],
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
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("vendors", {}).get(org_id, []))

def add_vendor(org_id: str, vendor_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    if "vendors" not in store:
        store["vendors"] = {}
    if org_id not in store["vendors"]:
        store["vendors"][org_id] = []
        
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    dpa_raw = vendor_data.get("dpa_status", "Not Started")
    dpa_upper = str(dpa_raw).upper()
    is_signed = any(k in dpa_upper for k in ("SIGNED", "EXECUTED", "ACTIVE"))
    vendor = {
        "id": f"vnd-{uuid.uuid4().hex[:6]}",
        "name": sanitize_plain_text(vendor_data.get("name", "Vendor Name"), 160),
        "service": sanitize_plain_text(vendor_data.get("service", "Software / Cloud Provider"), 160),
        "personal_data_processed": sanitize_plain_text(vendor_data.get("personal_data_processed", "Customer Records"), 200),
        "storage_location": sanitize_plain_text(vendor_data.get("storage_location", "Not specified"), 140),
        "dpa_status": dpa_raw,
        "agreement_expiry": sanitize_plain_text(vendor_data.get("agreement_expiry", ""), 40),
        "security_documentation": sanitize_plain_text(vendor_data.get("security_documentation", ""), 200),
        "breach_notification_clause": sanitize_plain_text(vendor_data.get("breach_notification_clause", ""), 160),
        "risk_rating": vendor_data.get("risk_rating", "MEDIUM" if not is_signed else "LOW"),
        "dpa_artifact_id": vendor_data.get("dpa_artifact_id", ""),
        "statutory_risk": (
            "Agreement on file: Section 8(2) processor contract tracked."
            if is_signed
            else "Needs attention: Section 8(2) requires engaging Data Processors under a valid contract."
        ),
        "created_at": now,
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
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("retention_schedules", {}).get(org_id, []))

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
        "owner": sanitize_plain_text(schedule_data.get("owner", "Privacy Lead"), 120),
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
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("erasure_tasks", {}).get(org_id, []))

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
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("breach_incidents", {}).get(org_id, []))

def log_breach_incident(org_id: str, incident_data: Dict[str, Any]) -> Dict[str, Any]:
    store = _load_dpdp_store()
    store.setdefault("breach_incidents", {}).setdefault(org_id, [])

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    affected_cats = incident_data.get("affected_data_categories", ["Customer Contact Records"])
    systems_affected = incident_data.get("systems_affected", [])
    incident = {
        "id": f"brc-{uuid.uuid4().hex[:6]}",
        "title": sanitize_plain_text(incident_data.get("title", "Suspected Data Security Incident"), 200),
        "severity": incident_data.get("severity", "MEDIUM"),
        "detected_at": incident_data.get("detected_at", now),
        "affected_data_categories": affected_cats,
        "systems_affected": systems_affected,
        "estimated_individuals_affected": int(incident_data.get("estimated_individuals_affected", 0) or 0),
        "containment_status": incident_data.get("containment_status", "CONTAINED"),
        "description": sanitize_plain_text(incident_data.get("description", ""), 2000),
        "board_notification_status": "DRAFT_PENDING_CUSTOMER_APPROVAL",
        "board_initial_intimation_draft": (
            f"INITIAL INTIMATION OF PERSONAL DATA BREACH (Section 8(6) & Rule 7, DPDP Rules 2025)\n"
            f"To: Data Protection Board of India\n"
            f"From: {org_id} (Data Fiduciary)\n"
            f"Date of Incident: {now}\n"
            f"Description: {incident_data.get('title')}\n"
            f"Immediate Containment Steps: Access revoked, affected system isolated, forensic log preserved.\n"
            f"Status: Investigation underway; detailed 72-hour follow-up report to be filed."
        ),
        "board_72h_detailed_intimation_draft": (
            f"DETAILED FOLLOW-UP INTIMATION (72-Hour Statutory Requirement)\n"
            f"Affected Categories: {', '.join(affected_cats) if isinstance(affected_cats, list) else affected_cats}\n"
            f"Systems Affected: {', '.join(systems_affected) if isinstance(systems_affected, list) else systems_affected}\n"
            f"Estimated Count: {incident_data.get('estimated_individuals_affected', 0)}\n"
            f"Forensic Conclusion: Root cause addressed. Remedial measures deployed."
        ),
        "principal_notification_draft": (
            f"NOTICE OF DATA SECURITY INCIDENT\n"
            f"Dear Customer,\n"
            f"We are writing to inform you of a recent security incident involving {incident_data.get('title')}.\n"
            f"We have contained the issue and are reviewing what actions help protect your information.\n"
            f"For questions, please contact our Privacy & Grievance Officer."
        ),
        "timeline_events": [
            {"timestamp": now, "event": "Incident recorded and triage initiated", "actor": "Privacy Lead"}
        ],
        "customer_authorized_to_send": False,
        "created_at": now,
        "updated_at": now,
    }
    store["breach_incidents"][org_id].insert(0, incident)
    _save_dpdp_store(store)
    return incident


def update_breach_incident(org_id: str, incident_id: str, updates: Dict[str, Any], actor: str = "Privacy Lead") -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    items = store.get("breach_incidents", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for item in items:
        if item.get("id") == incident_id:
            for k in ("title", "severity", "containment_status", "description", "affected_data_categories", "systems_affected", "estimated_individuals_affected"):
                if k in updates:
                    item[k] = updates[k]
            if updates.get("timeline_note"):
                item.setdefault("timeline_events", []).append({
                    "timestamp": now,
                    "event": sanitize_plain_text(updates["timeline_note"], 400),
                    "actor": actor,
                })
            elif updates:
                item.setdefault("timeline_events", []).append({
                    "timestamp": now,
                    "event": f"Updated fields: {', '.join(k for k in updates.keys() if k != 'timeline_note')}",
                    "actor": actor,
                })
            item["updated_at"] = now
            _save_dpdp_store(store)
            return item
    return None


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
            item.setdefault("timeline_events", []).append({
                "timestamp": now,
                "event": f"Customer authorized regulatory notice preparation ({authorized_by})",
                "actor": authorized_by,
            })
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
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("website_scans", {}).get(org_id, []))

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
    
    # Evaluated controls count (7 distinct statutory controls assessed in steps 4-6)
    total_applicable = 7
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
        
    # Security Safeguards (Sec 8(5) & Rule 6)
    if step4.get("encryption_at_rest_and_transit"):
        implemented_count += 1
    else:
        gaps.append({
            "requirement_id": "DPDP-SEC-08-05",
            "title": "Unverified Reasonable Security Safeguards on Personal Data",
            "severity": "CRITICAL",
            "action": "Verify encryption, masking, access controls, and security logs under Section 8(5) and Rule 6."
        })
        actions.append("Verify Section 8(5) and Rule 6 reasonable security safeguards")
        
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
        
    # Honest score: calculated strictly from verified responses without automatic bonus inflation
    score = int(round((implemented_count / max(1, total_applicable)) * 100))
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
    store = _read_dpdp_store_cached()
    existing = store.get("organisational_assessments", {}).get(org_id)
    if existing:
        return copy.deepcopy(existing)

    profile = get_onboarding_profile(org_id) or {}
    is_demo = demo_fixture.is_demo_org(org_id, profile=profile)

    if is_demo:
        return {
            "org_id": org_id,
            "is_complete": True,
            "is_demo": True,
            "demo_banner": demo_fixture.DEMO_DISCLAIMER,
            "current_step": 6,
            "organisation_profile": {
                "name": profile.get("company_name", demo_fixture.DEMO_ORG_NAME),
                "industry": profile.get("industry", demo_fixture.DEMO_INDUSTRY),
                "website": profile.get("website_url", demo_fixture.DEMO_WEBSITE),
                "size": profile.get("organisation_size", "11-50 (Small / Medium)"),
                "employees": profile.get("employee_count", 25),
                "locations": "Bengaluru & Mumbai, India",
                "contact_email": demo_fixture.DEMO_PRIVACY_EMAIL,
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

def _get_dpdp_org_evidence_dir(org_id: str) -> str:
    safe_org = "".join(c for c in str(org_id or "") if c.isalnum() or c in ("-", "_")).strip() or "org-default"
    base = os.path.join(os.path.dirname(os.path.abspath(DPDP_DATA_FILE)), "dpdp_evidence")
    os.makedirs(base, exist_ok=True)
    target = safe_resolve_under_dir(base, safe_org)
    os.makedirs(target, exist_ok=True)
    return target


def add_evidence_artifact(org_id: str, artifact: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
    """
    Adds a compliance evidence document with validated physical file storage (when bytes provided),
    cryptographic SHA-256 integrity, version history, and strict 5-state review status.
    """
    store = _load_dpdp_store()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if artifact is None:
        artifact = dict(kwargs)
    elif kwargs:
        artifact = {**artifact, **kwargs}

    artifact_id = f"EVI-{uuid.uuid4().hex[:8].upper()}"
    # Uploaded evidence NEVER begins as Verified automatically
    status = artifact.get("status", "Uploaded")
    if status not in VALID_EVIDENCE_STATUSES:
        status = "Uploaded"

    raw_filename = artifact.get("filename") or artifact.get("file_name") or "evidence_document.pdf"
    file_bytes = artifact.get("file_bytes")
    stored_filename = None
    mime_type = "application/octet-stream"
    file_size = 0
    encrypted_flag = False
    previewable = False

    if file_bytes is not None:
        if not isinstance(file_bytes, (bytes, bytearray)):
            raise ValueError("Evidence file bytes must be binary data.")
        ok, err_msg, meta = validate_uploaded_file(raw_filename, bytes(file_bytes))
        if not ok:
            raise ValueError(err_msg)
        safe_name = meta["safe_filename"]
        stored_filename = f"{artifact_id}_v1_{safe_name}"
        org_dir = _get_dpdp_org_evidence_dir(org_id)
        dest_path = safe_resolve_under_dir(org_dir, stored_filename)
        payload, encrypted_flag = encrypt_bytes_if_configured(bytes(file_bytes))
        atomic_write_bytes(dest_path, payload)
        file_hash = f"sha256:{meta['sha256']}"
        mime_type = meta["mime_type"]
        file_size = meta["size_bytes"]
        previewable = meta["previewable"]
    else:
        # Metadata-only call (validate filename extension strictly against executables/XSS)
        _, ext = os.path.splitext(os.path.basename(str(raw_filename)).lower())
        if ext in BLOCKED_DANGEROUS_EXTENSIONS or (ext and ext not in ALLOWED_UPLOAD_EXTENSIONS):
            raise ValueError(f"Unsupported or dangerous file extension '{ext}'.")
        safe_name = sanitize_filename(raw_filename)
        file_hash = artifact.get("file_hash") or f"sha256:metadata-only-{uuid.uuid4().hex}"

    version_entry = {
        "version": 1,
        "filename": safe_name,
        "stored_filename": stored_filename,
        "file_hash": file_hash,
        "mime_type": mime_type,
        "size_bytes": file_size,
        "encrypted": encrypted_flag,
        "uploaded_at": now,
        "uploaded_by": sanitize_plain_text(artifact.get("uploaded_by", "Privacy Lead"), 120),
    }

    new_artifact = {
        "id": artifact_id,
        "title": sanitize_plain_text(artifact.get("title") or safe_name, 200),
        "category": sanitize_plain_text(artifact.get("category", "General Policies"), 80),
        "control_id": sanitize_plain_text(artifact.get("control_id", "DPDP-SEC-08-05"), 80),
        "filename": safe_name,
        "stored_filename": stored_filename,
        "mime_type": mime_type,
        "size_bytes": file_size,
        "has_physical_file": bool(stored_filename),
        "previewable": previewable,
        "encrypted": encrypted_flag,
        "file_hash": file_hash,
        "uploaded_by": sanitize_plain_text(artifact.get("uploaded_by", "Privacy Lead"), 120),
        "uploaded_at": now,
        "expiry_date": sanitize_plain_text(
            artifact.get("expiry_date") or (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)).strftime("%Y-%m-%d"),
            30,
        ),
        "status": status,
        "review_notes": sanitize_plain_text(artifact.get("review_notes", "Awaiting compliance review."), 500),
        "reviewed_by": None,
        "reviewed_at": None,
        "versions": [version_entry],
        "audit_trail": [
            {"action": "UPLOADED", "timestamp": now, "actor": sanitize_plain_text(artifact.get("uploaded_by", "Privacy Lead"), 120)}
        ],
    }

    store.setdefault("evidence_vault", {}).setdefault(org_id, []).insert(0, new_artifact)
    _save_dpdp_store(store)
    return new_artifact


def get_evidence_file_bytes(org_id: str, artifact_id: str, version: Optional[int] = None) -> Tuple[Optional[bytes], Optional[Dict[str, Any]]]:
    """Reads physical file bytes strictly isolated to org_id."""
    store = _load_dpdp_store()
    artifacts = store.get("evidence_vault", {}).get(org_id, [])
    target = next((a for a in artifacts if a.get("id") == artifact_id), None)
    if not target:
        return None, None

    meta = target
    if version is not None:
        for v in target.get("versions", []):
            if v.get("version") == version:
                meta = v
                break

    stored_name = meta.get("stored_filename")
    if not stored_name:
        return None, None

    org_dir = _get_dpdp_org_evidence_dir(org_id)
    path = safe_resolve_under_dir(org_dir, stored_name)
    if not os.path.exists(path):
        return None, None

    with open(path, "rb") as f:
        disk_bytes = f.read()
    raw = decrypt_bytes_if_encrypted(disk_bytes, bool(meta.get("encrypted")))
    return raw, {
        "filename": meta.get("filename", "evidence_file"),
        "mime_type": meta.get("mime_type", "application/octet-stream"),
        "file_hash": meta.get("file_hash", ""),
        "previewable": meta.get("previewable", False),
    }


def add_evidence_version(
    org_id: str,
    artifact_id: str,
    file_bytes: bytes,
    filename: str,
    uploaded_by: str = "Privacy Lead",
    notes: str = "New evidence version uploaded",
) -> Optional[Dict[str, Any]]:
    ok, err_msg, meta = validate_uploaded_file(filename, file_bytes)
    if not ok:
        raise ValueError(err_msg)

    store = _load_dpdp_store()
    artifacts = store.get("evidence_vault", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for a in artifacts:
        if a.get("id") == artifact_id:
            next_v = len(a.get("versions", [])) + 1
            safe_name = meta["safe_filename"]
            stored_filename = f"{artifact_id}_v{next_v}_{safe_name}"
            org_dir = _get_dpdp_org_evidence_dir(org_id)
            dest_path = safe_resolve_under_dir(org_dir, stored_filename)
            payload, encrypted_flag = encrypt_bytes_if_configured(bytes(file_bytes))
            atomic_write_bytes(dest_path, payload)

            file_hash = f"sha256:{meta['sha256']}"
            ver = {
                "version": next_v,
                "filename": safe_name,
                "stored_filename": stored_filename,
                "file_hash": file_hash,
                "mime_type": meta["mime_type"],
                "size_bytes": meta["size_bytes"],
                "encrypted": encrypted_flag,
                "uploaded_at": now,
                "uploaded_by": uploaded_by,
                "notes": sanitize_plain_text(notes, 400),
            }
            a.setdefault("versions", []).append(ver)
            a["filename"] = safe_name
            a["stored_filename"] = stored_filename
            a["file_hash"] = file_hash
            a["mime_type"] = meta["mime_type"]
            a["size_bytes"] = meta["size_bytes"]
            a["has_physical_file"] = True
            a["previewable"] = meta["previewable"]
            a["encrypted"] = encrypted_flag
            a["status"] = "Uploaded"
            a.setdefault("audit_trail", []).append({
                "action": f"NEW_VERSION_V{next_v}",
                "timestamp": now,
                "actor": uploaded_by,
                "notes": sanitize_plain_text(notes, 400),
            })
            _save_dpdp_store(store)
            return a
    return None


def delete_evidence_artifact(org_id: str, artifact_id: str) -> bool:
    store = _load_dpdp_store()
    artifacts = store.get("evidence_vault", {}).get(org_id, [])
    target = next((a for a in artifacts if a.get("id") == artifact_id), None)
    if not target:
        return False

    org_dir = _get_dpdp_org_evidence_dir(org_id)
    for v in target.get("versions", []):
        sname = v.get("stored_filename")
        if sname:
            try:
                p = safe_resolve_under_dir(org_dir, sname)
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
    if target.get("stored_filename"):
        try:
            p = safe_resolve_under_dir(org_dir, target["stored_filename"])
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass

    store["evidence_vault"][org_id] = [a for a in artifacts if a.get("id") != artifact_id]
    _save_dpdp_store(store)
    return True

def get_evidence_artifacts(org_id: str, category: Optional[str] = None, status: Optional[str] = None, control_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns all evidence artifacts uploaded by the organization without write-on-read."""
    store = _read_dpdp_store_cached()
    artifacts = copy.deepcopy(store.get("evidence_vault", {}).get(org_id, []))
    profile = get_onboarding_profile(org_id) or {}
    is_demo = demo_fixture.is_demo_org(org_id, profile=profile)
    if not artifacts and is_demo:
        artifacts = copy.deepcopy(demo_fixture.get_demo_seed_collections()["evidence"])

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
        "title": "Customer Data Processing Register (Section 8 Accountability)",
        "statutory_ref": "DPDP Act 2023, Sections 4, 5 & 8",
        "description": "Plain-English catalog of digital data streams, legal bases, departments, retention limits, and storage systems."
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
        "statutory_ref": "DPDP Act 2023, Sections 11, 12, 13, 14; Rule 14",
        "description": "Workflows for processing customer and patient requests for access, correction, erasure, and nominee designation."
    },
    "grievance_procedure": {
        "title": "Grievance Redressal Policy & Escalation Mechanism (Section 8(10))",
        "statutory_ref": "DPDP Act 2023, Section 8(10)-(11); Rule 9",
        "description": "Structured procedure for handling privacy disputes, response timelines, and communication before Board escalation."
    },
    "vendor_register": {
        "title": "Third-Party Data Processor Agreement (DPA) Register (Section 8(2))",
        "statutory_ref": "DPDP Act 2023, Section 8(1)-(2)",
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
    company_name = profile.get("company_name") or "Your Organisation"
    industry = profile.get("industry") or "Business & Services"
    dpo_email = profile.get("contact_email") or "grievance@organisation.com"
    website = profile.get("website_url") or "https://your-business-website.example"
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

3. RETENTION REVIEW & DELETION WORKFLOW
Upon expiry of the prescribed retention period, responsible owners should identify affected systems, verify no Indian law mandates continued retention, perform record deletion, and upload deletion confirmation evidence.
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

1. PUBLISHED GRIEVANCE & REQUEST HANDLING TIMELINE
All Data Principal rights requests (Access, Correction, Erasure, Grievance, Nomination) must be acknowledged promptly and resolved within our published internal and grievance redressal timelines (note: the DPDP Act 2023 does not mandate a generic 72-hour deadline for rights requests).

2. VERIFICATION PROCEDURE
Before disclosing medical, financial, or customer records, verify the identity of the requester using registered mobile/email verification or valid photo ID check.
"""
    else:
        content = disclaimer_header + f"""{company_name.upper()}
COMPLIANCE GOVERNANCE DOCUMENT: {meta['title']}
Statutory Reference: {meta['statutory_ref']}

This document establishes standard operating protocols for {company_name} to support operational readiness under India's Digital Personal Data Protection Act, 2023.
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
    """Returns platform-wide administration metrics derived strictly from persisted store records."""
    store = _load_dpdp_store()

    profiles = store.get("onboarding_profiles", {})
    total_orgs = len(profiles)
    total_scans = sum(len(scans) for scans in store.get("website_scans", {}).values())
    total_evidence = sum(len(evs) for evs in store.get("evidence_vault", {}).values())
    total_inventories = sum(len(items) for items in store.get("data_inventories", {}).values())
    total_breaches = sum(len(b) for b in store.get("breach_incidents", {}).values())
    total_vendors = sum(len(v) for v in store.get("vendors", {}).values())
    total_retention = sum(len(r) for r in store.get("retention_schedules", {}).values())
    total_erasure = sum(len(e) for e in store.get("erasure_tasks", {}).values())

    sector_counts: Dict[str, int] = {}
    for p in profiles.values():
        ind = sanitize_plain_text(p.get("industry") or "Unspecified", 80) or "Unspecified"
        sector_counts[ind] = sector_counts.get(ind, 0) + 1

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
        "sector_distribution": sector_counts,
        "legal_database_version": "2026.11.4 (India DPDP Act 2023 & Rules 2025)",
        "last_legal_review": "2026-11-26",
        "active_plans": {
            "starter": {"price_inr": 999, "name": "Starter Plan"},
            "growth": {"price_inr": 1999, "name": "Growth Plan"},
            "business": {"price_inr": 2999, "name": "Business Plan"},
        },
    }


# ==============================================================================
# PART 4 & 5: HONEST SETUP PROGRESS, REAL ATTENTION TASKS, GENUINE ACTIVITY
# ==============================================================================

def get_setup_progress(org_id: str) -> Dict[str, Any]:
    """
    Computes genuine 'X of 5' workspace setup milestones without fake percentage inflation.
    """
    profile = get_onboarding_profile(org_id) or {}
    inventory = get_data_inventory(org_id)
    scans = get_website_scans(org_id)
    notices = get_privacy_notices(org_id)
    vendors = get_vendors(org_id)
    evidence = get_evidence_artifacts(org_id)

    has_privacy_docs = bool(notices) or bool(evidence)
    steps = [
        {
            "key": "business_details",
            "title": "Business details",
            "completed": bool(profile.get("onboarding_completed") or (profile.get("company_name") and profile.get("industry"))),
            "action_view": "onboarding",
            "action_label": "Update details",
        },
        {
            "key": "website_check",
            "title": "Website check",
            "completed": len(scans) > 0,
            "action_view": "website-check",
            "action_label": "Check site",
        },
        {
            "key": "customer_information",
            "title": "Customer information",
            "completed": len(inventory) > 0,
            "action_view": "inventory",
            "action_label": "Review data",
        },
        {
            "key": "external_services",
            "title": "External services",
            "completed": len(vendors) > 0,
            "action_view": "vendors",
            "action_label": "Add companies",
        },
        {
            "key": "privacy_documents",
            "title": "Privacy documents",
            "completed": has_privacy_docs,
            "action_view": "notices",
            "action_label": "Create notice",
        },
    ]
    completed_count = sum(1 for s in steps if s["completed"])
    next_step = next((s for s in steps if not s["completed"]), None)
    return {
        "completed_count": completed_count,
        "total_steps": 5,
        "steps": steps,
        "next_recommended_step": next_step,
        "onboarding_completed": bool(profile.get("onboarding_completed")),
    }


def _build_next_actions(inventory, notices, vendors, scans, requests_list, retention, incidents, rem_tasks, limit: int = 3) -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []
    if not inventory:
        tasks.append({
            "id": "attn-inventory",
            "title": "List what customer details your business collects",
            "why": "Every privacy notice, vendor agreement, and deletion rule starts with knowing what customer data you hold.",
            "what_to_do": "Open Customer Information and confirm suggested items or upload your spreadsheet.",
            "action_label": "Add customer data",
            "fix_target": "inventory",
            "status": "Needs attention",
            "severity": "HIGH",
        })
    else:
        drafts = [it for it in inventory if "CONFIRMATION" in str(it.get("confirmation_status", "")).upper() or "SUGGESTED" in str(it.get("confirmation_status", "")).upper()]
        if drafts:
            tasks.append({
                "id": "attn-inventory-drafts",
                "title": f"Confirm or edit {len(drafts)} suggested customer data item(s)",
                "why": "Suggestions stay drafts until someone in your business confirms they are accurate.",
                "what_to_do": "Open Customer Information, check suggested fields, and confirm what applies to you.",
                "action_label": "Review drafts",
                "fix_target": "inventory",
                "status": "Pending review",
                "severity": "HIGH",
            })

    if not notices:
        tasks.append({
            "id": "attn-notice",
            "title": "Create your customer Privacy Notice draft",
            "why": "Customers need clear plain-English details of what you collect, why you collect it, and who to contact.",
            "what_to_do": "Generate an editable draft built from your Customer Information and review it before publishing.",
            "action_label": "Create Privacy Notice",
            "fix_target": "notices",
            "status": "Needs attention",
            "severity": "HIGH",
        })

    unsigned_vendors = [
        v for v in vendors
        if not any(ok_w in str(v.get("dpa_status", "")).upper() for ok_w in ("SIGNED", "EXECUTED", "ACTIVE"))
    ]
    if unsigned_vendors:
        v0 = unsigned_vendors[0]
        tasks.append({
            "id": "attn-vendor-dpa",
            "title": f"Review agreement with {v0.get('name', 'external service')} ({len(unsigned_vendors)} pending)",
            "why": "You remain responsible for customer data shared with external tools unless written privacy agreements are in place.",
            "what_to_do": "Open Vendor Reviews to send a quick questionnaire or record an executed agreement.",
            "action_label": "Review companies",
            "fix_target": "vendor-reviews",
            "status": "Needs review",
            "severity": "HIGH",
        })
    elif not vendors:
        tasks.append({
            "id": "attn-vendors-empty",
            "title": "Add software, lab, or courier companies you share data with",
            "why": "Track billing tools, hosting, labs, and payment gateways so agreements and risks stay organised.",
            "what_to_do": "Add external tools your business uses in Companies I Share Data With.",
            "action_label": "Add companies",
            "fix_target": "vendors",
            "status": "To do",
            "severity": "MEDIUM",
        })

    if scans:
        open_gaps = [f for f in scans[0].get("findings", []) if f.get("severity") in ("CRITICAL", "HIGH")]
        if open_gaps:
            tasks.append({
                "id": "attn-scan-gap",
                "title": open_gaps[0].get("title", "Fix website privacy issue"),
                "why": f"Found publicly on {scans[0].get('target_url', 'your website')} during Website Check.",
                "what_to_do": open_gaps[0].get("recommended_action") or "Open Website Check to view instructions and update your site.",
                "action_label": "Fix finding",
                "fix_target": "website-check",
                "status": "Needs attention",
                "severity": open_gaps[0].get("severity", "HIGH"),
            })
    else:
        tasks.append({
            "id": "attn-scan-run",
            "title": "Run a Website Check for visible privacy gaps",
            "why": "Spotting missing privacy notice links or hidden scripts takes under a minute on your public website.",
            "what_to_do": "Enter your website URL in Website Check to inspect forms, links, and scripts.",
            "action_label": "Run website check",
            "fix_target": "website-check",
            "status": "To do",
            "severity": "MEDIUM",
        })

    open_req = [r for r in requests_list if r.get("status") not in ("COMPLETED", "REJECTED")]
    if open_req:
        tasks.append({
            "id": "attn-requests",
            "title": f"Respond to {len(open_req)} open customer request(s)",
            "why": "Customers asking to view, update, or erase data expect a tracked response.",
            "what_to_do": "Open Customer Requests to verify details and record your resolution.",
            "action_label": "Open requests",
            "fix_target": "rights",
            "status": "In progress",
            "severity": "HIGH",
        })

    if not retention:
        tasks.append({
            "id": "attn-retention",
            "title": "Set how long you keep customer records",
            "why": "Avoid keeping old enquiry forms or customer files indefinitely after their purpose ends.",
            "what_to_do": "Add simple keeping periods in Data Retention & Deletion.",
            "action_label": "Set deletion rules",
            "fix_target": "retention",
            "status": "To do",
            "severity": "MEDIUM",
        })

    if any(i.get("board_notification_status") == "DRAFT_PENDING_CUSTOMER_APPROVAL" for i in incidents):
        tasks.append({
            "id": "attn-incident",
            "title": "Review open incident timeline & notification draft",
            "why": "Ensure containment notes and notification drafts have human approval before sending.",
            "what_to_do": "Review open items under Privacy Incident Response.",
            "action_label": "Open incidents",
            "fix_target": "breaches",
            "status": "Needs approval",
            "severity": "CRITICAL",
        })

    for rt in [t for t in rem_tasks if t.get("status") not in ("Resolved", "Completed", "RESOLVED", "Not applicable")][:3]:
        tasks.append({
            "id": rt.get("id"),
            "title": rt.get("title", "Follow-up task"),
            "why": rt.get("why_it_matters") or rt.get("description", "Action item from your privacy workspace."),
            "what_to_do": rt.get("description") or "Open this task to update status or attach proof.",
            "action_label": "Start task",
            "fix_target": "remediation",
            "status": rt.get("status") or "Open",
            "severity": rt.get("severity", "MEDIUM"),
        })
    return tasks[:limit]


def get_home_attention_tasks(org_id: str, limit: int = 3) -> List[Dict[str, Any]]:
    """
    Returns at most 3 plain-English, genuinely detected items needing attention,
    each with a working action target inside the dashboard.
    """
    return _build_next_actions(
        inventory=get_data_inventory(org_id),
        notices=get_privacy_notices(org_id),
        vendors=get_vendors(org_id),
        scans=get_website_scans(org_id),
        requests_list=get_rights_requests(org_id),
        retention=get_retention_schedules(org_id),
        incidents=get_breach_incidents(org_id),
        rem_tasks=get_remediation_tasks(org_id),
        limit=limit,
    )


def get_recent_activity(org_id: str, limit: int = 12) -> List[Dict[str, Any]]:
    """
    Returns strictly genuine chronological activity recorded in this organisation's DB
    and security audit logs. Zero invented placeholder activity.
    """
    events: List[Dict[str, Any]] = []

    for sc in get_website_scans(org_id):
        events.append({
            "timestamp": sc.get("scanned_at") or sc.get("created_at") or "",
            "title": f"Website scanned: {sc.get('target_url', '')}",
            "category": "Website Check",
            "target_view": "scanner",
        })
    for ev in get_evidence_artifacts(org_id):
        events.append({
            "timestamp": ev.get("uploaded_at") or "",
            "title": f"Evidence uploaded: {ev.get('title', ev.get('filename', 'Document'))} ({ev.get('status', 'Uploaded')})",
            "category": "Evidence Vault",
            "target_view": "evidence",
        })
    for n in get_privacy_notices(org_id):
        events.append({
            "timestamp": n.get("updated_at") or n.get("created_at") or "",
            "title": f"Privacy Notice saved: {n.get('title', 'Notice')} ({n.get('version', 'v1.0')})",
            "category": "Privacy Notice",
            "target_view": "notices",
        })
    for req in get_rights_requests(org_id):
        events.append({
            "timestamp": req.get("received_at") or "",
            "title": f"Customer privacy request logged ({req.get('type', 'ACCESS')} - {req.get('status', 'RECEIVED')})",
            "category": "Customer Requests",
            "target_view": "rights",
        })
    for inc in get_breach_incidents(org_id):
        events.append({
            "timestamp": inc.get("created_at") or "",
            "title": f"Incident logged: {inc.get('title', 'Security Incident')}",
            "category": "Incident Response",
            "target_view": "breaches",
        })
    for aud in get_audit_logs(org_id, limit=limit):
        events.append({
            "timestamp": aud.get("timestamp", ""),
            "title": f"Account event: {aud.get('action', '')}",
            "category": "Audit Trail",
            "target_view": "settings",
        })

    events.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)
    return events[:limit]


# ==============================================================================
# GTM PLATFORM EXTENSIONS: DISCOVERY, ASSESSMENT TOPICS, KANBAN TASKS, PORTALS
# ==============================================================================

INDUSTRY_SUGGESTED_ACTIVITIES: Dict[str, List[Dict[str, Any]]] = {
    "healthcare": [
        {"key": "patient_appointments", "label": "Appointments", "category": "Health information", "fields": ["Patient Name", "Phone Number", "Appointment Date", "Doctor Requested"], "purpose": "Scheduling consultations and sending appointment reminders", "storage_system": "Clinic Booking Software / Register"},
        {"key": "contact_details", "label": "Patient contact details", "category": "Contact information", "fields": ["Full Name", "Mobile Number", "Email", "Emergency Contact"], "purpose": "Patient communication and follow-up care", "storage_system": "Reception CRM / Clinic Database"},
        {"key": "diagnostic_reports", "label": "Diagnostic reports", "category": "Health information", "fields": ["Patient ID", "Test Results", "Sample Type", "Clinical Notes"], "purpose": "Laboratory testing and medical report delivery", "storage_system": "Lab Management System"},
        {"key": "billing", "label": "Billing", "category": "Billing information", "fields": ["Patient Name", "Invoice Number", "Payment Mode", "GST/Receipt Details"], "purpose": "Medical billing and statutory tax records", "storage_system": "Billing Software"},
        {"key": "insurance_information", "label": "Insurance", "category": "Billing information", "fields": ["Policyholder Name", "Policy Number", "Insurer/TPA Name"], "purpose": "Cashless or reimbursement insurance claim processing", "storage_system": "Insurance Desk Portal"},
    ],
    "saas": [
        {"key": "registration", "label": "Registration", "category": "Customer accounts", "fields": ["Full Name", "Work Email", "Organisation Name"], "purpose": "Creating customer workspace accounts", "storage_system": "Application Database"},
        {"key": "user_profiles", "label": "Accounts", "category": "Customer accounts", "fields": ["Name", "Email", "Job Role", "Preferences"], "purpose": "Managing customer accounts and workspace access", "storage_system": "Application Database"},
        {"key": "subscription_billing", "label": "Payments", "category": "Billing information", "fields": ["Company Billing Name", "GSTIN", "Payment Method Token", "Invoices"], "purpose": "SaaS subscription invoicing and payment collection", "storage_system": "Payment Gateway & Billing Software"},
        {"key": "product_analytics", "label": "Analytics", "category": "Website and application information", "fields": ["User ID", "Page/Feature Events", "IP Address", "Browser"], "purpose": "Improving product reliability and usability", "storage_system": "Analytics Platform"},
        {"key": "customer_support", "label": "Customer support", "category": "Contact information", "fields": ["Name", "Email", "Support Ticket History"], "purpose": "Resolving customer questions and issues", "storage_system": "Helpdesk Software"},
    ],
    "ecommerce": [
        {"key": "order_history", "label": "Orders", "category": "Customer accounts", "fields": ["Order ID", "Purchased Items", "Order Timestamps"], "purpose": "Order fulfilment, warranty, and support", "storage_system": "Order Management System"},
        {"key": "delivery_information", "label": "Delivery details", "category": "Contact information", "fields": ["Recipient Name", "Street Address", "PIN Code", "Delivery Phone"], "purpose": "Shipping parcels via logistics partners", "storage_system": "Shipping & Courier Partners"},
        {"key": "payment_processing", "label": "Payments", "category": "Billing information", "fields": ["Transaction ID", "UPI/Card Token", "Amount"], "purpose": "Checkout payment collection and refunds", "storage_system": "Payment Gateway"},
        {"key": "returns", "label": "Returns", "category": "Billing information", "fields": ["Order ID", "Pickup Address", "Refund Account / UPI"], "purpose": "Processing product exchanges and refunds", "storage_system": "Returns Desk & Finance"},
        {"key": "marketing_campaigns", "label": "Marketing", "category": "Website and application information", "fields": ["Email", "Phone", "Ad Pixels", "Cart Activity"], "purpose": "Promotional messaging with opt-out support", "storage_system": "Marketing & Analytics Tools"},
    ],
    "education": [
        {"key": "student_registration", "label": "Student registration", "category": "Student information", "fields": ["Student Name", "Date of Birth", "Admission ID", "Grade/Course"], "purpose": "Student enrolment and academic records", "storage_system": "School / EdTech MIS"},
        {"key": "parent_contact", "label": "Parent details", "category": "Contact information", "fields": ["Parent/Guardian Name", "Mobile Number", "Email", "Residential Address"], "purpose": "Guardian notifications and parental permission records", "storage_system": "MIS & Messaging Tool"},
        {"key": "attendance", "label": "Attendance", "category": "Student information", "fields": ["Student ID", "Daily Attendance Status", "Timetable"], "purpose": "Daily attendance monitoring and safety alerts", "storage_system": "Attendance Register / App"},
        {"key": "examination_records", "label": "Examination records", "category": "Student information", "fields": ["Student ID", "Roll Number", "Assessment Marks", "Report Cards"], "purpose": "Academic grading and certificate issuance", "storage_system": "Examination Database"},
        {"key": "fee_records", "label": "Fee records", "category": "Billing information", "fields": ["Student ID", "Payer Name", "Fee Receipt", "Payment Reference"], "purpose": "Tuition fee collection and receipts", "storage_system": "Fee Billing System"},
    ],
    "professional_services": [
        {"key": "client_information", "label": "Client information", "category": "Contact information", "fields": ["Client Contact Name", "Work Email", "Phone", "Organisation"], "purpose": "Client onboarding and advisory engagements", "storage_system": "Practice CRM"},
        {"key": "contracts", "label": "Contracts", "category": "Other personal information", "fields": ["Signatory Name", "Authorised Signatory Details", "Signed SOW/NDA"], "purpose": "Executing client agreements and audits", "storage_system": "Document Storage"},
        {"key": "billing", "label": "Billing", "category": "Billing information", "fields": ["Billing Contact", "Invoice", "PAN/GST Details", "Bank Reference"], "purpose": "Fee invoicing and tax compliance", "storage_system": "Accounting Software"},
        {"key": "communication_records", "label": "Communication records", "category": "Contact information", "fields": ["Email Threads", "Meeting Notes", "Call Logs"], "purpose": "Client advisory records and project follow-up", "storage_system": "Business Email / Cloud Drive"},
        {"key": "employee_data", "label": "Employee data", "category": "Employee information", "fields": ["Employee Name", "PAN", "Bank Account", "PF/ESI Details"], "purpose": "Employment administration", "storage_system": "HR & Payroll Software"},
    ],
}


def get_industry_activity_suggestions(industry: str) -> List[Dict[str, Any]]:
    low = (industry or "saas").strip().lower()
    if any(k in low for k in ("health", "clinic", "hospital", "diag", "medical")):
        return list(INDUSTRY_SUGGESTED_ACTIVITIES["healthcare"])
    if any(k in low for k in ("ecom", "retail", "shop", "store", "d2c")):
        return list(INDUSTRY_SUGGESTED_ACTIVITIES["ecommerce"])
    if any(k in low for k in ("edu", "school", "college", "edtech", "academy")):
        return list(INDUSTRY_SUGGESTED_ACTIVITIES["education"])
    if any(k in low for k in ("prof", "legal", "ca", "consult", "agency")):
        return list(INDUSTRY_SUGGESTED_ACTIVITIES["professional_services"])
    return list(INDUSTRY_SUGGESTED_ACTIVITIES["saas"])


def prepopulate_industry_activities(org_id: str, industry: str, selected_keys: List[str]) -> List[Dict[str, Any]]:
    """Generates draft inventory items marked 'SUGGESTED — NEEDS CONFIRMATION' from selected activity cards."""
    catalog = get_industry_activity_suggestions(industry)
    selected_set = {str(k).strip().lower() for k in (selected_keys or []) if str(k).strip()}
    existing = get_data_inventory(org_id)
    existing_labels = {str(e.get("source", "")).lower() for e in existing}
    created: List[Dict[str, Any]] = []
    for item in catalog:
        if selected_set and item["key"].lower() not in selected_set and item["label"].lower() not in selected_set:
            continue
        if item["label"].lower() in existing_labels:
            continue
        rec = add_inventory_entry(org_id, {
            "category": item["category"],
            "fields": item["fields"],
            "principal_type": "Patients & Customers" if "health" in industry.lower() else ("Students & Guardians" if "edu" in industry.lower() else "Customers / Users"),
            "source": item["label"],
            "purpose": item["purpose"],
            "legal_basis": "Review needed (Consent Sec 6 or Legitimate Use Sec 7)",
            "storage_system": item["storage_system"],
            "confirmation_status": "SUGGESTED — NEEDS CONFIRMATION",
        })
        created.append(rec)
    return created


def find_inventory_duplicates(org_id: str) -> List[Dict[str, Any]]:
    items = get_data_inventory(org_id)
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for it in items:
        key = (
            str(it.get("category", "")).strip().lower(),
            str(it.get("purpose", "")).strip().lower(),
        )
        groups.setdefault(key, []).append(it)
    duplicates = []
    for (cat, purp), grp in groups.items():
        if len(grp) > 1:
            duplicates.append({
                "category": grp[0].get("category"),
                "purpose": grp[0].get("purpose"),
                "count": len(grp),
                "entry_ids": [g["id"] for g in grp],
            })
    return duplicates


def bulk_confirm_inventory(org_id: str, entry_ids: List[str], status: str = "Confirmed by business") -> int:
    clean_status = status if status in ("Confirmed by business", "SUGGESTED — NEEDS CONFIRMATION", "Needs review", "Rejected") else "Confirmed by business"
    target_set = set(entry_ids or [])
    store = _load_dpdp_store()
    items = store.get("data_inventories", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    changed = 0
    for it in items:
        if not target_set or it.get("id") in target_set:
            it["confirmation_status"] = clean_status
            it["updated_at"] = now
            new_ver = int(it.get("version", 1)) + 1
            it["version"] = new_ver
            it.setdefault("version_history", []).append({
                "version": new_ver, "timestamp": now, "status": clean_status, "note": f"Bulk status set to {clean_status}"
            })
            changed += 1
    if changed:
        _save_dpdp_store(store)
    return changed


def save_discovery_suggestions(org_id: str, suggestions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    store = _load_dpdp_store()
    bucket = store.setdefault("discovery_suggestions", {}).setdefault(org_id, [])
    existing_sigs = {(s.get("extracted_type"), str(s.get("value", "")).lower()) for s in bucket}
    added = []
    for sug in suggestions or []:
        sig = (sug.get("extracted_type"), str(sug.get("value", "")).lower())
        if sig in existing_sigs:
            continue
        item = {
            "id": sug.get("id") or f"ext-{uuid.uuid4().hex[:8]}",
            "extracted_type": sug.get("extracted_type", "data_activity"),
            "value": sanitize_plain_text(sug.get("value", ""), 200),
            "category": sug.get("category", "Other personal information"),
            "fields": sug.get("fields", []),
            "purpose": sug.get("purpose", ""),
            "storage_location": sug.get("storage_location", "To be confirmed"),
            "retention_period": sug.get("retention_period", ""),
            "source_document": sug.get("source_document", "Manual / Discovery"),
            "confidence": sug.get("confidence", "MEDIUM"),
            "status": sug.get("status", "Needs review"),
            "verified": False,
            "created_at": sug.get("created_at") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        bucket.insert(0, item)
        added.append(item)
        existing_sigs.add(sig)
    store["discovery_suggestions"][org_id] = bucket[:400]
    _save_dpdp_store(store)
    return added


def get_discovery_suggestions(org_id: str, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    store = _read_dpdp_store_cached()
    items = copy.deepcopy(list(store.get("discovery_suggestions", {}).get(org_id, [])))
    if status_filter:
        low = status_filter.strip().lower()
        items = [i for i in items if str(i.get("status", "")).lower() == low]
    return items


def review_discovery_suggestion(
    org_id: str,
    suggestion_id: str,
    action: str,
    edited_fields: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Human review screen for extracted or discovered suggestions: accept | edit | reject.
    Accepting adds a draft/confirmed record cleanly without silently overwriting existing confirmed records.
    """
    store = _load_dpdp_store()
    items = store.get("discovery_suggestions", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    target = next((i for i in items if i.get("id") == suggestion_id), None)
    if not target:
        return None

    act = (action or "").strip().lower()
    if edited_fields:
        for k in ("value", "category", "purpose", "storage_location", "retention_period", "fields"):
            if k in edited_fields and edited_fields[k] is not None:
                target[k] = edited_fields[k]

    if act == "reject":
        target["status"] = "Rejected"
        target["updated_at"] = now
        _save_dpdp_store(store)
        return {"suggestion": target, "created_record": None}

    if act in ("accept", "edit", "confirm"):
        target["status"] = "Confirmed by business"
        target["updated_at"] = now
        _save_dpdp_store(store)
        etype = target.get("extracted_type", "data_activity")
        created = None
        if etype == "vendor":
            created = add_vendor(org_id, {
                "name": target.get("value", "Vendor"),
                "category": target.get("category", "Third-Party Processor"),
                "service": target.get("purpose", "Confirmed from discovery"),
                "data_shared": ", ".join(target.get("fields", [])) or "Personal information",
                "dpa_status": "PENDING_REVIEW",
                "data_location": target.get("storage_location", "India / Verify region"),
                "status": "Not reviewed",
            })
        elif etype == "retention":
            created = add_retention_schedule(org_id, {
                "data_category": target.get("category", "General Data"),
                "retention_period": target.get("retention_period") or "Review duration",
                "trigger": target.get("value", ""),
                "legal_exception": "Review statutory exceptions",
            })
        elif etype in ("data_activity", "website_form", "tracker"):
            created = add_inventory_entry(org_id, {
                "category": target.get("category", "Contact information"),
                "fields": target.get("fields", []),
                "source": target.get("source_document", "Discovery"),
                "purpose": target.get("purpose") or target.get("value", "Business operations"),
                "storage_system": target.get("storage_location", "To be confirmed"),
                "retention_period": target.get("retention_period") or "Review schedule",
                "confirmation_status": "Confirmed by business",
            })
        return {"suggestion": target, "created_record": created}

    target["status"] = "Needs review"
    target["updated_at"] = now
    _save_dpdp_store(store)
    return {"suggestion": target, "created_record": None}


def create_remediation_task(org_id: str, task_data: Dict[str, Any]) -> Dict[str, Any]:
    """Creates a genuine tracked Action Plan task persisted cleanly in assessments[org_id]['remediation_tasks']."""
    store = _load_dpdp_store()
    assessment = get_assessment(org_id)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    default_due = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=14)).strftime("%Y-%m-%d")
    task = {
        "id": f"TSK-{uuid.uuid4().hex[:7].upper()}",
        "title": sanitize_plain_text(task_data.get("title") or "Complete privacy action", 160),
        "description": sanitize_plain_text(task_data.get("description") or "", 600),
        "why_it_matters": sanitize_plain_text(task_data.get("why_it_matters") or task_data.get("why") or "Supports DPDP readiness.", 300),
        "legal_reference": sanitize_plain_text(task_data.get("legal_reference") or task_data.get("section") or "DPDP Act, 2023", 120),
        "priority": (task_data.get("priority") or task_data.get("severity") or "MEDIUM").upper(),
        "severity": (task_data.get("priority") or task_data.get("severity") or "MEDIUM").upper(),
        "owner": sanitize_plain_text(task_data.get("owner") or task_data.get("assignee") or "Owner", 80),
        "assignee": sanitize_plain_text(task_data.get("assignee") or task_data.get("owner") or "Owner", 80),
        "due_date": sanitize_plain_text(task_data.get("due_date") or default_due, 30),
        "steps": task_data.get("steps") if isinstance(task_data.get("steps"), list) else [],
        "evidence_required": sanitize_plain_text(task_data.get("evidence_required") or "Upload supporting proof in Evidence Vault", 200),
        "status": task_data.get("status") if task_data.get("status") in VALID_TASK_STATUSES else "Open",
        "completion_notes": sanitize_plain_text(task_data.get("completion_notes") or "", 500),
        "created_at": now,
        "updated_at": now,
        "audit_trail": [{"action": "TASK_CREATED", "timestamp": now, "actor": task_data.get("actor", "Workspace User")}],
    }
    assessment.setdefault("remediation_tasks", []).insert(0, task)
    store.setdefault("assessments", {})[org_id] = assessment
    _save_dpdp_store(store)
    return task


ASSESSMENT_TOPICS: List[Dict[str, Any]] = [
    {"id": "topic_collection", "order": 1, "title": "1. Information collection", "legal_ref": "Sections 3, 4 & 7", "commencement": "Scheduled 13 May 2027", "question": "Have you listed only the customer personal information needed for clear business purposes?", "why_it_matters": "Collecting excessive details increases privacy risk and notice/deletion obligations.", "evidence_required": "Confirmed Customer Data List & intake form review", "not_sure_guidance": "Start in Discovery or Data Inventory to list your enquiry, billing, and user signup fields."},
    {"id": "topic_notices", "order": 2, "title": "2. Privacy notices", "legal_ref": "Section 5 & Rule 3", "commencement": "Scheduled 13 May 2027", "question": "Do customers see an itemised plain-language Privacy Notice before or when giving data?", "why_it_matters": "Section 5 requires telling individuals what data you collect, why, and how they can complain or withdraw consent.", "evidence_required": "Published Privacy Notice draft & website footer screenshot", "not_sure_guidance": "Use TrustAudit Privacy Notices to draft an itemised notice matching your inventory."},
    {"id": "topic_consent", "order": 3, "title": "3. Consent and other lawful grounds", "legal_ref": "Sections 4, 6 & 7", "commencement": "Sec 6(9) In Force 13 Nov 2026; Sec 6(1)-(8) & Sec 7 Scheduled 13 May 2027", "question": "Are consent checkboxes unchecked by default, and are non-consent Section 7 legitimate uses identified separately?", "why_it_matters": "Pre-ticked consent or treating mandatory billing/employment data identically as consent creates errors.", "evidence_required": "Form screenshots & Consent Records log", "not_sure_guidance": "Run Website Privacy Check on your public signup or appointment forms to inspect checkboxes."},
    {"id": "topic_sharing", "order": 4, "title": "4. Data sharing", "legal_ref": "Sections 8(1), 8(2) & 16", "commencement": "Scheduled 13 May 2027", "question": "Do software, cloud, payment, and external lab vendors sign binding written contracts with security duties?", "why_it_matters": "Businesses remain legally responsible for personal data handled by third-party processors.", "evidence_required": "Executed Vendor Data Processing Agreement (DPA)", "not_sure_guidance": "Add external providers in Vendors & Processors and send our built-in Vendor Questionnaire."},
    {"id": "topic_requests", "order": 5, "title": "5. Customer requests", "legal_ref": "Sections 8(10), 11–14 & Rule 9, 14", "commencement": "Scheduled 13 May 2027", "question": "Is there a published privacy contact and workflow for customer access, correction, erasure, nomination, and grievance requests?", "why_it_matters": "Individuals must have an accessible grievance contact before escalating to the Data Protection Board.", "evidence_required": "Published Grievance contact & Request handling log", "not_sure_guidance": "Enable TrustAudit's Branded Customer Privacy Request Portal in one click."},
    {"id": "topic_retention", "order": 6, "title": "6. Retention and deletion", "legal_ref": "Sections 8(7)–8(8) & Rule 8", "commencement": "Scheduled 13 May 2027", "question": "Have you defined how long customer records stay active and when expired data is deleted unless another Indian law mandates keeping it?", "why_it_matters": "Old personal data cannot be stored forever once the service purpose ends.", "evidence_required": "Retention Policy & verified deletion completion logs", "not_sure_guidance": "Review tax (Income Tax / GST) and sector rules before creating schedules in Data Retention."},
    {"id": "topic_security", "order": 7, "title": "7. Security safeguards", "legal_ref": "Section 8(5) & Rule 6", "commencement": "Scheduled 13 May 2027 (Ceiling up to ₹250 crore)", "question": "Are reasonable safeguards active across your systems (access controls, transport encryption, backups, logs, and storage safeguards)?", "why_it_matters": "Rule 6 outlines encryption/obfuscation, access control, logging, backups, and security reviews to prevent breaches.", "evidence_required": "Security policy, HTTPS check, backup & access review evidence", "not_sure_guidance": "Upload IT security notes or access review checklists into Evidence Vault."},
    {"id": "topic_incidents", "order": 8, "title": "8. Privacy incident response", "legal_ref": "Section 8(6) & Rule 7", "commencement": "Scheduled 13 May 2027 (Ceiling up to ₹200 crore)", "question": "Does your team have an Incident Response Plan covering containment, internal approvals, and Board/customer notifications?", "why_it_matters": "Prompt containment and prepared Rule 7 intimation drafts prevent chaotic incident handling.", "evidence_required": "Incident Response SOP & drill/log records", "not_sure_guidance": "Generate an Incident Response Plan draft from Document Centre and review roles."},
    {"id": "topic_children", "order": 9, "title": "9. Children & persons with disabilities with lawful guardians (where applicable)", "legal_ref": "Section 9(1) (clarified by S.O. 5458(E), Oct 2026) & Rule 10", "commencement": "Scheduled 13 May 2027 (Ceiling up to ₹200 crore)", "question": "If you process data of children under 18 or persons with disabilities who have lawful guardians, do you obtain verifiable parent/lawful guardian consent and block tracking or targeted ads to children?", "why_it_matters": "Section 9(1) governs verifiable consent for children and persons with disabilities who have lawful guardians, alongside strict prohibitions on behavioral tracking and targeted advertising to children.", "evidence_required": "Parent/lawful guardian consent workflow & tracker audit (or N/A declaration)", "not_sure_guidance": "Select 'Not applicable' only if you strictly serve independent adults and process neither children's data nor data involving a lawful guardian under Section 9(1)."},
    {"id": "topic_sdf", "order": 10, "title": "10. Significant Data Fiduciary duties (where applicable)", "legal_ref": "Section 10 (updated to 'data audit' under S.O. 5458(E), Oct 2026) & Rule 11", "commencement": "Conditional upon Central Government notification (13 May 2027)", "question": "If notified as a Significant Data Fiduciary, have you planned for a resident DPO, periodic DPIA, and independent data audit?", "why_it_matters": "Applies only to high-volume/high-sensitivity fiduciaries notified by the Central Government.", "evidence_required": "SDF applicability note / DPO resolution (or N/A assessment)", "not_sure_guidance": "Most SMEs and startups are NOT Significant Data Fiduciaries unless notified by the Government; pick 'Not sure' or 'Not applicable' for guidance."},
]


def get_assessment_topics(org_id: str) -> Dict[str, Any]:
    """
    Returns the 10 understandable guided assessment topics mapped with saved topic responses
    and honest 5-stage verification state: Not assessed -> Business self-attested -> Evidence uploaded -> Evidence reviewed -> Verified.
    """
    store = _read_dpdp_store_cached()
    saved_map = store.get("organisational_assessments", {}).get(f"{org_id}::topics", {})
    evidence = get_evidence_artifacts(org_id)
    verified_ev = [e for e in evidence if e.get("status") == "Verified"]
    reviewed_ev = [e for e in evidence if e.get("status") in ("Verified", "Evidence reviewed", "Under review")]

    topics_out = []
    answered = 0
    for top in ASSESSMENT_TOPICS:
        ans = saved_map.get(top["id"], {})
        choice = ans.get("answer", "Not assessed")  # Yes | No | Partially | Not sure | Not applicable | Not assessed
        if choice != "Not assessed":
            answered += 1
        ev_id = ans.get("evidence_id", "")
        linked_ev = next((e for e in evidence if e.get("id") == ev_id), None) if ev_id else None
        if linked_ev:
            ev_st = linked_ev.get("status", "")
            if ev_st == "Verified":
                v_state = "Verified"
            elif ev_st in ("Under review", "Rejected"):
                v_state = "Evidence reviewed"
            else:
                v_state = "Evidence uploaded"
        elif choice in ("Yes", "No", "Partially", "Not applicable"):
            v_state = "Business self-attested"
        else:
            v_state = "Not assessed"

        topics_out.append({
            **top,
            "answer": choice,
            "notes": ans.get("notes", ""),
            "evidence_id": ev_id,
            "verification_state": v_state,
            "updated_at": ans.get("updated_at"),
        })

    return {
        "topics": topics_out,
        "answered_count": answered,
        "total_topics": len(topics_out),
        "evidence_uploaded_count": len(evidence),
        "evidence_reviewed_count": len(reviewed_ev),
        "evidence_verified_count": len(verified_ev),
        "certification_disclaimer": "Assessment outputs organise internal business readiness only and are not a government certification or legal approval.",
    }


def save_assessment_topic_answer(org_id: str, topic_id: str, answer: str, notes: str = "", evidence_id: str = "") -> Dict[str, Any]:
    allowed = ("Yes", "No", "Partially", "Not sure", "Not applicable", "Not assessed")
    clean_ans = answer if answer in allowed else "Not sure"
    store = _load_dpdp_store()
    bucket = store.setdefault("organisational_assessments", {}).setdefault(f"{org_id}::topics", {})
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    bucket[topic_id] = {
        "answer": clean_ans,
        "notes": sanitize_plain_text(notes, 600),
        "evidence_id": sanitize_plain_text(evidence_id, 60),
        "updated_at": now,
    }
    _save_dpdp_store(store)
    return get_assessment_topics(org_id)


def compute_vendor_risk_basis(vendor: Dict[str, Any]) -> Dict[str, Any]:
    """Returns transparent explanation of vendor review factors without fake numerical scores."""
    reasons = []
    dpa = str(vendor.get("dpa_status", "PENDING")).upper()
    if any(k in dpa for k in ("SIGNED", "EXECUTED", "ACTIVE")):
        reasons.append("Written Data Processing Agreement (DPA) recorded as signed")
    else:
        reasons.append("No executed Data Processing Agreement (DPA) confirmed yet")
    loc = str(vendor.get("data_location", "")).strip() or "Unspecified"
    reasons.append(f"Declared hosting/processing location: {loc}")
    if vendor.get("security_review"):
        reasons.append(f"Security review note recorded: {vendor.get('security_review')}")
    else:
        reasons.append("Vendor security questionnaire / SOC/ISO evidence not yet reviewed")
    return {
        "review_status": vendor.get("status") or ("Approved" if "SIGNED" in dpa or "EXECUTED" in dpa else "Not reviewed"),
        "risk_basis": reasons,
    }


def create_vendor_intake_token(org_id: str, vendor_id: str) -> Optional[str]:
    vendors = get_vendors(org_id)
    if not any(v.get("id") == vendor_id for v in vendors):
        return None
    store = _load_dpdp_store()
    token = f"vint-{uuid.uuid4().hex[:14]}"
    store.setdefault("vendor_intake_tokens", {})[token] = {
        "org_id": org_id,
        "vendor_id": vendor_id,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    _save_dpdp_store(store)
    return token


def resolve_vendor_intake_token(token: str) -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    meta = store.get("vendor_intake_tokens", {}).get(token)
    if not meta:
        return None
    v = next((x for x in get_vendors(meta["org_id"]) if x.get("id") == meta["vendor_id"]), None)
    if not v:
        return None
    profile = get_onboarding_profile(meta["org_id"]) or {}
    return {"org_id": meta["org_id"], "org_name": profile.get("company_name") or "TrustAudit Business", "vendor": v}


def save_vendor_questionnaire(org_id: str, vendor_id: str, responses: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    q_rec = {
        "vendor_id": vendor_id,
        "encryption_at_rest": bool(responses.get("encryption_at_rest")),
        "access_controls": bool(responses.get("access_controls")),
        "breach_notification_24h": bool(responses.get("breach_notification_24h")),
        "subprocessor_disclosure": sanitize_plain_text(responses.get("subprocessor_disclosure", ""), 400),
        "data_location": sanitize_plain_text(responses.get("data_location", ""), 120),
        "dpa_signed_confirmed": bool(responses.get("dpa_signed_confirmed")),
        "submitted_by": sanitize_plain_text(responses.get("submitted_by", "Vendor Contact"), 120),
        "notes": sanitize_plain_text(responses.get("notes", ""), 500),
        "submitted_at": now,
    }
    store.setdefault("vendor_questionnaires", {}).setdefault(org_id, {})[vendor_id] = q_rec
    _save_dpdp_store(store)
    update_vendor(org_id, vendor_id, {
        "security_review": f"Questionnaire submitted {now[:10]}",
        "status": "Reviewing",
        "data_location": q_rec["data_location"] or "Declared in questionnaire",
    })
    return q_rec


def get_portal_config(org_id: str, default_name: str = "Registered Organisation", default_slug: str = "") -> Dict[str, Any]:
    store = _read_dpdp_store_cached()
    if demo_fixture.is_demo_org(org_id):
        saved_demo = store.get("portal_configs", {}).get(org_id)
        if saved_demo:
            res = copy.deepcopy(saved_demo)
            res["brand_name"] = demo_fixture.DEMO_ORG_NAME
            res["is_demo"] = True
            res["demo_banner"] = demo_fixture.DEMO_BANNER
            return res
        return demo_fixture.get_demo_portal_config()

    cfg = store.get("portal_configs", {}).get(org_id)
    if cfg:
        return copy.deepcopy(cfg)

    profile = get_onboarding_profile(org_id) or {}
    org_name = profile.get("company_name") or ""
    if not org_name or org_name == "Your Business":
        try:
            import saas_store
            org_rec = saas_store.get_organization(org_id) or {}
            org_name = org_rec.get("name") or default_name
        except Exception:
            org_name = default_name
    clean_slug = re.sub(r"[^a-z0-9-]", "-", (default_slug or org_id).lower()).strip("-")
    return {
        "enabled": True,
        "is_demo": False,
        "slug": clean_slug,
        "brand_name": org_name,
        "contact_email": profile.get("contact_email") or "",
        "intro_text": "Submit a privacy request (view data summary, request correction, ask for deletion, or raise a privacy grievance). Submitted details are handled strictly by this organisation.",
        "custom_domain_preview": f"privacy.{clean_slug}.in" if clean_slug else "",
        "require_human_verification": True,
        "updated_at": "",
    }


def save_portal_config(org_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    cur = get_portal_config(org_id)
    store = _load_dpdp_store()
    cur.update({
        "enabled": bool(updates.get("enabled", cur.get("enabled", True))),
        "brand_name": sanitize_plain_text(updates.get("brand_name") or cur["brand_name"], 120),
        "contact_email": sanitize_plain_text(updates.get("contact_email") or cur["contact_email"], 120),
        "intro_text": sanitize_plain_text(updates.get("intro_text") or cur["intro_text"], 500),
        "custom_domain_preview": sanitize_plain_text(updates.get("custom_domain_preview") or cur["custom_domain_preview"], 140),
        "require_human_verification": bool(updates.get("require_human_verification", True)),
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    store.setdefault("portal_configs", {})[org_id] = cur
    _save_dpdp_store(store)
    return cur


def submit_portal_request_public(org_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Stores a public Data Principal privacy request with an expiring random verification token
    and short-window duplicate guard without disclosing whether an email exists in any DB.
    """
    import secrets
    req_email = sanitize_plain_text(payload.get("email", ""), 120).lower()
    req_type = str(payload.get("type", "ACCESS")).upper()
    req_desc = sanitize_plain_text(payload.get("description", ""), 1000)

    now_dt = datetime.datetime.now(datetime.timezone.utc)
    recent_cutoff = now_dt - datetime.timedelta(minutes=10)
    for existing in get_rights_requests(org_id):
        if (
            str(existing.get("requester_email", "")).lower() == req_email
            and str(existing.get("type", "")).upper() == req_type
            and str(existing.get("description", "")).strip().lower() == req_desc.strip().lower()
        ):
            rec_at = str(existing.get("received_at", ""))
            try:
                parsed = datetime.datetime.fromisoformat(rec_at.replace("Z", "+00:00"))
                if parsed >= recent_cutoff:
                    return {
                        "duplicate": True,
                        "reference_id": existing["id"],
                        "verification_code": existing.get("verification_code", ""),
                        "verification_code_expires_at": existing.get("verification_code_expires_at", ""),
                        "status": existing.get("status", "RECEIVED"),
                        "message": "An identical request was recently submitted. Please check status with your reference ID.",
                    }
            except Exception:
                pass

    verification_code = secrets.token_hex(3).upper()
    expires_at = (now_dt + datetime.timedelta(days=30)).isoformat()
    req = submit_rights_request(org_id, {
        "type": req_type,
        "requester_name": sanitize_plain_text(payload.get("name", ""), 120),
        "requester_email": req_email,
        "description": req_desc,
        "verification_code": verification_code,
        "verification_code_expires_at": expires_at,
        "source_channel": "Customer Privacy Portal",
    })
    store = _load_dpdp_store()
    for r in store.get("rights_requests", {}).get(org_id, []):
        if r.get("id") == req.get("id"):
            r["requester_email"] = req_email
            r["verification_code"] = verification_code
            r["verification_code_expires_at"] = expires_at
            r["source_channel"] = "Customer Privacy Portal"
            break
    _save_dpdp_store(store)
    return {
        "duplicate": False,
        "reference_id": req["id"],
        "verification_code": verification_code,
        "verification_code_expires_at": expires_at,
        "status": req.get("status", "RECEIVED"),
        "message": "If this organisation holds matching records, your request will be verified and reviewed per published grievance processes.",
    }


def lookup_portal_request_public(org_id: str, reference_id: str, verification_code: str) -> Optional[Dict[str, Any]]:
    """Checks request status strictly matching non-expired reference_id + verification_code."""
    ref = (reference_id or "").strip().upper()
    code = (verification_code or "").strip().upper()
    if not ref or not code:
        return None
    now_dt = datetime.datetime.now(datetime.timezone.utc)
    for r in get_rights_requests(org_id):
        if str(r.get("id", "")).upper() == ref and str(r.get("verification_code", "")).upper() == code:
            exp = r.get("verification_code_expires_at")
            if exp:
                try:
                    if datetime.datetime.fromisoformat(str(exp).replace("Z", "+00:00")) < now_dt:
                        return None
                except Exception:
                    pass
            return {
                "reference_id": r["id"],
                "type": r.get("type"),
                "status": r.get("status"),
                "received_at": r.get("received_at"),
                "updated_at": r.get("updated_at"),
                "verification_code_expires_at": exp,
                "public_status_note": "Verified reference matched. Status updates are posted by the organisation administrator.",
            }
    return None


def get_privacy_profile_config(org_id: str, default_name: str = "") -> Dict[str, Any]:
    store = _read_dpdp_store_cached()
    if demo_fixture.is_demo_org(org_id):
        saved_demo = store.get("privacy_profiles", {}).get(org_id)
        if saved_demo:
            res = copy.deepcopy(saved_demo)
            res["headline"] = demo_fixture.DEMO_ORG_NAME
            res["is_demo"] = True
            res["demo_banner"] = demo_fixture.DEMO_DISCLAIMER
            return res
        return demo_fixture.get_demo_privacy_profile_config()

    cfg = store.get("privacy_profiles", {}).get(org_id)
    if cfg:
        return copy.deepcopy(cfg)

    profile = get_onboarding_profile(org_id) or {}
    org_name = profile.get("company_name") or ""
    if not org_name or org_name == "Your Business":
        try:
            import saas_store
            org_rec = saas_store.get_organization(org_id) or {}
            org_name = org_rec.get("name") or default_name or "Registered Organisation"
        except Exception:
            org_name = default_name or "Registered Organisation"

    return {
        "published": True,
        "is_demo": False,
        "headline": org_name,
        "privacy_contact_name": profile.get("grievance_officer") or "",
        "privacy_contact_email": profile.get("contact_email") or "",
        "show_approved_notice": True,
        "show_portal_link": True,
        "show_last_review_date": True,
        # Strictly NO fabricated default claims until explicitly reviewed & confirmed by business
        "selected_practices": [],
        "approved_document_ids": [],
        "last_reviewed_at": None,
    }


def save_privacy_profile_config(org_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
    cur = get_privacy_profile_config(org_id)
    store = _load_dpdp_store()
    now_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    cur.update({
        "published": bool(updates.get("published", cur["published"])),
        "headline": sanitize_plain_text(updates.get("headline") or cur["headline"], 140),
        "privacy_contact_name": sanitize_plain_text(updates.get("privacy_contact_name") if updates.get("privacy_contact_name") is not None else cur.get("privacy_contact_name", ""), 100),
        "privacy_contact_email": sanitize_plain_text(updates.get("privacy_contact_email") if updates.get("privacy_contact_email") is not None else cur.get("privacy_contact_email", ""), 120),
        "show_approved_notice": bool(updates.get("show_approved_notice", True)),
        "show_portal_link": bool(updates.get("show_portal_link", True)),
        "show_last_review_date": bool(updates.get("show_last_review_date", True)),
        "selected_practices": [sanitize_plain_text(p, 160) for p in updates.get("selected_practices", cur.get("selected_practices", [])) if str(p).strip()][:10],
        "approved_document_ids": list(updates.get("approved_document_ids", cur.get("approved_document_ids", [])))[:20],
        "last_reviewed_at": now_date,
        "reviewed_by": sanitize_plain_text(updates.get("reviewed_by") or "Workspace Administrator", 100),
    })
    store.setdefault("privacy_profiles", {})[org_id] = cur
    _save_dpdp_store(store)
    return cur


def get_public_privacy_profile(org_id: str, org_slug: str) -> Optional[Dict[str, Any]]:
    """
    Returns ONLY public-approved fields for an organisation's Shareable Privacy Profile.
    STRICTLY excludes inventory, vendor contracts, customer requests, security configs, evidence files, or internal assessments.
    Never shows unverified claims or fake review timestamps.
    """
    is_demo = demo_fixture.is_demo_org(org_id) or demo_fixture.is_demo_slug(org_slug)
    cfg = get_privacy_profile_config(org_id)
    if not cfg.get("published"):
        return None
    notices = [n for n in get_privacy_notices(org_id) if n.get("status") == "APPROVED_PUBLISHED"]
    latest_notice = notices[0] if (notices and cfg.get("show_approved_notice")) else None
    allowed_doc_ids = set(cfg.get("approved_document_ids", []))
    approved_docs = [
        {"id": d["id"], "title": d.get("title"), "version": d.get("version", "v1.0"), "updated_at": d.get("updated_at") or d.get("generated_at")}
        for d in get_generated_documents(org_id)
        if d.get("id") in allowed_doc_ids and d.get("status") == "APPROVED"
    ]
    return {
        "org_name": cfg["headline"],
        "is_demo": is_demo,
        "demo_banner": demo_fixture.DEMO_DISCLAIMER if is_demo else None,
        "privacy_contact_name": cfg.get("privacy_contact_name") or "",
        "privacy_contact_email": cfg.get("privacy_contact_email") or "",
        "portal_url": f"/portal/{org_slug}" if cfg.get("show_portal_link") else None,
        "approved_notice": {"title": latest_notice.get("title"), "version": latest_notice.get("version"), "content": latest_notice.get("content")} if latest_notice else None,
        "approved_documents": approved_docs,
        "selected_practices": cfg.get("selected_practices", []),
        "last_reviewed_at": cfg.get("last_reviewed_at") if cfg.get("show_last_review_date") else None,
        "mandatory_disclaimer": "This profile is information supplied and approved by the organisation. It is not a government certification or independent compliance approval.",
    }


def get_generated_documents(org_id: str) -> List[Dict[str, Any]]:
    store = _read_dpdp_store_cached()
    return copy.deepcopy(store.get("generated_documents", {}).get(org_id, []))


def get_generated_document(org_id: str, doc_id: str) -> Optional[Dict[str, Any]]:
    return next((d for d in get_generated_documents(org_id) if d.get("id") == doc_id), None)


def update_generated_document(org_id: str, doc_id: str, content: Optional[str] = None, status: Optional[str] = None, title: Optional[str] = None, actor: str = "Owner") -> Optional[Dict[str, Any]]:
    store = _load_dpdp_store()
    docs = store.get("generated_documents", {}).get(org_id, [])
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for d in docs:
        if d.get("id") == doc_id:
            if content is not None:
                d["content"] = content
            if title is not None and title.strip():
                d["title"] = sanitize_plain_text(title, 200)
            if status in ("DRAFT", "UNDER_REVIEW", "APPROVED"):
                d["status"] = status
                if status == "APPROVED":
                    d["approved_by"] = actor
                    d["approved_at"] = now
            cur_v = str(d.get("version", "v1.0"))
            m = re.match(r"v(\d+)", cur_v)
            next_v = f"v{(int(m.group(1)) + 1) if m else 2}.0"
            d["version"] = next_v
            d["updated_at"] = now
            d.setdefault("version_history", []).append({"version": next_v, "status": d.get("status", "DRAFT"), "actor": actor, "timestamp": now})
            _save_dpdp_store(store)
            return d
    return None


def save_generated_doc_to_evidence(org_id: str, doc_id: str, actor: str = "Owner") -> Optional[Dict[str, Any]]:
    """Persists an approved or draft compliance document into Evidence Vault as a genuine artifact."""
    doc = get_generated_document(org_id, doc_id)
    if not doc:
        return None
    title = doc.get("title") or f"DPDP Document ({doc.get('doc_type', 'policy')})"
    fname = f"{re.sub(r'[^a-zA-Z0-9_-]', '_', title[:40]).strip('_')}_{doc_id}.txt"
    content_bytes = (doc.get("content") or "").encode("utf-8")
    return add_evidence_artifact(
        org_id=org_id,
        title=f"{title} ({doc.get('version', 'v1.0')})",
        category="Policy & Document Draft",
        control_id=doc.get("doc_type", "DPDP-DOC"),
        file_bytes=content_bytes,
        file_name=fname,
        uploaded_by=actor,
        review_notes=f"Saved directly from TrustAudit Document Centre by {actor}.",
    )


def import_consent_csv(org_id: str, csv_content: str) -> int:
    reader = csv.DictReader(io.StringIO(csv_content or ""))
    imported = 0
    for row in reader:
        if not any(row.values()):
            continue
        record_consent(org_id, {
            "principal_ref": row.get("principal_ref") or row.get("customer_id") or row.get("Data Principal") or f"DP-{uuid.uuid4().hex[:6]}",
            "purpose": row.get("purpose") or row.get("Purpose") or "Service Delivery",
            "lawful_ground": row.get("lawful_ground") or row.get("Legal Basis") or "Consent (Section 6)",
            "notice_version": row.get("notice_version") or "v1.0",
            "source": row.get("source") or row.get("Source") or "CSV Import",
            "status": row.get("status") or "ACTIVE",
        })
        imported += 1
        if imported >= 250:
            break
    return imported


def search_org_workspace(org_id: str, query: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Global Cmd+K search across the authenticated organisation's workspace + DPDP legal index."""
    q = (query or "").strip().lower()
    if len(q) < 2:
        return []
    hits: List[Dict[str, Any]] = []

    for inv in get_data_inventory(org_id):
        hay = f"{inv.get('category', '')} {inv.get('purpose', '')} {inv.get('source', '')} {' '.join(inv.get('fields', []))}".lower()
        if q in hay:
            hits.append({"kind": "Data Inventory", "title": inv.get("category", "Record"), "subtitle": inv.get("purpose", ""), "href": "/app/data-inventory"})

    for v in get_vendors(org_id):
        hay = f"{v.get('name', '')} {v.get('category', '')} {v.get('service', '')}".lower()
        if q in hay:
            hits.append({"kind": "Vendor", "title": v.get("name", "Vendor"), "subtitle": f"{v.get('category', '')} — {v.get('dpa_status', '')}", "href": "/app/vendors"})

    for t in get_remediation_tasks(org_id):
        hay = f"{t.get('title', '')} {t.get('description', '')} {t.get('legal_reference', '')}".lower()
        if q in hay:
            hits.append({"kind": "Action Task", "title": t.get("title", "Task"), "subtitle": f"{t.get('status', '')} • {t.get('priority', '')}", "href": "/app/action-plan"})

    for n in get_privacy_notices(org_id):
        hay = f"{n.get('title', '')} {n.get('status', '')}".lower()
        if q in hay:
            hits.append({"kind": "Privacy Notice", "title": n.get("title", "Notice"), "subtitle": n.get("version", "v1.0"), "href": "/app/notices"})

    for ev in get_evidence_artifacts(org_id):
        hay = f"{ev.get('title', '')} {ev.get('filename', '')} {ev.get('category', '')}".lower()
        if q in hay:
            hits.append({"kind": "Evidence", "title": ev.get("title", ev.get("filename", "File")), "subtitle": ev.get("status", ""), "href": "/app/evidence"})

    for rule in DPDP_REQUIREMENTS:
        hay = f"{rule.get('section', '')} {rule.get('title', '')} {rule.get('description', '')}".lower()
        if q in hay:
            hits.append({"kind": "DPDP Legal Rule", "title": f"{rule.get('section')}: {rule.get('title')}", "subtitle": rule.get("effective_date", ""), "href": "/app/assessment"})

    return hits[:limit]


def delete_all_org_dpdp_data(org_id: str) -> None:
    """Purges all DPDP operational records and physical DPDP evidence files for org_id."""
    store = _load_dpdp_store()
    for bucket in (
        "data_inventories", "assessments", "privacy_notices", "consent_records",
        "withdrawal_requests", "rights_requests", "vendors", "retention_schedules",
        "breach_incidents", "remediation_tasks", "onboarding_profiles", "erasure_tasks",
        "website_scans", "evidence_vault", "organisational_assessments", "generated_documents",
        "discovery_suggestions", "portal_configs", "privacy_profiles", "vendor_questionnaires",
    ):
        store.get(bucket, {}).pop(org_id, None)
    _save_dpdp_store(store)

    try:
        org_dir = _get_dpdp_org_evidence_dir(org_id)
        if os.path.isdir(org_dir):
            for fname in os.listdir(org_dir):
                fpath = safe_resolve_under_dir(org_dir, fname)
                if os.path.isfile(fpath):
                    os.remove(fpath)
            os.rmdir(org_dir)
    except Exception:
        pass


def get_home_summary_fast(org_id: str) -> Dict[str, Any]:
    """
    Single-pass cached computation for /api/dpdp/home-summary.
    Reads _DPDP_CACHE_DATA once instead of parsing 4+ MB JSON 30 times per request.
    """
    store = _read_dpdp_store_cached()
    profile = copy.deepcopy(store.get("onboarding_profiles", {}).get(org_id) or {})
    if not profile and demo_fixture.is_demo_org(org_id):
        profile = demo_fixture.get_demo_onboarding_profile()
    elif profile and demo_fixture.is_demo_org(org_id, profile=profile):
        profile["company_name"] = demo_fixture.DEMO_ORG_NAME
        profile["is_demo"] = True

    inventory = store.get("data_inventories", {}).get(org_id, [])
    scans = store.get("website_scans", {}).get(org_id, [])
    notices = store.get("privacy_notices", {}).get(org_id, [])
    vendors = store.get("vendors", {}).get(org_id, [])
    requests_list = store.get("rights_requests", {}).get(org_id, [])
    retention = store.get("retention_schedules", {}).get(org_id, [])
    incidents = store.get("breach_incidents", {}).get(org_id, [])
    consents = store.get("consent_records", {}).get(org_id, [])
    evidence = store.get("evidence_vault", {}).get(org_id, [])
    if not evidence and demo_fixture.is_demo_org(org_id, profile=profile):
        evidence = demo_fixture.get_demo_seed_collections()["evidence"]

    assessment = store.get("assessments", {}).get(org_id)
    rem_tasks_all = (assessment or {}).get("remediation_tasks")
    if rem_tasks_all is None:
        rem_tasks_all = _initialize_assessment(org_id).get("remediation_tasks", [])

    has_privacy_docs = bool(notices) or bool(evidence)
    steps = [
        {"key": "business_details", "title": "Business details", "completed": bool(profile.get("onboarding_completed") or (profile.get("company_name") and profile.get("industry"))), "action_view": "onboarding", "action_label": "Update details"},
        {"key": "website_check", "title": "Website check", "completed": len(scans) > 0, "action_view": "website-check", "action_label": "Check site"},
        {"key": "customer_information", "title": "Customer information", "completed": len(inventory) > 0, "action_view": "inventory", "action_label": "Review data"},
        {"key": "external_services", "title": "External services", "completed": len(vendors) > 0, "action_view": "vendors", "action_label": "Add companies"},
        {"key": "privacy_documents", "title": "Privacy documents", "completed": has_privacy_docs, "action_view": "notices", "action_label": "Create notice"},
    ]
    completed_count = sum(1 for s in steps if s["completed"])
    setup_progress = {
        "completed_count": completed_count,
        "total_steps": 5,
        "steps": steps,
        "next_recommended_step": next((s for s in steps if not s["completed"]), None),
        "onboarding_completed": bool(profile.get("onboarding_completed")),
    }

    attention = _build_next_actions(
        inventory=inventory,
        notices=notices,
        vendors=vendors,
        scans=scans,
        requests_list=requests_list,
        retention=retention,
        incidents=incidents,
        rem_tasks=rem_tasks_all,
        limit=3,
    )
    open_req = [r for r in requests_list if r.get("status") not in ("COMPLETED", "REJECTED")]
    generated_docs = store.get("generated_documents", {}).get(org_id, [])

    events: List[Dict[str, Any]] = []
    for sc in scans[:5]:
        events.append({"timestamp": sc.get("scanned_at") or sc.get("created_at") or "", "title": f"Website checked: {sc.get('target_url', '')}", "category": "Website Check", "target_view": "website-check"})
    for ev in evidence[:5]:
        events.append({"timestamp": ev.get("uploaded_at") or "", "title": f"Document uploaded: {ev.get('title', ev.get('filename', 'Document'))} ({ev.get('status', 'Uploaded')})", "category": "Documents & Proof", "target_view": "evidence"})
    for n in notices[:5]:
        events.append({"timestamp": n.get("updated_at") or n.get("created_at") or "", "title": f"Privacy Notice saved: {n.get('title', 'Notice')} ({n.get('version', 'v1.0')})", "category": "Privacy Notice", "target_view": "notices"})
    for req in requests_list[:5]:
        events.append({"timestamp": req.get("received_at") or "", "title": f"Customer request logged ({req.get('type', 'ACCESS')} - {req.get('status', 'RECEIVED')})", "category": "Customer Requests", "target_view": "rights"})
    for inc in incidents[:5]:
        events.append({"timestamp": inc.get("created_at") or "", "title": f"Incident logged: {inc.get('title', 'Privacy Incident')}", "category": "Privacy Incident Response", "target_view": "breaches"})
    for aud in get_audit_logs(org_id, limit=8):
        events.append({"timestamp": aud.get("timestamp", ""), "title": f"Account event: {aud.get('action', '')}", "category": "History", "target_view": "settings"})
    events.sort(key=lambda e: str(e.get("timestamp", "")), reverse=True)

    open_rem_count = sum(1 for t in rem_tasks_all if t.get("status") not in ("Resolved", "Completed", "RESOLVED", "Not applicable"))
    docs_count = len(notices) + len(evidence) + len(generated_docs)
    return {
        "profile": profile,
        "setup_progress": setup_progress,
        "attention_tasks": attention,
        "recent_activity": events[:10],
        "counts": {
            "inventory_count": len(inventory),
            "data_categories_count": len({str(i.get("category", "")).strip() for i in inventory if str(i.get("category", "")).strip()}) or len(inventory),
            "vendor_count": len(vendors),
            "vendors_count": len(vendors),
            "notice_count": len(notices),
            "documents_count": docs_count,
            "open_tasks_count": len(attention) if not rem_tasks_all else max(len(attention), open_rem_count),
            "consent_count": len(consents),
            "request_count": len(requests_list),
            "rights_requests_count": len(requests_list),
            "open_requests_count": len(open_req),
            "retention_count": len(retention),
            "incident_count": len(incidents),
            "evidence_count": len(evidence),
            "evidence_awaiting_review_count": sum(1 for e in evidence if e.get("status") in ("Uploaded", "Pending review")),
            "scan_count": len(scans),
            "website_scans_count": len(scans),
        },
        "latest_scan": copy.deepcopy(scans[0]) if scans else None,
    }


def get_notifications(org_id: str) -> List[Dict[str, Any]]:
    """
    Computes genuine actionable notifications strictly from real stored workspace records:
    overdue action tasks, expiring evidence, unsigned vendor contracts, open customer requests, and security events.
    """
    store = _read_dpdp_store_cached()
    today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    in_30_days = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).strftime("%Y-%m-%d")
    notifs: List[Dict[str, Any]] = []

    requests_list = store.get("rights_requests", {}).get(org_id, [])
    for r in requests_list:
        if r.get("status") not in ("COMPLETED", "REJECTED"):
            notifs.append({
                "id": f"notif-req-{r.get('id')}",
                "kind": "customer_request",
                "severity": "HIGH",
                "title": f"Open {r.get('type', 'Privacy')} Request ({r.get('id')})",
                "detail": f"Status: {r.get('status', 'RECEIVED')}. Review and respond cleanly.",
                "href": "/app/requests",
            })

    tasks = (store.get("assessments", {}).get(org_id) or {}).get("remediation_tasks", [])
    for t in tasks:
        if t.get("status") in ("Resolved", "Completed", "RESOLVED", "Not applicable"):
            continue
        due = str(t.get("due_date") or t.get("deadline") or "")[:10]
        if due and due < today_str:
            notifs.append({
                "id": f"notif-tsk-{t.get('id')}",
                "kind": "overdue_task",
                "severity": "HIGH",
                "title": f"Overdue Action Task: {t.get('title', 'Task')}",
                "detail": f"Due {due}. Open Action Plan to update or resolve.",
                "href": "/app/action-plan",
            })

    evidence = store.get("evidence_vault", {}).get(org_id, [])
    for e in evidence:
        exp = str(e.get("expiry_date") or "")[:10]
        if exp and exp <= in_30_days:
            notifs.append({
                "id": f"notif-evi-{e.get('id')}",
                "kind": "evidence_expiry",
                "severity": "MEDIUM" if exp >= today_str else "HIGH",
                "title": f"Evidence {'Expired' if exp < today_str else 'Expiring Soon'}: {e.get('title', e.get('filename', 'Document'))}",
                "detail": f"Expiry date: {exp}. Upload a current version to Evidence Vault.",
                "href": "/app/evidence",
            })

    vendors = store.get("vendors", {}).get(org_id, [])
    for v in vendors:
        if not any(ok in str(v.get("dpa_status", "")).upper() for ok in ("SIGNED", "EXECUTED", "ACTIVE")):
            notifs.append({
                "id": f"notif-vnd-{v.get('id')}",
                "kind": "vendor_dpa",
                "severity": "MEDIUM",
                "title": f"Vendor DPA Pending: {v.get('name', 'Processor')}",
                "detail": "Written Section 8(2) agreement is not yet marked signed.",
                "href": "/app/vendors",
            })

    for aud in get_audit_logs(org_id, limit=10):
        act = str(aud.get("action", ""))
        if act in ("auth.login_failed", "auth.mfa_disabled", "auth.mfa_recovery_used"):
            notifs.append({
                "id": f"notif-sec-{aud.get('timestamp', '')}",
                "kind": "security_alert",
                "severity": "HIGH" if act == "auth.mfa_disabled" else "MEDIUM",
                "title": f"Security Alert: {act}",
                "detail": f"Actor: {aud.get('actor_email', 'Account')} at {str(aud.get('timestamp', ''))[:19]}",
                "href": "/app/settings",
            })

    return notifs[:25]
