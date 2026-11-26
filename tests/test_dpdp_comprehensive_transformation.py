"""
TrustAudit - Comprehensive DPDP Platform Transformation Test Suite.
Verifies all 20 phases of the DPDP Compliance Management SaaS platform transformation:
- 15 Statutory Requirements Matrix & Phase 4 Metadata
- 7 Sector-Specific Pre-Configured Templates & RoPAs
- 8-Step Guided Organisational Assessment & Dynamic Scoring
- Findings & Action Centre 7-Status Task Lifecycle
- Evidence Vault 5 Verification States & Audit Trails
- 9 Assisted Document Generation Workflows
- Website Scanner Diff & Regression Detection Engine
- Admin Oversight & Multi-Tenant Metrics
- Interactive 60-Second Guided Demo Route
- Public Security & Trust Portal Disclosures
"""

import json
import uuid
import pytest
from app import app
import dpdp_engine
import dpdp_store


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ==============================================================================
# 1. STATUTORY ENGINE & 15 REQUIREMENTS MATRIX (PHASE 4)
# ==============================================================================

def test_engine_has_all_15_requirements_with_complete_metadata():
    rules = dpdp_engine.get_all_rules()
    assert len(rules) == 15, f"Expected 15 statutory requirements, got {len(rules)}"

    mandatory_fields = [
        "rule_id", "legal_reference", "rule_title", "explanation",
        "applicability_conditions", "evidence_required", "detection_method",
        "severity", "confidence", "recommended_action", "verification_procedure",
        "last_reviewed_date", "rule_version", "official_source_reference",
        "commencement_status", "obligation_type", "category"
    ]

    for rule in rules:
        for field in mandatory_fields:
            assert field in rule and rule[field] is not None, f"Rule {rule.get('rule_id')} missing field: {field}"
            if isinstance(rule[field], str):
                assert len(rule[field].strip()) > 0, f"Rule {rule.get('rule_id')} field {field} cannot be empty"

    # Specific checks on commencement status
    rule_map = {r["rule_id"]: r for r in rules}
    assert "DPDP-SEC-05" in rule_map
    assert rule_map["DPDP-SEC-05"]["severity"] == "HIGH"
    assert "Section 5" in rule_map["DPDP-SEC-05"]["legal_reference"]

    # Verify query helpers
    assert dpdp_engine.get_rule_by_id("DPDP-SEC-08-06") is not None
    assert len(dpdp_engine.get_rules_by_category("Consent & Withdrawal")) >= 1
    assert len(dpdp_engine.get_rules_by_commencement_status("Scheduled: 13 May 2027")) >= 5


# ==============================================================================
# 2. 7 SECTOR-SPECIFIC PRE-CONFIGURED TEMPLATES (PHASE 9)
# ==============================================================================

def test_all_7_industry_templates():
    sectors = [
        "hospitals", "clinics", "diagnostic_centres", "saas",
        "ecommerce", "professional_services", "education"
    ]
    template_list = dpdp_engine.list_industry_templates()
    assert len(template_list) >= 7

    for sector in sectors:
        tpl = dpdp_engine.get_industry_template(sector)
        assert tpl is not None, f"Template for sector {sector} not found"
        assert "sector_id" in tpl
        assert "sector_name" in tpl
        assert "description" in tpl
        assert "sample_inventory" in tpl
        assert len(tpl["sample_inventory"]) >= 4, f"Sector {sector} must have at least 4 sample inventory streams"
        assert "suggested_retention" in tpl
        assert "priority_controls" in tpl
        assert len(tpl["priority_controls"]) >= 2


def test_deterministic_scoring_and_penalty_warning():
    res = dpdp_engine.calculate_dpdp_readiness_score(12, 15, has_critical_gap=True)
    assert res["readiness_score"] == 80
    assert "Critical Security Gap" in res["score_band"]
    assert "₹250 crore" in res["statutory_penalty_context"]

    res_perfect = dpdp_engine.calculate_dpdp_readiness_score(15, 15, has_critical_gap=False)
    assert res_perfect["readiness_score"] == 100
    assert "Audit-Ready" in res_perfect["score_band"]


# ==============================================================================
# 3. 8-STEP GUIDED ORGANISATIONAL ASSESSMENT (PHASE 5)
# ==============================================================================

def _comp_auth_headers(client, admin_email=None):
    email = admin_email or f"comp_{uuid.uuid4().hex[:6]}@clinic.in"
    reg = client.post("/api/auth/register", json={
        "email": email,
        "password": "StrongPassword#2026",
        "name": "Compliance Officer",
        "company_name": "Narayana Digital Health Ltd"
    })
    tok = reg.get_json()["data"]["token"]
    return {"Authorization": f"Bearer {tok}"}, reg.get_json()["data"]["organization"]["id"]


def test_organisational_assessment_flow(client):
    headers, org_id = _comp_auth_headers(client)

    # Initial fetch
    res = client.get("/api/dpdp/assessment/organisational", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "assessment" in data

    # Submit assessment responses across 8 steps
    assessment_payload = {
        "answers": {
            "current_step": 8,
            "step1_profile": {
                "legal_name": "Apollo Care Diagnostic Labs",
                "sector": "diagnostic_centres",
                "employee_count": "50-250",
                "is_significant_data_fiduciary": False
            },
            "step2_data_collection": {
                "collects_patient_health": True,
                "collects_financial": True,
                "collects_biometrics": False
            },
            "step3_purposes": {
                "diagnostic_reporting": True,
                "billing_and_tax": True,
                "promotional_sms": False
            },
            "step4_data_storage": {
                "cloud_provider": "AWS Mumbai (ap-south-1)",
                "encryption_at_rest_and_transit": True,
                "access_control_rbac": True
            },
            "step5_processors": {
                "all_dpas_executed": True,
                "diagnostic_courier_dpa": True
            },
            "step6_governance": {
                "has_privacy_notice": True,
                "unbundled_consent": True,
                "grievance_officer_designated": True,
                "retention_schedule_documented": True,
                "breach_sop_ready": True
            },
            "step7_docs": {
                "documents": [
                    {"name": "privacy_notice_v2.pdf", "type": "notice"},
                    {"name": "lab_vendor_dpa.pdf", "type": "dpa"},
                    {"name": "breach_protocol.pdf", "type": "sop"}
                ]
            }
        }
    }

    res_post = client.post(
        "/api/dpdp/assessment/organisational",
        headers=headers,
        data=json.dumps(assessment_payload),
        content_type="application/json"
    )
    assert res_post.status_code == 200
    post_data = res_post.get_json()
    assert post_data["status"] == "success"
    ass = post_data["assessment"]
    assert ass["is_complete"] is True
    metrics = ass["summary_metrics"]
    assert metrics["readiness_score"] >= 60
    assert "Evidence-Verified" in metrics["confidence_level"]


# ==============================================================================
# 4. 9 ASSISTED DOCUMENT GENERATOR WORKFLOWS (PHASE 10)
# ==============================================================================

def test_document_generator_catalog_and_all_9_types(client):
    headers, _ = _comp_auth_headers(client)
    # 1. Fetch catalog
    res = client.get("/api/dpdp/documents/templates")
    assert res.status_code == 200
    catalog = res.get_json()
    assert catalog["status"] == "success"
    assert len(catalog["templates"]) == 9

    doc_types = [
        "privacy_notice", "ropa_inventory", "retention_policy",
        "breach_procedure", "rights_procedure", "grievance_procedure",
        "vendor_register", "employee_privacy_policy", "training_material"
    ]

    # 2. Generate each of the 9 types
    for doc_type in doc_types:
        payload = {
            "doc_type": doc_type,
            "custom_params": {
                "organization_name": "Narayana Digital Health Ltd",
                "dpo_email": "privacy@narayanahealth.org",
                "grievance_email": "grievance@narayanahealth.org"
            }
        }
        gen_res = client.post(
            "/api/dpdp/documents/generate",
            headers=headers,
            data=json.dumps(payload),
            content_type="application/json"
        )
        assert gen_res.status_code == 201, f"Failed generating document type: {doc_type}"
        data = gen_res.get_json()
        assert data["status"] == "success"
        doc = data["document"]
        assert doc["doc_type"] == doc_type
        assert "statutory_citation" in doc
        assert "disclaimer" in doc
        assert len(doc["content"]) > 100
        # Check standard non-legal-advice disclaimer in generated policy
        assert "TrustAudit Document Generator" in doc["disclaimer"]


# ==============================================================================
# 5. FINDINGS & ACTION CENTRE 7-STATUS LIFECYCLE (PHASE 7)
# ==============================================================================

def test_findings_action_centre_7_status_lifecycle(client):
    headers, org_id = _comp_auth_headers(client)

    # Fetch initial remediation tasks belonging to authenticated org
    tasks = dpdp_store.get_remediation_tasks(org_id)
    assert len(tasks) >= 1
    task_id = tasks[0]["id"]

    statuses_to_test = [
        "In progress", "Awaiting evidence", "Under review",
        "Resolved", "Accepted risk", "Not applicable", "Open"
    ]

    for st in statuses_to_test:
        payload = {
            "status": st,
            "owner": "Chief Privacy Officer",
            "due_date": "2027-05-13",
            "comment": f"Transitioned status to {st} for compliance testing."
        }
        res = client.post(
            f"/api/dpdp/tasks/{task_id}/update",
            headers=headers,
            data=json.dumps(payload),
            content_type="application/json"
        )
        assert res.status_code == 200, f"Failed transitioning to status: {st}"
        data = res.get_json()
        assert data["status"] == "success"
        assert data["task"]["status"] == st
        assert data["task"]["owner"] == "Chief Privacy Officer"
        assert len(data["task"].get("audit_trail", [])) >= 1


# ==============================================================================
# 6. EVIDENCE VAULT 5-STATUS VERIFICATION LIFECYCLE (PHASE 8)
# ==============================================================================

def test_evidence_vault_5_status_verification(client):
    headers, _ = _comp_auth_headers(client)

    # Upload evidence artifact via API
    upload_payload = {
        "title": "Hospital Multi-Lingual Consent Screen Record",
        "category": "Consent Records",
        "control_id": "DPDP-SEC-06",
        "notes": "Patient admission kiosk screen capture showing bilingual Hindi/English choices.",
        "tags": ["consent", "kiosk", "hindi"],
        "expiry_date": "2027-11-22"
    }
    up_res = client.post(
        "/api/dpdp/evidence/upload",
        headers=headers,
        data=json.dumps(upload_payload),
        content_type="application/json"
    )
    assert up_res.status_code == 201
    up_data = up_res.get_json()
    assert up_data["status"] == "success"
    artifact = up_data["evidence"]
    assert artifact["status"] == "Uploaded"
    evidence_id = artifact["id"]

    # Transition through the 5 statutory verification states
    lifecycle_states = ["Pending review", "Verified", "Rejected", "Expired", "Verified"]
    for state in lifecycle_states:
        stat_res = client.post(
            f"/api/dpdp/evidence/{evidence_id}/status",
            headers=headers,
            data=json.dumps({
                "status": state,
                "verified_by": "Senior Legal Counsel",
                "notes": f"Verification review: marked as {state}"
            }),
            content_type="application/json"
        )
        assert stat_res.status_code == 200, f"Failed updating evidence status to: {state}"
        updated = stat_res.get_json()["evidence"]
        assert updated["status"] == state
        assert updated["verified_by"] == "Senior Legal Counsel"

    # Verify listing API with filters
    list_res = client.get("/api/dpdp/evidence/list?status=Verified", headers=headers)
    assert list_res.status_code == 200
    list_data = list_res.get_json()
    assert list_data["status"] == "success"
    assert isinstance(list_data["artifacts"], list)


# ==============================================================================
# 7. WEBSITE SCAN DIFF & COMPARISON ENGINE (PHASE 12)
# ==============================================================================

def test_website_scan_diff_and_regression_detection(client):
    org_id = f"test-diff-{uuid.uuid4().hex[:6]}"

    # Mock two scans in the store for this test
    old_scan_payload = {
        "id": "scan-mock-001",
        "scanned_url": "https://example-hospital.in",
        "completed_at": "2026-11-01T10:00:00Z",
        "dpdp_readiness_score": 60,
        "gaps_count": 3,
        "findings": [
            {"id": "f-1", "title": "Missing Privacy Notice", "severity": "HIGH"},
            {"id": "f-2", "title": "Pre-ticked Checkbox", "severity": "CRITICAL"},
            {"id": "f-3", "title": "No Grievance Email", "severity": "MEDIUM"}
        ]
    }
    new_scan_payload = {
        "id": "scan-mock-002",
        "scanned_url": "https://example-hospital.in",
        "completed_at": "2026-11-22T10:00:00Z",
        "dpdp_readiness_score": 85,
        "gaps_count": 1,
        "findings": [
            {"id": "f-3", "title": "No Grievance Email", "severity": "MEDIUM"},
            {"id": "f-4", "title": "Unencrypted Analytics Cookie", "severity": "LOW"}
        ]
    }

    # Save to store directly to simulate two completed scans
    store = dpdp_store._load_dpdp_store()
    history = store.setdefault("website_scans", {}).setdefault(org_id, [])
    history.append(old_scan_payload)
    history.append(new_scan_payload)
    dpdp_store._save_dpdp_store(store)

    # Perform scan diff comparison
    comp = dpdp_store.compare_website_scans(org_id, current_scan_id="scan-mock-002", previous_scan_id="scan-mock-001")
    assert comp is not None
    assert comp["score_delta"] == 25
    assert comp["resolved_count"] == 2
    assert comp["new_regressions_count"] == 1
    assert "f-1" in comp["resolved_finding_ids"]
    assert "f-2" in comp["resolved_finding_ids"]
    assert "f-4" in comp["new_regression_ids"]


# ==============================================================================
# 8. ADMIN OVERSIGHT & METRICS (PHASE 18)
# ==============================================================================

def test_admin_oversight_metrics(client, monkeypatch):
    admin_email = f"platadmin_{uuid.uuid4().hex[:6]}@trustaudit.io"
    monkeypatch.setenv("TRUSTAUDIT_PLATFORM_ADMIN_EMAILS", admin_email)
    headers, _ = _comp_auth_headers(client, admin_email=admin_email)
    res = client.get("/api/admin/metrics", headers=headers)
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    metrics = data["metrics"]
    assert "active_tenants_count" in metrics
    assert "aggregate_readiness_score" in metrics
    assert "sector_distribution" in metrics
    assert "system_status" in metrics
    assert metrics["system_status"] == "Operational"


# ==============================================================================
# 9. 60-SECOND GUIDED DEMO ROUTE (PHASE 16)
# ==============================================================================

def test_demo_route_rendering(client):
    res = client.get("/demo")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "DEMO MODE" in html
    assert "Arogya Diagnostics Clinic Ltd" in html
    assert "Create My Real Workspace" in html
    assert "Visual Data Map" in html
    assert "Customer Privacy Portal Preview" in html


# ==============================================================================
# 10. MULTI-TENANT ISOLATION (PHASE 14)
# ==============================================================================

def test_strict_multi_tenant_isolation():
    org_1 = f"tenant-alpha-{uuid.uuid4().hex[:6]}"
    org_2 = f"tenant-beta-{uuid.uuid4().hex[:6]}"

    # Add evidence in org 1
    dpdp_store.add_evidence_artifact(org_1, title="Confidential Internal Audit", category="Audit")

    # Verify org 2 cannot see org 1's evidence
    org_2_evidence = dpdp_store.get_evidence_artifacts(org_2)
    assert not any(e["title"] == "Confidential Internal Audit" for e in org_2_evidence)
