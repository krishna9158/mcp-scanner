"""
TrustAudit — DPDP Operations & Legal Compliance Platform Test Suite
===================================================================
Verifies all capabilities of the DPDP Compliance & Data Operations Platform:
1. Real Org unassessed empty states vs Demo mode
2. Statutory Penalty Engine (Schedule Items 1–6 ceilings, no blanket ₹50 cr)
3. Phased Commencement Tracker (Nov 2025, Nov 2026, May 2027 enforceability)
4. AI DPDP Assistant (RAG grounding, tenant awareness, statutory citations)
5. Dynamic multi-dimensional readiness scoring (enforceable vs forward-looking)
6. Data Flow Map & Schema Discovery heuristic classifier
7. Vendor & Processor Management (6 review states, DPA risk explanation, CRUD)
8. Retention & Erasure Management (Rule 8 schedules, erasure task proof lifecycle)
9. Data Principal Rights Management (identity verification & resolution)
10. Platform Admin Oversight & Metrics API
11. Landing Page 16 required sections & exact hero text
"""

import uuid
import pytest
from app import app
import dpdp_store
import dpdp_penalties
import dpdp_commencement
import ai_dpdp_assistant
import data_discovery


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestDPOperationsPlatform:

    # --------------------------------------------------------------------------
    # 1. Real Org Unassessed Empty State vs Demo Mode
    # --------------------------------------------------------------------------
    def test_real_org_starts_unassessed(self):
        real_org_id = f"clinic-{uuid.uuid4().hex[:8]}"
        assessment = dpdp_store.get_assessment(real_org_id)
        
        # Real org must start with 0% readiness and is_demo=False
        assert assessment["readiness_score"] == 0
        assert assessment["is_demo"] is False
        assert "Unassessed" in assessment["readiness_label"]
        assert assessment["controls_implemented"] == 0
        assert assessment["controls_total"] >= 10
        assert len(assessment["gaps"]) == assessment["controls_total"]

        # Real org must NOT have auto-seeded fake evidence
        evidence = dpdp_store.get_evidence_artifacts(real_org_id)
        assert len(evidence) == 0

        # Real org data inventory must be empty initially
        inventory = dpdp_store.get_data_inventory(real_org_id)
        assert len(inventory) == 0

    def test_demo_mode_provides_sample_data(self):
        demo_assessment = dpdp_store.get_assessment("demo")
        assert demo_assessment["is_demo"] is True
        assert demo_assessment["readiness_score"] > 0

        # Demo org has realistic pre-seeded sample evidence
        demo_evidence = dpdp_store.get_evidence_artifacts("demo")
        assert len(demo_evidence) >= 1
        assert any("notice" in e["title"].lower() or "dpa" in e["title"].lower() for e in demo_evidence)

    # --------------------------------------------------------------------------
    # 2. Central Statutory Penalty Registry (Schedule to DPDP Act 2023)
    # --------------------------------------------------------------------------
    def test_penalty_schedule_exact_ceilings(self):
        # Schedule Item 1: Reasonable Security Safeguards (Sec 8(5)) -> Up to ₹250 crore
        p1 = dpdp_penalties.map_statutory_penalty("Section 8(5)")
        assert p1["schedule_item"] == 1
        assert p1["max_penalty_text"] == "Up to ₹250 crore"
        assert p1["max_penalty_inr"] == 2500000000
        assert "statutory_disclaimer" in p1

        # Schedule Item 2: Breach Notification (Sec 8(6)) -> Up to ₹200 crore
        p2 = dpdp_penalties.map_statutory_penalty("Section 8(6)")
        assert p2["schedule_item"] == 2
        assert p2["max_penalty_text"] == "Up to ₹200 crore"
        assert p2["max_penalty_inr"] == 2000000000

        # Schedule Item 3: Children's Personal Data (Sec 9) -> Up to ₹200 crore
        p3 = dpdp_penalties.map_statutory_penalty("Section 9")
        assert p3["schedule_item"] == 3
        assert p3["max_penalty_text"] == "Up to ₹200 crore"
        assert p3["max_penalty_inr"] == 2000000000

        # Schedule Item 4: Significant Data Fiduciaries (Sec 10) -> Up to ₹150 crore
        p4 = dpdp_penalties.map_statutory_penalty("Section 10")
        assert p4["schedule_item"] == 4
        assert p4["max_penalty_text"] == "Up to ₹150 crore"
        assert p4["max_penalty_inr"] == 1500000000

        # Schedule Item 5: Data Principal Duties (Sec 15) -> Up to ₹10,000
        p5 = dpdp_penalties.map_statutory_penalty("Section 15")
        assert p5["schedule_item"] == 5
        assert p5["max_penalty_text"] == "Up to ₹10,000"
        assert p5["max_penalty_inr"] == 10000

        # Schedule Item 6: General contraventions (Sec 5, 6, 8(2), 8(7), 11-14) -> Up to ₹50 crore
        p6_notice = dpdp_penalties.map_statutory_penalty("Section 5")
        assert p6_notice["schedule_item"] == 6
        assert p6_notice["max_penalty_text"] == "Up to ₹50 crore"

        p6_consent = dpdp_penalties.map_statutory_penalty("Section 6")
        assert p6_consent["schedule_item"] == 6
        assert p6_consent["max_penalty_text"] == "Up to ₹50 crore"

        p6_rights = dpdp_penalties.map_statutory_penalty("Sections 11, 12, 13 & 14")
        assert p6_rights["schedule_item"] == 6
        assert p6_rights["max_penalty_text"] == "Up to ₹50 crore"

        # Advisory / non-statutory fallback
        padvisory = dpdp_penalties.map_statutory_penalty("internal_operational_guideline_xyz")
        assert padvisory["schedule_item"] is None
        assert padvisory["max_penalty_text"] == "Specific penalty mapping requires legal review."

    # --------------------------------------------------------------------------
    # 3. Phased Commencement Tracker (2025, 2026, 2027)
    # --------------------------------------------------------------------------
    def test_phased_commencement_enforceability(self):
        # Phase 1: Section 1 & 18 commenced 13 Nov 2025
        sec1 = dpdp_commencement.get_statutory_commencement("Section 1")
        assert sec1["commencement_status"] == "In force"
        assert sec1["enforceable_now"] is True
        assert dpdp_commencement.is_currently_enforceable("Section 1") is True

        # Phase 2: Section 6(9) commenced 13 Nov 2026
        sec6_9 = dpdp_commencement.get_statutory_commencement("Section 6(9)")
        assert sec6_9["commencement_status"] == "In force"
        assert sec6_9["enforceable_now"] is True
        assert dpdp_commencement.is_currently_enforceable("Section 6(9)") is True

        # Phase 3: Substantive business obligations scheduled for 13 May 2027
        sec5 = dpdp_commencement.get_statutory_commencement("Section 5")
        assert sec5["commencement_status"] == "Scheduled to commence"
        assert sec5["effective_date"] == "13 May 2027"
        assert sec5["enforceable_now"] is False
        assert dpdp_commencement.is_currently_enforceable("Section 5") is False

        sec8_5 = dpdp_commencement.get_statutory_commencement("Section 8(5)")
        assert sec8_5["effective_date"] == "13 May 2027"
        assert sec8_5["enforceable_now"] is False

    # --------------------------------------------------------------------------
    # 4. AI DPDP Assistant (Grounded RAG & Tenant-Awareness)
    # --------------------------------------------------------------------------
    def test_ai_dpdp_assistant_grounded_rag(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        
        # Test query for children's data -> must cite Section 9
        res = ai_dpdp_assistant.query_ai_dpdp_assistant("How do I handle children data?", org_id=org_id)
        assert res["status"] == "success"
        assert "Section 9" in res["matched_section"]
        assert "verifiable parental consent" in res["answer"].lower()
        assert len(res["suggested_questions"]) >= 2
        assert res["organization_context_applied"] is not None

        # Test query for breach notification -> must cite Section 8(6)
        res_breach = ai_dpdp_assistant.query_ai_dpdp_assistant("What is the breach notification timeline?", org_id=org_id)
        assert res_breach["status"] == "success"
        assert "Section 8(6)" in res_breach["matched_section"]
        assert "Data Protection Board of India" in res_breach["answer"]

        # Test query for penalty ceiling -> must cite Schedule
        res_pen = ai_dpdp_assistant.query_ai_dpdp_assistant("What is the penalty for not taking reasonable security safeguards?", org_id=org_id)
        assert res_pen["status"] == "success"
        assert "250 crore" in res_pen["answer"]

    # --------------------------------------------------------------------------
    # 5. Dynamic Readiness Scoring Engine
    # --------------------------------------------------------------------------
    def test_dynamic_readiness_scoring(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        scores = dpdp_store.calculate_dynamic_readiness(org_id)
        
        assert "overall_readiness_score" in scores
        assert "enforceable_now_score" in scores
        assert "forward_looking_score" in scores
        assert "sub_scores" in scores
        
        sub = scores["sub_scores"]
        assert "Notices & Consent" in sub
        assert "Security Safeguards" in sub
        assert "Vendor Governance" in sub
        assert "Rights & Grievance" in sub
        assert "Retention & Erasure" in sub
        assert "Breach Readiness" in sub

    # --------------------------------------------------------------------------
    # 6. Personal Data Flow Map & Schema Discovery
    # --------------------------------------------------------------------------
    def test_data_flow_map_generation(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        dpdp_store.add_inventory_entry(org_id, {
            "category": "Patient EHR Records",
            "storage_system": "AWS RDS Mumbai",
            "processor": "Cloud Health Tech"
        })
        dpdp_store.add_vendor(org_id, {
            "name": "Cloud Health Tech",
            "service": "EHR SaaS Hosting",
            "dpa_status": "DPA SIGNED & ACTIVE"
        })

        flow = data_discovery.generate_data_flow_map(org_id)
        assert "nodes" in flow
        assert len(flow["nodes"]) == 6
        node_labels = [n["label"] for n in flow["nodes"]]
        assert "Data Principals" in node_labels
        assert "Website & App Intake" in node_labels
        assert "Your Organisation Database" in node_labels

    def test_schema_heuristic_detection(self):
        classified = data_discovery.inspect_schema_metadata("patients_table", [
            "aadhaar_num", "blood_group", "annual_income", "child_guardian_phone"
        ])
        assert len(classified) == 4
        categories = [c["detected_category"] for c in classified]
        assert any("Aadhaar" in cat for cat in categories)
        assert any("Health" in cat for cat in categories)
        assert any("Financial" in cat for cat in categories)
        assert any("Minor" in cat or "Children" in cat for cat in categories)

    # --------------------------------------------------------------------------
    # 7. Vendor & Processor Management (Section 8(2) CRUD & Risk)
    # --------------------------------------------------------------------------
    def test_vendor_processor_lifecycle(self, client):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        
        v = dpdp_store.add_vendor(org_id, {
            "name": "SMS Messaging Gateway Ltd",
            "service": "OTP & Notification Dispatch",
            "dpa_status": "DPA PENDING EXECUTION"
        })
        assert v["id"].startswith("vnd-")

        v_updated = dpdp_store.update_vendor(org_id, v["id"], {
            "dpa_status": "DPA SIGNED & ACTIVE"
        })
        assert "COMPLIANT" in v_updated["statutory_risk"]

        deleted = dpdp_store.delete_vendor(org_id, v["id"])
        assert deleted is True

        reg = client.post("/api/auth/register", json={
            "email": f"vnd_{uuid.uuid4().hex[:6]}@clinic.in",
            "password": "StrongPassword#2026",
            "name": "Vendor Lead",
            "company_name": "Vendor Clinic"
        })
        hdrs = {"Authorization": f"Bearer {reg.get_json()['data']['token']}"}
        res_add = client.post("/api/dpdp/vendors", headers=hdrs, json={"name": "Cloud DB", "service": "Postgres Hosting"})
        assert res_add.status_code == 201
        vnd_id = res_add.get_json()["vendor"]["id"]

        res_del = client.delete(f"/api/dpdp/vendors/{vnd_id}", headers=hdrs)
        assert res_del.status_code == 200

    # --------------------------------------------------------------------------
    # 8. Retention Schedules & Erasure Tasks (Section 8(7) & Rule 8)
    # --------------------------------------------------------------------------
    def test_retention_and_erasure_tasks(self, client):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        
        sched = dpdp_store.add_retention_schedule(org_id, {
            "category": "Tax & Billing Invoices",
            "period_years": 8,
            "statutory_basis": "Income Tax Act 1961 read with Section 8(7) proviso"
        })
        assert sched["id"].startswith("ret-")

        task = dpdp_store.create_erasure_task(org_id, {
            "retention_schedule_id": sched["id"],
            "subject_identifier": "INV-2019-8821",
            "data_category": "Tax & Billing Invoices",
            "trigger_type": "PURPOSE_EXPIRED"
        })
        assert task["id"].startswith("era-")
        assert task["status"] == "PENDING_EXECUTION"

        proof_hash = "sha256:d8e8fca2dc0f896fd7cb4cb0031ba249"
        updated_task = dpdp_store.update_erasure_task(
            org_id, task["id"], "VERIFIED_ERASED",
            proof_hash=proof_hash, verified_by="Lead Privacy Engineer"
        )
        assert updated_task["status"] == "VERIFIED_ERASED"
        assert updated_task["proof_hash"] == proof_hash
        assert updated_task["completed_at"] is not None

        del_sched = dpdp_store.delete_retention_schedule(org_id, sched["id"])
        assert del_sched is True

    # --------------------------------------------------------------------------
    # 9. Data Principal Rights Update
    # --------------------------------------------------------------------------
    def test_rights_request_full_lifecycle(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        req = dpdp_store.submit_rights_request(org_id, {
            "type": "ACCESS",
            "principal_name": "Rohan Deshmukh",
            "contact_email": "rohan@example.in",
            "details": "Requesting copy of consultation history"
        })
        assert req["id"].startswith("dpr-")

        updated = dpdp_store.update_rights_request_full(org_id, req["id"], {
            "identity_verification_status": "Identity Verified (Aadhaar OTP via Digilocker)",
            "status": "COMPLETED",
            "response_summary": "Consultation records exported and securely transmitted via encrypted email."
        })
        assert updated["identity_verification_status"] == "Identity Verified (Aadhaar OTP via Digilocker)"
        assert updated["status"] == "COMPLETED"

    # --------------------------------------------------------------------------
    # 10. Platform Administration Oversight & Metrics API
    # --------------------------------------------------------------------------
    def test_admin_metrics_api(self, client, monkeypatch):
        admin_email = f"sysadmin_{uuid.uuid4().hex[:6]}@trustaudit.io"
        monkeypatch.setenv("TRUSTAUDIT_PLATFORM_ADMIN_EMAILS", admin_email)
        reg = client.post("/api/auth/register", json={
            "email": admin_email,
            "password": "StrongPassword#2026",
            "name": "Platform Admin",
            "company_name": "TrustAudit Ops"
        })
        hdrs = {"Authorization": f"Bearer {reg.get_json()['data']['token']}"}
        res = client.get("/api/admin/metrics", headers=hdrs)
        assert res.status_code == 200
        metrics = res.get_json()["metrics"]
        assert "platform_status" in metrics
        assert metrics["platform_status"] == "OPERATIONAL"
        assert "legal_database_version" in metrics
        assert "active_plans" in metrics
        assert metrics["active_plans"]["starter"]["price_inr"] == 999
        assert metrics["active_plans"]["growth"]["price_inr"] == 1999
        assert metrics["active_plans"]["business"]["price_inr"] == 2999

    # --------------------------------------------------------------------------
    # 11. Homepage Hero & Plain-Language Launch Sections
    # --------------------------------------------------------------------------
    def test_homepage_hero_and_sections(self, client):
        res = client.get("/")
        assert res.status_code == 200
        body = res.data.decode("utf-8")

        assert "Your Customer Data. Finally Under Control." in body
        assert "Start My Free Assessment" in body
        assert "Explore TrustAudit" in body

        for route_link in ["/features", "/industries", "/pricing", "/how-it-works", "/security", "/resources", "/demo"]:
            assert route_link in body, f"Missing routed website link: {route_link}"

        assert "Data Inventory" in body or "Customer Data" in body
        assert "Visual Data Map" in body or "Data Map" in body
        assert "Action Management" in body or "Action Plan" in body
        assert "Vendor Operations" in body or "Vendor" in body
        assert "Customer Privacy Portal" in body

        res_lib = client.get("/resources")
        lib_body = res_lib.data.decode("utf-8")
        assert "₹250 crore" in lib_body
        assert "₹50 crore" in lib_body

        # Phased Statutory Commencement Roadmap
        assert "13 November 2025" in body
        assert "13 November 2026" in body
        assert "13 May 2027" in body

        # Pricing plans
        assert "999" in body
        assert "1,999" in body
        assert "2,999" in body
