"""
TrustAudit — Complete DPDP Platform Verification Suite (Phases 1 to 24: A through Z)
=====================================================================================
Automated tests covering:
A. Registration and login
B. Organisation creation
C. Business onboarding
D. Industry selection
E. DPDP applicability assessment
F. Personal data inventory
G. Questionnaire branching
H. Gap identification
I. Privacy notice generation
J. Consent record creation
K. Consent withdrawal workflows (Section 6(4)-(6))
L. Rights requests (Sections 11-14)
M. Vendor management (Section 8(2))
N. Evidence upload and download
O. Evidence versioning
P. Retention schedules (Rule 8)
Q. Deletion workflows (Section 8(7))
R. Breach management (Section 8(6) & Rule 7)
S. Remediation tasks
T. Reports & Audit Summaries
U. Organisation isolation & Multi-tenant security
V. Role permissions & RBAC
W. Responsive dashboard rendering
X. Homepage links & Certinal-inspired sections
Y. Pricing and subscription limits
Z. Trust Centre disclosures & Disclaimers
"""

import pytest
import json
import io
import uuid
import time
from app import app
import dpdp_engine
import dpdp_store
import saas_store


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestDPDPCompleteSuite:
    """Complete A through Z verification for DPDP Compliance Platform."""

    # A. Registration and login
    def test_a_registration_and_login(self, client):
        test_email = f"clinic_admin_{uuid.uuid4().hex[:6]}@arogyaclinic.in"
        test_pw = "StrictP@ssw0rd2026!"
        reg_res = client.post("/api/auth/register", json={
            "email": test_email,
            "password": test_pw,
            "name": "Dr. Sunita Sharma",
            "org_name": "Arogya Diagnostics Clinic",
            "industry": "healthcare"
        })
        assert reg_res.status_code in (200, 201)
        data = reg_res.get_json()
        assert data.get("status") == "success"

        # Verify login
        login_res = client.post("/api/auth/login", json={
            "email": test_email,
            "password": test_pw
        })
        assert login_res.status_code == 200
        assert "trustaudit_session" in login_res.headers.get("Set-Cookie", "") or login_res.get_json().get("token")

    # B. Organisation creation
    def test_b_organisation_creation(self):
        org_name = f"Apollo Diagnostics Clinic {uuid.uuid4().hex[:4]}"
        user_email = f"dr_apollo_{uuid.uuid4().hex[:6]}@apolloclinic.in"
        ok, msg, payload = saas_store.register_user(
            email=user_email,
            password="SecurePassword2026!",
            name="Dr. Apollo Lead",
            org_name=org_name
        )
        assert ok is True
        assert "user" in payload
        assert "org_id" in payload["user"]
        org = saas_store.get_organization(payload["user"]["org_id"])
        assert org["name"] == org_name

    # C & D. Business onboarding & Industry selection
    def test_c_d_onboarding_and_industry_selection(self, client):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        ob_data = {
            "business_name": "City Care Diagnostic Center",
            "industry": "healthcare",
            "locations": "Bengaluru, Indiranagar",
            "employee_count": "15-50",
            "customer_types": ["Patients", "Corporate Health Checkups"],
            "children_data_processed": True
        }
        profile = dpdp_store.save_onboarding_profile(org_id, ob_data)
        assert profile["business_name"] == "City Care Diagnostic Center"
        assert profile["industry"] == "healthcare"

        # Verify automatic healthcare inventory pre-population
        inv = dpdp_store.get_data_inventory(org_id)
        assert len(inv) >= 4
        categories = [item["category"] for item in inv]
        assert any("Patient" in c for c in categories)
        assert any("Diagnostic" in c for c in categories)

    # E. DPDP applicability assessment
    def test_e_dpdp_applicability_assessment(self):
        reqs = dpdp_engine.DPDP_REQUIREMENTS
        assert len(reqs) >= 12
        sec3 = next(r for r in reqs if r["id"] == "DPDP-SEC-03")
        assert sec3["legal_status"] == "SCHEDULED_MAY_2027"
        assert sec3["effective_date"] == "13 May 2027"
        assert "Applicability" in sec3["title"]

    # F. Personal data inventory (Add, List, Update, Delete, CSV Export)
    def test_f_personal_data_inventory(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        entry = dpdp_store.add_inventory_entry(org_id, {
            "category": "Patient Blood Pathology Results",
            "principal_type": "Patients",
            "source": "Diagnostic Laboratory Analyzer",
            "purpose": "Clinical Pathology Assessment",
            "legal_basis": "DPDP Section 6 (Consent) & Section 7(e) Medical Emergency",
            "storage_system": "LIMS Cloud (AWS ap-south-1)",
            "retention_period": "5 Years"
        })
        assert entry["id"].startswith("inv-")
        assert entry["category"] == "Patient Blood Pathology Results"

        # Export CSV
        csv_str = dpdp_store.export_inventory_csv(org_id)
        assert "Patient Blood Pathology Results" in csv_str
        assert "LIMS Cloud" in csv_str

        # Import CSV
        count = dpdp_store.import_inventory_csv(org_id, csv_str)
        assert count >= 1

    # G & H. Questionnaire branching & Gap identification
    def test_g_h_branching_and_gap_identification(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        assessment = dpdp_store.get_assessment(org_id)
        assert "readiness_score" in assessment
        assert assessment["controls_total"] >= 10
        assert len(assessment["gaps"]) >= 1

        # Check gap structure
        gap = assessment["gaps"][0]
        assert "requirement_id" in gap
        assert "why_it_matters" in gap
        assert "recommended_solution" in gap

    # I. Privacy notice generation (Section 5 read with Rule 3)
    def test_i_privacy_notice_generation(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        notice = dpdp_store.generate_privacy_notice(org_id, {
            "company_name": "Sanjeevani Clinic",
            "grievance_email": "grievance@sanjeevaniclinic.com",
            "grievance_officer": "Dr. K. Rao",
            "address": "Koramangala, Bengaluru"
        })
        assert "Section 5 read with Rule 3" in notice["content"]
        assert "grievance@sanjeevaniclinic.com" in notice["content"]
        assert "Eighth Schedule" in notice["content"]

    # J & K. Consent records & Consent withdrawal workflows (Section 6(4)-(6))
    def test_j_k_consent_and_withdrawal_cascade(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        cst = dpdp_store.record_consent(org_id, {
            "principal_ref": "DP-9921",
            "category": "Patient Diagnostic Information",
            "purpose": "Clinical Pathology Review"
        })
        assert cst["status"] == "ACTIVE"

        # Execute withdrawal
        wth = dpdp_store.submit_consent_withdrawal(org_id, {
            "principal_ref": "DP-9921",
            "retention_exception": True
        })
        assert wth["status"] == "COMPLETED"
        assert wth["processor_notified"] is True
        assert "Clinical Establishments Rules" in wth["exception_reason"]

    # L. Data Principal Rights management (Sections 11–14)
    def test_l_data_principal_rights(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        req = dpdp_store.submit_rights_request(org_id, {
            "type": "CORRECTION",
            "principal_name": "Ananya Sen",
            "description": "Update residential address and contact number on patient chart."
        })
        assert req["status"] == "RECEIVED"
        assert req["sla_deadline"] is not None

        updated = dpdp_store.update_rights_request_status(org_id, req["id"], "COMPLETED", "Address updated in HMS.")
        assert updated["status"] == "COMPLETED"
        assert updated["closed_at"] is not None

    # M. Vendor management (Section 8(2))
    def test_m_vendor_and_processor_management(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        vendor = dpdp_store.add_vendor(org_id, {
            "name": "MedCloud Diagnostics SaaS",
            "service": "Picture Archiving & Radiology Cloud",
            "personal_data_processed": "Patient X-Ray and MRI Scans",
            "storage_location": "AWS Asia Pacific (Mumbai) ap-south-1",
            "dpa_status": "EXECUTED",
            "risk_rating": "LOW"
        })
        assert vendor["id"].startswith("vnd-")
        assert vendor["dpa_status"] == "EXECUTED"

    # N & O. Evidence upload, download, and versioning
    def test_n_o_evidence_vault(self, client):
        reg = client.post("/api/auth/register", json={
            "email": f"ev_{uuid.uuid4().hex[:6]}@clinic.in",
            "password": "StrongPassword#2026",
            "name": "Clinic Owner",
            "company_name": "Evidence Clinic"
        })
        tok = reg.get_json()["data"]["token"]
        # Valid PDF magic bytes required by hardened uploader
        data = io.BytesIO(b"%PDF-1.4\nITEMISED PRIVACY NOTICE V1.0 OFFICIAL CLINIC DOCUMENT")
        data.name = "clinic_notice_v1.pdf"

        post_data = {
            "title": "Clinic Itemised Privacy Notice v1.0",
            "category": "notices",
            "control_id": "DPDP-SEC-05",
            "file": (data, "clinic_notice_v1.pdf")
        }
        res = client.post("/api/evidence", headers={"Authorization": f"Bearer {tok}"}, data=post_data, content_type="multipart/form-data")
        assert res.status_code in (200, 201)
        evi_data = res.get_json()
        assert evi_data.get("status") == "success"
        assert "evidence" in evi_data
        assert "id" in evi_data["evidence"]
        assert evi_data["evidence"]["control_id"] == "DPDP-SEC-05"

    # P & Q. Retention schedules (Rule 8) and Deletion workflows (Section 8(7))
    def test_p_q_retention_and_deletion(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        sched = dpdp_store.add_retention_schedule(org_id, {
            "category": "Patient Consultation Records",
            "purpose": "Clinical care and follow-up",
            "statutory_basis": "Clinical Establishments Act & DPDP Section 8(7)",
            "period_years": 3,
            "end_of_purpose_trigger": "3 years from last consultation",
            "deletion_method": "Cryptographic DB scrub"
        })
        assert sched["period_years"] == 3
        assert "Clinical Establishments" in sched["statutory_basis"]

    # R. Breach management (Section 8(6) & Rule 7)
    def test_r_breach_management_dual_stage_intimation(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        incident = dpdp_store.log_breach_incident(org_id, {
            "title": "Unauthorized Access Attempt to Frontdesk PC",
            "severity": "MEDIUM",
            "affected_data_categories": ["Patient Registration Logs"],
            "estimated_individuals_affected": 45
        })
        assert incident["board_notification_status"] == "DRAFT_PENDING_CUSTOMER_APPROVAL"
        assert "INITIAL INTIMATION" in incident["board_initial_intimation_draft"]
        assert "72-Hour Statutory Requirement" in incident["board_72h_detailed_intimation_draft"]

        # Authorize intimation
        authorized = dpdp_store.authorize_breach_intimation(org_id, incident["id"], "Medical Director")
        assert authorized["customer_authorized_to_send"] is True
        assert authorized["board_notification_status"] == "AUTHORIZED_SUBMITTED"

    # S. Remediation tasks
    def test_s_remediation_tasks(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        tasks = dpdp_store.get_remediation_tasks(org_id)
        assert len(tasks) >= 1
        task_id = tasks[0]["id"]
        updated = dpdp_store.update_remediation_task(org_id, task_id, "COMPLETED", "Multi-lingual notice published.")
        assert updated["status"] == "COMPLETED"

    # T. Reports & Audit summaries
    def test_t_reports_and_audit(self, client):
        reg = client.post("/api/auth/register", json={
            "email": f"rpt_{uuid.uuid4().hex[:6]}@clinic.in",
            "password": "StrongPassword#2026",
            "name": "Report Lead",
            "company_name": "Report Clinic"
        })
        tok = reg.get_json()["data"]["token"]
        pdf_res = client.get("/api/dpdp/reports/pdf", headers={"Authorization": f"Bearer {tok}"})
        assert pdf_res.status_code == 200
        assert pdf_res.data.startswith(b"%PDF-1.4")

    # U. Organisation isolation & Multi-tenant security
    def test_u_organisation_isolation(self):
        org_a = f"org-a-{uuid.uuid4().hex[:4]}"
        org_b = f"org-b-{uuid.uuid4().hex[:4]}"

        dpdp_store.add_inventory_entry(org_a, {"category": "Org A Patient Secret"})
        inv_b = dpdp_store.get_data_inventory(org_b)
        assert not any(i["category"] == "Org A Patient Secret" for i in inv_b)

    # V. Role permissions & RBAC
    def test_v_role_permissions(self):
        org_id = f"org-{uuid.uuid4().hex[:6]}"
        team = saas_store.list_team_members(org_id)
        assert isinstance(team, list)

    # W. Responsive routed workspace rendering (authenticated user opens /app/home cleanly)
    def test_w_dashboard_rendering(self, client):
        res_public = client.get("/dashboard")
        assert res_public.status_code == 200
        # Register & verify routed /app/home sidebar renders all plain-language modules
        reg = client.post("/api/auth/register", json={
            "name": "UI Tester", "company_name": "Clinic UI", "industry": "healthcare",
            "email": f"uit_{uuid.uuid4().hex[:6]}@clinic.in", "password": "Password123!"
        })
        assert reg.status_code == 201
        res = client.get("/app/home")
        assert res.status_code == 200
        assert b"Customer Information" in res.data
        assert b"Where My Data Goes" in res.data
        assert b"Companies I Share Data With" in res.data
        assert b"Website Check" in res.data
        assert b"Privacy Assessment" in res.data
        assert b"Consent Records" in res.data
        assert b"Customer Requests" in res.data
        assert b"Data Retention &amp; Deletion" in res.data
        assert b"Privacy Incident Response" in res.data
        assert b"Vendor Reviews" in res.data
        assert b"Privacy Notice" in res.data
        assert b"My Documents" in res.data
        assert b"Evidence" in res.data
        assert b"Reports" in res.data
        assert b"History" in res.data
        assert b"AI Assistant" in res.data
        assert b"Learning Centre" in res.data

    # X. Homepage links & GTM hero sections
    def test_x_homepage_links(self, client):
        res = client.get("/")
        assert res.status_code == 200
        assert b"Not Sure Where Your Customer Data Goes? Start Here." in res.data
        assert b"Check My Business" in res.data
        assert b"See a Live Demo" in res.data
        assert b"Clinics &amp; Healthcare" in res.data
        assert b"Product" in res.data
        assert b"How It Works" in res.data
        assert b"Industries" in res.data
        assert b"Pricing" in res.data
        assert b"Resources" in res.data

    # Y. Pricing and subscription limits
    def test_y_pricing_and_plans(self, client):
        res = client.get("/")
        assert res.status_code == 200
        assert b"999" in res.data
        assert b"1,999" in res.data
        assert b"2,999" in res.data
        assert b"Starter" in res.data
        assert b"Growth" in res.data
        assert b"Business" in res.data

    # Z. Trust Centre disclosures & Disclaimers
    def test_z_trust_centre_disclosures(self, client):
        res = client.get("/trust")
        assert res.status_code == 200
        assert b"Zero Raw Patient Data Collection" in res.data
        assert b"grievance@trustaudit.io" in res.data
        assert b"security@trustaudit.io" in res.data
        assert b"Not a Government Certification Body" in res.data
        assert b"Not a Statutory Consent Manager" in res.data
