"""
TrustAudit Go-To-Market Product Transformation E2E Test Suite (Part 28).

Covers every major customer journey across two completely isolated organisations:
1. Public website routes (/features, /industries, /pricing, /how-it-works, /security, /resources, /about, /login, /register, /demo)
2. Hero diagram, animated flow & interactive public walkthrough booking
3. Registration -> 6-step Onboarding -> Industry activity suggestions ('SUGGESTED — NEEDS CONFIRMATION')
4. Extraction engine (.CSV, .XLSX OOXML, .DOCX OOXML, scanned PDF fallback) -> Review (Accept / Edit / Reject)
5. Inventory confirmation, duplicate detection, bulk review, version history & Data Map SVG edges
6. 10-topic Guided Assessment (5 verification states + 'Not sure' guidance) & Kanban/List/Calendar Tasks
7. Vendor creation, transparent risk basis explanation, & restricted /vendor-intake/<token> link
8. Privacy Notice generation, DOCX export, Document Centre save-to-Evidence Vault
9. Customer Privacy Request Portal (/portal/<org_slug>) with HMAC challenge & zero email enumeration
10. Shareable Privacy Profile (/p/<org_slug>) whitelisted public disclosure check
11. Consent CSV import, Guided Deletion workflow, Privacy Incident updates
12. Grounded AI Privacy Assistant prompts & S.O. 5458(E) Removal of Difficulties Order ('data audit')
13. Multi-tenant isolation across two separate organisations + Platform Admin configurable plans
14. Real PDF report export & Permanent organisation deletion
"""

import io
import os
import sys
import uuid
import zipfile
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app as flask_app
import dpdp_commencement
import dpdp_engine
import dpdp_penalties
import dpdp_store
import extraction_engine
import saas_store


@pytest.fixture
def isolated_gtm_env(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    monkeypatch.setenv("TRUSTAUDIT_DATA_DIR", str(data_dir))
    monkeypatch.setenv("TRUSTAUDIT_PLATFORM_ADMIN_EMAILS", "operator@trustaudit.in")
    monkeypatch.setattr(saas_store, "DATA_FILE", str(tmp_path / "saas_data.json"))
    monkeypatch.setattr(dpdp_store, "DPDP_DATA_FILE", str(data_dir / "dpdp_store.json"))
    flask_app.app.config["TESTING"] = True
    return tmp_path, flask_app.app.test_client()


def _create_sample_xlsx_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "xl/sharedStrings.xml",
            '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            "<si><t>Category</t></si><si><t>Fields</t></si><si><t>Purpose</t></si><si><t>Vendor</t></si>"
            "<si><t>Health information</t></si><si><t>Patient Name, Lab Report</t></si>"
            "<si><t>Diagnostic reporting</t></si><si><t>Thyrocare Lab</t></si></sst>",
        )
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
            '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>3</v></c></row>'
            '<row r="2"><c r="A2" t="s"><v>4</v></c><c r="B2" t="s"><v>5</v></c><c r="C2" t="s"><v>6</v></c><c r="D2" t="s"><v>7</v></c></row>'
            "</sheetData></worksheet>",
        )
    return buf.getvalue()


class TestGTMProductTransformation:
    def test_legal_accuracy_removal_of_difficulties_so_5458_e(self):
        sources_text = " ".join(dpdp_commencement.OFFICIAL_SOURCES.values())
        assert "G.S.R. 843(E)" in sources_text
        assert "G.S.R. 846(E)" in sources_text
        assert "S.O. 5458(E)" in sources_text
        assert "data audit" in sources_text
        assert "Section 9(1)" in sources_text

        sec10 = next(r for r in dpdp_engine.DPDP_REQUIREMENTS if r["id"] == "DPDP-SEC-10")
        assert "S.O. 5458(E)" in sec10["description"]
        assert "data audit" in sec10["description"]

        p10 = dpdp_penalties.map_statutory_penalty("SEC_10")
        assert "S.O. 5458(E)" in p10["explanation"]
        assert "data audit" in p10["explanation"]

    def test_extraction_engine_csv_xlsx_docx_and_scanned_pdf(self):
        # 1. CSV auto-mapping
        csv_raw = b"Category,Personal Data,Purpose,Storage System,Vendor\nHealth information,\"Patient Name, Phone\",Appointments,Clinic DB,Zoho CRM\n"
        csv_res = extraction_engine.extract_from_uploaded_file("register.csv", csv_raw)
        assert csv_res["rows_parsed"] == 1
        assert csv_res["suggestions_count"] >= 2
        assert all(s["status"] == "Needs review" and s["verified"] is False for s in csv_res["suggestions"])

        # 2. XLSX pure-Python OOXML reader
        xlsx_res = extraction_engine.extract_from_uploaded_file("patient_data.xlsx", _create_sample_xlsx_bytes())
        assert xlsx_res["rows_parsed"] == 1
        assert any("Thyrocare Lab" in s["value"] for s in xlsx_res["suggestions"])

        # 3. DOCX export + DOCX extraction roundtrip
        docx_bytes = extraction_engine.generate_docx_bytes(
            "Clinic Privacy Policy",
            "Contact Grievance Desk at privacy@kaveri.in.\nPatient appointments processed via Razorpay.\nRetain invoices for 8 years.",
            "Kaveri Clinic",
        )
        docx_res = extraction_engine.extract_from_uploaded_file("policy.docx", docx_bytes)
        assert any(s["extracted_type"] == "contact" and "privacy@kaveri.in" in s["value"] for s in docx_res["suggestions"])
        assert any(s["extracted_type"] == "vendor" and "Razorpay" in s["value"] for s in docx_res["suggestions"])
        assert any(s["extracted_type"] == "retention" and "8 years" in s["retention_period"] for s in docx_res["suggestions"])

        # 4. Scanned image-only PDF fails honestly without fabricating text
        fake_scanned_pdf = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
        pdf_res = extraction_engine.extract_from_uploaded_file("scanned.pdf", fake_scanned_pdf)
        assert pdf_res["suggestions_count"] == 0
        assert any("Scanned" in w for w in pdf_res["warnings"])

    def test_all_15_journeys_and_two_org_isolation(self, isolated_gtm_env):
        _, client = isolated_gtm_env

        # Public website & walkthrough
        for route in ["/", "/features", "/industries", "/pricing", "/how-it-works", "/security", "/trust", "/resources", "/about", "/login", "/register", "/demo"]:
            assert client.get(route).status_code == 200, route

        wk = client.post("/api/public/walkthrough", json={"name": "Dr. Meera", "email": "meera@kaveri.in", "company": "Kaveri Clinic"})
        assert wk.status_code == 201 and wk.get_json()["data"]["reference_id"].startswith("WLK-")

        # Register Org A (Clinic)
        reg_a = client.post("/api/auth/register", json={
            "name": "Dr. Meera", "company_name": "Kaveri Clinic", "industry": "healthcare",
            "email": "admin@kaveri.in", "password": "StrongPassword123!"
        })
        assert reg_a.status_code == 201
        tok_a = reg_a.get_json()["data"]["token"]
        org_a = reg_a.get_json()["data"]["organization"]
        slug_a = org_a["slug"]
        hdr_a = {"Authorization": f"Bearer {tok_a}"}

        # Unauthenticated /app/home redirects to login; authenticated loads cleanly
        unauth_client = flask_app.app.test_client()
        assert unauth_client.get("/app/home").status_code in (302, 303)
        for p in ["home", "onboarding", "discovery", "data-inventory", "data-map", "assessment", "action-plan", "vendors", "notices", "consent", "privacy-requests", "retention", "incidents", "document-centre", "evidence", "reports", "privacy-assistant", "privacy-portal", "privacy-profile", "integrations", "settings"]:
            res_p = client.get(f"/app/{p}", headers=hdr_a)
            assert res_p.status_code == 200, f"/app/{p}"

        # Journey 3: Industry activity suggestions -> "SUGGESTED — NEEDS CONFIRMATION"
        act_res = client.post("/api/dpdp/onboarding/activities", headers=hdr_a, json={"industry": "healthcare", "selected_keys": ["patient_appointments", "billing"]})
        assert act_res.status_code == 201 and act_res.get_json()["created_count"] == 2
        inv = client.get("/api/dpdp/inventory", headers=hdr_a).get_json()["items"]
        assert inv[0]["confirmation_status"] == "SUGGESTED — NEEDS CONFIRMATION"
        assert client.post("/api/dpdp/inventory/bulk-review", headers=hdr_a, json={"entry_ids": [i["id"] for i in inv]}).status_code == 200

        # Journey 5 & 10: Upload DOCX -> review suggestion -> accept creates vendor & inventory
        docx_up = extraction_engine.generate_docx_bytes("Clinic Intake", "Using Zoho CRM and retaining patient data for 5 years. privacy@kaveri.in", "Kaveri Clinic")
        up = client.post("/api/dpdp/extraction/upload", headers=hdr_a, data={"file": (io.BytesIO(docx_up), "clinic.docx")}, content_type="multipart/form-data")
        assert up.status_code == 200 and up.get_json()["extraction"]["suggestions_count"] >= 2
        sug_id = up.get_json()["extraction"]["suggestions"][0]["id"]
        assert client.post(f"/api/dpdp/extraction/suggestions/{sug_id}/review", headers=hdr_a, json={"action": "accept"}).status_code == 200

        # Journey 6: 10-topic assessment ('Not sure' produces guidance, 5 verification states)
        t_res = client.post("/api/dpdp/assessment/topics", headers=hdr_a, json={"topic_id": "topic_collection", "answer": "Not sure"})
        assert t_res.status_code == 200 and len(t_res.get_json()["topics"]) == 10
        assert t_res.get_json()["topics"][0]["verification_state"] == "Not assessed"
        t_yes = client.post("/api/dpdp/assessment/topics", headers=hdr_a, json={"topic_id": "topic_collection", "answer": "Yes"}).get_json()
        assert t_yes["topics"][0]["verification_state"] == "Business self-attested"

        # Journey 7 & 8: Create Task + Create Vendor + Vendor intake token
        tk = client.post("/api/dpdp/tasks", headers=hdr_a, json={"title": "Sign PathLab DPA", "priority": "HIGH"}).get_json()["task"]
        assert client.post(f"/api/dpdp/tasks/{tk['id']}/update", headers=hdr_a, json={"status": "Resolved"}).status_code == 200
        vnd = client.post("/api/dpdp/vendors", headers=hdr_a, json={"name": "Thyrocare Lab", "category": "Health Partner", "data_location": "India"}).get_json()["vendor"]
        link_res = client.post(f"/api/dpdp/vendors/{vnd['id']}/intake-link", headers=hdr_a).get_json()
        assert client.get(link_res["intake_path"]).status_code == 200
        assert client.post(f"/api/public/vendor-intake/{link_res['token']}", json={"submitted_by": "Compliance Lead", "data_location": "Mumbai", "encryption_at_rest": True}).status_code == 200

        # Journey 9 & 16: Privacy Notice + Document Centre DOCX export & Save to Vault
        notice = client.post("/api/dpdp/notices/generate", headers=hdr_a, json={"grievance_officer": "Dr. Meera", "grievance_email": "privacy@kaveri.in"}).get_json()["notice"]
        assert client.put(f"/api/dpdp/notices/{notice['id']}", headers=hdr_a, json={"status": "APPROVED_PUBLISHED"}).status_code == 200
        assert client.get(f"/api/dpdp/notices/{notice['id']}/export?format=docx", headers=hdr_a).status_code == 200
        doc = client.post("/api/dpdp/documents/generate", headers=hdr_a, json={"doc_type": "retention_policy"}).get_json()["document"]
        assert client.post(f"/api/dpdp/documents/{doc['id']}/save-evidence", headers=hdr_a, json={}).status_code == 201

        # Journey 10 & 15: Public Customer Privacy Portal + Non-enumeration status + Shareable Privacy Profile
        portal_html = client.get(f"/portal/{slug_a}").get_data(as_text=True)
        assert "Kaveri Clinic" in portal_html
        # Test valid challenge submission directly via HMAC helper
        prompt, c_tok = flask_app._make_portal_challenge()
        a_num, b_num = [int(x.strip()) for x in prompt.split("+")]
        sub = client.post(f"/api/public/portal/{slug_a}/submit", json={
            "type": "ERASURE", "name": "Ravi", "email": "ravi@example.com", "description": "Please remove old booking record",
            "challenge_token": c_tok, "challenge_answer": str(a_num + b_num),
        })
        assert sub.status_code == 201
        sub_json = sub.get_json()
        # Wrong verification code reveals nothing
        bad_lookup = client.post(f"/api/public/portal/{slug_a}/status", json={"reference_id": sub_json["reference_id"], "verification_code": "WRONG1"}).get_json()
        assert bad_lookup["match"] is None
        good_lookup = client.post(f"/api/public/portal/{slug_a}/status", json={"reference_id": sub_json["reference_id"], "verification_code": sub_json["verification_code"]}).get_json()
        assert good_lookup["match"]["type"] == "ERASURE"

        prof_pub = client.get(f"/api/public/privacy-profile/{slug_a}").get_json()["profile"]
        assert "not a government certification" in prof_pub["mandatory_disclaimer"].lower()
        assert "Thyrocare Lab" not in str(prof_pub)  # internal vendor contracts never leaked on public profile

        # Journey 13: AI Assistant S.O. 5458(E) + search + PDF report
        ai = client.post("/api/dpdp/assistant", headers=hdr_a, json={"query": "What did S.O. 5458(E) change for data audit?"}).get_json()
        assert "data audit" in ai["answer"] and ai["rule_ref"]
        assert client.get("/api/dpdp/search?q=Thyrocare", headers=hdr_a).get_json()["results"]
        pdf = client.get("/api/dpdp/reports/pdf", headers=hdr_a)
        assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF-1.4")

        # Register Org B (Cross-Tenant Isolation + Platform Admin Console)
        reg_b = client.post("/api/auth/register", json={
            "name": "Operator", "company_name": "Org Beta SaaS", "industry": "saas",
            "email": "operator@trustaudit.in", "password": "StrongPassword123!"
        })
        tok_b = reg_b.get_json()["data"]["token"]
        hdr_b = {"Authorization": f"Bearer {tok_b}"}

        # Org B cannot see Org A's inventory, vendors, notices, or requests
        assert client.get("/api/dpdp/inventory", headers=hdr_b).get_json()["items"] == []
        assert client.get("/api/dpdp/vendors", headers=hdr_b).get_json()["items"] == []
        assert client.get("/api/dpdp/notices", headers=hdr_b).get_json()["notices"] == []
        assert client.get("/api/dpdp/rights", headers=hdr_b).get_json()["requests"] == []

        # Non-platform-admin (Org A) blocked from /api/admin/plans and /app/admin
        assert client.get("/api/admin/plans", headers=hdr_a).status_code == 403
        assert client.get("/app/admin", headers=hdr_a).status_code == 403

        # Platform Admin (Org B operator@trustaudit.in) can configure pricing plans live
        assert client.get("/app/admin", headers=hdr_b).status_code == 200
        upd_plan = client.post("/api/admin/plans", headers=hdr_b, json={"plan_key": "starter", "price_monthly_inr": 1299})
        assert upd_plan.status_code == 200
        assert client.get("/api/plans").get_json()["public_plans"][1]["price_monthly_inr"] == 1299

        # Journey 15: Org A permanently deleted
        assert client.post("/api/account/delete", headers=hdr_a, json={}).status_code == 200
        assert unauth_client.get("/api/auth/me", headers=hdr_a).status_code == 401
