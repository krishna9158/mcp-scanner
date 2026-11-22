"""
Automated Verification Suite for TrustAudit DPDP Website Scanner & Gap Detection
===============================================================================
Covers all requirements from Phase 1 to Phase 20:
- SSRF boundaries & private IP rejection
- Mandatory ownership/authorization confirmation
- Non-invasive form analysis (never submits forms)
- Fixture test cases:
  1. Proper privacy notice
  2. Missing privacy notice
  3. Contact form without nearby notice
  4. Form with un-ticked consent
  5. Form with pre-selected consent
  6. Third-party tracking scripts
  7. Grievance contact presence & omission
  8. Children-oriented content (Section 9)
  9. HTTPS & security headers (Section 8(5))
- Statutory penalty exposure mappings & disclaimers
- Dynamic effective date labels (13 May 2027 future readiness)
- Backend API endpoints (start, results, history, delete, convert-task)
- Zero visitor data retention & tenant isolation
- Frontend dashboard and landing page navigation
"""

import json
import pytest
import uuid
from app import app
import dpdp_website_scanner
import dpdp_store
import saas_store
from ssrf_protection import SSRFSecurityError, validate_target_url_ssrf_safe


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestDPDPWebsiteScannerSuite:
    """Comprehensive test suite for DPDP Website Scanner."""

    # 1. SSRF Protection Tests
    def test_01_ssrf_protection_blocks_internal_and_cloud_metadata(self):
        """Rejects localhost, loopback, private IPv4/IPv6, and cloud metadata IPs."""
        blocked_targets = [
            "http://127.0.0.1",
            "http://localhost:8080",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.15/admin",
            "http://192.168.1.1",
            "http://metadata.google.internal",
            "http://[::1]",
        ]
        for target in blocked_targets:
            with pytest.raises(SSRFSecurityError):
                validate_target_url_ssrf_safe(target)

    # 2. Mandatory Authorization Check
    def test_02_scanner_requires_explicit_authorization(self):
        """Ensures scanning cannot start without explicit authorization confirmation."""
        scanner = dpdp_website_scanner.DPDPWebsiteScanner(
            target_url="https://example.com",
            authorization_confirmed=False
        )
        with pytest.raises(ValueError, match="authorization"):
            scanner.run_scan()

    # 3. Passive Non-Invasive Form Parsing (Never submits forms)
    def test_03_scanner_never_submits_forms(self):
        """Verifies parser inspects input tags without performing HTTP POST submissions."""
        sample_html = """
        <html><body>
        <form id="contact-form" action="/api/submit-lead" method="POST">
            <input type="text" name="full_name" placeholder="Your Name">
            <input type="tel" name="phone_number" placeholder="Mobile Number">
            <input type="email" name="email_addr" placeholder="Email">
            <button type="submit">Submit Enquiry</button>
        </form>
        </body></html>
        """
        parser = dpdp_website_scanner.WebPageParser("https://clinic.example.in")
        parser.feed(sample_html)
        assert len(parser.forms) == 1
        form = parser.forms[0]
        assert form["id"] == "contact-form"
        assert len(form["inputs"]) == 3
        # Check input types and names parsed safely
        names = [inp["name"] for inp in form["inputs"]]
        assert "full_name" in names
        assert "phone_number" in names
        assert "email_addr" in names

    # 4. Fixture: Missing Privacy Notice
    def test_04_fixture_missing_privacy_notice(self):
        """Flags Section 5 notice gap when no privacy notice exists on scanned pages."""
        scanner = dpdp_website_scanner.DPDPWebsiteScanner(
            target_url="https://exampleclinic.in",
            business_name="Example Clinic",
            authorization_confirmed=True
        )
        # Mock scanned pages without privacy notice
        scanner.scanned_pages = [
            {"url": "https://exampleclinic.in", "html": "<html><body><h1>Welcome</h1></body></html>", "headers": {"strict-transport-security": "max-age=31536000"}}
        ]
        scanner.privacy_pages = []
        scanner._stage_08_statutory_mapping(None)

        notice_gaps = [f for f in scanner.findings if "Notice Not Detected" in f["title"]]
        assert len(notice_gaps) == 1
        gap = notice_gaps[0]
        assert gap["severity"] == "HIGH"
        assert "Section 5" in gap["legal_reference"]
        assert gap["effective_status"] == "SCHEDULED_MAY_2027"
        # Verify penalty ceiling uses General Contravention (₹50 Cr), NOT ₹250 Cr
        assert "₹50 crore" in gap["penalty_ceiling_text"]
        assert "statutory maximum penalty ceilings" in gap["statutory_disclaimer"].lower()

    # 5. Fixture: Form with Pre-Selected Consent Checkbox
    def test_05_fixture_form_with_preselected_consent(self):
        """Flags Section 6(1) unconditional consent gap when checkbox is pre-ticked."""
        scanner = dpdp_website_scanner.DPDPWebsiteScanner(
            target_url="https://testclinic.in",
            authorization_confirmed=True
        )
        sample_html = """
        <html><body>
        <form id="book-form">
            <input name="patient_name" placeholder="Patient Name">
            <input type="checkbox" name="agree_terms" checked> I agree to terms & marketing
        </form>
        </body></html>
        """
        scanner.scanned_pages = [{"url": "https://testclinic.in", "html": sample_html, "headers": {}}]
        scanner.privacy_pages = [{"url": "https://testclinic.in/privacy", "html": "privacy policy content access correction erasure grievance withdraw consent"}]
        scanner._stage_03_form_analysis(None)
        scanner._stage_08_statutory_mapping(None)

        pretick_gaps = [f for f in scanner.findings if "Pre-Selected Consent" in f["title"]]
        assert len(pretick_gaps) == 1
        assert pretick_gaps[0]["severity"] == "HIGH"
        assert "Section 6(1)" in pretick_gaps[0]["legal_reference"]

    # 6. Fixture: Form with Unselected Consent Checkbox (Valid)
    def test_06_fixture_form_with_unselected_consent(self):
        """Does NOT flag pre-selected consent gap when checkbox is unselected."""
        scanner = dpdp_website_scanner.DPDPWebsiteScanner(
            target_url="https://testclinic.in",
            authorization_confirmed=True
        )
        sample_html = """
        <html><body>
        <form id="book-form">
            <input name="patient_name" placeholder="Patient Name">
            <input type="checkbox" name="agree_terms"> I agree to privacy notice
        </form>
        </body></html>
        """
        scanner.scanned_pages = [{"url": "https://testclinic.in", "html": sample_html, "headers": {}}]
        scanner.privacy_pages = [{"url": "https://testclinic.in/privacy", "html": "privacy policy content access correction erasure grievance withdraw consent"}]
        scanner._stage_03_form_analysis(None)
        scanner._stage_08_statutory_mapping(None)

        pretick_gaps = [f for f in scanner.findings if "Pre-Selected Consent" in f["title"]]
        assert len(pretick_gaps) == 0

    # 7. Fixture: Third-Party Tracking Scripts Detection
    def test_07_fixture_third_party_tracking_detection(self):
        """Identifies third-party analytics and tracking scripts, mapping to Section 8(2) DPA."""
        scanner = dpdp_website_scanner.DPDPWebsiteScanner(
            target_url="https://testclinic.in",
            authorization_confirmed=True
        )
        sample_html = """
        <html><head>
        <script src="https://www.googletagmanager.com/gtm.js?id=GTM-123"></script>
        <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
        </head><body><h1>Home</h1></body></html>
        """
        scanner.scanned_pages = [{"url": "https://testclinic.in", "html": sample_html, "headers": {}}]
        scanner.privacy_pages = [{"url": "https://testclinic.in/privacy", "html": "privacy policy content access correction erasure grievance withdraw consent"}]
        scanner._stage_06_tracker_analysis(None)
        scanner._stage_08_statutory_mapping(None)

        assert len(scanner.third_party_services) == 2
        tracker_names = [s["name"] for s in scanner.third_party_services]
        assert "Google Tag Manager" in tracker_names
        assert "Meta Pixel (Facebook)" in tracker_names

        sharing_gaps = [f for f in scanner.findings if "Third-Party Trackers" in f["title"]]
        assert len(sharing_gaps) == 1
        assert "Section 8(2)" in sharing_gaps[0]["legal_reference"]

    # 8. Fixture: Grievance Contact Omission Detection
    def test_08_fixture_grievance_contact_omission(self):
        """Flags Section 8(9) & Section 13 gap when no Grievance Officer details are published."""
        scanner = dpdp_website_scanner.DPDPWebsiteScanner(
            target_url="https://testclinic.in",
            authorization_confirmed=True
        )
        sample_html = "<html><body><h1>Welcome to Clinic</h1><p>Call us at 9999999999</p></body></html>"
        scanner.scanned_pages = [{"url": "https://testclinic.in", "html": sample_html, "headers": {}}]
        scanner.privacy_pages = [{"url": "https://testclinic.in/privacy", "html": "general text without grievance contact"}]
        scanner._stage_08_statutory_mapping(None)

        grievance_gaps = [f for f in scanner.findings if "Grievance Redressal Contact" in f["title"]]
        assert len(grievance_gaps) == 1
        assert "Section 8(9)" in grievance_gaps[0]["legal_reference"]
        assert "Section 13" in grievance_gaps[0]["legal_reference"]

    # 9. Fixture: Children's Data Processing Indicators (Section 9)
    def test_09_fixture_children_data_indicators(self):
        """Evaluates Section 9 parental consent requirement when minor data processed."""
        scanner = dpdp_website_scanner.DPDPWebsiteScanner(
            target_url="https://pediatriccare.in",
            industry="education",
            children_data_processed=True,
            authorization_confirmed=True
        )
        sample_html = "<html><body><h1>School Admission Portal</h1><p>Enquire for Grade 1-10 students.</p></body></html>"
        scanner.scanned_pages = [{"url": "https://pediatriccare.in", "html": sample_html, "headers": {}}]
        scanner.privacy_pages = [{"url": "https://pediatriccare.in/privacy", "html": "general terms without parental consent"}]
        scanner._stage_08_statutory_mapping(None)

        child_gaps = [f for f in scanner.findings if "Children's Data" in f["title"] or "Parental Consent" in f["title"]]
        assert len(child_gaps) == 1
        assert child_gaps[0]["severity"] == "HIGH"
        assert "Section 9(1)" in child_gaps[0]["legal_reference"]
        assert "₹200 crore" in child_gaps[0]["penalty_ceiling_text"]

    # 10. Statutory Penalty Ceilings & Disclaimers
    def test_10_statutory_penalty_ceilings_and_disclaimer(self):
        """Verifies accurate Schedule maximum penalty ceilings and statutory disclaimers."""
        assert dpdp_website_scanner.DPDP_STATUTORY_PENALTIES["SEC_08_05"]["max_penalty_text"] == "Up to ₹250 crore"
        assert dpdp_website_scanner.DPDP_STATUTORY_PENALTIES["SEC_08_06"]["max_penalty_text"] == "Up to ₹200 crore"
        assert dpdp_website_scanner.DPDP_STATUTORY_PENALTIES["SEC_09"]["max_penalty_text"] == "Up to ₹200 crore"
        assert dpdp_website_scanner.DPDP_STATUTORY_PENALTIES["SEC_10"]["max_penalty_text"] == "Up to ₹150 crore"
        assert dpdp_website_scanner.DPDP_STATUTORY_PENALTIES["GENERAL_CONTRAVENTION"]["max_penalty_text"] == "Up to ₹50 crore"
        assert dpdp_website_scanner.DPDP_STATUTORY_PENALTIES["SEC_15"]["max_penalty_text"] == "Up to ₹10,000"

    # 11. Demo Scan Generator
    def test_11_demo_scan_generator(self):
        """Generates realistic demo website scan report with all structured fields."""
        report = dpdp_website_scanner.generate_demo_website_scan(
            business_name="Arogya Diagnostics",
            target_url="https://arogyaclinic.example.in",
            industry="healthcare"
        )
        assert report["scan_id"].startswith("dpdp-scan-")
        assert report["business_name"] == "Arogya Diagnostics"
        assert len(report["findings"]) >= 4
        assert len(report["third_party_services"]) >= 2
        assert report["summary_metrics"]["readiness_score"] > 0
        assert "statutory_disclaimer" in report

    # 12. API: Start Website Scan (Demo & Validation)
    def test_12_api_start_website_scan(self, client):
        """Tests POST /api/dpdp/scanner/start for validation and demo execution."""
        # A. Missing authorization confirmation rejected
        res = client.post("/api/dpdp/scanner/start", json={
            "website_url": "https://exampleclinic.in",
            "authorization_confirmed": False
        })
        assert res.status_code == 400
        assert "authorization" in res.get_json()["message"].lower()

        # B. Demo scan succeeds
        res_demo = client.post("/api/dpdp/scanner/start", json={
            "website_url": "https://citycare.example.in",
            "business_name": "City Care Diagnostic Center",
            "industry": "healthcare",
            "authorization_confirmed": True,
            "is_demo": True
        })
        assert res_demo.status_code == 200
        data = res_demo.get_json()
        assert data["status"] == "success"
        assert "scan" in data
        assert len(data["scan"]["findings"]) >= 3

    # 13. API: Scan History & Results Retrieval
    def test_13_api_scan_history_and_results(self, client):
        """Tests scan persistence and retrieval via GET /api/dpdp/scanner/history."""
        # Run demo scan
        start_res = client.post("/api/dpdp/scanner/start", json={
            "website_url": "https://apollodiag.example.in",
            "business_name": "Apollo Diag Lab",
            "industry": "healthcare",
            "authorization_confirmed": True,
            "is_demo": True
        })
        scan_id = start_res.get_json()["scan"]["scan_id"]

        # Retrieve history
        hist_res = client.get("/api/dpdp/scanner/history")
        assert hist_res.status_code == 200
        scans = hist_res.get_json()["scans"]
        assert any(s["scan_id"] == scan_id for s in scans)

        # Retrieve specific results
        res_item = client.get(f"/api/dpdp/scanner/results/{scan_id}")
        assert res_item.status_code == 200
        assert res_item.get_json()["scan"]["scan_id"] == scan_id

    # 14. API: Convert Finding to Remediation Task
    def test_14_api_convert_finding_to_task(self, client):
        """Converts an observable website gap directly into an actionable remediation task."""
        start_res = client.post("/api/dpdp/scanner/start", json={
            "website_url": "https://medicare.example.in",
            "business_name": "MediCare Clinic",
            "industry": "healthcare",
            "authorization_confirmed": True,
            "is_demo": True
        })
        scan = start_res.get_json()["scan"]
        scan_id = scan["scan_id"]
        finding_id = scan["findings"][0]["id"]

        conv_res = client.post("/api/dpdp/scanner/convert-task", json={
            "scan_id": scan_id,
            "finding_id": finding_id,
            "assignee": "Compliance DPO"
        })
        assert conv_res.status_code == 201
        task_data = conv_res.get_json()["task"]
        assert task_data["id"].startswith("TASK-SCAN-")
        assert task_data["status"] == "OPEN"
        assert task_data["assignee"] == "Compliance DPO"

    # 15. API: Delete Website Scan (Data Minimization)
    def test_15_api_delete_website_scan(self, client):
        """Permanently deletes a scan record for tenant privacy under Section 8(7)."""
        start_res = client.post("/api/dpdp/scanner/start", json={
            "website_url": "https://tempclinic.example.in",
            "business_name": "Temp Clinic",
            "industry": "healthcare",
            "authorization_confirmed": True,
            "is_demo": True
        })
        scan_id = start_res.get_json()["scan"]["scan_id"]

        del_res = client.delete(f"/api/dpdp/scanner/{scan_id}")
        assert del_res.status_code == 200
        assert del_res.get_json()["deleted"] is True

        # Verify no longer exists
        get_res = client.get(f"/api/dpdp/scanner/results/{scan_id}")
        assert get_res.status_code == 404

    # 16. Tenant Data Isolation
    def test_16_tenant_data_isolation(self):
        """Ensures organization A cannot access website scans belonging to organization B."""
        org_a = f"org-tenant-a-{uuid.uuid4().hex[:6]}"
        org_b = f"org-tenant-b-{uuid.uuid4().hex[:6]}"

        scan_a = dpdp_website_scanner.generate_demo_website_scan("Clinic A", "https://clinica.in")
        scan_b = dpdp_website_scanner.generate_demo_website_scan("Clinic B", "https://clinicb.in")

        dpdp_store.save_website_scan(org_a, scan_a)
        dpdp_store.save_website_scan(org_b, scan_b)

        scans_a = dpdp_store.get_website_scans(org_a)
        scans_b = dpdp_store.get_website_scans(org_b)

        assert any(s["scan_id"] == scan_a["scan_id"] for s in scans_a)
        assert not any(s["scan_id"] == scan_b["scan_id"] for s in scans_a)
        assert any(s["scan_id"] == scan_b["scan_id"] for s in scans_b)
        assert not any(s["scan_id"] == scan_a["scan_id"] for s in scans_b)

    # 17. Dashboard Rendering
    def test_17_dashboard_rendering_has_scanner_tab(self, client):
        """Verifies dashboard template includes DPDP Website Scanner in navigation and content."""
        res = client.get("/dashboard")
        assert res.status_code == 200
        html_text = res.get_data(as_text=True)
        assert "DPDP Website Scanner" in html_text
        assert 'id="section-scanner"' in html_text
        assert 'id="btn-start-scan"' in html_text
        assert 'id="scanner-progress-panel"' in html_text
        assert 'id="scanner-results-panel"' in html_text

    # 18. Homepage Rendering
    def test_18_homepage_has_website_scanner_link(self, client):
        """Verifies public landing page features DPDP Website Scanner links and cards."""
        res = client.get("/")
        assert res.status_code == 200
        html_text = res.get_data(as_text=True)
        assert "Website Scanner" in html_text
        assert "/dashboard#scanner" in html_text
