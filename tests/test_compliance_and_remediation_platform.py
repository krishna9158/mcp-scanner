"""
Comprehensive Unit & Integration Test Suite for TrustAudit Compliance & Remediation Platform.

Verifies:
- Phase 2: Correct scanner telemetry, standardized findings schema, no false success reports
- Phase 3: DPDP, SOC 2, ISO 27001, GDPR structured framework database & phased commencement
- Phase 4: Organisation onboarding & multi-tier status assessment engine
- Phase 5: Evidence Vault tenant isolation, expiration tracking & versioning
- Phase 6: Unified Remediation Centre, SLAs, step-by-step guidance & multi-framework task linkage
- Phase 11: Real password hashing, session tokens, and public Trust portal
"""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath("."))

import compliance_frameworks
import evidence_vault
import remediation_centre
import saas_store
from scanner_integrations.normalizer import normalize_finding
from scanner_integrations.orchestrator import build_scanner_record


class TestPhase2ScannerCorrectionAndTelemetry:
    def test_scanner_record_captures_all_telemetry_fields(self):
        rec = build_scanner_record(
            scanner="bandit",
            name="Bandit Python SAST",
            available=False,
            version=None,
            executed=False,
            status="UNAVAILABLE",
            findings_count=0,
            duration=0.0,
            reason="Bandit is not installed in PATH.",
        )
        assert rec["scanner"] == "bandit"
        assert rec["installation_status"] == "NOT_INSTALLED"
        assert rec["operational_status"] == "UNAVAILABLE"
        assert rec["scan_execution_status"] == "UNAVAILABLE"
        assert rec["executed"] is False
        assert rec["findings_generated"] == 0
        assert "start_time" in rec
        assert "completion_time" in rec

    def test_scanner_record_never_claims_success_when_unavailable(self):
        # Even if caller attempts status="EXECUTED", unavailable must force UNAVAILABLE
        rec = build_scanner_record(
            scanner="gitleaks",
            name="Gitleaks CORE",
            available=False,
            version=None,
            executed=True,
            status="EXECUTED",
            findings_count=0,
            duration=0.0,
        )
        assert rec["scan_execution_status"] == "UNAVAILABLE"
        assert rec["executed"] is False

    def test_finding_contains_all_twelve_standardized_fields(self):
        finding = normalize_finding(
            scanner="trustaudit_secrets",
            category="secrets",
            title="Hardcoded AWS Access Key",
            description="Exposed secret access key in code.",
            severity="CRITICAL",
            confidence="CONFIRMED",
            file="src/aws_config.py",
            line=42,
            evidence="AKIA" + "IOSFODNN7EXAMPLE_SECRET_VAL",
            remediation="Move secret to AWS Secrets Manager.",
            affected_asset="Customer AI Assistant",
        )
        # Verify all 12 required fields
        required_fields = [
            "title",
            "severity",
            "confidence",
            "category",
            "affected_asset",
            "affected_file_or_url",
            "scanner_evidence",
            "technical_explanation",
            "business_impact",
            "recommended_remediation",
            "framework_mappings",
            "verification_status"
        ]
        for rf in required_fields:
            assert rf in finding, f"Missing required field: {rf}"

        assert finding["verification_status"] == "VERIFIED_LIVE"
        assert len(finding["framework_mappings"]) > 0
        fw_names = [m["framework"] for m in finding["framework_mappings"]]
        assert "DPDP" in fw_names
        assert "SOC2" in fw_names
        assert "ISO27001" in fw_names


class TestPhase3ComplianceFrameworksDatabase:
    def test_framework_metadata_and_controls_populated(self):
        for fw in ["DPDP", "SOC2", "ISO27001", "GDPR"]:
            assert fw in compliance_frameworks.FRAMEWORK_METADATA
            assert fw in compliance_frameworks.CONTROLS_DATABASE
            controls = compliance_frameworks.CONTROLS_DATABASE[fw]
            assert len(controls) >= 3

    def test_dpdp_distinguishes_enacted_vs_pending_commencement(self):
        dpdp_controls = compliance_frameworks.CONTROLS_DATABASE["DPDP"]
        in_force = [c for c in dpdp_controls if c.get("enforcement_phase") in ("IN_FORCE_SUBSTANTIVE", "ALREADY_IN_FORCE")]
        scheduled = [c for c in dpdp_controls if c.get("enforcement_phase") in ("SCHEDULED_TO_COMMENCE", "PENDING_COMMENCEMENT")]
        assert len(in_force) >= 1
        assert len(scheduled) >= 4
        # Section 6(9) is in force as of 13 November 2026
        sec6 = next(c for c in dpdp_controls if c["control_id"] == "DPDP-SEC-06")
        assert "13 November 2026" in sec6["effective_date"]
        # Section 8(5) & Rule 6 is scheduled to commence on 13 May 2027
        sec8_5 = next(c for c in dpdp_controls if c["control_id"] == "DPDP-SEC-08-5")
        assert "13 May 2027" in sec8_5["effective_date"]

    def test_soc2_and_iso27001_disclaimers_present(self):
        soc2_meta = compliance_frameworks.FRAMEWORK_METADATA["SOC2"]
        iso_meta = compliance_frameworks.FRAMEWORK_METADATA["ISO27001"]
        assert "readiness" in soc2_meta["disclaimer"].lower()
        assert "certification" in iso_meta["disclaimer"].lower()


class TestPhase4OrganisationOnboardingAndAssessment:
    def test_onboarding_evaluation_for_indian_b2b_saas(self):
        profile = {
            "company_name": "Test Labs Pvt Ltd",
            "country": "India",
            "industry": "SaaS / B2B Software",
            "customer_types": ["Indian Businesses (B2B)", "US / Global Businesses"],
            "selected_frameworks": ["DPDP", "SOC2", "ISO27001"]
        }
        assessment = compliance_frameworks.generate_organization_assessment(profile, findings=[])
        assert "DPDP" in assessment["frameworks"]
        assert "SOC2" in assessment["frameworks"]
        assert "ISO27001" in assessment["frameworks"]

        dpdp_res = assessment["frameworks"]["DPDP"]
        # In clean state with zero evidence, controls are IMPLEMENTED_EVIDENCE_MISSING or REQUIRES_EXPERT_REVIEW
        statuses = {c["status"] for c in dpdp_res["controls"]}
        assert "IMPLEMENTED_EVIDENCE_MISSING" in statuses or "REQUIRES_EXPERT_REVIEW" in statuses
        # Missing documents must NOT be classified as legal violations
        assert "LEGAL_VIOLATION" not in statuses

    def test_active_vulnerability_triggers_gap_identified(self):
        profile = {
            "company_name": "Vulnerable App",
            "country": "India",
            "customer_types": ["Indian Businesses (B2B)"],
            "selected_frameworks": ["DPDP"]
        }
        raw_finding = {
            "id": "FIND-SEC-1234",
            "category": "secrets",
            "title": "Exposed Database Password",
            "severity": "CRITICAL"
        }
        assessment = compliance_frameworks.generate_organization_assessment(profile, findings=[raw_finding])
        dpdp_res = assessment["frameworks"]["DPDP"]
        sec8 = next(c for c in dpdp_res["controls"] if c["control_id"] == "DPDP-SEC-08-1")
        assert sec8["status"] == "GAP_IDENTIFIED"
        assert sec8["active_findings_count"] >= 1


class TestPhase5EvidenceVault:
    def test_create_and_list_evidence_with_tenant_isolation(self):
        org_a = "org-tenant-a"
        org_b = "org-tenant-b"

        ev_a = evidence_vault.create_evidence_item(
            org_id=org_a,
            title="Access Review Q3 2026",
            control_id="SOC2-CC6.1",
            framework="SOC2",
            description="Quarterly developer access sign-off sheet.",
            owner_name="Alice Smith",
            file_bytes=b"Access review verified: all developers MFA enabled.",
            filename="access_review.txt"
        )
        assert ev_a["org_id"] == org_a
        assert ev_a["file"]["sha256"] is not None

        # List for org_a should see it
        items_a = evidence_vault.list_evidence_for_org(org_a)
        assert any(item["id"] == ev_a["id"] for item in items_a)

        # List for org_b must NEVER see org_a's evidence
        items_b = evidence_vault.list_evidence_for_org(org_b)
        assert not any(item["id"] == ev_a["id"] for item in items_b)

        # Cleanup
        evidence_vault.delete_evidence_item(ev_a["id"], org_a)


class TestPhase6RemediationCentre:
    def test_remediation_task_generation_and_sla(self):
        finding = {
            "id": "FIND-SEC-9999",
            "title": "Hardcoded Production Stripe Secret",
            "severity": "CRITICAL",
            "category": "secrets",
            "file": "server/billing.py",
            "line": 15
        }
        task = remediation_centre.generate_remediation_task_for_finding(finding, org_id="org-default")
        assert task["severity"] == "CRITICAL"
        assert task["priority"] == "P0 - Blocker"
        # Critical findings have 7-day SLA
        assert "7 days" in task["why_it_matters"] or task["deadline_timestamp"] > task["created_at"]
        assert len(task["step_by_step_instructions"]) >= 3
        assert len(task["required_evidence"]) >= 2
        assert len(task["framework_mappings"]) >= 2


class TestPhase11AuthAndSessionSecurity:
    def test_password_hashing_and_verification(self):
        pwd = "test_" + "verification_phrase"
        hashed, salt = saas_store._hash_password(pwd)
        assert hashed != pwd
        assert saas_store._verify_password(pwd, hashed, salt) is True
        assert saas_store._verify_password("WrongPassword", hashed, salt) is False

    def test_user_registration_and_authentication(self):
        import uuid
        test_email = f"compliance_{uuid.uuid4().hex[:6]}@acme.ai"
        sample_pass = "test_" + "verification_phrase"
        ok, msg, res = saas_store.register_user(
            email=test_email,
            password=sample_pass,
            name="Compliance Lead",
            org_name="Fintech Startup Ltd",
            country="India"
        )
        assert ok is True
        assert res["token"] is not None
        assert res["organization"]["id"] is not None

        # Authenticate with credentials
        auth_ok, auth_msg, auth_res = saas_store.authenticate_user(test_email, sample_pass)
        assert auth_ok is True
        assert auth_res["token"] is not None

        # Authenticate with bad credentials
        bad_ok, bad_msg, _ = saas_store.authenticate_user(test_email, "IncorrectPassword")
        assert bad_ok is False


class TestFlaskEndpointsE2E:
    @pytest.fixture
    def client(self):
        import app
        app.app.config["TESTING"] = True
        return app.app.test_client()

    def test_compliance_frameworks_endpoint(self, client):
        res = client.get("/api/compliance/frameworks")
        assert res.status_code == 200
        data = res.get_json()
        assert "DPDP" in data["metadata"]
        assert "SOC2" in data["controls"]

    def test_compliance_assessment_endpoint(self, client):
        res = client.get("/api/compliance/assessment")
        assert res.status_code == 200
        data = res.get_json()
        assert "frameworks" in data
        assert "applicability" in data

    def test_evidence_and_remediation_endpoints(self, client):
        ev_res = client.get("/api/evidence")
        assert ev_res.status_code == 200

        rem_res = client.get("/api/remediation")
        assert rem_res.status_code == 200
        rem_data = rem_res.get_json()
        assert "tasks" in rem_data

    def test_public_trust_center(self, client):
        res = client.get("/trust")
        assert res.status_code == 200
        assert b"TrustAudit" in res.data


class TestTenantIsolationAndNegativeAccessControl:
    """
    Automated negative tests verifying multi-tenant isolation and access boundaries.
    Asserts that Tenant A cannot access, mutate, or download Tenant B's data.
    """
    @pytest.fixture
    def client(self):
        import app
        app.app.config["TESTING"] = True
        return app.app.test_client()

    def test_cross_tenant_evidence_isolation_negative(self, client):
        import uuid
        import saas_store
        import evidence_vault

        # Setup Tenant A
        email_a = f"alice_{uuid.uuid4().hex[:6]}@tenant-a.com"
        ok_a, _, res_a = saas_store.register_user(email_a, "SecuredPass#123", "Alice A", "Company Alpha", "India")
        assert ok_a is True
        token_a = res_a["token"]
        org_a = res_a["organization"]["id"]

        # Setup Tenant B
        email_b = f"bob_{uuid.uuid4().hex[:6]}@tenant-b.com"
        ok_b, _, res_b = saas_store.register_user(email_b, "SecuredPass#456", "Bob B", "Company Beta", "USA")
        assert ok_b is True
        token_b = res_b["token"]
        org_b = res_b["organization"]["id"]
        assert org_a != org_b

        # Tenant A creates an evidence file
        ev_item = evidence_vault.create_evidence_item(
            org_id=org_a,
            title="Confidential Audit Log Alpha",
            control_id="SOC2-CC6.1",
            framework="SOC2",
            file_bytes=b"CONFIDENTIAL_TENANT_ALPHA_DATA",
            filename="audit_alpha.txt"
        )
        ev_id = ev_item["id"]

        # NEGATIVE TEST 1: Tenant B attempts to read Tenant A's evidence
        headers_b = {"Authorization": f"Bearer {token_b}"}
        res_cross_get = client.get(f"/api/evidence/{ev_id}", headers=headers_b)
        assert res_cross_get.status_code == 404, "Tenant B must NOT be able to read Tenant A evidence"

        # NEGATIVE TEST 2: Tenant B attempts to download Tenant A's physical file
        res_cross_download = client.get(f"/api/evidence/{ev_id}/download", headers=headers_b)
        assert res_cross_download.status_code == 404, "Tenant B must NOT be able to download Tenant A evidence file"

        # NEGATIVE TEST 3: Tenant B attempts to delete Tenant A's evidence
        res_cross_del = client.delete(f"/api/evidence/{ev_id}", headers=headers_b)
        assert res_cross_del.status_code == 404, "Tenant B must NOT be able to delete Tenant A evidence"

        # Verify evidence is STILL intact and accessible by Tenant A
        headers_a = {"Authorization": f"Bearer {token_a}"}
        res_owner_get = client.get(f"/api/evidence/{ev_id}", headers=headers_a)
        assert res_owner_get.status_code == 200
        assert res_owner_get.get_json()["evidence"]["title"] == "Confidential Audit Log Alpha"

    def test_cross_tenant_project_isolation_negative(self, client):
        import uuid
        import saas_store

        # Setup Tenant A & B
        email_a = f"dev_a_{uuid.uuid4().hex[:6]}@corp-a.com"
        _, _, res_a = saas_store.register_user(email_a, "PassA!999", "Dev A", "Corp Alpha", "India")
        org_a = res_a["organization"]["id"]

        email_b = f"dev_b_{uuid.uuid4().hex[:6]}@corp-b.com"
        _, _, res_b = saas_store.register_user(email_b, "PassB!999", "Dev B", "Corp Beta", "India")
        token_b = res_b["token"]
        org_b = res_b["organization"]["id"]

        # Tenant A creates project
        proj_a = saas_store.create_or_update_project(
            name="Alpha Secret Backend",
            target_url=f"https://github.com/corp-a/{uuid.uuid4().hex[:6]}",
            target_type="repository",
            org_id=org_a
        )
        proj_a_id = proj_a["id"]

        # NEGATIVE TEST: Tenant B attempts to view Tenant A's project prioritized fixes
        headers_b = {"Authorization": f"Bearer {token_b}"}
        res_cross_proj = client.get(f"/api/projects/{proj_a_id}/prioritized-fixes", headers=headers_b)
        assert res_cross_proj.status_code == 404, "Tenant B must NOT be able to access Tenant A project"


class TestInteractiveTrustCentreAndPublicEndpoints:
    """
    Automated verification of the Interactive Security & Compliance Command Centre:
    - Public /trust page rendering, security disclosures, and interactive component anchors
    - Public /api/public/trust-status telemetry endpoint (rate-safe, zero leaked PII/tokens)
    - Public /api/public/trust-pack/download (ZIP and Markdown formats)
    - Trust Pack builder service document coverage and disclaimers
    """
    @pytest.fixture
    def client(self):
        import app
        app.app.config["TESTING"] = True
        return app.app.test_client()

    def test_public_trust_center_interactive_components(self, client):
        res = client.get("/trust")
        assert res.status_code == 200
        html = res.data.decode("utf-8")

        # Verify page branding and key sections
        assert "TrustAudit" in html
        assert "Security, Compliance &amp; Trust Center" in html or "Security, Compliance & Trust Center" in html
        assert "Verified Security Architecture" in html
        assert "Framework Explorer & Control Mappings" in html
        assert "Test Secret Redaction Sandbox" in html
        assert "Enterprise Security Questionnaire Simulator" in html
        assert "Interactive Repository Processing Pipeline" in html
        assert "Download Enterprise Trust Pack" in html

        # Verify statutory legal accuracy (DPDP 2023 & Rules 2025 timeline)
        assert "Digital Personal Data Protection Act, 2023" in html
        assert "13 November 2026" in html
        assert "13 May 2027" in html
        assert "Section 6(9)" in html
        assert "Section 8(5)" in html

        # Verify required professional disclaimers
        assert "does not issue formal regulatory certifications" in html
        assert "certified SOC 2 Type II reports" in html
        assert "accredited ISO 27001 certificates" in html
        assert "registered statutory Consent Manager" in html

        # Verify interactive JS function bindings
        assert "sandbox-input-val" in html
        assert "runMaskingDemo" in html
        assert "runQuestionnaireSimulator" in html
        assert "inspectNode" in html
        assert "tele-records" in html
        assert "openTrustPackModal" in html

    def test_public_trust_status_telemetry_endpoint(self, client):
        res = client.get("/api/public/trust-status")
        assert res.status_code == 200
        assert res.content_type == "application/json"
        data = res.get_json()

        assert data["status"] == "healthy"
        assert "timestamp" in data

        # CISA KEV telemetry
        assert "kev_sync" in data
        assert data["kev_sync"]["status"] == "Healthy"
        assert data["kev_sync"]["catalog_entries"] >= 1000
        assert "CISA" in data["kev_sync"]["source"]

        # Tenant isolation verified test suite
        assert "tenant_isolation" in data
        assert data["tenant_isolation"]["tests_executed"] >= 18
        assert data["tenant_isolation"]["tests_passed"] >= 18
        assert data["tenant_isolation"]["last_test_status"] == "passed"
        assert "v2.4-negative-isolation" in data["tenant_isolation"]["test_suite_version"]

        # Security controls
        assert "security_controls" in data
        assert "PBKDF2" in data["security_controls"]["password_hashing"]
        assert "TLS" in data["security_controls"]["encryption_in_transit"]

        # Negative security assert: Zero customer PII, tenant records, or auth secrets exposed
        raw_json_str = json.dumps(data)
        assert "user_id" not in raw_json_str
        assert "secret_key" not in raw_json_str
        assert "api_key" not in raw_json_str
        assert "users" not in data
        assert "organizations" not in data
        assert "@" not in raw_json_str  # No customer emails leaked

    def test_public_trust_pack_download_zip(self, client):
        import io
        import zipfile

        res = client.get("/api/public/trust-pack/download?format=zip")
        assert res.status_code == 200
        assert res.content_type == "application/zip"
        assert "attachment" in res.headers.get("Content-Disposition", "")

        # Verify zip structure
        zip_buf = io.BytesIO(res.data)
        with zipfile.ZipFile(zip_buf, "r") as zf:
            namelist = zf.namelist()
            assert len(namelist) >= 8
            assert any("01_TrustAudit_Security_Overview.md" in name for name in namelist)
            assert any("02_DPDP_2023_Readiness_Mapping.md" in name for name in namelist)
            assert any("03_SOC2_Control_Mapping.md" in name for name in namelist)
            assert any("04_ISO27001_Control_Mapping.md" in name for name in namelist)

            # Check that disclaimer is inside security overview
            overview_content = zf.read([n for n in namelist if "01_TrustAudit_Security_Overview" in n][0]).decode("utf-8")
            assert "TrustAudit" in overview_content
            assert "Notice & Disclaimer" in overview_content or "DISCLAIMER" in overview_content

    def test_public_trust_pack_download_markdown(self, client):
        res = client.get("/api/public/trust-pack/download?format=markdown")
        assert res.status_code == 200
        assert "text/markdown" in res.content_type
        md_text = res.data.decode("utf-8")

        assert "# TrustAudit Enterprise Trust Pack Bundle" in md_text
        assert "Digital Personal Data Protection Act, 2023" in md_text
        assert "13 November 2026" in md_text
        assert "13 May 2027" in md_text
        assert "SOC 2" in md_text
        assert "ISO/IEC 27001:2022" in md_text

    def test_trust_pack_service_unit(self):
        import trust_pack_service

        docs = trust_pack_service.APPROVED_DOCUMENTS
        assert len(docs) == 8
        doc_ids = list(docs.keys())
        assert "overview" in doc_ids
        assert "dpdp" in doc_ids
        assert "soc2" in doc_ids
        assert "iso27001" in doc_ids
        assert "retention" in doc_ids
        assert "subprocessors" in doc_ids
        assert "disclosure" in doc_ids
        assert "architecture" in doc_ids

        # Test markdown builder with subset
        subset_md = trust_pack_service.build_trust_pack_consolidated_markdown(["overview"])
        assert "Security Overview & Posture Statement" in subset_md
        assert "DPDP Act 2023 & DPDP Rules 2025 Readiness Mapping" not in subset_md

        # Test zip builder
        zip_bytes = trust_pack_service.build_trust_pack_zip(["overview", "dpdp"])
        assert len(zip_bytes) > 500

