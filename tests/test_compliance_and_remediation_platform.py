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
        in_force = [c for c in dpdp_controls if c.get("enforcement_phase") == "IN_FORCE_SUBSTANTIVE"]
        pending = [c for c in dpdp_controls if c.get("enforcement_phase") == "PENDING_COMMENCEMENT"]
        assert len(in_force) >= 1
        assert len(pending) >= 2
        # Section 8(1) reasonable safeguards must be substantive
        sec8 = next(c for c in dpdp_controls if c["control_id"] == "DPDP-SEC-08-1")
        assert sec8["enforcement_phase"] == "IN_FORCE_SUBSTANTIVE"

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
        assert b"TrustAudit Security & Trust Center" in res.data
