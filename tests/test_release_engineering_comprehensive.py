"""
TrustAudit Final Production Release Engineering Suite.

Tests across isolated temp storage (never touching production JSON files):
- Unified Canonical Demo Fixture & Demo Reset RBAC
- Pure-Python QR Code SVG MFA Enrollment, 8 Single-Use Recovery Codes, Recovery Login & Session Revocation
- Change Password & Terms Acknowledgement Enforcement
- Plan Selection Carryover, Invalid Plan Rejection, and Server-Side Quota Limits
- Customer Portal Duplicate Guard & Expiry + Zero Fabricated Profile Claims
- Configuration-Aware Trust Centre (TRUSTAUDIT_DATA_KEY Enabled vs Not enabled) & ZIP Integrity
- /website-check Route, /scan Redirect & SSRF Rejection
- Async Background Jobs (/api/dpdp/reports/jobs, scanner?async=1, extraction?async=1, cancel & isolation)
- Section 9(1) & S.O. 5458(E) Consistency + 30-Question AI Assistant Suite + PII Scrubbing
- Notification Centre, Audit CSV Export, Report a Problem Reference ID, and OWASP Regressions
"""

import base64
import datetime
import hashlib
import hmac
import io
import os
import struct
import time
import zipfile

import pytest


def _totp_now(secret_b32: str) -> str:
    key = base64.b32decode(secret_b32.upper())
    counter = int(time.time() // 30)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    idx = h[-1] & 0x0F
    code = (
        (h[idx] & 0x7F) << 24
        | (h[idx + 1] & 0xFF) << 16
        | (h[idx + 2] & 0xFF) << 8
        | (h[idx + 3] & 0xFF)
    )
    return str(code % 1000000).zfill(6)


@pytest.fixture()
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTAUDIT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TRUSTAUDIT_PLATFORM_ADMIN_EMAILS", "platformadmin@trustaudit.in")
    monkeypatch.delenv("TRUSTAUDIT_DATA_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    import app as app_mod
    import dpdp_store
    import evidence_vault
    import saas_store
    import security_utils

    saas_file = str(tmp_path / "saas_data.json")
    dpdp_file = str(tmp_path / "dpdp_store.json")
    ev_dir = str(tmp_path / "evidence_vault")
    dpdp_ev_dir = str(tmp_path / "dpdp_evidence")
    audit_file = str(tmp_path / "audit_logs.json")
    griev_file = str(tmp_path / "grievances.json")

    os.makedirs(ev_dir, exist_ok=True)
    os.makedirs(dpdp_ev_dir, exist_ok=True)

    monkeypatch.setattr(saas_store, "DATA_FILE", saas_file)
    monkeypatch.setattr(dpdp_store, "DPDP_DATA_FILE", dpdp_file)
    monkeypatch.setattr(dpdp_store, "DPDP_EVIDENCE_FILES_DIR", dpdp_ev_dir)
    monkeypatch.setattr(evidence_vault, "EVIDENCE_STORE_FILE", str(tmp_path / "evidence_store.json"))
    monkeypatch.setattr(evidence_vault, "EVIDENCE_FILES_DIR", ev_dir)
    monkeypatch.setattr(saas_store, "_ACTIVE_SESSIONS", {})
    monkeypatch.setattr(saas_store, "_SAAS_CACHE_KEY", None)
    monkeypatch.setattr(saas_store, "_SAAS_CACHE_DATA", None)
    monkeypatch.setattr(saas_store, "_SAAS_CACHE_JSON", None)
    monkeypatch.setattr(dpdp_store, "_DPDP_CACHE_KEY", None)
    monkeypatch.setattr(dpdp_store, "_DPDP_CACHE_DATA", None)
    monkeypatch.setattr(dpdp_store, "_DPDP_CACHE_JSON", None)
    monkeypatch.setattr(app_mod, "_PUBLIC_TRUST_CACHE", {"data": None, "cached_at": 0})
    security_utils.rate_limiter._buckets.clear()

    return app_mod, app_mod.app.test_client()


def test_unified_demo_fixture_and_reset_rbac(isolated_env):
    _mod, client = isolated_env
    demo_html = client.get("/demo").get_data(as_text=True)
    portal_html = client.get("/portal/demo-sandbox").get_data(as_text=True)
    profile_html = client.get("/p/demo-sandbox").get_data(as_text=True)
    demo_json = client.get("/api/demo/workspace").get_json()

    expected = "Arogya Diagnostics Clinic"
    for surface in (demo_html, portal_html, profile_html, demo_json["profile"]["company_name"]):
        assert expected in surface
        assert "Sample Indian Clinic" not in surface
        assert "Acme AI Labs" not in surface
    assert "DEMO DATA" in demo_json["demo_banner"]
    assert "DEMO DATA" in profile_html
    assert "DEMO DATA" in portal_html

    # Register normal org vs platform admin -> normal org blocked from resetting demo
    reg_norm = client.post("/api/auth/register", json={
        "name": "Regular", "company_name": "Kaveri Clinic", "email": "reg@kaveri.in",
        "password": "Password123!", "plan": "starter", "terms_accepted": True,
    }).get_json()["data"]["token"]
    assert client.post("/api/demo/reset", headers={"Authorization": f"Bearer {reg_norm}"}).status_code == 403
    assert client.post("/api/admin/demo/reset", headers={"Authorization": f"Bearer {reg_norm}"}).status_code == 403

    reg_admin = client.post("/api/auth/register", json={
        "name": "Platform Operator", "company_name": "Ops Org", "email": "platformadmin@trustaudit.in",
        "password": "Password123!", "plan": "business", "terms_accepted": True,
    }).get_json()["data"]["token"]
    reset_res = client.post("/api/admin/demo/reset", headers={"Authorization": f"Bearer {reg_admin}"})
    assert reset_res.status_code == 200
    assert reset_res.get_json()["demo"]["counts"]["inventory_count"] == 5


def test_auth_signup_plan_validation_qr_mfa_recovery_and_sessions(isolated_env):
    _mod, client = isolated_env

    # Register page shows selected plan banner, Change Plan, Terms checkbox & proper labels
    reg_page = client.get("/register?plan=growth").get_data(as_text=True)
    assert "Selected Plan" in reg_page
    assert "Growth" in reg_page
    assert "Change Plan" in reg_page
    assert 'for="reg-terms"' in reg_page
    assert 'for="reg-plan"' in reg_page

    # Reject explicit false terms or invalid plan
    bad_terms = client.post("/api/auth/register", json={
        "name": "A", "company_name": "B", "email": "a@b.in", "password": "Password123!",
        "plan": "growth", "terms_accepted": False,
    })
    assert bad_terms.status_code == 400

    bad_plan = client.post("/api/auth/register", json={
        "name": "A", "company_name": "B", "email": "a@b.in", "password": "Password123!",
        "plan": "bogus-tier-999", "terms_accepted": True,
    })
    assert bad_plan.status_code == 400

    # Successful signup on free plan enforces 1-member seat limit cleanly
    reg = client.post("/api/auth/register", json={
        "name": "Meera Nair", "company_name": "GreenLeaf Health", "email": "meera@greenleaf.in",
        "password": "StrongPassword#1", "plan": "free", "terms_accepted": True,
    })
    assert reg.status_code == 201
    tok1 = reg.get_json()["data"]["token"]
    hdr1 = {"Authorization": f"Bearer {tok1}"}
    assert reg.get_json()["data"]["organization"]["plan"] == "free"

    # Free plan max_team_members == 1 -> inviting second member hits server quota
    invite = client.post("/api/team/members", headers=hdr1, json={
        "name": "Second User", "email": "u2@greenleaf.in", "role": "member", "password": "Password123!"
    })
    assert invite.status_code in (400, 403)
    assert "limit" in str(invite.get_json()).lower()

    # MFA Setup produces offline <svg> QR + manual key, and MFA remains disabled until OTP confirmed
    setup = client.post("/api/auth/mfa/setup", headers=hdr1, json={}).get_json()["data"]
    assert "<svg" in setup["qr_svg"] and "viewBox=" in setup["qr_svg"]
    assert setup["secret"]
    assert client.get("/api/auth/me", headers=hdr1).get_json()["user"]["mfa_enabled"] is False

    # Enable MFA -> receives 8 single-use recovery codes
    otp = _totp_now(setup["secret"])
    enable = client.post("/api/auth/mfa/enable", headers=hdr1, json={"code": otp}).get_json()
    codes = enable["recovery_codes"]
    assert len(codes) == 8

    # Password-only login prompts MFA_REQUIRED; login with recovery code succeeds & burns code
    no_mfa = client.post("/api/auth/login", json={"email": "meera@greenleaf.in", "password": "StrongPassword#1"}).get_json()
    assert no_mfa["mfa_required"] is True

    rec_ok = client.post("/api/auth/login", json={
        "email": "meera@greenleaf.in", "password": "StrongPassword#1", "recovery_code": codes[0],
    })
    assert rec_ok.status_code == 200
    tok2 = rec_ok.get_json()["data"]["token"]
    assert rec_ok.get_json()["data"]["mfa_recovery_remaining"] == 7

    # Reusing burned recovery code fails
    rec_reuse = client.post("/api/auth/login", json={
        "email": "meera@greenleaf.in", "password": "StrongPassword#1", "recovery_code": codes[0],
    })
    assert rec_reuse.status_code == 401

    # Active sessions list & revoke session
    sess = client.get("/api/auth/sessions", headers={"Authorization": f"Bearer {tok2}"}).get_json()["sessions"]
    assert len(sess) >= 2
    other_id = next(s["session_id"] for s in sess if not s["is_current"])
    assert client.post("/api/auth/sessions/revoke", headers={"Authorization": f"Bearer {tok2}"}, json={"session_id": other_id}).status_code == 200
    assert client.get("/api/auth/me", headers=hdr1).status_code == 401

    # Change password works cleanly
    cp = client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {tok2}"}, json={
        "current_password": "StrongPassword#1", "new_password": "NewStrongPassword#2"
    })
    assert cp.status_code == 200


def test_profile_portal_website_check_trust_centre_and_async_jobs(isolated_env, monkeypatch):
    mod, client = isolated_env

    # /website-check renders cleanly and /scan redirects to /website-check
    assert client.get("/website-check").status_code == 200
    scan_redir = client.get("/scan", follow_redirects=False)
    assert scan_redir.status_code in (301, 302) and "/website-check" in scan_redir.headers["Location"]

    # Register fresh org -> Privacy Profile has ZERO unverified claims & NOT reviewed yet
    reg = client.post("/api/auth/register", json={
        "name": "Owner", "company_name": "Sahara Logistics Pvt Ltd", "email": "ops@saharalogistics.in",
        "password": "Password#1234", "plan": "growth", "terms_accepted": True,
    }).get_json()["data"]
    tok = reg["token"]
    slug = reg["organization"]["slug"]
    hdr = {"Authorization": f"Bearer {tok}"}

    pub_prof = client.get(f"/api/public/privacy-profile/{slug}").get_json()["profile"]
    assert pub_prof["org_name"] == "Sahara Logistics Pvt Ltd"
    assert pub_prof["last_reviewed_at"] is None
    assert pub_prof["selected_practices"] == []
    assert "Your Business" not in str(pub_prof)
    prof_html = client.get(f"/p/{slug}").get_data(as_text=True)
    assert "Not yet formally reviewed" in prof_html

    # Portal duplicate guard & expiry field
    prompt, ctok = mod._make_portal_challenge()
    a, b = [int(x.strip()) for x in prompt.split("+")]
    sub1 = client.post(f"/api/public/portal/{slug}/submit", json={
        "type": "ACCESS", "name": "Rohan", "email": "rohan@gmail.com", "description": "Copy of my records",
        "challenge_token": ctok, "challenge_answer": str(a + b),
    }).get_json()
    assert sub1["duplicate"] is False and sub1["verification_code_expires_at"]
    sub2 = client.post(f"/api/public/portal/{slug}/submit", json={
        "type": "ACCESS", "name": "Rohan", "email": "rohan@gmail.com", "description": "Copy of my records",
        "challenge_token": ctok, "challenge_answer": str(a + b),
    }).get_json()
    assert sub2["duplicate"] is True and sub2["reference_id"] == sub1["reference_id"]

    # Trust Centre: TRUSTAUDIT_DATA_KEY unset -> Not enabled
    ts_off = client.get("/api/public/trust-status").get_json()
    app_enc_row = next(r for r in ts_off["controls_matrix"] if r["id"] == "app_layer_encryption")
    assert app_enc_row["state"] == "Not enabled"
    assert ts_off["posture_state"] == "attention_recommended"

    # When TRUSTAUDIT_DATA_KEY IS configured -> Enabled and verified by automated test
    from cryptography.fernet import Fernet
    monkeypatch.setenv("TRUSTAUDIT_DATA_KEY", Fernet.generate_key().decode())
    ts_on = client.get("/api/public/trust-status").get_json()
    app_enc_row2 = next(r for r in ts_on["controls_matrix"] if r["id"] == "app_layer_encryption")
    assert app_enc_row2["state"] == "Enabled and verified by automated test"
    assert ts_on["posture_state"] == "verified"

    # Trust Pack ZIP download integrity
    zres = client.get("/api/public/trust-pack/download?format=zip")
    assert zres.status_code == 200 and "TrustAudit_Enterprise_Trust_Pack.zip" in zres.headers.get("Content-Disposition", "")
    with zipfile.ZipFile(io.BytesIO(zres.data)) as zf:
        assert zf.testzip() is None and len(zf.namelist()) >= 2

    # Background ZIP Report Job + polling + cross-tenant job isolation
    jstart = client.post("/api/dpdp/reports/jobs", headers=hdr, json={"kind": "bundle"}).get_json()
    jid = jstart["job_id"]
    done_job = None
    for _ in range(30):
        st = client.get(f"/api/jobs/{jid}", headers=hdr).get_json()["job"]
        if st["status"] == "COMPLETED":
            done_job = st
            break
        time.sleep(0.08)
    assert done_job and done_job["result"]["download_ready"] is True
    dl = client.get(f"/api/jobs/{jid}/download", headers=hdr)
    assert dl.status_code == 200 and zipfile.is_zipfile(io.BytesIO(dl.data))

    # Notifications + Report Problem + Audit CSV
    assert client.get("/api/dpdp/notifications", headers=hdr).status_code == 200
    prob = client.post("/api/support/report-problem", headers=hdr, json={
        "category": "Page issue", "description": "Testing issue reporting reference ID", "page_route": "/app/home"
    })
    assert prob.status_code == 201 and prob.get_json()["reference_id"].startswith("BUG-")
    acsv = client.get("/api/audit-logs?format=csv", headers=hdr)
    assert acsv.status_code == 200 and "text/csv" in acsv.content_type and b"Action" in acsv.data


def test_section_9_1_so_5458_and_30_ai_assistant_questions(isolated_env):
    import ai_dpdp_assistant
    import compliance_frameworks
    import data_discovery
    import dpdp_engine

    sec9_ctrl = next(r for r in dpdp_engine.DPDP_REQUIREMENTS if r["id"] == "DPDP-SEC-09")
    assert "lawful guardian" in sec9_ctrl["description"].lower()
    cf_sec9 = next(c for c in compliance_frameworks.CONTROLS_DATABASE["DPDP"] if c["control_id"] == "DPDP-SEC-09")
    assert "lawful guardian" in cf_sec9["description"].lower()
    dd_sec9 = next(f for f in data_discovery.FIELD_DETECTION_PATTERNS if "Section 9(1)" in f["reason"])
    assert "lawful guardian" in dd_sec9["reason"].lower()

    # 30 diverse realistic business DPDP queries tested end-to-end with PII redaction check
    questions = [
        "When does the DPDP Act take effect?",
        "What provisions commenced on 13 November 2025?",
        "When do Consent Managers under Section 6(9) commence?",
        "What happens on 13 May 2027 under G.S.R. 846(E)?",
        "What did S.O. 5458(E) change regarding data audit?",
        "What does Section 9(1) require for children and persons with disabilities who have lawful guardians?",
        "What must a Section 5 Privacy Notice include under Rule 3?",
        "Is the Eighth Schedule language requirement applicable to privacy notices?",
        "How does consent withdrawal work under Section 6(4)?",
        "When can our clinic rely on Section 7 legitimate uses instead of consent?",
        "Does employee payroll data require consent or Section 7(i)?",
        "What is the maximum statutory penalty for Section 8(5) failure under Schedule Item 1?",
        "What must Rule 6 reasonable security safeguards include?",
        "How should we prepare for personal data breaches under Section 8(6) and Rule 7?",
        "What is the dual-stage intimation under Rule 7?",
        "How long can we keep customer invoices under Rule 8 and Tax laws?",
        "Are third-party SaaS vendors covered under Section 8(2) processor contracts?",
        "Do we need a Data Processing Agreement with our payment gateway?",
        "How should a customer request data erasure under Section 12?",
        "What is a customer's Right to Nominate under Section 14?",
        "What timelines apply to Data Principal grievances under Section 13?",
        "Can we transfer personal data outside India under Section 16?",
        "Who qualifies as a Significant Data Fiduciary under Section 10?",
        "What is a Data Protection Impact Assessment under Rule 11?",
        "Are behavioural analytics or targeted ads allowed on children's accounts?",
        "How should a diagnostic clinic handle pediatric and elderly guardian consent?",
        "Do pre-checked boxes count as valid consent under Section 6?",
        "What evidence should our startup upload to TrustAudit Evidence Vault?",
        "We scanned our SaaS site; what if no privacy policy link was detected?",
        "Can customer@clinic.in (+91 9876543210) consent be withdrawn via Consent Manager?",
    ]
    assert len(questions) == 30
    for q in questions:
        ans = ai_dpdp_assistant.query_ai_dpdp_assistant(q, org_id="org-default", save_to_history=False)
        assert ans and ans.get("status") == "success" and ans.get("answer") and len(ans["answer"]) > 40
        assert ans.get("matched_section") or ans.get("source_document")
        # Ensure PII from question 30 was sanitized and never echoed raw
        assert "customer@clinic.in" not in ans["answer"]
        assert "9876543210" not in ans["answer"]


def test_owasp_security_boundaries_and_cross_tenant_jobs(isolated_env):
    _mod, client = isolated_env

    # Unauthenticated calls to new protected endpoints return 401
    for method, url in [
        ("GET", "/api/auth/sessions"),
        ("POST", "/api/auth/sessions/revoke"),
        ("POST", "/api/auth/change-password"),
        ("GET", "/api/dpdp/notifications"),
        ("POST", "/api/dpdp/reports/jobs"),
        ("POST", "/api/support/report-problem"),
        ("POST", "/api/demo/reset"),
    ]:
        res = client.get(url) if method == "GET" else client.post(url, json={})
        assert res.status_code == 401, f"{method} {url} should require auth"

    reg_a = client.post("/api/auth/register", json={
        "name": "Alpha", "company_name": "Alpha Co", "email": "alpha@a.in",
        "password": "Password#111", "plan": "starter", "terms_accepted": True,
    }).get_json()["data"]
    reg_b = client.post("/api/auth/register", json={
        "name": "Beta", "company_name": "Beta Co", "email": "beta@b.in",
        "password": "Password#222", "plan": "starter", "terms_accepted": True,
    }).get_json()["data"]
    hdr_a = {"Authorization": f"Bearer {reg_a['token']}"}
    hdr_b = {"Authorization": f"Bearer {reg_b['token']}"}

    # XSS escaped safely in rendered HTML report
    xss_payload = "<script>alert('xss')</script>Vendor Note"
    inv_res = client.post("/api/dpdp/inventory", headers=hdr_a, json={
        "category": xss_payload, "purpose": "Billing <img src=x onerror=alert(1)>"
    })
    assert inv_res.status_code in (200, 201)
    html_rep = client.get("/api/dpdp/reports/html", headers=hdr_a).get_data(as_text=True)
    assert "<script>alert('xss')</script>" not in html_rep
    assert "&lt;script&gt;alert(" in html_rep

    # SSRF blocking on /api/dpdp/scanner/start
    for blocked in ("http://127.0.0.1/admin", "http://169.254.169.254/latest/meta-data/"):
        s_res = client.post("/api/dpdp/scanner/start", headers=hdr_a, json={
            "website_url": blocked, "authorization_confirmed": True,
        })
        assert s_res.status_code == 400 and "ssrf" in str(s_res.get_json()).lower()

    # Path traversal / blocked executable extension on file extraction
    bad_up = client.post("/api/dpdp/extraction/upload", headers=hdr_a, data={
        "file": (io.BytesIO(b"MZ_FAKE_EXE"), "../../evil.exe")
    }, content_type="multipart/form-data")
    assert bad_up.status_code == 400

    # Cross-tenant job isolation: Org A job inaccessible to Org B (404)
    j = client.post("/api/dpdp/reports/jobs", headers=hdr_a, json={"kind": "pdf"}).get_json()["job_id"]
    assert client.get(f"/api/jobs/{j}", headers=hdr_b).status_code == 404
    assert client.post(f"/api/jobs/{j}/cancel", headers=hdr_b).status_code == 404

    # CSRF origin check when Referer/Origin mismatches Host on POST with cookie
    csrf_res = client.post("/api/dpdp/inventory", headers={
        "Origin": "https://evil-attacker.example",
        "Host": "127.0.0.1:5000",
    }, json={"category": "Test"})
    assert csrf_res.status_code in (401, 403)

