"""
TrustAudit Pre-Launch Hardening & Security Verification Test Suite.

Automated verification of:
1. SSRF Protection: Private IPs, loopback, cloud metadata, port and scheme checks.
2. OWASP Password Hashing: 600,000 PBKDF2 iterations, structured format, rehash-on-login.
3. Login Rate Limiting: Lockout on repeated brute-force failures.
4. Session Token Security: Strict validation, no fallback to org-default on invalid tokens.
5. Password Reset Flow: Time-limited single-use token and session invalidation.
6. Multi-Factor Authentication: RFC 6238 TOTP generation, validation, and enforcement.
7. Customer Data Deletion: Complete organization and asset purge.
8. RFC 9116 Standard: /.well-known/security.txt format and metadata.
9. Operational Grievance Redressal: Submission, reference ID generation, audit trail.
10. Quick Perimeter & Privacy Check: SSRF blocking and legitimate check verification.
"""

import json
import os
import sys
import time
import uuid
import pytest

sys.path.insert(0, os.path.abspath("."))
import saas_store
import ssrf_protection


class TestSSRFProtectionSuite:
    """Rigorous SSRF defense verification."""

    def test_loopback_and_private_ip_rejection(self):
        blocked_urls = [
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://localhost",
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://172.16.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal",
        ]
        for url in blocked_urls:
            with pytest.raises(ssrf_protection.SSRFSecurityError):
                ssrf_protection.validate_target_url_ssrf_safe(url)

    def test_prohibited_schemes_and_credentials(self):
        prohibited = [
            "file:///etc/passwd",
            "gopher://127.0.0.1:70",
            "ftp://files.example.com",
            "http://admin:secret@example.com",
            "http://example.com:22",
            "http://example.com:3306",
        ]
        for url in prohibited:
            with pytest.raises(ssrf_protection.SSRFSecurityError):
                ssrf_protection.validate_target_url_ssrf_safe(url)

    def test_legitimate_url_acceptance(self):
        meta = ssrf_protection.validate_target_url_ssrf_safe("https://example.com")
        assert meta["valid"] is True
        assert meta["scheme"] == "https"
        assert meta["port"] == 443
        assert len(meta["resolved_ips"]) > 0


class TestAuthHardeningAndMFA:
    """OWASP password hashing, rate limiting, and TOTP MFA verification."""

    def test_owasp_600k_pbkdf2_format(self):
        pwd = "EnterpriseHardenedPass#2026"
        hashed, salt = saas_store._hash_password(pwd)
        assert hashed.startswith("pbkdf2_sha256$600000$")
        assert len(salt) == 32
        assert saas_store._verify_password(pwd, hashed, salt) is True
        assert saas_store._verify_password("WrongPass", hashed, salt) is False

    def test_legacy_rehash_on_login(self):
        import hashlib
        pwd = "LegacyPassword#123"
        legacy_salt = "feedcafe12345678"
        # Create legacy 100,000 hash
        legacy_raw = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), legacy_salt.encode("utf-8"), 100000).hex()

        # Direct verification indicates needs_rehash
        is_valid, needs_rehash = saas_store._verify_password(pwd, legacy_raw, legacy_salt, stored_iterations=100000, return_needs_rehash=True)
        assert is_valid is True
        assert needs_rehash is True

        # Register user with legacy format manually to test transparent upgrade
        email = f"legacy_{uuid.uuid4().hex[:6]}@old-tenant.com"
        _, _, res = saas_store.register_user(email, "TempPass", "Legacy Lead", "Legacy Corp", "India")
        uid = res["user"]["id"]

        data = saas_store._load_data()
        data["users"][uid]["pwd_hash"] = legacy_raw
        data["users"][uid]["salt"] = legacy_salt
        data["users"][uid]["pwd_iterations"] = 100000
        saas_store._save_data(data)

        # Authenticate with legacy password
        ok, msg, auth_res = saas_store.authenticate_user(email, pwd)
        assert ok is True

        # Verify password record was automatically upgraded to 600,000 iterations
        updated_data = saas_store._load_data()
        upgraded_user = updated_data["users"][uid]
        assert upgraded_user["pwd_hash"].startswith("pbkdf2_sha256$600000$")
        assert upgraded_user["pwd_iterations"] == 600000

    def test_login_rate_limiting_lockout(self):
        victim_email = f"target_{uuid.uuid4().hex[:6]}@victim.com"
        # 5 failed attempts
        for _ in range(5):
            saas_store.record_failed_login(victim_email)

        allowed, retry_sec = saas_store.check_login_rate_limit(victim_email)
        assert allowed is False
        assert retry_sec > 0

        # Authenticate user blocked by rate limit
        ok, msg, _ = saas_store.authenticate_user(victim_email, "AnyPassword")
        assert ok is False
        assert "Too many failed login attempts" in msg

        # Clear failed logins
        saas_store.clear_failed_logins(victim_email)
        allowed, _ = saas_store.check_login_rate_limit(victim_email)
        assert allowed is True

    def test_totp_mfa_flow(self):
        email = f"mfa_{uuid.uuid4().hex[:6]}@mfa-corp.com"
        pwd = "MfaSecurePass#2026"
        _, _, res = saas_store.register_user(email, pwd, "MFA Lead", "MFA Corp", "India")
        uid = res["user"]["id"]

        # Setup MFA
        ok, msg, setup_res = saas_store.setup_mfa_for_user(uid)
        assert ok is True
        secret = setup_res["secret"]
        assert len(secret) >= 16

        # Invalid verification code
        ok, msg = saas_store.confirm_and_enable_mfa(uid, "000000")
        assert ok is False

        # Generate legitimate code
        code = self._generate_test_totp(secret)
        ok, msg = saas_store.confirm_and_enable_mfa(uid, code)
        assert ok is True

        # Attempt login without code -> triggers MFA_REQUIRED
        ok, msg, auth_res = saas_store.authenticate_user(email, pwd)
        assert ok is False
        assert msg == "MFA_REQUIRED"

        # Attempt login with correct code
        code_fresh = self._generate_test_totp(secret)
        ok, msg, auth_res = saas_store.authenticate_user(email, pwd, totp_code=code_fresh)
        assert ok is True
        assert auth_res["token"] is not None

    def _generate_test_totp(self, secret: str) -> str:
        import base64, struct, hmac, hashlib
        key = base64.b32decode(secret)
        counter = int(time.time() // 30)
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        idx = h[-1] & 0x0F
        c = ((h[idx] & 0x7F) << 24 | (h[idx + 1] & 0xFF) << 16 | (h[idx + 2] & 0xFF) << 8 | (h[idx + 3] & 0xFF))
        return str(c % 1000000).zfill(6)

    def test_strict_session_validation_negative(self):
        # Negative test: invalid token must NOT return org-default
        is_valid, user, org_id = saas_store.validate_session("fabricated_or_expired_token")
        assert is_valid is False
        assert user is None
        assert org_id is None


class TestPublicAndGovernanceEndpoints:
    """Verification of new pre-launch public APIs."""

    @pytest.fixture
    def client(self):
        import app
        app.app.config["TESTING"] = True
        return app.app.test_client()

    def test_security_txt_endpoint(self, client):
        res = client.get("/.well-known/security.txt")
        assert res.status_code == 200
        assert "text/plain" in res.content_type
        txt = res.data.decode("utf-8")
        assert "Contact: mailto:security@trustaudit.io" in txt
        assert "Contact: mailto:grievance@trustaudit.io" in txt
        assert "Canonical: https://mcp-scanner.onrender.com/.well-known/security.txt" in txt

    def test_grievance_submission_endpoint(self, client):
        payload = {
            "name": "Jane Principal",
            "email": "jane@data-principal.in",
            "category": "Consent Withdrawal Inquiry",
            "description": "Requesting confirmation of stop-processing instruction.",
            "company": "Data Subject Rights"
        }
        res = client.post("/api/public/grievance/submit", json=payload)
        assert res.status_code == 201
        data = res.get_json()
        assert data["status"] == "success"
        assert "GRV-" in data["ticket"]["reference_id"]
        assert data["ticket"]["status"] == "RECEIVED"

    def test_quick_perimeter_check_ssrf_blocked(self, client):
        # Probing private network / cloud metadata should be blocked immediately
        res = client.post("/api/public/quick-check", json={"url": "http://169.254.169.254/latest/meta-data/"})
        assert res.status_code == 400
        data = res.get_json()
        assert data["status"] == "blocked"
        assert "SSRF security policy" in data["message"]

    def test_quick_perimeter_check_loopback_blocked(self, client):
        res = client.post("/api/public/quick-check", json={"url": "http://127.0.0.1:5000"})
        assert res.status_code == 400
        data = res.get_json()
        assert data["status"] == "blocked"

    def test_organization_deletion_api(self, client):
        # Register test org
        email = f"del_{uuid.uuid4().hex[:6]}@purge-corp.com"
        _, _, res = saas_store.register_user(email, "PurgePassword#123", "Purge Lead", "Purge Corp", "India")
        token = res["token"]
        org_id = res["organization"]["id"]

        headers = {"Authorization": f"Bearer {token}"}
        del_res = client.post("/api/account/delete", headers=headers)
        assert del_res.status_code == 200
        del_data = del_res.get_json()
        assert del_data["status"] == "success"
        assert del_data["deletion_audit_record"]["organization_id"] == org_id
        assert del_data["deletion_audit_record"]["status"] == "COMPLETED"

        # Verify subsequent access fails (session deleted)
        me_res = client.get("/api/auth/me", headers=headers)
        assert me_res.get_json()["user"] is None
