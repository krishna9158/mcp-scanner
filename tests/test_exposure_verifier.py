"""
Unit and Integration Tests for Public Exposure and Sensitive File Detection Engine.

Validates that:
- Real exposed .env is verified and reported with high confidence.
- 404/403 .env responses are NEVER reported as exposed.
- 200 HTML pages and custom 404/SPA fallbacks are rejected (ZERO false positives).
- 301/302 redirects to non-.env paths are rejected.
- Empty .env responses are rejected.
- Confidence levels (LOW, MEDIUM, HIGH, VERIFIED) and structured evidence are populated.
- Historical resolved finding tracking properly marks non-reproducible 404 items.
"""

import pytest
from exposure_verifier import (
    ExposureVerificationResult,
    is_html_or_error_page,
    verify_env_file_exposure,
    verify_git_head_exposure,
    reconcile_resolved_exposure_findings,
)


class TestExposureVerifierUnit:
    """Requirement 16 test cases covering all edge cases for sensitive exposure verification."""

    def test_1_real_exposed_env_with_multiple_signatures(self):
        """Test: Real exposed .env containing multiple standard key-value assignments."""
        env_body = """
# Production Configuration
APP_ENV=production
DATABASE_URL=postgresql://postgres:SuperSecretP@ss123@db.prod.internal:5432/main
SECRET_KEY=9f82d8c3b1a4e5f60718293a4b5c6d7e
JWT_SECRET=super_secret_jwt_token_key_abcdef123456
PORT=8080
"""
        res = verify_env_file_exposure(
            requested_url="https://api.example.com/.env",
            status_code=200,
            content_type="text/plain",
            response_text=env_body,
            final_url="https://api.example.com/.env",
        )
        assert res.is_exposed is True
        assert res.confidence == "VERIFIED"
        assert res.severity == "CRITICAL"
        assert res.http_status == 200
        assert "DATABASE_URL" in res.matched_signatures
        assert "SECRET_KEY" in res.matched_signatures
        assert "JWT_SECRET" in res.matched_signatures
        assert len(res.detection_indicators) >= 2

    def test_2_404_not_found_env(self):
        """Test: 404 Not Found response is never classified as exposed."""
        res = verify_env_file_exposure(
            requested_url="https://example.com/.env",
            status_code=404,
            content_type="text/html",
            response_text="<html><body>404 Not Found</body></html>",
            final_url="https://example.com/.env",
        )
        assert res.is_exposed is False
        assert res.confidence == "NONE"
        assert res.severity == "INFO"

    def test_3_403_forbidden_env(self):
        """Test: 403 Forbidden response is never classified as exposed."""
        res = verify_env_file_exposure(
            requested_url="https://example.com/.env",
            status_code=403,
            content_type="text/html",
            response_text="<html><body>403 Forbidden: Access Denied</body></html>",
            final_url="https://example.com/.env",
        )
        assert res.is_exposed is False
        assert res.confidence == "NONE"
        assert res.severity == "INFO"

    def test_4_200_html_page_rejected(self):
        """Test: HTTP 200 containing normal HTML document is rejected (false positive prevention)."""
        html_body = """<!DOCTYPE html>
<html lang="en">
<head>
    <title>Welcome to Our SaaS</title>
    <meta name="keywords" content="KEY=value, SECRET_CODE">
</head>
<body>
    <h1>Welcome</h1>
    <p>Please login to continue</p>
    <script>var API_KEY="dummy_script_bundle";</script>
</body>
</html>"""
        res = verify_env_file_exposure(
            requested_url="https://claude.ai/.env",
            status_code=200,
            content_type="text/html; charset=utf-8",
            response_text=html_body,
            final_url="https://claude.ai/.env",
        )
        assert res.is_exposed is False
        assert res.confidence == "NONE"
        assert res.is_html_or_spa is True
        assert any("HTML" in ind for ind in res.detection_indicators)

    def test_5_200_custom_404_page_rejected(self):
        """Test: HTTP 200 returning custom 404 page is rejected."""
        custom_404 = """<!DOCTYPE html>
<html>
<head><title>Page Not Found</title></head>
<body>
    <div id="error-container">
        <h2>404 - Page Not Found</h2>
        <p>The requested URL was not found on this server.</p>
    </div>
</body>
</html>"""
        res = verify_env_file_exposure(
            requested_url="https://example.com/.env",
            status_code=200,
            content_type="text/html",
            response_text=custom_404,
            final_url="https://example.com/.env",
        )
        assert res.is_exposed is False
        assert res.confidence == "NONE"
        assert res.is_html_or_spa is True

    def test_6_301_302_redirect_rejected(self):
        """Test: Redirect to homepage or login is rejected."""
        login_page = "<html><body>Please sign in</body></html>"
        res = verify_env_file_exposure(
            requested_url="https://example.com/.env",
            status_code=200,
            content_type="text/html",
            response_text=login_page,
            final_url="https://example.com/login",
        )
        assert res.is_exposed is False
        assert res.confidence == "NONE"
        assert res.is_redirected is True

    def test_7_real_env_containing_aws_and_db_secrets(self):
        """Test: Real .env file containing AWS & Postgres secrets generates verified critical finding."""
        env_body = """
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
POSTGRES_PASSWORD=UltraSecretDatabasePassword999!
DB_HOST=10.0.1.50
"""
        res = verify_env_file_exposure(
            requested_url="https://staging.example.com/.env",
            status_code=200,
            content_type="text/plain",
            response_text=env_body,
            final_url="https://staging.example.com/.env",
        )
        assert res.is_exposed is True
        assert res.confidence == "VERIFIED"
        assert res.severity == "CRITICAL"
        finding = res.to_finding_dict()
        assert finding["severity"] == "CRITICAL"
        assert "AWS_ACCESS_KEY_ID" in res.matched_signatures
        assert "POSTGRES_PASSWORD" in res.matched_signatures

    def test_8_empty_env_rejected(self):
        """Test: Completely empty 0-byte .env response is rejected."""
        res = verify_env_file_exposure(
            requested_url="https://example.com/.env",
            status_code=200,
            content_type="text/plain",
            response_text="",
            final_url="https://example.com/.env",
        )
        assert res.is_exposed is False
        assert res.confidence == "NONE"

    def test_9_spa_fallback_returning_200_rejected(self):
        """Test: React/Next.js/Vue SPA router fallback returning index.html is rejected."""
        spa_index = """<!doctype html>
<html>
<head>
    <script defer="defer" src="/static/js/main.5f91b92a.js"></script>
    <link href="/static/css/main.7c72f7e4.css" rel="stylesheet">
</head>
<body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
</body>
</html>"""
        res = verify_env_file_exposure(
            requested_url="https://spa-app.example.com/.env",
            status_code=200,
            content_type="text/html",
            response_text=spa_index,
            final_url="https://spa-app.example.com/.env",
        )
        assert res.is_exposed is False
        assert res.confidence == "NONE"
        assert res.is_html_or_spa is True

    def test_10_git_head_verification(self):
        """Test: Valid Git HEAD is verified; HTML response is rejected."""
        # Real Git HEAD
        res_real = verify_git_head_exposure(
            requested_url="https://example.com/.git/HEAD",
            status_code=200,
            content_type="text/plain",
            response_text="ref: refs/heads/main\n",
        )
        assert res_real.is_exposed is True
        assert res_real.confidence == "VERIFIED"
        assert res_real.severity == "CRITICAL"

        # Fake Git HEAD (HTML 404 page returning 200)
        res_fake = verify_git_head_exposure(
            requested_url="https://example.com/.git/HEAD",
            status_code=200,
            content_type="text/html",
            response_text="<html><body>404 Not Found</body></html>",
        )
        assert res_fake.is_exposed is False
        assert res_fake.confidence == "NONE"

    def test_11_reconcile_resolved_exposure_findings(self):
        """Test: Previous exposure finding is reconciled to 'RESOLVED' when new scan returns 404."""
        prev_findings = [
            {
                "id": "FIND-EXPO-1234",
                "category": "exposure",
                "severity": "CRITICAL",
                "title": "Critical Public Exposure: .env Environment File Exposed",
                "file": "https://example.com/.env",
                "status": "OPEN",
            }
        ]
        # In current scan, .env is fixed and not in active findings
        active_findings = []
        active_out, resolved_out = reconcile_resolved_exposure_findings(
            target_url="https://example.com",
            active_findings=active_findings,
            historical_findings=prev_findings,
        )
        assert len(active_out) == 0
        assert len(resolved_out) == 1
        assert resolved_out[0]["status"] == "RESOLVED"
        assert "Resolved / No longer reproducible" in resolved_out[0]["resolution_reason"]
