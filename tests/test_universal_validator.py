"""
Unit and Integration Tests for Universal False-Positive Prevention Engine (Phase 1).

Tests:
1. RFC 2606 Reserved Domain & Localhost Filtering (example.com, 127.0.0.1, collector.example.com)
2. Known-Placeholder Denylist (AKIAIOSFODNN7EXAMPLE, wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)
3. Suppression Comments (# pragma: allowlist secret, # gitleaks:allow, # nosec, // nosec, # noqa)
4. Test/Example Context Downgrade (redact_secrets.test.cjs, /tests/, /fixtures/, /examples/)
5. Shannon Entropy Scoring for Secrets
6. 3-Tier Confidence System (CONFIRMED, LIKELY, POSSIBLE)
7. Live Credential Verification (AWS STS, GitHub API, Stripe API)
8. End-to-end simulation on awslabs/mcp and github/gh-aw patterns
"""

import pytest
from universal_validator import (
    calculate_entropy,
    is_known_placeholder,
    is_line_suppressed,
    is_rfc2606_reserved_url,
    is_test_context,
    validate_and_sanitize_finding,
    verify_credential_live,
)


class TestUniversalValidatorCore:
    """Tests core validation primitives."""

    def test_rfc2606_reserved_domains(self):
        assert is_rfc2606_reserved_url("https://user:secret@collector.example.com/v1/traces?token=") is True
        assert is_rfc2606_reserved_url("https://example.com/api/v1") is True
        assert is_rfc2606_reserved_url("http://localhost:8080/debug") is True
        assert is_rfc2606_reserved_url("http://127.0.0.1:3000") is True
        assert is_rfc2606_reserved_url("https://test.invalid/auth") is True
        assert is_rfc2606_reserved_url("https://api.github.com/repos") is False
        assert is_rfc2606_reserved_url("https://production-service.acme.corp/login") is False

    def test_known_placeholders_and_substrings(self):
        assert is_known_placeholder("AKIAIOSFODNN7EXAMPLE") is True
        assert is_known_placeholder("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") is True
        assert is_known_placeholder("ghp_EXAMPLETOKENFORGITHUBDOCS123456789") is True
        assert is_known_placeholder("your-api-key-here") is True
        assert is_known_placeholder("dummy_secret_value_12345") is True
        assert is_known_placeholder("changeme") is True
        assert is_known_placeholder("AKIAAAAAAAAAAAAAAAAA") is True
        # Real production-looking key
        assert is_known_placeholder("AKIA2G7XYZ994PRODKEY") is False

    def test_suppression_comments_detection(self):
        assert is_line_suppressed("aws_key = 'AKIA2G7XYZ994PRODKEY'  # pragma: allowlist secret") is True
        assert is_line_suppressed("token = 'ghp_1234567890abcdef' // pragma: allowlist secret") is True
        assert is_line_suppressed("secret = 'sk-ant-api03-12345'  # gitleaks:allow") is True
        assert is_line_suppressed("auth = 'secret'  # nosec") is True
        assert is_line_suppressed("db_pass = 'pass'  // nosec") is True
        assert is_line_suppressed("key = '123'  # noqa: secret") is True
        assert is_line_suppressed("key = '123'  # trustaudit:allow") is True
        assert is_line_suppressed("aws_key = 'AKIA2G7XYZ994PRODKEY'") is False

    def test_test_context_detection(self):
        # File paths
        assert is_test_context("redact_secrets.test.cjs") is True
        assert is_test_context("src/tests/test_auth.py") is True
        assert is_test_context("tests/unit/test_api.ts") is True
        assert is_test_context("fixtures/secrets.json") is True
        assert is_test_context("examples/demo_app.py") is True
        assert is_test_context("mocks/mock_aws.py") is True
        assert is_test_context("spec/models/user_spec.rb") is True
        # Production files
        assert is_test_context("src/api/auth.py") is False
        assert is_test_context("app/controllers/payment.js") is False
        assert is_test_context("config/settings.py") is False

    def test_entropy_calculation(self):
        high_entropy = calculate_entropy("sk-ant-api03-8xL9pQ2mZw7vR4tY1kJs5bN0eC")
        low_entropy = calculate_entropy("AAAAAAAAAAAAAAAAAAAA")
        assert high_entropy >= 3.8
        assert low_entropy <= 1.0


class TestUniversalFindingSanitizer:
    """Tests the unified validate_and_sanitize_finding pipeline."""

    def test_exclude_suppressed_finding(self):
        finding = {
            "title": "Exposed AWS Access Key",
            "category": "secrets",
            "severity": "CRITICAL",
            "file": "app/aws.py",
            "evidence": "aws_access_key_id='AKIA2G7XYZ994PRODKEY',  # pragma: allowlist secret",
            "raw_value": "AKIA2G7XYZ994PRODKEY",
        }
        res = validate_and_sanitize_finding(finding)
        assert res is None, "Suppressed finding must be excluded (None)"

    def test_exclude_official_aws_placeholder_finding(self):
        finding = {
            "title": "Exposed AWS Access Key",
            "category": "secrets",
            "severity": "CRITICAL",
            "file": "app/aws.py",
            "evidence": "aws_access_key_id='AKIAIOSFODNN7EXAMPLE'",
            "raw_value": "AKIAIOSFODNN7EXAMPLE",
        }
        res = validate_and_sanitize_finding(finding)
        assert res is None, "Official AWS placeholder key must be excluded (None)"

    def test_downgrade_rfc2606_reserved_domain_url(self):
        finding = {
            "title": "Exposed Database Connection String with Credentials",
            "category": "secrets",
            "severity": "HIGH",
            "file": "config/tracer.py",
            "evidence": "url = 'https://user:secret@collector.example.com/v1/traces?token='",
            "raw_value": "https://user:secret@collector.example.com/v1/traces?token=",
        }
        res = validate_and_sanitize_finding(finding)
        assert res is not None
        assert res["severity"] == "LOW"
        assert res["confidence"] == "POSSIBLE"
        assert res["is_test_data"] is True
        assert "Likely Test/Example Data" in res["title"]

    def test_downgrade_test_file_finding_redact_secrets_test(self):
        finding = {
            "title": "Exposed OpenAI API Key",
            "category": "secrets",
            "severity": "CRITICAL",
            "file": "test/redact_secrets.test.cjs",
            "evidence": "const key = 'sk-proj-abcdef1234567890abcdef1234567890abcdef';",
            "raw_value": "sk-proj-abcdef1234567890abcdef1234567890abcdef",
        }
        res = validate_and_sanitize_finding(finding)
        assert res is not None
        assert res["severity"] == "LOW"
        assert res["confidence"] == "POSSIBLE"
        assert res["is_test_context"] is True
        assert "Likely Test/Example Data" in res["title"]

    def test_production_real_secret_retains_likely_confidence(self):
        finding = {
            "title": "Exposed Anthropic API Key",
            "category": "secrets",
            "severity": "CRITICAL",
            "file": "src/services/ai_agent.py",
            "evidence": "ANTHROPIC_KEY = 'sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890'",
            "raw_value": "sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890",
        }
        res = validate_and_sanitize_finding(finding)
        assert res is not None
        assert res["severity"] == "CRITICAL"
        assert res["confidence"] in ("LIKELY", "CONFIRMED")
        assert not res.get("is_test_context")


class TestLiveVerification:
    """Tests live credential probes."""

    def test_aws_sts_probe_placeholder_or_invalid(self):
        res = verify_credential_live("AWS Access Key", "AKIAIOSFODNN7EXAMPLE")
        assert res["status"] == "INVALID"
        assert res["active"] is False

    def test_github_token_probe_invalid_format(self):
        res = verify_credential_live("GitHub Token", "invalid_short_token")
        assert res["status"] == "INVALID"
        assert res["active"] is False


class TestAwslabsMcpProofSimulation:
    """
    Simulates the exact false-positive findings reported by the user on awslabs/mcp and github/gh-aw:
    1. AWS's official example key 'AKIAIOSFODNN7EXAMPLE' with '# pragma: allowlist secret'
    2. Tokens in files named 'redact_secrets.test.cjs'
    3. 'https://user:secret@collector.example.com/v1/traces?token='
    """

    def test_awslabs_mcp_exact_patterns(self):
        raw_scanned_findings = [
            # 1. AWS official example key with suppression comment
            {
                "title": "Exposed AWS Access Key",
                "category": "secrets",
                "severity": "CRITICAL",
                "file": "awslabs/mcp/session.py",
                "evidence": "aws_access_key_id='AKIAIOSFODNN7EXAMPLE',  # pragma: allowlist secret",
                "raw_value": "AKIAIOSFODNN7EXAMPLE",
            },
            # 2. AWS secret key with suppression comment
            {
                "title": "Exposed AWS Secret Key",
                "category": "secrets",
                "severity": "CRITICAL",
                "file": "awslabs/mcp/session.py",
                "evidence": "aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',  # pragma: allowlist secret",
                "raw_value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            },
            # 3. Test token in redact_secrets.test.cjs
            {
                "title": "Exposed GitHub Token",
                "category": "secrets",
                "severity": "CRITICAL",
                "file": "test/redact_secrets.test.cjs",
                "evidence": "const dummyToken = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';",
                "raw_value": "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            },
            # 4. Collector example URL
            {
                "title": "Exposed Database Connection String with Credentials",
                "category": "secrets",
                "severity": "HIGH",
                "file": "telemetry/tracer.py",
                "evidence": "endpoint = 'https://user:secret@collector.example.com/v1/traces?token='",
                "raw_value": "https://user:secret@collector.example.com/v1/traces?token=",
            },
            # 5. Genuine Production Key
            {
                "title": "Exposed Anthropic API Key",
                "category": "secrets",
                "severity": "CRITICAL",
                "file": "src/agent/config.py",
                "evidence": "ANTHROPIC_KEY = 'sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890'",
                "raw_value": "sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890",
            },
        ]

        sanitized_findings = []
        for f in raw_scanned_findings:
            res = validate_and_sanitize_finding(f)
            if res:
                sanitized_findings.append(res)

        # Proof Assertions:
        # Items 1 and 2 (AKIAIOSFODNN7EXAMPLE and secret key with suppression) must be completely EXCLUDED
        assert not any(f["file"] == "awslabs/mcp/session.py" for f in sanitized_findings), "awslabs/mcp placeholder keys must be excluded"

        # Item 3 (redact_secrets.test.cjs) must be downgraded to LOW (not CRITICAL) and confidence POSSIBLE
        test_file_finding = next((f for f in sanitized_findings if "redact_secrets.test.cjs" in f["file"]), None)
        assert test_file_finding is not None
        assert test_file_finding["severity"] == "LOW"
        assert test_file_finding["confidence"] == "POSSIBLE"
        assert "Likely Test/Example Data" in test_file_finding["title"]

        # Item 4 (collector.example.com) must be downgraded to LOW (not HIGH/CRITICAL) and confidence POSSIBLE
        collector_finding = next((f for f in sanitized_findings if "tracer.py" in f["file"]), None)
        assert collector_finding is not None
        assert collector_finding["severity"] == "LOW"
        assert collector_finding["confidence"] == "POSSIBLE"

        # Item 5 (Production Anthropic Key) must remain CRITICAL and LIKELY
        prod_finding = next((f for f in sanitized_findings if "config.py" in f["file"]), None)
        assert prod_finding is not None
        assert prod_finding["severity"] == "CRITICAL"
        assert prod_finding["confidence"] in ("LIKELY", "CONFIRMED")
