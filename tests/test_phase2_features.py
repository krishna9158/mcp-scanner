"""
Unit & Integration Tests for Phase 2: Trust & Distribution Features.
"""

import os
import tempfile
import pytest
from app import app
import badge
import scanner_integrations.deduplicator as deduplicator
import trust_features


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestMultiLocationDeduplication:
    def test_group_and_aggregate_locations_across_files(self):
        findings = [
            {
                "id": "FIND-1",
                "title": "Exposed Hardcoded API Key",
                "category": "secrets",
                "severity": "CRITICAL",
                "confidence": "LIKELY",
                "file": "src/api.py",
                "line": 14,
                "evidence": "sk-ant-...[REDACTED]...",
                "scanner": "gitleaks",
            },
            {
                "id": "FIND-2",
                "title": "Exposed Hardcoded API Key",
                "category": "secrets",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "file": "src/services/auth.py",
                "line": 28,
                "evidence": "sk-ant-...[REDACTED]...",
                "scanner": "trustaudit_secrets",
            },
            {
                "id": "FIND-3",
                "title": "Exposed Hardcoded API Key",
                "category": "secrets",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "file": "src/api.py",
                "line": 14,  # Duplicate exact location
                "evidence": "sk-ant-...[REDACTED]...",
                "scanner": "semgrep",
            }
        ]

        deduped = deduplicator.deduplicate_findings(findings)
        assert len(deduped) == 1
        f = deduped[0]
        assert f["severity"] == "CRITICAL"
        assert f["confidence"] == "CONFIRMED"
        assert len(f["locations"]) == 2
        assert f["affected_locations_count"] == 2
        files = [loc["file"] for loc in f["locations"]]
        assert "src/api.py" in files
        assert "src/services/auth.py" in files
        assert set(f["scanners"]) == {"gitleaks", "trustaudit_secrets", "semgrep"}


class TestEli5Explanation:
    def test_eli5_plain_english_categories(self):
        # 1. Secret
        sec_finding = {
            "title": "Exposed Stripe Secret Key",
            "category": "secrets",
            "file": "server/payment.js",
            "line": 42
        }
        sec_eli5 = trust_features.generate_eli5_explanation(sec_finding)
        assert "🔑 **Plain English:**" in sec_eli5
        assert "house key" in sec_eli5

        # 2. SQL Injection
        sqli_finding = {
            "title": "SQL Injection in User Profile Lookup",
            "category": "code_security",
            "file": "db/users.py",
            "line": 88
        }
        sqli_eli5 = trust_features.generate_eli5_explanation(sqli_finding)
        assert "💉 **Plain English:**" in sqli_eli5
        assert "parameterized queries" in sqli_eli5

        # 3. Dependency CVE
        dep_finding = {
            "title": "Remote Code Execution in PyYAML",
            "category": "dependencies",
            "package": "PyYAML",
            "file": "requirements.txt"
        }
        dep_eli5 = trust_features.generate_eli5_explanation(dep_finding)
        assert "📦 **Plain English:**" in dep_eli5
        assert "PyYAML" in dep_eli5


class TestAiFixPrompt:
    def test_ai_fix_prompt_generation(self):
        finding = {
            "title": "Exposed Stripe Live Key",
            "category": "secrets",
            "file": "src/checkout.ts",
            "line": 50
        }
        prompt = trust_features.generate_ai_fix_prompt(finding)
        assert "Ask Cursor / Claude:" in prompt
        assert "src/checkout.ts" in prompt
        assert "process.env" in prompt
        assert ".gitignore" in prompt


class TestBadgeGenerator:
    def test_badge_svg_rendering(self):
        svg_passing = badge.generate_badge_svg(score=95, grade="A")
        assert "<svg" in svg_passing
        assert "95/100 A" in svg_passing
        assert "#22c55e" in svg_passing

        svg_failing = badge.generate_badge_svg(score=40, grade="F")
        assert "<svg" in svg_failing
        assert "40/100 F" in svg_failing
        assert "#ef4444" in svg_failing

    def test_badge_markdown_generation(self):
        badge_data = trust_features.generate_badge_markdown("my-saas-repo", score=92, grade="A")
        assert "my-saas-repo" in badge_data["project_slug"]
        assert "[![TrustAudit Security Score]" in badge_data["markdown"]
        assert "https://img.shields.io" in badge_data["shields_markdown"]


class TestWeeklyDigest:
    def test_weekly_digest_zero_findings_narrative(self):
        digest = trust_features.generate_weekly_digest("org-default")
        assert "org_id" in digest
        assert "date" in digest
        assert digest["scans_executed_this_week"] >= 1
        assert "headline" in digest
        assert "status_narrative" in digest

    def test_weekly_digest_dispatch(self):
        res = trust_features.dispatch_weekly_digest("org-default")
        assert res["dispatched"] is True
        assert "@" in res["recipient"]
        assert "Weekly Digest" in res["subject"]


class TestPhase2APIEndpoints:
    def test_api_badge_svg_endpoint(self, client):
        resp = client.get("/api/badge/acme-ai.svg")
        assert resp.status_code == 200
        assert resp.mimetype == "image/svg+xml"
        assert b"<svg" in resp.data

    def test_api_badge_info_endpoint(self, client):
        resp = client.get("/api/projects/proj-default/badge")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "markdown" in data
        assert "badge_svg_url" in data

    def test_api_digest_weekly_endpoint(self, client):
        resp = client.get("/api/digest/weekly")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "headline" in data
        assert "status_narrative" in data

    def test_api_alerts_weekly_digest_dispatch(self, client):
        resp = client.post("/api/alerts/weekly-digest")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["dispatched"] is True

    def test_api_eli5_endpoint(self, client):
        resp = client.post("/api/findings/eli5", json={
            "title": "Hardcoded AWS Key",
            "category": "secrets",
            "file": "deploy.py",
            "line": 10
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "🔑 **Plain English:**" in data["eli5_explanation"]

    def test_api_ai_prompt_endpoint(self, client):
        resp = client.post("/api/findings/ai-prompt", json={
            "title": "SQL Injection Flaw",
            "category": "code_security",
            "file": "api/users.py",
            "line": 33
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "Ask Cursor / Claude:" in data["ai_fix_prompt"]
