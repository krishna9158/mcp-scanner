"""
Unit and Integration Tests for Open-Source Security Engine Integrations:
- BaseScanner Interface
- Gitleaks Secret Scanner (with zero secret leakage redaction)
- OSV-Scanner Dependency Auditor
- Trivy Filesystem & Misconfiguration Scanner
- Nuclei Live AppSec (with strict authorization & SSRF protections)
- Syft Software Bill of Materials (SBOM) Engine
- Finding Normalizer & Deduplicator (multi-engine attribution)
- ScanOrchestrator End-to-End Execution
- Health Check & REST API Endpoints
"""

import json
import os
import sys
import tempfile
import pytest

from scanner_integrations.base import BaseScanner
from scanner_integrations.gitleaks import GitleaksScanner
from scanner_integrations.osv_scanner import OSVScanner
from scanner_integrations.trivy import TrivyScanner
from scanner_integrations.nuclei import NucleiScanner, validate_target_url_for_live_scan, is_private_ip
from scanner_integrations.syft import SyftScanner
from scanner_integrations.zap import ZapScanner
from scanner_integrations.normalizer import (
    normalize_finding,
    compute_finding_fingerprint,
    redact_secret_string,
    normalize_severity,
    normalize_confidence,
)
from scanner_integrations.deduplicator import deduplicate_findings, merge_findings, get_dedup_key
from scanner_integrations.orchestrator import ScanOrchestrator
from app import app


# ===========================================================================
# 1. BASE SCANNER & NORMALIZATION TESTS
# ===========================================================================

class TestBaseScannerAndNormalizer:
    def test_base_scanner_health_check(self):
        class DummyScanner(BaseScanner):
            def scan(self, target, **kwargs):
                return {}
            def parse_results(self, raw_output):
                return []
            def normalize_findings(self, raw_findings):
                return []

        dummy = DummyScanner(name="dummy_tool")
        hc = dummy.health_check()
        assert hc["name"] == "dummy_tool"
        assert "available" in hc
        assert "status" in hc

    def test_secret_redaction_guarantees(self):
        raw_key = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        redacted = redact_secret_string(raw_key)
        assert raw_key not in redacted
        assert "[REDACTED]" in redacted

        # Test normalizer secret masking in evidence
        norm = normalize_finding(
            scanner="test_scanner",
            category="secrets",
            title="AWS Access Key Exposed",
            description="Exposed key in config",
            evidence="AKIAIOSFODNN7EXAMPLE12345",
        )
        assert "AKIAIOSFODNN7EXAMPLE12345" not in norm["evidence"]
        assert "[REDACTED]" in norm["evidence"]

    def test_deterministic_fingerprint(self):
        fp1 = compute_finding_fingerprint(
            category="secrets",
            title="Exposed API Key",
            file_path="src/config.py",
            line=42,
        )
        fp2 = compute_finding_fingerprint(
            category="secrets",
            title="Exposed API Key",
            file_path="src/config.py",
            line=42,
        )
        assert fp1 == fp2
        assert len(fp1) == 16


# ===========================================================================
# 2. GITLEAKS INTEGRATION TESTS
# ===========================================================================

class TestGitleaksIntegration:
    def test_gitleaks_availability_and_health(self):
        scanner = GitleaksScanner()
        hc = scanner.health_check()
        assert hc["name"] == "gitleaks"
        assert isinstance(hc["available"], bool)

    def test_gitleaks_parsing_and_normalization(self):
        scanner = GitleaksScanner()
        sample_gitleaks_output = [
            {
                "Description": "AWS Access Key",
                "StartLine": 14,
                "EndLine": 14,
                "StartColumn": 1,
                "EndColumn": 25,
                "Match": "AKIA2G7XYZ994TESTKEY",
                "Secret": "AKIA2G7XYZ994TESTKEY",
                "File": "config/credentials.json",
                "RuleID": "aws-access-token",
                "Entropy": 3.72,
            },
            {
                "Description": "AWS Placeholder Key",
                "StartLine": 20,
                "EndLine": 20,
                "StartColumn": 1,
                "EndColumn": 25,
                "Match": "AKIAIOSFODNN7EXAMPLE",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "config/docs.py",
                "RuleID": "aws-access-token",
                "Entropy": 3.72,
            }
        ]
        normalized = scanner.normalize_findings(sample_gitleaks_output)
        # Placeholder should be filtered, only synthetic active key retained
        assert len(normalized) == 1
        finding = normalized[0]
        assert finding["scanner"] == "gitleaks"
        assert finding["category"] == "secrets"
        assert finding["severity"] == "CRITICAL"
        assert finding["file"] == "config/credentials.json"
        assert finding["line"] == 14
        # Crucial: verify secret is masked
        assert "AKIA2G7XYZ994TESTKEY" not in finding["evidence"]
        assert "[REDACTED]" in finding["evidence"]

    def test_gitleaks_graceful_missing_binary_fallback(self):
        scanner = GitleaksScanner()
        res = scanner.scan("tests/fixtures/tiny-project")
        assert res["status"] in ("completed", "not_installed")
        assert "normalized_findings" in res



# ===========================================================================
# 3. OSV-SCANNER INTEGRATION TESTS
# ===========================================================================

class TestOSVScannerIntegration:
    def test_osv_scanner_availability_and_health(self):
        scanner = OSVScanner()
        hc = scanner.health_check()
        assert hc["name"] == "osv-scanner"
        assert isinstance(hc["available"], bool)

    def test_osv_scanner_parsing_and_normalization(self):
        scanner = OSVScanner()
        sample_osv_json = json.dumps({
            "results": [
                {
                    "source": {"path": "package.json", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {"name": "express", "version": "4.16.0", "ecosystem": "npm"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-qw6h-v8gh-w36c",
                                    "aliases": ["CVE-2022-24999"],
                                    "summary": "qs vulnerable to Prototype Pollution",
                                    "affected": [
                                        {
                                            "package": {"name": "express", "ecosystem": "npm"},
                                            "ranges": [
                                                {
                                                    "type": "SEMVER",
                                                    "events": [{"introduced": "0"}, {"fixed": "4.17.3"}]
                                                }
                                            ]
                                        }
                                    ],
                                    "references": [{"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-24999"}]
                                }
                            ]
                        }
                    ]
                }
            ]
        })
        raw = scanner.parse_results(sample_osv_json)
        assert len(raw) == 1
        normalized = scanner.normalize_findings(raw)
        assert len(normalized) == 1
        f = normalized[0]
        assert f["scanner"] == "osv-scanner"
        assert f["category"] == "dependencies"
        assert f["package"] == "express"
        assert f["version"] == "4.16.0"
        assert f["cve"] == "CVE-2022-24999"
        assert "4.17.3" in f["remediation"]


# ===========================================================================
# 4. TRIVY INTEGRATION TESTS
# ===========================================================================

class TestTrivyIntegration:
    def test_trivy_availability_and_health(self):
        scanner = TrivyScanner()
        hc = scanner.health_check()
        assert hc["name"] == "trivy"
        assert isinstance(hc["available"], bool)

    def test_trivy_parsing_and_normalization(self):
        scanner = TrivyScanner()
        sample_trivy_json = json.dumps({
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-33503",
                            "PkgName": "urllib3",
                            "InstalledVersion": "1.26.4",
                            "FixedVersion": "1.26.5",
                            "Severity": "HIGH",
                            "Title": "urllib3 Catastrophic Backtracking",
                            "Description": "Regular expression denial of service in urllib3",
                            "References": ["https://github.com/advisories/GHSA-q2x7-8rv6-6q7h"]
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Title": "Image user should not be 'root'",
                            "Description": "Running containers with 'root' user can lead to container breakout",
                            "Message": "Specify a non-root user in Dockerfile",
                            "Severity": "MEDIUM",
                            "Resolution": "Add USER <non-root-user> to Dockerfile",
                            "CauseMetadata": {"StartLine": 1}
                        }
                    ]
                }
            ]
        })
        raw = scanner.parse_results(sample_trivy_json)
        assert len(raw) == 2
        normalized = scanner.normalize_findings(raw)
        assert len(normalized) == 2
        
        # Check vulnerability finding
        vuln_f = next(f for f in normalized if f["category"] == "dependencies")
        assert vuln_f["package"] == "urllib3"
        assert vuln_f["version"] == "1.26.4"
        assert vuln_f["cve"] == "CVE-2021-33503"
        assert "1.26.5" in vuln_f["remediation"]

        # Check misconfig finding
        misconf_f = next(f for f in normalized if f["category"] == "misconfiguration")
        assert misconf_f["severity"] == "MEDIUM"
        assert misconf_f["line"] == 1


# ===========================================================================
# 5. NUCLEI INTEGRATION TESTS (STRICT AUTH & SSRF PROTECTIONS)
# ===========================================================================

class TestNucleiIntegration:
    def test_nuclei_strict_authorization_rejection(self):
        scanner = NucleiScanner()
        # Missing explicit authorization confirmation
        res = scanner.scan("https://example.com", authorization_confirmed=False)
        assert res["status"] == "not_executed"
        assert "authorization" in res["reason"].lower()

    def test_nuclei_ssrf_and_private_ip_blocking(self):
        # 1. Localhost blocking
        val_local = validate_target_url_for_live_scan("http://localhost:8080", allow_local=False)
        assert val_local["valid"] is False
        assert "prohibited" in val_local["error"].lower()

        # 2. Loopback IP blocking
        val_loop = validate_target_url_for_live_scan("http://127.0.0.1:3000", allow_local=False)
        assert val_loop["valid"] is False

        # 3. Cloud Metadata IP blocking
        val_meta = validate_target_url_for_live_scan("http://169.254.169.254/latest/meta-data", allow_local=False)
        assert val_meta["valid"] is False

        # 4. Valid external URL
        val_ext = validate_target_url_for_live_scan("https://example.com", allow_local=False)
        assert val_ext["valid"] is True

    def test_nuclei_parsing_and_normalization(self):
        scanner = NucleiScanner()
        sample_nuclei_jsonl = """
{"template-id":"exposed-git-config","info":{"name":"Git Config Exposure","severity":"medium","description":".git/config was exposed publicly","remediation":"Block access to hidden .git directory"},"matched-at":"https://app.startup-target.io/.git/config"}
{"template-id":"tls-version","info":{"name":"Weak TLS Version","severity":"low","description":"Server supports TLS 1.0/1.1","remediation":"Enforce TLS 1.2 or 1.3"},"matched-at":"https://app.startup-target.io"}
"""
        raw = scanner.parse_results(sample_nuclei_jsonl)
        assert len(raw) == 2
        normalized = scanner.normalize_findings(raw, target_url="https://app.startup-target.io")
        assert len(normalized) == 2
        git_f = normalized[0]
        assert git_f["scanner"] == "nuclei"
        assert git_f["category"] == "website_security"
        assert "Git Config" in git_f["title"]
        assert git_f["severity"] == "MEDIUM"


# ===========================================================================
# 6. SYFT SBOM INTEGRATION TESTS
# ===========================================================================

class TestSyftIntegration:
    def test_syft_manifest_sbom_generation(self):
        scanner = SyftScanner()
        tiny_path = os.path.join(os.path.dirname(__file__), "fixtures", "tiny-project")
        res = scanner.scan(tiny_path)
        assert res["status"] == "completed"
        sbom = res["sbom"]
        assert "total_packages" in sbom
        assert sbom["total_packages"] > 0
        assert "packages" in sbom
        assert "ecosystems" in sbom
        assert any(p["name"] == "express" for p in sbom["packages"])

    def test_syft_vulnerable_project_sbom_ai_components(self):
        scanner = SyftScanner()
        vuln_path = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-project")
        res = scanner.scan(vuln_path)
        assert res["status"] == "completed"
        sbom = res["sbom"]
        assert any(p["name"] == "urllib3" for p in sbom["packages"])



# ===========================================================================
# 7. FINDING DEDUPLICATION & MULTI-ENGINE ATTRIBUTION
# ===========================================================================

class TestFindingDeduplication:
    def test_deduplicate_overlapping_secret_findings(self):
        f_gitleaks = normalize_finding(
            scanner="gitleaks",
            category="secrets",
            title="Exposed API Key",
            description="High entropy token found",
            severity="CRITICAL",
            confidence="CONFIRMED",
            file="app.py",
            line=12,
            evidence="Pattern match in app.py:12",
        )
        f_trivy = normalize_finding(
            scanner="trivy",
            category="secrets",
            title="Secret Credential",
            description="Generic secret detected",
            severity="HIGH",
            confidence="LIKELY",
            file="app.py",
            line=12,
            evidence="Secret on line 12",
        )

        deduped = deduplicate_findings([f_gitleaks, f_trivy])
        assert len(deduped) == 1
        merged = deduped[0]
        # Multi-engine attribution preserved:
        assert "gitleaks" in merged["scanners"]
        assert "trivy" in merged["scanners"]
        # Highest severity adopted:
        assert merged["severity"] == "CRITICAL"
        assert merged["confidence"] in ("CONFIRMED", "LIKELY")

    def test_deduplicate_overlapping_dependency_findings(self):
        f_osv = normalize_finding(
            scanner="osv-scanner",
            category="dependencies",
            title="Vulnerable Dependency urllib3",
            description="CVE-2021-33503 in urllib3",
            package="urllib3",
            version="1.26.4",
            cve="CVE-2021-33503",
            severity="HIGH",
            file="requirements.txt",
        )
        f_trivy = normalize_finding(
            scanner="trivy",
            category="dependencies",
            title="urllib3 ReDoS",
            description="ReDoS vulnerability in urllib3",
            package="urllib3",
            version="1.26.4",
            cve="CVE-2021-33503",
            severity="HIGH",
            file="requirements.txt",
        )

        deduped = deduplicate_findings([f_osv, f_trivy])
        assert len(deduped) == 1
        assert "osv-scanner" in deduped[0]["scanners"]
        assert "trivy" in deduped[0]["scanners"]


# ===========================================================================
# 8. SCAN ORCHESTRATOR & END-TO-END EXECUTION
# ===========================================================================

class TestScanOrchestrator:
    def test_orchestrator_engine_status(self):
        orchestrator = ScanOrchestrator()
        status = orchestrator.get_engine_status()
        assert "mcp_engine" in status
        assert "semgrep" in status
        assert "gitleaks" in status
        assert "osv_scanner" in status
        assert "trivy" in status
        assert "nuclei" in status
        assert "syft" in status

    def test_orchestrate_repository_scan_on_tiny_project(self):
        orchestrator = ScanOrchestrator()
        tiny_path = os.path.join(os.path.dirname(__file__), "fixtures", "tiny-project")
        result = orchestrator.orchestrate_repository_scan(tiny_path, full_scan=False)
        assert result is not None
        assert "report" in result
        assert "findings" in result
        assert "sbom" in result
        assert "engines_executed" in result
        assert len(result["engines_executed"]) >= 3

    def test_orchestrate_repository_scan_on_vulnerable_project(self):
        orchestrator = ScanOrchestrator()
        vuln_path = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-project")
        result = orchestrator.orchestrate_repository_scan(vuln_path, full_scan=False)
        assert result is not None
        assert len(result["secrets"]) > 0
        assert len(result["findings"]) > 0
        assert result["score"] < 90
        assert "sbom" in result
        assert result["sbom"]["total_packages"] > 0


# ===========================================================================
# 9. FLASK API REST & HEALTH CHECK ENDPOINTS
# ===========================================================================

class TestAPIEndpointsWithOpenSourceEngines:
    def test_api_health_scanner_includes_engines(self):
        with app.test_client() as client:
            resp = client.get("/api/health/scanner")
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["backend"] == "OK"
            assert "engines" in data
            assert "gitleaks" in data["engines"]
            assert "osv_scanner" in data["engines"]
            assert "trivy" in data["engines"]
            assert "nuclei" in data["engines"]
            assert "syft" in data["engines"]

    def test_api_scan_returns_sbom_and_findings(self):
        tiny_path = os.path.join(os.path.dirname(__file__), "fixtures", "tiny-project")
        with app.test_client() as client:
            resp = client.post("/api/scan", json={
                "target": tiny_path,
                "scan_type": "repository",
                "auth_confirmed": True
            })
            assert resp.status_code == 200
            data = resp.get_json()
            assert "findings" in data
            assert "sbom" in data
            assert "engines_executed" in data
            assert "score" in data


# ===========================================================================
# 10. WEBSITE SCANNER HTTPS TO HTTP FALLBACK TESTS
# ===========================================================================

class TestWebsiteScannerFallback:
    def test_https_fallback_to_http(self):
        from unittest.mock import patch, MagicMock
        import requests
        from website_scanner import scan_website
        from reports import generate_html_report

        with patch('website_scanner.check_dns_resolution', return_value=(['93.184.216.34'], None)), \
             patch('website_scanner.create_resilient_session') as mock_create_session:
            mock_session = MagicMock()
            
            def side_effect_get(url, **kwargs):
                if url.startswith('https://'):
                    raise requests.exceptions.ConnectionError('ConnectionResetError(10054, An existing connection was forcibly closed)')
                else:
                    mock_resp = MagicMock()
                    mock_resp.status_code = 200
                    mock_resp.url = url
                    mock_resp.headers = {'Server': 'Apache/2.4.41', 'Content-Type': 'text/html'}
                    mock_resp.cookies = []
                    mock_resp.text = '<html><body>Test Page</body></html>'
                    return mock_resp
                    
            mock_session.get.side_effect = side_effect_get
            mock_create_session.return_value = mock_session

            res = scan_website('https://broken-https-target.example')
            assert res.get('used_http_fallback') is True
            assert 'Broken HTTPS' in res.get('http_fallback_reason', '') or 'HTTPS connection failed' in res.get('http_fallback_reason', '')
            assert any('Broken HTTPS' in f['title'] for f in res.get('findings', []))

            # Verify report generation handles fallback
            report = generate_html_report(res)
            assert 'Plaintext HTTP Fallback Active' in report


# ===========================================================================
# 11. OWASP ZAP DAST ADAPTER & EXECUTION TESTS
# ===========================================================================

class TestZapScannerIntegration:
    """Tests for OWASP ZAP DAST Adapter across Docker, Local, and Graceful modes."""

    def test_zap_health_check_telemetry(self):
        zap = ZapScanner()
        hc = zap.health_check()
        assert hc["name"] == "OWASP ZAP DAST Scanner"
        assert "available" in hc
        assert "status" in hc
        assert "execution_mode" in hc
        assert "docker_available" in hc
        assert "docker_image" in hc

    def test_zap_target_safety_validation(self):
        zap = ZapScanner()
        # Invalid scheme / malformed URL
        res = zap.scan("ftp://invalidscheme.example.com", mode="PASSIVE")
        assert res["status"] == "FAILED"
        assert len(res["errors"]) > 0

    def test_zap_localhost_blocking_by_policy(self):
        zap = ZapScanner()
        res = zap.scan("http://127.0.0.1:8080", mode="PASSIVE", allow_local=False)
        assert res["status"] == "SKIPPED"
        assert any(e.get("type") == "PRIVATE_NETWORK_BLOCKED" for e in res.get("errors", []))

    def test_zap_active_mode_requires_authorization(self):
        zap = ZapScanner()
        res = zap.scan("https://example.com", mode="ACTIVE", authorization_confirmed=False)
        assert res["status"] == "SKIPPED"
        assert any(e.get("type") == "AUTHORIZATION_REQUIRED" for e in res.get("errors", []))

    def test_zap_unavailable_graceful_handling(self):
        from unittest.mock import patch
        zap = ZapScanner()
        with patch.object(zap, 'get_execution_mode', return_value='none'), \
             patch.object(zap, 'check_docker_available', return_value=(False, 'Daemon not running')):
            res = zap.scan("https://example.com", mode="PASSIVE")
            assert res["status"] == "UNAVAILABLE"
            assert res["mode"] == "none"
            assert len(res["findings"]) == 0
            assert any(e.get("type") == "TOOL_NOT_INSTALLED" for e in res.get("errors", []))

    def test_zap_parse_results_standard_format(self):
        zap = ZapScanner()
        sample_zap_json = json.dumps({
            "site": [{
                "@name": "https://testphp.vulnweb.com",
                "alerts": [
                    {
                        "alert": "Cross Site Scripting (Reflected)",
                        "riskdesc": "High (Medium)",
                        "confidence": "Medium",
                        "desc": "Cross-site Scripting (XSS) is an attack...",
                        "solution": "Phase out insecure script reflection",
                        "uri": "https://testphp.vulnweb.com/search.php?test=query",
                        "cweid": "79",
                        "evidence": "<script>alert(1)</script>"
                    },
                    {
                        "alert": "Directory Browsing",
                        "riskdesc": "Medium (High)",
                        "confidence": "High",
                        "desc": "Directory browsing is enabled on the server.",
                        "solution": "Disable directory indexing.",
                        "uri": "https://testphp.vulnweb.com/images/",
                        "cweid": "548",
                        "evidence": "Index of /images"
                    }
                ]
            }]
        })
        findings = zap.parse_results(sample_zap_json, "https://testphp.vulnweb.com")
        assert len(findings) == 2
        assert findings[0]["scanner"] == "zap"
        assert findings[0]["severity"] == "HIGH"
        assert "CWE-79" in findings[0]["cwe"]
        assert findings[1]["severity"] == "MEDIUM"
        assert "CWE-548" in findings[1]["cwe"]

    def test_zap_docker_scan_mock(self):
        from unittest.mock import patch, MagicMock
        zap = ZapScanner()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "ZAP Baseline completed"
        mock_proc.stderr = ""

        with patch.object(zap, 'get_execution_mode', return_value='docker'), \
             patch('subprocess.run', return_value=mock_proc):
            res = zap.scan("https://example.com", mode="PASSIVE", authorization_confirmed=True)
            assert res["status"] == "COMPLETED"
            assert res["mode"] == "docker"
            assert "duration_ms" in res


