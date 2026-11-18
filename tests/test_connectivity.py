"""
Automated unit and integration tests for TrustAudit Connectivity, Target Normalization,
DNS Resolution, HTTP/HTTPS Probing, Engine Isolation, and Canonical Status Modeling.
"""

import unittest
from unittest.mock import patch, MagicMock
import socket
import requests

from connectivity import (
    normalize_target_url,
    resolve_dns,
    check_tcp_connectivity,
    check_tls_connectivity,
    check_http_connectivity,
    detect_proxy_environment,
    run_target_diagnostics,
)
from scanner_integrations.orchestrator import normalize_engine_status, build_scanner_record, ScanOrchestrator
from website_scanner import scan_website


class TestTargetNormalization(unittest.TestCase):
    """Tests URL normalization across various input formats."""

    def test_https_url(self):
        norm = normalize_target_url("https://example.com")
        self.assertTrue(norm["valid"])
        self.assertEqual(norm["normalized_url"], "https://example.com/")
        self.assertEqual(norm["hostname"], "example.com")
        self.assertEqual(norm["port"], 443)
        self.assertEqual(norm["scheme"], "https")

    def test_http_url(self):
        norm = normalize_target_url("http://example.com")
        self.assertTrue(norm["valid"])
        self.assertEqual(norm["normalized_url"], "http://example.com/")
        self.assertEqual(norm["hostname"], "example.com")
        self.assertEqual(norm["port"], 80)
        self.assertEqual(norm["scheme"], "http")

    def test_bare_domain(self):
        norm = normalize_target_url("example.com")
        self.assertTrue(norm["valid"])
        self.assertEqual(norm["normalized_url"], "https://example.com/")
        self.assertEqual(norm["hostname"], "example.com")
        self.assertEqual(norm["port"], 443)
        self.assertEqual(norm["scheme"], "https")

    def test_www_domain_with_path_and_query(self):
        norm = normalize_target_url("www.example.com/api/v1?test=true")
        self.assertTrue(norm["valid"])
        self.assertEqual(norm["normalized_url"], "https://www.example.com/api/v1?test=true")
        self.assertEqual(norm["hostname"], "www.example.com")
        self.assertEqual(norm["path"], "/api/v1")
        self.assertEqual(norm["query"], "test=true")

    def test_custom_port(self):
        norm = normalize_target_url("http://127.0.0.1:8080/dashboard")
        self.assertTrue(norm["valid"])
        self.assertEqual(norm["normalized_url"], "http://127.0.0.1:8080/dashboard")
        self.assertEqual(norm["hostname"], "127.0.0.1")
        self.assertEqual(norm["port"], 8080)

    def test_localhost(self):
        norm = normalize_target_url("http://localhost:5000")
        self.assertTrue(norm["valid"])
        self.assertEqual(norm["hostname"], "localhost")
        self.assertEqual(norm["port"], 5000)

    def test_whitespace_handling(self):
        norm = normalize_target_url("   https://testphp.vulnweb.com/   ")
        self.assertTrue(norm["valid"])
        self.assertEqual(norm["hostname"], "testphp.vulnweb.com")

    def test_invalid_urls(self):
        self.assertFalse(normalize_target_url("")["valid"])
        self.assertFalse(normalize_target_url("   ")["valid"])
        self.assertFalse(normalize_target_url(None)["valid"])
        self.assertFalse(normalize_target_url("invalid")["valid"])
        self.assertFalse(normalize_target_url("ftp://example.com")["valid"])


class TestDNSResolution(unittest.TestCase):
    """Tests dual-stack DNS resolution and error reporting."""

    def test_valid_domain_resolution(self):
        dns = resolve_dns("example.com")
        self.assertTrue(dns["success"])
        self.assertTrue(len(dns["ipv4"]) > 0 or len(dns["ipv6"]) > 0)
        self.assertIsNone(dns["error"])

    def test_localhost_resolution(self):
        dns = resolve_dns("localhost")
        self.assertTrue(dns["success"])
        self.assertIn("127.0.0.1", dns["ipv4"] + dns["all_ips"])

    def test_nonexistent_domain(self):
        dns = resolve_dns("nonexistent-testaudit-domain-999.test")
        self.assertFalse(dns["success"])
        self.assertEqual(len(dns["all_ips"]), 0)
        self.assertIsNotNone(dns["error"])
        self.assertIn("DNS resolution failed", dns["error"])


class TestProxyEnvironment(unittest.TestCase):
    """Tests proxy environment detection and secret masking."""

    def test_no_proxy_by_default(self):
        with patch.dict("os.environ", {}, clear=True):
            proxies = detect_proxy_environment()
            self.assertFalse(proxies["has_proxy"])

    def test_proxy_detected_and_redacted(self):
        with patch.dict("os.environ", {"HTTP_PROXY": "http://admin:secret123@proxy.corp.internal:8080"}):
            proxies = detect_proxy_environment()
            self.assertTrue(proxies["has_proxy"])
            self.assertEqual(proxies["http_proxy"], "http://admin:***@proxy.corp.internal:8080")


class TestHTTPConnectivity(unittest.TestCase):
    """Tests HTTP/HTTPS connectivity checks including 404/403 and fallback behavior."""

    @patch("requests.Session.get")
    def test_http_200_ok(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = "https://example.com/"
        mock_resp.headers = {"Server": "ECS", "Content-Type": "text/html"}
        mock_resp.cookies = []
        mock_resp.history = []
        mock_get.return_value = mock_resp

        norm = normalize_target_url("https://example.com")
        res = check_http_connectivity(norm)
        self.assertTrue(res["reachable"])
        self.assertEqual(res["status_code"], 200)
        self.assertFalse(res["used_http_fallback"])

    @patch("requests.Session.get")
    def test_http_404_reachable(self, mock_get):
        """Reachable servers returning 404 must be marked reachable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.url = "https://example.com/missing"
        mock_resp.headers = {"Server": "Apache/2.4"}
        mock_resp.cookies = []
        mock_resp.history = []
        mock_get.return_value = mock_resp

        norm = normalize_target_url("https://example.com/missing")
        res = check_http_connectivity(norm)
        self.assertTrue(res["reachable"])
        self.assertEqual(res["status_code"], 404)

    @patch("requests.Session.get")
    def test_http_403_reachable(self, mock_get):
        """Reachable servers returning 403 must be marked reachable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.url = "https://example.com/restricted"
        mock_resp.headers = {"Server": "Nginx"}
        mock_resp.cookies = []
        mock_resp.history = []
        mock_get.return_value = mock_resp

        norm = normalize_target_url("https://example.com/restricted")
        res = check_http_connectivity(norm)
        self.assertTrue(res["reachable"])
        self.assertEqual(res["status_code"], 403)

    @patch("requests.Session.get")
    def test_https_fallback_to_http(self, mock_get):
        """When HTTPS fails with connection reset, fall back to plain HTTP."""
        def side_effect(url, **kwargs):
            if url.startswith("https://"):
                raise requests.exceptions.ConnectionError("Connection forcibly closed")
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.url = "http://example.com/"
            mock_resp.headers = {"Server": "Apache"}
            mock_resp.cookies = []
            mock_resp.history = []
            return mock_resp

        mock_get.side_effect = side_effect
        norm = normalize_target_url("https://example.com")
        res = check_http_connectivity(norm, allow_http_fallback=True)
        self.assertTrue(res["reachable"])
        self.assertTrue(res["used_http_fallback"])
        self.assertEqual(res["status_code"], 200)


class TestEngineStatusModel(unittest.TestCase):
    """Tests the canonical 4-state engine status model."""

    def test_status_normalization(self):
        self.assertEqual(normalize_engine_status("completed"), "EXECUTED")
        self.assertEqual(normalize_engine_status("EXECUTED"), "EXECUTED")
        self.assertEqual(normalize_engine_status("not_applicable"), "NOT_APPLICABLE")
        self.assertEqual(normalize_engine_status("NOT_APPLICABLE"), "NOT_APPLICABLE")
        self.assertEqual(normalize_engine_status("not_executed"), "SKIPPED")
        self.assertEqual(normalize_engine_status("SKIPPED"), "SKIPPED")
        self.assertEqual(normalize_engine_status("failed"), "FAILED")
        self.assertEqual(normalize_engine_status("not_installed"), "FAILED")

    def test_build_scanner_record(self):
        rec = build_scanner_record(
            scanner="test_engine",
            name="Test Engine",
            available=True,
            version="1.0",
            executed=True,
            status="completed",
        )
        self.assertEqual(rec["status"], "EXECUTED")
        self.assertTrue(rec["executed"])


class TestEngineIsolationAndOrchestration(unittest.TestCase):
    """Tests engine isolation when DNS fails or target is unreachable."""

    def test_dns_failure_marks_web_skipped_and_repo_not_applicable(self):
        orch = ScanOrchestrator()
        # Scan a guaranteed non-resolving domain
        res = orch.orchestrate_website_scan("nonexistent-testaudit-domain-xyz-999.test")
        self.assertEqual(res["status"], "DNS_FAILURE")
        
        # Verify scan coverage statuses
        executed_names = [s["scanner"] for s in res["scan_coverage"]["scanners_executed"]]
        self.assertEqual(len(executed_names), 0)

        not_run_statuses = {s["scanner"]: s["status"] for s in res["scan_coverage"]["scanners_not_run"]}
        # Network engines must be SKIPPED
        self.assertEqual(not_run_statuses.get("passive_web_scanner"), "SKIPPED")
        self.assertEqual(not_run_statuses.get("tls_analyzer"), "SKIPPED")
        self.assertEqual(not_run_statuses.get("nuclei"), "SKIPPED")
        # Repo engines must be NOT_APPLICABLE
        self.assertEqual(not_run_statuses.get("mcp_scanner"), "NOT_APPLICABLE")
        self.assertEqual(not_run_statuses.get("semgrep"), "NOT_APPLICABLE")
        self.assertEqual(not_run_statuses.get("gitleaks"), "NOT_APPLICABLE")


if __name__ == "__main__":
    unittest.main()
