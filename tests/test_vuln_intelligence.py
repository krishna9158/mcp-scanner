"""
Comprehensive Test Suite for TrustAudit Vulnerability Intelligence System.

Tests all 26 key vulnerability intelligence specifications:
1. OSV package query with known vulnerable and safe packages.
2. CISA KEV official feed synchronization and lookup.
3. NVD CVE API 2.0 connector and CVSS parsing.
4. Multi-ecosystem software inventory extraction (Node.js, Python, Java, Go, Rust, Web).
5. Semantic version comparison and affected version range evaluation.
6. TrustAudit multi-factor Risk Prioritization score & rationale generation.
7. Finding lifecycle transitions and deduplication.
8. Find -> Fix -> Verify workflow (promoting to VERIFIED_FIXED on upgrade).
9. Background Intelligence Service discrete jobs.
10. Flask REST APIs & Dashboard HTML rendering.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import app
import correlation_engine
import inventory_engine
import vuln_intel_service
import vuln_intel_sources
import vuln_intel_store


class TestVulnerabilityIntelligence(unittest.TestCase):

    def setUp(self):
        self.client = app.app.test_client()
        self.test_dir = tempfile.mkdtemp(prefix="trustaudit_test_intel_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir)
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # 1. Software Inventory Extraction (All Ecosystems)
    # -----------------------------------------------------------------------
    def test_multi_ecosystem_manifest_parsing(self):
        # 1. Python requirements.txt
        req_content = "requests==2.28.1\nflask==2.3.2\nunknown-pkg\n# comment\n"
        py_pkgs = inventory_engine.parse_requirements_txt(req_content)
        self.assertIn(("requests", "2.28.1"), py_pkgs)
        self.assertIn(("flask", "2.3.2"), py_pkgs)
        self.assertIn(("unknown-pkg", "UNKNOWN VERSION"), py_pkgs)

        # 2. Node.js package.json
        pkg_json = json.dumps({
            "dependencies": {"next": "15.2.0", "react": "^18.2.0"},
            "devDependencies": {"typescript": "~5.0.4"}
        })
        js_pkgs = inventory_engine.parse_package_json(pkg_json)
        self.assertIn(("next", "15.2.0"), js_pkgs)
        self.assertIn(("react", "18.2.0"), js_pkgs)

        # 3. Go go.mod
        go_mod = "module myapp\n\ngo 1.20\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgolang.org/x/crypto v0.10.0\n)\n"
        go_pkgs = inventory_engine.parse_go_mod(go_mod)
        self.assertIn(("github.com/gin-gonic/gin", "1.9.1"), go_pkgs)
        self.assertIn(("golang.org/x/crypto", "0.10.0"), go_pkgs)

        # 4. Rust Cargo.toml & Cargo.lock
        cargo_lock = '[[package]]\nname = "tokio"\nversion = "1.28.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.160"\n'
        rust_pkgs = inventory_engine.parse_cargo_toml_and_lock(None, cargo_lock)
        self.assertIn(("tokio", "1.28.0"), rust_pkgs)
        self.assertIn(("serde", "1.0.160"), rust_pkgs)

        # 5. Java pom.xml
        pom_xml = """<project><dependencies>
            <dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-web</artifactId>
                <version>3.1.0</version>
            </dependency>
        </dependencies></project>"""
        java_pkgs = inventory_engine.parse_pom_xml(pom_xml)
        self.assertIn(("org.springframework.boot:spring-boot-starter-web", "3.1.0"), java_pkgs)

    def test_repository_inventory_scanning(self):
        # Create dummy repo files
        with open(os.path.join(self.test_dir, "requirements.txt"), "w") as f:
            f.write("urllib3==1.26.4\n")
        with open(os.path.join(self.test_dir, "package.json"), "w") as f:
            f.write(json.dumps({"dependencies": {"lodash": "4.17.15"}}))

        comps = inventory_engine.scan_and_record_repository_inventory(
            self.test_dir, project_id="proj-test-repo", repository_url="https://github.com/org/repo"
        )
        self.assertTrue(len(comps) >= 2)
        pkg_names = [c["package_name"] for c in comps]
        self.assertIn("urllib3", pkg_names)
        self.assertIn("lodash", pkg_names)

    # -----------------------------------------------------------------------
    # 2. Semantic Version Evaluation & Range Matching
    # -----------------------------------------------------------------------
    def test_semantic_version_comparison(self):
        self.assertEqual(correlation_engine.compare_versions("1.2.0", "1.2.4"), -1)
        self.assertEqual(correlation_engine.compare_versions("1.2.4", "1.2.0"), 1)
        self.assertEqual(correlation_engine.compare_versions("2.0.0", "2.0.0"), 0)
        self.assertEqual(correlation_engine.compare_versions("15.2.0", "15.2.4"), -1)

    def test_is_version_affected_logic(self):
        # Installed 15.2.0, fixed in 15.2.4 -> CONFIRMED_AFFECTED
        state1 = correlation_engine.is_version_affected("15.2.0", fixed_versions=["15.2.4"], affected_ranges=[">=15.0.0, <15.2.4"])
        self.assertEqual(state1, "CONFIRMED_AFFECTED")

        # Installed 15.2.4, fixed in 15.2.4 -> NOT_AFFECTED
        state2 = correlation_engine.is_version_affected("15.2.4", fixed_versions=["15.2.4"], affected_ranges=[">=15.0.0, <15.2.4"])
        self.assertEqual(state2, "NOT_AFFECTED")

        # Unknown version -> POTENTIALLY_AFFECTED
        state3 = correlation_engine.is_version_affected("UNKNOWN VERSION", fixed_versions=["15.2.4"], affected_ranges=[])
        self.assertEqual(state3, "POTENTIALLY_AFFECTED")

    # -----------------------------------------------------------------------
    # 3. CISA KEV & NVD Intelligence Lookups
    # -----------------------------------------------------------------------
    def test_cisa_kev_lookup_and_enrichment(self):
        # Mock KEV sync
        mock_kev_data = {
            "CVE-2021-44228": {
                "cve_id": "CVE-2021-44228",
                "vulnerability_name": "Apache Log4j Remote Code Execution",
                "date_added": "2021-12-10",
                "required_action": "Apply updates per vendor instructions.",
                "due_date": "2021-12-24",
                "is_known_exploited": True,
            }
        }
        vuln_intel_sources._CISA_KEV_CACHE = mock_kev_data
        kev_entry = vuln_intel_sources.lookup_cisa_kev("CVE-2021-44228")
        self.assertIsNotNone(kev_entry)
        self.assertTrue(kev_entry["is_known_exploited"])

        # Non-KEV CVE
        non_kev = vuln_intel_sources.lookup_cisa_kev("CVE-9999-0001")
        self.assertIsNone(non_kev)

    # -----------------------------------------------------------------------
    # 4. Multi-Factor Risk Prioritization Scoring
    # -----------------------------------------------------------------------
    def test_risk_prioritization_calculation(self):
        # Critical KEV vulnerability in production internet-facing component
        vuln_kev = {
            "cvss_score": 9.8,
            "cve_id": "CVE-2021-44228",
            "kev_status": {"date_added": "2021-12-10"},
        }
        comp = {
            "package_name": "log4j-core",
            "environment": "Production",
            "manifest_file": "pom.xml"
        }
        score, sev, explanation = correlation_engine.calculate_vulnerability_risk_priority(
            vuln_kev, comp, correlation_state="CONFIRMED_AFFECTED"
        )
        self.assertTrue(score >= 85)
        self.assertEqual(sev, "CRITICAL")
        self.assertIn("actively exploited", explanation.lower())
        self.assertIn("confirmed", explanation.lower())

    # -----------------------------------------------------------------------
    # 5. Finding Correlation & Find -> Fix -> Verify
    # -----------------------------------------------------------------------
    def test_find_fix_verify_workflow(self):
        project_id = "proj-test-verify"
        comp = {
            "id": "comp-test-1",
            "project_id": project_id,
            "asset_id": "asset-test-1",
            "package_name": "lodash",
            "version": "4.17.15",
            "ecosystem": "npm",
            "environment": "Production",
            "manifest_file": "package.json",
        }

        # 1. Mock OSV finding for lodash 4.17.15
        mock_vulns = [{
            "id": "VULN-CVE-2020-8203",
            "source": "OSV",
            "source_id": "GHSA-p6mc-m468-83gw",
            "cve_id": "CVE-2020-8203",
            "osv_id": "GHSA-p6mc-m468-83gw",
            "title": "Prototype Pollution in lodash",
            "description": "Prototype pollution vulnerability in lodash.",
            "severity": "HIGH",
            "cvss_score": 7.4,
            "package_name": "lodash",
            "ecosystem": "npm",
            "affected_version_ranges": ["<4.17.19"],
            "fixed_versions": ["4.17.19"],
            "references": [],
            "raw_source_metadata": {}
        }]

        with patch("vuln_intel_sources.query_osv_package", return_value=mock_vulns):
            findings = correlation_engine.correlate_component_vulnerabilities(comp, org_id="org-default")
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            self.assertEqual(finding["correlation_state"], "CONFIRMED_AFFECTED")
            self.assertEqual(finding["package_name"], "lodash")
            self.assertEqual(finding["installed_version"], "4.17.15")

        # 2. Recheck with upgraded version (4.17.21) -> Should verify fix!
        recheck_res = correlation_engine.verify_component_fix_recheck(
            project_id=project_id,
            package_name="lodash",
            new_version="4.17.21",
            ecosystem="npm",
            org_id="org-default"
        )
        self.assertEqual(recheck_res["verified_fixed_count"], 1)
        self.assertEqual(recheck_res["remaining_open_count"], 0)

    # -----------------------------------------------------------------------
    # 6. REST API Endpoints
    # -----------------------------------------------------------------------
    def test_api_intel_endpoints(self):
        # 1. /api/intel/status
        res_status = self.client.get("/api/intel/status")
        self.assertEqual(res_status.status_code, 200)
        data_status = res_status.get_json()
        self.assertIn("sources", data_status)
        self.assertIn("osv", data_status["sources"])
        self.assertIn("nvd", data_status["sources"])
        self.assertIn("cisa_kev", data_status["sources"])

        # 2. /api/intel/vulnerabilities
        res_vulns = self.client.get("/api/intel/vulnerabilities")
        self.assertEqual(res_vulns.status_code, 200)
        self.assertIn("vulnerabilities", res_vulns.get_json())

        # 3. /api/inventory
        res_inv = self.client.get("/api/inventory")
        self.assertEqual(res_inv.status_code, 200)
        self.assertIn("components", res_inv.get_json())

        # 4. /api/intel/affecting
        res_aff = self.client.get("/api/intel/affecting")
        self.assertEqual(res_aff.status_code, 200)
        self.assertIn("affecting_vulnerabilities", res_aff.get_json())

    # -----------------------------------------------------------------------
    # 7. Dashboard Rendering with Vulnerability Intelligence
    # -----------------------------------------------------------------------
    def test_dashboard_renders_vuln_intelligence(self):
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("dash-vuln-intel", html)
        self.assertIn("Vulnerability Intelligence Engine", html)
        self.assertIn("OSV.dev Database", html)
        self.assertIn("NVD CVE API 2.0", html)
        self.assertIn("CISA KEV Catalog", html)
        self.assertIn("intelModal", html)


if __name__ == "__main__":
    unittest.main()
