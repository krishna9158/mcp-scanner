"""
Comprehensive Verification Script for Three Scan Modes, Real Subprocess Execution & Tool Health:
1. Mode A: Website Scan Execution & Telemetry
2. Mode B: Repository / Source Code Scan Execution & Telemetry
3. Mode C: Dedicated MCP Security Scan Execution & Telemetry
4. Missing Tool Simulation (NOT_INSTALLED Status & Setup Guide)
5. Tool Health API & Registry Verification
6. Uploaded Project (ZIP archive) Scan Verification
"""

import json
import os
import sys
import time
import tempfile
import zipfile
import io

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_integrations.orchestrator import ScanOrchestrator
from scanner_integrations.tool_health import get_all_tool_health, SETUP_GUIDES
from app import app, execute_scan, execute_website_scan, execute_mcp_scan


def test_mode_a_website_scan():
    print("\n" + "="*70)
    print("TEST 1: MODE A - WEBSITE SCAN ACTUAL EXECUTION")
    print("="*70)

    orchestrator = ScanOrchestrator()
    target_url = "https://example.com"
    
    t0 = time.time()
    result = orchestrator.orchestrate_website_scan(target_url, authorization_confirmed=True)
    duration = time.time() - t0

    print(f"Target: {result.get('target_url')}")
    print(f"Mode: {result.get('scan_mode')}")
    print(f"Score: {result.get('score')}/100 (Grade {result.get('grade')})")
    print(f"Score Explanation: {result.get('score_explanation')}")
    print(f"Duration: {duration:.2f}s")
    
    coverage = result.get("scan_coverage", {})
    print(f"Coverage Summary: {coverage.get('summary')}")
    
    executed = [sc["scanner"] for sc in coverage.get("scanners_executed", [])]
    not_run = [sc["scanner"] for sc in coverage.get("scanners_not_run", [])]
    
    print(f"Executed Engines ({len(executed)}): {', '.join(executed)}")
    print(f"Not Run / Not Applicable ({len(not_run)}): {', '.join(not_run)}")

    assert "passive_web_scanner" in executed
    assert "tls_analyzer" in executed
    assert "headers_analyzer" in executed
    assert "cookie_analyzer" in executed
    assert "cors_analyzer" in executed
    assert "exposure_scanner" in executed
    assert "api_discovery" in executed

    assert "semgrep" in not_run
    assert "gitleaks" in not_run
    assert "osv_scanner" in not_run
    assert "mcp_scanner" in not_run
    assert "syft" in not_run

    print("[PASSED] Mode A (Website Scan) verified successfully!")


def test_mode_b_repository_scan():
    print("\n" + "="*70)
    print("TEST 2: MODE B - REPOSITORY / SOURCE CODE SCAN ACTUAL EXECUTION")
    print("="*70)

    orchestrator = ScanOrchestrator()
    tiny_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "fixtures", "tiny-project")
    
    t0 = time.time()
    result = orchestrator.orchestrate_repository_scan(tiny_path, full_scan=False)
    duration = time.time() - t0

    print(f"Target: {result.get('github_url')}")
    print(f"Mode: {result.get('scan_mode')}")
    print(f"Score: {result.get('score')}/100 (Grade {result.get('grade')})")
    print(f"Score Explanation: {result.get('score_explanation')}")
    print(f"Duration: {duration:.2f}s")
    
    coverage = result.get("scan_coverage", {})
    print(f"Coverage Summary: {coverage.get('summary')}")
    
    executed = [sc["scanner"] for sc in coverage.get("scanners_executed", [])]
    not_run = [sc["scanner"] for sc in coverage.get("scanners_not_run", [])]
    
    print(f"Executed Engines ({len(executed)}): {', '.join(executed)}")
    print(f"Not Run / Not Applicable ({len(not_run)}): {', '.join(not_run)}")

    assert "mcp_scanner" in executed
    assert "semgrep" in executed
    assert "trustaudit_secrets" in executed
    assert "dependency_checker" in executed
    assert "syft" in executed
    assert "appsec_analyzer" in executed
    assert "attack_path_engine" in executed

    assert "passive_web_scanner" in not_run
    assert "nuclei" in not_run

    print("[PASSED] Mode B (Repository Scan) verified successfully!")


def test_mode_c_mcp_scan():
    print("\n" + "="*70)
    print("TEST 3: MODE C - DEDICATED MCP SECURITY SCAN ACTUAL EXECUTION")
    print("="*70)

    orchestrator = ScanOrchestrator()
    vuln_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "fixtures", "vulnerable-project")
    
    t0 = time.time()
    result = orchestrator.orchestrate_mcp_scan(vuln_path, full_scan=True, target_name="Vulnerable MCP Server")
    duration = time.time() - t0

    print(f"Target: {result.get('target')}")
    print(f"Mode: {result.get('scan_mode')}")
    print(f"Score: {result.get('score')}/100 (Grade {result.get('grade')})")
    print(f"Score Explanation: {result.get('score_explanation')}")
    print(f"Total Unified Findings: {len(result.get('findings', []))}")
    print(f"MCP Tools Analyzed: {len(result.get('report', []))}")
    print(f"Attack Paths: {len(result.get('attack_paths', []))}")
    print(f"Duration: {duration:.2f}s")
    
    coverage = result.get("scan_coverage", {})
    executed = [sc["scanner"] for sc in coverage.get("scanners_executed", [])]
    not_run = [sc["scanner"] for sc in coverage.get("scanners_not_run", [])]
    
    print(f"Executed Engines: {', '.join(executed)}")
    print(f"Not Run Engines: {', '.join(not_run)}")

    assert "mcp_scanner" in executed
    assert "trustaudit_secrets" in executed
    assert "semgrep" in executed
    assert "syft" in executed
    assert "attack_path_engine" in executed
    assert "passive_web_scanner" in not_run

    print("[PASSED] Mode C (Dedicated MCP Scan) verified successfully!")


def test_tool_health_and_setup_guidance():
    print("\n" + "="*70)
    print("TEST 4: TOOL HEALTH REGISTRY & SETUP GUIDES")
    print("="*70)

    tools = get_all_tool_health()
    print(f"Total Integrated Engines Registered: {len(tools)}")
    
    for t in tools:
        print(f"  [{t['status']:<13}] {t['name']:<40} | Version: {t['version']}")
        assert "id" in t
        assert "name" in t
        assert "status" in t
        assert "install_commands" in t

    # Verify REST API endpoint
    with app.test_client() as client:
        resp = client.get("/api/health/tools")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "tools" in data
        assert len(data["tools"]) == 8
        print("[PASSED] /api/health/tools returns all 8 tools with install guidance")


def test_missing_tool_simulation():
    print("\n" + "="*70)
    print("TEST 5: MISSING TOOL SIMULATION (NOT_INSTALLED TRANSPARENCY)")
    print("="*70)

    from scanner_integrations.gitleaks import GitleaksScanner
    scanner = GitleaksScanner()
    
    # Simulate missing tool by temporarily setting check_available to return False
    orig_check = scanner.check_available
    scanner.check_available = lambda: False
    
    res = scanner.scan("tests/fixtures/tiny-project")
    scanner.check_available = orig_check  # restore
    
    print(f"Simulated Missing Binary Scan Status: {res.get('status')}")
    print(f"Reason: {res.get('reason')}")
    
    assert res.get("status") == "not_installed"
    assert res.get("executed") is False
    assert "not installed" in res.get("reason").lower()
    print("[PASSED] Missing tool correctly transitions to NOT_INSTALLED status without faking execution!")



def test_zip_file_upload_scan():
    print("\n" + "="*70)
    print("TEST 6: UPLOADED PROJECT (ZIP ARCHIVE) SCANNING")
    print("="*70)

    # Create an in-memory test ZIP containing a small project
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("package.json", '{"name": "test-pkg", "version": "1.0.0", "dependencies": {"express": "^4.18.2"}}')
        zf.writestr("server.js", 'const express = require("express");\nconst app = express();\napp.listen(3000);')
    zip_buffer.seek(0)

    with app.test_client() as client:
        response = client.post(
            "/scan",
            data={
                "scan_type": "repository",
                "full_scan": "no",
                "auth_confirmed": "yes",
                "project_file": (zip_buffer, "test-project.zip"),
            },
            content_type="multipart/form-data",
        )
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert "Scan Coverage &amp; Engine Execution Transparency" in html or "Scan Coverage" in html
        print("[PASSED] ZIP upload extraction and multi-engine scan executed successfully!")


if __name__ == "__main__":
    try:
        test_mode_a_website_scan()
        test_mode_b_repository_scan()
        test_mode_c_mcp_scan()
        test_tool_health_and_setup_guidance()
        test_missing_tool_simulation()
        test_zip_file_upload_scan()
        print("\n" + "="*70)
        print("ALL THREE SCAN MODES & TOOL HEALTH TESTS PASSED 100%!")
        print("="*70)
    except Exception as e:
        print(f"\n[FAILED] TEST ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
