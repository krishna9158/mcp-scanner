"""
Verification Script for Nuclei Windows Compatibility, NUCLEI_PATH Discovery, and Diagnostic Endpoint.
"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner_integrations.nuclei import NucleiScanner, validate_target_url_for_live_scan
from app import app


def test_nuclei_uninstalled_state():
    print("\n" + "="*70)
    print("TEST 1: UNINSTALLED NUCLEI DIAGNOSIS & TRANSPARENT STATUS")
    print("="*70)

    # Ensure NUCLEI_PATH is unset
    if "NUCLEI_PATH" in os.environ:
        del os.environ["NUCLEI_PATH"]

    scanner = NucleiScanner()
    scanner._cached_binary_path = None
    scanner._cached_version = None

    diag = scanner.diagnose()
    print(f"Diagnose result: {json.dumps(diag, indent=2)}")
    
    assert diag["installed"] is False
    assert diag["executable"] is None
    assert "not found" in diag["error"].lower()

    scan_res = scanner.scan("https://example.com", authorization_confirmed=True)
    print(f"Scan status: {scan_res['status']}")
    print(f"Reason: {scan_res['reason']}")
    assert scan_res["status"] == "not_installed"
    assert scan_res["executed"] is False

    with app.test_client() as client:
        resp = client.get("/api/tools/nuclei/diagnose")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["installed"] is False
        print("[PASSED] /api/tools/nuclei/diagnose correctly reports uninstalled status")


def test_nuclei_with_nuclei_path_env_var():
    print("\n" + "="*70)
    print("TEST 2: NUCLEI DISCOVERY VIA NUCLEI_PATH ENVIRONMENT VARIABLE")
    print("="*70)

    # Create a mock Windows executable script that simulates real nuclei
    temp_dir = tempfile.mkdtemp(prefix="mock_nuclei_")
    mock_bin = os.path.join(temp_dir, "mock_nuclei.bat")
    with open(mock_bin, "w", encoding="utf-8") as f:
        f.write('@echo off\n')
        f.write('if "%1"=="-version" (\n')
        f.write('    echo Nuclei Engine v3.3.7\n')
        f.write('    exit /b 0\n')
        f.write(')\n')
        f.write('echo {"template-id":"git-config-exposure","info":{"name":"Git Config Exposure","severity":"medium","description":".git/config exposed","remediation":"Block .git"},"matched-at":"https://example.com/.git/config"}\n')
        f.write('exit /b 0\n')

    os.environ["NUCLEI_PATH"] = mock_bin
    
    scanner = NucleiScanner()
    scanner._cached_binary_path = None
    scanner._cached_version = None

    diag = scanner.diagnose()
    print(f"Diagnose result with NUCLEI_PATH set:\n{json.dumps(diag, indent=2)}")

    assert diag["installed"] is True
    assert diag["executable"] == mock_bin
    assert "v3.3.7" in diag["version"]
    assert diag["error"] is None

    # Execute real scan via the discovered mock binary
    print("\n--- Executing Nuclei Scan with Backend Logging ---")
    scan_res = scanner.scan("https://example.com", authorization_confirmed=True)
    print(f"Scan status: {scan_res['status']}")
    print(f"Findings count: {scan_res['findings_count']}")
    
    assert scan_res["status"] == "completed"
    assert scan_res["executed"] is True
    assert scan_res["findings_count"] == 1
    
    finding = scan_res["normalized_findings"][0]
    print(f"Normalized Finding: [{finding['severity']}] {finding['title']} at {finding['file']}")
    assert finding["scanner"] == "nuclei"
    assert finding["severity"] == "MEDIUM"

    with app.test_client() as client:
        resp = client.get("/api/tools/nuclei/diagnose")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["installed"] is True
        assert data["executable"] == mock_bin
        print("[PASSED] /api/tools/nuclei/diagnose correctly reports installed state with version")

    # Cleanup
    if "NUCLEI_PATH" in os.environ:
        del os.environ["NUCLEI_PATH"]


def test_nuclei_execution_failure_handling():
    print("\n" + "="*70)
    print("TEST 3: NUCLEI PROCESS EXECUTION FAILURE (STATUS = FAILED)")
    print("="*70)

    temp_dir = tempfile.mkdtemp(prefix="mock_nuclei_fail_")
    mock_bin = os.path.join(temp_dir, "mock_nuclei_fail.bat")
    with open(mock_bin, "w", encoding="utf-8") as f:
        f.write('@echo off\n')
        f.write('if "%1"=="-version" (\n')
        f.write('    echo Nuclei Engine v3.3.7\n')
        f.write('    exit /b 0\n')
        f.write(')\n')
        f.write('echo Fatal error: network interface unreachable 1>&2\n')
        f.write('exit /b 1\n')

    os.environ["NUCLEI_PATH"] = mock_bin
    scanner = NucleiScanner()
    scanner._cached_binary_path = None
    scanner._cached_version = None

    scan_res = scanner.scan("https://example.com", authorization_confirmed=True)
    print(f"Scan status: {scan_res['status']}")
    print(f"Captured Error: {scan_res.get('error')}")

    assert scan_res["status"] == "failed"
    assert scan_res["executed"] is True
    assert "network interface unreachable" in scan_res["error"]

    if "NUCLEI_PATH" in os.environ:
        del os.environ["NUCLEI_PATH"]
    print("[PASSED] Process failure is truthfully captured as FAILED with real stderr message!")


if __name__ == "__main__":
    try:
        test_nuclei_uninstalled_state()
        test_nuclei_with_nuclei_path_env_var()
        test_nuclei_execution_failure_handling()
        print("\n" + "="*70)
        print("ALL NUCLEI WINDOWS COMPATIBILITY & DEBUG TESTS PASSED 100%!")
        print("="*70)
    except Exception as e:
        print(f"\n[FAILED] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
