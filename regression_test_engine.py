"""
Security Regression Test Engine (TrustAudit Platform).


Converts confirmed security findings into automated, reusable regression test cases.
On each future scan, evaluates whether previously fixed security flaws have regressed:
- Cross-tenant data isolation regression
- Re-introduction of dangerous shell tools
- Re-appearance of hardcoded secrets
- Unauthenticated network endpoint regression
"""
import os
import json
import time

REGRESSION_DB_PATH = os.path.join(os.path.dirname(__file__), "regression_tests.json")


def _load_tests():
    if not os.path.exists(REGRESSION_DB_PATH):
        return {}
    try:
        with open(REGRESSION_DB_PATH, "r", encoding="utf-8") as fp:
            return json.load(fp)
    except Exception:
        return {}


def _save_tests(data):
    try:
        with open(REGRESSION_DB_PATH, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2)
    except Exception:
        pass


def create_regression_test_from_finding(repo_key, finding):
    """
    Generates and persists an automated regression test from a confirmed finding.
    """
    db = _load_tests()
    repo_tests = db.setdefault(repo_key, [])

    test_id = f"REG-TEST-{len(repo_tests)+1:03d}"
    test_case = {
        "test_id": test_id,
        "name": f"Regression Guard: {finding.get('title', 'Security Finding')}",
        "category": finding.get("category", "mcp_security"),
        "severity": finding.get("severity", "HIGH"),
        "target_file": finding.get("file", ""),
        "target_tool": finding.get("tool_name", ""),
        "expected_condition": f"Vulnerability '{finding.get('title')}' must remain remediated.",
        "created_at": time.time(),
        "last_evaluated": None,
        "status": "ACTIVE_MONITORING"
    }

    repo_tests.append(test_case)
    _save_tests(db)
    return test_case


def run_regression_tests(repo_key, current_findings):
    """
    Evaluates all active regression tests against current scan findings.
    If a finding matching an active regression test is re-detected, flags REGRESSION_FAILED.
    """
    db = _load_tests()
    repo_tests = db.get(repo_key, [])

    results = []
    has_regressions = False

    for test in repo_tests:
        # Check if the vulnerability is still present in current findings
        matching_finding = next(
            (f for f in current_findings if (
                f.get("file") == test.get("target_file") and
                f.get("tool_name") == test.get("target_tool") and
                f.get("category") == test.get("category")
            )),
            None
        )

        if matching_finding:
            status = "FAILED_REGRESSION"
            has_regressions = True
            msg = f"Security regression! '{test['name']}' failed because vulnerability re-occurred in {test['target_file']}."
        else:
            status = "PASSED"
            msg = f"Clean: '{test['name']}' verified."

        test["last_evaluated"] = time.time()
        test["last_status"] = status

        results.append({
            "test_id": test["test_id"],
            "name": test["name"],
            "severity": test["severity"],
            "status": status,
            "message": msg
        })

    _save_tests(db)
    return {
        "total_tests": len(results),
        "passed_count": sum(1 for r in results if r["status"] == "PASSED"),
        "failed_count": sum(1 for r in results if r["status"] == "FAILED_REGRESSION"),
        "has_regressions": has_regressions,
        "results": results
    }
