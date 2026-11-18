"""
TrustAudit Platform CLI.

Commands:
    trustaudit scan <path|url> [--full-scan] [--json]
    trustaudit test <path> [--fail-on CRITICAL|HIGH|MEDIUM]
    trustaudit baseline <path>
    trustaudit diff <path>

Exit codes:
    0 = PASS / Clean
    1 = SECURITY FAILURE (Findings exceed threshold or regression failed)
    2 = CONFIGURATION / USAGE ERROR
"""
import argparse
import sys
import os
import json

from compare import compare
from secret_detector import scan_folder_for_secrets
from dependency_check import scan_dependencies
from mcp_auth_analyzer import analyze_mcp_authentication
from ai_appsec_analyzer import scan_ai_application_security
from attack_path_analyzer import generate_attack_paths
from risk_engine import calculate_unified_security_score
from baseline_store import set_security_baseline, compute_baseline_drift
from regression_test_engine import run_regression_tests


from website_scanner import scan_website, is_github_repo_url


def run_local_scan(path, full_scan=False):
    """Executes full multi-surface scan against a local directory."""
    if not os.path.exists(path):
        print(f"Error: Path '{path}' does not exist.", file=sys.stderr)
        sys.exit(2)

    report, warning = compare(path, full_scan=full_scan)
    secrets = scan_folder_for_secrets(path, max_files=None if full_scan else 5000)
    dependencies = scan_dependencies(path, max_packages=100 if full_scan else 30)
    auth_analysis = analyze_mcp_authentication(path)
    appsec_findings = scan_ai_application_security(path)
    attack_paths = generate_attack_paths(report, secrets=secrets, auth_analysis=auth_analysis)
    
    risk_evaluation = calculate_unified_security_score(
        report, secrets=secrets, dependencies=dependencies, auth_analysis=auth_analysis
    )

    return {
        "target_type": "repository",
        "path": os.path.abspath(path),
        "score": risk_evaluation.get("score", 100),
        "grade": risk_evaluation.get("grade", "A"),
        "status": risk_evaluation.get("status", "SECURE"),
        "category_scores": risk_evaluation.get("category_scores", {}),
        "warning": warning,
        "report": report,
        "secrets": secrets,
        "dependencies": dependencies,
        "auth_analysis": auth_analysis,
        "appsec_findings": appsec_findings,
        "attack_paths": attack_paths,
    }


def main():
    parser = argparse.ArgumentParser(prog="trustaudit", description="TrustAudit AI & Web Continuous Security Platform CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. scan command
    scan_parser = subparsers.add_parser("scan", help="Run full security scan on a repository folder or website URL")
    scan_parser.add_argument("target", help="Path to local repository folder or website URL (https://...)")
    scan_parser.add_argument("--type", choices=["auto", "repository", "website"], default="auto", help="Explicit target type")
    scan_parser.add_argument("--full-scan", action="store_true", help="Inspect all files without heuristic caps")
    scan_parser.add_argument("--json", action="store_true", help="Output results as JSON")

    # 2. test command (CI quality gate)
    test_parser = subparsers.add_parser("test", help="Run CI security quality gate with strict exit codes")
    test_parser.add_argument("path", help="Path to local repository folder")
    test_parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "NEVER"], default="CRITICAL", help="Severity threshold to fail build")

    # 3. baseline command
    base_parser = subparsers.add_parser("baseline", help="Set current repository version as the approved security baseline")
    base_parser.add_argument("path", help="Path to local repository folder")

    # 4. diff command
    diff_parser = subparsers.add_parser("diff", help="Compare current code against approved baseline for security drift")
    diff_parser.add_argument("path", help="Path to local repository folder")

    args = parser.parse_args()

    if args.command == "scan":
        target = args.target
        target_type = args.type

        if target_type == "auto":
            if (target.startswith("http://") or target.startswith("https://")) and not os.path.exists(target):
                target_type = "website"
            else:
                target_type = "repository"

        if target_type == "website":
            result = scan_website(target)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"\n=======================================================")
                print(f" TrustAudit Web Security Audit: {result.get('target_url')}")
                print(f" Score: {result.get('score')}/100 (Grade {result.get('grade')}) - {result.get('status')}")
                print(f"=======================================================")
                print(f" Total Findings:    {len(result.get('findings', []))}")
                print(f" TLS Encryption:    {result.get('subscores', {}).get('tls_encryption', 100)}/100")
                print(f" Security Headers:  {result.get('subscores', {}).get('security_headers', 100)}/100")
                print(f" Cookie Security:   {result.get('subscores', {}).get('cookie_security', 100)}/100")
                print(f" CORS Access:       {result.get('subscores', {}).get('cors_access', 100)}/100\n")
            sys.exit(0)
        else:
            result = run_local_scan(target, full_scan=args.full_scan)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"\n=======================================================")
                print(f" TrustAudit Security Audit: {result['path']}")
                print(f" Score: {result['score']}/100 (Grade {result['grade']}) - {result['status']}")
                print(f"=======================================================")
                print(f" MCP Tools Scanned: {len(result['report'])}")
                print(f" Secrets Detected:  {len(result['secrets'])}")
                print(f" Attack Paths:      {len(result['attack_paths'])}")
                print(f" AppSec Findings:   {len(result['appsec_findings'])}\n")
            sys.exit(0)



    elif args.command == "baseline":
        result = run_local_scan(args.path, full_scan=True)
        set_security_baseline(args.path, result)
        print(f"[+] Successfully established security baseline for '{args.path}' (Score: {result['score']}/100, Grade {result['grade']}).")
        sys.exit(0)

    elif args.command == "diff":
        result = run_local_scan(args.path, full_scan=False)
        drift = compute_baseline_drift(args.path, result)
        if not drift.get("has_baseline"):
            print(f"[!] {drift['message']}")
            sys.exit(2)
        print(f"\n--- Baseline Drift Analysis ---")
        print(f"Baseline Score: {drift['baseline_score']} -> Current Score: {drift['current_score']} (Delta: {drift['score_drift']})")
        print(f"Rug-Pull Alerts: {len(drift['rug_pull_alerts'])}")
        print(f"Drift Events:    {len(drift['drift_events'])}")
        if not drift["is_clean"]:
            for alert in drift["rug_pull_alerts"]:
                print(f" [CRITICAL] {alert['type']}: {alert['detail']}")
            sys.exit(1)
        print("[+] Zero malicious drift detected.")
        sys.exit(0)

    elif args.command == "test":
        result = run_local_scan(args.path, full_scan=False)
        crit_count = sum(1 for s in result["secrets"] if s.get("severity") == "CRITICAL")
        crit_count += sum(1 for a in result["appsec_findings"] if a.get("severity") == "CRITICAL")
        crit_count += sum(1 for ap in result["attack_paths"] if ap.get("severity") == "CRITICAL")

        # Run regression tests
        reg_eval = run_regression_tests(args.path, result["secrets"] + result["appsec_findings"])
        
        print(f"\n--- Antigravity CI Quality Gate ---")
        print(f"Overall Score: {result['score']}/100 (Grade {result['grade']})")
        print(f"Critical Findings: {crit_count}")
        print(f"Regression Tests:  {reg_eval['passed_count']}/{reg_eval['total_tests']} passed")

        if reg_eval["has_regressions"]:
            print(f"\n[FAIL] BUILD BLOCKED: Security regression detected in previous verified fixes.")
            sys.exit(1)

        if args.fail_on == "CRITICAL" and crit_count > 0:
            print(f"\n[FAIL] BUILD BLOCKED: {crit_count} Critical security finding(s) detected.")
            sys.exit(1)

        print("\n[PASS] CI Security Gate: PASSED")
        sys.exit(0)



if __name__ == "__main__":
    main()
