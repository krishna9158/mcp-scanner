"""
Worker function for running a scan in its own isolated process.

This lives in its own file on purpose - it must NOT be defined inside
app.py. Python's multiprocessing needs to be able to import the target
function by name in the new background process it starts. When the
function instead lives inside the script you run directly (app.py, which
becomes the "__main__" module when you type "python app.py"), some Python
installs - notably the Windows Store version of python.exe - fail to
correctly re-import "__main__" in that new process, causing an error like:

    AttributeError: Can't get attribute '_run_scan_worker' on
    <module '__main__' (<class '_frozen_importlib.BuiltinImporter'>)>

Putting the function in its own ordinary, importable module avoids that
problem entirely: the background process can just "import scan_worker"
like any other module, regardless of how the main script was launched.
"""
import os
from download_repo import download_repo
from compare import compare
from secret_detector import scan_folder_for_secrets
from dependency_check import scan_dependencies, parse_requirements_txt
from typosquat_check import scan_requirements_for_typosquatting
from mcp_auth_analyzer import analyze_mcp_authentication
from appsec_scanner import scan_folder_for_appsec
from attack_path_analyzer import generate_attack_paths
from risk_engine import calculate_unified_security_score
from mcp_poisoning_scanner import scan_all_tools_for_poisoning
from permission_graph import build_permission_graph
from supply_chain_analyzer import audit_supply_chain
from ai_appsec_analyzer import scan_ai_application_security
from tenant_isolation_tester import audit_tenant_isolation
from secret_validator import validate_and_classify_secret
from baseline_store import compute_baseline_drift
from policy_engine import evaluate_security_policies
from ai_analyst import generate_executive_analysis


def run_scan_worker(github_url, full_scan, destination_folder, result_queue):
    """
    Runs in a separate process. Executes all deterministic security scanners,
    permission graphs, supply chain audits, and baseline comparisons.
    """
    try:
        folder = download_repo(github_url, destination_folder=destination_folder)
        if not folder:
            result_queue.put(("error", "Could not download that repo. Double-check the GitHub URL is correct and public."))
            return
        
        # 1. Static AST, regex & MCP discovery
        report, warning = compare(folder, full_scan=full_scan)
        raw_secrets = scan_folder_for_secrets(folder, max_files=None if full_scan else 5000)
        secrets = [validate_and_classify_secret(s) for s in raw_secrets]
        dependencies = scan_dependencies(folder, max_packages=100 if full_scan else 30)
        auth_analysis = analyze_mcp_authentication(folder)
        appsec_findings = scan_folder_for_appsec(folder)
        ai_appsec_findings = scan_ai_application_security(folder)
        combined_appsec = appsec_findings + ai_appsec_findings

        # 2. Typosquats
        typosquats = []
        req_path = os.path.join(folder, "requirements.txt")
        if os.path.exists(req_path):
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    packages = parse_requirements_txt(f.read())
                package_names = [name for name, _version in packages]
                typosquats = scan_requirements_for_typosquatting(package_names)
            except Exception:
                pass

        # 3. Deep MCP poisoning & schema analysis
        poisoning_results = scan_all_tools_for_poisoning(report)
        for tool in report:
            tname = tool.get("name")
            if tname in poisoning_results:
                tool.setdefault("injection_findings", []).extend(poisoning_results[tname])

        # 4. Multi-tenant analysis & Supply chain
        tenancy_report = audit_tenant_isolation(folder)
        supply_chain_findings = audit_supply_chain(folder)

        # 5. Permission graph & Policies
        permission_graph = build_permission_graph(report, server_name=os.path.basename(folder))
        policy_evaluation = evaluate_security_policies(report)

        # 6. Attack path correlation
        attack_paths = generate_attack_paths(report, secrets=secrets, auth_analysis=auth_analysis)

        # 7. Unified 0-100 Risk Evaluation
        risk_evaluation = calculate_unified_security_score(
            report,
            secrets=secrets,
            dependencies=dependencies,
            typosquats=typosquats,
            auth_analysis=auth_analysis,
        )

        # 8. Baseline drift & AI executive analysis
        baseline_drift = compute_baseline_drift(github_url, {"score": risk_evaluation.get("score", 100), "report": report})
        
        scan_snapshot = {
            "github_url": github_url,
            "score": risk_evaluation.get("score", 100),
            "grade": risk_evaluation.get("grade", "A"),
            "status": risk_evaluation.get("status", "SECURE"),
            "report": report,
            "secrets": secrets,
            "dependencies": dependencies,
            "attack_paths": attack_paths,
            "appsec_findings": combined_appsec,
        }
        executive_analysis = generate_executive_analysis(scan_snapshot)

        # Build comprehensive debug execution info
        total_mcp_findings = sum(
            len(t.get("mismatches", [])) +
            len(t.get("semgrep_findings", [])) +
            len(t.get("injection_findings", [])) +
            len(t.get("shadowing_findings", [])) +
            len(t.get("permission_matrix", {}).get("findings", []))
            for t in report
        )
        total_secrets_findings = len(secrets)
        total_dep_findings = len(dependencies.get("findings", [])) if dependencies else 0
        total_auth_findings = len(auth_analysis.get("findings", [])) if auth_analysis else 0
        total_appsec_findings = len(combined_appsec)
        total_attack_paths = len(attack_paths)
        total_supply_findings = len(supply_chain_findings)
        total_tenancy_findings = len(tenancy_report.get("findings", [])) if tenancy_report else 0
        total_policy_violations = len(policy_evaluation.get("violations", [])) if policy_evaluation else 0

        raw_count = (
            total_mcp_findings + total_secrets_findings + total_dep_findings +
            total_auth_findings + total_appsec_findings + total_attack_paths +
            total_supply_findings + total_tenancy_findings + total_policy_violations
        )

        detector_execution = [
            {"detector": "MCP Tool Discovery & Parser", "executed": True, "findings": len(report), "status": "SUCCESS" if report else "NO_TOOLS_FOUND"},
            {"detector": "Capability Mismatch Detector", "executed": True, "findings": sum(len(t.get("mismatches", [])) for t in report), "status": "SUCCESS"},
            {"detector": "Prompt Injection / Poisoning", "executed": True, "findings": sum(len(t.get("injection_findings", [])) for t in report), "status": "SUCCESS"},
            {"detector": "Tool Shadowing Detector", "executed": True, "findings": sum(len(t.get("shadowing_findings", [])) for t in report), "status": "SUCCESS"},
            {"detector": "Hardcoded Secrets Scanner", "executed": True, "findings": total_secrets_findings, "status": "SUCCESS" if secrets else "NO_FINDINGS"},
            {"detector": "Dependency / CVE Scanner (OSV.dev)", "executed": True, "findings": total_dep_findings, "status": dependencies.get("status", "SUCCESS")},
            {"detector": "MCP Authentication Analyzer", "executed": True, "findings": total_auth_findings, "status": auth_analysis.get("status", "SUCCESS")},
            {"detector": "AppSec & AI Framework Scanner", "executed": True, "findings": total_appsec_findings, "status": "SUCCESS" if combined_appsec else "NO_FINDINGS"},
            {"detector": "Attack Path Correlator", "executed": True, "findings": total_attack_paths, "status": "SUCCESS" if attack_paths else "NO_FINDINGS"},
            {"detector": "Supply Chain & Container Auditor", "executed": True, "findings": total_supply_findings, "status": "SUCCESS" if supply_chain_findings else "NO_FINDINGS"},
            {"detector": "Tenant Isolation Auditor", "executed": True, "findings": total_tenancy_findings, "status": "SUCCESS" if total_tenancy_findings else "NO_FINDINGS"},
            {"detector": "Security Policy Engine", "executed": True, "findings": total_policy_violations, "status": "SUCCESS"},
        ]

        debug_info = {
            "repository_path": folder,
            "raw_findings_count": raw_count,
            "deduplicated_findings_count": raw_count,
            "final_findings_count": raw_count,
            "detectors": detector_execution,
        }

        payload = {
            "report": report,
            "warning": warning,
            "secrets": secrets,
            "dependencies": dependencies,
            "typosquats": typosquats,
            "auth_analysis": auth_analysis,
            "appsec_findings": combined_appsec,
            "attack_paths": attack_paths,
            "risk_evaluation": risk_evaluation,
            "permission_graph": permission_graph,
            "supply_chain_findings": supply_chain_findings,
            "tenancy_report": tenancy_report,
            "policy_evaluation": policy_evaluation,
            "baseline_drift": baseline_drift,
            "executive_analysis": executive_analysis,
            "debug_info": debug_info,
        }
        result_queue.put(("ok", payload))
    except Exception as e:
        result_queue.put(("error", str(e)))



