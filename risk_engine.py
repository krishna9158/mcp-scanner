"""
Unified Multi-Dimensional Risk Engine for TrustAudit Platform.

Calculates a standardized 0-100 Security Score, Letter Grade (A-F),
and 8 domain-specific subscores:
1. Code Security Score
2. Dependency Score
3. Secret Score
4. Web Score
5. MCP Score
6. Infrastructure Score (IaC, Docker, Cloud)
7. Exposure Score
8. Overall Security Score

Deductions prioritize:
- Criticality & Severity
- Confidence & Exploitability
- Internet Exposure & Public Reachability
- Attack Path participation & Blast Radius
- Fix availability
"""

from typing import Any, Dict, List, Optional

SEVERITY_WEIGHTS = {
    "CRITICAL": 35,
    "HIGH": 18,
    "MEDIUM": 8,
    "LOW": 2,
    "INFO": 0,
}

DOMAIN_CATEGORY_MAP = {
    "code_security": "code_security",
    "dependencies": "dependency_security",
    "supply_chain": "dependency_security",
    "secrets": "secret_security",
    "website_security": "web_security",
    "tls": "web_security",
    "headers": "web_security",
    "cookies": "web_security",
    "cors": "web_security",
    "mcp_security": "mcp_security",
    "prompt_injection": "mcp_security",
    "misconfiguration": "infrastructure_security",
    "infrastructure": "infrastructure_security",
    "tenancy": "code_security",
    "exposure": "exposure_security",
    "authentication": "code_security",
    "authorization": "code_security",
}


def calculate_unified_security_score(
    report=None,
    secrets=None,
    dependencies=None,
    typosquats=None,
    auth_analysis=None,
    previous_score=None,
    raw_findings: Optional[List[Dict[str, Any]]] = None,
    attack_paths: Optional[List[Dict[str, Any]]] = None,
    iac_findings: Optional[List[Dict[str, Any]]] = None,
):
    """
    Computes comprehensive multi-dimensional security posture score (0-100)
    across all 8 security domains.
    """
    report = report or []
    secrets = secrets or []
    dependencies = dependencies or {}
    typosquats = typosquats or []
    auth_analysis = auth_analysis or {}
    attack_paths = attack_paths or []
    iac_findings = iac_findings or []
    
    # 8 domain scores initialized at 100
    domain_deductions = {
        "code_security": 0,
        "dependency_security": 0,
        "secret_security": 0,
        "web_security": 0,
        "mcp_security": 0,
        "infrastructure_security": 0,
        "exposure_security": 0,
    }

    reasons: List[str] = []
    has_critical = False

    # 1. Secrets deductions
    for sec in secrets:
        sev = sec.get("severity", "HIGH").upper()
        if sev == "CRITICAL":
            has_critical = True
        ded = SEVERITY_WEIGHTS.get(sev, 18)
        domain_deductions["secret_security"] += ded
        reasons.append(f"Exposed secret ({sev}): {sec.get('type', 'Credential')} in {sec.get('file', 'code')}")

    # 2. Dependency deductions
    dep_findings = dependencies.get("findings", []) if isinstance(dependencies, dict) else []
    for dep in dep_findings:
        vulns = dep.get("vulnerabilities", [])
        ded = min(len(vulns) * 12, 50)
        domain_deductions["dependency_security"] += ded
        reasons.append(f"Vulnerable package: {dep.get('package')} ({len(vulns)} CVEs)")

    for typo in typosquats:
        domain_deductions["dependency_security"] += 20
        reasons.append(f"Typosquatted dependency: {typo.get('package')}")

    # 3. Auth & AppSec deductions
    auth_findings = auth_analysis.get("findings", [])
    for f in auth_findings:
        sev = f.get("severity", "HIGH").upper()
        if sev == "CRITICAL":
            has_critical = True
        ded = SEVERITY_WEIGHTS.get(sev, 18)
        domain_deductions["code_security"] += ded
        reasons.append(f"{f.get('type', 'Auth Flaw')} ({sev})")

    # 4. MCP Tools deductions
    for tool in report:
        injections = tool.get("injection_findings", [])
        if injections:
            has_critical = True
            domain_deductions["mcp_security"] += 30
            reasons.append(f"Prompt injection risk in tool '{tool.get('name')}'")

        shadows = tool.get("shadowing_findings", [])
        if shadows:
            domain_deductions["mcp_security"] += 15
            reasons.append(f"Tool shadowing risk in '{tool.get('name')}'")

        risk_level = tool.get("risk_level", "LOW").upper()
        if risk_level == "CRITICAL":
            has_critical = True
            domain_deductions["mcp_security"] += 25
        elif risk_level == "HIGH":
            domain_deductions["mcp_security"] += 12

        semgrep_findings = tool.get("semgrep_findings", [])
        for sf in semgrep_findings:
            sev = sf.get("severity", "INFO").upper()
            if sev in ("CRITICAL", "ERROR", "HIGH"):
                domain_deductions["code_security"] += 15
            else:
                domain_deductions["code_security"] += 5

    # 5. IaC deductions
    for iac in iac_findings:
        sev = iac.get("severity", "MEDIUM").upper()
        if sev == "CRITICAL":
            has_critical = True
        ded = SEVERITY_WEIGHTS.get(sev, 8)
        domain_deductions["infrastructure_security"] += ded
        reasons.append(f"IaC misconfiguration: {iac.get('title', 'Policy Violation')}")

    # 6. Raw Findings direct mapping
    if raw_findings:
        for f in raw_findings:
            cat = f.get("category", "code_security")
            sev = f.get("severity", "MEDIUM").upper()
            if sev == "CRITICAL":
                has_critical = True
            target_domain = DOMAIN_CATEGORY_MAP.get(cat, "code_security")
            if target_domain in domain_deductions:
                domain_deductions[target_domain] += SEVERITY_WEIGHTS.get(sev, 8)

    # 7. Attack Path participation penalty
    if attack_paths:
        domain_deductions["code_security"] += min(len(attack_paths) * 10, 30)
        domain_deductions["mcp_security"] += min(len(attack_paths) * 10, 30)
        reasons.append(f"Identified {len(attack_paths)} executable multi-stage attack path(s)")

    # Calculate domain subscores (clamped 0 - 100)
    domain_scores = {
        "overall": 100,
        "code_security": max(0, 100 - domain_deductions["code_security"]),
        "dependency_security": max(0, 100 - domain_deductions["dependency_security"]),
        "secret_security": max(0, 100 - domain_deductions["secret_security"]),
        "web_security": max(0, 100 - domain_deductions["web_security"]),
        "mcp_security": max(0, 100 - domain_deductions["mcp_security"]),
        "infrastructure_security": max(0, 100 - domain_deductions["infrastructure_security"]),
        "exposure_security": max(0, 100 - domain_deductions["exposure_security"]),
    }

    # Backward-compatible category_scores dict
    category_scores = {
        "secrets": domain_scores["secret_security"],
        "dependencies": domain_scores["dependency_security"],
        "code_security": domain_scores["code_security"],
        "mcp_security": domain_scores["mcp_security"],
        "authentication": domain_scores["code_security"],
        "prompt_injection": domain_scores["mcp_security"],
        "infrastructure": domain_scores["infrastructure_security"],
        "web_security": domain_scores["web_security"],
    }

    # Weighted Overall Score
    weights = {
        "secret_security": 0.25,
        "code_security": 0.20,
        "mcp_security": 0.20,
        "dependency_security": 0.15,
        "infrastructure_security": 0.10,
        "web_security": 0.05,
        "exposure_security": 0.05,
    }

    weighted_total = sum(domain_scores[k] * w for k, w in weights.items())
    overall_num = int(round(weighted_total))
    if has_critical:
        overall_num = min(overall_num, 65)

    overall_num = max(0, min(100, overall_num))
    domain_scores["overall"] = overall_num

    # Grade determination
    if overall_num >= 90:
        grade = "A"
        badge_color = "GREEN"
        status = "SECURE"
    elif overall_num >= 75:
        grade = "B"
        badge_color = "GREEN"
        status = "GOOD"
    elif overall_num >= 60:
        grade = "C"
        badge_color = "YELLOW"
        status = "MODERATE RISK"
    elif overall_num >= 45:
        grade = "D"
        badge_color = "YELLOW"
        status = "ELEVATED RISK"
    else:
        grade = "F"
        badge_color = "RED"
        status = "CRITICAL RISK"

    score_delta = None
    if previous_score is not None:
        try:
            prev_num = int(previous_score) if isinstance(previous_score, (int, float)) else None
            if prev_num is not None:
                score_delta = overall_num - prev_num
        except Exception:
            pass

    return {
        "score": overall_num,
        "grade": grade,
        "badge_color": badge_color,
        "status": status,
        "domain_scores": domain_scores,
        "category_scores": category_scores,
        "subscores": category_scores,
        "top_reasons": reasons[:5],
        "all_reasons": reasons,
        "score_delta": score_delta,
    }


def compute_overall_score(report, secrets, dependencies, typosquats):
    """
    Backward-compatible rollup score returning RED / YELLOW / GREEN / UNKNOWN.
    """
    if secrets:
        return "RED"
    if dependencies and isinstance(dependencies, dict) and dependencies.get("findings"):
        return "RED"
    if typosquats:
        return "RED"
    if report:
        scores = {entry.get("score") for entry in report if "score" in entry}
        if "RED" in scores:
            return "RED"
        if "YELLOW" in scores:
            return "YELLOW"
        return "GREEN"
    return "UNKNOWN"
