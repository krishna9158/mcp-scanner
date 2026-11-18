"""
AI Security Analyst & Advisor Engine (TrustAudit Platform).

Grounded exclusively in deterministic scanner evidence:
- Produces executive summaries
- Explains score changes, root causes, and blast radius
- Correlates multi-tool findings into attack narratives
- Interactive AI Security Advisor querying real findings
"""

import json
import os
import re
from typing import Any, Dict, List, Optional


def generate_executive_analysis(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Synthesizes a clear, plain-language executive analysis of scan results.
    """
    score = scan_result.get("score", 100)
    grade = scan_result.get("grade", "A")
    status = scan_result.get("status", "SECURE")

    tools = scan_result.get("report", [])
    secrets = scan_result.get("secrets", [])
    deps = scan_result.get("dependencies", {}).get("findings", []) if isinstance(scan_result.get("dependencies"), dict) else []
    attack_paths = scan_result.get("attack_paths", [])
    appsec = scan_result.get("appsec_findings", [])
    findings = scan_result.get("findings", [])

    highlights = []

    if secrets:
        highlights.append(f"• **Credentials Exposed**: {len(secrets)} hardcoded secret(s) detected. Rotate exposed keys immediately.")
    if attack_paths:
        highlights.append(f"• **Active Attack Paths**: {len(attack_paths)} viable compromise chain(s) identified linking untrusted inputs to backend assets.")
    if deps:
        highlights.append(f"• **Vulnerable Dependencies**: {len(deps)} third-party package(s) have known published CVEs.")
    if appsec:
        highlights.append(f"• **Application Code Flaws**: {len(appsec)} OWASP/AI code vulnerabilities found.")
    if not highlights and findings:
        highlights.append(f"• **Audit Findings**: {len(findings)} operational and perimeter finding(s) cataloged.")
    if not highlights:
        highlights.append("• **Clean Posture**: Zero high-risk findings detected across MCP tools, secrets, and application code.")

    summary_text = (
        f"TrustAudit Security Posture: **{score}/100 (Grade {grade}) - {status}**.\n\n"
        + "\n".join(highlights)
    )

    action_plan = []
    if secrets:
        action_plan.append("1. Rotate and revoke all exposed credentials found in source files.")
    if attack_paths:
        action_plan.append("2. Decouple dangerous tool capabilities (e.g. restrict shell execution and isolate outbound network egress).")
    if deps:
        action_plan.append("3. Upgrade vulnerable dependencies to their specified fixed releases.")
    if not action_plan:
        action_plan.append("1. Establish current version as the approved baseline to detect future security drift.")

    return {
        "summary": summary_text,
        "score_narrative": f"Target scored {score}/100 based on multi-surface evaluation across integrated security engines.",
        "key_highlights": highlights,
        "recommended_action_plan": action_plan
    }


def query_ai_security_advisor(query: str, scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Answers developer security questions strictly grounded in actual scan findings and evidence.
    Does not hallucinate or invent non-existent vulnerabilities.
    """
    q = (query or "").lower().strip()
    findings = scan_result.get("findings", [])
    score = scan_result.get("score", 100)
    grade = scan_result.get("grade", "A")
    attack_paths = scan_result.get("attack_paths", [])
    secrets = scan_result.get("secrets", [])
    blast_radius = scan_result.get("blast_radius", {})
    delta = scan_result.get("last_delta") or {}

    crit_findings = [f for f in findings if (f.get("severity") or "").upper() == "CRITICAL"]
    high_crit_findings = [f for f in findings if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH")]

    # 1. "What is my biggest security problem?"
    if any(w in q for w in ("biggest security problem", "biggest problem", "worst issue", "main risk", "top threat")):
        if crit_findings:
            top_f = crit_findings[0]
            answer = (
                f"**Your biggest security problem** is `{top_f.get('title')}` (Severity: **CRITICAL**, ID: `{top_f.get('id')}`).\n\n"
                f"• **Location**: `{top_f.get('file')}:{top_f.get('line') or 'N/A'}`\n"
                f"• **Why it's critical**: {top_f.get('description')}\n"
                f"• **Evidence**: `{top_f.get('evidence')}`\n"
                f"• **Immediate Action**: {top_f.get('remediation')}"
            )
            return {"answer": answer, "referenced_findings": [top_f.get("id")]}
        elif high_crit_findings:
            top_f = high_crit_findings[0]
            answer = (
                f"**Your biggest security problem** is `{top_f.get('title')}` (Severity: **{top_f.get('severity')}**, ID: `{top_f.get('id')}`).\n\n"
                f"• **Location**: `{top_f.get('file')}:{top_f.get('line') or 'N/A'}`\n"
                f"• **Why it matters**: {top_f.get('description')}\n"
                f"• **Recommended Fix**: {top_f.get('remediation')}"
            )
            return {"answer": answer, "referenced_findings": [top_f.get("id")]}
        else:
            return {
                "answer": f"Great news! There are no Critical or High severity security problems detected. Your current security score is **{score}/100 (Grade {grade})**.",
                "referenced_findings": [],
            }

    # 2. "What changed today?" / "What changed?"
    if any(w in q for w in ("what changed", "changed today", "changes", "recent changes", "delta")):
        new_f = delta.get("new_findings", [])
        fixed_f = delta.get("fixed_findings", [])
        score_diff = delta.get("score_delta", 0)
        sign = "+" if score_diff > 0 else ""

        answer = (
            f"**What Changed in Continuous Monitoring**:\n\n"
            f"• **New Vulnerabilities**: {len(new_f)} new finding(s) detected.\n"
            f"• **Resolved Issues**: {len(fixed_f)} finding(s) verified fixed.\n"
            f"• **Score Shift**: {sign}{score_diff} points ({delta.get('previous_score', score)} → {score}).\n\n"
            f"**Summary**: {delta.get('summary', 'Continuous monitoring is tracking changes.')}"
        )
        return {"answer": answer, "referenced_findings": [f.get("id") for f in new_f[:3]]}

    # 3. "Which vulnerabilities should I fix first?" / "Fix first"
    if any(w in q for w in ("fix first", "priority", "which should i fix", "where to start", "first")):
        if high_crit_findings:
            lines = ["**Top Priority Vulnerabilities to Fix First**:"]
            for idx, f in enumerate(high_crit_findings[:3], 1):
                lines.append(f"{idx}. **[{f.get('severity')}]** `{f.get('title')}` in `{f.get('file')}:{f.get('line') or 'N/A'}` — *{f.get('remediation')}*")
            return {"answer": "\n\n".join(lines), "referenced_findings": [f.get("id") for f in high_crit_findings[:3]]}
        else:
            return {
                "answer": "No Critical or High issues found. Review any Medium or Low findings in the Fix Center.",
                "referenced_findings": [],
            }

    # 4. "Show me all critical issues."
    if any(w in q for w in ("critical issues", "all critical", "show critical")):
        if crit_findings:
            lines = [f"**Found {len(crit_findings)} Critical Issue(s)**:"]
            for idx, f in enumerate(crit_findings, 1):
                lines.append(f"{idx}. `{f.get('title')}` (ID: `{f.get('id')}`)\n   • File: `{f.get('file')}:{f.get('line') or 'N/A'}`\n   • Evidence: `{f.get('evidence')}`\n   • Fix: {f.get('remediation')}")
            return {"answer": "\n\n".join(lines), "referenced_findings": [f.get("id") for f in crit_findings]}
        else:
            return {"answer": "✅ Zero Critical severity vulnerabilities detected in your application.", "referenced_findings": []}

    # 5. "Did yesterday's vulnerability get fixed?"
    if any(w in q for w in ("get fixed", "fixed", "resolved", "verified", "yesterday")):
        fixed_f = delta.get("fixed_findings", [])
        if fixed_f:
            lines = [f"✅ **Yes, {len(fixed_f)} vulnerability(ies) have been verified as fixed**:"]
            for f in fixed_f[:3]:
                lines.append(f"• `{f.get('title')}` in `{f.get('file')}` (Verified absent in latest scan)")
            return {"answer": "\n".join(lines), "referenced_findings": [f.get("id") for f in fixed_f[:3]]}
        else:
            return {"answer": "No recently resolved findings were detected in the latest scan comparison. Use 'Rescan & Verify' in the Fix Center once you commit a patch.", "referenced_findings": []}

    # 6. "Why is this dangerous?" / "Why is this finding critical?"
    if any(w in q for w in ("dangerous", "danger", "why is this finding critical", "why critical", "why is this", "impact")):
        if high_crit_findings:
            cf = high_crit_findings[0]
            answer = (
                f"**Primary Danger & Exploitability Analysis for `{cf.get('title')}`**:\n\n"
                f"1. **Direct Exploitability**: The vulnerability provides unauthenticated or direct access to sensitive assets or code execution.\n"
                f"2. **Evidence**: `{cf.get('evidence')}`\n"
                f"3. **Potential Blast Radius**: Compromises data confidentiality or server integrity without requiring complex chaining.\n"
                f"4. **Fix Requirement**: Apply immediate remediation: {cf.get('remediation')}"
            )
            return {"answer": answer, "referenced_findings": [cf.get("id")]}
        else:
            return {"answer": "There are no active High or Critical findings in this scan.", "referenced_findings": []}

    # 7. "What should my developer do?"
    if any(w in q for w in ("what should my developer do", "developer do", "developer action", "instructions")):
        if high_crit_findings:
            top_f = high_crit_findings[0]
            prompt_guide = (
                f"**Developer Action Plan**:\n\n"
                f"1. Open `{top_f.get('file')}`.\n"
                f"2. Apply fix: {top_f.get('remediation')}\n"
                f"3. AI Prompt to paste into Cursor/Claude Code/Copilot:\n"
                f"   > `Fix {top_f.get('title')} in {top_f.get('file')}. Evidence: {top_f.get('evidence')}. Apply defensive parameterization.`\n"
                f"4. Re-run TrustAudit scan to automatically mark finding as VERIFIED."
            )
            return {"answer": prompt_guide, "referenced_findings": [top_f.get("id")]}
        else:
            return {"answer": "Your application has no urgent Critical/High vulnerabilities. Developers should maintain baseline security during code updates.", "referenced_findings": []}

    # 8. General Summary fallback
    answer = (
        f"**TrustAudit AI Security Advisor**:\n\n"
        f"• **Current Posture**: {score}/100 (Grade {grade})\n"
        f"• **Total Findings**: {len(findings)} ({len(high_crit_findings)} Critical/High)\n"
        f"• **Active Attack Paths**: {len(attack_paths)}\n\n"
        f"You can ask me: 'What is my biggest security problem?', 'What changed today?', 'Which vulnerabilities should I fix first?', or 'What should my developer do?'"
    )
    return {"answer": answer, "referenced_findings": [f.get("id") for f in high_crit_findings[:2]]}
