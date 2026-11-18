"""
Security Policy & Contract Enforcement Engine.

Evaluates user-defined security policies and contracts:
- "AI agents cannot execute shell commands"
- "Production MCP servers cannot communicate with unknown domains"
- "CRM MCP cannot export > 100 records per request"
- "GitHub MCP cannot access environment secrets"
"""
import re

DEFAULT_POLICIES = [
    {
        "id": "POL-NO-UNRESTRICTED-EXEC",
        "name": "Block Unrestricted Shell Execution",
        "description": "AI agents and MCP tools must not execute raw shell commands without human-in-the-loop approval.",
        "target": "capability",
        "forbidden": ["EXECUTE", "subprocess_execution"],
        "severity": "CRITICAL"
    },
    {
        "id": "POL-NO-SECRET-EXFIL",
        "name": "Block Credential and Egress Pairing",
        "description": "Tools that read environment secrets must not also maintain outbound network connections.",
        "target": "combination",
        "forbidden_combination": [["CREDENTIAL", "NETWORK"], ["environment_access", "network_access"]],
        "severity": "CRITICAL"
    },
    {
        "id": "POL-APPROVED-DOMAINS-ONLY",
        "name": "Egress Domain Allowlisting",
        "description": "Network tools may only connect to approved corporate or official API domains.",
        "target": "domain",
        "blocked_keywords": ["attacker", "webhook.site", "pastebin", "ngrok", "burpcollaborator"],
        "severity": "HIGH"
    }
]


def evaluate_security_policies(tools_report, custom_policies=None):
    """
    Evaluates discovered tools and configurations against security policies.
    Returns violated policies with evidence.
    """
    policies = custom_policies or DEFAULT_POLICIES
    violations = []

    for tool in tools_report:
        tname = tool.get("name", "unknown")
        caps = set(tool.get("actual_behavior", []) or [])
        desc = tool.get("description", "")
        code = tool.get("code_snippet", "")

        for pol in policies:
            # 1. Capability checks
            if pol.get("target") == "capability":
                forbidden = pol.get("forbidden", [])
                if any(f in caps for f in forbidden):
                    violations.append({
                        "policy_id": pol["id"],
                        "policy_name": pol["name"],
                        "tool": tname,
                        "severity": pol["severity"],
                        "detail": f"Tool '{tname}' violates policy '{pol['name']}': Capability `{', '.join(caps)}` is forbidden in automated agents.",
                        "remediation": "Restrict tool capabilities or require explicit human approval before execution."
                    })

            # 2. Dangerous combination checks
            elif pol.get("target") == "combination":
                combos = pol.get("forbidden_combination", [])
                for pair in combos:
                    if all(c in caps for c in pair):
                        violations.append({
                            "policy_id": pol["id"],
                            "policy_name": pol["name"],
                            "tool": tname,
                            "severity": pol["severity"],
                            "detail": f"Tool '{tname}' violates policy '{pol['name']}': Combines sensitive access `{pair[0]}` with outbound egress `{pair[1]}`.",
                            "remediation": "Decouple secret access from network transmission."
                        })

            # 3. Domain allowlist checks
            elif pol.get("target") == "domain":
                blocked_kws = pol.get("blocked_keywords", [])
                for kw in blocked_kws:
                    if kw in desc.lower() or kw in code.lower():
                        violations.append({
                            "policy_id": pol["id"],
                            "policy_name": pol["name"],
                            "tool": tname,
                            "severity": pol["severity"],
                            "detail": f"Tool '{tname}' violates domain egress policy: References suspicious or unapproved endpoint `{kw}`.",
                            "remediation": "Ensure tools only communicate with verified, corporate-allowlisted domains."
                        })

    return {
        "total_evaluated": len(tools_report),
        "violations_count": len(violations),
        "violations": violations,
        "is_compliant": len(violations) == 0
    }
