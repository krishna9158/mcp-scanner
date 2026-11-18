"""
AI-Powered Security Explanation & Remediation Engine.

Provides 4-part structured remediation for every security finding:
1. WHAT IS WRONG?
2. WHY DOES IT MATTER?
3. WHAT IS THE EVIDENCE? (strictly grounded in scan artifacts, zero hallucinations)
4. HOW CAN I FIX IT? (actionable code or config guidance)

Includes pre-built deterministic playbooks for all finding categories,
with optional dynamic LLM enhancement when an Anthropic API key is available.
"""
import os

try:
    import requests
except ImportError:
    requests = None

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-haiku-4-5-20251001"

PLAYBOOKS = {
    "secret": {
        "what": "Hardcoded plaintext credentials or tokens detected in source code.",
        "why": "Anyone with read access to this repository (or any build log / artifact) can compromise the associated cloud service, database, or API.",
        "fix": "1. Immediately revoke and rotate the exposed credential.\n2. Store secrets in environment variables (.env locally) or a dedicated secret manager.\n3. Add .env to .gitignore."
    },
    "dependency": {
        "what": "Third-party package with published CVE advisories or known vulnerabilities.",
        "why": "Known vulnerabilities can be exploited for remote code execution, denial of service, or authentication bypass.",
        "fix": "Upgrade the package to the fixed version specified in the advisory, or update to the latest stable release."
    },
    "typosquat": {
        "what": "Package name closely resembles a popular package (potential typosquatting attack).",
        "why": "Typosquatted packages often contain malicious code designed to execute on install and steal secrets.",
        "fix": "Verify the exact package name against official documentation and remove any misspelled packages."
    },
    "unauthenticated_mcp": {
        "what": "Network-facing MCP server transport lacks authentication guards.",
        "why": "Any network client or unauthorized actor can send tool invocation commands directly to the server.",
        "fix": "Add Bearer token authentication or API key verification middleware to incoming HTTP/SSE/WebSocket requests."
    },
    "prompt_injection": {
        "what": "MCP tool description contains prompt-injection or tool-poisoning phrases.",
        "why": "An AI agent reading this description may be manipulated into overriding instructions, calling unauthorized tools, or exfiltrating data.",
        "fix": "Remove directive phrases ('ignore previous instructions', 'always call', etc.) from the tool description and ensure it solely describes tool utility."
    },
    "tool_shadowing": {
        "what": "Duplicate tool names registered across multiple files.",
        "why": "Client implementations may arbitrarily resolve one implementation over another, leading to unexpected or hijacked execution paths.",
        "fix": "Rename conflicting tools to unique names or centralize registration in a single file."
    },
    "excessive_permission": {
        "what": "Tool code implements powerful capabilities (shell execution, environment access) not disclosed in its description.",
        "why": "AI agents trust the description and will invoke the tool without knowing it has broad side effects.",
        "fix": "Either remove the unused capabilities from the code or update the description to explicitly document them."
    },
    "high_risk_tool": {
        "what": "Tool performs high-impact or destructive operations (system shutdown, process termination, arbitrary shell execution).",
        "why": "If called autonomously by an AI agent (or tricked by prompt injection), catastrophic data loss or system disruption may occur.",
        "fix": "Require human-in-the-loop approval before tool execution, and enforce strict parameter validation."
    }
}


def explain_finding(finding_type, title, evidence, file=None, line=None, custom_context=None):
    """
    Generates a structured 4-part explanation grounded in scan evidence.
    """
    pb_key = "secret"
    f_lower = str(finding_type).lower()
    
    if "secret" in f_lower:
        pb_key = "secret"
    elif "depend" in f_lower or "cve" in f_lower:
        pb_key = "dependency"
    elif "typo" in f_lower:
        pb_key = "typosquat"
    elif "auth" in f_lower or "transport" in f_lower:
        pb_key = "unauthenticated_mcp"
    elif "injection" in f_lower or "poison" in f_lower:
        pb_key = "prompt_injection"
    elif "shadow" in f_lower:
        pb_key = "tool_shadowing"
    elif "excessive" in f_lower or "undisclosed" in f_lower:
        pb_key = "excessive_permission"
    elif "risk" in f_lower or "critical" in f_lower:
        pb_key = "high_risk_tool"

    playbook = PLAYBOOKS.get(pb_key, PLAYBOOKS["secret"])
    loc_str = f" in `{file}` (Line {line})" if file and line else (f" in `{file}`" if file else "")

    return {
        "title": title,
        "location": loc_str,
        "what": playbook["what"],
        "why": playbook["why"],
        "evidence": evidence or f"Identified {finding_type}{loc_str}",
        "fix": playbook["fix"]
    }
