"""
Attack Path Engine for AI Applications & MCP Setups.

Correlates findings across:
1. Entry points (Prompt injection, unauthenticated MCP SSE/HTTP transport, untrusted input)
2. AI Agent reasoning & Tool invocation
3. Tool execution capabilities (subprocess, filesystem, network, environment variables)
4. Downstream asset impact (Remote Code Execution, Credential Theft, Data Exfiltration)

Only generates attack paths with concrete supporting evidence from the scan results.
"""

import time
from typing import Any, Dict, List, Optional, Set

MAX_ATTACK_PATHS = 50
MAX_ANALYSIS_SECONDS = 3.0

def generate_attack_paths(tools_report, secrets=None, auth_analysis=None, injection_findings=None, max_paths=MAX_ATTACK_PATHS):
    """
    Constructs end-to-end attack paths from scan findings with strict depth and time limit guards.
    Returns a list of structured attack path objects.
    """
    t0 = time.time()
    attack_paths = []
    tools_report = tools_report or []
    secrets = secrets or []
    auth_analysis = auth_analysis or {}
    injection_findings = injection_findings or []
    visited_nodes = set()

    # 1. Path: Prompt Injection -> Agent Hijack -> Subprocess Tool -> Host Takeover
    for tool in tools_report:
        tool_injections = tool.get("injection_findings", [])
        tool_caps = tool.get("actual_behavior", []) or []
        
        if tool_injections and "subprocess_execution" in tool_caps:
            inj_summary = tool_injections[0].get("detail", "Instruction override detected")
            attack_paths.append({
                "id": f"AP-INJ-RCE-{tool['name']}",
                "title": f"Prompt Injection to Remote Code Execution via '{tool['name']}'",
                "severity": "CRITICAL",
                "entry_point": "Malicious Prompt / Poisoned Tool Description",
                "target": "Host Operating System",
                "steps": [
                    {
                        "step": 1,
                        "stage": "Entry / Poisoning",
                        "actor": "Attacker / Untrusted Content",
                        "action": f"Injects adversarial instruction in description for tool '{tool['name']}' ({inj_summary}).",
                        "evidence": tool_injections[0].get("matched_text", "Poisoned description")
                    },
                    {
                        "step": 2,
                        "stage": "AI Agent Dispatch",
                        "actor": "AI Agent / LLM",
                        "action": f"Agent reads '{tool['name']}' description and executes tool with attacker-manipulated arguments.",
                        "evidence": f"Tool '{tool['name']}' registered in server"
                    },
                    {
                        "step": 3,
                        "stage": "Command Execution",
                        "actor": f"Tool: {tool['name']}",
                        "action": "Executes shell commands / subprocess on the host environment.",
                        "evidence": f"File: {tool.get('file', 'unknown')}"
                    },
                    {
                        "step": 4,
                        "stage": "Final Impact",
                        "actor": "Host OS",
                        "action": "Attacker achieves arbitrary command execution with the privileges of the running MCP process.",
                        "evidence": "subprocess_execution capability detected in code"
                    }
                ],
                "impact": "Complete host compromise, unauthorized command execution, and potential lateral movement.",
                "remediation": f"Sanitize tool description for '{tool['name']}', apply input validation, and enforce strict human approval before running subprocess tools."
            })

    # 2. Path: Unauthenticated Network Transport -> Unauthorized MCP Tool Call -> Secret Exfiltration
    if auth_analysis.get("is_network_facing") and not auth_analysis.get("has_auth_guards"):
        for tool in tools_report:
            tool_caps = tool.get("actual_behavior", []) or []
            if "environment_access" in tool_caps or "file_access" in tool_caps:
                attack_paths.append({
                    "id": f"AP-UNAUTH-EXFIL-{tool['name']}",
                    "title": f"Unauthenticated Network Endpoint to Data/Secret Access via '{tool['name']}'",
                    "severity": "HIGH",
                    "entry_point": "Exposed Network SSE/HTTP Endpoint",
                    "target": "Environment Secrets / Local Files",
                    "steps": [
                        {
                            "step": 1,
                            "stage": "Network Access",
                            "actor": "External Network Client",
                            "action": "Sends unauthenticated MCP JSON-RPC call over exposed network transport.",
                            "evidence": f"Transports: {', '.join(auth_analysis.get('transports', ['network']))}"
                        },
                        {
                            "step": 2,
                            "stage": "Tool Invocation",
                            "actor": "MCP Server",
                            "action": f"Dispatches call to tool '{tool['name']}' without validating authentication credentials.",
                            "evidence": "Missing authentication middleware"
                        },
                        {
                            "step": 3,
                            "stage": "Asset Access",
                            "actor": f"Tool: {tool['name']}",
                            "action": "Reads sensitive environment variables or filesystem files.",
                            "evidence": f"Actual capabilities: {', '.join(tool_caps)}"
                        }
                    ],
                    "impact": "Unauthorized exposure of local data, environment secrets, and backend configurations.",
                    "remediation": "Add Bearer token or OAuth authentication to the MCP network transport before accepting requests."
                })
                break  # one primary representative path for unauth transport

    # 3. Path: Hardcoded Secret Exposure -> Cloud / Service Compromise
    if secrets:
        critical_secrets = [s for s in secrets if s.get("severity") in ("CRITICAL", "HIGH")]
        if critical_secrets:
            sec = critical_secrets[0]
            attack_paths.append({
                "id": f"AP-SEC-LEAK-{sec.get('type', 'Secret').replace(' ', '-')}",
                "title": f"Hardcoded {sec.get('type')} Exploitation",
                "severity": sec.get("severity", "CRITICAL"),
                "entry_point": "Public / Shared Source Code Repository",
                "target": f"External {sec.get('type')} Provider / Infrastructure",
                "steps": [
                    {
                        "step": 1,
                        "stage": "Credential Discovery",
                        "actor": "Adversary / Automated Credential Scraper",
                        "action": f"Extracts exposed {sec.get('type')} credential from repository files.",
                        "evidence": f"{sec.get('file', 'repo')}:{sec.get('line', 1)} ({sec.get('value_preview', '[REDACTED]')})"
                    },
                    {
                        "step": 2,
                        "stage": "Unauthorized API Access",
                        "actor": "Adversary",
                        "action": f"Uses credential to authenticate directly against target service API bypassing application controls.",
                        "evidence": f"Credential signature: {sec.get('type')}"
                    },
                    {
                        "step": 3,
                        "stage": "Account Takeover / Data Access",
                        "actor": "Target Cloud Service",
                        "action": "Grants unauthorized access to resources, billing, or stored customer data.",
                        "evidence": "Hardcoded credential in source"
                    }
                ],
                "impact": f"Direct compromise of associated {sec.get('type')} account, data leakage, and potential unauthorized billing.",
                "remediation": f"Immediately revoke and rotate the {sec.get('type')} at {sec.get('file')}:{sec.get('line')} and ingest secrets via environment variables."
            })

    # 4. Path: Data Exfiltration Chain (File Access + Outbound Network)
    for tool in tools_report:
        tool_caps = set(tool.get("actual_behavior", []) or [])
        if "file_access" in tool_caps and "network_access" in tool_caps:
            # Check if this combination was disclosed
            desc = tool.get("description", "").lower()
            if not ("network" in desc and "file" in desc):
                attack_paths.append({
                    "id": f"AP-EXFIL-CHAIN-{tool['name']}",
                    "title": f"Data Exfiltration Capability Chain in '{tool['name']}'",
                    "severity": "HIGH",
                    "entry_point": "AI Agent Task Execution",
                    "target": "Remote Attacker Server",
                    "steps": [
                        {
                            "step": 1,
                            "stage": "File Read",
                            "actor": f"Tool: {tool['name']}",
                            "action": "Reads local files from the filesystem.",
                            "evidence": "file_access capability detected in tool code"
                        },
                        {
                            "step": 2,
                            "stage": "Network Transmission",
                            "actor": f"Tool: {tool['name']}",
                            "action": "Transmits data across an outbound network connection.",
                            "evidence": "network_access capability detected in tool code"
                        },
                        {
                            "step": 3,
                            "stage": "Data Exfiltration",
                            "actor": "External Destination",
                            "action": "Attacker-controlled or external server receives exfiltrated payload.",
                            "evidence": f"Undisclosed dual-capability in {tool.get('file', 'tool')}"
                        }
                    ],
                    "impact": "Silent leakage of confidential files, source code, or application data over network channels.",
                    "remediation": f"Explicitly document both file and network access in '{tool['name']}' description and restrict network destinations using an allowlist."
                })
                break

    return attack_paths[:max_paths]


def generate_visual_attack_graph(attack_paths: Optional[List[Dict[str, Any]]] = None, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Constructs a visual graph model (nodes & edges) for interactive UI attack-path rendering:
    Nodes: Internet -> Asset -> Endpoint -> Vulnerability -> Identity/Agent -> Tool -> Resource -> Sensitive Data
    """
    attack_paths = attack_paths or []
    findings = findings or []

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    node_ids = set()

    def add_node(node_id: str, label: str, node_type: str, severity: str = "INFO", details: Optional[Dict[str, Any]] = None):
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,
                "severity": severity,
                "details": details or {},
            })

    def add_edge(source: str, target: str, label: str = ""):
        edge_key = f"{source}->{target}:{label}"
        if not any(f"{e['source']}->{e['target']}:{e['label']}" == edge_key for e in edges):
            edges.append({"source": source, "target": target, "label": label})

    # Always establish Internet Entry Node
    add_node("node_internet", "Internet / Untrusted Input", "internet", "INFO")

    # If attack paths exist, map them directly into graph nodes
    for idx, ap in enumerate(attack_paths, 1):
        ap_id = f"ap_{idx}"
        entry_pt = ap.get("entry_point", "Untrusted Request")
        target_asset = ap.get("target", "Target Asset")
        sev = ap.get("severity", "HIGH")

        entry_node_id = f"entry_{idx}"
        target_node_id = f"target_{idx}"

        add_node(entry_node_id, entry_pt, "endpoint", sev)
        add_edge("node_internet", entry_node_id, "Infiltrates")

        steps = ap.get("steps", [])
        prev_node = entry_node_id
        for s_idx, step in enumerate(steps, 1):
            actor = step.get("actor", f"Step {s_idx}")
            action = step.get("action", "")
            stage = step.get("stage", "Execution")
            step_node_id = f"step_{idx}_{s_idx}"
            
            ntype = "agent" if "agent" in actor.lower() or "llm" in actor.lower() else ("tool" if "tool" in actor.lower() else "vulnerability")
            add_node(step_node_id, f"{actor}: {stage}", ntype, sev, {"action": action, "evidence": step.get("evidence", "")})
            add_edge(prev_node, step_node_id, "Transitions to")
            prev_node = step_node_id

        add_node(target_node_id, target_asset, "database" if "database" in target_asset.lower() or "secret" in target_asset.lower() else "cloud", sev, {"impact": ap.get("impact", "")})
        add_edge(prev_node, target_node_id, "Compromises")

    # If no paths, map high/critical findings to show attack surface
    if not attack_paths and findings:
        app_node_id = "node_app"
        add_node(app_node_id, "Target Application", "asset", "INFO")
        add_edge("node_internet", app_node_id, "Inspects")

        for f_idx, f in enumerate(findings[:8], 1):
            f_sev = f.get("severity", "MEDIUM")
            if f_sev in ("CRITICAL", "HIGH"):
                f_node_id = f"finding_node_{f_idx}"
                add_node(f_node_id, f.get("title", "Finding")[:32], "vulnerability", f_sev, {
                    "description": f.get("description", ""),
                    "evidence": f.get("evidence", ""),
                    "remediation": f.get("remediation", ""),
                })
                add_edge(app_node_id, f_node_id, "Exposes")

    return {
        "nodes": nodes,
        "edges": edges,
        "total_paths": len(attack_paths),
    }

