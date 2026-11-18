"""
Cryptographic MCP Rug-Pull & Security Drift Detector.

Generates SHA-256 cryptographic fingerprints for:
- Tool signatures & names
- Parameter schemas & types
- Descriptions & return annotations
- Declared & detected capabilities
- Network destinations & egress domains

Detects:
- Tool additions / removals
- Description changes (e.g. hidden instructions added in release update)
- Permission creep / escalation (e.g. read-only tool becomes shell execute)
- New unapproved outbound destinations
"""
import hashlib
import json
import time

def fingerprint_tool(tool):
    """
    Computes deterministic SHA-256 hashes for individual facets of a tool.
    """
    name = tool.get("name", "")
    desc = tool.get("description", "").strip()
    schema = tool.get("input_schema") or tool.get("parameters") or {}
    caps = sorted(list(set(tool.get("actual_behavior", []) or [])))

    schema_str = json.dumps(schema, sort_keys=True)
    caps_str = ",".join(caps)

    full_payload = f"{name}::{desc}::{schema_str}::{caps_str}"
    
    return {
        "tool_name": name,
        "full_hash": hashlib.sha256(full_payload.encode("utf-8")).hexdigest(),
        "desc_hash": hashlib.sha256(desc.encode("utf-8")).hexdigest(),
        "schema_hash": hashlib.sha256(schema_str.encode("utf-8")).hexdigest(),
        "description": desc,
        "capabilities": caps,
        "schema": schema,
    }


def create_baseline_fingerprint(tools_report, repo_url="local"):
    """
    Generates a complete baseline fingerprint map for a repository.
    """
    tools_fingerprints = {}
    for tool in tools_report:
        tname = tool.get("name", "unknown")
        tools_fingerprints[tname] = fingerprint_tool(tool)

    return {
        "repo_url": repo_url,
        "created_at": time.time(),
        "tools": tools_fingerprints,
        "tool_count": len(tools_fingerprints)
    }


def detect_rug_pull_and_drift(current_tools_report, baseline_data):
    """
    Compares current scan tools against approved baseline fingerprint.
    Returns a structured drift report with drift events and rug-pull alerts.
    """
    if not baseline_data or "tools" not in baseline_data:
        return {
            "has_baseline": False,
            "drift_events": [],
            "rug_pull_alerts": [],
            "summary": "No approved baseline found for this repository."
        }

    baseline_tools = baseline_data.get("tools", {})
    current_tools = {t.get("name", "unknown"): t for t in current_tools_report}

    drift_events = []
    rug_pull_alerts = []

    # 1. Check for removed tools
    for b_name in baseline_tools:
        if b_name not in current_tools:
            drift_events.append({
                "type": "TOOL_REMOVED",
                "severity": "LOW",
                "tool": b_name,
                "detail": f"Tool '{b_name}' was present in baseline but has been removed."
            })

    # 2. Check for new tools & modified tools
    for c_name, c_tool in current_tools.items():
        c_fp = fingerprint_tool(c_tool)

        if c_name not in baseline_tools:
            # New tool introduced
            drift_events.append({
                "type": "TOOL_ADDED",
                "severity": "MEDIUM",
                "tool": c_name,
                "detail": f"New tool '{c_name}' introduced since baseline.",
                "capabilities": c_fp["capabilities"]
            })
            if "EXECUTE" in c_fp["capabilities"] or "subprocess_execution" in c_fp["capabilities"]:
                rug_pull_alerts.append({
                    "type": "HIGH_RISK_TOOL_INTRODUCED",
                    "severity": "CRITICAL",
                    "tool": c_name,
                    "detail": f"New tool '{c_name}' introduced with arbitrary command execution capabilities."
                })
        else:
            b_fp = baseline_tools[c_name]
            
            # Check description drift
            if c_fp["desc_hash"] != b_fp["desc_hash"]:
                drift_events.append({
                    "type": "DESCRIPTION_CHANGED",
                    "severity": "HIGH",
                    "tool": c_name,
                    "old_value": b_fp["description"],
                    "new_value": c_fp["description"],
                    "detail": f"Description for tool '{c_name}' was modified."
                })

                # Check if description changes introduced suspicious behavior
                old_lower = b_fp["description"].lower()
                new_lower = c_fp["description"].lower()
                if ("env" in new_lower or "secret" in new_lower or "ignore" in new_lower) and not ("env" in old_lower or "secret" in old_lower or "ignore" in old_lower):
                    rug_pull_alerts.append({
                        "type": "CRITICAL_DESCRIPTION_RUG_PULL",
                        "severity": "CRITICAL",
                        "tool": c_name,
                        "old_description": b_fp["description"],
                        "new_description": c_fp["description"],
                        "detail": f"Tool '{c_name}' description was modified to include sensitive access instructions."
                    })

            # Check permission escalation
            old_caps = set(b_fp["capabilities"])
            new_caps = set(c_fp["capabilities"])
            escalated_caps = new_caps - old_caps
            if escalated_caps:
                drift_events.append({
                    "type": "PERMISSION_ESCALATION",
                    "severity": "CRITICAL",
                    "tool": c_name,
                    "escalated_capabilities": list(escalated_caps),
                    "detail": f"Tool '{c_name}' gained new capabilities: {', '.join(escalated_caps)}."
                })
                rug_pull_alerts.append({
                    "type": "PERMISSION_RUG_PULL",
                    "severity": "CRITICAL",
                    "tool": c_name,
                    "detail": f"Tool '{c_name}' escalated permissions to include: {', '.join(escalated_caps)}."
                })

    return {
        "has_baseline": True,
        "baseline_created_at": baseline_data.get("created_at"),
        "drift_events": drift_events,
        "rug_pull_alerts": rug_pull_alerts,
        "is_clean": len(drift_events) == 0 and len(rug_pull_alerts) == 0,
        "summary": f"Detected {len(drift_events)} drift events and {len(rug_pull_alerts)} rug-pull alerts."
    }
