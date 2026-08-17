"""
Blast Radius & Attack-Path Analysis for MCP tools.

Given a tool's capabilities, this module models what a compromised or
misused tool could reach. It builds attack paths in the form:

    user input -> AI agent -> MCP tool -> database/filesystem/network/secrets

And assigns each tool a 0-100 blast-radius score based on how far-reaching
its potential impact is.

This module is designed to be called with the existing tool data from
compare.py's pipeline -- it consumes the same tool dicts and capability
categories already produced by scan_behavior.py and tool_analyzer.py.
"""
import re

# ---------------------------------------------------------------------------
# Downstream target taxonomy
# ---------------------------------------------------------------------------

DOWNSTREAM_TARGETS = {
    "file_access": {
        "targets": ["local_filesystem", "config_files", "source_code", "data_files", "credentials_stored_in_files"],
        "sensitivity": 3,
        "description": "Files on disk (read, write, delete)",
    },
    "network_access": {
        "targets": ["external_apis", "internal_services", "dns", "attacker_server", "cloud_services"],
        "sensitivity": 4,
        "description": "Outbound network connections",
    },
    "subprocess_execution": {
        "targets": ["shell", "system_commands", "other_processes", "installed_tools", "os_level"],
        "sensitivity": 5,
        "description": "Shell commands and child processes",
    },
    "environment_access": {
        "targets": ["api_keys", "database_passwords", "cloud_credentials", "secrets_manager", "jwt_tokens"],
        "sensitivity": 5,
        "description": "Environment variables (common secret storage)",
    },
}

# Additional targets reachable through combination of capabilities
COMBINATION_PATHS = [
    {
        "name": "Data exfiltration chain",
        "requires": ["file_access", "network_access"],
        "targets": ["remote_attacker_server", "data_leak"],
        "description": "Reads local files and sends them over the network",
        "sensitivity": 5,
    },
    {
        "name": "Credential harvesting chain",
        "requires": ["environment_access", "network_access"],
        "targets": ["remote_attacker_server", "stolen_credentials"],
        "description": "Reads env vars (secrets) and exfiltrates them via network",
        "sensitivity": 5,
    },
    {
        "name": "Full system takeover",
        "requires": ["subprocess_execution", "environment_access"],
        "targets": ["entire_filesystem", "all_processes", "all_secrets"],
        "description": "Runs arbitrary shell commands with access to secrets",
        "sensitivity": 5,
    },
    {
        "name": "Persistent backdoor",
        "requires": ["subprocess_execution", "file_access", "network_access"],
        "targets": ["cron_jobs", "startup_scripts", "remote_c2"],
        "description": "Installs persistent access via cron/startup + C2 channel",
        "sensitivity": 5,
    },
    {
        "name": "Lateral movement",
        "requires": ["subprocess_execution", "network_access"],
        "targets": ["internal_network", "other_servers", "database_hosts"],
        "description": "Uses shell + network to pivot to other internal systems",
        "sensitivity": 4,
    },
    {
        "name": "Config tampering",
        "requires": ["file_access", "environment_access"],
        "targets": ["app_config", "deployment_settings", "auth_config"],
        "description": "Modifies config files and environment to change app behavior",
        "sensitivity": 4,
    },
]

# ---------------------------------------------------------------------------
# Inherent risk amplifications (risk_classifier keywords)
# ---------------------------------------------------------------------------

HIGH_IMPACT_KEYWORDS = {
    "delete", "drop", "wipe", "destroy", "purge", "format",
    "transfer_money", "transfer_funds", "send_payment", "pay", "withdraw",
    "shutdown", "terminate", "kill_process",
}

MEDIUM_IMPACT_KEYWORDS = {
    "send_email", "send_message", "post_public", "publish", "broadcast",
    "grant_access", "revoke", "admin", "override", "bypass", "escalate",
    "execute_command", "run_shell", "eval_code", "exec_code",
}

LOW_IMPACT_KEYWORDS = {
    "update", "modify", "write", "create", "upload", "edit",
}


def _score_capability_amplification(capabilities):
    """
    Score 0-30 based on which capability categories the tool has.
    Each category contributes a base score, with env_access + subprocess
    being the most dangerous.
    """
    scores = {
        "file_access": 6,
        "network_access": 8,
        "subprocess_execution": 10,
        "environment_access": 10,
    }
    return sum(scores.get(c, 0) for c in capabilities)


def _score_downstream_targets(capabilities):
    """
    Score 0-30 based on what downstream targets the tool can reach.
    More sensitive targets = higher score.
    """
    total = 0
    seen_targets = set()
    for cap in capabilities:
        info = DOWNSTREAM_TARGETS.get(cap)
        if not info:
            continue
        for target in info["targets"]:
            if target not in seen_targets:
                total += info["sensitivity"]
                seen_targets.add(target)
    # Cap at 30
    return min(total, 30)


def _score_combination_paths(capabilities):
    """
    Score 0-25 based on dangerous capability combinations (attack chains).
    Each viable combination path adds to the score.
    """
    cap_set = set(capabilities)
    score = 0
    for path in COMBINATION_PATHS:
        if all(c in cap_set for c in path["requires"]):
            score += 5
    return min(score, 25)


def _score_risk_amplification(tool_name, tool_description, risk_level):
    """
    Score 0-15 based on the tool's inherent risk classification. A
    CRITICAL-risk tool that also has network access is much more dangerous
    than the same capabilities in a read-only info tool.
    """
    # Base score from risk level
    base = {"LOW": 2, "MEDIUM": 5, "HIGH": 10, "CRITICAL": 15}.get(risk_level, 2)

    # Amplify if the tool name/description contains high-impact keywords
    text = f"{tool_name} {tool_description}".lower()
    text = re.sub(r'[_\-]', ' ', text)

    amp = 0
    for kw in HIGH_IMPACT_KEYWORDS:
        if re.search(r'\b' + re.escape(kw) + r'\b', text):
            amp = max(amp, 5)
            break
    if amp == 0:
        for kw in MEDIUM_IMPACT_KEYWORDS:
            if re.search(r'\b' + re.escape(kw) + r'\b', text):
                amp = max(amp, 3)
                break
    if amp == 0:
        for kw in LOW_IMPACT_KEYWORDS:
            if re.search(r'\b' + re.escape(kw) + r'\b', text):
                amp = max(amp, 1)
                break

    return base + amp


def compute_blast_radius(tool_name, tool_description, capabilities, risk_level="LOW"):
    """
    Compute a blast-radius score (0-100) for a single tool.

    The score is composed of:
        - Capability amplification: 0-30
        - Downstream target exposure: 0-30
        - Combination attack paths: 0-25
        - Risk amplification (name/description): 0-15

    Higher score = more dangerous if compromised or misused.
    """
    capabilities = list(capabilities or [])

    cap_score = _score_capability_amplification(capabilities)
    target_score = _score_downstream_targets(capabilities)
    combo_score = _score_combination_paths(capabilities)
    risk_score = _score_risk_amplification(tool_name, tool_description, risk_level)

    total = cap_score + target_score + combo_score + risk_score
    total = min(total, 100)

    # Determine label
    if total >= 75:
        label = "CRITICAL"
    elif total >= 50:
        label = "HIGH"
    elif total >= 25:
        label = "MEDIUM"
    elif total > 0:
        label = "LOW"
    else:
        label = "NONE"

    # Build attack path description
    attack_paths = []
    for path in COMBINATION_PATHS:
        if all(c in capabilities for c in path["requires"]):
            attack_paths.append({
                "name": path["name"],
                "description": path["description"],
                "reaches": path["targets"],
                "requires": path["requires"],
            })

    # Add individual capability paths
    for cap in capabilities:
        info = DOWNSTREAM_TARGETS.get(cap)
        if info:
            attack_paths.append({
                "name": f"Direct {cap}",
                "description": f"Tool can {info['description']}",
                "reaches": info["targets"],
                "requires": [cap],
            })

    return {
        "score": total,
        "label": label,
        "components": {
            "capability_amplification": cap_score,
            "downstream_targets": target_score,
            "combination_paths": combo_score,
            "risk_amplification": risk_score,
        },
        "attack_paths": attack_paths,
        "capabilities_analyzed": capabilities,
    }


def compute_all_blast_radii(tools_analysis):
    """
    Compute blast radius for all tools given the output of
    tool_analyzer.analyze_all_tools(). Returns a dict keyed by tool name.
    """
    results = {}
    for tool_name, analysis in tools_analysis.items():
        caps = analysis.get("actual_capabilities", [])
        risk = analysis.get("severity", "LOW")
        results[tool_name] = compute_blast_radius(
            tool_name, "", caps, risk_level=risk
        )
    return results


def get_repo_blast_summary(tools_analysis):
    """
    Summarize blast radius across all tools in a repo.
    Returns overall worst score, total attack paths, and tools sorted by score.
    """
    radii = compute_all_blast_radii(tools_analysis)
    if not radii:
        return {
            "max_score": 0,
            "max_label": "NONE",
            "total_tools": 0,
            "high_risk_tools": [],
            "tools_sorted": [],
        }

    sorted_tools = sorted(radii.items(), key=lambda x: x[1]["score"], reverse=True)
    max_score = sorted_tools[0][1]["score"] if sorted_tools else 0
    max_label = sorted_tools[0][1]["label"] if sorted_tools else "NONE"

    high_risk = [(name, data) for name, data in sorted_tools if data["score"] >= 50]

    return {
        "max_score": max_score,
        "max_label": max_label,
        "total_tools": len(radii),
        "high_risk_tools": high_risk,
        "tools_sorted": sorted_tools,
    }