"""
Permission Graph Model for MCP Servers & AI Systems.

Constructs multi-hop capability graph:
Server -> Tool -> Capability -> Resource -> Data Type -> Destination

Detects dangerous combinations across nodes (e.g. Bulk PII + Outbound Network).
"""
import re
from capability_classifier import classify_tool_capabilities

RESOURCE_MAPPING = {
    "FINANCIAL": ("Payment Gateway / Stripe", "Financial Records"),
    "ADMIN": ("System Kernel / Process Manager", "Privileged OS State"),
    "EXECUTE": ("Host Operating System / Shell", "Arbitrary Code"),
    "DELETE": ("Local Disk / Database", "Persistent Storage"),
    "CREDENTIAL": ("Environment Variables / Vault", "Secrets & Tokens"),
    "EXTERNAL_COMMUNICATION": ("Email / Webhook Server", "Communication Payloads"),
    "DATABASE": ("SQL / MongoDB Database", "Structured Records"),
    "NETWORK": ("External Web Endpoints", "Network Packets"),
    "FILESYSTEM": ("Local Filesystem", "Files & Directories"),
    "WRITE": ("Application Storage", "User Data"),
    "READ": ("Informational Datastore", "Public Data"),
}

URL_REGEX = re.compile(r'https?://([a-zA-Z0-9.\-]+(?::\d+)?)')


def extract_destinations_from_text(text):
    """Finds referenced hostnames or destinations in descriptions/code."""
    if not text:
        return []
    urls = URL_REGEX.findall(text)
    return list(set(urls))


def build_permission_graph(tools_report, server_name="MCP-Server"):
    """
    Builds a complete permission graph for all discovered tools.
    """
    nodes = []
    edges = []
    dangerous_combinations = []
    
    server_id = f"server:{server_name}"
    nodes.append({"id": server_id, "label": server_name, "type": "server", "severity": "INFO"})

    for tool in tools_report:
        tool_name = tool.get("name", "unknown_tool")
        tool_id = f"tool:{tool_name}"
        desc = tool.get("description", "")
        code = tool.get("code_snippet", "")
        
        caps = classify_tool_capabilities(tool_name, desc, code)
        worst_sev = caps[0]["severity"] if caps else "LOW"

        nodes.append({
            "id": tool_id,
            "label": tool_name,
            "type": "tool",
            "severity": worst_sev,
            "description": desc[:100]
        })
        edges.append({"source": server_id, "target": tool_id, "relation": "exposes"})

        cap_names = [c["category"] for c in caps]
        destinations = extract_destinations_from_text(f"{desc} {code}")

        for cap_info in caps:
            cat = cap_info["category"]
            cap_id = f"cap:{tool_name}:{cat}"
            nodes.append({
                "id": cap_id,
                "label": cat,
                "type": "capability",
                "severity": cap_info["severity"],
            })
            edges.append({"source": tool_id, "target": cap_id, "relation": "performs"})

            res_name, data_type = RESOURCE_MAPPING.get(cat, ("General Resource", "Data"))
            res_id = f"res:{cat}:{res_name.replace(' ', '_')}"
            nodes.append({
                "id": res_id,
                "label": res_name,
                "type": "resource",
                "severity": cap_info["severity"],
                "data_type": data_type
            })
            edges.append({"source": cap_id, "target": res_id, "relation": "accesses"})

        # Link outbound destinations
        for dest in destinations:
            dest_id = f"dest:{dest}"
            nodes.append({
                "id": dest_id,
                "label": dest,
                "type": "destination",
                "severity": "MEDIUM"
            })
            edges.append({"source": tool_id, "target": dest_id, "relation": "connects_to"})

        # Detect dangerous graph combinations
        if ("FILESYSTEM" in cap_names or "CREDENTIAL" in cap_names) and ("NETWORK" in cap_names or "EXTERNAL_COMMUNICATION" in cap_names):
            dangerous_combinations.append({
                "tool": tool_name,
                "type": "Exfiltration Hazard Chain",
                "severity": "CRITICAL",
                "detail": f"Tool '{tool_name}' bridges sensitive local resources (Credentials/Files) with outbound egress (Network/Communication).",
                "nodes": [tool_id, f"cap:{tool_name}:CREDENTIAL", f"cap:{tool_name}:NETWORK"]
            })

        if "EXECUTE" in cap_names and "CREDENTIAL" in cap_names:
            dangerous_combinations.append({
                "tool": tool_name,
                "type": "Privileged Execution Chain",
                "severity": "CRITICAL",
                "detail": f"Tool '{tool_name}' pairs arbitrary shell/command execution with access to environment secrets.",
                "nodes": [tool_id, f"cap:{tool_name}:EXECUTE", f"cap:{tool_name}:CREDENTIAL"]
            })

    # Deduplicate nodes by ID
    unique_nodes = list({n["id"]: n for n in nodes}.values())

    return {
        "server": server_name,
        "nodes": unique_nodes,
        "edges": edges,
        "dangerous_combinations": dangerous_combinations,
        "total_tools": len(tools_report),
        "high_risk_chains": len(dangerous_combinations)
    }
