"""
Tool & Permission Analyzer for MCP servers.

Analyzes what each MCP tool can actually access/do, detects excessive permissions,
and compares declared tool purpose vs actual capabilities. This is the "who does what"
layer that turns raw behavior flags into structured permission models for downstream
features (blast radius, firewall, scoring).

This module reuses scan_behavior.py's SUSPICIOUS_PATTERNS categories and is
intentionally standalone so it can be called independently from a CI script without
running the full compare() pipeline.
"""
import re
from scan_behavior import SUSPICIOUS_PATTERNS, scan_text
from js_ts_scanner import scan_js_text, JS_TS_EXTENSIONS

CAPABILITY_DESCRIPTIONS = {
    "file_access": "Read/write/delete files on disk or in-memory file objects",
    "network_access": "Make outbound network connections (HTTP, socket, DNS)",
    "subprocess_execution": "Run shell commands or spawn child processes",
    "environment_access": "Read or write OS environment variables (often secret storage)",
}

CAPABILITY_SEVERITY_IF_UNDISCLOSED = {
    "file_access": "MEDIUM",
    "network_access": "MEDIUM",
    "subprocess_execution": "HIGH",
    "environment_access": "HIGH",
}

CAPABILITY_HINT_KEYWORDS = {
    "file_access": ["file", "disk", "read", "write", "save", "load", "open", "store", "document", "path"],
    "network_access": ["url", "http", "web", "internet", "fetch", "download", "api", "request", "connect", "network"],
    "subprocess_execution": ["run", "execute", "command", "process", "shell", "invoke", "script"],
    "environment_access": ["environment", "config", "variable", "setting", "env", "credentials"],
}


def get_declared_capabilities(description):
    """
    Parse a tool description text and return which capability categories
    it genuinely indicates the tool needs -- based on keyword matching.
    Returns a set of category strings from CAPABILITY_DESCRIPTIONS.
    """
    if not description:
        return set()
    lowered = description.lower()
    declared = set()
    for category, keywords in CAPABILITY_HINT_KEYWORDS.items():
        if any(kw in lowered for kw in keywords):
            declared.add(category)
    return declared


def get_actual_capabilities(filepath, code_snippet=None):
    """
    Determine which capability categories a tool actually has access to,
    based on scanning its code. Reuses scan_behavior.py and js_ts_scanner.py patterns.

    Accepts either a filepath (reads the file) or a code_snippet string.
    Returns a set of capability category strings.
    """
    is_js = bool(filepath and filepath.lower().endswith(JS_TS_EXTENSIONS))
    if code_snippet is not None:
        py_caps = set(scan_text(code_snippet))
        js_caps = set(scan_js_text(code_snippet))
        return py_caps | js_caps
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return set(scan_js_text(content) if is_js else scan_text(content))
    except Exception:
        return set()



def compute_permission_matrix(actual_caps, declared_caps):
    """
    Build a structured permission analysis for a single tool.

    Returns a dict with:
        - declared: capabilities claimed/implied by description
        - actual: capabilities found in code
        - undisclosed_actual: capabilities present in code but absent from description
        - extra_declared: capabilities description claims but code doesn't need
        - excessive: list of capability categories that look like over-permissioning

    The "extra_declared" category catches cases where the description promises
    capabilities the code doesn't actually use (honest but inflated claims,
    or a description that was copy-pasted from a different tool).
    """
    actual_caps = actual_caps or set()
    declared_caps = declared_caps or set()

    # Capabilities in code but NOT in description = undisclosed actual
    # These are the dangerous ones: the AI agent trusts the description and
    # calls the tool without realizing it has these side effects.
    undisclosed_actual = actual_caps - declared_caps

    # Capabilities in description but NOT in code = extra declared
    # These are misleading at best, confusing for the AI agent at worst.
    extra_declared = declared_caps - actual_caps

    # "Excessive" = broader than necessary. We flag it when a tool has more
    # capability categories than its declared scope (any declared + any
    # undisclosed combined). This means the tool can touch more surface area
    # than the description lets on.
    total_active = actual_caps | declared_caps
    excessive = []
    if len(total_active) > 1 and len(declared_caps) == 0:
        # Has capabilities but claims nothing in the description
        excessive = sorted(actual_caps)

    return {
        "declared": sorted(declared_caps),
        "actual": sorted(actual_caps),
        "undisclosed_actual": sorted(undisclosed_actual),
        "extra_declared": sorted(extra_declared),
        "excessive": excessive,
        "permission_count": len(total_active),
        "has_undisclosed": bool(undisclosed_actual),
        "has_extra_declared": bool(extra_declared),
    }


def analyze_tool_permissions(tool):
    """
    Full permission analysis for one tool dict (the shape produced by
    extract_tools.py / js_ts_scanner.py).

    Returns a dict with:
        - permission_matrix: from compute_permission_matrix
        - severity: worst severity among undisclosed capabilities
        - findings: human-readable descriptions of issues found
        - blast_radius_hints: which downstream targets this tool can reach
    """
    actual_caps = get_actual_capabilities(
        tool.get("file", ""),
        code_snippet=tool.get("code_snippet"),
    )
    declared_caps = get_declared_capabilities(tool.get("description", ""))
    matrix = compute_permission_matrix(actual_caps, declared_caps)

    findings = []
    severities = set()

    for cap in matrix["undisclosed_actual"]:
        severity = CAPABILITY_SEVERITY_IF_UNDISCLOSED.get(cap, "LOW")
        severities.add(severity)
        findings.append({
            "type": "Undisclosed capability",
            "category": cap,
            "severity": severity,
            "detail": (
                f"The tool performs {CAPABILITY_DESCRIPTIONS.get(cap, cap)} "
                f"but its description never mentions this. An AI agent trusting "
                f"the description would not expect these side effects."
            ),
            "capability": cap,
        })

    for cap in matrix["extra_declared"]:
        findings.append({
            "type": "Inflated declaration",
            "category": cap,
            "severity": "LOW",
            "detail": (
                f"The description implies {CAPABILITY_DESCRIPTIONS.get(cap, cap)} "
                f"but the tool's code does not actually use this. This may be "
                f"an honest copy-paste error, but it misleads the AI agent."
            ),
            "capability": cap,
        })

    # Determine worst severity
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    overall_severity = "LOW"
    if severities:
        overall_severity = max(severities, key=lambda s: severity_rank.get(s, 0))

    return {
        "permission_matrix": matrix,
        "severity": overall_severity,
        "findings": findings,
        "actual_capabilities": sorted(actual_caps),
        "declared_capabilities": sorted(declared_caps),
    }


def analyze_all_tools(tools):
    """
    Run permission analysis on a list of tool dicts. Returns a dict keyed
    by tool name for easy lookup during scoring.
    """
    results = {}
    for tool in tools:
        analysis = analyze_tool_permissions(tool)
        results[tool["name"]] = analysis
    return results