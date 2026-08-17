"""
Tool-shadowing detection.

"Shadowing" is a specific attack pattern in tool-calling systems like MCP:
a malicious tool tries to intercept calls meant for a different,
legitimate tool - either by registering a tool with the exact same name
(so whichever registration a client happens to load "wins"), or by
writing a description that explicitly instructs the AI agent to use this
tool "instead of" another one by name.

This module adds severity/confidence levels so callers can distinguish
high-confidence shadowing attempts from low-signal false positives.
"""
import re

REDIRECT_PHRASE_PATTERNS = [
    (r'instead of (?:using |calling )?["\']?(\w+)["\']?', "HIGH",
     "Explicit redirect away from another tool"),
    (r'(?:use|call) this (?:tool )?instead of ["\']?(\w+)["\']?', "HIGH",
     "Direct instruction to use this tool in place of another"),
    (r'overrides? (?:the )?["\']?(\w+)["\']? tool', "HIGH",
     "Claims to override another tool"),
    (r'replaces? (?:the )?["\']?(\w+)["\']? tool', "HIGH",
     "Claims to replace another tool"),
    (r'takes? priority over ["\']?(\w+)["\']?', "MEDIUM",
     "Claims higher priority than another tool"),
    (r'supersedes ["\']?(\w+)["\']?', "MEDIUM",
     "Claims to supersede another tool"),
]


def find_duplicate_tool_names(tools):
    """
    Flags tool names registered more than once across the repo. Not proof
    of an attack by itself - legitimate re-exports happen - but worth
    surfacing, since which of the two identically-named tools an AI
    client actually loads determines what code runs when it's called.

    Confidence is MEDIUM because duplicate names are often legitimate
    (re-exports, aliases); severity is HIGH because if it's malicious,
    the impact is severe (interception of all calls to that tool name).
    """
    seen = {}
    for tool in tools:
        seen.setdefault(tool["name"], []).append(tool["file"])

    findings = []
    for name, files in seen.items():
        if len(files) > 1:
            findings.append({
                "tool": name,
                "type": "Duplicate tool name",
                "detail": (
                    f"'{name}' is registered {len(files)} times across different "
                    f"files ({', '.join(files)}). Whichever registration a client "
                    f"loads determines which code actually runs when this tool is "
                    f"called."
                ),
                "confidence": "MEDIUM",
                "severity": "HIGH",
                "matched_text": f"{len(files)} registrations across {len(set(files))} files",
                "files": list(set(files)),
            })
    return findings


def find_redirect_language(tool_name, description):
    """
    Flags descriptions that explicitly try to redirect the AI agent away
    from a different, presumably trusted, tool and toward this one.
    Returns a list of finding dicts with confidence/severity.
    """
    findings = []
    if not description:
        return findings

    for pattern, confidence, explanation in REDIRECT_PHRASE_PATTERNS:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            referenced = match.group(1) if match.groups() else "another tool"
            # Severity always HIGH for redirect language: any redirect is
            # a serious security issue, even if our confidence is MEDIUM
            severity = "HIGH"
            findings.append({
                "tool": tool_name,
                "type": "Redirect language",
                "detail": (
                    f"{explanation} - description instructs the AI agent to use "
                    f"this tool instead of '{referenced}', a known technique for "
                    f"hijacking calls meant for a different, trusted tool."
                ),
                "confidence": confidence,
                "severity": severity,
                "matched_text": match.group(0),
                "referenced_tool": referenced,
            })
            break  # one match is enough to flag this tool
    return findings


def scan_tools_for_shadowing(tools):
    """
    tools: list of dicts with at least 'name', 'description', and 'file'
    keys - the same shape produced by extract_tools.py and
    js_ts_scanner.py. Returns a flat list of findings; each finding
    includes which tool it's about via its 'tool' key, so callers can
    group them per-tool if needed.
    """
    findings = list(find_duplicate_tool_names(tools))
    for tool in tools:
        findings.extend(
            find_redirect_language(tool.get("name", "UNKNOWN"), tool.get("description", ""))
        )
    return findings