"""
Tool-shadowing detection.

"Shadowing" is a specific attack pattern in tool-calling systems like MCP:
a malicious tool tries to intercept calls meant for a different,
legitimate tool - either by registering a tool with the exact same name
(so whichever registration a client happens to load "wins"), or by
writing a description that explicitly instructs the AI agent to use this
tool "instead of" another one by name. Either way, the goal is the same:
get calls that were meant for a trusted tool redirected to this one
instead.
"""
import re

REDIRECT_PHRASE_PATTERNS = [
    r'instead of (?:using |calling )?["\']?(\w+)["\']?',
    r'(?:use|call) this (?:tool )?instead of ["\']?(\w+)["\']?',
    r'overrides? (?:the )?["\']?(\w+)["\']? tool',
    r'replaces? (?:the )?["\']?(\w+)["\']? tool',
    r'takes? priority over ["\']?(\w+)["\']?',
    r'supersedes ["\']?(\w+)["\']?',
]


def find_duplicate_tool_names(tools):
    """
    Flags tool names registered more than once across the repo. Not proof
    of an attack by itself - legitimate re-exports happen - but worth
    surfacing, since which of the two identically-named tools an AI
    client actually loads determines what code runs when it's called.
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
            })
    return findings


def find_redirect_language(tool_name, description):
    """
    Flags descriptions that explicitly try to redirect the AI agent away
    from a different, presumably trusted, tool and toward this one.
    """
    findings = []
    if not description:
        return findings

    for pattern in REDIRECT_PHRASE_PATTERNS:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            referenced = match.group(1) if match.groups() else "another tool"
            findings.append({
                "tool": tool_name,
                "type": "Redirect language",
                "detail": (
                    f"Description appears to instruct the AI agent to use this "
                    f"tool instead of '{referenced}' - a known technique for "
                    f"hijacking calls meant for a different, trusted tool."
                ),
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
        findings.extend(find_redirect_language(tool.get("name", "UNKNOWN"), tool.get("description", "")))
    return findings
