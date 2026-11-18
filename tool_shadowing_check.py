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


def _canonical_name(name):
    """Normalizes camelCase, PascalCase, snake_case, and kebab-case into a lowercase token string."""
    # Split camelCase
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
    # Remove separators and pluralization artifacts
    cleaned = re.sub(r'[-_.]', '', s2)
    if cleaned.endswith('s') and len(cleaned) > 3:
        cleaned = cleaned[:-1]
    return cleaned


def find_near_identical_tool_names(tools):
    """
    Detects cross-server deceptive name variations (e.g. search_files vs searchFiles vs search-file).
    """
    canonical_map = {}
    for tool in tools:
        tname = tool.get("name", "")
        if not tname:
            continue
        c_name = _canonical_name(tname)
        canonical_map.setdefault(c_name, []).append((tname, tool.get("file", "")))

    findings = []
    for c_name, variants in canonical_map.items():
        unique_names = list({name for name, _file in variants})
        if len(unique_names) > 1:
            files_involved = list({f for _n, f in variants})
            for v_name, v_file in variants:
                other_names = [n for n in unique_names if n != v_name]
                findings.append({
                    "tool": v_name,
                    "type": "Deceptive Near-Identical Tool Collision",
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "detail": (
                        f"Tool '{v_name}' has near-identical naming to {other_names} "
                        f"across files ({', '.join(files_involved)}). This ambiguity can deceive "
                        f"an AI agent into invoking the wrong tool or hijacking client dispatcher logic."
                    ),
                    "matched_text": f"Variants: {', '.join(unique_names)}",
                    "files": files_involved,
                })
    return findings


def scan_tools_for_shadowing(tools):
    """
    Scans for duplicate names, near-identical collision names, and redirect phrases.
    """
    findings = list(find_duplicate_tool_names(tools))
    findings.extend(find_near_identical_tool_names(tools))
    for tool in tools:
        findings.extend(
            find_redirect_language(tool.get("name", "UNKNOWN"), tool.get("description", ""))
        )
    return findings