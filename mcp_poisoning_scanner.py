"""
Deep MCP Tool Poisoning & Schema Injection Scanner.

Inspects the entire tool surface:
- Name & human description
- Parameters & parameter descriptions
- JSON schema properties, types, defaults
- Enums and example payloads
- Annotations and return descriptions

Detects:
- Instruction override attempts
- Fake developer/system framing (<system>, [SYSTEM], Developer Note:)
- Covert secret exfiltration commands
- Zero-width and steganographic Unicode encoding
- Social engineering directives (e.g. "Do not tell the user")
"""
import re
import json

POISON_PATTERNS = [
    (r'(?i)\bignore (?:all )?(?:previous|prior|above) instructions\b', "CRITICAL", "Direct instruction override attempt"),
    (r'(?i)\bdisregard (?:all )?(?:previous|prior|above) instructions\b', "CRITICAL", "Direct instruction override attempt"),
    (r'(?i)\b(?:reveal|print|exfiltrate|send|dump)\s+(?:the\s+)?(?:api[_-]?key|secrets?|passwords?|env(?:ironment)?)\b', "CRITICAL", "Secret exfiltration instruction"),
    (r'(?i)(?:<system>|\[system\]|system\s*:|developer\s+mode:)', "HIGH", "Fake system/developer prompt framing"),
    (r'(?i)\bdo not (?:tell|inform|notify|alert) the user\b', "HIGH", "Covert action directive concealing behavior from user"),
    (r'(?i)\balways (?:call|invoke|use)\s+["\']?(\w+)["\']?\s+first\b', "HIGH", "Forced tool chaining / execution hijacking"),
    (r'(?i)\byou are (?:now|operating as)\s+(?:an?\s+)?(?:root|admin|unrestricted)\b', "HIGH", "Role hijacking / jailbreak framing"),
]

ZERO_WIDTH_CHARS = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff']


def _extract_all_strings_from_object(obj, path=""):
    """
    Recursively extracts all string values along with their JSON paths
    from a dictionary or list structure.
    """
    results = []
    if isinstance(obj, str):
        results.append((path or "root", obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            curr_path = f"{path}.{k}" if path else k
            results.append((f"{curr_path} [key]", str(k)))
            results.extend(_extract_all_strings_from_object(v, curr_path))
    elif isinstance(obj, (list, tuple)):
        for idx, item in enumerate(obj):
            curr_path = f"{path}[{idx}]"
            results.extend(_extract_all_strings_from_object(item, curr_path))
    return results


def scan_tool_definition_for_poisoning(tool):
    """
    Scans every facet of a tool definition (name, description, schema,
    parameters, annotations) for prompt-injection / tool poisoning.
    """
    findings = []
    tool_name = tool.get("name", "unnamed_tool")
    
    # 1. Collect all textual fields
    fields_to_check = [
        ("tool.name", tool_name),
        ("tool.description", tool.get("description", "")),
        ("tool.return_description", tool.get("return_description", "")),
    ]

    # Inspect schema if available
    schema = tool.get("input_schema") or tool.get("parameters") or {}
    if schema:
        fields_to_check.extend(_extract_all_strings_from_object(schema, "tool.parameters"))

    annotations = tool.get("annotations") or {}
    if annotations:
        fields_to_check.extend(_extract_all_strings_from_object(annotations, "tool.annotations"))

    # 2. Check each field for poisoning
    for location, text in fields_to_check:
        if not text or not isinstance(text, str):
            continue

        # Zero-width characters check
        for zw in ZERO_WIDTH_CHARS:
            if zw in text:
                findings.append({
                    "type": "Steganographic Hidden Content",
                    "severity": "CRITICAL",
                    "confidence": "CONFIRMED",
                    "location": location,
                    "matched_text": f"[Zero-width unicode char U+{ord(zw):04X}]",
                    "detail": f"Hidden zero-width Unicode character found at `{location}`. This is commonly used to conceal prompt injection from human reviewers."
                })
                break

        # Regex pattern check
        for pattern, severity, description in POISON_PATTERNS:
            match = re.search(pattern, text)
            if match:
                findings.append({
                    "type": description,
                    "severity": severity,
                    "confidence": "CONFIRMED" if severity == "CRITICAL" else "LIKELY",
                    "location": location,
                    "matched_text": match.group(0),
                    "detail": f"Suspicious prompt-injection content found in `{location}`: '{match.group(0)}'."
                })

    return findings


def scan_all_tools_for_poisoning(tools):
    """
    Runs complete schema & description poisoning scan across all tools.
    """
    results = {}
    for tool in tools:
        tname = tool.get("name", "unnamed")
        tool_findings = scan_tool_definition_for_poisoning(tool)
        if tool_findings:
            results[tname] = tool_findings
    return results
