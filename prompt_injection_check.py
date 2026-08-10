"""
Prompt-injection ("tool poisoning") detection.

A tool's name and description aren't just documentation for a human
developer - they're read directly by the AI agent that decides when and
how to call the tool. That creates an attack surface unique to MCP and
similar tool-calling systems: a malicious server can write a description
that looks innocent to a human skimming the code, but contains hidden
instructions aimed at the AI itself - e.g. telling it to also call a
different tool, to hide something from the user, or to exfiltrate data
elsewhere. This is often called "tool poisoning."

This is a heuristic, pattern-based first pass (no LLM call required, so
it's fast and free to run on every scan) - it flags descriptions that
read like instructions rather than documentation. Like the rest of this
scanner's mismatch detection, it's meant to catch obvious cases and point
a human at anything worth a closer look, not to be a perfect detector.
"""
import re

# Phrases seen in real-world tool-poisoning attempts - language that
# instructs the AI agent on how to behave more broadly, rather than
# describing what this one tool does. A legitimate tool description
# explains its own purpose; it never needs to tell the agent to hide
# things from the user, always chain into another tool, or ignore its
# other instructions.
SUSPICIOUS_INSTRUCTION_PHRASES = [
    r'ignore (?:all )?(?:previous|prior|above) instructions',
    r'disregard (?:all )?(?:previous|prior|above) instructions',
    r'you must (?:always|never)',
    r'do not (?:tell|inform|mention|notify) the user',
    r'without (?:telling|informing|notifying) the user',
    r'secretly',
    r'before (?:responding|answering|replying) to the user',
    r'after (?:calling|using) this tool,?\s*(?:also|always)',
    r'always call \w+',
    r'in addition to your (?:task|instructions)',
    r'system\s*:',
    r'\byou are (?:now|a)\b',
    r'forward (?:this|the) (?:data|result|output|information) to',
    r'send (?:this|the) (?:data|result|output|information) to',
    r'append .* to (?:every|all) (?:response|reply|message)',
]

# Zero-width / invisible Unicode characters: a description can look
# completely normal to a human reviewing the code while still containing
# extra hidden text an AI would read in full - these characters are the
# usual way that's done.
ZERO_WIDTH_CHARS = ['\u200b', '\u200c', '\u200d', '\u2060', '\ufeff']

# A real tool description explaining what a tool does rarely needs to run
# this long - length alone isn't proof of anything, but it's a mild signal
# worth surfacing, since injected instructions tend to be verbose.
LONG_DESCRIPTION_THRESHOLD = 800


def check_description_for_injection(tool_name, description):
    """
    Scans a single tool's description for signs of prompt injection.
    Returns a list of finding dicts (empty if nothing suspicious found).
    """
    findings = []
    if not description:
        return findings

    lowered = description.lower()

    for pattern in SUSPICIOUS_INSTRUCTION_PHRASES:
        if re.search(pattern, lowered):
            findings.append({
                "tool": tool_name,
                "type": "Suspicious instruction phrase",
                "detail": (
                    "Description contains language that reads like an instruction "
                    "aimed at the AI agent, not a description of what the tool does."
                ),
            })
            break  # one match is enough to flag this tool - avoid duplicate spam

    for ch in ZERO_WIDTH_CHARS:
        if ch in description:
            findings.append({
                "tool": tool_name,
                "type": "Hidden characters",
                "detail": (
                    "Description contains invisible/zero-width Unicode characters, "
                    "which can hide extra text from a human reviewer while an AI "
                    "agent still reads it in full."
                ),
            })
            break

    if len(description) > LONG_DESCRIPTION_THRESHOLD:
        findings.append({
            "tool": tool_name,
            "type": "Unusually long description",
            "detail": (
                f"Description is {len(description)} characters long - far longer "
                f"than a typical tool description, which can be used to smuggle "
                f"in extra instructions."
            ),
        })

    return findings


def scan_tools_for_prompt_injection(tools):
    """
    tools: list of dicts with at least 'name' and 'description' keys - the
    same shape produced by extract_tools.py and js_ts_scanner.py.
    """
    all_findings = []
    for tool in tools:
        all_findings.extend(
            check_description_for_injection(tool.get("name", "UNKNOWN"), tool.get("description", ""))
        )
    return all_findings
