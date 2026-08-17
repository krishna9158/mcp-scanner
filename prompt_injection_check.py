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

This module provides TWO layers of detection:
    1. Heuristic pattern-based (no LLM required, fast and free)
    2. Severity-scored findings with confidence levels

Confidence levels reflect how sure we are this is actually malicious:
    - HIGH:    Very likely prompt injection (direct instruction phrases,
               hidden characters, or extremely long descriptions with
               instruction-like content)
    - MEDIUM:  Suspicious but could have an innocent explanation
    - LOW:     Mild signal worth flagging, but easily a false positive
"""
import re

# Phrases seen in real-world tool-poisoning attempts - language that
# instructs the AI agent on how to behave more broadly, rather than
# describing what this one tool does.
SUSPICIOUS_INSTRUCTION_PHRASES = [
    # Direct command injection -- HIGH confidence
    (r'ignore (?:all )?(?:previous|prior|above) instructions', "HIGH", "Direct instruction to override system prompts"),
    (r'disregard (?:all )?(?:previous|prior|above) instructions', "HIGH", "Direct instruction to override system prompts"),
    (r'you must (?:always|never)', "HIGH", "Imperative command directed at the AI agent"),
    (r'do not (?:tell|inform|mention|notify) the user', "HIGH", "Explicit instruction to conceal from the user"),
    (r'without (?:telling|informing|notifying) the user', "HIGH", "Implicit instruction to act secretly"),
    # Tool redirection -- HIGH confidence
    (r'always call \w+', "HIGH", "Instructs AI to call another tool regardless of context"),
    (r'after (?:calling|using) this tool,?\s*(?:also|always)', "HIGH", "Forces chaining to another tool"),
    (r'in addition to your (?:task|instructions)', "HIGH", "Adds hidden task beyond what user requested"),
    (r'append .* to (?:every|all) (?:response|reply|message)', "HIGH", "Instructs AI to modify its outputs"),
    # Data exfiltration -- HIGH confidence
    (r'forward (?:this|the) (?:data|result|output|information) to', "HIGH", "Instructs data forwarding to external recipient"),
    (r'send (?:this|the) (?:data|result|output|information) to', "HIGH", "Instructs data sending to external recipient"),
    # Role manipulation -- MEDIUM confidence (could be legitimate framing)
    (r'\byou are (?:now|a)\b', "MEDIUM", "Attempts to change the AI's role or identity"),
    (r'before (?:responding|answering|replying) to the user', "MEDIUM", "Instructs pre-response behavior modification"),
    (r'secretly', "MEDIUM", "Suggests hidden/covert action"),
    # Subtle injection -- LOW confidence
    (r'system\s*:', "LOW", "Contains system-prompt-like formatting"),
]

# Zero-width / invisible Unicode characters: a description can look
# completely normal to a human reviewing the code while still containing
# extra hidden text an AI would read in full.
ZERO_WIDTH_CHARS = ['​', '‌', '‍', '⁠', '﻿']
ZERO_WIDTH_CONFIDENCE = "HIGH"  # Zero-width chars are very rarely legitimate

# Length threshold for unusually long descriptions
LONG_DESCRIPTION_THRESHOLD = 800
LONG_DESC_CONFIDENCE = "MEDIUM"  # Could be thorough docs, not necessarily injection

# Patterns that suggest a description is a legitimate system prompt reference
# rather than injection (reduces confidence when present)
LEGITIMATE_FRAMING = [
    r"this (?:is a|is an) .* (?:assistant|helper|agent|system)",
    r"the following (?:is|are) .* (?:instruction|guideline|rule|policy)",
    r"please (?:note|remember|keep in mind|be aware)",
]


def _check_legitimate_framing(description):
    """
    If the description contains phrases indicating it's documenting the
    AI's instructions (rather than trying to inject new ones), reduce
    confidence. This catches false positives where a description is
    legitimately summarizing system behavior.
    """
    if not description:
        return False
    lowered = description.lower()
    for pattern in LEGITIMATE_FRAMING:
        if re.search(pattern, lowered):
            return True
    return False


def check_description_for_injection(tool_name, description):
    """
    Scans a single tool's description for signs of prompt injection.

    Returns a list of finding dicts (empty if nothing suspicious found).
    Each finding includes:
        - type: category of injection signal
        - detail: human-readable explanation
        - confidence: HIGH | MEDIUM | LOW
        - severity: HIGH | MEDIUM | LOW
        - matched_text: the specific phrase that triggered the detection
    """
    findings = []
    if not description:
        return findings

    lowered = description.lower()

    # Check instruction phrases with severity/confidence
    for pattern, confidence, explanation in SUSPICIOUS_INSTRUCTION_PHRASES:
        match = re.search(pattern, lowered)
        if match:
            # Reduce confidence if legitimate framing is also present
            final_confidence = confidence
            if _check_legitimate_framing(description):
                if confidence == "HIGH":
                    final_confidence = "MEDIUM"
                elif confidence == "MEDIUM":
                    final_confidence = "LOW"

            findings.append({
                "tool": tool_name,
                "type": "Suspicious instruction phrase",
                "detail": explanation,
                "confidence": final_confidence,
                "severity": confidence,
                "matched_text": match.group(0),
            })
            break  # one match is enough to flag this tool

    # Zero-width characters
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
                "confidence": ZERO_WIDTH_CONFIDENCE,
                "severity": "HIGH",
                "matched_text": repr(ch),
            })
            break

    # Unusually long description
    if len(description) > LONG_DESCRIPTION_THRESHOLD:
        findings.append({
            "tool": tool_name,
            "type": "Unusually long description",
            "detail": (
                f"Description is {len(description)} characters long - far longer "
                f"than a typical tool description, which can be used to smuggle "
                f"in extra instructions."
            ),
            "confidence": LONG_DESC_CONFIDENCE,
            "severity": "MEDIUM",
            "matched_text": f"length={len(description)}",
        })

    return findings


def scan_tools_for_prompt_injection(tools):
    """
    tools: list of dicts with at least 'name' and 'description' keys - the
    same shape produced by extract_tools.py and js_ts_scanner.py.

    Returns a flat list of finding dicts; each finding includes which tool
    it's about via its 'tool' key, so callers can group them per-tool if
    needed.
    """
    all_findings = []
    for tool in tools:
        all_findings.extend(
            check_description_for_injection(
                tool.get("name", "UNKNOWN"), tool.get("description", "")
            )
        )
    return all_findings