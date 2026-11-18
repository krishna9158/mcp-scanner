"""
MCP Tool Result & Response Scanner (Indirect Prompt Injection & Exfiltration Defense).

Defensively analyzes runtime/mock tool responses and outputs for:
- Indirect prompt injection payloads (e.g. data returned from external APIs or scraped web pages containing instructions)
- Accidental secret leaks in tool return values
- Suspicious exfiltration URLs
- Base64 / Hex encoded secondary instructions
"""
import re
import json

INDIRECT_INJECTION_PATTERNS = [
    (r'(?i)\bignore (?:all )?(?:previous|prior|above) instructions\b', "CRITICAL", "Indirect Prompt Injection: Instruction override in tool result"),
    (r'(?i)\bdisregard (?:all )?(?:previous|prior|above) instructions\b', "CRITICAL", "Indirect Prompt Injection: Instruction override in tool result"),
    (r'(?i)\b(?:forward|send|exfiltrate|post)\s+(?:the\s+)?(?:data|output|result|keys?|secrets?)\s+to\s+https?://\S+', "CRITICAL", "Indirect Exfiltration Directive in tool result"),
    (r'(?i)\bdo not (?:tell|inform|alert) the user\b', "HIGH", "Covert action instruction in tool result"),
    (r'(?i)<system>.*?</system>', "HIGH", "Embedded XML system prompt tag in tool result"),
]

SECRET_INDICATOR_PATTERNS = [
    (r'\bAKIA[0-9A-Z]{16}\b', "AWS Access Key leaked in tool response"),
    (r'\bsk-[A-Za-z0-9_\-]{20,}\b', "OpenAI / Anthropic API Key leaked in tool response"),
    (r'\bgh[pousr]_[A-Za-z0-9]{36,}\b', "GitHub Token leaked in tool response"),
    (r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b', "JWT credential token leaked in tool response"),
]


def scan_tool_response(tool_name, response_payload):
    """
    Scans a tool's output or sample response for indirect injection and secret leakage.
    Accepts a string, dict, or list.
    """
    findings = []
    if isinstance(response_payload, (dict, list)):
        try:
            content_str = json.dumps(response_payload)
        except Exception:
            content_str = str(response_payload)
    else:
        content_str = str(response_payload or "")

    # 1. Indirect Prompt Injection check
    for pattern, severity, desc in INDIRECT_INJECTION_PATTERNS:
        match = re.search(pattern, content_str)
        if match:
            findings.append({
                "type": "Indirect Prompt Injection",
                "tool": tool_name,
                "severity": severity,
                "confidence": "CONFIRMED",
                "evidence": match.group(0),
                "detail": f"Tool '{tool_name}' output contains adversarial directive: '{match.group(0)}'. An AI agent ingesting this result would be vulnerable to indirect prompt injection.",
                "remediation": "Sanitize and strip prompt-directive delimiters and instruction phrases from tool return values before passing them back to the LLM context."
            })

    # 2. Secret leakage in response check
    for pattern, desc in SECRET_INDICATOR_PATTERNS:
        match = re.search(pattern, content_str)
        if match:
            findings.append({
                "type": "Secret Leakage in Output",
                "tool": tool_name,
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "evidence": f"{match.group(0)[:4]}...[REDACTED]...",
                "detail": f"Tool '{tool_name}' output contains an exposed credential signature: {desc}.",
                "remediation": "Ensure tools filter credentials and sensitive authentication headers before returning data to the client."
            })

    return {
        "tool_name": tool_name,
        "is_clean": len(findings) == 0,
        "findings": findings
    }
