import re
import math
import os


# Common variable-name patterns that suggest a secret is being assigned
SECRET_VARIABLE_PATTERN = re.compile(
    r'\b(?:api[_-]?key|secret|token|password|passwd|pwd|auth|credential|access[_-]?key|private[_-]?key)'
    r'\s*=\s*["\']([^"\']{8,})["\']',
    re.IGNORECASE
)

# Known secret formats with recognizable prefixes - these are near-certain
# matches, not heuristics, so they get flagged regardless of entropy.
KNOWN_SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "GitHub Token": re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    "Anthropic API Key": re.compile(r'\bsk-ant-[A-Za-z0-9\-_]{20,}\b'),
    "OpenAI API Key": re.compile(r'\bsk-[A-Za-z0-9]{20,}\b'),
    "Slack Token": re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b'),
    "Generic Bearer Token": re.compile(r'\bBearer\s+[A-Za-z0-9\-_.]{20,}\b'),
}

# Values that LOOK like secrets by pattern but obviously aren't real ones -
# skip these so we don't spam false positives on every example/test file.
PLACEHOLDER_VALUES = {
    "your_api_key_here", "your-api-key-here", "changeme", "xxxxxxxx",
    "insert_key_here", "replace_me", "example_key", "placeholder",
    "test", "testing", "dummy", "fake_key", "your_secret_here",
}


def calculate_entropy(text):
    """
    Shannon entropy: measures how 'random' a string looks, on a scale
    where higher = more random/unpredictable. Real secrets (API keys,
    tokens) are typically randomly generated, so they score high. Normal
    English words, sentences, or simple placeholders score low.
    A rough guide: below ~3.0 is normal text, above ~4.0 is very likely
    random-generated data.
    """
    if not text:
        return 0.0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


ENTROPY_THRESHOLD = 3.5


def scan_text_for_secrets(content, filepath="unknown"):
    """
    Two detection strategies, combined:
    1. Known secret formats (AWS keys, GitHub tokens, etc.) - matched by
       their distinctive prefix, near-certain when found.
    2. Variable-assignment + entropy check - finds `api_key = "..."`-style
       assignments, then scores the assigned value's randomness. High
       entropy + a secret-sounding variable name = likely a real secret.
    """
    findings = []

    for secret_type, pattern in KNOWN_SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            findings.append({
                "file": filepath,
                "type": secret_type,
                "value_preview": match.group(0)[:12] + "...",
                "confidence": "HIGH",
                "reason": f"Matches known {secret_type} format.",
            })

    for match in SECRET_VARIABLE_PATTERN.finditer(content):
        value = match.group(1)
        if value.lower() in PLACEHOLDER_VALUES:
            continue
        entropy = calculate_entropy(value)
        if entropy >= ENTROPY_THRESHOLD:
            findings.append({
                "file": filepath,
                "type": "Possible hardcoded secret",
                "value_preview": value[:4] + "..." + value[-2:] if len(value) > 8 else "***",
                "confidence": "MEDIUM",
                "reason": f"Assigned to a secret-sounding variable name with high randomness (entropy {entropy:.1f}).",
            })

    return findings


def scan_folder_for_secrets(folder, max_files=500):
    all_findings = []
    count = 0
    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.endswith((".py", ".js", ".ts", ".json", ".env", ".yml", ".yaml")):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                findings = scan_text_for_secrets(content, filepath)
                all_findings.extend(findings)
                count += 1
                if count >= max_files:
                    return all_findings
    return all_findings
