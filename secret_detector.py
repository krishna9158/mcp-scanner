import re
import math
import os


SECRET_VARIABLE_PATTERN = re.compile(
    r'\b(?:api[_-]?key|secret|token|password|passwd|pwd|auth|credential|access[_-]?key|private[_-]?key)'
    r'\s*=\s*["\']([^"\']{8,})["\']',
    re.IGNORECASE
)

# Known secret formats with recognizable prefixes/shapes - these are
# near-certain matches, not heuristics, so they get flagged regardless of
# entropy.
KNOWN_SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "GitHub Token": re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    "Anthropic API Key": re.compile(r'\bsk-ant-[A-Za-z0-9\-_]{20,}\b'),
    "OpenAI API Key": re.compile(r'\bsk-[A-Za-z0-9]{20,}\b'),
    "Slack Token": re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b'),
    "Slack Webhook URL": re.compile(r'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+'),
    "Generic Bearer Token": re.compile(r'\bBearer\s+[A-Za-z0-9\-_.]{20,}\b'),
    "Stripe Live Key": re.compile(r'\bsk_live_[A-Za-z0-9]{20,}\b'),
    "Stripe Test Key": re.compile(r'\bsk_test_[A-Za-z0-9]{20,}\b'),
    "Stripe Publishable Key": re.compile(r'\bpk_live_[A-Za-z0-9]{20,}\b'),
    "Google API Key": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    "Twilio Account SID": re.compile(r'\bAC[a-f0-9]{32}\b'),
    "Twilio Auth Token": re.compile(r'\bSK[a-f0-9]{32}\b'),
    "SendGrid API Key": re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b'),
    "JWT": re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
    "PEM Private Key Block": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----'),
    "Database Connection String with Credentials": re.compile(
        r'\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:\s"\']+:[^@\s"\']+@[^\s"\']+'
    ),
}

# Values that LOOK like secrets by pattern but obviously aren't real ones -
# skip these so we don't spam false positives on every example/test file.
PLACEHOLDER_VALUES = {
    "your_api_key_here", "your-api-key-here", "changeme", "xxxxxxxx",
    "insert_key_here", "replace_me", "example_key", "placeholder",
    "test", "testing", "dummy", "fake_key", "your_secret_here",
    "your_token_here", "your-token-here", "changethis", "todo",
    "not_a_real_key", "fake_secret", "sample_key", "abc123", "12345678",
}

# Files that would otherwise flood results with noise or false positives:
# minified bundles often contain long random-looking strings that are just
# obfuscated code, not secrets, and lockfiles/vendored code isn't this
# project's own secrets to fix even if something matched.
SKIP_FILENAME_PATTERNS = (".min.js", ".min.css", "-lock.json", ".lock")
SKIP_PATH_SEGMENTS = ("vendor", "third_party", "node_modules", "dist", "build", ".git", ".pytest_cache", ".venv", "venv", ".next", "coverage")
MAX_INDIVIDUAL_FILE_BYTES = 5 * 1024 * 1024  # 5 MB max per file for regex analysis


def _should_skip_file(filepath):
    normalized = filepath.replace("\\", "/").lower()
    parts = normalized.split("/")
    if any(part in SKIP_PATH_SEGMENTS for part in parts):
        return True
    filename = parts[-1]
    return any(filename.endswith(suffix) for suffix in SKIP_FILENAME_PATTERNS)


def calculate_entropy(text):
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
    findings = []

    # Limit string length processed at once to prevent regex hangs on giant strings
    if len(content) > MAX_INDIVIDUAL_FILE_BYTES:
        content = content[:MAX_INDIVIDUAL_FILE_BYTES]

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


def scan_folder_for_secrets(folder, max_files=5000):
    all_findings = []
    count = 0
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_PATH_SEGMENTS]
        for file in files:
            if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".json", ".env", ".yml", ".yaml")):
                filepath = os.path.join(root, file)
                if _should_skip_file(filepath):
                    continue
                try:
                    # Skip extremely large binary/data dumps
                    if os.path.getsize(filepath) > 20 * 1024 * 1024:
                        continue
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(MAX_INDIVIDUAL_FILE_BYTES)
                except Exception:
                    continue
                findings = scan_text_for_secrets(content, filepath)
                all_findings.extend(findings)
                count += 1
                if max_files is not None and count >= max_files:
                    return all_findings
    return all_findings

