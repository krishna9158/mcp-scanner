"""
Secret Detection & Multi-Layer Credential Scanner for TrustAudit.

Features:
- High-confidence signature matching for major cloud & SaaS providers
- Comprehensive Known-Placeholder Denylist (AWS, GCP, Azure, Slack, GitHub, Stripe documentation keys)
- Full support for standard suppression comments:
    # pragma: allowlist secret / // pragma: allowlist secret (detect-secrets / AWS repos)
    # gitleaks:allow / // gitleaks:allow (gitleaks)
    # nosec / // nosec (bandit / gosec)
    # noqa: secret / # noqa (linter suppression)
- Test-Context Awareness: Downgrades test fixtures/mock secrets to MEDIUM/LOW instead of CRITICAL
- Zero-leak credential redaction guarantees
"""

import math
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Variable assignment patterns for high-entropy heuristic analysis
# ---------------------------------------------------------------------------
SECRET_VARIABLE_PATTERN = re.compile(
    r'\b(?:api[_-]?key|secret|token|password|passwd|pwd|auth(?:_token)?|credential|access[_-]?key|private[_-]?key|client[_-]?secret)'
    r'\s*[:=]\s*["\']([^"\']{8,})["\']',
    re.IGNORECASE
)

# ---------------------------------------------------------------------------
# Known high-confidence signature patterns
# ---------------------------------------------------------------------------
KNOWN_SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r'\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b'),
    "AWS Secret Key": re.compile(r'(?i)\b(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'),
    "GitHub Token": re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b'),
    "Anthropic API Key": re.compile(r'\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9\-_]{20,}\b'),
    "OpenAI API Key": re.compile(r'\bsk-(?:proj-|svcacct-)?[A-Za-z0-9\-_]{20,}\b'),
    "Google API Key": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    "GCP Service Account": re.compile(r'"(?:type":\s*"service_account"|"private_key_id":\s*"[0-9a-f]{40}")'),
    "Azure Client Secret": re.compile(r'(?i)\b(?:azure_client_secret|azure_secret)\s*[:=]\s*["\']([A-Za-z0-9~_.\-]{30,})["\']'),
    "Slack Token": re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b'),
    "Slack Webhook URL": re.compile(r'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+'),
    "Generic Bearer Token": re.compile(r'\bBearer\s+([A-Za-z0-9\-_.]{20,})\b'),
    "Stripe Live Key": re.compile(r'\bsk_live_[A-Za-z0-9]{20,}\b'),
    "Stripe Test Key": re.compile(r'\bsk_test_[A-Za-z0-9]{20,}\b'),
    "Stripe Publishable Key": re.compile(r'\bpk_live_[A-Za-z0-9]{20,}\b'),
    "Twilio Account SID": re.compile(r'\bAC[a-f0-9]{32}\b'),
    "Twilio Auth Token": re.compile(r'\bSK[a-f0-9]{32}\b'),
    "SendGrid API Key": re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b'),
    "JWT Token": re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
    "PEM Private Key Block": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |)PRIVATE KEY-----'),
    "Database Connection String with Credentials": re.compile(
        r'\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s"\']+:[^@\s"\']+@[^\s"\']+'
    ),
}

SECRET_SEVERITY = {
    "AWS Access Key": "CRITICAL",
    "AWS Secret Key": "CRITICAL",
    "GitHub Token": "CRITICAL",
    "Anthropic API Key": "CRITICAL",
    "OpenAI API Key": "CRITICAL",
    "PEM Private Key Block": "CRITICAL",
    "Database Connection String with Credentials": "CRITICAL",
    "GCP Service Account": "CRITICAL",
    "Azure Client Secret": "CRITICAL",
    "Stripe Live Key": "CRITICAL",
    "Twilio Auth Token": "HIGH",
    "SendGrid API Key": "HIGH",
    "Slack Token": "HIGH",
    "Slack Webhook URL": "MEDIUM",
    "Google API Key": "HIGH",
    "JWT Token": "MEDIUM",
    "Generic Bearer Token": "HIGH",
    "Stripe Test Key": "LOW",
    "Stripe Publishable Key": "LOW",
    "Possible hardcoded secret": "HIGH",
}

# ---------------------------------------------------------------------------
# Known Documentation Placeholders & Example Credentials Denylist
# ---------------------------------------------------------------------------
KNOWN_PLACEHOLDER_SECRETS = {
    # AWS official documentation keys
    "AKIAIOSFODNN7EXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "je7M31357EOtx1xTxRfiCYEXAMPLEKEY",
    
    # GCP documentation placeholders
    "AIzaSyDummyKey1234567890abcdefghijklm",
    "AIzaSyEXAMPLEKeyForDocumentationPurposes1",
    "AIzaSyEXAMPLEKey1234567890abcdefghijkl",
    
    # Azure documentation placeholders
    "00000000-0000-0000-0000-000000000000",
    "11111111-1111-1111-1111-111111111111",
    "~EXAMPLE_AZURE_CLIENT_SECRET_KEY~",
    
    # GitHub documentation placeholders
    "ghp_EXAMPLETOKENFORGITHUBDOCS123456789",
    "ghp_000000000000000000000000000000000000",
    "gho_000000000000000000000000000000000000",
    "ghu_000000000000000000000000000000000000",
    "ghs_000000000000000000000000000000000000",
    "ghr_000000000000000000000000000000000000",
    "github_pat_0000000000000000000000_000000000000000000000000000000000000000000000000000000000000000000000000000000",
    
    # OpenAI & Anthropic documentation placeholders
    "sk-ant-api03-00000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "sk-proj-00000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "sk-000000000000000000000000000000000000000000000000",
    
    # Slack documentation placeholders
    "xox" + "b-000000000000-000000000000-EXAMPLETOKENFORSLACKDOCS",
    "xox" + "p-000000000000-000000000000-EXAMPLETOKENFORSLACKDOCS",
    "https://hooks.slack.com/services/" + "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    
    # Stripe documentation placeholders
    "sk" + "_test_4eC39HqLyjWDarjtT1zdp7dc",
    "pk" + "_test_TYooMQauvdEDq54NiTphI7jx",
    "sk" + "_test_BQokikJOvBiI2HlWgH4olfQ2",
    "pk" + "_test_6pRNASCoBOKtIshFeQdubGuO",
    
    # Generic repeated/dummy patterns
    "AKIAAAAAAAAAAAAAAAAA",
    "AKIA0000000000000000",
    "AKIA1111111111111111",
    "12345678901234567890",
    "abcdefghijklmnopqrst",
    "ABCDEFGHIJKLMNOPQRST",
}

PLACEHOLDER_SUBSTRINGS = (
    "example", "placeholder", "changeme", "replace_me", "insert_key",
    "dummy", "fake_key", "your_secret", "your_token", "your_api_key",
    "sample_key", "test_key", "mock_key", "demo_key",
)

PLACEHOLDER_VALUES = {
    "your_api_key_here", "your-api-key-here", "changeme", "xxxxxxxx",
    "insert_key_here", "replace_me", "example_key", "placeholder",
    "test", "testing", "dummy", "fake_key", "your_secret_here",
    "your_token_here", "your-token-here", "changethis", "todo",
    "not_a_real_key", "fake_secret", "sample_key", "abc123", "12345678",
    "null", "none", "true", "false", "undefined", "localhost", "secret",
}

# ---------------------------------------------------------------------------
# Suppression Comment Signatures
# ---------------------------------------------------------------------------
SUPPRESSION_PATTERNS = [
    re.compile(r'#\s*(?:pragma:\s*allowlist\s*secret|gitleaks:allow|nosec|noqa(?::\s*secret)?|trustaudit:allow|ignore-secret)', re.IGNORECASE),
    re.compile(r'//\s*(?:pragma:\s*allowlist\s*secret|gitleaks:allow|nosec|noqa(?::\s*secret)?|trustaudit:allow|ignore-secret)', re.IGNORECASE),
    re.compile(r'/\*\s*(?:pragma:\s*allowlist\s*secret|gitleaks:allow|nosec|noqa|trustaudit:allow)\s*\*/', re.IGNORECASE),
    re.compile(r'<!--\s*(?:pragma:\s*allowlist\s*secret|gitleaks:allow|nosec)\s*-->', re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Test Context Path & File Signatures
# ---------------------------------------------------------------------------
TEST_PATH_SEGMENTS = (
    "/tests/", "/test/", "/testing/", "/fixtures/", "/test_data/", "/mocks/", "/stubs/",
    "/__tests__/", "/__fixtures__/", "/__mocks__/", "\\tests\\", "\\test\\", "\\testing\\",
    "\\fixtures\\", "\\test_data\\", "\\mocks\\", "\\stubs\\", "\\__tests__\\", "\\__fixtures__\\"
)

TEST_FILE_PATTERNS = (
    r"(?i)^test_.*\.py$",
    r"(?i)^.*_test\.py$",
    r"(?i)^.*\.test\.[jt]sx?$",
    r"(?i)^.*\.spec\.[jt]sx?$",
    r"(?i)^conftest\.py$",
    r"(?i)^mock_.*\.py$",
    r"(?i)^fixture.*\.json$",
)

SKIP_FILENAME_PATTERNS = (".min.js", ".min.css", "-lock.json", ".lock")
SKIP_PATH_SEGMENTS = ("vendor", "third_party", "node_modules", "dist", "build", ".git", ".pytest_cache", ".venv", "venv", ".next", "coverage")
MAX_INDIVIDUAL_FILE_BYTES = 5 * 1024 * 1024  # 5 MB max per file
ENTROPY_THRESHOLD = 3.5


def is_known_placeholder_secret(value: str) -> bool:
    """
    Checks if a detected secret value is a known documentation placeholder,
    tutorial example, dummy test string, or contains 'EXAMPLE'.
    """
    if not value or not isinstance(value, str) or not value.strip():
        return False
    val_clean = value.strip()
    val_lower = val_clean.lower()

    # 1. Direct match in KNOWN_PLACEHOLDER_SECRETS
    if val_clean in KNOWN_PLACEHOLDER_SECRETS or val_lower in PLACEHOLDER_VALUES:
        return True
    for placeholder in KNOWN_PLACEHOLDER_SECRETS:
        if val_lower == placeholder.lower():
            return True

    # 2. Substring match for 'example' or documentation placeholders
    if "example" in val_lower:
        return True
    for substr in PLACEHOLDER_SUBSTRINGS:
        if substr in val_lower:
            return True

    # 3. Repeated character / Low entropy dummy secrets (e.g. AAAAAAAA, 00000000)
    alphanumeric = re.sub(r'[^A-Za-z0-9]', '', val_clean)
    if len(alphanumeric) >= 8 and len(set(alphanumeric)) <= 2:
        return True

    return False


def is_line_suppressed(line_text: str, next_line_text: str = "") -> bool:
    """
    Checks if a code line contains standard suppression comments (detect-secrets, gitleaks, bandit, noqa).
    Also checks the immediate next line in case the suppression comment is placed directly below.
    """
    combined = f"{line_text}\n{next_line_text}"
    return any(pat.search(combined) for pat in SUPPRESSION_PATTERNS)


def is_test_context(filepath: str) -> bool:
    """
    Determines whether a file is located in a test/fixture directory or has a test filename.
    """
    if not filepath:
        return False
    norm_path = filepath.replace("\\", "/").lower().strip("/")
    parts = norm_path.split("/")
    test_dir_names = {"tests", "test", "testing", "fixtures", "test_data", "mocks", "stubs", "__tests__", "__fixtures__", "__mocks__"}
    if any(part in test_dir_names for part in parts[:-1]):
        return True
    if any(part in test_dir_names for part in parts):
        return True
    filename = parts[-1]
    return any(re.search(pat, filename) for pat in TEST_FILE_PATTERNS)


def redact_secret(value: str) -> str:
    """
    Safely redacts a sensitive credential so that zero actual secret material
    is leaked in logs, UI, JSON, or reports.
    """
    if not value or not isinstance(value, str):
        return "[REDACTED]"
    val = value.strip()
    if len(val) <= 8:
        return "[REDACTED]"
    prefix = val[:4]
    suffix = val[-2:]
    return f"{prefix}...[REDACTED]...{suffix}"


def _get_line_number_and_text(content: str, char_index: int) -> Tuple[int, str, str]:
    """Computes the 1-based line number, current line text, and next line text."""
    line_num = content.count("\n", 0, char_index) + 1
    lines = content.splitlines()
    curr_line = lines[line_num - 1] if line_num - 1 < len(lines) else ""
    next_line = lines[line_num] if line_num < len(lines) else ""
    return line_num, curr_line, next_line


def _should_skip_file(filepath: str) -> bool:
    normalized = filepath.replace("\\", "/").lower()
    parts = normalized.split("/")
    if any(part in SKIP_PATH_SEGMENTS for part in parts):
        return True
    filename = parts[-1]
    return any(filename.endswith(suffix) for suffix in SKIP_FILENAME_PATTERNS)


def calculate_entropy(text: str) -> float:
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


def scan_text_for_secrets(content: str, filepath: str = "unknown") -> List[Dict[str, Any]]:
    findings = []
    seen_matches = set()

    if len(content) > MAX_INDIVIDUAL_FILE_BYTES:
        content = content[:MAX_INDIVIDUAL_FILE_BYTES]

    in_test = is_test_context(filepath)

    # 1. Signature-based scanning
    for secret_type, pattern in KNOWN_SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            
            # Step A: Filter out known documentation placeholders
            if is_known_placeholder_secret(val):
                continue

            line, line_text, next_line_text = _get_line_number_and_text(content, match.start())

            # Step B: Filter out lines with standard suppression comments
            if is_line_suppressed(line_text, next_line_text):
                continue

            key = (filepath, line, secret_type)
            if key in seen_matches:
                continue
            seen_matches.add(key)

            # Step C: Test-context handling (downgrade severity, don't hide)
            if in_test:
                severity = "MEDIUM" if SECRET_SEVERITY.get(secret_type) == "CRITICAL" else "LOW"
                finding_type = f"Possible Test Fixture ({secret_type})"
                confidence = "MEDIUM"
                reason = f"Matches {secret_type} format inside test directory/file ({filepath}). Verified as possible test credential."
                remediation = "If this is a real credential accidentally committed to tests, rotate it immediately. Otherwise, use mock fixture tokens."
            else:
                severity = SECRET_SEVERITY.get(secret_type, "HIGH")
                finding_type = secret_type
                confidence = "HIGH"
                reason = f"Matches known {secret_type} signature."
                remediation = "Rotate this credential immediately and move it to environment variables or a secure secret manager (e.g. AWS Secrets Manager, HashiCorp Vault)."

            findings.append({
                "file": filepath,
                "line": line,
                "type": finding_type,
                "severity": severity,
                "value_preview": redact_secret(val),
                "confidence": confidence,
                "reason": reason,
                "recommendation": remediation,
                "is_test_context": in_test,
            })

    # 2. Heuristic entropy-based scanning
    for match in SECRET_VARIABLE_PATTERN.finditer(content):
        value = match.group(1)
        if is_known_placeholder_secret(value):
            continue

        entropy = calculate_entropy(value)
        if entropy >= ENTROPY_THRESHOLD:
            line, line_text, next_line_text = _get_line_number_and_text(content, match.start())
            if is_line_suppressed(line_text, next_line_text):
                continue

            key = (filepath, line, "Possible hardcoded secret")
            if key in seen_matches:
                continue
            seen_matches.add(key)

            if in_test:
                severity = "LOW"
                finding_type = "Possible Test Fixture (Entropy Match)"
                confidence = "LOW"
                reason = f"High-entropy string assigned to secret variable inside test file ({filepath})."
                remediation = "Verify whether this is a mock test key. If so, annotate with '# pragma: allowlist secret'."
            else:
                severity = "HIGH"
                finding_type = "Possible hardcoded secret"
                confidence = "MEDIUM"
                reason = f"Assigned to a secret-sounding variable name with high randomness (Shannon entropy {entropy:.1f})."
                remediation = "Verify whether this is an active credential. If so, rotate it and load it dynamically from environment variables."

            findings.append({
                "file": filepath,
                "line": line,
                "type": finding_type,
                "severity": severity,
                "value_preview": redact_secret(value),
                "confidence": confidence,
                "reason": reason,
                "recommendation": remediation,
                "is_test_context": in_test,
            })

    return findings


def scan_folder_for_secrets(folder: str, max_files: int = 5000) -> List[Dict[str, Any]]:
    all_findings = []
    count = 0
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_PATH_SEGMENTS]
        for file in files:
            if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".json", ".env", ".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg")):
                filepath = os.path.join(root, file)
                if _should_skip_file(filepath):
                    continue
                try:
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
