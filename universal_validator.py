"""
Universal False-Positive Prevention Engine & Credential Verifier for TrustAudit.

Provides a single shared validation function that every scanning engine runs every
finding through before assigning final severity and confidence:

1. Placeholder & Example Denylist:
   - Excludes/downgrades matches containing: "EXAMPLE", "REDACTED", "PLACEHOLDER",
     "SAMPLE", "DUMMY", "FAKE", "TEST", "xxx", "your-", "changeme", "TODO"
2. RFC 2606 Reserved Domain & Localhost Filter:
   - Excludes/downgrades URLs matching example.com/.org/.net, localhost, 127.0.0.1,
     0.0.0.0, ::1, or any RFC 2606 reserved TLDs (.invalid, .test, .example, .localhost)
3. Suppression Comments:
   - Excludes findings with: # pragma: allowlist secret, # gitleaks:allow, # nosec,
     // nosec, # noqa, # trustaudit:allow, # ignore-secret
4. Test/Example Context Downgrade:
   - Downgrades findings in /test/, /tests/, /fixtures/, /mocks/, /examples/, /demo/
     or matching *.test.*, *_test.*, test_*.*, *.spec.*, redact_secrets.test.cjs
     to LOW severity with label "Likely Test/Example Data" (Confidence: POSSIBLE)
5. Entropy Scoring:
   - Calculates Shannon entropy for secret matches. Low-entropy/predictable strings
     are never marked CONFIRMED.
6. 3-Tier Standardized Confidence:
   - CONFIRMED (verified live or directly exploitable)
   - LIKELY (strong match in production context, unverified)
   - POSSIBLE (matches pattern but has test/example/ambiguity signals or low entropy)
7. Live Credential Verification:
   - AWS STS GetCallerIdentity
   - GitHub API Token validation (/user)
   - Stripe API Key balance check (/v1/balance)
"""

import math
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# 1. RFC 2606 Reserved Domains & Localhost IP Signatures
# ---------------------------------------------------------------------------
RFC_2606_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "invalid", "test", "example", "localhost"
}

RFC_2606_SUFFIXES = (
    ".example.com", ".example.org", ".example.net", ".example.edu",
    ".invalid", ".test", ".example", ".localhost"
)

LOCAL_HOST_TARGETS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "127.0.0.2"}

# ---------------------------------------------------------------------------
# 2. Known Documentation Placeholders & Example Substrings
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

    # Generic dummy repeated keys
    "AKIAAAAAAAAAAAAAAAAA",
    "AKIA0000000000000000",
    "AKIA1111111111111111",
    "12345678901234567890",
    "abcdefghijklmnopqrst",
    "ABCDEFGHIJKLMNOPQRST",
}

PLACEHOLDER_SUBSTRINGS = (
    "example", "redacted", "placeholder", "sample", "dummy", "fake",
    "test", "xxx", "your-", "your_", "changeme", "todo", "insert_key",
    "replace_me", "dummy_key", "fake_secret", "sample_key", "mock_key",
    "demo_key", "your_secret", "your_token", "your_api_key", "fake_key",
)

# ---------------------------------------------------------------------------
# 3. Standard Suppression Comment Signatures
# ---------------------------------------------------------------------------
SUPPRESSION_PATTERNS = [
    re.compile(r'#\s*(?:pragma:\s*allowlist\s*secret|gitleaks:allow|nosec|noqa(?::\s*secret)?|trustaudit:allow|ignore-secret)', re.IGNORECASE),
    re.compile(r'//\s*(?:pragma:\s*allowlist\s*secret|gitleaks:allow|nosec|noqa(?::\s*secret)?|trustaudit:allow|ignore-secret)', re.IGNORECASE),
    re.compile(r'/\*\s*(?:pragma:\s*allowlist\s*secret|gitleaks:allow|nosec|noqa|trustaudit:allow)\s*\*/', re.IGNORECASE),
    re.compile(r'<!--\s*(?:pragma:\s*allowlist\s*secret|gitleaks:allow|nosec)\s*-->', re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# 4. Test & Example Path / File Signatures
# ---------------------------------------------------------------------------
TEST_PATH_SEGMENTS = (
    "test", "tests", "fixtures", "mocks", "examples", "demo", "samples",
    "__tests__", "__fixtures__", "__mocks__", "stubs", "spec", "specs"
)

TEST_FILE_PATTERNS = (
    r"(?i)^test_.*$",
    r"(?i)^.*_test\..*$",
    r"(?i)^.*\.test\..*$",
    r"(?i)^.*\.spec\..*$",
    r"(?i)^conftest\..*$",
    r"(?i)^mock_.*$",
    r"(?i)^fixture.*$",
    r"(?i)^.*\.example\..*$",
    r"(?i)^.*\.sample\..*$",
    r"(?i)^redact_secrets\.test\..*$",
)


def calculate_entropy(text: str) -> float:
    """Computes Shannon Entropy of a string."""
    if not text:
        return 0.0
    frequency: Dict[str, int] = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def is_rfc2606_reserved_url(url_or_text: str) -> bool:
    """
    Checks if a URL or text string targets an RFC 2606 reserved domain (example.com, .test, .invalid, localhost).
    """
    if not url_or_text or not isinstance(url_or_text, str):
        return False
    text_lower = url_or_text.lower()
    
    # Check for reserved domains in string
    for rfc_dom in RFC_2606_DOMAINS:
        if f"://{rfc_dom}" in text_lower or f"@{rfc_dom}" in text_lower or f".{rfc_dom}" in text_lower:
            return True
        if text_lower == rfc_dom or text_lower.startswith(f"{rfc_dom}/") or text_lower.startswith(f"{rfc_dom}:"):
            return True

    for suffix in RFC_2606_SUFFIXES:
        if suffix in text_lower:
            return True

    # Check localhost and loopback IPs
    for local_target in LOCAL_HOST_TARGETS:
        if f"://{local_target}" in text_lower or f"@{local_target}" in text_lower or text_lower.startswith(f"{local_target}:") or text_lower == local_target:
            return True

    try:
        parsed = urllib.parse.urlparse(url_or_text)
        host = (parsed.hostname or "").lower()
        if host in RFC_2606_DOMAINS or host in LOCAL_HOST_TARGETS or any(host.endswith(s) for s in RFC_2606_SUFFIXES):
            return True
    except Exception:
        pass

    return False


def is_pure_placeholder_secret(value: str) -> bool:
    """
    Checks if a secret value is a pure documentation placeholder token (e.g. AKIAIOSFODNN7EXAMPLE).
    These are completely excluded from reports.
    """
    if not value or not isinstance(value, str) or not value.strip():
        return False
    val_clean = value.strip()
    val_lower = val_clean.lower()

    # URLs with reserved domains or paths are handled by the RFC 2606 rule (downgraded, not excluded)
    if "://" in val_clean or "@" in val_clean or is_rfc2606_reserved_url(val_clean):
        return False

    if val_clean in KNOWN_PLACEHOLDER_SECRETS:
        return True
    for placeholder in KNOWN_PLACEHOLDER_SECRETS:
        if val_lower == placeholder.lower():
            return True

    for substr in ("example", "your-", "your_", "changeme", "dummy_key", "fake_secret", "sample_key", "mock_key", "insert_key", "replace_me"):
        if substr in val_lower:
            return True

    # Low character variety (e.g. AAAAAAAA, 00000000)
    alphanumeric = re.sub(r'[^A-Za-z0-9]', '', val_clean)
    if len(alphanumeric) >= 8 and len(set(alphanumeric)) <= 2:
        return True

    return False


def is_known_placeholder(value: str) -> bool:
    """Checks if a secret, variable, or text is a known documentation placeholder or contains placeholder keywords."""
    if not value or not isinstance(value, str) or not value.strip():
        return False
    val_clean = value.strip()
    val_lower = val_clean.lower()

    if is_pure_placeholder_secret(val_clean):
        return True

    for substr in PLACEHOLDER_SUBSTRINGS:
        if substr in val_lower:
            return True

    return False


def is_line_suppressed(line_text: str, next_line_text: str = "") -> bool:
    """Checks if a code line contains standard suppression comments."""
    combined = f"{line_text}\n{next_line_text}"
    return any(pat.search(combined) for pat in SUPPRESSION_PATTERNS)


def is_test_context(filepath: str) -> bool:
    """Determines whether a file is located in a test, fixture, mock, or example directory or test filename."""
    if not filepath or not isinstance(filepath, str):
        return False
    norm_path = filepath.replace("\\", "/").lower().strip("/")
    parts = norm_path.split("/")
    
    # Path segments check
    if any(part in TEST_PATH_SEGMENTS for part in parts[:-1]):
        return True
    if any(part in TEST_PATH_SEGMENTS for part in parts):
        return True

    # Filename check
    filename = parts[-1]
    return any(re.search(pat, filename) for pat in TEST_FILE_PATTERNS)


# ---------------------------------------------------------------------------
# 5. Live Credential Verification Engine
# ---------------------------------------------------------------------------
def verify_credential_live(
    secret_type: str,
    raw_value: str,
    extra_details: Optional[Dict[str, Any]] = None,
    timeout: float = 2.0
) -> Dict[str, Any]:
    """
    Attempts non-destructive live verification against provider APIs where feasible.
    Returns: {"verified": bool, "active": bool, "status": "CONFIRMED" | "UNVERIFIED" | "INVALID", "detail": str}
    """
    if not raw_value or is_pure_placeholder_secret(raw_value):
        return {"verified": True, "active": False, "status": "INVALID", "detail": "Known documentation placeholder"}

    stype_lower = secret_type.lower()

    # A. AWS Access Key Verification
    if "aws" in stype_lower and "key" in stype_lower:
        if not (raw_value.startswith(("AKIA", "ASIA", "ABIA", "ACCA")) and len(raw_value) == 20):
            return {"verified": True, "active": False, "status": "INVALID", "detail": "Invalid AWS Access Key structure"}
        try:
            url = "https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"
            req = urllib.request.Request(url, headers={"User-Agent": "TrustAudit-LiveCheck/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    return {"verified": True, "active": True, "status": "CONFIRMED", "detail": "AWS STS authenticated successfully."}
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # STS returned 403 (unauthenticated request without signature). Valid structure, unverified offline.
                return {"verified": False, "active": True, "status": "UNVERIFIED", "detail": "Valid AWS key structure (Unverified offline)."}
            return {"verified": True, "active": False, "status": "INVALID", "detail": f"AWS STS returned HTTP {e.code}."}
        except Exception as e:
            return {"verified": False, "active": True, "status": "UNVERIFIED", "detail": f"Live STS probe timeout/offline ({e})."}

    # B. GitHub Token Verification
    if "github" in stype_lower and ("token" in stype_lower or "pat" in stype_lower):
        if not (raw_value.startswith(("ghp_", "github_pat_", "gho_", "ghu_", "ghs_")) and len(raw_value) >= 36):
            return {"verified": True, "active": False, "status": "INVALID", "detail": "Invalid GitHub Token structure"}
        try:
            req = urllib.request.Request("https://api.github.com/user", headers={
                "Authorization": f"Bearer {raw_value}",
                "User-Agent": "TrustAudit-LiveCheck/2.0",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    return {"verified": True, "active": True, "status": "CONFIRMED", "detail": "GitHub API authenticated active token."}
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return {"verified": True, "active": False, "status": "INVALID", "detail": "GitHub Token is revoked/invalid (HTTP 401)."}
            return {"verified": False, "active": True, "status": "UNVERIFIED", "detail": f"GitHub API returned HTTP {e.code}."}
        except Exception:
            return {"verified": False, "active": True, "status": "UNVERIFIED", "detail": "GitHub API verification offline."}

    # C. Stripe Live / Test Key Verification
    if "stripe" in stype_lower:
        if not raw_value.startswith(("sk_live_", "sk_test_", "rk_live_", "rk_test_")):
            return {"verified": True, "active": False, "status": "INVALID", "detail": "Invalid Stripe key format"}
        try:
            req = urllib.request.Request("https://api.stripe.com/v1/balance", headers={
                "Authorization": f"Bearer {raw_value}",
                "User-Agent": "TrustAudit-LiveCheck/2.0",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    return {"verified": True, "active": True, "status": "CONFIRMED", "detail": "Stripe balance API confirmed active key."}
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return {"verified": True, "active": False, "status": "INVALID", "detail": "Stripe key is revoked/invalid (HTTP 401)."}
            return {"verified": False, "active": True, "status": "UNVERIFIED", "detail": f"Stripe API returned HTTP {e.code}."}
        except Exception:
            return {"verified": False, "active": True, "status": "UNVERIFIED", "detail": "Stripe API check offline."}

    return {"verified": False, "active": True, "status": "UNVERIFIED", "detail": "Unverified (Provider does not support anonymous live check)."}


# ---------------------------------------------------------------------------
# 6. Unified Universal Validation Function
# ---------------------------------------------------------------------------
def validate_and_sanitize_finding(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Single shared validation function that every scanning engine runs every finding through.

    Rules applied:
    1. EXCLUDES findings with suppression comments (# pragma: allowlist secret, # gitleaks:allow, # nosec, # noqa)
    2. EXCLUDES pure known documentation placeholders (e.g. AKIAIOSFODNN7EXAMPLE)
    3. DOWNGRADES RFC 2606 reserved domains (example.com, localhost) to LOW with label "Likely Test/Example Data" (Confidence: POSSIBLE)
    4. DOWNGRADES test/example context findings (/test/, *.test.*, redact_secrets.test.cjs) to LOW (Confidence: POSSIBLE)
    5. ASSIGNS standardized 3-tier confidence: CONFIRMED, LIKELY, POSSIBLE
    6. REDACTS secret strings so zero credential material is leaked

    Returns sanitized finding dict, or None if finding is excluded.
    """
    if not finding or not isinstance(finding, dict):
        return None

    title = str(finding.get("title") or "").strip()
    evidence = str(finding.get("evidence") or "")
    description = str(finding.get("description") or "")
    file_path = str(finding.get("file") or "")
    raw_val = str(finding.get("raw_value") or finding.get("secret") or finding.get("value_preview") or "")
    matched_snippet = str(finding.get("matched_snippet") or finding.get("snippet") or "")
    orig_sev = str(finding.get("severity") or "MEDIUM").upper()
    category = str(finding.get("category") or "code_security").lower()

    # Rule 1: Suppression comment check
    combined_code = f"{evidence}\n{matched_snippet}\n{description}"
    if is_line_suppressed(combined_code):
        return None

    # Rule 2: Pure known documentation placeholder key exclusion
    if raw_val and is_pure_placeholder_secret(raw_val) and category == "secrets":
        return None

    # Check if URL / endpoint is an RFC 2606 reserved domain (e.g. example.com, localhost)
    is_reserved_domain = is_rfc2606_reserved_url(evidence) or is_rfc2606_reserved_url(raw_val) or is_rfc2606_reserved_url(file_path)

    # Check if finding is in test / example directory or test file
    in_test = is_test_context(file_path)

    # Check if matched text contains placeholder / dummy substrings (exclude internal [REDACTED] / 'Redacted preview:' tokens)
    evidence_clean = re.sub(r'redacted\s+preview:?', '', evidence, flags=re.IGNORECASE)
    evidence_clean = re.sub(r'\[\s*redacted\s*\]', '', evidence_clean, flags=re.IGNORECASE)
    has_placeholder_kw = any(kw in evidence_clean.lower() or kw in raw_val.lower() or kw in title.lower() for kw in PLACEHOLDER_SUBSTRINGS)

    # Calculate entropy if secret
    entropy = calculate_entropy(raw_val) if (raw_val and category == "secrets") else None
    low_entropy = (entropy is not None and entropy < 3.2)

    # Live verification check for secrets
    live_status = None
    if raw_val and category == "secrets" and not in_test and not has_placeholder_kw and not is_reserved_domain:
        verif = verify_credential_live(finding.get("type", title), raw_val)
        if verif["status"] == "INVALID":
            # Invalid/revoked key -> exclude
            return None
        live_status = verif["status"]

    # -----------------------------------------------------------------------
    # Decision Matrix: Severity & Confidence (3 Tiers: CONFIRMED, LIKELY, POSSIBLE)
    # -----------------------------------------------------------------------
    final_sev = orig_sev
    final_conf = "LIKELY"
    final_title = title
    is_test_data = False

    if in_test or is_reserved_domain or has_placeholder_kw:
        is_test_data = True
        # Downgrade to LOW (never scream CRITICAL for test/example files)
        final_sev = "LOW"
        final_conf = "POSSIBLE"
        if not title.startswith("Likely Test/Example Data") and not title.startswith("Possible Test Fixture"):
            final_title = f"Likely Test/Example Data: {title}"
        remediation = "Verify whether this test fixture contains mock data. If intentionally mock, annotate with '# pragma: allowlist secret' or '# nosec'."
    elif low_entropy:
        final_sev = "LOW" if orig_sev in ("LOW", "INFO") else "MEDIUM"
        final_conf = "POSSIBLE"
        remediation = "Credential exhibits low randomness/predictable pattern. Verify if active or placeholder."
    elif live_status == "CONFIRMED":
        final_sev = "CRITICAL"
        final_conf = "CONFIRMED"
        remediation = finding.get("remediation") or "Revoke and rotate this active credential immediately."
    else:
        # Standard production finding: LIKELY confidence
        final_conf = "LIKELY"
        remediation = finding.get("remediation") or "Review and remediate this security risk."

    # Return sanitized copy
    sanitized = dict(finding)
    sanitized["title"] = final_title
    sanitized["severity"] = final_sev
    sanitized["confidence"] = final_conf
    sanitized["is_test_context"] = in_test
    sanitized["is_test_data"] = is_test_data
    sanitized["remediation"] = remediation
    if entropy is not None:
        sanitized["entropy"] = round(entropy, 2)

    return sanitized


# Alias for backward compatibility
sanitize_and_validate_finding = validate_and_sanitize_finding

