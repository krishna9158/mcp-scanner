"""
Public Exposure & Sensitive File Deep Verification Engine for TrustAudit.

Ensures zero false positives for public exposures (/.env, /.git, /backup.zip, etc.)
by rigorously validating:
1. HTTP status (200 is necessary but NOT sufficient)
2. Final URL after redirects
3. Content-Type and response size
4. HTML / SPA / Custom 404 / Error page rejection
5. Multi-signature environment variable syntax and credential verification
6. Strict confidence scoring: LOW, MEDIUM, HIGH, VERIFIED
7. Secondary verification step before creating CRITICAL findings
8. Resolution tracking: marks non-reproducible / 404 findings as Resolved
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    requests = None

# Known strong environment variable prefixes and keys
STRONG_ENV_SIGNATURES = [
    # Databases & Stores
    "DATABASE_URL", "DB_PASSWORD", "DB_PASS", "DB_HOST", "DB_USER", "DB_NAME", "DB_PORT",
    "REDIS_URL", "REDIS_PASSWORD", "REDIS_HOST", "MONGO_URI", "MONGODB_URL", "MONGODB_URI",
    "POSTGRES_PASSWORD", "POSTGRES_USER", "POSTGRES_DB", "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD",
    # Secret Keys & Tokens
    "SECRET_KEY", "DJANGO_SECRET_KEY", "APP_SECRET", "NEXTAUTH_SECRET", "JWT_SECRET", "JWT_KEY",
    "JWT_SIGNING_KEY", "ENCRYPTION_KEY", "PRIVATE_KEY", "CLIENT_SECRET", "OAUTH_CLIENT_SECRET",
    # Cloud & Provider API Keys
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION", "STRIPE_SECRET_KEY", "STRIPE_API_KEY",
    "SENDGRID_API_KEY", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ANON_KEY", "SUPABASE_URL",
    "GITHUB_TOKEN", "SLACK_BOT_TOKEN", "MAIL_PASSWORD", "TWILIO_AUTH_TOKEN", "SENTRY_DSN",
    # Framework & App Config
    "APP_ENV", "NODE_ENV", "ENVIRONMENT", "APP_DEBUG", "PORT", "SESSION_SECRET",
]

# Signatures for HTML error / SPA pages
HTML_TAG_PATTERNS = [
    r"(?i)<!doctype\s+html",
    r"(?i)<html[\s>]",
    r"(?i)<head[\s>]",
    r"(?i)<body[\s>]",
    r"(?i)<title[\s>]",
    r"(?i)<div\s+id=[\"'](?:root|__next|app|main)[\"']",
    r"(?i)<script[\s>]",
    r"(?i)<meta\s+name=",
]

CUSTOM_404_PATTERNS = [
    r"(?i)page\s+not\s+found",
    r"(?i)404\s+not\s+found",
    r"(?i)404\s+-\s+page\s+not\s+found",
    r"(?i)the\s+requested\s+url\s+(?:was\s+)?not\s+found",
    r"(?i)cannot\s+get\s+/",
    r"(?i)route\s+not\s+found",
    r"(?i)does\s+not\s+exist",
    r"(?i)access\s+denied",
    r"(?i)403\s+forbidden",
    r"(?i)unauthorized",
    r"(?i)something\s+went\s+wrong",
    r"(?i)this\s+page\s+could\s+not\s+be\s+found",
]


class ExposureVerificationResult:
    """Structured, reproducible verification result for a sensitive endpoint."""

    def __init__(
        self,
        is_exposed: bool,
        confidence: str,  # NONE, LOW, MEDIUM, HIGH, VERIFIED
        severity: str,    # CRITICAL, HIGH, MEDIUM, LOW, INFO
        requested_url: str,
        final_url: str,
        http_status: int,
        content_type: str,
        response_size: int,
        detection_indicators: List[str],
        matched_signatures: List[str],
        title: str,
        description: str,
        remediation: str,
        cwe_id: str = "CWE-552",
        owasp_category: str = "A01:2021-Broken Access Control",
        is_html_or_spa: bool = False,
        is_redirected: bool = False,
    ):
        self.is_exposed = is_exposed
        self.confidence = confidence
        self.severity = severity
        self.requested_url = requested_url
        self.final_url = final_url
        self.http_status = http_status
        self.content_type = content_type
        self.response_size = response_size
        self.detection_indicators = detection_indicators
        self.matched_signatures = matched_signatures
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        self.title = title
        self.description = description
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.owasp_category = owasp_category
        self.is_html_or_spa = is_html_or_spa
        self.is_redirected = is_redirected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_exposed": self.is_exposed,
            "confidence": self.confidence,
            "severity": self.severity,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "content_type": self.content_type,
            "response_size": self.response_size,
            "detection_indicators": self.detection_indicators,
            "matched_signatures": self.matched_signatures,
            "timestamp": self.timestamp,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "is_html_or_spa": self.is_html_or_spa,
            "is_redirected": self.is_redirected,
        }

    def to_finding_dict(self) -> Dict[str, Any]:
        evidence_summary = (
            f"GET {self.requested_url} -> HTTP {self.http_status} (Final: {self.final_url}) | "
            f"Content-Type: {self.content_type} | Size: {self.response_size}B | "
            f"Confidence: {self.confidence} | Indicators: {'; '.join(self.detection_indicators[:3])}"
        )
        return {
            "category": "exposure",
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "evidence": evidence_summary,
            "file": self.requested_url,
            "line": None,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "raw_details": self.to_dict(),
        }


def is_html_or_error_page(
    response_text: str,
    content_type: str = "",
    status_code: int = 200,
) -> Tuple[bool, List[str]]:
    """
    Determines if a response is an HTML page, SPA fallback, custom 404, or generic error template.
    """
    reasons = []
    text_sample = (response_text or "")[:100000]
    ct = (content_type or "").lower()

    if "text/html" in ct or "application/xhtml+xml" in ct:
        reasons.append(f"Content-Type is HTML ({ct})")

    # Check for HTML tag markup
    html_tag_matches = 0
    for pat in HTML_TAG_PATTERNS:
        if re.search(pat, text_sample):
            html_tag_matches += 1
    if html_tag_matches >= 2:
        reasons.append(f"Detected {html_tag_matches} HTML structural tags (e.g. <html>, <head>, <body>)")

    # Check for custom 404 / SPA error messages
    for pat in CUSTOM_404_PATTERNS:
        if re.search(pat, text_sample):
            reasons.append(f"Contains error/not-found phrasing matching pattern '{pat}'")
            break

    # Check for JSON error response
    if text_sample.strip().startswith("{") and text_sample.strip().endswith("}"):
        try:
            data = json.loads(text_sample)
            if isinstance(data, dict):
                if any(k in data for k in ("error", "statusCode", "status", "message")) and any(
                    str(v).lower() in ("not found", "404", "forbidden", "403", "unauthorized")
                    for v in data.values()
                ):
                    reasons.append("Contains JSON API error/404 response payload")
        except Exception:
            pass

    return len(reasons) > 0, reasons


def verify_env_file_exposure(
    requested_url: str,
    status_code: int,
    content_type: str,
    response_text: str,
    final_url: Optional[str] = None,
) -> ExposureVerificationResult:
    """
    Rigorously analyzes whether a response to /.env is genuine exposed environment configuration.
    Guarantees:
    - Never flags solely on HTTP 200.
    - Rejects HTML error pages and SPAs.
    - Rejects redirects to homepage or login pages.
    - Requires multiple valid KEY=VALUE lines and matched strong signatures.
    - Only HIGH / VERIFIED confidence creates CRITICAL severity.
    """
    final_url = final_url or requested_url
    ct = (content_type or "").lower()
    text = response_text or ""
    size = len(text.encode("utf-8", errors="ignore"))

    # 1. Status Code Validation
    if status_code in (404, 403, 401, 410, 500, 502, 503, 504) or status_code != 200:
        return ExposureVerificationResult(
            is_exposed=False,
            confidence="NONE",
            severity="INFO",
            requested_url=requested_url,
            final_url=final_url,
            http_status=status_code,
            content_type=ct,
            response_size=size,
            detection_indicators=[f"Endpoint returned non-exposed HTTP status {status_code}"],
            matched_signatures=[],
            title="Environment File Not Exposed",
            description=f"Endpoint {requested_url} returned HTTP {status_code}.",
            remediation="No action required.",
        )

    # 2. Redirect Inspection
    req_parsed = urlparse(requested_url)
    fin_parsed = urlparse(final_url)
    is_redirected = bool(req_parsed.path != fin_parsed.path or req_parsed.netloc != fin_parsed.netloc)
    
    if is_redirected and not fin_parsed.path.endswith(".env"):
        return ExposureVerificationResult(
            is_exposed=False,
            confidence="NONE",
            severity="INFO",
            requested_url=requested_url,
            final_url=final_url,
            http_status=status_code,
            content_type=ct,
            response_size=size,
            detection_indicators=[f"Request was redirected to non-.env URL: {final_url}"],
            matched_signatures=[],
            title="Environment File Not Exposed (Redirected)",
            description=f"Request to {requested_url} was redirected to {final_url}.",
            remediation="No action required.",
            is_redirected=True,
        )

    # 3. HTML / SPA / Custom 404 Rejection
    is_html, html_reasons = is_html_or_error_page(text, content_type=ct, status_code=status_code)
    if is_html:
        return ExposureVerificationResult(
            is_exposed=False,
            confidence="NONE",
            severity="INFO",
            requested_url=requested_url,
            final_url=final_url,
            http_status=status_code,
            content_type=ct,
            response_size=size,
            detection_indicators=[f"Rejected HTML/SPA error page: {'; '.join(html_reasons)}"],
            matched_signatures=[],
            title="Environment File Not Exposed (HTML Error/SPA Response)",
            description=f"Endpoint returned HTTP 200 but body is an HTML document or SPA fallback rather than raw .env content.",
            remediation="No action required.",
            is_html_or_spa=True,
            is_redirected=is_redirected,
        )

    # 4. Empty Response Check
    if len(text.strip()) == 0:
        return ExposureVerificationResult(
            is_exposed=False,
            confidence="NONE",
            severity="INFO",
            requested_url=requested_url,
            final_url=final_url,
            http_status=status_code,
            content_type=ct,
            response_size=0,
            detection_indicators=["Response body is completely empty (0 bytes)"],
            matched_signatures=[],
            title="Environment File Not Exposed (Empty)",
            description="Endpoint returned an empty 0-byte response.",
            remediation="No action required.",
        )

    # 5. Line-by-Line Syntax & Signature Extraction
    valid_env_lines = []
    matched_sigs = set()
    has_secret_values = False

    lines = text.splitlines()
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        # Check line matches KEY=VALUE assignment
        m = re.match(r"^([A-Za-z0-9_]{2,64})\s*=\s*(.*)$", s)
        if m:
            var_name = m.group(1).upper()
            var_val = m.group(2).strip()

            # Reject lines that look like HTML attributes or JavaScript
            if any(token in s for token in ("<", "/>", "</", "function(", "const ", "var ", "let ", "href=")):
                continue

            valid_env_lines.append(var_name)

            for sig in STRONG_ENV_SIGNATURES:
                if sig in var_name or var_name.startswith(sig):
                    matched_sigs.add(var_name)
                    # Check if value has non-empty sensitive content
                    if len(var_val) > 3 and not var_val.startswith(("<", "http://", "https://", "localhost")):
                        has_secret_values = True

    # 6. Multi-Signature Confidence Assessment
    valid_line_count = len(valid_env_lines)
    sig_count = len(matched_sigs)
    indicators = [
        f"Parsed {valid_line_count} valid KEY=VALUE assignment lines",
        f"Matched {sig_count} recognized environment variable signatures ({', '.join(list(matched_sigs)[:5])})",
    ]

    confidence = "NONE"
    severity = "INFO"
    is_exposed = False

    if valid_line_count >= 3 and sig_count >= 2:
        confidence = "VERIFIED"
        severity = "CRITICAL"
        is_exposed = True
        indicators.append("Verified raw environment file syntax with multiple high-confidence credential signatures")
    elif valid_line_count >= 2 and (sig_count >= 1 or has_secret_values):
        confidence = "HIGH"
        severity = "CRITICAL"
        is_exposed = True
        indicators.append("High confidence: valid environment file syntax with credentials detected")
    elif valid_line_count >= 2:
        confidence = "MEDIUM"
        severity = "MEDIUM"
        is_exposed = True
        indicators.append("Medium confidence: valid key-value format but only generic configuration variables present")
    elif valid_line_count == 1 and sig_count == 1:
        confidence = "LOW"
        severity = "LOW"
        is_exposed = False  # Single line alone is insufficient for confident critical alert
        indicators.append("Low confidence: only a single variable line detected (below critical threshold)")
    else:
        confidence = "NONE"
        severity = "INFO"
        is_exposed = False
        indicators.append("No valid environment variable assignments identified")

    return ExposureVerificationResult(
        is_exposed=is_exposed,
        confidence=confidence,
        severity=severity,
        requested_url=requested_url,
        final_url=final_url,
        http_status=status_code,
        content_type=ct,
        response_size=size,
        detection_indicators=indicators,
        matched_signatures=list(matched_sigs),
        title="Critical Public Exposure: .env Environment File Exposed" if is_exposed else "Environment File Not Exposed",
        description=(
            f"Production .env environment configuration file is publicly readable at {requested_url}. "
            f"Contains sensitive configurations: {', '.join(list(matched_sigs)[:4])}."
        ) if is_exposed else f"No exposed environment file detected at {requested_url}.",
        remediation="Prevent web server from serving dotfiles (.env) and move configuration secrets outside the web root.",
        cwe_id="CWE-552",
        owasp_category="A01:2021-Broken Access Control",
        is_html_or_spa=False,
        is_redirected=is_redirected,
    )


def verify_git_head_exposure(
    requested_url: str,
    status_code: int,
    content_type: str,
    response_text: str,
    final_url: Optional[str] = None,
) -> ExposureVerificationResult:
    """Verifies exposed /.git/HEAD repository metadata."""
    final_url = final_url or requested_url
    text = (response_text or "").strip()
    ct = (content_type or "").lower()
    size = len(text.encode("utf-8", errors="ignore"))

    if status_code != 200:
        return ExposureVerificationResult(
            is_exposed=False, confidence="NONE", severity="INFO",
            requested_url=requested_url, final_url=final_url, http_status=status_code,
            content_type=ct, response_size=size,
            detection_indicators=[f"HTTP status {status_code}"], matched_signatures=[],
            title="Git Repository Not Exposed", description="No git repository metadata found.", remediation="N/A",
        )

    is_html, html_reasons = is_html_or_error_page(text, content_type=ct, status_code=status_code)
    if is_html:
        return ExposureVerificationResult(
            is_exposed=False, confidence="NONE", severity="INFO",
            requested_url=requested_url, final_url=final_url, http_status=status_code,
            content_type=ct, response_size=size,
            detection_indicators=[f"Rejected HTML/SPA response: {'; '.join(html_reasons)}"], matched_signatures=[],
            title="Git Repository Not Exposed (HTML Error/SPA)", description="HTML page returned instead of Git metadata.", remediation="N/A",
            is_html_or_spa=True,
        )

    is_git_ref = bool(text.startswith("ref: refs/heads/") or text.startswith("ref: refs/tags/") or re.match(r"^[0-9a-f]{40}$", text))
    if is_git_ref and size <= 300:
        return ExposureVerificationResult(
            is_exposed=True, confidence="VERIFIED", severity="CRITICAL",
            requested_url=requested_url, final_url=final_url, http_status=status_code,
            content_type=ct, response_size=size,
            detection_indicators=[f"Verified valid Git HEAD reference: '{text[:60]}'"],
            matched_signatures=["ref: refs/"],
            title="Critical Public Exposure: .git Source Repository Exposed",
            description=f"The internal .git version control repository is publicly readable at {requested_url}.",
            remediation="Block access to all /.git paths in web server configuration immediately.",
            cwe_id="CWE-538",
        )

    return ExposureVerificationResult(
        is_exposed=False, confidence="NONE", severity="INFO",
        requested_url=requested_url, final_url=final_url, http_status=status_code,
        content_type=ct, response_size=size,
        detection_indicators=["Body does not match Git HEAD ref format"], matched_signatures=[],
        title="Git Repository Not Exposed", description="No valid git metadata detected.", remediation="N/A",
    )


def verify_sensitive_path_exposure(
    key: str,
    path: str,
    label: str,
    requested_url: str,
    session: requests.Session,
    timeout: Tuple[float, float] = (1.5, 2.5),
) -> ExposureVerificationResult:
    """
    Actively probes and verifies sensitive exposure endpoints with redirect and content-type validation.
    """
    try:
        res = session.get(requested_url, timeout=timeout, allow_redirects=True)
        final_url = res.url
        status_code = res.status_code
        ct = res.headers.get("Content-Type", "")
        text = res.text or ""

        if key == "env_file":
            # Primary verification
            ver_res = verify_env_file_exposure(
                requested_url=requested_url,
                status_code=status_code,
                content_type=ct,
                response_text=text,
                final_url=final_url,
            )
            # If suspected exposed, perform secondary confirmation probe
            if ver_res.is_exposed and ver_res.confidence in ("HIGH", "VERIFIED"):
                try:
                    conf_res = session.get(requested_url, timeout=timeout, allow_redirects=False, headers={"Cache-Control": "no-cache"})
                    if conf_res.status_code != 200:
                        ver_res.is_exposed = False
                        ver_res.confidence = "NONE"
                        ver_res.detection_indicators.append(f"Secondary confirmation probe failed (HTTP {conf_res.status_code})")
                except Exception:
                    pass
            return ver_res

        elif key == "git_head":
            return verify_git_head_exposure(
                requested_url=requested_url,
                status_code=status_code,
                content_type=ct,
                response_text=text,
                final_url=final_url,
            )

        elif key == "robots.txt":
            is_html, _ = is_html_or_error_page(text, content_type=ct)
            is_robots = status_code == 200 and not is_html and ("User-agent:" in text or "Disallow:" in text or "Allow:" in text)
            return ExposureVerificationResult(
                is_exposed=is_robots,
                confidence="VERIFIED" if is_robots else "NONE",
                severity="INFO",
                requested_url=requested_url,
                final_url=final_url,
                http_status=status_code,
                content_type=ct,
                response_size=len(text),
                detection_indicators=["Verified robots.txt syntax"] if is_robots else ["Not a valid robots.txt"],
                matched_signatures=["User-agent:"] if is_robots else [],
                title="Robots Configuration File Present",
                description="Robots.txt file found.",
                remediation="N/A",
            )

        elif key == "security.txt":
            is_html, _ = is_html_or_error_page(text, content_type=ct)
            is_sec = status_code == 200 and not is_html and ("Contact:" in text or "Expires:" in text)
            return ExposureVerificationResult(
                is_exposed=is_sec,
                confidence="VERIFIED" if is_sec else "NONE",
                severity="INFO",
                requested_url=requested_url,
                final_url=final_url,
                http_status=status_code,
                content_type=ct,
                response_size=len(text),
                detection_indicators=["Verified security.txt policy contact headers"] if is_sec else ["Not a valid security.txt"],
                matched_signatures=["Contact:"] if is_sec else [],
                title="Security Policy Contact File Present",
                description="Security.txt contact policy found.",
                remediation="N/A",
            )

        elif key == "swagger_api":
            is_html, _ = is_html_or_error_page(text, content_type=ct)
            is_swag = False
            if status_code == 200 and not is_html:
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and ("swagger" in data or "openapi" in data or "paths" in data):
                        is_swag = True
                except Exception:
                    pass
            return ExposureVerificationResult(
                is_exposed=is_swag,
                confidence="VERIFIED" if is_swag else "NONE",
                severity="LOW" if is_swag else "INFO",
                requested_url=requested_url,
                final_url=final_url,
                http_status=status_code,
                content_type=ct,
                response_size=len(text),
                detection_indicators=["Verified OpenAPI/Swagger JSON schema"] if is_swag else ["Not OpenAPI schema"],
                matched_signatures=["swagger/openapi"] if is_swag else [],
                title="Public OpenAPI / Swagger Specification Exposed" if is_swag else "Swagger Not Exposed",
                description="Interactive API definition exposed.",
                remediation="Restrict access to internal API schemas.",
            )

        elif key == "graphql_api":
            is_graphql = status_code in (200, 400) and ("Must provide an operation" in text or "GET query missing" in text or "graphql" in text.lower())
            return ExposureVerificationResult(
                is_exposed=is_graphql,
                confidence="HIGH" if is_graphql else "NONE",
                severity="LOW" if is_graphql else "INFO",
                requested_url=requested_url,
                final_url=final_url,
                http_status=status_code,
                content_type=ct,
                response_size=len(text),
                detection_indicators=["GraphQL query error response confirmed"] if is_graphql else [],
                matched_signatures=["graphql"] if is_graphql else [],
                title="GraphQL Endpoint Discovered" if is_graphql else "GraphQL Not Discovered",
                description="GraphQL endpoint active.",
                remediation="Disable introspection on public production GraphQL endpoints.",
            )

        elif key == "actuator_env":
            is_html, _ = is_html_or_error_page(text, content_type=ct)
            is_actuator = False
            if status_code == 200 and not is_html:
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and ("propertySources" in data or "activeProfiles" in data):
                        is_actuator = True
                except Exception:
                    pass
            return ExposureVerificationResult(
                is_exposed=is_actuator,
                confidence="VERIFIED" if is_actuator else "NONE",
                severity="CRITICAL" if is_actuator else "INFO",
                requested_url=requested_url,
                final_url=final_url,
                http_status=status_code,
                content_type=ct,
                response_size=len(text),
                detection_indicators=["Verified Spring Boot Actuator environment properties"] if is_actuator else [],
                matched_signatures=["propertySources"] if is_actuator else [],
                title="Exposed Spring Boot Actuator Environment" if is_actuator else "Actuator Not Exposed",
                description="Spring Boot Actuator /env endpoint is publicly accessible, leaking configuration and secret keys.",
                remediation="Restrict access to actuator endpoints or set management.endpoints.web.exposure.exclude=env.",
                cwe_id="CWE-200",
                owasp_category="A05:2021-Security Misconfiguration"
            )

        elif key == "aws_metadata":
            is_html, _ = is_html_or_error_page(text, content_type=ct)
            is_meta = status_code == 200 and not is_html and any(sig in text for sig in ("ami-id", "instance-id", "iam/", "local-ipv4"))
            return ExposureVerificationResult(
                is_exposed=is_meta,
                confidence="VERIFIED" if is_meta else "NONE",
                severity="CRITICAL" if is_meta else "INFO",
                requested_url=requested_url,
                final_url=final_url,
                http_status=status_code,
                content_type=ct,
                response_size=len(text),
                detection_indicators=["Verified AWS/Cloud Instance Metadata response"] if is_meta else [],
                matched_signatures=["ami-id/iam"] if is_meta else [],
                title="Critical Cloud Instance Metadata Service Exposed" if is_meta else "Metadata Not Exposed",
                description="Cloud instance metadata service (IMDS) is accessible, allowing attackers to steal IAM temporary credentials.",
                remediation="Enforce IMDSv2 with token hops restricted to 1, and configure reverse proxies to block /latest/meta-data/ requests.",
                cwe_id="CWE-918",
                owasp_category="A10:2021-Server-Side Request Forgery (SSRF)"
            )

        elif key == "database_dump":
            is_html, _ = is_html_or_error_page(text, content_type=ct)
            is_dump = status_code == 200 and not is_html and any(sig in text for sig in ("CREATE TABLE", "INSERT INTO `", "SQLite format 3", "-- MySQL dump"))
            return ExposureVerificationResult(
                is_exposed=is_dump,
                confidence="VERIFIED" if is_dump else "NONE",
                severity="CRITICAL" if is_dump else "INFO",
                requested_url=requested_url,
                final_url=final_url,
                http_status=status_code,
                content_type=ct,
                response_size=len(text),
                detection_indicators=["Verified database DDL/DML dump signatures"] if is_dump else [],
                matched_signatures=["CREATE TABLE/SQL"] if is_dump else [],
                title="Critical Database Dump / Backup File Exposed" if is_dump else "DB Dump Not Exposed",
                description="Raw database dump file is publicly downloadable, exposing complete database tables and customer records.",
                remediation="Remove database dump files from the public webroot immediately and store backups in encrypted private storage.",
                cwe_id="CWE-552",
                owasp_category="A01:2021-Broken Access Control"
            )

        elif key == "npm_config":
            is_html, _ = is_html_or_error_page(text, content_type=ct)
            is_npm = status_code == 200 and not is_html and ("_authToken" in text or "//registry.npmjs.org/" in text)
            return ExposureVerificationResult(
                is_exposed=is_npm,
                confidence="VERIFIED" if is_npm else "NONE",
                severity="HIGH" if is_npm else "INFO",
                requested_url=requested_url,
                final_url=final_url,
                http_status=status_code,
                content_type=ct,
                response_size=len(text),
                detection_indicators=["Verified NPM auth token syntax"] if is_npm else [],
                matched_signatures=["_authToken"] if is_npm else [],
                title="Exposed .npmrc Configuration with Auth Tokens" if is_npm else "NPM Config Not Exposed",
                description=".npmrc configuration file is publicly exposed, leaking NPM registry credentials and package publishing tokens.",
                remediation="Delete .npmrc from the public webroot and revoke any leaked registry auth tokens.",
                cwe_id="CWE-200",
                owasp_category="A05:2021-Security Misconfiguration"
            )

    except Exception as e:
        return ExposureVerificationResult(
            is_exposed=False,
            confidence="NONE",
            severity="INFO",
            requested_url=requested_url,
            final_url=requested_url,
            http_status=0,
            content_type="none",
            response_size=0,
            detection_indicators=[f"Connection failed: {str(e)}"],
            matched_signatures=[],
            title="Probe Error",
            description=str(e),
            remediation="N/A",
        )


def reconcile_resolved_exposure_findings(
    target_url: str,
    active_findings: List[Dict[str, Any]],
    historical_findings: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Compares historical exposure findings against the latest scan findings.
    If a previous scan detected an exposed file (e.g. /.env) but the latest scan confirmed 404/not exposed:
    marks it as 'Resolved / No longer reproducible' and does NOT report it as an active critical finding.
    """
    historical_findings = historical_findings or []
    current_active_keys = {
        f.get("file"): f for f in active_findings if f.get("category") == "exposure"
    }

    resolved_findings = []
    for prev in historical_findings:
        if prev.get("category") == "exposure":
            prev_file = prev.get("file")
            if prev_file and prev_file not in current_active_keys:
                # Mark as resolved
                resolved_item = dict(prev)
                resolved_item["status"] = "RESOLVED"
                resolved_item["resolution_reason"] = (
                    "Resolved / No longer reproducible: Endpoint returned HTTP 404/not-exposed in latest scan."
                )
                resolved_item["resolved_at"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
                resolved_findings.append(resolved_item)

    return active_findings, resolved_findings
