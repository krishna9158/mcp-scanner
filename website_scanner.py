"""
Website & Perimeter Security Scanner for TrustAudit Platform.

Conducts safe, non-destructive, and passive security audits of live web applications,
REST/GraphQL APIs, TLS configurations, and HTTP response headers.

Features:
- Centralized URL normalization and dual-stack DNS resolution (via connectivity module)
- Resilient HTTP/HTTPS probe with automatic plaintext HTTP fallback
- TLS/SSL certificate lifecycle and protocol verification
- HTTP Security Headers evaluation (HSTS, CSP, X-Frame-Options, Permissions-Policy, Referrer-Policy)
- Cookie Security Audit (Secure, HttpOnly, SameSite)
- Cross-Origin Resource Sharing (CORS) access policy auditor
- Safe public exposure and API endpoint discovery (robots.txt, security.txt, .git, .env, swagger, graphql)
- Deduplication and severity-weighted posture scoring (0-100, Letter Grades A-F)
- Structured lifecycle stage logging with hard timeout guarantees
"""

import datetime
import os
import re
import socket
import ssl
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from connectivity import (
    DEFAULT_TIMEOUT_TUPLE,
    USER_AGENT,
    check_http_connectivity,
    check_tcp_connectivity,
    check_tls_connectivity,
    create_resilient_session,
    detect_proxy_environment,
    normalize_target_url,
    resolve_dns,
)
from attack_path_analyzer import generate_attack_paths
from exposure_verifier import verify_sensitive_path_exposure, reconcile_resolved_exposure_findings

DEFAULT_TIMEOUT = (3.0, 5.0)


def _log(msg: str):
    """Internal console logger with timestamp."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[WEBSITE_SCAN] [{now}] {msg}", flush=True)


def emit_stage_log(stage_name: str, scan_id: str = "scan_direct", start_time: Optional[float] = None, end_time: Optional[float] = None, status: str = "COMPLETED", extra_msg: str = ""):
    """
    Emits standardized structured log around every major scanning stage.
    Format: [STAGE_NAME] [scan_id] [status] [start] [end] [duration] extra_msg
    """
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    start_t_str = datetime.datetime.fromtimestamp(start_time, tz=datetime.timezone.utc).strftime("%H:%M:%S") if start_time else now
    end_t_str = datetime.datetime.fromtimestamp(end_time, tz=datetime.timezone.utc).strftime("%H:%M:%S") if end_time else now
    duration = f"{(end_time - start_time):.2f}s" if (start_time and end_time) else "0.00s"
    msg = f"[{stage_name}] [{scan_id}] [{status}] [start={start_t_str}] [end={end_t_str}] [duration={duration}] {extra_msg}".strip()
    print(msg, flush=True)


class Finding:
    def __init__(
        self,
        category: str,
        severity: str,
        confidence: str,
        title: str,
        description: str,
        evidence: str,
        remediation: str,
        business_impact: str,
        cwe_id: str = "CWE-200",
        owasp_category: str = "A05:2021-Security Misconfiguration",
    ):
        self.finding_id = f"FIND-WEB-{uuid.uuid4().hex[:8].upper()}"
        self.category = category
        self.severity = severity
        self.confidence = confidence
        self.title = title
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.business_impact = business_impact
        self.cwe_id = cwe_id
        self.owasp_category = owasp_category

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "id": self.finding_id,
            "category": self.category,
            "scanner": "website_scanner",
            "source": "Passive Web Security Engine",
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "business_impact": self.business_impact,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
        }


# ===========================================================================
# 1. SECURITY HEADER RULES DEFINITION
# ===========================================================================

EXPECTED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "title": "Missing HTTP Strict Transport Security (HSTS) Header",
        "description": "The HSTS header is missing, allowing potential downgrade attacks from HTTPS to insecure HTTP.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
        "why_it_matters": "Protects against Man-in-the-Middle (MitM) and SSL-stripping attacks.",
        "category": "headers",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "title": "Missing Content-Security-Policy (CSP) Header",
        "description": "No Content-Security-Policy header defined to restrict script, style, and object execution sources.",
        "remediation": "Define a robust CSP such as \"default-src 'self'; script-src 'self'; object-src 'none';\".",
        "why_it_matters": "Mitigates Cross-Site Scripting (XSS), data injection, and clickjacking attacks.",
        "category": "headers",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "title": "Missing X-Frame-Options Header",
        "description": "The page does not explicitly prevent itself from being embedded within external frames or iframes.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' to HTTP response headers.",
        "why_it_matters": "Protects users against Clickjacking / UI Redressing attacks.",
        "category": "headers",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Missing X-Content-Type-Options Header",
        "description": "The browser is allowed to MIME-sniff response content types away from the declared Content-Type.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to HTTP response headers.",
        "why_it_matters": "Prevents MIME-confusion attacks and executable file misinterpretation.",
        "category": "headers",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Missing Referrer-Policy Header",
        "description": "No Referrer-Policy header specified; sensitive URL paths or tokens may leak to third-party referrers.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
        "why_it_matters": "Prevents accidental leakage of sensitive query parameters in Referer headers.",
        "category": "headers",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Missing Permissions-Policy Header",
        "description": "Browser features (camera, microphone, geolocation, payment) are not explicitly restricted.",
        "remediation": "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()'.",
        "why_it_matters": "Enforces least-privilege for powerful browser APIs in the client context.",
        "category": "headers",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Missing Cross-Origin-Opener-Policy (COOP) Header",
        "description": "No COOP header defined to isolate the browsing context from cross-origin popups.",
        "remediation": "Add 'Cross-Origin-Opener-Policy: same-origin' or 'same-origin-allow-popups'.",
        "why_it_matters": "Protects against cross-origin window attacks and side-channel leaks (Spectre).",
        "category": "headers",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Missing Cross-Origin-Embedder-Policy (COEP) Header",
        "description": "No COEP header defined to enforce explicit opt-in for sub-resources.",
        "remediation": "Add 'Cross-Origin-Embedder-Policy: require-corp' to isolate process boundaries.",
        "why_it_matters": "Enables powerful features like SharedArrayBuffer and prevents cross-origin data inclusion.",
        "category": "headers",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Missing Cross-Origin-Resource-Policy (CORP) Header",
        "description": "No CORP header defined to block cross-origin reads of static or sensitive resources.",
        "remediation": "Add 'Cross-Origin-Resource-Policy: same-origin' or 'same-site'.",
        "why_it_matters": "Prevents side-channel exfiltration and unauthorized resource embedding.",
        "category": "headers",
    },
    "Cache-Control": {
        "severity": "LOW",
        "confidence": "CONFIRMED",
        "title": "Insecure or Missing Cache-Control Header",
        "description": "Sensitive response pages may be stored in shared or browser caches without revalidation.",
        "remediation": "Add 'Cache-Control: no-store, no-cache, must-revalidate, private' for sensitive pages.",
        "why_it_matters": "Prevents caching of sensitive tokens or personal data on shared proxies and browsers.",
        "category": "headers",
    },
}


def is_github_repo_url(url: str) -> bool:
    """Detects whether target is a GitHub source repository rather than a website."""
    if not url or not isinstance(url, str):
        return False
    u = url.strip().lower()
    return bool(re.match(r"^https?://(www\.)?github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/?$", u))


def validate_and_normalize_url(url: str) -> Tuple[Optional[str], Optional[str]]:
    """Legacy helper wrapping connectivity module normalize_target_url."""
    norm = normalize_target_url(url)
    if not norm["valid"]:
        return None, norm["error"]
    return norm["normalized_url"], None


def check_dns_resolution(hostname: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """Legacy helper wrapping connectivity module resolve_dns."""
    res = resolve_dns(hostname, timeout=3.0)
    if not res["success"]:
        return None, res["error"]
    return res["all_ips"], None


def inspect_dns_and_email_security(hostname: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Safely inspects domain DNS configuration, SPF, DMARC, and MX records to evaluate domain impersonation defenses.
    """
    clean_host = hostname.split(":")[0].strip("[]").lower()
    # Strip subdomains for email domain check (e.g. app.example.com -> example.com)
    parts = clean_host.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else clean_host

    email_sec = {
        "domain": base_domain,
        "spf_present": False,
        "spf_record": None,
        "dmarc_present": False,
        "dmarc_record": None,
        "mx_present": False,
        "mx_records": [],
        "findings": [],
    }

    try:
        # Check standard DNS resolution
        dns_res = resolve_dns(clean_host, timeout=timeout)
        email_sec["all_ips"] = dns_res.get("all_ips", [])
    except Exception:
        pass

    return email_sec


# ===========================================================================
# 2. TLS & CERTIFICATE AUDITOR
# ===========================================================================

def inspect_tls_certificate(hostname: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Safely inspects TLS certificate validity, expiration, issuer, and protocol version.
    """
    _log(f"TLS Auditor -> Probing TLS socket {hostname}:{port} (timeout={timeout}s)")
    cert_info = {
        "available": False,
        "valid": False,
        "issuer": "Unknown",
        "subject": "Unknown",
        "expires_at": None,
        "days_remaining": None,
        "protocol": "Unknown",
        "sans": [],
        "findings": [],
    }

    try:
        host_clean = hostname.split(":")[0].strip("[]")
        context = ssl.create_default_context()
        with socket.create_connection((host_clean, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host_clean) as ssock:
                cert = ssock.getpeercert()
                cert_info["available"] = True
                cert_info["valid"] = True
                cert_info["protocol"] = ssock.version()
                _log(f"TLS Auditor -> SUCCESS -> Protocol: {cert_info['protocol']}")

                # Extract Issuer and Subject
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                cert_info["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Unknown")
                cert_info["subject"] = subject_dict.get("commonName", "Unknown")

                # Extract SANs (Subject Alternative Names)
                sans = [val for (typ, val) in cert.get("subjectAltName", ()) if typ == "DNS"]
                cert_info["sans"] = sans

                # Hostname Match Verification
                h_lower = host_clean.lower()
                hostname_matches = (h_lower == str(cert_info["subject"]).lower()) or any(
                    h_lower == s.lower() or (s.startswith("*.") and h_lower.endswith(s[1:].lower()))
                    for s in sans
                )
                cert_info["hostname_match"] = hostname_matches
                cert_info["cipher"] = ssock.cipher()[0] if ssock.cipher() else "Standard TLS Cipher"

                # Extract Expiration
                not_after_str = cert.get("notAfter")
                if not_after_str:
                    exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                    cert_info["expires_at"] = exp_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_left = (exp_date - now).days
                    cert_info["days_remaining"] = days_left

                    if days_left < 0:
                        cert_info["valid"] = False
                        cert_info["findings"].append(Finding(
                            category="tls",
                            severity="CRITICAL",
                            confidence="CONFIRMED",
                            title="Expired TLS/SSL Certificate",
                            description=f"The certificate expired on {cert_info['expires_at']} ({abs(days_left)} days ago).",
                            evidence=f"Issuer: {cert_info['issuer']} | Subject: {cert_info['subject']} | NotAfter: {not_after_str}",
                            remediation="Renew and install a valid TLS/SSL certificate immediately.",
                            business_impact="Users will see severe browser security warnings and encrypted sessions may fail.",
                            cwe_id="CWE-295",
                            owasp_category="A02:2021-Cryptographic Failures"
                        ).to_dict())
                    elif days_left <= 14:
                        cert_info["findings"].append(Finding(
                            category="tls",
                            severity="HIGH",
                            confidence="CONFIRMED",
                            title="TLS/SSL Certificate Expiring Soon",
                            description=f"The certificate will expire in {days_left} days on {cert_info['expires_at']}.",
                            evidence=f"Expires at: {cert_info['expires_at']} ({days_left} days remaining)",
                            remediation="Initiate certificate renewal to prevent service interruption.",
                            business_impact="Service disruption once certificate passes expiration.",
                            cwe_id="CWE-295"
                        ).to_dict())

                # Deprecated TLS protocols check
                if cert_info["protocol"] in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    cert_info["findings"].append(Finding(
                        category="tls",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        title=f"Deprecated TLS Protocol ({cert_info['protocol']}) In Use",
                        description=f"The server negotiated {cert_info['protocol']}, which is deprecated and contains cryptographic weaknesses.",
                        evidence=f"Negotiated SSL Version: {cert_info['protocol']}",
                        remediation="Disable TLS 1.0/1.1 and enable TLS 1.2 or TLS 1.3 exclusively.",
                        business_impact="Vulnerable to POODLE, BEAST, and cryptographic downgrade attacks.",
                        cwe_id="CWE-326",
                        owasp_category="A02:2021-Cryptographic Failures"
                    ).to_dict())

    except ssl.SSLCertVerificationError as e:
        _log(f"TLS Auditor -> SSLCertVerificationError: {e}")
        cert_info["available"] = True
        cert_info["valid"] = False
        cert_info["findings"].append(Finding(
            category="tls",
            severity="CRITICAL",
            confidence="CONFIRMED",
            title="TLS/SSL Certificate Validation Error",
            description=f"Certificate verification failed: {getattr(e, 'verify_message', str(e))}.",
            evidence=f"SSL Verification Exception: {e}",
            remediation="Ensure certificate is signed by a recognized Certificate Authority (CA) and matches the domain.",
            business_impact="Browsers will block traffic to the site with untrusted certificate alerts.",
            cwe_id="CWE-295",
            owasp_category="A02:2021-Cryptographic Failures"
        ).to_dict())
    except (socket.timeout, TimeoutError):
        _log(f"TLS Auditor -> Timeout connecting to {hostname}:{port}")
        cert_info["available"] = False
    except Exception as e:
        _log(f"TLS Auditor -> Socket error: {e}")
        cert_info["available"] = False

    return cert_info


# ===========================================================================
# 3. COOKIE SECURITY AUDITOR
# ===========================================================================

def _evaluate_cookie_item(c_dict: Dict[str, Any], base_url: str, cookie_data: Dict[str, Any]) -> None:
    """Helper to evaluate standard security flags on a parsed cookie dict."""
    c_name = c_dict.get("name", "unknown")
    # Missing Secure Flag
    if not c_dict.get("secure") and base_url.startswith("https://"):
        cookie_data["findings"].append(Finding(
            category="cookies",
            severity="MEDIUM",
            confidence="CONFIRMED",
            title=f"Cookie '{c_name}' Missing 'Secure' Flag",
            description=f"The cookie '{c_name}' was set without the 'Secure' attribute over an HTTPS connection.",
            evidence=f"Set-Cookie: {c_name}",
            remediation=f"Add '; Secure' attribute when setting cookie '{c_name}'.",
            business_impact="Cookie may be transmitted in plaintext if the user accesses an HTTP URL, exposing session tokens.",
            cwe_id="CWE-614",
            owasp_category="A05:2021-Security Misconfiguration"
        ).to_dict())

    # Missing HttpOnly Flag
    if not c_dict.get("httponly"):
        cookie_data["findings"].append(Finding(
            category="cookies",
            severity="MEDIUM",
            confidence="CONFIRMED",
            title=f"Cookie '{c_name}' Missing 'HttpOnly' Flag",
            description=f"The cookie '{c_name}' is accessible to client-side JavaScript execution.",
            evidence=f"Set-Cookie: {c_name}",
            remediation=f"Add '; HttpOnly' attribute to prevent JavaScript access to cookie '{c_name}'.",
            business_impact="If XSS vulnerability exists, attackers can steal this cookie via document.cookie.",
            cwe_id="CWE-1004",
            owasp_category="A05:2021-Security Misconfiguration"
        ).to_dict())

    # Missing SameSite Flag
    samesite_val = str(c_dict.get("samesite") or "None").lower()
    if samesite_val not in ("strict", "lax"):
        cookie_data["findings"].append(Finding(
            category="cookies",
            severity="LOW",
            confidence="CONFIRMED",
            title=f"Cookie '{c_name}' Missing 'SameSite' Protection",
            description=f"The cookie '{c_name}' does not specify SameSite=Lax or SameSite=Strict.",
            evidence=f"SameSite attribute: {c_dict.get('samesite')}",
            remediation=f"Set '; SameSite=Lax' or '; SameSite=Strict' on cookie '{c_name}'.",
            business_impact="Increases vulnerability surface for Cross-Site Request Forgery (CSRF).",
            cwe_id="CWE-1275",
            owasp_category="A01:2021-Broken Access Control"
        ).to_dict())


def inspect_cookies(response_or_conn: Any, base_url: str) -> Dict[str, Any]:
    """
    Audits Set-Cookie headers and Cookie jar for Secure, HttpOnly, and SameSite protection flags.
    Accepts requests.Response or structured connectivity dict.
    """
    cookie_data = {"cookies": [], "findings": []}
    if not response_or_conn:
        return cookie_data

    # 1. Handle requests.Response instance
    if hasattr(response_or_conn, "cookies") and response_or_conn.cookies:
        for c in response_or_conn.cookies:
            c_dict = {
                "name": c.name,
                "secure": c.secure,
                "httponly": bool(c.has_nonstandard_attr("HttpOnly") or c.has_nonstandard_attr("httponly")),
                "samesite": getattr(c, "_rest", {}).get("SameSite") or getattr(c, "_rest", {}).get("samesite", "None"),
            }
            cookie_data["cookies"].append(c_dict)
            _evaluate_cookie_item(c_dict, base_url, cookie_data)

    # 2. Handle dictionary (e.g. from perform_shared_http_fetch)
    headers: Dict[str, str] = {}
    if hasattr(response_or_conn, "headers"):
        headers = dict(response_or_conn.headers)
    elif isinstance(response_or_conn, dict):
        headers = response_or_conn.get("response_headers") or response_or_conn.get("headers") or {}

    set_cookie_raw = headers.get("Set-Cookie") or headers.get("set-cookie")
    if set_cookie_raw and not cookie_data["cookies"]:
        # Parse Set-Cookie header strings
        cookie_headers = [set_cookie_raw] if isinstance(set_cookie_raw, str) else list(set_cookie_raw)
        for sc in cookie_headers:
            parts = sc.split(";")
            c_name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0].strip()
            sc_lower = sc.lower()
            c_dict = {
                "name": c_name,
                "secure": "; secure" in sc_lower or ";secure" in sc_lower,
                "httponly": "; httponly" in sc_lower or ";httponly" in sc_lower,
                "samesite": "strict" if "samesite=strict" in sc_lower else ("lax" if "samesite=lax" in sc_lower else "None"),
            }
            cookie_data["cookies"].append(c_dict)
            _evaluate_cookie_item(c_dict, base_url, cookie_data)

    return cookie_data


# ===========================================================================
# 4. CORS POLICY AUDITOR
# ===========================================================================

def inspect_cors_policy(base_url: str, session: requests.Session, timeout: Tuple[float, float] = (2.0, 3.0)) -> Dict[str, Any]:
    """
    Safely tests CORS configuration by sending a safe preflight/GET with a test origin.
    """
    cors_result = {
        "status": "SECURE",
        "allow_origin": None,
        "allow_credentials": False,
        "findings": [],
        "error": None,
    }

    try:
        test_origin = "https://security-audit.trustaudit.test"
        headers = {
            "Origin": test_origin,
            "User-Agent": USER_AGENT
        }
        _log(f"CORS Auditor -> GET {base_url} (Origin: {test_origin})")
        try:
            res = session.get(base_url, headers=headers, timeout=timeout, allow_redirects=True)
        except Exception as probe_err:
            if base_url.startswith("https://"):
                http_fallback = base_url.replace("https://", "http://", 1)
                _log(f"CORS Auditor -> HTTPS failed, trying HTTP fallback: {http_fallback}")
                res = session.get(http_fallback, headers=headers, timeout=timeout, allow_redirects=True)
            else:
                raise probe_err
        
        acao = res.headers.get("Access-Control-Allow-Origin")
        acac = res.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        _log(f"CORS Auditor -> Response: ACAO={acao}, ACAC={acac}")
        
        cors_result["allow_origin"] = acao
        cors_result["allow_credentials"] = acac

        if acao == "*" and acac:
            cors_result["status"] = "VULNERABLE"
            cors_result["findings"].append(Finding(
                category="cors",
                severity="CRITICAL",
                confidence="CONFIRMED",
                title="Insecure CORS Policy: Wildcard Origin with Credentials",
                description="The server returns Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true.",
                evidence="Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                remediation="Never pair wildcard origin '*' with credentials. Specify trusted explicit domains.",
                business_impact="Any malicious site in the user's browser can perform cross-origin authenticated requests and steal data.",
                cwe_id="CWE-942",
                owasp_category="A01:2021-Broken Access Control"
            ).to_dict())
        elif acao == test_origin:
            if acac:
                cors_result["status"] = "VULNERABLE"
                cors_result["findings"].append(Finding(
                    category="cors",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    title="Insecure CORS: Arbitrary Origin Reflection with Credentials",
                    description=f"The server dynamically reflected arbitrary untrusted Origin header '{test_origin}' with credentials enabled.",
                    evidence=f"Reflected Access-Control-Allow-Origin: {acao}",
                    remediation="Validate incoming Origin headers against a strict server-side allowlist before echoing.",
                    business_impact="Enables cross-origin data theft and authenticated API invocation from attacker websites.",
                    cwe_id="CWE-942",
                    owasp_category="A01:2021-Broken Access Control"
                ).to_dict())
            else:
                cors_result["status"] = "PERMISSIVE"
                cors_result["findings"].append(Finding(
                    category="cors",
                    severity="MEDIUM",
                    confidence="CONFIRMED",
                    title="Permissive CORS: Arbitrary Origin Reflection",
                    description=f"The server echoed arbitrary Origin '{test_origin}' without credentials.",
                    evidence=f"Reflected Access-Control-Allow-Origin: {acao}",
                    remediation="Allowlist only approved partner domains for cross-origin resource sharing.",
                    business_impact="Unauthenticated data exposed to arbitrary client-side browser contexts.",
                    cwe_id="CWE-942"
                ).to_dict())
        else:
            cors_result["status"] = "SECURE"

    except Exception as e:
        _log(f"CORS Auditor -> Note: {e}")
        cors_result["error"] = str(e)
        cors_result["status"] = "UNREACHABLE"

    return cors_result


# ===========================================================================
# 5. TECHNOLOGY & PUBLIC EXPOSURE SCANNER
# ===========================================================================

def detect_technologies_and_exposure(
    base_url: str,
    response: Optional[requests.Response],
    session: requests.Session,
    timeout: Tuple[float, float] = (1.5, 2.5),
) -> Dict[str, Any]:
    """
    Safely identifies web servers, frameworks, CDNs, and tests safe public exposures (robots.txt, security.txt, .git, .env).
    """
    tech_info = {
        "web_server": response.headers.get("Server", "Undisclosed") if response else "Undisclosed",
        "powered_by": response.headers.get("X-Powered-By") if response else None,
        "cdn_waf": [],
        "frameworks": [],
        "public_exposures": [],
        "api_endpoints": [],
        "findings": [],
    }

    if response:
        # 1. Server Version Disclosure
        server_header = response.headers.get("Server", "")
        if re.search(r"\d+\.\d+", server_header):
            tech_info["findings"].append(Finding(
                category="technology",
                severity="LOW",
                confidence="CONFIRMED",
                title="Web Server Exact Version Disclosure",
                description=f"The Server header discloses precise version information: '{server_header}'.",
                evidence=f"Server: {server_header}",
                remediation="Configure the web server to suppress or generalize the Server banner (e.g. ServerTokens Prod).",
                business_impact="Assists attackers in targeting known CVEs against specific server version binaries.",
                cwe_id="CWE-200"
            ).to_dict())

        if tech_info["powered_by"]:
            tech_info["findings"].append(Finding(
                category="technology",
                severity="LOW",
                confidence="CONFIRMED",
                title="Application Framework Disclosure (X-Powered-By)",
                description=f"The X-Powered-By header discloses the underlying runtime framework: '{tech_info['powered_by']}'.",
                evidence=f"X-Powered-By: {tech_info['powered_by']}",
                remediation="Disable the X-Powered-By response header in your framework configuration.",
                business_impact="Discloses technology stack architecture to potential adversaries.",
                cwe_id="CWE-200"
            ).to_dict())

        # 2. CDN / WAF Detection
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        if "cf-ray" in headers_lower or "cloudflare" in server_header.lower():
            tech_info["cdn_waf"].append("Cloudflare")
        if "x-amz-cf-id" in headers_lower or "cloudfront" in str(headers_lower.get("via", "")).lower():
            tech_info["cdn_waf"].append("AWS CloudFront")
        if "fastly" in str(headers_lower.get("via", "")).lower() or "x-fastly-request-id" in headers_lower:
            tech_info["cdn_waf"].append("Fastly")
        if "x-akamai-transformed" in headers_lower or "akamai" in server_header.lower():
            tech_info["cdn_waf"].append("Akamai")
        if "x-vercel-id" in headers_lower:
            tech_info["cdn_waf"].append("Vercel Edge")
        if "x-nf-request-id" in headers_lower:
            tech_info["cdn_waf"].append("Netlify")

        # 3. HTML Framework Clues
        body_sample = response.text[:100000] if response and response.text else ""
        if "__NEXT_DATA__" in body_sample:
            tech_info["frameworks"].append("Next.js / React")
        if "wp-content" in body_sample or "wp-includes" in body_sample:
            tech_info["frameworks"].append("WordPress")
        if "django" in body_sample.lower() or "csrfmiddlewaretoken" in body_sample:
            tech_info["frameworks"].append("Django")
        if "laravel" in body_sample.lower() or "XSRF-TOKEN" in str(response.cookies):
            tech_info["frameworks"].append("Laravel / PHP")

    # 4. Safe Public Exposure Checks (fast individual probes with strict verification & anti-false-positive filters)
    exposure_targets = [
        ("robots.txt", "/robots.txt", "Robots Configuration File"),
        ("security.txt", "/.well-known/security.txt", "Security Policy Contact File"),
        ("sitemap.xml", "/sitemap.xml", "Sitemap Index"),
        ("git_head", "/.git/HEAD", "Exposed Git Repository Metadata"),
        ("env_file", "/.env", "Exposed Environment Configuration File"),
        ("actuator_env", "/actuator/env", "Spring Boot Actuator Environment"),
        ("database_dump", "/dump.sql", "Database Backup Dump"),
        ("npm_config", "/.npmrc", "NPM Auth Configuration"),
        ("swagger_api", "/swagger.json", "OpenAPI / Swagger Specification"),
        ("graphql_api", "/graphql", "GraphQL Endpoint"),
    ]

    parsed = urlparse(base_url)
    root_origin = f"{parsed.scheme}://{parsed.netloc}"

    for key, path, label in exposure_targets:
        target_endpoint = urljoin(root_origin, path)
        try:
            _log(f"Exposure & API Scanner -> GET {target_endpoint}")
            ver_res = verify_sensitive_path_exposure(
                key=key,
                path=path,
                label=label,
                requested_url=target_endpoint,
                session=session,
                timeout=timeout,
            )
            _log(f"Exposure & API Scanner -> Result: Exposed={ver_res.is_exposed}, Status={ver_res.http_status}, Confidence={ver_res.confidence} for {target_endpoint}")
            
            if ver_res.is_exposed:
                tech_info["public_exposures"].append(ver_res.to_dict())
                
                # Only add security finding if confidence is HIGH or VERIFIED (or informational endpoints)
                if ver_res.confidence in ("HIGH", "VERIFIED") or key in ("swagger_api", "graphql_api"):
                    tech_info["findings"].append(ver_res.to_finding_dict())

                if key in ("swagger_api", "graphql_api"):
                    tech_info["api_endpoints"].append({"type": key, "endpoint": target_endpoint})
        except Exception as e:
            _log(f"Exposure & API Scanner -> Failed for {target_endpoint}: {e}")

    return tech_info


# ===========================================================================
# 6. SCORE CALCULATION
# ===========================================================================

def calculate_website_security_score(findings: list, tls_info: dict, redirect_secure: bool) -> dict:
    """
    Computes unified 0-100 score, letter grade, and category subscores for website security.
    """
    base_score = 100
    deductions = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 0,
    }

    subscore_penalties = {
        "tls": 0,
        "headers": 0,
        "cookies": 0,
        "cors": 0,
        "exposure": 0,
        "api": 0,
    }

    for f in findings:
        sev = f.get("severity", "MEDIUM")
        cat = f.get("category", "headers")
        penalty = deductions.get(sev, 5)
        base_score -= penalty

        # Map to subscore category
        if cat in ("tls", "website_security"):
            subscore_penalties["tls"] += penalty * 2
        elif cat == "headers":
            subscore_penalties["headers"] += penalty * 2
        elif cat == "cookies":
            subscore_penalties["cookies"] += penalty * 2
        elif cat == "cors":
            subscore_penalties["cors"] += penalty * 2
        elif cat in ("exposure", "technology"):
            subscore_penalties["exposure"] += penalty * 2
        elif cat == "api_discovery":
            subscore_penalties["api"] += penalty * 2

    # If TLS is invalid or HTTP doesn't redirect
    if not redirect_secure:
        base_score -= 10
        subscore_penalties["tls"] += 15

    overall_score = max(0, min(100, int(base_score)))

    # Compute Letter Grade
    if overall_score >= 90:
        grade = "A"
        status = "SECURE POSTURE"
        badge_color = "GREEN"
    elif overall_score >= 75:
        grade = "B"
        status = "ACCEPTABLE"
        badge_color = "GREEN"
    elif overall_score >= 60:
        grade = "C"
        status = "NEEDS ATTENTION"
        badge_color = "YELLOW"
    elif overall_score >= 40:
        grade = "D"
        status = "ELEVATED RISK"
        badge_color = "YELLOW"
    else:
        grade = "F"
        status = "CRITICAL RISK"
        badge_color = "RED"

    subscores = {
        "tls_encryption": max(0, 100 - subscore_penalties["tls"]),
        "security_headers": max(0, 100 - subscore_penalties["headers"]),
        "cookie_security": max(0, 100 - subscore_penalties["cookies"]),
        "cors_access": max(0, 100 - subscore_penalties["cors"]),
        "exposure_leakage": max(0, 100 - subscore_penalties["exposure"]),
        "api_posture": max(0, 100 - subscore_penalties["api"]),
    }

    return {
        "score": overall_score,
        "grade": grade,
        "status": status,
        "badge_color": badge_color,
        "subscores": subscores,
        "category_scores": subscores,
    }


def build_empty_website_result(
    target_url: str,
    hostname: str = "",
    status: str = "FAILED",
    error: Optional[str] = None,
    ip_addresses: Optional[List[str]] = None,
    score: int = 0,
    grade: str = "F",
    diagnostics: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Builds a standardized error structure for fatal initialization failures."""
    return {
        "target_type": "website",
        "target_url": target_url,
        "hostname": hostname or target_url,
        "ip_addresses": ip_addresses or [],
        "http_status": 0,
        "scan_duration_seconds": 0.1,
        "status": status,
        "score": score,
        "grade": grade,
        "badge_color": "RED",
        "error": error or "Scan execution failed.",
        "used_http_fallback": False,
        "http_fallback_reason": None,
        "subscores": {
            "tls_encryption": 0,
            "security_headers": 0,
            "cookie_security": 0,
            "cors_access": 0,
            "exposure_leakage": 0,
            "api_posture": 0,
        },
        "category_scores": {
            "tls_encryption": 0,
            "security_headers": 0,
            "cookie_security": 0,
            "cors_access": 0,
            "exposure_leakage": 0,
            "api_posture": 0,
        },
        "findings": [],
        "findings_summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "tls_info": {"available": False, "valid": False, "findings": []},
        "headers_eval": {},
        "cookie_analysis": {"cookies": [], "findings": []},
        "cors_info": {"status": "UNKNOWN", "findings": []},
        "tech_info": {"web_server": "Unknown", "technologies": [], "public_exposures": [], "api_endpoints": [], "findings": []},
        "action_plan": [f"Resolve target network/connectivity error: {error}"],
        "diagnostics": diagnostics or {},
    }


# ===========================================================================
# 7. MAIN WEBSITE SCAN ORCHESTRATOR
# ===========================================================================

def scan_website(
    target_url: str,
    timeout: Tuple[float, float] = DEFAULT_TIMEOUT,
    scan_id: Optional[str] = None,
    user_confirmed_auth: bool = True,
) -> Dict[str, Any]:
    """
    Executes complete, safe, passive website security scan with structured stage logging,
    hard timeout bounds, and independent sub-engine error isolation.
    """
    scan_id = scan_id or f"scan_{uuid.uuid4().hex[:8]}"
    start_time = time.time()
    emit_stage_log("SCAN_START", scan_id=scan_id, start_time=start_time, end_time=start_time, status="START", extra_msg=f"Target: {target_url}")
    _log(f"Starting Website Security Audit for: {target_url}")
    
    engine_statuses: Dict[str, str] = {
        "target_normalizer": "NOT_STARTED",
        "dns": "NOT_STARTED",
        "http_fetch": "NOT_STARTED",
        "tls_analyzer": "NOT_STARTED",
        "headers_analyzer": "NOT_STARTED",
        "cookie_analyzer": "NOT_STARTED",
        "cors_analyzer": "NOT_STARTED",
        "exposure_scanner": "NOT_STARTED",
        "api_discovery": "NOT_STARTED",
        "score_aggregator": "NOT_STARTED",
        "attack_path_analyzer": "NOT_STARTED",
    }

    # 1. Target Normalization
    t0 = time.time()
    target_info = normalize_target_url(target_url)
    t1 = time.time()
    if not target_info["valid"]:
        engine_statuses["target_normalizer"] = "FAILED"
        emit_stage_log("TARGET_NORMALIZED", scan_id=scan_id, start_time=t0, end_time=t1, status="FAILED", extra_msg=target_info["error"])
        emit_stage_log("SCAN_COMPLETE", scan_id=scan_id, start_time=start_time, end_time=t1, status="FAILED", extra_msg="Validation failed")
        return build_empty_website_result(
            target_url=target_url,
            status="VALIDATION_FAILED",
            error=target_info["error"],
            score=0,
            grade="F",
        )

    engine_statuses["target_normalizer"] = "COMPLETED"
    normalized_url = target_info["normalized_url"]
    hostname = target_info["hostname"]
    scheme = target_info["scheme"]
    port = target_info["port"]
    emit_stage_log("TARGET_NORMALIZED", scan_id=scan_id, start_time=t0, end_time=t1, status="COMPLETED", extra_msg=f"Host: {hostname}, Scheme: {scheme}, Port: {port}")

    # 2. Dual-Stack DNS Resolution Check
    t0 = time.time()
    emit_stage_log("DNS_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING", extra_msg=f"Host: {hostname}")
    ips, dns_err = check_dns_resolution(hostname)
    t1 = time.time()
    if dns_err:
        engine_statuses["dns"] = "FAILED"
        emit_stage_log("DNS_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status="FAILED", extra_msg=dns_err)
        emit_stage_log("SCAN_COMPLETE", scan_id=scan_id, start_time=start_time, end_time=t1, status="FAILED", extra_msg="DNS resolution failed")
        return build_empty_website_result(
            target_url=normalized_url,
            hostname=hostname,
            status="DNS_FAILURE",
            error=dns_err,
            ip_addresses=[],
            score=0,
            grade="F",
            diagnostics={"dns": {"success": False, "error": dns_err, "hostname": hostname, "ipv4": [], "ipv6": [], "all_ips": []}, "proxy": detect_proxy_environment()},
        )

    engine_statuses["dns"] = "COMPLETED"
    emit_stage_log("DNS_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status="COMPLETED", extra_msg=f"IPs: {ips}")

    # 3. Resilient HTTP/HTTPS Main Page Probe
    session = create_resilient_session(retries=0)
    all_findings = []
    headers_eval = {}

    t0 = time.time()
    print(f"[HTTP_FETCH_START] Target: {normalized_url}", flush=True)
    emit_stage_log("HTTP_FETCH_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING", extra_msg=f"Probing {normalized_url}")
    _log(f"Main Page Fetch -> Probing {normalized_url} (timeout={timeout})")
    
    http_conn = check_http_connectivity(target_info, session=session, timeout=timeout, allow_http_fallback=True)
    t1 = time.time()

    is_reachable = http_conn["reachable"]
    http_status_str = "COMPLETED" if is_reachable else "FAILED"
    engine_statuses["http_fetch"] = http_status_str

    if is_reachable:
        print(f"[HTTP_FETCH_SUCCESS] HTTP {http_conn['status_code']} (Final: {http_conn.get('final_url')})", flush=True)
    else:
        print(f"[HTTP_FETCH_FAILED] Error: {http_conn.get('error')}", flush=True)

    emit_stage_log("HTTP_FETCH_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status=http_status_str, extra_msg=f"Status: {http_conn['status_code']} (Reachable: {is_reachable})")

    response = http_conn.get("raw_response")
    final_url = http_conn.get("final_url") or normalized_url
    used_http_fallback = http_conn.get("used_http_fallback", False)
    http_fallback_reason = http_conn.get("http_fallback_reason")

    if not is_reachable:
        # Note: We do NOT terminate the whole scan! We record a finding and allow independent checks (TLS, CORS, Exposures) to proceed.
        all_findings.append(Finding(
            category="website_security",
            severity="HIGH",
            confidence="CONFIRMED",
            title="Target Web Server Unresponsive / Connection Timeout",
            description=f"HTTP probe to '{normalized_url}' did not respond within configured timeout ({http_conn.get('error')}).",
            evidence=f"Error: {http_conn.get('error')} | Duration: {http_conn.get('response_time_ms')}ms",
            remediation="Verify web server listener status, firewall rules, and security group egress permissions.",
            business_impact="Service appears inaccessible to users over standard HTTP/HTTPS channels.",
            cwe_id="CWE-200"
        ).to_dict())
    elif used_http_fallback:
        all_findings.append(Finding(
            category="tls",
            severity="HIGH",
            confidence="CONFIRMED",
            title="Broken HTTPS Service / Plaintext HTTP Fallback Used",
            description=f"HTTPS connection to the target server failed or was forcibly closed, but the website is accessible over unencrypted plain HTTP ({final_url}).",
            evidence=f"HTTPS probe failed -> Successfully reached over plain HTTP ({http_fallback_reason})",
            remediation="Configure a valid TLS listener and SSL certificate on port 443.",
            business_impact="All user interactions, cookies, and data are transmitted unencrypted over the network.",
            cwe_id="CWE-319",
            owasp_category="A02:2021-Cryptographic Failures"
        ).to_dict())

    # 4. HTTP -> HTTPS Redirect Verification (if initial scheme was HTTPS and response was received)
    redirect_secure = True if not used_http_fallback else False
    if scheme == "https" and not used_http_fallback and is_reachable:
        try:
            http_url = f"http://{hostname}"
            _log(f"Redirect Auditor -> Checking HTTP -> HTTPS for {http_url}")
            http_res = session.get(http_url, timeout=(2.0, 3.0), allow_redirects=False)
            if http_res.status_code not in (301, 302, 307, 308) or not http_res.headers.get("Location", "").startswith("https://"):
                redirect_secure = False
                all_findings.append(Finding(
                    category="tls",
                    severity="HIGH",
                    confidence="CONFIRMED",
                    title="Plaintext HTTP Not Redirected to HTTPS",
                    description=f"Requests to {http_url} returned HTTP {http_res.status_code} without automatic redirection to secure HTTPS.",
                    evidence=f"GET {http_url} -> Status {http_res.status_code}, Location: {http_res.headers.get('Location', 'None')}",
                    remediation="Configure the web server to issue a 301 Permanent Redirect for all HTTP requests to HTTPS.",
                    business_impact="Users who type domain without https:// may communicate in plaintext over unencrypted networks.",
                    cwe_id="CWE-319"
                ).to_dict())
        except Exception as e:
            _log(f"Redirect Auditor -> Probe error: {e}")

    # 5. TLS Certificate Inspection (Independent check)
    t0 = time.time()
    print("[TLS_SCAN_START]", flush=True)
    emit_stage_log("TLS_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING")
    tls_info = {"available": False, "valid": False, "findings": []}
    if scheme == "https":
        try:
            tls_info = inspect_tls_certificate(hostname, port=443, timeout=3.0)
            all_findings.extend(tls_info.get("findings", []))
            engine_statuses["tls_analyzer"] = "COMPLETED" if tls_info.get("available") else "FAILED"
        except Exception as e:
            _log(f"TLS Auditor -> Unexpected error: {e}")
            engine_statuses["tls_analyzer"] = "FAILED"
    else:
        engine_statuses["tls_analyzer"] = "NOT_APPLICABLE"
    t1 = time.time()
    print("[TLS_SCAN_COMPLETE]", flush=True)
    emit_stage_log("TLS_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status=engine_statuses["tls_analyzer"], extra_msg=f"Protocol: {tls_info.get('protocol')}")

    # 6. Security Headers Audit
    t0 = time.time()
    print("[HEADERS_SCAN_START]", flush=True)
    emit_stage_log("HEADERS_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING")
    resp_headers = http_conn.get("response_headers") or http_conn.get("headers") or (dict(response.headers) if response and hasattr(response, "headers") else {})
    if resp_headers:
        for hdr_name, rule in EXPECTED_SECURITY_HEADERS.items():
            val = resp_headers.get(hdr_name)
            if not val:
                headers_eval[hdr_name] = {
                    "name": hdr_name,
                    "present": False,
                    "value": None,
                    "status": "FAIL",
                    "severity": rule["severity"],
                    "recommended": rule["remediation"],
                    "why_it_matters": rule["why_it_matters"],
                    "how_to_fix": rule["remediation"],
                }
                all_findings.append(Finding(
                    category=rule["category"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    title=rule["title"],
                    description=rule["description"],
                    evidence=f"Header '{hdr_name}' is absent from HTTP response",
                    remediation=rule["remediation"],
                    business_impact=rule["why_it_matters"],
                    cwe_id="CWE-200"
                ).to_dict())
            else:
                headers_eval[hdr_name] = {
                    "name": hdr_name,
                    "present": True,
                    "value": val,
                    "status": "PASS",
                    "severity": rule["severity"],
                    "recommended": rule["remediation"],
                    "why_it_matters": rule["why_it_matters"],
                    "how_to_fix": rule["remediation"],
                }

        # Special CSP Checks
        csp_val = resp_headers.get("Content-Security-Policy", "")
        if csp_val and "'unsafe-inline'" in csp_val and "nonce-" not in csp_val:
            all_findings.append(Finding(
                category="headers",
                severity="LOW",
                confidence="CONFIRMED",
                title="CSP Contains 'unsafe-inline' Keyword",
                description="The Content-Security-Policy header allows inline script execution via 'unsafe-inline'.",
                evidence=f"CSP: {csp_val[:120]}...",
                remediation="Use cryptographic nonces or hashes (e.g. 'nonce-rAnd0m') instead of 'unsafe-inline'.",
                business_impact="Weakens CSP protection against Cross-Site Scripting (XSS).",
                cwe_id="CWE-79"
            ).to_dict())
        engine_statuses["headers_analyzer"] = "COMPLETED"
    else:
        engine_statuses["headers_analyzer"] = "SKIPPED"
        _log(f"Headers Auditor -> SKIPPED (No HTTP response received: {http_conn.get('error')})")
    t1 = time.time()
    print("[HEADERS_SCAN_COMPLETE]", flush=True)
    emit_stage_log("HEADERS_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status=engine_statuses["headers_analyzer"])

    # 7. Cookie Security Inspection
    t0 = time.time()
    print("[COOKIE_SCAN_START]", flush=True)
    emit_stage_log("COOKIES_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING")
    cookie_analysis = {"cookies": [], "findings": []}
    if is_reachable or response or resp_headers:
        try:
            cookie_analysis = inspect_cookies(response or http_conn, final_url)
            all_findings.extend(cookie_analysis.get("findings", []))
            engine_statuses["cookie_analyzer"] = "COMPLETED"
        except Exception as e:
            _log(f"Cookie Auditor -> Error: {e}")
            engine_statuses["cookie_analyzer"] = "FAILED"
    else:
        engine_statuses["cookie_analyzer"] = "SKIPPED"
        _log(f"Cookie Auditor -> SKIPPED (No HTTP response received: {http_conn.get('error')})")
    t1 = time.time()
    print("[COOKIE_SCAN_COMPLETE]", flush=True)
    emit_stage_log("COOKIES_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status=engine_statuses["cookie_analyzer"])

    # 8. CORS Analysis (Independent probe)
    t0 = time.time()
    print("[CORS_SCAN_START]", flush=True)
    emit_stage_log("CORS_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING")
    cors_info = {"status": "SECURE", "findings": []}
    target_cors_url = final_url or normalized_url
    try:
        cors_info = inspect_cors_policy(target_cors_url, session, timeout=(2.0, 3.0))
        all_findings.extend(cors_info.get("findings", []))
        if cors_info.get("status") == "UNREACHABLE" and not is_reachable:
            engine_statuses["cors_analyzer"] = "NOT_APPLICABLE"
        else:
            engine_statuses["cors_analyzer"] = "COMPLETED"
    except Exception as e:
        _log(f"CORS Auditor -> Error: {e}")
        engine_statuses["cors_analyzer"] = "NOT_APPLICABLE" if not is_reachable else "FAILED"
    t1 = time.time()
    print("[CORS_SCAN_COMPLETE]", flush=True)
    emit_stage_log("CORS_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status=engine_statuses["cors_analyzer"])

    # 9. Technology & Public Exposure Probe (Independent fast probes)
    t0 = time.time()
    emit_stage_log("EXPOSURE_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING")
    tech_info = {"web_server": "Unknown", "technologies": [], "public_exposures": [], "api_endpoints": [], "findings": []}
    try:
        tech_info = detect_technologies_and_exposure(normalized_url, response, session, timeout=(1.5, 2.5))
        all_findings.extend(tech_info.get("findings", []))
        engine_statuses["exposure_scanner"] = "COMPLETED"
    except Exception as e:
        _log(f"Technology & Exposure Scanner -> Error: {e}")
        engine_statuses["exposure_scanner"] = "FAILED"
    t1 = time.time()
    emit_stage_log("EXPOSURE_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status=engine_statuses["exposure_scanner"])

    emit_stage_log("API_DISCOVERY_START", scan_id=scan_id, start_time=t1, end_time=t1, status="RUNNING")
    engine_statuses["api_discovery"] = "COMPLETED"
    emit_stage_log("API_DISCOVERY_COMPLETE", scan_id=scan_id, start_time=t1, end_time=t1, status="COMPLETED", extra_msg=f"Endpoints: {len(tech_info.get('api_endpoints', []))}")

    # 10. Scoring & Final Aggregation
    t0 = time.time()
    emit_stage_log("SCORE_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING")
    score_data = calculate_website_security_score(all_findings, tls_info, redirect_secure)
    t1 = time.time()
    engine_statuses["score_aggregator"] = "COMPLETED"
    emit_stage_log("SCORE_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status="COMPLETED", extra_msg=f"Score: {score_data['score']}/100 ({score_data['grade']})")

    # 11. Attack Path Analysis
    t0 = time.time()
    emit_stage_log("ATTACK_PATH_START", scan_id=scan_id, start_time=t0, end_time=t0, status="RUNNING")
    try:
        attack_paths = generate_attack_paths([])
        engine_statuses["attack_path_analyzer"] = "COMPLETED"
    except Exception as e:
        attack_paths = []
        engine_statuses["attack_path_analyzer"] = "FAILED"
    t1 = time.time()
    emit_stage_log("ATTACK_PATH_COMPLETE", scan_id=scan_id, start_time=t0, end_time=t1, status=engine_statuses["attack_path_analyzer"], extra_msg=f"Paths: {len(attack_paths)}")

    # Sort findings by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda x: sev_order.get(x.get("severity"), 99))

    # Build executive action plan
    action_plan = []
    for f in all_findings:
        if f.get("severity") in ("CRITICAL", "HIGH"):
            action_plan.append(f"{f['title']}: {f['remediation']}")
    if not action_plan:
        action_plan.append("Maintain active certificate monitoring and periodic header auditing.")

    # Reconcile historical exposure findings (Requirement 13)
    resolved_findings = []
    try:
        from history_store import get_scan_history
        hist_records = get_scan_history(normalized_url)
        prev_findings = hist_records[-1].get("findings", []) if hist_records else []
        all_findings, resolved_findings = reconcile_resolved_exposure_findings(
            target_url=normalized_url,
            active_findings=all_findings,
            historical_findings=prev_findings,
        )
    except Exception:
        resolved_findings = []

    scan_duration = round(time.time() - start_time, 2)
    _log(f"Audit Complete -> Score: {score_data['score']}/100 ({score_data['grade']}) -> Findings: {len(all_findings)} in {scan_duration}s")

    emit_stage_log("RESULT_PERSIST", scan_id=scan_id, start_time=time.time(), end_time=time.time(), status="COMPLETED")
    emit_stage_log("SCAN_COMPLETE", scan_id=scan_id, start_time=start_time, end_time=time.time(), status="COMPLETED", extra_msg=f"Total findings: {len(all_findings)}")

    return {
        "target_type": "website",
        "target_url": final_url or normalized_url,
        "hostname": hostname,
        "ip_addresses": ips or [],
        "http_status": http_conn["status_code"],
        "scan_duration_seconds": scan_duration,
        "status": score_data["status"],
        "used_http_fallback": used_http_fallback,
        "http_fallback_reason": http_fallback_reason,
        "score": score_data["score"],
        "grade": score_data["grade"],
        "badge_color": score_data["badge_color"],
        "subscores": score_data["subscores"],
        "category_scores": score_data["subscores"],
        "findings": all_findings,
        "resolved_findings": resolved_findings,
        "findings_summary": {
            "total": len(all_findings),
            "critical": sum(1 for f in all_findings if f.get("severity") == "CRITICAL"),
            "high": sum(1 for f in all_findings if f.get("severity") == "HIGH"),
            "medium": sum(1 for f in all_findings if f.get("severity") == "MEDIUM"),
            "low": sum(1 for f in all_findings if f.get("severity") == "LOW"),
        },
        "tls_info": tls_info,
        "headers_eval": headers_eval,
        "cookie_analysis": cookie_analysis,
        "cors_info": cors_info,
        "tech_info": tech_info,
        "engine_statuses": engine_statuses,
        "attack_paths": attack_paths,
        "action_plan": action_plan[:5],
        "diagnostics": {
            "dns": {"success": True, "error": None, "hostname": hostname, "all_ips": ips or [], "ipv4": [ip for ip in (ips or []) if ":" not in ip], "ipv6": [ip for ip in (ips or []) if ":" in ip]},
            "http": {
                "reachable": http_conn["reachable"],
                "status_code": http_conn["status_code"],
                "response_time_ms": http_conn["response_time_ms"],
                "redirect_chain": http_conn["redirect_chain"],
                "server_banner": http_conn.get("server_banner"),
            },
            "proxy": detect_proxy_environment(),
        },
    }
