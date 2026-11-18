"""
Target Connectivity and Diagnostics Module for TrustAudit Security Platform.

Provides unified, production-grade target normalization, dual-stack DNS resolution (IPv4 & IPv6),
TCP port probing, TLS handshake verification, resilient HTTP/HTTPS probing with redirect tracking,
proxy environment detection, and comprehensive diagnostic telemetry.
"""

import os
import re
import socket
import ssl
import time
from typing import Dict, List, Any, Optional, Tuple, Union
from urllib.parse import urlparse, urlunparse, urljoin
import requests
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

USER_AGENT = "TrustAudit-Security-Scanner/2.0 (+https://github.com/mcp-scanner; safe passive audit)"
CONNECT_TIMEOUT = float(os.environ.get("TRUSTAUDIT_CONNECT_TIMEOUT", "10.0"))
READ_TIMEOUT = float(os.environ.get("TRUSTAUDIT_READ_TIMEOUT", "30.0"))
TOTAL_TIMEOUT = float(os.environ.get("TRUSTAUDIT_TOTAL_TIMEOUT", "60.0"))
MAX_RETRIES = int(os.environ.get("TRUSTAUDIT_MAX_RETRIES", "2"))

DEFAULT_CONNECT_TIMEOUT = CONNECT_TIMEOUT
DEFAULT_READ_TIMEOUT = READ_TIMEOUT
DEFAULT_TIMEOUT_TUPLE: Tuple[float, float] = (CONNECT_TIMEOUT, READ_TIMEOUT)
DEFAULT_CONNECTIVITY_TIMEOUT = TOTAL_TIMEOUT
MAX_REDIRECTS = 5


# ===========================================================================
# 1. ROBUST TARGET NORMALIZER
# ===========================================================================

def normalize_target_url(raw_target: str) -> Dict[str, Any]:
    """
    Normalizes arbitrary target input (e.g. 'example.com', 'https://example.com/api?v=1',
    'www.example.com', 'http://127.0.0.1:8080/path') into structured target metadata.
    
    Returns:
    {
        "valid": bool,
        "original": str,
        "normalized_url": str,
        "scheme": str,
        "hostname": str,
        "port": int,
        "path": str,
        "query": str,
        "error": Optional[str]
    }
    """
    if not raw_target or not isinstance(raw_target, str):
        return {
            "valid": False,
            "original": str(raw_target or ""),
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "port": 0,
            "path": "/",
            "query": "",
            "error": "Target URL cannot be empty.",
        }

    clean = raw_target.strip()
    if not clean:
        return {
            "valid": False,
            "original": raw_target,
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "port": 0,
            "path": "/",
            "query": "",
            "error": "Target URL cannot be empty or whitespace.",
        }

    # Add default scheme if missing
    has_scheme = bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', clean))
    if not has_scheme:
        clean = "https://" + clean

    try:
        parsed = urlparse(clean)
    except Exception as e:
        return {
            "valid": False,
            "original": raw_target,
            "normalized_url": "",
            "scheme": "",
            "hostname": "",
            "port": 0,
            "path": "/",
            "query": "",
            "error": f"URL parse error: {e}",
        }

    scheme = (parsed.scheme or "https").lower()
    if scheme not in ("http", "https"):
        return {
            "valid": False,
            "original": raw_target,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": "",
            "port": 0,
            "path": "/",
            "query": "",
            "error": f"Unsupported URL scheme '{scheme}'. Only http:// and https:// are supported.",
        }

    netloc = parsed.netloc or ""
    if not netloc:
        return {
            "valid": False,
            "original": raw_target,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": "",
            "port": 0,
            "path": "/",
            "query": "",
            "error": "Invalid URL: Missing hostname / network location.",
        }

    # Extract hostname and port safely (including IPv6 [::1]:8080 support)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)

    if not hostname:
        # Fallback for complex netlocs
        host_part = netloc.split(":")[0] if ":" in netloc and not netloc.startswith("[") else netloc
        hostname = host_part.strip("[]")

    hostname_clean = hostname.strip().lower()

    # Hostname validation
    if not hostname_clean:
        return {
            "valid": False,
            "original": raw_target,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": "",
            "port": 0,
            "path": "/",
            "query": "",
            "error": "Invalid hostname: empty host.",
        }

    # Must contain dot (e.g. example.com), or be localhost or valid IP
    is_localhost = hostname_clean == "localhost"
    is_ip = False
    try:
        socket.inet_aton(hostname_clean)
        is_ip = True
    except socket.error:
        pass
    if not is_ip and ":" in hostname_clean:
        # IPv6
        is_ip = True

    if not is_localhost and not is_ip and "." not in hostname_clean:
        return {
            "valid": False,
            "original": raw_target,
            "normalized_url": "",
            "scheme": scheme,
            "hostname": hostname_clean,
            "port": port,
            "path": "/",
            "query": "",
            "error": f"Invalid domain '{hostname_clean}'. Hostname must be a valid domain, IP address, or localhost.",
        }

    path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path

    query = parsed.query or ""

    # Build canonical normalized URL
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        canonical_netloc = hostname_clean
    else:
        canonical_netloc = f"{hostname_clean}:{port}"

    canonical_url = f"{scheme}://{canonical_netloc}{path}"
    if query:
        canonical_url += f"?{query}"

    return {
        "valid": True,
        "original": raw_target,
        "normalized_url": canonical_url,
        "scheme": scheme,
        "hostname": hostname_clean,
        "port": port,
        "path": path,
        "query": query,
        "error": None,
    }


# ===========================================================================
# 2. DEDICATED DNS RESOLUTION (IPv4 & IPv6)
# ===========================================================================

def resolve_dns(hostname: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Performs robust dual-stack DNS resolution for a hostname.
    Extracts IPv4 (A records) and IPv6 (AAAA records) separately, deduplicating results.
    Never crashes, catches socket.gaierror and socket.herror cleanly.
    
    Returns:
    {
        "success": bool,
        "hostname": str,
        "ipv4": List[str],
        "ipv6": List[str],
        "all_ips": List[str],
        "duration_ms": float,
        "error": Optional[str]
    }
    """
    t0 = time.time()
    clean_host = hostname.strip().split(":")[0].strip("[]")
    
    ipv4_list: List[str] = []
    ipv6_list: List[str] = []
    error_msg: Optional[str] = None

    try:
        # socket.getaddrinfo handles dual-stack DNS lookup
        addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for item in addr_info:
            family, socktype, proto, canonname, sockaddr = item
            ip_addr = sockaddr[0]
            if family == socket.AF_INET:
                if ip_addr not in ipv4_list:
                    ipv4_list.append(ip_addr)
            elif family == socket.AF_INET6:
                if ip_addr not in ipv6_list:
                    ipv6_list.append(ip_addr)

        if not ipv4_list and not ipv6_list:
            error_msg = f"DNS lookup succeeded but returned no IPv4 or IPv6 records for '{clean_host}'."

    except socket.gaierror as e:
        errno_val = getattr(e, "errno", None)
        if errno_val == 11001 or "getaddrinfo failed" in str(e):
            error_msg = f"DNS resolution failed for '{clean_host}': Host not found in DNS (WSAHOST_NOT_FOUND)."
        elif errno_val == 11002:
            error_msg = f"DNS resolution temporary failure for '{clean_host}': Try again later (WSATRY_AGAIN)."
        elif errno_val == 11004:
            error_msg = f"DNS name '{clean_host}' exists but has no IP address records (WSANO_DATA)."
        else:
            error_msg = f"DNS resolution failed for '{clean_host}': {e}"
    except Exception as e:
        error_msg = f"DNS lookup error for '{clean_host}': {type(e).__name__}: {e}"

    duration_ms = round((time.time() - t0) * 1000, 2)
    all_ips = ipv4_list + ipv6_list
    success = bool(all_ips and not error_msg)

    return {
        "success": success,
        "hostname": clean_host,
        "ipv4": ipv4_list,
        "ipv6": ipv6_list,
        "all_ips": all_ips,
        "duration_ms": duration_ms,
        "error": error_msg,
    }


# ===========================================================================
# 3. PROXY ENVIRONMENT DETECTION
# ===========================================================================

def detect_proxy_environment() -> Dict[str, Any]:
    """
    Inspects environment variables for proxy configurations without exposing credentials.
    Detects HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY.
    """
    def sanitize_proxy_url(val: Optional[str]) -> Optional[str]:
        if not val:
            return None
        # Redact password if present: http://user:pass@proxy.host:8080 -> http://user:***@proxy.host:8080
        return re.sub(r'://([^:]+):([^@]+)@', r'://\1:***@', str(val))

    http_p = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    https_p = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    all_p = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")
    no_p = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")

    has_proxy = bool(http_p or https_p or all_p)

    return {
        "has_proxy": has_proxy,
        "http_proxy": sanitize_proxy_url(http_p),
        "https_proxy": sanitize_proxy_url(https_p),
        "all_proxy": sanitize_proxy_url(all_p),
        "no_proxy": no_p,
    }


# ===========================================================================
# 4. TCP SOCKET CONNECTIVITY CHECK
# ===========================================================================

def check_tcp_connectivity(hostname: str, port: int, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Tests raw TCP socket connection to hostname:port.
    """
    t0 = time.time()
    clean_host = hostname.strip().split(":")[0].strip("[]")
    
    try:
        sock = socket.create_connection((clean_host, port), timeout=timeout)
        sock.close()
        duration_ms = round((time.time() - t0) * 1000, 2)
        return {
            "success": True,
            "hostname": clean_host,
            "port": port,
            "duration_ms": duration_ms,
            "error": None,
        }
    except socket.timeout:
        return {
            "success": False,
            "hostname": clean_host,
            "port": port,
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "error": f"TCP connection to {clean_host}:{port} timed out after {timeout}s.",
        }
    except Exception as e:
        return {
            "success": False,
            "hostname": clean_host,
            "port": port,
            "duration_ms": round((time.time() - t0) * 1000, 2),
            "error": f"TCP connection to {clean_host}:{port} failed: {e}",
        }


# ===========================================================================
# 5. TLS HANDSHAKE CHECK
# ===========================================================================

def check_tls_connectivity(hostname: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Performs safe TLS handshake and returns protocol version, certificate validity, and expiration.
    """
    t0 = time.time()
    clean_host = hostname.strip().split(":")[0].strip("[]")

    result = {
        "success": False,
        "hostname": clean_host,
        "port": port,
        "protocol": None,
        "valid_cert": False,
        "issuer": None,
        "subject": None,
        "days_remaining": None,
        "duration_ms": 0.0,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((clean_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                result["success"] = True
                result["valid_cert"] = True
                result["protocol"] = ssock.version()

                # Extract Issuer and Subject
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                result["issuer"] = issuer_dict.get("organizationName") or issuer_dict.get("commonName", "Unknown")
                result["subject"] = subject_dict.get("commonName", "Unknown")

                not_after_str = cert.get("notAfter")
                if not_after_str:
                    import datetime
                    exp_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                    now = datetime.datetime.now(datetime.timezone.utc)
                    result["days_remaining"] = (exp_date - now).days

    except ssl.SSLCertVerificationError as e:
        result["success"] = True  # TLS is open, but cert invalid
        result["valid_cert"] = False
        result["error"] = f"Certificate verification failed: {getattr(e, 'verify_message', str(e))}"
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)

    result["duration_ms"] = round((time.time() - t0) * 1000, 2)
    return result


# ===========================================================================
# 6. HTTP / HTTPS RESILIENT PROBE & FALLBACK
# ===========================================================================

def create_resilient_session(
    retries: int = 1,
    backoff_factor: float = 0.1,
    status_forcelist: Tuple[int, ...] = (429, 500, 502, 503, 504),
) -> requests.Session:
    """
    Constructs a requests Session equipped with urllib3 Retry adapter
    and standardized TrustAudit headers across all outbound requests.
    Fast-failing retry parameters prevent hung connections on non-responsive ports.
    """
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    retry_strategy = Retry(
        total=retries,
        connect=retries,
        read=0,  # Do not loop on socket read hangs
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def check_http_connectivity(
    target_info: Dict[str, Any],
    session: Optional[requests.Session] = None,
    timeout: Union[float, Tuple[float, float]] = DEFAULT_TIMEOUT_TUPLE,
    allow_http_fallback: bool = True,
) -> Dict[str, Any]:
    """
    Executes HTTP/HTTPS probe with redirect tracing, TLS verification, response timing,
    and automatic HTTP fallback if HTTPS fails with a connection/SSL/timeout error.
    
    IMPORTANT: HTTP status codes (200, 301, 401, 403, 404, 500, 503) indicate
    that the server IS REACHABLE. They are NOT connection failures.
    """
    t0 = time.time()
    active_session = session or create_resilient_session(retries=0)
    
    normalized_url = target_info.get("normalized_url") or target_info.get("original")
    scheme = target_info.get("scheme", "https")
    hostname = target_info.get("hostname", "")

    req_timeout = timeout if isinstance(timeout, (tuple, list, float, int)) else DEFAULT_TIMEOUT_TUPLE

    result: Dict[str, Any] = {
        "success": False,
        "reachable": False,
        "status_code": 0,
        "initial_url": normalized_url,
        "final_url": normalized_url,
        "redirect_chain": [],
        "response_time_ms": 0.0,
        "headers": {},
        "cookies": [],
        "used_http_fallback": False,
        "http_fallback_reason": None,
        "server_banner": None,
        "error": None,
        "error_type": None,
        "raw_response": None,
    }

    try:
        resp = active_session.get(normalized_url, timeout=req_timeout, allow_redirects=True)
        result["success"] = True
        result["reachable"] = True
        result["status_code"] = resp.status_code
        result["final_url"] = resp.url
        result["headers"] = dict(resp.headers)
        result["server_banner"] = resp.headers.get("Server")
        result["cookies"] = [c.name for c in resp.cookies]
        result["raw_response"] = resp

        if resp.history:
            result["redirect_chain"] = [
                {"url": r.url, "status_code": r.status_code, "location": r.headers.get("Location")}
                for r in resp.history
            ]

    except requests.exceptions.TooManyRedirects as redir_err:
        result["reachable"] = False
        result["error_type"] = "TOO_MANY_REDIRECTS"
        result["error"] = f"Too many redirects encountered connecting to '{hostname}': {redir_err}"
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.SSLError) as conn_err:
        err_type = "TIMEOUT" if isinstance(conn_err, requests.exceptions.Timeout) else ("SSL_ERROR" if isinstance(conn_err, requests.exceptions.SSLError) else "CONNECTION_ERROR")
        if scheme == "https" and allow_http_fallback:
            http_fallback_url = normalized_url.replace("https://", "http://", 1)
            try:
                fallback_resp = active_session.get(http_fallback_url, timeout=req_timeout, allow_redirects=True)
                result["success"] = True
                result["reachable"] = True
                result["status_code"] = fallback_resp.status_code
                result["final_url"] = fallback_resp.url
                result["headers"] = dict(fallback_resp.headers)
                result["server_banner"] = fallback_resp.headers.get("Server")
                result["cookies"] = [c.name for c in fallback_resp.cookies]
                result["used_http_fallback"] = True
                result["http_fallback_reason"] = f"HTTPS connection failed ({err_type}: {conn_err}). Reached over plain HTTP."
                result["raw_response"] = fallback_resp

                if fallback_resp.history:
                    result["redirect_chain"] = [
                        {"url": r.url, "status_code": r.status_code, "location": r.headers.get("Location")}
                        for r in fallback_resp.history
                    ]
            except Exception as http_fallback_err:
                result["reachable"] = False
                result["error_type"] = err_type
                result["error"] = (
                    f"Target host '{hostname}' unreachable on both HTTPS (port 443) and HTTP (port 80): "
                    f"HTTPS error ({conn_err}), HTTP fallback error ({http_fallback_err})."
                )
        else:
            result["reachable"] = False
            result["error_type"] = err_type
            result["error"] = f"Could not connect to target server '{hostname}': {conn_err}"
    except Exception as e:
        result["reachable"] = False
        result["error_type"] = "UNEXPECTED_ERROR"
        result["error"] = f"Unexpected connectivity error for '{hostname}': {type(e).__name__}: {e}"

    result["response_time_ms"] = round((time.time() - t0) * 1000, 2)
    return result


def perform_shared_http_fetch(
    target: str,
    session: Optional[requests.Session] = None,
    timeout: Union[float, Tuple[float, float]] = DEFAULT_TIMEOUT_TUPLE,
    allow_http_fallback: bool = True,
) -> Dict[str, Any]:
    """
    Unified Shared HTTP/HTTPS Fetch Engine for TrustAudit Passive Analyzers.
    
    Executes DNS resolution, TCP handshake, TLS verification, and HTTP fetch in one
    coherent pass, returning a rich structured context used by Headers, Cookies, CORS,
    Exposure, and Technology discovery scanners.
    """
    target_info = normalize_target_url(target)
    if not target_info["valid"]:
        return {
            "reachable": False,
            "url": target,
            "final_url": target,
            "status_code": 0,
            "scheme": "",
            "hostname": "",
            "port": 0,
            "response_headers": {},
            "response_body_available": False,
            "tls_available": False,
            "tls_info": {},
            "cookies": [],
            "raw_response": None,
            "used_http_fallback": False,
            "http_fallback_reason": None,
            "redirect_chain": [],
            "response_time_ms": 0.0,
            "error": target_info.get("error", "Invalid target URL"),
            "error_stage": "NORMALIZATION",
        }

    conn_res = check_http_connectivity(
        target_info=target_info,
        session=session,
        timeout=timeout,
        allow_http_fallback=allow_http_fallback,
    )

    resp = conn_res.get("raw_response")
    body_avail = bool(resp and getattr(resp, "text", None))
    
    return {
        "reachable": conn_res.get("reachable", False),
        "url": conn_res.get("initial_url", target_info["normalized_url"]),
        "final_url": conn_res.get("final_url", target_info["normalized_url"]),
        "status_code": conn_res.get("status_code", 0),
        "scheme": target_info.get("scheme", "https"),
        "hostname": target_info.get("hostname", ""),
        "port": target_info.get("port", 443 if target_info.get("scheme") == "https" else 80),
        "response_headers": conn_res.get("headers", {}),
        "response_body_available": body_avail,
        "tls_available": target_info.get("scheme") == "https" and not conn_res.get("used_http_fallback", False) and conn_res.get("reachable", False),
        "tls_info": {},
        "cookies": conn_res.get("cookies", []),
        "raw_response": resp,
        "used_http_fallback": conn_res.get("used_http_fallback", False),
        "http_fallback_reason": conn_res.get("http_fallback_reason"),
        "redirect_chain": conn_res.get("redirect_chain", []),
        "response_time_ms": conn_res.get("response_time_ms", 0.0),
        "error": conn_res.get("error"),
        "error_stage": conn_res.get("error_type"),
    }


# ===========================================================================
# 7. FULL TARGET DIAGNOSTIC SUITE
# ===========================================================================

def run_target_diagnostics(target: str) -> Dict[str, Any]:
    """
    Runs complete end-to-end diagnostic telemetry for a target URL.
    Used by Diagnostic Mode (?debug=true).
    """
    norm = normalize_target_url(target)
    if not norm["valid"]:
        return {
            "target": target,
            "normalized": norm,
            "dns": {"success": False, "error": norm["error"]},
            "proxy": detect_proxy_environment(),
            "tcp_443": {"success": False, "error": "Invalid target"},
            "tcp_80": {"success": False, "error": "Invalid target"},
            "tls": {"success": False, "error": "Invalid target"},
            "http": {"reachable": False, "error": norm["error"]},
        }

    hostname = norm["hostname"]
    port = norm["port"]

    dns_res = resolve_dns(hostname)
    proxy_res = detect_proxy_environment()
    tcp_443 = check_tcp_connectivity(hostname, 443, timeout=3.0)
    tcp_80 = check_tcp_connectivity(hostname, 80, timeout=3.0)
    tls_res = check_tls_connectivity(hostname, 443, timeout=3.0) if tcp_443["success"] else {"success": False, "error": "Port 443 closed / not reachable"}
    http_res = check_http_connectivity(norm, timeout=(3.0, 5.0))

    return {
        "target": target,
        "normalized": norm,
        "dns": dns_res,
        "proxy": proxy_res,
        "tcp_443": tcp_443,
        "tcp_80": tcp_80,
        "tls": tls_res,
        "http": {
            "reachable": http_res["reachable"],
            "status_code": http_res["status_code"],
            "final_url": http_res["final_url"],
            "response_time_ms": http_res["response_time_ms"],
            "used_http_fallback": http_res["used_http_fallback"],
            "http_fallback_reason": http_res["http_fallback_reason"],
            "server_banner": http_res["server_banner"],
            "error": http_res["error"],
        },
    }
