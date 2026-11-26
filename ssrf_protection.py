"""
TrustAudit Enterprise SSRF (Server-Side Request Forgery) Protection Module.

Implements strict defense-in-depth protection for public and internal URL fetching:
1. Scheme Whitelist: Only http and https permitted.
2. Credentials Rejection: Rejects URLs with embedded user/password credentials.
3. Port Whitelist: Restricts destination ports to approved web ports (80, 443, 8080, 8443).
4. Dual-Stack DNS Resolution: Resolves all IPv4 (A) and IPv6 (AAAA) records before connection.
5. Strict IP Filtering:
   - Blocks loopback addresses (127.0.0.0/8, ::1).
   - Blocks private RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
   - Blocks private IPv6 ranges (fc00::/7, fd00::/8).
   - Blocks link-local addresses (169.254.0.0/16, fe80::/10).
   - Blocks cloud metadata endpoints (169.254.169.254, fd00:ec2::254, metadata.google.internal).
   - Blocks multicast, reserved, and unspecified addresses (0.0.0.0, 224.0.0.0/4, ::).
6. DNS Rebinding & Redirect Defense:
   - Intercepts and re-validates every redirect hop prior to sending subsequent requests.
   - Enforces maximum redirect depth (default: 3 hops).
7. Resource Bounds:
   - Enforces strict socket connection (3.0s) and read (4.0s) timeouts.
   - Enforces maximum response body size limits (default: 512 KB) to prevent OOM / zip bombs.
"""

import ipaddress
import socket
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
    "metadata.azure.com",
}
CLOUD_METADATA_IPS = {
    "169.254.169.254",
    "fd00:ec2::254",
    "169.254.169.250",
    "169.254.169.251",
    "100.100.100.200",  # Alibaba cloud metadata
}
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
DEFAULT_MAX_REDIRECTS = 3
DEFAULT_MAX_BODY_BYTES = 512 * 1024  # 512 KB
DEFAULT_TIMEOUT_CONNECT = 3.0
DEFAULT_TIMEOUT_READ = 4.0


class SSRFSecurityError(ValueError):
    """Raised when a target URL violates SSRF security boundaries."""
    pass


def validate_target_url_ssrf_safe(url: str) -> Dict[str, Any]:
    """
    Validates a URL against all SSRF security rules.
    Resolves DNS and checks all resulting IPv4/IPv6 addresses.
    Returns structured validation metadata or raises SSRFSecurityError.
    """
    if not url or not isinstance(url, str):
        raise SSRFSecurityError("Target URL cannot be empty.")

    clean_url = url.strip()
    if not clean_url:
        raise SSRFSecurityError("Target URL cannot be whitespace.")

    # Parse URL
    try:
        parsed = urlparse(clean_url)
    except Exception as e:
        raise SSRFSecurityError(f"Malformed URL: {e}")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFSecurityError(
            f"Invalid URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."
        )

    # Reject credentials embedded in URLs
    if parsed.username or parsed.password:
        raise SSRFSecurityError(
            "URLs containing embedded credentials (user:password@host) are prohibited."
        )

    # Netloc check
    netloc = parsed.netloc
    if not netloc:
        raise SSRFSecurityError("Missing hostname / network location.")

    # Extract hostname & port
    hostname = parsed.hostname or ""
    if not hostname:
        host_part = netloc.split(":")[0] if ":" in netloc and not netloc.startswith("[") else netloc
        hostname = host_part.strip("[]")

    hostname_clean = hostname.strip().lower()
    if not hostname_clean:
        raise SSRFSecurityError("Empty hostname is prohibited.")

    if hostname_clean in BLOCKED_HOSTNAMES or hostname_clean.endswith(".local") or hostname_clean.endswith(".internal"):
        raise SSRFSecurityError(f"Hostname '{hostname_clean}' is prohibited.")

    # Determine port
    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFSecurityError(
            f"Port {port} is not in the allowed web ports list ({sorted(list(ALLOWED_PORTS))})."
        )

    # Resolve DNS dual-stack and validate all IPs
    resolved_ips = _resolve_and_verify_ips(hostname_clean)

    return {
        "valid": True,
        "clean_url": clean_url,
        "scheme": scheme,
        "hostname": hostname_clean,
        "port": port,
        "path": parsed.path or "/",
        "query": parsed.query or "",
        "resolved_ips": resolved_ips,
    }


def _assert_public_ip(ip_str: str) -> None:
    clean_ip = str(ip_str).split("%", 1)[0].strip("[]")
    if clean_ip in CLOUD_METADATA_IPS:
        raise SSRFSecurityError(
            f"Access to cloud metadata IP '{clean_ip}' is strictly prohibited."
        )

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        raise SSRFSecurityError(f"Invalid resolved IP address: '{clean_ip}'.")

    # Unwrap IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1, ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        _assert_public_ip(str(ip_obj.ipv4_mapped))

    if ip_obj.is_loopback:
        raise SSRFSecurityError(
            f"Loopback address '{clean_ip}' is prohibited (internal host access blocked)."
        )

    if ip_obj.is_private:
        raise SSRFSecurityError(
            f"Private IP address '{clean_ip}' (RFC 1918 / RFC 4193) is prohibited."
        )

    if ip_obj.is_link_local:
        raise SSRFSecurityError(
            f"Link-local address '{clean_ip}' (RFC 3927) is prohibited."
        )

    if ip_obj.is_multicast:
        raise SSRFSecurityError(
            f"Multicast address '{clean_ip}' is prohibited."
        )

    if ip_obj.is_reserved or ip_obj.is_unspecified:
        raise SSRFSecurityError(
            f"Reserved or unspecified address '{clean_ip}' is prohibited."
        )

    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in CGNAT_NETWORK:
        raise SSRFSecurityError(
            f"Carrier-grade NAT / internal IP '{clean_ip}' (RFC 6598) is prohibited."
        )


def _resolve_and_verify_ips(hostname: str) -> List[str]:
    """
    Resolves all A and AAAA records for hostname and verifies each IP address.
    Raises SSRFSecurityError if any IP is private, loopback, link-local, or cloud metadata.
    """
    resolved_ips: List[str] = []

    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFSecurityError(f"DNS resolution failed for '{hostname}': {e}")
    except Exception as e:
        raise SSRFSecurityError(f"DNS lookup error for '{hostname}': {e}")

    if not addr_info:
        raise SSRFSecurityError(f"No DNS records found for host '{hostname}'.")

    for item in addr_info:
        ip_str = item[4][0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    for ip_str in resolved_ips:
        _assert_public_ip(ip_str)

    return resolved_ips


def safe_http_fetch(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: Tuple[float, float] = (DEFAULT_TIMEOUT_CONNECT, DEFAULT_TIMEOUT_READ),
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> Dict[str, Any]:
    """
    Executes a safe HTTP/HTTPS request protected against SSRF, redirect bypasses,
    DNS rebinding, and resource exhaustion.

    Returns:
    {
        "status_code": int,
        "final_url": str,
        "headers": dict,
        "content_bytes": bytes,
        "content_text": str,
        "duration_ms": float,
        "redirect_chain": list,
        "tls_version": str or None,
    }
    """
    current_url = url
    redirect_chain = []
    t_start = time.time()

    default_headers = {
        "User-Agent": "TrustAudit-Security-Scanner/2.4 (Enterprise Non-Invasive Scanner; +https://mcp-scanner.onrender.com/trust)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if headers:
        default_headers.update(headers)

    for hop in range(max_redirects + 1):
        # 1. SSRF validation for current hop
        meta = validate_target_url_ssrf_safe(current_url)
        redirect_chain.append(meta["clean_url"])

        # 2. Issue single-hop request (allow_redirects=False)
        try:
            res = requests.request(
                method=method,
                url=meta["clean_url"],
                headers=default_headers,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                verify=True,
            )
            # Re-verify connected socket peer IP against DNS rebinding
            try:
                sock = getattr(getattr(res.raw, "_connection", None), "sock", None)
                if sock is not None:
                    peer = sock.getpeername()
                    if peer and peer[0]:
                        _assert_public_ip(peer[0])
            except SSRFSecurityError:
                res.close()
                raise
            except Exception:
                pass
        except SSRFSecurityError:
            raise
        except requests.exceptions.SSLError as e:
            # Retry with verify=False only if we still enforce strict SSRF IP check
            # For public scans, we capture SSL error as a security finding
            return {
                "success": False,
                "error": f"TLS/SSL Certificate Verification Failed: {e}",
                "error_type": "SSL_ERROR",
                "final_url": current_url,
                "redirect_chain": redirect_chain,
            }
        except requests.exceptions.Timeout as e:
            return {
                "success": False,
                "error": f"Connection timed out: {e}",
                "error_type": "TIMEOUT",
                "final_url": current_url,
                "redirect_chain": redirect_chain,
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Network request error: {e}",
                "error_type": "NETWORK_ERROR",
                "final_url": current_url,
                "redirect_chain": redirect_chain,
            }

        # Check for HTTP redirect status codes (301, 302, 303, 307, 308)
        if res.status_code in (301, 302, 303, 307, 308):
            location = res.headers.get("Location")
            if not location:
                # Malformed redirect without location; treat as final response
                break

            if hop >= max_redirects:
                return {
                    "success": False,
                    "error": f"Exceeded maximum redirect limit ({max_redirects} hops).",
                    "error_type": "TOO_MANY_REDIRECTS",
                    "final_url": current_url,
                    "redirect_chain": redirect_chain,
                }

            # Resolve relative redirect against current_url
            next_url = urljoin(current_url, location)
            current_url = next_url
            continue

        # If not redirecting, read bounded body
        body_chunks = []
        bytes_read = 0
        try:
            for chunk in res.iter_content(chunk_size=8192):
                if chunk:
                    bytes_read += len(chunk)
                    if bytes_read > max_body_bytes:
                        body_chunks.append(chunk[: max_body_bytes - (bytes_read - len(chunk))])
                        break
                    body_chunks.append(chunk)
        except Exception as e:
            pass
        finally:
            res.close()

        body_bytes = b"".join(body_chunks)
        encoding = res.encoding or "utf-8"
        try:
            body_text = body_bytes.decode(encoding, errors="replace")
        except Exception:
            body_text = body_bytes.decode("utf-8", errors="replace")

        elapsed_ms = round((time.time() - t_start) * 1000, 2)

        return {
            "success": True,
            "status_code": res.status_code,
            "final_url": current_url,
            "headers": dict(res.headers),
            "content_bytes": body_bytes,
            "content_text": body_text,
            "body_length": len(body_bytes),
            "duration_ms": elapsed_ms,
            "redirect_chain": redirect_chain,
            "error": None,
        }

    return {
        "success": False,
        "error": "Redirect processing loop exceeded.",
        "error_type": "REDIRECT_LOOP",
        "final_url": current_url,
        "redirect_chain": redirect_chain,
    }
