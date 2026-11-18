"""
Nuclei Integration for Live Application Security Auditing.

Performs safe, non-destructive live web application and API scanning.
Enforces strict target authorization, SSRF protections, and safe template execution.

Windows Compatibility:
- Discovers nuclei.exe across WinGet, Go (%USERPROFILE%\\go\\bin), .pdtm, Chocolatey, Scoop, and system PATH.
- Supports custom executable override via NUCLEI_PATH environment variable.
"""

import ipaddress
import json
import os
import re
import socket
import subprocess
import shutil
import time
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

from scanner_integrations.base import BaseScanner, get_subprocess_env, get_extended_search_paths
from scanner_integrations.normalizer import normalize_finding


def is_private_ip(ip_str: str) -> bool:
    """Checks if an IP address falls within private, loopback, or reserved subnets."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def validate_target_url_for_live_scan(url: str, allow_local: bool = False) -> Dict[str, Any]:
    """
    Validates target URL and checks for SSRF or unauthorized internal scanning attempts.
    """
    if not url or not isinstance(url, str):
        return {"valid": False, "error": "Target URL is required."}

    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        return {"valid": False, "error": "Target URL must start with http:// or https://"}

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return {"valid": False, "error": "Invalid hostname in target URL."}

    # Reject localhost / metadata endpoints unless explicitly allowed
    if not allow_local:
        if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"):
            return {"valid": False, "error": "Scanning localhost and internal cloud metadata IPs is prohibited."}

        try:
            addr_info = socket.getaddrinfo(hostname, None)
            for item in addr_info:
                ip_addr = item[4][0]
                if is_private_ip(ip_addr):
                    return {
                        "valid": False,
                        "error": f"Target domain '{hostname}' resolves to private/internal IP '{ip_addr}'. Scanning internal networks is restricted.",
                    }
        except socket.gaierror:
            return {"valid": False, "error": f"DNS resolution failed for hostname '{hostname}'."}

    return {"valid": True, "hostname": hostname, "url": url}


class NucleiScanner(BaseScanner):
    """Integrates ProjectDiscovery's Nuclei CLI for live application auditing."""

    def __init__(self, timeout_seconds: Optional[int] = None):
        t_sec = timeout_seconds or int(os.environ.get("NUCLEI_TIMEOUT", "200"))
        super().__init__(name="nuclei", timeout_seconds=t_sec)

    def get_binary_path(self, candidates: Optional[List[str]] = None) -> Optional[str]:
        """
        Discovers the Nuclei executable on Windows, Linux, and macOS.
        
        Resolution Priority:
        1. NUCLEI_PATH environment variable (if specified)
        2. shutil.which lookup across system & extended PATH
        3. Standard Windows install locations (%LOCALAPPDATA%\\Microsoft\\WinGet\\Links, %USERPROFILE%\\go\\bin, etc.)
        """
        # 1. Custom environment variable override: NUCLEI_PATH
        custom_path = os.environ.get("NUCLEI_PATH", "").strip()
        if custom_path:
            if os.path.isfile(custom_path):
                self._cached_binary_path = custom_path
                return custom_path
            elif os.path.isdir(custom_path):
                for ext in ("", ".exe", ".cmd", ".bat"):
                    candidate = os.path.join(custom_path, f"nuclei{ext}")
                    if os.path.isfile(candidate):
                        self._cached_binary_path = candidate
                        return candidate

        # 2. Check cached path if still valid
        if self._cached_binary_path and os.path.isfile(self._cached_binary_path):
            return self._cached_binary_path

        # 3. Standard search across PATH and extended directories
        env_path = get_subprocess_env().get("PATH", "")
        for bname in (candidates or ["nuclei", "nuclei.exe"]):
            # shutil.which lookup
            found = shutil.which(bname, path=env_path)
            if found and os.path.isfile(found):
                self._cached_binary_path = found
                return found

            # Direct check in extended search paths
            for sdir in get_extended_search_paths():
                for ext in ("", ".exe", ".cmd", ".bat"):
                    candidate = os.path.join(sdir, f"nuclei{ext}")
                    if os.path.isfile(candidate):
                        self._cached_binary_path = candidate
                        return candidate

        return None

    def get_version(self) -> Optional[str]:
        """Queries Nuclei executable for version string using 'nuclei -version'."""
        if self._cached_version:
            return self._cached_version
        bin_path = self.get_binary_path()
        if not bin_path:
            return None
        try:
            res = subprocess.run(
                [bin_path, "-version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                env=get_subprocess_env(),
            )
            out = (res.stdout or res.stderr or "").strip()
            # Look for version pattern e.g. "Nuclei Engine v3.3.0" or "v3.x"
            match = re.search(r"v\d+\.\d+[\.\d]*", out, re.IGNORECASE)
            if match:
                self._cached_version = match.group(0)
            elif out:
                self._cached_version = out.splitlines()[0]
            else:
                self._cached_version = "installed"
            return self._cached_version
        except Exception:
            return "installed"

    def diagnose(self) -> Dict[str, Any]:
        """
        Diagnostic function returning comprehensive status, binary location, and version.
        """
        bin_path = self.get_binary_path()
        installed = bin_path is not None and os.path.isfile(bin_path)
        version = self.get_version() if installed else None
        error = None

        if not installed:
            error = (
                "Nuclei executable was not found. Install via 'winget install ProjectDiscovery.Nuclei' "
                "or 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest', or set NUCLEI_PATH."
            )

        return {
            "installed": installed,
            "executable": bin_path,
            "version": version,
            "error": error,
        }

    def scan(self, target: str, authorization_confirmed: bool = False, allow_local: bool = False, timeout_seconds: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Executes a safe Nuclei scan on a verified live application.
        Requires explicit authorization confirmation.
        """
        start_time = time.time()
        effective_timeout = timeout_seconds or self.timeout_seconds
        
        # 1. Authorization check
        if not authorization_confirmed:
            print("[NUCLEI] Execution skipped: Target authorization not confirmed", flush=True)
            return {
                "scanner": self.name,
                "name": "Nuclei Live Application Scanner",
                "available": self.check_available(),
                "version": self.get_version() if self.check_available() else None,
                "executed": False,
                "status": "not_executed",
                "findings_count": 0,
                "duration": 0.0,
                "raw_findings": [],
                "normalized_findings": [],
                "error": None,
                "reason": "Target authorization not confirmed ('Only scan applications you own or have explicit permission to test').",
            }

        print("[NUCLEI] Checking executable", flush=True)
        bin_path = self.get_binary_path()
        installed = bin_path is not None and os.path.isfile(bin_path)

        if not installed:
            print(f"[NUCLEI] Executable: NOT FOUND", flush=True)
            return {
                "scanner": self.name,
                "name": "Nuclei Live Application Scanner",
                "available": False,
                "version": None,
                "executed": False,
                "status": "not_installed",
                "findings_count": 0,
                "duration": 0.0,
                "raw_findings": [],
                "normalized_findings": [],
                "error": None,
                "reason": "Nuclei CLI binary is not installed in system PATH or NUCLEI_PATH.",
            }

        version_str = self.get_version()
        print(f"[NUCLEI] Executable: {bin_path}", flush=True)
        print(f"[NUCLEI] Version: {version_str}", flush=True)

        # 2. SSRF & URL validation
        val_check = validate_target_url_for_live_scan(target, allow_local=allow_local)
        if not val_check["valid"]:
            print(f"[NUCLEI] Validation failed: {val_check['error']}", flush=True)
            return {
                "scanner": self.name,
                "name": "Nuclei Live Application Scanner",
                "available": True,
                "version": version_str,
                "executed": False,
                "status": "FAILED",
                "findings_count": 0,
                "duration": 0.0,
                "raw_findings": [],
                "normalized_findings": [],
                "error": val_check["error"],
                "reason": val_check["error"],
            }

        target_url = val_check["url"]
        print("[NUCLEI_START]", flush=True)
        print(f"[NUCLEI] Starting scan: {target_url} (timeout: {effective_timeout}s)", flush=True)

        # 3. Safe non-destructive template execution without shell=True
        cmd = [
            bin_path,
            "-u", target_url,
            "-jsonl",
            "-tags", "misconfig,exposure,headers,tech",
            "-exclude-tags", "dos,fuzz,destructive",
            "-severity", "info,low,medium,high,critical",
            "-rate-limit", "150",
            "-c", "25",
            "-timeout", "5",
            "-retries", "1",
            "-silent",
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
                env=get_subprocess_env(),
            )

            print(f"[NUCLEI] Process exited: code {res.returncode}", flush=True)

            # Check for hard process errors if non-zero exit and no stdout findings
            if res.returncode != 0 and not res.stdout.strip() and res.stderr.strip():
                err_msg = res.stderr.strip().splitlines()[-1] if res.stderr else f"Exit code {res.returncode}"
                print(f"[NUCLEI] Execution error: {err_msg}", flush=True)
                return {
                    "scanner": self.name,
                    "name": "Nuclei Live Application Scanner",
                    "available": True,
                    "version": version_str,
                    "executed": False,
                    "status": "FAILED",
                    "findings_count": 0,
                    "duration": round(time.time() - start_time, 2),
                    "raw_findings": [],
                    "normalized_findings": [],
                    "error": err_msg,
                    "reason": err_msg,
                }

            raw_findings = self.parse_results(res.stdout or "")
            normalized = self.normalize_findings(raw_findings, target_url=target_url)
            dur = round(time.time() - start_time, 2)

            print(f"[NUCLEI] Findings: {len(normalized)} normalized findings detected ({dur}s)", flush=True)
            print("[NUCLEI_COMPLETE]", flush=True)

            return {
                "scanner": self.name,
                "name": "Nuclei Live Application Scanner",
                "available": True,
                "version": version_str,
                "executed": True,
                "status": "COMPLETED",
                "findings_count": len(normalized),
                "duration": dur,
                "raw_findings": raw_findings,
                "normalized_findings": normalized,
                "error": None,
                "reason": "Scan completed successfully.",
            }

        except subprocess.TimeoutExpired:
            dur = round(time.time() - start_time, 2)
            timeout_msg = f"Nuclei scan timed out after {effective_timeout}s."
            print(f"[NUCLEI] {timeout_msg}", flush=True)
            return {
                "scanner": self.name,
                "name": "Nuclei Live Application Scanner",
                "available": True,
                "version": version_str,
                "executed": False,
                "status": "TIMEOUT",
                "findings_count": 0,
                "duration": dur,
                "raw_findings": [],
                "normalized_findings": [],
                "error": timeout_msg,
                "reason": timeout_msg,
            }
        except Exception as e:
            dur = round(time.time() - start_time, 2)
            print(f"[NUCLEI] Exception during execution: {e}", flush=True)
            return {
                "scanner": self.name,
                "name": "Nuclei Live Application Scanner",
                "available": True,
                "version": version_str,
                "executed": False,
                "status": "FAILED",
                "findings_count": 0,
                "duration": dur,
                "raw_findings": [],
                "normalized_findings": [],
                "error": str(e),
                "reason": f"Execution error: {e}",
            }

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parses JSON-Lines output generated by Nuclei."""
        if not raw_output or not raw_output.strip():
            return []
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
                findings.append(data)
            except Exception:
                continue
        return findings

    def normalize_findings(self, raw_findings: List[Dict[str, Any]], target_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Normalizes Nuclei findings into the standard finding schema."""
        normalized = []
        for item in raw_findings:
            template_id = item.get("template-id", "nuclei-finding")
            info = item.get("info", {})
            title = info.get("name") or template_id.replace("-", " ").title()
            desc = info.get("description") or f"Live vulnerability matching rule '{template_id}'."
            sev = str(info.get("severity", "MEDIUM")).upper()
            if sev == "INFO":
                sev = "LOW"
            matched_at = item.get("matched-at") or target_url or "unknown"
            
            remediation = info.get("remediation") or "Patch target application or update web server configuration."
            reference = info.get("reference", [])
            if isinstance(reference, str):
                reference = [reference]

            norm = normalize_finding(
                scanner="nuclei",
                category="website_security",
                title=f"Live Vulnerability: {title}",
                description=desc,
                severity=sev,
                confidence="CONFIRMED",
                file=matched_at,
                evidence=f"Matched template '{template_id}' at {matched_at}",
                remediation=remediation,
                references=reference,
                raw_details=item,
            )
            normalized.append(norm)
        return normalized
