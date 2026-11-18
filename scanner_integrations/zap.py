"""
OWASP ZAP (Zed Attack Proxy) DAST Adapter for TrustAudit Platform.

Integrates OWASP ZAP for dynamic application security testing (DAST):
- Supports 3 execution modes:
    1. Docker Mode (preferred, official ZAP container: ghcr.io/zaproxy/zaproxy:stable or zaproxy/zap-stable)
    2. Local Mode (zap.bat on Windows, zap.sh / zaproxy / zap-baseline.py on Linux/macOS, or ZAP_PATH)
    3. Graceful Unavailable Mode (status=UNAVAILABLE with actionable diagnostics)
- Supports PASSIVE, SAFE_ACTIVE, and ACTIVE scanning profiles.
- Strict pre-scan target validation, normalization, and localhost/private-IP safeguards.
- Enforces user authorization before any active probing.
- Full lifecycle management: Launch -> Ready check -> Scan -> Collect -> Parse -> Stop -> Cleanup.
- Transparent lifecycle logging: [ZAP_START], [ZAP_READY], [ZAP_SCAN_START], [ZAP_SCAN_COMPLETE], [ZAP_STOP].
- Zero fake findings: only reports real ZAP findings, properly parses reports.
"""

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

from scanner_integrations.base import BaseScanner, get_subprocess_env
from scanner_integrations.normalizer import normalize_finding, normalize_severity, normalize_confidence

logger = logging.getLogger("trustaudit.zap")

# Configurable timeouts
ZAP_STARTUP_TIMEOUT = int(os.environ.get("ZAP_STARTUP_TIMEOUT", "20"))
ZAP_CONNECTION_TIMEOUT = int(os.environ.get("ZAP_CONNECTION_TIMEOUT", "10"))
ZAP_SCAN_TIMEOUT = int(os.environ.get("ZAP_SCAN_TIMEOUT", "60"))
DEFAULT_OFFICIAL_ZAP_IMAGE = os.environ.get("ZAP_IMAGE", "ghcr.io/zaproxy/zaproxy:stable")
DEFAULT_ZAP_TIMEOUT = int(os.environ.get("ZAP_TOTAL_TIMEOUT", os.environ.get("ZAP_TIMEOUT", os.environ.get("ZAP_MAX_DURATION", "120"))))


def _is_private_or_localhost(hostname: str) -> bool:
    """Checks if a hostname resolves to a loopback or private network."""
    h = (hostname or "").lower().strip()
    if h in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return True
    if h.startswith("10.") or h.startswith("192.168."):
        return True
    if re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", h):
        return True
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".test"):
        return True
    return False


def _check_target_reachability(hostname: str, port: int = 80, timeout: float = 3.0) -> bool:
    """Quick socket check to ensure target host is answering before launching heavy DAST process."""
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except Exception:
        return False


class ZapError(str):
    """Hybrid error object that supports both string operations (e.g. .lower()) and dict lookups (['type'], ['message'])."""
    def __new__(cls, message: str, error_type: str = "ERROR"):
        obj = str.__new__(cls, message)
        obj.type = error_type
        obj.message = message
        return obj

    def get(self, key, default=None):
        if key == "type":
            return self.type
        elif key == "message":
            return self.message
        return default

    def __getitem__(self, key):
        if key == "type":
            return self.type
        elif key == "message":
            return self.message
        return super().__getitem__(key)


class ZapScanner(BaseScanner):
    """Production-grade Adapter for OWASP ZAP DAST with Docker and Local execution modes."""

    def __init__(self, timeout_seconds: int = DEFAULT_ZAP_TIMEOUT):
        super().__init__(name="OWASP ZAP DAST Scanner", timeout_seconds=timeout_seconds)
        self.supported_modes = ["PASSIVE", "SAFE_ACTIVE", "ACTIVE"]
        self.docker_image = os.environ.get("ZAP_IMAGE", DEFAULT_OFFICIAL_ZAP_IMAGE)
        self.configured_mode = os.environ.get("ZAP_EXECUTION_MODE", "auto").lower()  # auto, docker, local, disabled
        self._cached_docker_status: Optional[Tuple[bool, str]] = None
        self._cached_local_path: Optional[str] = None
        self._cached_version: Optional[str] = None

    def check_docker_available(self) -> Tuple[bool, str]:
        """
        Checks if Docker CLI is installed and the Docker daemon is responding.
        Returns (is_available, status_or_version_string).
        """
        if self._cached_docker_status is not None:
            return self._cached_docker_status

        docker_bin = shutil.which("docker", path=get_subprocess_env().get("PATH"))
        if not docker_bin:
            self._cached_docker_status = (False, "Docker CLI not found in PATH")
            return self._cached_docker_status

        # Test if Docker daemon is responding
        try:
            env = get_subprocess_env()
            res = subprocess.run(
                [docker_bin, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=3,
                env=env,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                version_str = res.stdout.strip()
                self._cached_docker_status = (True, f"Docker Engine {version_str}")
                return self._cached_docker_status
            else:
                self._cached_docker_status = (False, "Docker Desktop daemon is not running")
                return self._cached_docker_status
        except subprocess.TimeoutExpired:
            self._cached_docker_status = (False, "Docker daemon connection timed out (3s)")
            return self._cached_docker_status
        except Exception as e:
            self._cached_docker_status = (False, "Docker Desktop daemon is not running")
            return self._cached_docker_status

    def get_local_binary_path(self) -> Optional[str]:
        """Finds local ZAP executable across PATH and known directories."""
        if self._cached_local_path and os.path.exists(self._cached_local_path):
            return self._cached_local_path

        # 1. Custom ZAP_PATH environment variable
        custom_path = os.environ.get("ZAP_PATH", "").strip()
        if custom_path:
            if os.path.isfile(custom_path):
                self._cached_local_path = custom_path
                return custom_path
            elif os.path.isdir(custom_path):
                for candidate in ("zap.bat", "zap.sh", "zaproxy", "zap-baseline.py", "zap-cli.exe"):
                    p = os.path.join(custom_path, candidate)
                    if os.path.isfile(p):
                        self._cached_local_path = p
                        return p
                # Check for JAR inside directory
                try:
                    for fname in os.listdir(custom_path):
                        if fname.lower().startswith("zap") and fname.lower().endswith(".jar"):
                            p = os.path.join(custom_path, fname)
                            self._cached_local_path = p
                            return p
                except Exception:
                    pass

        # 2. Binary candidates across extended PATH
        candidates = [
            "zap-baseline.py",
            "zap-full-scan.py",
            "zap-cli",
            "zap.bat",
            "zap.sh",
            "zaproxy",
            "zaproxy.bat",
            "zaproxy.exe",
        ]
        path = self.get_binary_path(candidates)
        if path:
            self._cached_local_path = path
            return path

        # 3. Known platform default install directories
        known_dirs = [
            r"C:\Program Files\ZAP\Zed Attack Proxy",
            r"C:\Program Files (x86)\ZAP\Zed Attack Proxy",
            r"C:\Program Files\OWASP\Zed Attack Proxy",
            "/usr/share/zaproxy",
            "/opt/zaproxy",
            "/usr/local/bin",
            "/Applications/OWASP ZAP.app/Contents/Java",
        ]
        for kdir in known_dirs:
            if not os.path.isdir(kdir):
                continue
            for bname in ("zap.bat", "zap.sh", "zaproxy", "zap-baseline.py", "zap.exe"):
                candidate_path = os.path.join(kdir, bname)
                if os.path.isfile(candidate_path):
                    self._cached_local_path = candidate_path
                    return candidate_path
            try:
                for fname in os.listdir(kdir):
                    if fname.lower().startswith("zap") and fname.lower().endswith(".jar"):
                        jar_path = os.path.join(kdir, fname)
                        self._cached_local_path = jar_path
                        return jar_path
            except Exception:
                pass

        return None

    def get_execution_mode(self) -> str:
        """
        Determines the active ZAP execution mode based on system state and configuration.
        Returns: 'docker', 'local', or 'none'.
        """
        if self.configured_mode == "disabled":
            return "none"

        # Explicit mode preference
        if self.configured_mode == "docker":
            docker_ok, _ = self.check_docker_available()
            return "docker" if docker_ok else "none"
        if self.configured_mode == "local":
            local_bin = self.get_local_binary_path()
            return "local" if local_bin else "none"

        # Auto mode: Docker (preferred) -> Local -> None
        docker_ok, _ = self.check_docker_available()
        if docker_ok:
            return "docker"

        local_bin = self.get_local_binary_path()
        if local_bin:
            return "local"

        return "none"

    def check_available(self) -> bool:
        """Determines if OWASP ZAP is ready to execute (via Docker or Local)."""
        return self.get_execution_mode() in ("docker", "local")

    def get_version(self) -> str:
        """Retrieves ZAP version string or Docker image tag dynamically without slow JVM startup."""
        if self._cached_version:
            return self._cached_version

        mode = self.get_execution_mode()
        if mode == "docker":
            self._cached_version = f"Official Container ({self.docker_image})"
            return self._cached_version
        elif mode == "local":
            bin_path = self.get_local_binary_path()
            if not bin_path:
                return "Not Installed"

            # Check filename pattern e.g. zap-2.17.0.jar
            dir_name = os.path.dirname(bin_path) if os.path.isabs(bin_path) else os.getcwd()
            base_name = os.path.basename(bin_path)
            jar_match = re.search(r"zap[_-]?(\d+\.\d+\.\d+)", base_name, re.IGNORECASE)
            if jar_match:
                self._cached_version = f"v{jar_match.group(1)} (Local)"
                return self._cached_version

            # Check directory for matching zap-*.jar
            try:
                for fname in os.listdir(dir_name):
                    m = re.search(r"zap[_-]?(\d+\.\d+\.\d+)\.jar", fname, re.IGNORECASE)
                    if m:
                        self._cached_version = f"v{m.group(1)} (Local)"
                        return self._cached_version
            except Exception:
                pass

            self._cached_version = "OWASP ZAP (Local)"
            return self._cached_version

        return "Not Installed"

    def health_check(self) -> Dict[str, Any]:
        """Provides diagnostic health telemetry for OWASP ZAP engine."""
        docker_ok, docker_msg = self.check_docker_available()
        local_bin = self.get_local_binary_path()
        mode = self.get_execution_mode()
        available = mode in ("docker", "local")

        return {
            "name": self.name,
            "available": available,
            "status": "READY" if available else "UNAVAILABLE",
            "execution_mode": mode,
            "version": self.get_version() if available else None,
            "docker_available": docker_ok,
            "docker_status": docker_msg,
            "docker_image": self.docker_image,
            "local_binary": local_bin,
            "configured_mode": self.configured_mode,
        }

    def scan(
        self,
        target_url: str,
        mode: str = "PASSIVE",
        authorization_confirmed: bool = False,
        allow_local: bool = False,
        max_crawl_depth: int = 2,
        max_duration_seconds: Optional[int] = None,
        rate_limit_per_sec: int = 5,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Executes an OWASP ZAP security audit with strict target validation and lifecycle management.
        """
        t0 = time.time()
        timeout = max_duration_seconds or self.timeout_seconds
        findings: List[Dict[str, Any]] = []

        print("[ZAP_START]", flush=True)

        mode_clean = (mode or "PASSIVE").upper()
        if mode_clean not in self.supported_modes:
            mode_clean = "PASSIVE"

        # 1. Target URL Validation & Normalization
        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme or parsed.scheme not in ("http", "https") or not parsed.netloc:
            print("[ZAP_STOP]", flush=True)
            return {
                "engine": "OWASP_ZAP",
                "status": "FAILED",
                "mode": "none",
                "target": target_url,
                "duration_ms": int((time.time() - t0) * 1000),
                "findings": [],
                "errors": [ZapError(f"Invalid target URL for ZAP scan: {target_url}", "INVALID_TARGET")],
                "metadata": {"target": target_url, "execution_mode": "none"},
            }

        hostname = parsed.hostname or ""
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 2. Localhost / Private IP Guard
        if _is_private_or_localhost(hostname) and not allow_local:
            print("[ZAP_STOP]", flush=True)
            return {
                "engine": "OWASP_ZAP",
                "status": "SKIPPED",
                "mode": "none",
                "target": target_url,
                "duration_ms": 0,
                "findings": [],
                "errors": [ZapError("Localhost/private network target blocked by safety policy.", "PRIVATE_NETWORK_BLOCKED")],
                "metadata": {"mode": mode_clean, "target": target_url, "execution_mode": "none"},
            }

        # 3. Target Pre-Flight Connectivity Check
        # If target host does not answer socket check, mark as NOT_EXECUTED without spawning slow process
        target_reachable = _check_target_reachability(hostname, target_port, timeout=float(ZAP_CONNECTION_TIMEOUT))
        if not target_reachable and not allow_local:
            print(f"[ZAP_STOP] Target host {hostname}:{target_port} unreachable", flush=True)
            return {
                "engine": "OWASP_ZAP",
                "status": "NOT_EXECUTED",
                "mode": "none",
                "target": target_url,
                "duration_ms": int((time.time() - t0) * 1000),
                "findings": [],
                "errors": [ZapError(f"Target host {hostname} is unreachable on port {target_port}. Live ZAP scan skipped.", "TARGET_UNREACHABLE")],
                "metadata": {
                    "reason": f"Target host {hostname} is unreachable on port {target_port}.",
                    "execution_mode": "none",
                },
            }

        # 4. Authorization Guard for Active Scanning
        if mode_clean in ("SAFE_ACTIVE", "ACTIVE") and not authorization_confirmed:
            print("[ZAP_STOP]", flush=True)
            return {
                "engine": "OWASP_ZAP",
                "status": "SKIPPED",
                "mode": "none",
                "target": target_url,
                "duration_ms": 0,
                "findings": [],
                "errors": [ZapError("Target authorization not confirmed. Active DAST scanning is disabled.", "AUTHORIZATION_REQUIRED")],
                "metadata": {"mode": mode_clean, "authorized": False, "execution_mode": "none"},
            }

        # 5. Determine Execution Mode
        exec_mode = self.get_execution_mode()
        if exec_mode == "none":
            docker_ok, docker_msg = self.check_docker_available()
            reason = (
                "OWASP ZAP is not available. Docker Desktop daemon is not running and local ZAP binary "
                "(zap.bat/zap.sh) is not on PATH. Start Docker Desktop or install OWASP ZAP locally to enable DAST scanning."
            )
            print("[ZAP_STOP]", flush=True)
            return {
                "engine": "OWASP_ZAP",
                "status": "UNAVAILABLE",
                "mode": "none",
                "target": target_url,
                "duration_ms": int((time.time() - t0) * 1000),
                "findings": [],
                "errors": [ZapError(reason, "TOOL_NOT_INSTALLED")],
                "metadata": {
                    "zap_version": None,
                    "execution_mode": "none",
                    "reason": reason,
                    "docker_status": docker_msg,
                },
            }

        print(f"[ZAP_READY] Execution mode: {exec_mode.upper()} | Profile: {mode_clean} | Timeout: {timeout}s", flush=True)
        print(f"[ZAP_SCAN_START] Probing target: {target_url}", flush=True)

        # 6. Execute Scan in Selected Mode
        if exec_mode == "docker":
            result = self._scan_docker(target_url, mode_clean, max_crawl_depth, timeout)
        else:
            result = self._scan_local(target_url, mode_clean, max_crawl_depth, timeout)

        dur_ms = int((time.time() - t0) * 1000)
        result["duration_ms"] = dur_ms
        result["target"] = target_url

        print(f"[ZAP_SCAN_COMPLETE] Duration: {dur_ms}ms | Findings: {len(result.get('findings', []))}", flush=True)
        print("[ZAP_STOP]", flush=True)

        return result

    def _scan_docker(self, target_url: str, mode: str, max_crawl_depth: int, timeout: int) -> Dict[str, Any]:
        """Runs ZAP scan inside the official OWASP ZAP Docker container."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_file = "zap_report.json"
            report_path = os.path.join(tmpdir, report_file)

            script_name = "zap-full-scan.py" if mode == "ACTIVE" else "zap-baseline.py"
            timeout_mins = max(1, int(timeout / 60))

            docker_cmd = [
                "docker", "run", "--rm",
                "-v", f"{tmpdir}:/zap/wrk/:rw",
                "-t", self.docker_image,
                script_name,
                "-t", target_url,
                "-J", report_file,
                "-m", str(max_crawl_depth),
                "-T", str(timeout_mins),
            ]

            try:
                env = get_subprocess_env()
                proc = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    check=False,
                )

                raw_json = ""
                if os.path.exists(report_path):
                    with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                        raw_json = f.read()

                if raw_json:
                    parsed_findings = self.parse_results(raw_json, target_url)
                    return {
                        "engine": "OWASP_ZAP",
                        "status": "COMPLETED",
                        "mode": "docker",
                        "findings": parsed_findings,
                        "errors": [],
                        "metadata": {
                            "zap_version": self.docker_image,
                            "execution_mode": "docker",
                            "exit_code": proc.returncode,
                        },
                    }
                elif proc.returncode == 0:
                    return {
                        "engine": "OWASP_ZAP",
                        "status": "COMPLETED",
                        "mode": "docker",
                        "findings": [],
                        "errors": [],
                        "metadata": {
                            "zap_version": self.docker_image,
                            "execution_mode": "docker",
                            "exit_code": 0,
                        },
                    }
                else:
                    err_msg = (proc.stderr or proc.stdout or "ZAP container execution failed").strip()
                    return {
                        "engine": "OWASP_ZAP",
                        "status": "FAILED",
                        "mode": "docker",
                        "findings": [],
                        "errors": [{"type": "EXECUTION_ERROR", "message": err_msg[:500]}],
                        "metadata": {
                            "zap_version": self.docker_image,
                            "execution_mode": "docker",
                            "exit_code": proc.returncode,
                        },
                    }

            except subprocess.TimeoutExpired:
                partial_findings = []
                if os.path.exists(report_path):
                    try:
                        with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                            partial_findings = self.parse_results(f.read(), target_url)
                    except Exception:
                        pass
                return {
                    "engine": "OWASP_ZAP",
                    "status": "TIMEOUT",
                    "mode": "docker",
                    "findings": partial_findings,
                    "errors": [{"type": "TIMEOUT", "message": f"ZAP Docker scan timed out after {timeout} seconds"}],
                    "metadata": {"execution_mode": "docker", "timed_out": True, "reason": f"ZAP scan timed out after {timeout}s"},
                }
            except Exception as e:
                return {
                    "engine": "OWASP_ZAP",
                    "status": "FAILED",
                    "mode": "docker",
                    "findings": [],
                    "errors": [{"type": "EXCEPTION", "message": str(e)}],
                    "metadata": {"execution_mode": "docker"},
                }

    def _scan_local(self, target_url: str, mode: str, max_crawl_depth: int, timeout: int) -> Dict[str, Any]:
        """Runs ZAP scan using locally installed ZAP executable with an isolated per-scan home directory."""
        t_detect_start = time.time()
        bin_path = self.get_local_binary_path()
        t_detect = time.time() - t_detect_start
        print(f"[ZAP] Detecting installation... {t_detect:.2f}s", flush=True)

        if not bin_path:
            return {
                "engine": "OWASP_ZAP",
                "status": "NOT_INSTALLED",
                "mode": "local",
                "findings": [],
                "errors": [ZapError("Local ZAP binary not found", "TOOL_NOT_INSTALLED")],
                "metadata": {"execution_mode": "local"},
            }

        scan_uuid = uuid.uuid4().hex[:12]
        zap_home_dir = os.path.join(tempfile.gettempdir(), f"trustaudit_zap_home_{scan_uuid}")
        tmp_wrk_dir = os.path.join(tempfile.gettempdir(), f"trustaudit_zap_wrk_{scan_uuid}")
        os.makedirs(zap_home_dir, exist_ok=True)
        os.makedirs(tmp_wrk_dir, exist_ok=True)

        print(f"[ZAP] Creating isolated home directory: {zap_home_dir}", flush=True)

        report_file = os.path.join(tmp_wrk_dir, "zap_report.json")
        install_dir = os.path.dirname(bin_path) if os.path.isabs(bin_path) else os.getcwd()
        bin_base = os.path.basename(bin_path).lower()

        free_port = 0
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("", 0))
                free_port = s.getsockname()[1]
        except Exception:
            free_port = 8095

        # Determine JAR path in installation directory
        jar_path = bin_path if bin_base.endswith(".jar") else None
        if not jar_path and os.path.isdir(install_dir):
            try:
                for fname in os.listdir(install_dir):
                    if fname.lower().startswith("zap") and fname.lower().endswith(".jar"):
                        jar_path = os.path.join(install_dir, fname)
                        break
            except Exception:
                pass

        java_bin = shutil.which("java") or "java"

        # Bounded scan parameters to prevent spider and active scanner hangs
        spider_depth = max(1, min(max_crawl_depth or 1, 3))
        scan_configs = [
            "-config", f"spider.maxDepth={spider_depth}",
            "-config", "spider.maxDuration=1",
            "-config", "spider.maxChildren=10",
            "-config", "scanner.maxScanDurationInMins=1",
            "-config", "scanner.maxRuleDurationInMins=1",
            "-config", "scanner.threadPerHost=2",
        ]

        if jar_path and os.path.isfile(jar_path):
            cmd = [
                java_bin,
                "-Xmx512m",
                "-jar", jar_path,
                "-dir", zap_home_dir,
                "-installdir", install_dir,
                "-port", str(free_port),
                "-notel",
                "-silent",
            ] + scan_configs + [
                "-cmd",
                "-quickurl", target_url,
                "-quickout", report_file,
            ]
        elif bin_base in ("zap.bat", "zap.sh", "zaproxy", "zap.exe"):
            cmd = [
                bin_path,
                "-dir", zap_home_dir,
                "-port", str(free_port),
                "-notel",
                "-silent",
            ] + scan_configs + [
                "-cmd",
                "-quickurl", target_url,
                "-quickout", report_file,
            ]
        else:
            cmd = [bin_path, "-t", target_url, "-J", report_file, "-m", str(max_crawl_depth)]
            if mode == "PASSIVE":
                cmd.append("--passive-only")

        proc: Optional[subprocess.Popen] = None
        t_start = time.time()
        try:
            env = get_subprocess_env()
            print(f"[ZAP] Starting process in cwd={install_dir}...", flush=True)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=install_dir,
            )
            t_proc_started = time.time() - t_start
            print(f"[ZAP] Process started (PID: {proc.pid})... {t_proc_started:.2f}s", flush=True)
            print(f"[ZAP] Target connectivity & scan execution started: {target_url}", flush=True)

            timed_out = False
            t_scan_start = time.time()
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
                t_scan = time.time() - t_scan_start
                print(f"[ZAP] Scan execution completed... {t_scan:.2f}s (Exit code: {proc.returncode})", flush=True)
            except subprocess.TimeoutExpired:
                timed_out = True
                t_scan = time.time() - t_scan_start
                print(f"[ZAP] Scan timed out after {timeout}s ({t_scan:.2f}s). Terminating PID {proc.pid}...", flush=True)
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=2)
                stdout, stderr = "", f"ZAP scan timed out after {timeout} seconds. Target was not completely tested."

            t_collect_start = time.time()
            print("[ZAP] Collecting alerts...", flush=True)
            raw_json = ""
            if os.path.exists(report_file):
                with open(report_file, "r", encoding="utf-8", errors="ignore") as f:
                    raw_json = f.read()

            t_collect = time.time() - t_collect_start
            print(f"[ZAP] Alerts collected... {t_collect:.2f}s", flush=True)

            if raw_json:
                parsed_findings = self.parse_results(raw_json, target_url)
                return {
                    "engine": "OWASP_ZAP",
                    "status": "COMPLETED" if not timed_out else "TIMEOUT",
                    "mode": "local",
                    "findings": parsed_findings,
                    "errors": [] if not timed_out else [{"type": "TIMEOUT", "message": f"ZAP scan timed out after {timeout} seconds. Target was not completely tested."}],
                    "metadata": {
                        "zap_version": self.get_version(),
                        "execution_mode": "local",
                        "exit_code": proc.returncode,
                        "home_dir": zap_home_dir,
                    },
                }
            elif timed_out:
                return {
                    "engine": "OWASP_ZAP",
                    "status": "TIMEOUT",
                    "mode": "local",
                    "findings": [],
                    "errors": [ZapError(f"ZAP scan timed out after {timeout} seconds. Target was not completely tested.", "TIMEOUT")],
                    "metadata": {
                        "zap_version": self.get_version(),
                        "execution_mode": "local",
                        "timed_out": True,
                        "reason": f"ZAP scan timed out after {timeout} seconds. Target was not completely tested.",
                    },
                }
            else:
                err_output = ((stderr or "") + " " + (stdout or "")).strip()
                status_code = "COMPLETED" if proc.returncode == 0 else "FAILED"
                return {
                    "engine": "OWASP_ZAP",
                    "status": status_code,
                    "mode": "local",
                    "findings": [],
                    "errors": [] if proc.returncode == 0 else [ZapError(err_output[:500] or "ZAP process returned error", "EXEC_ERROR")],
                    "metadata": {
                        "zap_version": self.get_version(),
                        "execution_mode": "local",
                        "exit_code": proc.returncode,
                        "error_output": err_output[:500],
                        "home_dir": zap_home_dir,
                    },
                }

        except Exception as e:
            return {
                "engine": "OWASP_ZAP",
                "status": "FAILED",
                "mode": "local",
                "findings": [],
                "errors": [ZapError(str(e), "EXCEPTION")],
                "metadata": {"execution_mode": "local", "home_dir": zap_home_dir},
            }
        finally:
            t_clean_start = time.time()
            print("[ZAP] Stopping process & shutdown...", flush=True)
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            print(f"[ZAP] Cleaning up isolated home directory: {zap_home_dir}", flush=True)
            shutil.rmtree(zap_home_dir, ignore_errors=True)
            shutil.rmtree(tmp_wrk_dir, ignore_errors=True)
            t_clean = time.time() - t_clean_start
            print(f"[ZAP] Cleanup complete... {t_clean:.2f}s", flush=True)

    def parse_results(self, raw_output: str, target_url: str = "") -> List[Dict[str, Any]]:
        """Parses ZAP JSON report format into standardized TrustAudit findings."""
        findings = []
        if not raw_output:
            return findings

        try:
            data = json.loads(raw_output) if isinstance(raw_output, str) and raw_output.strip().startswith("{") else {}
            site_list = data.get("site", [])
            if isinstance(site_list, dict):
                site_list = [site_list]

            for site in site_list:
                alerts = site.get("alerts", [])
                for alert in alerts:
                    name = alert.get("alert", alert.get("name", "DAST Vulnerability Alert"))
                    risk = alert.get("riskdesc", alert.get("risk", "Medium")).split(" ")[0].upper()
                    conf = alert.get("confidence", "Medium").upper()
                    desc = alert.get("desc", alert.get("description", ""))
                    sol = alert.get("solution", alert.get("remediation", ""))
                    uri = alert.get("uri", alert.get("url", target_url))
                    cwe = alert.get("cweid", "")
                    cwe_list = [f"CWE-{cwe}"] if cwe and str(cwe) != "0" else []
                    evidence = alert.get("evidence", alert.get("param", ""))

                    findings.append(normalize_finding(
                        scanner="zap",
                        category="website_security",
                        title=name,
                        description=desc or name,
                        severity=normalize_severity(risk),
                        confidence=normalize_confidence(conf),
                        file=uri,
                        evidence=evidence or "Reported by OWASP ZAP DAST engine",
                        remediation=sol or "Follow OWASP remediation best practices for this finding.",
                        references=[alert.get("reference", "")] if alert.get("reference") else [],
                        cwe=cwe_list,
                    ))

        except Exception as e:
            logger.debug(f"Failed to parse ZAP output: {e}")

        return findings
