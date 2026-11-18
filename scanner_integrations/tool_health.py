"""
Tool Health and Installation Registry for TrustAudit Security Engines.

Tracks operational health, binary availability, versioning, executable paths,
last execution timestamps, and setup/installation guidance for all supported tools:
- Docker Container Runtime & Daemon Status
- OWASP ZAP DAST Scanner (Docker & Local)
- Proprietary MCP Security Engine
- Semgrep Semantic SAST Engine
- Bandit Python SAST Engine
- Checkov IaC Security Engine
- Gitleaks CORE Secret Scanner
- OSV-Scanner Dependency Auditor
- Trivy Filesystem & Misconfig Scanner
- Nuclei Live Web AppSec Scanner
- Syft SBOM Generation Engine
- Passive Web & TLS Security Engine
"""

import os
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from scanner_integrations.base import get_extended_search_paths, get_subprocess_env


SETUP_GUIDES = {
    "docker": {
        "title": "Docker Container Engine",
        "description": "Container virtualization runtime for isolated security scanning (ZAP, Trivy, etc.).",
        "category": "Container Infrastructure",
        "install_commands": {
            "windows": "winget install Docker.DockerDesktop  # Start Docker Desktop after install",
            "macos": "brew install --cask docker  # Start Docker Desktop",
            "linux": "sudo apt-get install docker.io && sudo systemctl start docker",
        },
        "docs_url": "https://docs.docker.com/engine/install/",
    },
    "zap": {
        "title": "OWASP ZAP DAST Scanner",
        "description": "Open Web Application Security Project (OWASP) Zed Attack Proxy dynamic vulnerability scanner.",
        "category": "Dynamic Web Application Security (DAST)",
        "install_commands": {
            "docker": "docker pull ghcr.io/zaproxy/zaproxy:stable  # Preferred official container",
            "windows": "winget install OWASP.ZAP  # or: choco install zaproxy",
            "macos": "brew install --cask zaproxy",
            "linux": "sudo apt-get install zaproxy  # or download official ZAP from zaproxy.org",
        },
        "docs_url": "https://www.zaproxy.org/docs/docker/baseline-scan/",
    },
    "bandit": {
        "title": "Bandit Python SAST Engine",
        "description": "Security-focused static analysis tool designed to find common security issues in Python code.",
        "category": "Static Application Security Testing (SAST)",
        "install_commands": {
            "all": "pip install bandit",
        },
        "docs_url": "https://github.com/PyCQA/bandit",
    },
    "checkov": {
        "title": "Checkov IaC Security Engine",
        "description": "Static code analysis tool for Infrastructure as Code (Terraform, Kubernetes, Dockerfile).",
        "category": "Infrastructure as Code (IaC)",
        "install_commands": {
            "all": "pip install checkov",
        },
        "docs_url": "https://github.com/bridgecrewio/checkov",
    },
    "nuclei": {
        "title": "ProjectDiscovery Nuclei",
        "description": "Fast and customizable live vulnerability scanner based on simple YAML DSL.",
        "category": "Live Application Security",
        "install_commands": {
            "windows": "winget install ProjectDiscovery.Nuclei  # or: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "macos": "brew install nuclei",
            "linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        },
        "docs_url": "https://github.com/projectdiscovery/nuclei",
    },
    "gitleaks": {
        "title": "Gitleaks CORE CLI",
        "description": "High-performance credential, token, and API key scanner.",
        "category": "Secret Detection",
        "install_commands": {
            "windows": "winget install Gitleaks.Gitleaks  # or: choco install gitleaks",
            "macos": "brew install gitleaks",
            "linux": "go install github.com/gitleaks/gitleaks/v8@latest",
        },
        "docs_url": "https://github.com/gitleaks/gitleaks",
    },
    "osv_scanner": {
        "title": "Google OSV-Scanner",
        "description": "Vulnerability scanner powered by the Open Source Vulnerability (OSV) database.",
        "category": "Dependency Security",
        "install_commands": {
            "windows": "winget install Google.OSV-Scanner  # or: go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
            "macos": "brew install osv-scanner",
            "linux": "go install github.com/google/osv-scanner/cmd/osv-scanner@latest",
        },
        "docs_url": "https://github.com/google/osv-scanner",
    },
    "trivy": {
        "title": "Aqua Security Trivy",
        "description": "Comprehensive security scanner for container images, filesystems, and configurations.",
        "category": "Filesystem & Misconfiguration",
        "install_commands": {
            "windows": "winget install AquaSecurity.Trivy  # or: choco install trivy",
            "macos": "brew install trivy",
            "linux": "sudo apt-get install wget apt-transport-https gnupg lsb-release && ... # see Trivy installation docs",
        },
        "docs_url": "https://github.com/aquasecurity/trivy",
    },
    "syft": {
        "title": "Anchore Syft",
        "description": "CLI tool and library for generating Software Bill of Materials (SBOM) from filesystems.",
        "category": "SBOM Generation",
        "install_commands": {
            "windows": "winget install Anchore.Syft  # or: choco install syft",
            "macos": "brew install syft",
            "linux": "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
        },
        "docs_url": "https://github.com/anchore/syft",
    },
    "semgrep": {
        "title": "Semgrep SAST",
        "description": "Fast, lightweight static analysis engine for finding bugs and enforcing code standards.",
        "category": "Static Application Security Testing (SAST)",
        "install_commands": {
            "windows": "pip install semgrep",
            "macos": "brew install semgrep  # or: pip install semgrep",
            "linux": "pip install semgrep",
        },
        "docs_url": "https://github.com/semgrep/semgrep",
    },
    "mcp_engine": {
        "title": "Proprietary MCP Security Engine",
        "description": "TrustAudit core AST and semantic analyzer for Model Context Protocol servers and tools.",
        "category": "MCP Security & Behavioral Auditing",
        "install_commands": {
            "all": "Built into TrustAudit platform (No external CLI required)",
        },
        "docs_url": "https://modelcontextprotocol.io",
    },
    "passive_web": {
        "title": "Passive Web & TLS Security Engine",
        "description": "TrustAudit native HTTP header, TLS certificate, cookie security, and CORS analyzer.",
        "category": "Web Security & Perimeter Posture",
        "install_commands": {
            "all": "Built into TrustAudit platform (No external CLI required)",
        },
        "docs_url": "https://trustaudit.io",
    },
}

# Global registry tracking execution telemetry across the lifetime of the application
_TOOL_EXECUTION_HISTORY: Dict[str, Dict[str, Any]] = {}


def record_tool_execution(tool_id: str, status: str, duration: float, findings_count: int, error: Optional[str] = None):
    """Records the timestamp and outcome of a tool execution."""
    _TOOL_EXECUTION_HISTORY[tool_id] = {
        "last_execution_time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "last_status": status,
        "last_duration": round(duration, 2),
        "last_findings_count": findings_count,
        "last_error": error,
    }


def check_docker_runtime_health() -> Dict[str, Any]:
    """Inspects host Docker CLI and Daemon health."""
    docker_bin = shutil.which("docker", path=get_subprocess_env().get("PATH"))
    if not docker_bin:
        return {
            "installed": False,
            "daemon_running": False,
            "version": None,
            "status": "NOT_INSTALLED",
            "message": "Docker CLI binary not found in PATH",
        }
    try:
        res = subprocess.run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=3,
            env=get_subprocess_env(),
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return {
                "installed": True,
                "daemon_running": True,
                "version": f"Docker {res.stdout.strip()}",
                "status": "HEALTHY",
                "message": "Docker Engine daemon is active and responsive",
            }
        else:
            return {
                "installed": True,
                "daemon_running": False,
                "version": "Docker CLI Installed",
                "status": "DAEMON_NOT_RUNNING",
                "message": "Docker CLI is installed, but Docker Desktop / Engine daemon is not running.",
            }
    except Exception as e:
        return {
            "installed": True,
            "daemon_running": False,
            "version": "Docker CLI Installed",
            "status": "DAEMON_NOT_RUNNING",
            "message": f"Could not connect to Docker daemon: {e}",
        }


def get_all_tool_health(orchestrator_instance=None) -> List[Dict[str, Any]]:
    """
    Returns comprehensive operational health, versions, executable paths,
    and installation instructions for all scanner engines.
    """
    from scanner_integrations.gitleaks import GitleaksScanner
    from scanner_integrations.osv_scanner import OSVScanner
    from scanner_integrations.trivy import TrivyScanner
    from scanner_integrations.nuclei import NucleiScanner
    from scanner_integrations.syft import SyftScanner
    from scanner_integrations.zap import ZapScanner
    from scanner_integrations.bandit import BanditScanner
    from scanner_integrations.checkov import CheckovScanner

    scanner_instances = {
        "zap": ZapScanner(),
        "bandit": BanditScanner(),
        "checkov": CheckovScanner(),
        "gitleaks": GitleaksScanner(),
        "osv_scanner": OSVScanner(),
        "trivy": TrivyScanner(),
        "nuclei": NucleiScanner(),
        "syft": SyftScanner(),
    }

    tools = [
        ("docker", "Docker Container Engine", False, None, None),
        ("zap", "OWASP ZAP DAST Scanner", False, None, None),
        ("mcp_engine", "Proprietary MCP Security Engine", True, "2.0 (Built-in)", "Built-in AST Engine"),
        ("passive_web", "Passive Web & TLS Security Engine", True, "2.0 (Built-in)", "Built-in Web Auditor"),
        ("semgrep", "Semgrep Semantic SAST Engine", None, None, None),
        ("bandit", "Bandit Python SAST Engine", False, None, None),
        ("checkov", "Checkov IaC Security Engine", False, None, None),
        ("gitleaks", "Gitleaks CORE Secret Scanner", False, None, None),
        ("osv_scanner", "Google OSV-Scanner", False, None, None),
        ("trivy", "Aqua Security Trivy", False, None, None),
        ("nuclei", "ProjectDiscovery Nuclei Live Scanner", False, None, None),
        ("syft", "Anchore Syft SBOM Engine", False, None, None),
    ]

    docker_health = check_docker_runtime_health()
    health_list = []

    for tool_id, tool_name, is_builtin, builtin_ver, builtin_path in tools:
        guide = SETUP_GUIDES.get(tool_id, {})
        history = _TOOL_EXECUTION_HISTORY.get(tool_id, {})

        if tool_id == "docker":
            available = docker_health["daemon_running"]
            version = docker_health["version"] or "Not Running"
            bin_path = shutil.which("docker")
            status = docker_health["status"]
            desc = guide.get("description", "") + f" ({docker_health['message']})"
        elif is_builtin:
            available = True
            version = builtin_ver
            bin_path = builtin_path
            status = "HEALTHY"
            desc = guide.get("description", "")
        elif tool_id == "semgrep":
            from run_semgrep import _get_semgrep_env_and_candidates
            candidates, env = _get_semgrep_env_and_candidates()
            bin_path = candidates[0][0] if candidates and candidates[0] != ["semgrep"] else shutil.which("semgrep", path=env.get("PATH"))
            available = bin_path is not None
            version = "1.172.0" if available else None
            status = "HEALTHY" if available else "NOT_INSTALLED"
            desc = guide.get("description", "")
        else:
            scanner = scanner_instances.get(tool_id)
            available = scanner.check_available() if scanner else False
            bin_path = scanner.get_binary_path() if scanner and available else None
            version = scanner.get_version() if scanner and available else None
            status = "HEALTHY" if available else "NOT_INSTALLED"
            desc = guide.get("description", "")

        health_list.append({
            "id": tool_id,
            "name": tool_name,
            "category": guide.get("category", "Security Scanner"),
            "description": desc,
            "installed": available,
            "status": status,
            "version": version or "Not Available",
            "executable_path": bin_path or "None",
            "last_execution": history.get("last_execution_time", "Never executed in current session"),
            "last_status": history.get("last_status", "IDLE"),
            "last_findings_count": history.get("last_findings_count", 0),
            "last_duration": history.get("last_duration", 0.0),
            "install_commands": guide.get("install_commands", {}),
            "docs_url": guide.get("docs_url", ""),
        })

    return health_list
