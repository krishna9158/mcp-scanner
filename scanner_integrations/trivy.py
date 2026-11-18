"""
Trivy Integration for Vulnerability and Misconfiguration Auditing.

Performs broad security analysis across filesystem assets:
- Vulnerable package dependencies
- IaC / Configuration security flaws (Dockerfile, Kubernetes, Terraform)
- Insecure repository settings
"""

import json
import os
import subprocess
import time
from typing import Any, Dict, List, Optional

from scanner_integrations.base import BaseScanner, get_subprocess_env
from scanner_integrations.normalizer import normalize_finding


class TrivyScanner(BaseScanner):
    """Integrates Aqua Security's Trivy CLI for filesystem and misconfiguration analysis."""

    def __init__(self, timeout_seconds: int = 45):
        super().__init__(name="trivy", timeout_seconds=timeout_seconds)

    def get_binary_path(self, candidates: Optional[List[str]] = None) -> Optional[str]:
        return super().get_binary_path(candidates or ["trivy", "trivy.exe"])

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Runs Trivy selective filesystem scan.
        """
        start_time = time.time()
        if not self.check_available():
            return {
                "scanner": self.name,
                "name": "Trivy Filesystem & Misconfig Scanner",
                "available": False,
                "version": None,
                "executed": False,
                "status": "not_installed",
                "findings_count": 0,
                "duration": 0.0,
                "raw_findings": [],
                "normalized_findings": [],
                "error": None,
                "reason": "Trivy CLI binary is not installed in system PATH.",
            }

        if not os.path.exists(target):
            return {
                "scanner": self.name,
                "name": "Trivy Filesystem & Misconfig Scanner",
                "available": True,
                "version": self.get_version(),
                "executed": False,
                "status": "failed",
                "findings_count": 0,
                "duration": round(time.time() - start_time, 2),
                "raw_findings": [],
                "normalized_findings": [],
                "error": f"Target path '{target}' does not exist.",
                "reason": "Invalid target directory.",
            }

        bin_path = self.get_binary_path()
        cmd = [
            bin_path,
            "fs",
            "--format", "json",
            "--scanners", "vuln,misconfig",
            "--quiet",
            target,
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=get_subprocess_env(),
            )

            raw_findings = self.parse_results(res.stdout or "")
            normalized = self.normalize_findings(raw_findings, base_folder=target)
            dur = round(time.time() - start_time, 2)

            return {
                "scanner": self.name,
                "name": "Trivy Filesystem & Misconfig Scanner",
                "available": True,
                "version": self.get_version(),
                "executed": True,
                "status": "completed",
                "findings_count": len(normalized),
                "duration": dur,
                "raw_findings": raw_findings,
                "normalized_findings": normalized,
                "error": None,
            }

        except subprocess.TimeoutExpired:
            return {
                "scanner": self.name,
                "name": "Trivy Filesystem & Misconfig Scanner",
                "available": True,
                "version": self.get_version(),
                "executed": True,
                "status": "failed",
                "findings_count": 0,
                "duration": round(time.time() - start_time, 2),
                "raw_findings": [],
                "normalized_findings": [],
                "error": f"Trivy scan exceeded timeout ({self.timeout_seconds}s).",
                "reason": "Execution timed out.",
            }
        except Exception as e:
            return {
                "scanner": self.name,
                "name": "Trivy Filesystem & Misconfig Scanner",
                "available": True,
                "version": self.get_version(),
                "executed": True,
                "status": "failed",
                "findings_count": 0,
                "duration": round(time.time() - start_time, 2),
                "raw_findings": [],
                "normalized_findings": [],
                "error": str(e),
            }

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parses Trivy JSON format output."""
        if not raw_output or not raw_output.strip():
            return []
        try:
            data = json.loads(raw_output)
            results = data.get("Results", [])
            findings = []
            for res_block in results:
                target_file = res_block.get("Target", "")
                
                # 1. Vulnerabilities
                for vuln in res_block.get("Vulnerabilities", []):
                    findings.append({
                        "type": "vulnerability",
                        "target_file": target_file,
                        "vulnerability_id": vuln.get("VulnerabilityID", ""),
                        "pkg_name": vuln.get("PkgName", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": vuln.get("FixedVersion", ""),
                        "severity": vuln.get("Severity", "MEDIUM"),
                        "title": vuln.get("Title") or f"Vulnerability {vuln.get('VulnerabilityID')}",
                        "description": vuln.get("Description", ""),
                        "primary_url": vuln.get("PrimaryURL", ""),
                        "references": vuln.get("References", []),
                    })
                
                # 2. Misconfigurations
                for misconf in res_block.get("Misconfigurations", []):
                    findings.append({
                        "type": "misconfiguration",
                        "target_file": target_file,
                        "vulnerability_id": misconf.get("ID", ""),
                        "title": misconf.get("Title", "Security Misconfiguration"),
                        "description": misconf.get("Description", ""),
                        "message": misconf.get("Message", ""),
                        "severity": misconf.get("Severity", "MEDIUM"),
                        "remediation": misconf.get("Resolution", ""),
                        "references": misconf.get("References", []),
                        "line": misconf.get("CauseMetadata", {}).get("StartLine"),
                    })
            return findings
        except Exception:
            return []

    def normalize_findings(self, raw_findings: List[Dict[str, Any]], base_folder: Optional[str] = None) -> List[Dict[str, Any]]:
        """Normalizes Trivy findings into the standard format."""
        normalized = []
        for item in raw_findings:
            target_file = item.get("target_file", "")
            if base_folder and os.path.isabs(target_file):
                target_file = os.path.relpath(target_file, base_folder)

            ftype = item.get("type", "vulnerability")
            vuln_id = item.get("vulnerability_id", "TRIVY-SEC")
            sev = item.get("severity", "MEDIUM")

            if ftype == "vulnerability":
                pkg_name = item.get("pkg_name", "unknown")
                pkg_ver = item.get("installed_version", "")
                fixed_ver = item.get("fixed_version")
                remediation = f"Upgrade {pkg_name} to >={fixed_ver}" if fixed_ver else "Upgrade package to a patched release version."

                norm = normalize_finding(
                    scanner="trivy",
                    category="dependencies",
                    title=f"Vulnerable Package {pkg_name} ({vuln_id})",
                    description=item.get("description") or f"Package {pkg_name} has known advisory {vuln_id}.",
                    severity=sev,
                    confidence="CONFIRMED",
                    file=target_file,
                    package=pkg_name,
                    version=pkg_ver,
                    cve=vuln_id if vuln_id.startswith("CVE-") else None,
                    evidence=f"Package {pkg_name} {pkg_ver} flagged with {vuln_id}",
                    remediation=remediation,
                    references=item.get("references", []),
                    raw_details=item,
                )
            else:
                norm = normalize_finding(
                    scanner="trivy",
                    category="misconfiguration",
                    title=item.get("title", f"Misconfiguration ({vuln_id})"),
                    description=item.get("description") or item.get("message", ""),
                    severity=sev,
                    confidence="LIKELY",
                    file=target_file,
                    line=item.get("line"),
                    evidence=item.get("message") or f"Rule match: {vuln_id}",
                    remediation=item.get("remediation") or "Update configuration according to security hardening guidelines.",
                    references=item.get("references", []),
                    raw_details=item,
                )
            normalized.append(norm)
        return normalized
