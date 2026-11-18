"""
OSV-Scanner Integration for Dependency Vulnerability Auditing.

Discovers known CVEs and GHSA advisories in dependency manifests:
- package.json / package-lock.json / yarn.lock
- requirements.txt / Pipfile.lock / poetry.lock
- go.mod / go.sum
- pom.xml / build.gradle
"""

import json
import os
import subprocess
import time
from typing import Any, Dict, List, Optional

from scanner_integrations.base import BaseScanner, get_subprocess_env
from scanner_integrations.normalizer import normalize_finding


class OSVScanner(BaseScanner):
    """Integrates Google's OSV-Scanner CLI for dependency vulnerability analysis."""

    def __init__(self, timeout_seconds: int = 45):
        super().__init__(name="osv-scanner", timeout_seconds=timeout_seconds)

    def get_binary_path(self, candidates: Optional[List[str]] = None) -> Optional[str]:
        return super().get_binary_path(candidates or ["osv-scanner", "osv-scanner.exe"])

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Runs OSV-Scanner against a local directory or manifest file.
        """
        start_time = time.time()
        if not self.check_available():
            return {
                "scanner": self.name,
                "name": "OSV-Scanner",
                "available": False,
                "version": None,
                "executed": False,
                "status": "not_installed",
                "findings_count": 0,
                "duration": 0.0,
                "raw_findings": [],
                "normalized_findings": [],
                "error": None,
                "reason": "OSV-Scanner CLI binary is not installed in system PATH.",
            }

        if not os.path.exists(target):
            return {
                "scanner": self.name,
                "name": "OSV-Scanner",
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
        cmd = [bin_path, "--json", "-r", target] if os.path.isdir(target) else [bin_path, "--json", target]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=get_subprocess_env(),
            )

            raw_findings = self.parse_results(res.stdout or res.stderr or "")
            normalized = self.normalize_findings(raw_findings, base_folder=target)
            dur = round(time.time() - start_time, 2)

            return {
                "scanner": self.name,
                "name": "OSV-Scanner",
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
                "name": "OSV-Scanner",
                "available": True,
                "version": self.get_version(),
                "executed": True,
                "status": "failed",
                "findings_count": 0,
                "duration": round(time.time() - start_time, 2),
                "raw_findings": [],
                "normalized_findings": [],
                "error": f"OSV-Scanner exceeded timeout ({self.timeout_seconds}s).",
                "reason": "Execution timed out.",
            }
        except Exception as e:
            return {
                "scanner": self.name,
                "name": "OSV-Scanner",
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
        """Parses JSON output produced by OSV-Scanner."""
        if not raw_output or not raw_output.strip():
            return []
        try:
            data = json.loads(raw_output)
            results = data.get("results", [])
            findings = []
            for item in results:
                source = item.get("source", {}).get("path", "")
                packages = item.get("packages", [])
                for pkg_wrapper in packages:
                    pkg_info = pkg_wrapper.get("package", {})
                    pkg_name = pkg_info.get("name", "unknown")
                    pkg_version = pkg_info.get("version", "unknown")
                    pkg_ecosystem = pkg_info.get("ecosystem", "")
                    
                    vulns = pkg_wrapper.get("vulnerabilities", [])
                    for vuln in vulns:
                        findings.append({
                            "source_file": source,
                            "package_name": pkg_name,
                            "package_version": pkg_version,
                            "ecosystem": pkg_ecosystem,
                            "vuln_id": vuln.get("id", ""),
                            "aliases": vuln.get("aliases", []),
                            "summary": vuln.get("summary") or vuln.get("details", "Vulnerability advisory"),
                            "details": vuln.get("details", ""),
                            "severity": vuln.get("severity", []),
                            "database_specific": vuln.get("database_specific", {}),
                            "references": [ref.get("url") for ref in vuln.get("references", []) if ref.get("url")],
                            "affected": vuln.get("affected", []),
                        })
            return findings
        except Exception:
            return []

    def normalize_findings(self, raw_findings: List[Dict[str, Any]], base_folder: Optional[str] = None) -> List[Dict[str, Any]]:
        """Normalizes OSV-Scanner output into the standard finding schema."""
        normalized = []
        for item in raw_findings:
            pkg_name = item.get("package_name", "unknown")
            pkg_ver = item.get("package_version", "unknown")
            vuln_id = item.get("vuln_id", "UNKNOWN-ADVISORY")
            
            # Prefer CVE identifier if present in aliases
            cve_id = vuln_id if vuln_id.startswith("CVE-") else next((a for a in item.get("aliases", []) if a.startswith("CVE-")), vuln_id)
            
            source_file = item.get("source_file", "")
            if base_folder and os.path.isabs(source_file):
                source_file = os.path.relpath(source_file, base_folder)

            # Determine fixed version if present in affected ranges
            fixed_version = None
            for aff in item.get("affected", []):
                for r in aff.get("ranges", []):
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            fixed_version = ev["fixed"]
                            break

            remediation = f"Upgrade {pkg_name} to >={fixed_version}" if fixed_version else f"Upgrade {pkg_name} to a secure release version."

            # Calculate severity from CVSS or default
            severity = "HIGH"
            sev_data = item.get("severity", [])
            if isinstance(sev_data, list):
                for s in sev_data:
                    if isinstance(s, dict) and "score" in s:
                        score_str = str(s.get("score", ""))
                        if "CVSS:3" in score_str:
                            severity = "HIGH"

            title = f"Vulnerable Dependency {pkg_name} ({cve_id})"
            desc = item.get("summary") or f"Known vulnerability {cve_id} affects package {pkg_name} version {pkg_ver}."

            norm = normalize_finding(
                scanner="osv-scanner",
                category="dependencies",
                title=title,
                description=desc,
                severity=severity,
                confidence="CONFIRMED",
                file=source_file or "manifest",
                package=pkg_name,
                version=pkg_ver,
                cve=cve_id,
                evidence=f"{pkg_name}=={pkg_ver} is vulnerable to {cve_id}",
                remediation=remediation,
                references=item.get("references", []),
                raw_details=item,
            )
            normalized.append(norm)
        return normalized
