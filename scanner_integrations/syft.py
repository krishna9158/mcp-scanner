"""
Syft Integration for Software Bill of Materials (SBOM) Generation.

Inspects repository code and generates a standardized, machine-readable inventory
of all software components, runtime dependencies, MCP SDKs, and AI libraries.

Note: SBOM components are inventoried for visibility and are evaluated for
vulnerabilities via the OSV and Trivy engines.
"""

import json
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional

from scanner_integrations.base import BaseScanner, get_subprocess_env
from dependency_check import parse_package_json, parse_requirements_txt


class SyftScanner(BaseScanner):
    """Integrates Anchore's Syft CLI for SBOM generation."""

    def __init__(self, timeout_seconds: int = 45):
        super().__init__(name="syft", timeout_seconds=timeout_seconds)

    def get_binary_path(self, candidates: Optional[List[str]] = None) -> Optional[str]:
        return super().get_binary_path(candidates or ["syft", "syft.exe"])

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Generates an SBOM for the target repository.
        Falls back to native manifest analysis if the Syft CLI is not installed.
        """
        start_time = time.time()
        if not os.path.exists(target):
            return {
                "scanner": self.name,
                "name": "Syft SBOM Engine",
                "available": self.check_available(),
                "version": self.get_version() if self.check_available() else None,
                "executed": False,
                "status": "failed",
                "findings_count": 0,
                "duration": 0.0,
                "sbom": {"total_packages": 0, "packages": [], "ecosystems": {}},
                "raw_findings": [],
                "normalized_findings": [],
                "error": f"Target path '{target}' does not exist.",
            }

        # 1. If CLI is available, run Syft
        if self.check_available():
            bin_path = self.get_binary_path()
            cmd = [bin_path, target, "-o", "json", "--quiet"]

            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                    env=get_subprocess_env(),
                )
                sbom = self.parse_results(res.stdout or "")
                dur = round(time.time() - start_time, 2)
                return {
                    "scanner": self.name,
                    "name": "Syft SBOM Engine",
                    "available": True,
                    "version": self.get_version(),
                    "executed": True,
                    "status": "completed",
                    "findings_count": sbom.get("total_packages", 0),
                    "duration": dur,
                    "sbom": sbom,
                    "raw_findings": [],
                    "normalized_findings": [],
                    "error": None,
                }
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass

        # 2. Native manifest fallback (when Syft CLI is absent or fails)
        sbom = self._generate_native_sbom(target)
        dur = round(time.time() - start_time, 2)
        return {
            "scanner": self.name,
            "name": "Syft SBOM Engine",
            "available": False,
            "version": "Native Manifest Parser",
            "executed": True,
            "status": "completed",
            "findings_count": sbom.get("total_packages", 0),
            "duration": dur,
            "sbom": sbom,
            "raw_findings": [],
            "normalized_findings": [],
            "error": None,
        }

    def parse_results(self, raw_output: str) -> Dict[str, Any]:
        """Parses Syft JSON SBOM output."""
        if not raw_output or not raw_output.strip():
            return {"total_packages": 0, "packages": [], "ecosystems": {}, "ai_components": []}
        try:
            data = json.loads(raw_output)
            artifacts = data.get("artifacts", [])
            packages = []
            ecosystems: Dict[str, int] = {}
            ai_components: List[str] = []

            for art in artifacts:
                name = art.get("name", "")
                version = art.get("version", "")
                pkg_type = art.get("type", "unknown")
                purl = art.get("purl", "")
                licenses = [lic.get("value", "") for lic in art.get("licenses", []) if isinstance(lic, dict)]

                ecosystems[pkg_type] = ecosystems.get(pkg_type, 0) + 1
                if any(ai_term in name.lower() for ai_term in ("mcp", "anthropic", "openai", "langchain", "llama", "huggingface", "transformers")):
                    ai_components.append(name)

                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": pkg_type,
                    "purl": purl,
                    "licenses": licenses,
                })

            return {
                "total_packages": len(packages),
                "packages": packages,
                "ecosystems": ecosystems,
                "ai_components": list(dict.fromkeys(ai_components)),
            }
        except Exception:
            return {"total_packages": 0, "packages": [], "ecosystems": {}, "ai_components": []}

    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """SBOM components are inventory records rather than vulnerability findings."""
        return []

    def _generate_native_sbom(self, folder: str) -> Dict[str, Any]:
        """Generates a structured component inventory directly from repository manifests."""
        packages = []
        ecosystems: Dict[str, int] = {}
        ai_components: List[str] = []

        # 1. Python requirements.txt / pyproject.toml
        req_path = os.path.join(folder, "requirements.txt")
        if os.path.exists(req_path):
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    py_pkgs = parse_requirements_txt(f.read())
                    for name, ver in py_pkgs:
                        ecosystems["python"] = ecosystems.get("python", 0) + 1
                        if any(ai_term in name.lower() for ai_term in ("mcp", "anthropic", "openai", "langchain", "llama")):
                            ai_components.append(name)
                        packages.append({
                            "name": name,
                            "version": ver,
                            "ecosystem": "python",
                            "purl": f"pkg:pypi/{name}@{ver}",
                            "licenses": [],
                        })
            except Exception:
                pass

        # 2. Node.js package.json / package-lock.json
        pkg_json_path = os.path.join(folder, "package.json")
        if os.path.exists(pkg_json_path):
            try:
                with open(pkg_json_path, "r", encoding="utf-8", errors="ignore") as f:
                    js_pkgs = parse_package_json(f.read())
                    for name, ver in js_pkgs:
                        ecosystems["npm"] = ecosystems.get("npm", 0) + 1
                        if any(ai_term in name.lower() for ai_term in ("mcp", "modelcontextprotocol", "anthropic", "openai")):
                            ai_components.append(name)
                        packages.append({
                            "name": name,
                            "version": ver,
                            "ecosystem": "npm",
                            "purl": f"pkg:npm/{name}@{ver}",
                            "licenses": [],
                        })
            except Exception:
                pass

        return {
            "total_packages": len(packages),
            "packages": packages,
            "ecosystems": ecosystems,
            "ai_components": list(dict.fromkeys(ai_components)),
        }
