"""
Checkov Infrastructure-as-Code (IaC) Scanner Adapter for TrustAudit Platform.

Analyzes Terraform, CloudFormation, Kubernetes manifests, Dockerfile, Helm charts,
and CI/CD pipelines for security misconfigurations and compliance violations.
Includes a native AST/pattern fallback parser when the Checkov CLI is not installed.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from scanner_integrations.base import BaseScanner, get_subprocess_env
from scanner_integrations.normalizer import normalize_finding, normalize_severity, normalize_confidence

logger = logging.getLogger("trustaudit.checkov")


class CheckovScanner(BaseScanner):
    """Adapter for Checkov Infrastructure as Code security engine."""

    def __init__(self, timeout_seconds: int = 45):
        super().__init__(name="Checkov IaC Security Engine", timeout_seconds=timeout_seconds)

    def get_binary_candidates(self) -> List[str]:
        return ["checkov", "checkov.exe", "checkov.cmd"]

    def check_available(self) -> bool:
        return self.get_binary_path(self.get_binary_candidates()) is not None

    def get_version(self) -> str:
        if self._cached_version:
            return self._cached_version
        bin_path = self.get_binary_path(self.get_binary_candidates())
        if not bin_path:
            return "3.2.0 (Native IaC Engine Active)"
        try:
            env = get_subprocess_env()
            res = subprocess.run([bin_path, "-v"], capture_output=True, text=True, timeout=5, env=env)
            ver = res.stdout.strip()
            self._cached_version = ver if ver else "3.2.0"
            return self._cached_version
        except Exception:
            return "3.2.0"

    def scan(self, target_dir: str, **kwargs) -> Dict[str, Any]:
        """
        Scans IaC files in target directory.
        Uses Checkov CLI if installed; otherwise executes native IaC analyzer.
        """
        t0 = time.time()
        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        if not os.path.exists(target_dir):
            return {
                "engine": "checkov",
                "name": self.name,
                "status": "FAILED",
                "duration_ms": 0,
                "findings": [],
                "errors": [f"Directory not found: {target_dir}"],
                "metadata": {"target": target_dir},
            }

        bin_path = self.get_binary_path(self.get_binary_candidates())
        if bin_path:
            try:
                env = get_subprocess_env()
                cmd = [bin_path, "-d", target_dir, "-o", "json", "--quiet", "--compact"]
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    env=env,
                )
                raw_out = proc.stdout
                findings = self.parse_results(raw_out, target_dir)
                dur_ms = int((time.time() - t0) * 1000)
                return {
                    "engine": "checkov",
                    "name": self.name,
                    "status": "COMPLETED",
                    "duration_ms": dur_ms,
                    "findings": findings,
                    "errors": errors,
                    "metadata": {"mode": "cli", "findings_count": len(findings)},
                }
            except subprocess.TimeoutExpired:
                errors.append(f"Checkov CLI timed out after {self.timeout_seconds}s. Falling back to native IaC engine.")
            except Exception as e:
                errors.append(f"Checkov CLI execution failed: {e}. Falling back to native IaC engine.")

        # Native IaC Engine Fallback
        native_findings = self._native_iac_scan(target_dir)
        findings.extend(native_findings)
        dur_ms = int((time.time() - t0) * 1000)

        return {
            "engine": "checkov",
            "name": self.name,
            "status": "COMPLETED",
            "duration_ms": dur_ms,
            "findings": findings,
            "errors": errors,
            "metadata": {"mode": "native_iac_engine", "findings_count": len(findings)},
        }

    def _native_iac_scan(self, target_dir: str) -> List[Dict[str, Any]]:
        """Native deterministic parser for Dockerfile, Kubernetes, and Terraform misconfigurations."""
        findings = []

        for root, _, files in os.walk(target_dir):
            if any(p in root for p in [".git", "node_modules", "venv", "__pycache__", "dist", "build"]):
                continue

            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, target_dir).replace("\\", "/")

                # 1. Dockerfile checks
                if fname.lower() in ("dockerfile", "containerfile") or fname.lower().endswith(".dockerfile"):
                    findings.extend(self._audit_dockerfile(fpath, rel_path))

                # 2. Kubernetes YAML checks
                elif fname.endswith((".yaml", ".yml")):
                    findings.extend(self._audit_k8s_yaml(fpath, rel_path))

                # 3. Terraform .tf checks
                elif fname.endswith(".tf"):
                    findings.extend(self._audit_terraform(fpath, rel_path))

        return findings

    def _audit_dockerfile(self, filepath: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            has_user = False
            has_healthcheck = False

            for i, line in enumerate(lines, 1):
                clean_l = line.strip()
                if clean_l.startswith("#"):
                    continue

                if re.match(r"^USER\s+", clean_l, re.IGNORECASE):
                    has_user = True
                    if "root" in clean_l.lower() or "0" in clean_l:
                        findings.append(normalize_finding(
                            scanner="checkov",
                            category="misconfiguration",
                            title="Container Running as Root User",
                            description="Dockerfile explicitly configures the container to execute with root privileges.",
                            severity="HIGH",
                            confidence="CONFIRMED",
                            file=rel_path,
                            line=i,
                            evidence=clean_l,
                            remediation="Create a dedicated non-root service user: 'USER nonroot' or 'USER 10001'.",
                            references=["https://docs.docker.com/engine/security/"],
                            cwe=["CWE-250"],
                        ))

                if re.match(r"^HEALTHCHECK\s+", clean_l, re.IGNORECASE):
                    has_healthcheck = True

                # Check for latest tag
                if re.match(r"^FROM\s+.*:latest", clean_l, re.IGNORECASE) or (re.match(r"^FROM\s+\S+", clean_l, re.IGNORECASE) and ":" not in clean_l.split()[1] and "@" not in clean_l.split()[1]):
                    findings.append(normalize_finding(
                        scanner="checkov",
                        category="misconfiguration",
                        title="Base Image Uses Untagged or 'latest' Version",
                        description="Base container image references mutable 'latest' tag, creating build reproducibility and supply chain risks.",
                        severity="LOW",
                        confidence="CONFIRMED",
                        file=rel_path,
                        line=i,
                        evidence=clean_l,
                        remediation="Pin base image to an immutable digest (e.g. node@sha256:...) or specific semantic version tag.",
                        cwe=["CWE-1104"],
                    ))

                # Hardcoded secrets in ENV or ARG
                if re.match(r"^(ENV|ARG)\s+.*(KEY|SECRET|PASSWORD|TOKEN|AUTH)\s*=", clean_l, re.IGNORECASE):
                    if not re.search(r"=\s*(\$\{.*\}|\"\"|''|\$\(.*\))\s*$", clean_l):
                        findings.append(normalize_finding(
                            scanner="checkov",
                            category="secrets",
                            title="Hardcoded Credential in Dockerfile Instruction",
                            description="Sensitive secret or password defined directly inside container image layers.",
                            severity="HIGH",
                            confidence="CONFIRMED",
                            file=rel_path,
                            line=i,
                            evidence=clean_l[:30] + "...[REDACTED]",
                            remediation="Pass credentials securely at runtime using Docker BuildKit secrets or container secret managers.",
                            cwe=["CWE-798"],
                        ))

            if not has_user and len(lines) > 2:
                findings.append(normalize_finding(
                    scanner="checkov",
                    category="misconfiguration",
                    title="Missing USER Instruction in Dockerfile",
                    description="No USER instruction defined; container will execute as root by default.",
                    severity="MEDIUM",
                    confidence="CONFIRMED",
                    file=rel_path,
                    line=1,
                    evidence="No USER directive found",
                    remediation="Add 'USER nonroot' before ENTRYPOINT/CMD to minimize container privilege escalation.",
                    cwe=["CWE-250"],
                ))
        except Exception:
            pass
        return findings

    def _audit_k8s_yaml(self, filepath: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            if "apiVersion" not in content or "kind" not in content:
                return findings

            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                clean_l = line.strip()
                if "privileged: true" in clean_l:
                    findings.append(normalize_finding(
                        scanner="checkov",
                        category="misconfiguration",
                        title="Kubernetes Container Running in Privileged Mode",
                        description="SecurityContext specifies privileged: true, granting container access to all host devices.",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        file=rel_path,
                        line=i,
                        evidence=clean_l,
                        remediation="Set 'securityContext.privileged: false' and grant specific Linux capabilities if required.",
                        cwe=["CWE-250"],
                    ))
                if "hostNetwork: true" in clean_l:
                    findings.append(normalize_finding(
                        scanner="checkov",
                        category="misconfiguration",
                        title="Kubernetes Pod Shares Host Network Namespace",
                        description="hostNetwork: true exposes container network traffic directly to the host network stack.",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        file=rel_path,
                        line=i,
                        evidence=clean_l,
                        remediation="Disable hostNetwork or isolate workload within dedicated Kubernetes network policies.",
                        cwe=["CWE-668"],
                    ))
                if "allowPrivilegeEscalation: true" in clean_l:
                    findings.append(normalize_finding(
                        scanner="checkov",
                        category="misconfiguration",
                        title="Kubernetes Container Allows Privilege Escalation",
                        description="Container process can gain more privileges than its parent process (allowPrivilegeEscalation: true).",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        file=rel_path,
                        line=i,
                        evidence=clean_l,
                        remediation="Set 'securityContext.allowPrivilegeEscalation: false'.",
                        cwe=["CWE-250"],
                    ))
        except Exception:
            pass
        return findings

    def _audit_terraform(self, filepath: str, rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                clean_l = line.strip()
                # Unrestricted ingress
                if re.search(r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"\s*\]", clean_l) and "0.0.0.0/0" in clean_l:
                    findings.append(normalize_finding(
                        scanner="checkov",
                        category="misconfiguration",
                        title="Terraform Security Group Exposes Open Ingress (0.0.0.0/0)",
                        description="Security group ingress rule opens port access to the entire public Internet.",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        file=rel_path,
                        line=i,
                        evidence=clean_l,
                        remediation="Restrict ingress cidr_blocks to authorized corporate CIDRs or VPC boundaries.",
                        cwe=["CWE-284"],
                    ))
                # Unencrypted S3 bucket / storage
                if re.search(r"acl\s*=\s*\"public-read\"", clean_l):
                    findings.append(normalize_finding(
                        scanner="checkov",
                        category="misconfiguration",
                        title="Cloud Storage Bucket Configured with Public Read Access",
                        description="Storage resource explicitly enables public read access (acl = 'public-read').",
                        severity="CRITICAL",
                        confidence="CONFIRMED",
                        file=rel_path,
                        line=i,
                        evidence=clean_l,
                        remediation="Configure 'acl = \"private\"' and enable AWS S3 Block Public Access.",
                        cwe=["CWE-732"],
                    ))
        except Exception:
            pass
        return findings

    def parse_results(self, raw_output: str, target_dir: str) -> List[Dict[str, Any]]:
        """Parses Checkov JSON output into normalized findings."""
        findings = []
        if not raw_output:
            return findings
        try:
            data = json.loads(raw_output)
            results = data if isinstance(data, list) else [data]
            for block in results:
                checks = block.get("results", {}).get("failed_checks", [])
                for check in checks:
                    check_id = check.get("check_id", "CKV_IAC")
                    name = check.get("check_name", "IaC Security Check")
                    fpath = check.get("file_path", "")
                    lines = check.get("file_line_range", [1, 1])
                    guideline = check.get("guideline", "")
                    
                    findings.append(normalize_finding(
                        scanner="checkov",
                        category="misconfiguration",
                        title=f"{check_id}: {name}",
                        description=check.get("check_name", ""),
                        severity="HIGH",
                        confidence="CONFIRMED",
                        file=fpath.lstrip("/"),
                        line=lines[0] if lines else 1,
                        evidence=f"Failed check {check_id} on resource {check.get('resource', '')}",
                        remediation=guideline or "Remediate infrastructure template according to CIS/Cloud provider benchmarks.",
                        references=[guideline] if guideline else [],
                    ))
        except Exception as e:
            logger.debug(f"Failed to parse Checkov JSON: {e}")
        return findings
