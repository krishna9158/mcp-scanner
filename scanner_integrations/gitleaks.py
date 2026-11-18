"""
Gitleaks Integration for Secret Detection.

Detects exposed API keys, cloud credentials, tokens, passwords, and private keys.
Executes the Gitleaks Core CLI with zero secret leakage in logs or findings.
"""

import json
import os
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional

from scanner_integrations.base import BaseScanner, get_subprocess_env
from scanner_integrations.normalizer import normalize_finding, redact_secret_string


class GitleaksScanner(BaseScanner):
    """Integrates Gitleaks CLI for repository credential detection."""

    def __init__(self, timeout_seconds: int = 30):
        super().__init__(name="gitleaks", timeout_seconds=timeout_seconds)

    def get_binary_path(self, candidates: Optional[List[str]] = None) -> Optional[str]:
        return super().get_binary_path(candidates or ["gitleaks", "gitleaks.exe"])

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Runs Gitleaks against a local repository directory.
        """
        start_time = time.time()
        if not self.check_available():
            return {
                "scanner": self.name,
                "name": "Gitleaks Secret Scanner",
                "available": False,
                "version": None,
                "executed": False,
                "status": "not_installed",
                "findings_count": 0,
                "duration": 0.0,
                "raw_findings": [],
                "normalized_findings": [],
                "error": None,
                "reason": "Gitleaks CORE CLI binary is not installed in system PATH.",
            }

        if not os.path.exists(target) or not os.path.isdir(target):
            return {
                "scanner": self.name,
                "name": "Gitleaks Secret Scanner",
                "available": True,
                "version": self.get_version(),
                "executed": False,
                "status": "failed",
                "findings_count": 0,
                "duration": round(time.time() - start_time, 2),
                "raw_findings": [],
                "normalized_findings": [],
                "error": f"Target path '{target}' does not exist or is not a directory.",
                "reason": "Invalid target directory.",
            }

        bin_path = self.get_binary_path()
        report_file = os.path.join(tempfile.gettempdir(), f"gitleaks_report_{os.getpid()}_{int(time.time()*1000)}.json")

        cmd = [
            bin_path,
            "detect",
            "--source", target,
            "--report-format", "json",
            "--report-path", report_file,
            "--no-git",
            "--exit-code", "0",
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

            raw_findings = []
            if os.path.exists(report_file):
                try:
                    with open(report_file, "r", encoding="utf-8", errors="ignore") as rf:
                        content = rf.read().strip()
                        if content:
                            raw_findings = json.loads(content)
                except Exception as e:
                    return {
                        "scanner": self.name,
                        "name": "Gitleaks Secret Scanner",
                        "available": True,
                        "version": self.get_version(),
                        "executed": True,
                        "status": "failed",
                        "findings_count": 0,
                        "duration": round(time.time() - start_time, 2),
                        "raw_findings": [],
                        "normalized_findings": [],
                        "error": f"Failed to parse Gitleaks report JSON: {e}",
                    }
                finally:
                    if os.path.exists(report_file):
                        try:
                            os.remove(report_file)
                        except OSError:
                            pass

            normalized = self.normalize_findings(raw_findings, base_folder=target)
            dur = round(time.time() - start_time, 2)

            # Sanitize raw findings so raw credentials are never persisted in memory or logs
            sanitized_raw = []
            for rf_item in raw_findings:
                clean_item = dict(rf_item)
                if "Secret" in clean_item and clean_item["Secret"]:
                    clean_item["Secret"] = redact_secret_string(str(clean_item["Secret"]))
                if "Match" in clean_item and clean_item["Match"]:
                    clean_item["Match"] = redact_secret_string(str(clean_item["Match"]))
                sanitized_raw.append(clean_item)

            return {
                "scanner": self.name,
                "name": "Gitleaks Secret Scanner",
                "available": True,
                "version": self.get_version(),
                "executed": True,
                "status": "completed",
                "findings_count": len(normalized),
                "duration": dur,
                "raw_findings": sanitized_raw,
                "normalized_findings": normalized,
                "error": None,
            }

        except subprocess.TimeoutExpired:
            return {
                "scanner": self.name,
                "name": "Gitleaks Secret Scanner",
                "available": True,
                "version": self.get_version(),
                "executed": True,
                "status": "failed",
                "findings_count": 0,
                "duration": round(time.time() - start_time, 2),
                "raw_findings": [],
                "normalized_findings": [],
                "error": f"Gitleaks scan exceeded timeout ({self.timeout_seconds}s).",
                "reason": "Execution timed out.",
            }
        except Exception as e:
            return {
                "scanner": self.name,
                "name": "Gitleaks Secret Scanner",
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
        """Parses JSON text output from Gitleaks."""
        if not raw_output or not raw_output.strip():
            return []
        try:
            data = json.loads(raw_output)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def normalize_findings(self, raw_findings: List[Dict[str, Any]], base_folder: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Normalizes Gitleaks output into standard finding schema.
        Guarantees zero raw secret leakage by masking secret values.
        Filters out known documentation placeholders and respects test-context downgrades.
        """
        from secret_detector import is_known_placeholder_secret, is_test_context, is_line_suppressed

        normalized = []
        for item in raw_findings:
            secret_val = item.get("Secret", "")
            match_line = item.get("Match", "") or item.get("Line", "")

            # 1. Drop known documentation placeholders (e.g. AKIAIOSFODNN7EXAMPLE)
            if is_known_placeholder_secret(secret_val) or is_known_placeholder_secret(match_line):
                continue

            # 2. Check for suppression comments
            if is_line_suppressed(str(match_line)):
                continue

            rule_id = item.get("RuleID", "generic-secret")
            desc = item.get("Description") or f"Exposed credential: {rule_id}"
            file_path = item.get("File", "unknown")
            if base_folder and os.path.isabs(file_path):
                file_path = os.path.relpath(file_path, base_folder)
            
            line = item.get("StartLine") or item.get("Line")
            masked_preview = redact_secret_string(secret_val) if secret_val else "[REDACTED]"
            
            in_test = is_test_context(file_path)

            # Map high-risk secret rules to CRITICAL unless in test context
            if in_test:
                severity = "MEDIUM"
                title = f"Possible Test Fixture ({rule_id.replace('-', ' ').title()})"
                confidence = "MEDIUM"
            else:
                severity = "CRITICAL"
                rule_lower = rule_id.lower()
                if any(k in rule_lower for k in ("test", "example", "dummy")):
                    severity = "LOW"
                elif any(k in rule_lower for k in ("webhook", "slack-webhook", "discord-webhook")):
                    severity = "HIGH"
                title = f"Exposed {rule_id.replace('-', ' ').title()}"
                confidence = "CONFIRMED"

            norm = normalize_finding(
                scanner="gitleaks",
                category="secrets",
                title=title,
                description=desc,
                severity=severity,
                confidence=confidence,
                file=file_path,
                line=line,
                evidence=f"Credential pattern '{rule_id}' detected: {masked_preview}",
                remediation="Rotate and revoke the exposed credential immediately. Store secrets in secure environment variables or vault." if not in_test else "If this is a real credential in tests, rotate it. Otherwise, annotate with '# pragma: allowlist secret'.",
                references=["https://github.com/gitleaks/gitleaks"],
                raw_details={
                    "rule_id": rule_id,
                    "entropy": item.get("Entropy"),
                    "commit": item.get("Commit"),
                    "author": item.get("Author"),
                    "is_test_context": in_test,
                },
            )
            normalized.append(norm)
        return normalized
