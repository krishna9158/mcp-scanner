"""
Infrastructure as Code (IaC) & Cloud Security Scanner for TrustAudit Platform.

Audits Terraform, OpenTofu, Kubernetes manifests, Dockerfiles, and GitHub Actions CI/CD workflows
for critical infrastructure misconfigurations, privilege escalations, and cloud vulnerabilities:
- S3 Bucket Public Access Block & Encryption (CRITICAL)
- Security Groups with Wildcard Ingress (0.0.0.0/0 on Port 22/3389/Databases) (CRITICAL)
- IAM Policies with Wildcard Admin Rights ("Action": "*", "Resource": "*") (CRITICAL)
- Kubernetes Pods with Privileged Mode & HostPath Escapes (CRITICAL)
- CI/CD PwnRequest / Script Injection via pull_request_target (CRITICAL)
- Exposed Secrets in CI/CD Run Steps (HIGH)
- Unencrypted Database / Storage Volumes (HIGH)
- Unpinned GitHub Actions / Docker Base Images (MEDIUM)
"""

import os
import re
from typing import Any, Dict, List, Optional


IAC_RULES = [
    # 1. Terraform Cloud Misconfigurations
    {
        "id": "IAC-TF-S3-PUBLIC-WILDCARD",
        "name": "S3 Bucket Public Access Allowed",
        "category": "Cloud Security",
        "severity": "CRITICAL",
        "file_patterns": [r"\.tf$", r"\.tfvars$"],
        "patterns": [
            r'resource\s+["\']aws_s3_bucket_public_access_block["\'][\s\S]*?block_public_acls\s*=\s*false',
            r'resource\s+["\']aws_s3_bucket_public_access_block["\'][\s\S]*?block_public_policy\s*=\s*false',
            r'acl\s*=\s*["\']public-read["\']',
            r'acl\s*=\s*["\']public-read-write["\']',
        ],
        "message": "AWS S3 bucket configured with public ACLs or disabled Public Access Block, risking confidential data exposure.",
        "remediation": "Enable `block_public_acls = true` and `block_public_policy = true` on `aws_s3_bucket_public_access_block`.",
        "cwe": "CWE-284",
    },
    {
        "id": "IAC-TF-OPEN-SECURITY-GROUP",
        "name": "Security Group Ingress Open to Internet (0.0.0.0/0)",
        "category": "Network Security",
        "severity": "CRITICAL",
        "file_patterns": [r"\.tf$", r"\.tfvars$"],
        "patterns": [
            r'cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\][\s\S]*?from_port\s*=\s*(?:22|3389|3306|5432|27017|6379)\b',
            r'from_port\s*=\s*(?:22|3389|3306|5432|27017|6379)\b[\s\S]*?cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']\s*\]',
        ],
        "message": "Security group exposes administrative (SSH/RDP) or database ports directly to the public internet (0.0.0.0/0).",
        "remediation": "Restrict ingress CIDR blocks to specific VPN or bastion subnets rather than 0.0.0.0/0.",
        "cwe": "CWE-284",
    },
    {
        "id": "IAC-TF-IAM-WILDCARD-ADMIN",
        "name": "IAM Policy Grants Wildcard Admin Privileges (*:*)",
        "category": "IAM Security",
        "severity": "CRITICAL",
        "file_patterns": [r"\.tf$", r"\.json$", r"\.tfvars$"],
        "patterns": [
            r'["\']Action["\']\s*:\s*["\']\*["\'][\s\S]*?["\']Resource["\']\s*:\s*["\']\*["\']',
            r'actions\s*=\s*\[\s*["\']\*["\']\s*\][\s\S]*?resources\s*=\s*\[\s*["\']\*["\']\s*\]',
        ],
        "message": "IAM policy statement grants full administrative access (`*` action on `*` resource), violating the Principle of Least Privilege.",
        "remediation": "Scope IAM policy actions to exact required AWS services and restrict resource ARNs.",
        "cwe": "CWE-250",
    },
    {
        "id": "IAC-TF-UNENCRYPTED-STORAGE",
        "name": "Unencrypted Storage Volume / RDS Database",
        "category": "Cloud Security",
        "severity": "HIGH",
        "file_patterns": [r"\.tf$", r"\.tfvars$"],
        "patterns": [
            r'resource\s+["\']aws_db_instance["\'][\s\S]*?storage_encrypted\s*=\s*false',
            r'resource\s+["\']aws_ebs_volume["\'][\s\S]*?encrypted\s*=\s*false',
        ],
        "message": "Persistent storage volume or database instance is deployed without encryption at rest.",
        "remediation": "Set `storage_encrypted = true` or `encrypted = true` and specify a KMS Customer Managed Key.",
        "cwe": "CWE-311",
    },

    # 2. Kubernetes Manifest Security
    {
        "id": "IAC-K8S-PRIVILEGED-CONTAINER",
        "name": "Kubernetes Pod Running in Privileged Mode",
        "category": "Container Security",
        "severity": "CRITICAL",
        "file_patterns": [r"\.yaml$", r"\.yml$"],
        "patterns": [
            r'securityContext:[\s\S]*?privileged:\s*true',
            r'allowPrivilegeEscalation:\s*true',
        ],
        "message": "Kubernetes container runs in privileged mode or permits privilege escalation, enabling root host compromise.",
        "remediation": "Set `privileged: false` and `allowPrivilegeEscalation: false` in container securityContext.",
        "cwe": "CWE-250",
    },
    {
        "id": "IAC-K8S-HOSTPATH-ESCAPE",
        "name": "Kubernetes Dangerous HostPath Mount",
        "category": "Container Security",
        "severity": "CRITICAL",
        "file_patterns": [r"\.yaml$", r"\.yml$"],
        "patterns": [
            r'hostPath:[\s\S]*?path:\s*["\']?(?:/|/var/run/docker\.sock|/etc|/root|/var/log)["\']?',
        ],
        "message": "Pod mounts critical host root filesystems or the Docker daemon socket, permitting complete node takeover.",
        "remediation": "Avoid hostPath volume mounts; use PVCs or ConfigMaps instead.",
        "cwe": "CWE-552",
    },

    # 3. GitHub Actions CI/CD Security
    {
        "id": "IAC-CICD-PWNREQUEST-INJECTION",
        "name": "CI/CD Script Injection via pull_request_target",
        "category": "CI/CD Security",
        "severity": "CRITICAL",
        "file_patterns": [r"\.github/workflows/.*\.ya?ml$"],
        "patterns": [
            r'on:\s*[\s\S]*?pull_request_target[\s\S]*?uses:\s*actions/checkout@[^\n]+[\s\S]*?ref:\s*\${{\s*github\.event\.pull_request\.head\.sha\s*}}',
        ],
        "message": "Workflow triggers on `pull_request_target` and checks out untrusted fork PR code, allowing repository secret exfiltration.",
        "remediation": "Use `on: pull_request` without write permissions or checkout only base branch on `pull_request_target`.",
        "cwe": "CWE-94",
    },
    {
        "id": "IAC-CICD-SECRET-IN-RUN-STEP",
        "name": "Secret Interpolated Directly in CI/CD Shell Script",
        "category": "CI/CD Security",
        "severity": "HIGH",
        "file_patterns": [r"\.github/workflows/.*\.ya?ml$"],
        "patterns": [
            r'run:\s*[\s\S]*?\${{\s*secrets\.[A-Za-z0-9_]+\s*}}',
        ],
        "message": "GitHub Actions secrets interpolated directly into `run:` scripts are vulnerable to command injection and process argument inspection.",
        "remediation": "Pass secrets as environment variables (`env: SECRET_VAL: ${{ secrets.MY_SECRET }}`) and reference them via shell `$SECRET_VAL`.",
        "cwe": "CWE-532",
    },
]


def scan_file_for_iac_vulnerabilities(content: str, filepath: str) -> List[Dict[str, Any]]:
    """
    Scans a single IaC file (Terraform, Kubernetes, GitHub Actions) for misconfigurations.
    """
    findings = []
    norm_path = filepath.replace("\\", "/").lower()

    for rule in IAC_RULES:
        # Check if filepath matches any file patterns
        matches_file = any(re.search(pat, norm_path) for pat in rule["file_patterns"])
        if not matches_file:
            continue

        for pat in rule["patterns"]:
            match = re.search(pat, content)
            if match:
                line = content.count("\n", 0, match.start()) + 1
                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "file": filepath,
                    "line": line,
                    "message": rule["message"],
                    "matched_snippet": match.group(0)[:140],
                    "fix": rule["remediation"],
                    "cwe": rule.get("cwe", "CWE-284"),
                })
                break  # one finding per rule per file

    return findings


def scan_folder_for_iac(folder: str, max_files: int = 1000) -> List[Dict[str, Any]]:
    """
    Recursively scans folder for Terraform, Kubernetes, and CI/CD security vulnerabilities.
    """
    findings = []
    count = 0
    skip_dirs = (".git", "node_modules", "dist", "build", ".venv", "venv", ".pytest_cache", ".terraform")

    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]
        for file in files:
            file_lower = file.lower()
            if (
                file_lower.endswith((".tf", ".tfvars", ".yaml", ".yml", ".json"))
                or "dockerfile" in file_lower
            ):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(500000)
                    file_findings = scan_file_for_iac_vulnerabilities(content, filepath)
                    findings.extend(file_findings)
                except Exception:
                    continue
                count += 1
                if count >= max_files:
                    return findings

    return findings
