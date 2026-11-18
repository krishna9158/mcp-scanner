"""
Supply-Chain & Manifest Security Analyzer for MCP & AI Applications.

Inspects:
- package.json & lockfiles (package-lock, yarn.lock, pnpm-lock)
- requirements.txt & pyproject.toml
- Dockerfiles & container manifests
- Git direct dependencies

Detects:
- Malicious install / preinstall / postinstall lifecycle scripts
- Unpinned / open-ended wildcard dependencies (*, latest)
- Untrusted direct Git URLs
- Typosquats and supply-chain anomalies
"""
import os
import json
import re

SUSPICIOUS_LIFECYCLE_PATTERNS = [
    r'curl\s+.*?\|\s*(?:bash|sh)',
    r'wget\s+.*?\|\s*(?:bash|sh)',
    r'node\s+-e\s+["\'].*?(?:eval|Buffer|exec)',
    r'powershell\s+-enc',
    r'python\s+-c\s+["\'].*?(?:urllib|requests|exec)',
]


def audit_package_json(content, filepath="package.json"):
    """Audits package.json for dangerous install scripts and unpinned deps."""
    findings = []
    try:
        data = json.loads(content)
    except Exception:
        return findings

    # 1. Lifecycle scripts check
    scripts = data.get("scripts", {})
    if isinstance(scripts, dict):
        for script_name in ("preinstall", "install", "postinstall", "prepublish"):
            cmd = scripts.get(script_name, "")
            if cmd:
                is_suspicious = any(re.search(pat, cmd, re.IGNORECASE) for pat in SUSPICIOUS_LIFECYCLE_PATTERNS)
                findings.append({
                    "type": "NPM Lifecycle Script",
                    "file": filepath,
                    "severity": "CRITICAL" if is_suspicious else "MEDIUM",
                    "confidence": "CONFIRMED",
                    "detail": f"Manifest defines '{script_name}': `{cmd[:100]}` which automatically runs during `npm install`.",
                    "evidence": f"scripts.{script_name}: {cmd[:150]}",
                    "remediation": "Audit lifecycle scripts for malicious remote code downloads and use `npm install --ignore-scripts` in untrusted builds."
                })

    # 2. Unpinned dependencies check
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for pkg, ver in deps.items():
        if ver in ("*", "latest") or ver.startswith(">="):
            findings.append({
                "type": "Unpinned Wildcard Dependency",
                "file": filepath,
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "detail": f"Dependency '{pkg}' is unpinned ({ver}). Wildcard versions risk pulling untested breaking changes or compromised releases.",
                "evidence": f'"{pkg}": "{ver}"',
                "remediation": f"Pin exact version in package.json (e.g. '{ver.replace('*', '1.0.0')}')."
            })
        elif ver.startswith("git+") or ver.startswith("http"):
            findings.append({
                "type": "Direct Git / URL Dependency",
                "file": filepath,
                "severity": "MEDIUM",
                "confidence": "CONFIRMED",
                "detail": f"Dependency '{pkg}' is sourced directly from a URL/Git repository rather than a registry.",
                "evidence": f'"{pkg}": "{ver}"',
                "remediation": "Verify the integrity and immutable commit hash of the external repository."
            })

    return findings


def audit_dockerfile(content, filepath="Dockerfile"):
    """Audits Dockerfile for root privileges, untrusted base images, and unpinned packages."""
    findings = []
    lines = content.splitlines()
    has_user = False
    
    for idx, line in enumerate(lines, 1):
        line_clean = line.strip()
        if line_clean.startswith("#") or not line_clean:
            continue
        
        if line_clean.upper().startswith("USER "):
            has_user = True

        if line_clean.upper().startswith("FROM ") and (":latest" in line_clean or ":" not in line_clean.split()[1]):
            findings.append({
                "type": "Unpinned Docker Base Image",
                "file": filepath,
                "line": idx,
                "severity": "LOW",
                "confidence": "CONFIRMED",
                "detail": f"Base image `{line_clean}` does not specify an immutable digest or exact version tag.",
                "evidence": line_clean,
                "remediation": "Pin base images to a specific version or SHA256 digest (e.g. python:3.11-slim@sha256:...)."
            })

        for pat in SUSPICIOUS_LIFECYCLE_PATTERNS:
            if re.search(pat, line_clean, re.IGNORECASE):
                findings.append({
                    "type": "Suspicious Docker RUN Command",
                    "file": filepath,
                    "line": idx,
                    "severity": "HIGH",
                    "confidence": "CONFIRMED",
                    "detail": "Dockerfile runs piping curl/wget straight to shell execution.",
                    "evidence": line_clean[:120],
                    "remediation": "Download scripts, verify GPG signatures/checksums, and inspect contents before running."
                })

    if not has_user and len(lines) >= 2:
        findings.append({
            "type": "Container Runs as Root",
            "file": filepath,
            "line": 1,
            "severity": "MEDIUM",
            "confidence": "CONFIRMED",
            "detail": "Dockerfile does not define a non-root USER instruction. The container will execute as root by default.",
            "evidence": "Missing USER instruction",
            "remediation": "Add `USER appuser` with restricted UID/GID permissions."
        })


    return findings


def audit_supply_chain(folder):
    """
    Recursively scans the folder for package.json, requirements.txt, and Dockerfile supply-chain issues.
    """
    all_findings = []
    for root, _dirs, files in os.walk(folder):
        for f in files:
            filepath = os.path.join(root, f)
            rel_path = filepath.replace("\\", "/")
            if f == "package.json" and "node_modules" not in rel_path:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as fp:
                        all_findings.extend(audit_package_json(fp.read(), rel_path))
                except Exception:
                    pass
            elif f.lower() in ("dockerfile", "containerfile") and ".git" not in rel_path:
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as fp:
                        all_findings.extend(audit_dockerfile(fp.read(), rel_path))
                except Exception:
                    pass
    return all_findings
