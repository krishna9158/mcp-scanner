# TrustAudit Security Platform — Third-Party Notices & Licenses

This document lists the open-source software packages, tools, and libraries utilized by the TrustAudit platform, including version information, source repositories, license types, redistribution permissions, and SaaS/commercial usage guidelines.

TrustAudit employs an **Adapter Architecture**: external tools are decoupled and executed via isolated subprocesses or APIs. If a specific tool's license prohibits commercial multi-tenant SaaS operation, TrustAudit operates using built-in native fallback analyzers and allows users to bring their own binaries locally.

---

## Summary of Integrated Open-Source Security Engines

| Engine | Version Tested | License | Source Repository | Redistribution Allowed? | Commercial / SaaS Allowed? | Integration Method |
|---|---|---|---|---|---|---|
| **OWASP ZAP** | 2.14.0+ / Weekly | Apache 2.0 | [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) | Yes | Yes (Apache 2.0) | Subprocess / REST API Adapter |
| **Aqua Security Trivy** | 0.50.0+ | Apache 2.0 | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Yes | Yes (Apache 2.0) | Subprocess JSON Adapter |
| **Bridgecrew Checkov** | 3.2.0+ | Apache 2.0 | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | Yes | Yes (Apache 2.0) | Subprocess JSON Adapter + Native Parser Fallback |
| **Google OSV-Scanner** | 1.7.0+ | Apache 2.0 | [google/osv-scanner](https://github.com/google/osv-scanner) | Yes | Yes (Apache 2.0) | Subprocess JSON Adapter + OSV API Client |
| **Anchore Syft** | 1.0.0+ | Apache 2.0 | [anchore/syft](https://github.com/anchore/syft) | Yes | Yes (Apache 2.0) | Subprocess JSON Adapter + Native Manifest Fallback |
| **ProjectDiscovery Nuclei** | 3.11.0+ | MIT | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | Yes | Yes (MIT) | Subprocess JSON Adapter (Authorized Scans Only) |
| **PyCQA Bandit** | 1.7.8+ | Apache 2.0 | [PyCQA/bandit](https://github.com/PyCQA/bandit) | Yes | Yes (Apache 2.0) | Subprocess JSON Adapter + Native AST Fallback |
| **Gitleaks** | 8.18.0+ | MIT | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | Yes | Yes (MIT) | Subprocess JSON Adapter + Native Regex Detector |
| **Semgrep Core / CLI** | 1.70.0+ | LGPL-2.1 (CLI) / Proprietary Rules Policy | [semgrep/semgrep](https://github.com/semgrep/semgrep) | Restricted (Rules) | Conditional (LGPL engine; commercial rules restricted) | Adapter decoupled; uses user's system PATH or native rules |

---

## Detailed Tool Notices & License Declarations

### 1. OWASP Zed Attack Proxy (ZAP)
- **License**: Apache License 2.0
- **Homepage**: https://www.zaproxy.org/
- **Repository**: https://github.com/zaproxy/zaproxy
- **Copyright**: Copyright OWASP Foundation and ZAP contributors
- **Permissions**: Commercial use, modification, distribution, sublicensing, private use.
- **Requirements**: Include license notice, state changes.
- **TrustAudit Integration**: Invoked via command-line adapter or local daemon REST API with scope limits, rate limits, and non-destructive passive/safe-active rules.

### 2. Trivy (Aqua Security)
- **License**: Apache License 2.0
- **Repository**: https://github.com/aquasecurity/trivy
- **Copyright**: Copyright Aqua Security Software Ltd.
- **Permissions**: Commercial use, modification, distribution, private use.
- **TrustAudit Integration**: Used for container, repository filesystem, and vulnerability scanning.

### 3. Checkov (Bridgecrew by Prisma Cloud)
- **License**: Apache License 2.0
- **Repository**: https://github.com/bridgecrewio/checkov
- **Copyright**: Copyright Bridgecrew Inc.
- **Permissions**: Commercial use, modification, distribution, private use.
- **TrustAudit Integration**: Evaluates Infrastructure as Code (Terraform, CloudFormation, Kubernetes, Dockerfile). When the CLI binary is absent, TrustAudit executes its built-in native IaC AST parser.

### 4. OSV-Scanner (Google)
- **License**: Apache License 2.0
- **Repository**: https://github.com/google/osv-scanner
- **Copyright**: Copyright 2022-2026 Google LLC
- **Permissions**: Commercial use, modification, distribution, private use.
- **TrustAudit Integration**: Queries Open Source Vulnerabilities database for direct and transitive dependency risks.

### 5. Syft (Anchore)
- **License**: Apache License 2.0
- **Repository**: https://github.com/anchore/syft
- **Copyright**: Copyright Anchore, Inc.
- **Permissions**: Commercial use, modification, distribution, private use.
- **TrustAudit Integration**: Generates Software Bill of Materials (SBOM) in SPDX and CycloneDX standard formats. Native parser serves as automatic fallback.

### 6. Nuclei (ProjectDiscovery)
- **License**: MIT License
- **Repository**: https://github.com/projectdiscovery/nuclei
- **Copyright**: Copyright (c) ProjectDiscovery, Inc.
- **Permissions**: Commercial use, modification, distribution, private use.
- **TrustAudit Integration**: Executes fast template-based vulnerability assessment with strict pre-flight target authorization confirmation.

### 7. Bandit (PyCQA)
- **License**: Apache License 2.0
- **Repository**: https://github.com/PyCQA/bandit
- **Copyright**: Copyright 2014 Hewlett-Packard Development Company, L.P. / PyCQA contributors
- **Permissions**: Commercial use, modification, distribution, private use.
- **TrustAudit Integration**: Performs AST-based SAST security analysis for Python codebases.

### 8. Gitleaks
- **License**: MIT License
- **Repository**: https://github.com/gitleaks/gitleaks
- **Copyright**: Copyright (c) 2018 Zachary Rice
- **Permissions**: Commercial use, modification, distribution, private use.
- **TrustAudit Integration**: Scans git repositories and folders for hardcoded credentials and high-entropy secret patterns.

### 9. Semgrep
- **License**: LGPL-2.1 (CLI engine)
- **Repository**: https://github.com/semgrep/semgrep
- **Notice**: Semgrep CLI is licensed under LGPL 2.1. TrustAudit does not bundle Semgrep proprietary rules or SaaS services; it invokes the user's locally installed Semgrep binary or executes TrustAudit's proprietary, built-in deterministic rules.

---

## Software License Texts

Copies of standard license texts are located in the `licenses/` directory:
- `licenses/APACHE-2.0.txt`
- `licenses/MIT.txt`
- `licenses/LGPL-2.1.txt`
