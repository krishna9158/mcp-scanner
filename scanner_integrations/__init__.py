"""
Scanner Integrations Package for TrustAudit Platform.

Provides wrappers, normalizers, deduplicators, and orchestration for:
- Gitleaks (Secret Detection)
- OSV-Scanner (Dependency Vulnerabilities)
- Trivy (Filesystem & Misconfigurations)
- Nuclei (Live Application & API Security)
- Syft (Software Bill of Materials / SBOM)
- BaseScanner Interface
- Finding Normalizer & Deduplicator
- ScanOrchestrator
"""

from scanner_integrations.base import BaseScanner
from scanner_integrations.gitleaks import GitleaksScanner
from scanner_integrations.osv_scanner import OSVScanner
from scanner_integrations.trivy import TrivyScanner
from scanner_integrations.nuclei import NucleiScanner
from scanner_integrations.syft import SyftScanner
from scanner_integrations.normalizer import normalize_finding, compute_finding_fingerprint
from scanner_integrations.deduplicator import deduplicate_findings
from scanner_integrations.orchestrator import ScanOrchestrator

__all__ = [
    "BaseScanner",
    "GitleaksScanner",
    "OSVScanner",
    "TrivyScanner",
    "NucleiScanner",
    "SyftScanner",
    "normalize_finding",
    "compute_finding_fingerprint",
    "deduplicate_findings",
    "ScanOrchestrator",
]
