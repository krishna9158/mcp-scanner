"""
Standardized Security Finding Model for TrustAudit Platform.

Defines a uniform finding schema across all analyzers:
- Unique finding IDs
- Severity & evidence-based confidence
- Line numbers and code locations
- Exploit scenarios & business impact
- Actionable remediation and automated verification methods
- Finding lifecycle status tracking (open, acknowledged, fixed, verified, false_positive)
"""
import time
import uuid
import hashlib

VALID_CATEGORIES = {
    "mcp_security",
    "secrets",
    "dependencies",
    "authentication",
    "authorization",
    "prompt_injection",
    "data_exfiltration",
    "code_security",
    "supply_chain",
    "tenancy",
    "rug_pull",
    "policy_violation",
    "website_security",
    "tls",
    "headers",
    "cookies",
    "cors",
    "exposure",
    "api_discovery",
    "technology",
}

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_CONFIDENCES = {"CONFIRMED", "LIKELY", "POTENTIAL", "INFORMATIONAL"}
VALID_STATUSES = {"open", "acknowledged", "fixed", "verified", "false_positive"}


class Finding:
    def __init__(
        self,
        category,
        severity,
        title,
        description,
        evidence,
        confidence="CONFIRMED",
        file=None,
        line=None,
        tool_name=None,
        component=None,
        exploit_scenario=None,
        business_impact=None,
        remediation=None,
        verification_method=None,
        finding_id=None,
        status="open",
        first_detected=None,
        last_detected=None,
    ):
        self.category = category if category in VALID_CATEGORIES else "mcp_security"
        self.severity = severity if severity in VALID_SEVERITIES else "MEDIUM"
        self.confidence = confidence if confidence in VALID_CONFIDENCES else "LIKELY"
        self.title = title
        self.description = description
        self.evidence = evidence or "No raw evidence string provided."
        self.file = file or "unknown"
        self.line = int(line) if line is not None and str(line).isdigit() else None
        self.tool_name = tool_name
        self.component = component or (f"tool:{tool_name}" if tool_name else "source")
        self.exploit_scenario = exploit_scenario or "An attacker exploits this vulnerability to bypass intended security controls."
        self.business_impact = business_impact or "Compromise of confidentiality, integrity, or system availability."
        self.remediation = remediation or "Review and patch the affected source code or configuration."
        self.verification_method = verification_method or "Rescan repository and run associated regression tests."
        self.status = status if status in VALID_STATUSES else "open"
        
        now = time.time()
        self.first_detected = first_detected or now
        self.last_detected = last_detected or now

        # Deterministic finding ID based on content to track across scans
        if finding_id:
            self.finding_id = finding_id
        else:
            seed = f"{self.category}:{self.title}:{self.file}:{self.line}:{self.tool_name}"
            content_hash = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8].upper()
            prefix_map = {
                "mcp_security": "MCP",
                "secrets": "SEC",
                "dependencies": "DEP",
                "authentication": "AUTH",
                "authorization": "AUTHZ",
                "prompt_injection": "INJ",
                "data_exfiltration": "EXFIL",
                "code_security": "CODE",
                "supply_chain": "SUPPLY",
                "tenancy": "TENANT",
                "rug_pull": "RUG",
                "policy_violation": "POL",
                "website_security": "WEB",
                "tls": "TLS",
                "headers": "HDR",
                "cookies": "COOK",
                "cors": "CORS",
                "exposure": "EXP",
                "api_discovery": "API",
                "technology": "TECH",
            }
            pfx = prefix_map.get(self.category, "FIND")
            self.finding_id = f"FIND-{pfx}-{content_hash}"


    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "file": self.file,
            "line": self.line,
            "tool_name": self.tool_name,
            "component": self.component,
            "exploit_scenario": self.exploit_scenario,
            "business_impact": self.business_impact,
            "remediation": self.remediation,
            "verification_method": self.verification_method,
            "first_detected": self.first_detected,
            "last_detected": self.last_detected,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            category=data.get("category", "mcp_security"),
            severity=data.get("severity", "MEDIUM"),
            title=data.get("title", "Untitled Finding"),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            confidence=data.get("confidence", "CONFIRMED"),
            file=data.get("file"),
            line=data.get("line"),
            tool_name=data.get("tool_name"),
            component=data.get("component"),
            exploit_scenario=data.get("exploit_scenario"),
            business_impact=data.get("business_impact"),
            remediation=data.get("remediation"),
            verification_method=data.get("verification_method"),
            finding_id=data.get("finding_id"),
            status=data.get("status", "open"),
            first_detected=data.get("first_detected"),
            last_detected=data.get("last_detected"),
        )
