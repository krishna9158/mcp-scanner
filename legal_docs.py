"""
TrustAudit Version-Controlled Public Legal & Compliance Disclosures Registry.

Generates truthful, implementation-aligned legal documents for:
- /privacy (Privacy Notice)
- /terms (Terms of Service)
- /acceptable-use (Acceptable Use Policy)
- /data-processing (Data Processing Overview / DPA Terms)
- /ai-disclosure (AI Processing & Data Minimisation Disclosure)

Uses configurable environment contacts and strictly never fabricates corporate
addresses, unobtained certifications, or unsupported security guarantees.
"""

import os
from typing import Any, Dict, List


LEGAL_DOC_VERSIONS = {
    "privacy": "2026-11-v2",
    "terms": "2026-11-v2",
    "acceptable_use": "2026-11-v1",
    "data_processing": "2026-11-v1",
    "ai_disclosure": "2026-11-v1",
}


def get_contact_config() -> Dict[str, Any]:
    privacy_email = os.environ.get("TRUSTAUDIT_PRIVACY_EMAIL", "").strip()
    security_email = os.environ.get("TRUSTAUDIT_SECURITY_EMAIL", "").strip()
    support_email = os.environ.get("TRUSTAUDIT_SUPPORT_EMAIL", "").strip()
    operator_name = os.environ.get("TRUSTAUDIT_OPERATOR_NAME", "TrustAudit").strip() or "TrustAudit"
    configured_addr = os.environ.get("TRUSTAUDIT_REGISTERED_ADDRESS", "").strip()
    return {
        "operator_name": operator_name,
        "privacy_email": privacy_email,
        "security_email": security_email,
        "support_email": support_email,
        "registered_address": configured_addr or "Configurable operator contact available via published Security & Grievance Intake channels on this platform.",
        "web_grievance_path": "/security",
        "portal_path": "/portal/demo-sandbox",
    }


def get_legal_document(slug: str) -> Dict[str, Any]:
    cfg = get_contact_config()
    priv_contact = cfg["privacy_email"] or "the TrustAudit Grievance Desk at /security"
    sec_contact = cfg["security_email"] or "the TrustAudit Security & Vulnerability intake channel at /security"

    if slug == "privacy":
        return {
            "slug": "privacy",
            "title": "TrustAudit Privacy Notice",
            "version": LEGAL_DOC_VERSIONS["privacy"],
            "effective_date": "27 November 2026",
            "subtitle": "How TrustAudit collects, uses, safeguards, and deletes personal data submitted to our platform.",
            "sections": [
                {
                    "id": "account-info",
                    "heading": "1. Account & Sign-Up Information",
                    "body": (
                        "When you create a TrustAudit account, we collect your name, work email address, organisation name, "
                        "selected industry, selected workspace plan, password (stored strictly as a 600,000-iteration salted PBKDF2-HMAC-SHA256 hash), "
                        "and timestamped acceptances of our Terms of Service and Privacy Notice. If you enrol two-factor authentication (2FA), "
                        "we store your TOTP secret, last verified step counter (to prevent code replay), and SHA-256 hashes of your 8 single-use recovery codes."
                    ),
                },
                {
                    "id": "org-and-website",
                    "heading": "2. Organisation & Public Website Check Information",
                    "body": (
                        "Inside your workspace, we store the data categories, purposes, vendor contracts, privacy notices, action items, "
                        "customer request tracking metadata, and retention schedules entered or confirmed by your team. When you run a Public "
                        "Website Privacy Check (/website-check), TrustAudit inspects publicly reachable HTML headers, links, public forms, "
                        "and third-party script domains strictly from external URLs after SSRF validation."
                    ),
                },
                {
                    "id": "evidence-uploads",
                    "heading": "3. Documents & Evidence Vault Uploads",
                    "body": (
                        "Files uploaded to Discovery Centre or Evidence Vault (allowlisted formats under 5 MB) are validated by extension "
                        "and file magic bytes. Uploaded Evidence Vault files are encrypted at rest using application-layer Fernet encryption "
                        "when TRUSTAUDIT_DATA_KEY is configured in the hosting environment; otherwise host volume encryption applies cleanly, "
                        "as reported live on /trust."
                    ),
                },
                {
                    "id": "ai-processing",
                    "heading": "4. AI Assistant & External AI Providers",
                    "body": (
                        "By default, TrustAudit answers DPDP Act & Rules questions locally using a deterministic corpus grounded in official "
                        "Gazette sources without sending prompts to external AI APIs. If an operator explicitly enables an external AI provider "
                        "(e.g. via GEMINI_API_KEY), direct personal emails, phone numbers, and tax/ID patterns are scrubbed before prompt construction."
                    ),
                },
                {
                    "id": "subprocessors",
                    "heading": "5. Hosting, Storage & Purpose of Processing",
                    "body": (
                        "TrustAudit is hosted on Render compute and persistent volume infrastructure strictly for providing authenticated "
                        "workspace operations, security monitoring, audit logging, and export downloads (PDF/CSV/ZIP). We do not sell personal information."
                    ),
                },
                {
                    "id": "retention-deletion",
                    "heading": "6. Data Retention, Sessions, Cookies & Permanent Deletion",
                    "body": (
                        "Session authentication relies on SHA-256 hashed session tokens stored in HttpOnly SameSite cookies (valid up to 30 days or until "
                        "revoked via Settings -> Active Sessions) and browser localStorage strictly for client preferences (theme/sidebar state and API bearer helper). "
                        "We do not load third-party ad networks. Organisation administrators may permanently purge their entire tenant and Evidence Vault files "
                        "at any time via Settings -> Delete Organisation Permanently (/api/account/delete)."
                    ),
                },
                {
                    "id": "rights-contact",
                    "heading": "7. Your Rights & Grievance Contact",
                    "body": (
                        f"You can exercise access, correction, erasure, or grievance rights via Settings or by contacting {priv_contact}. "
                        f"Security vulnerabilities may be reported via {sec_contact} (see /.well-known/security.txt). "
                        f"Operator details: {cfg['operator_name']} — {cfg['registered_address']}."
                    ),
                },
            ],
        }

    if slug == "terms":
        return {
            "slug": "terms",
            "title": "TrustAudit Terms of Service",
            "version": LEGAL_DOC_VERSIONS["terms"],
            "effective_date": "27 November 2026",
            "subtitle": "Contractual rules governing access to the TrustAudit DPDP Readiness & Privacy Operations Platform.",
            "sections": [
                {
                    "id": "service-scope",
                    "heading": "1. Service Description & Readiness Disclaimer",
                    "body": (
                        "TrustAudit provides SaaS software workflows to catalogue personal data categories, run authorised public website checks, "
                        "generate draft privacy notices and operational SOPs, track vendor contracts, and organise supporting evidence. "
                        "TrustAudit is NOT a law firm, audit firm, registered Consent Manager under Section 6(9), or government certification body."
                    ),
                },
                {
                    "id": "accounts-security",
                    "heading": "2. Account Security & Organisation Responsibilities",
                    "body": (
                        "You must provide accurate work account information, keep passwords confidential, review role assignments (Admin/Member/Viewer), "
                        "and strongly enable Authenticator 2FA. Only run /website-check against domains you own or hold explicit authorisation to inspect."
                    ),
                },
                {
                    "id": "plans-quotas",
                    "heading": "3. Subscription Plans, Quotas & Early Access",
                    "body": (
                        "Workspaces operate under Free Community (Rs. 0), Starter (Rs. 999/mo), Growth (Rs. 1,999/mo), or Business (Rs. 2,999/mo) tier quotas "
                        "enforced server-side across domains, team seats, data streams, vendors, and Evidence Vault files. Early-access plan selection configures "
                        "workspace limits immediately without simulating or charging live card transactions inside the product."
                    ),
                },
                {
                    "id": "acceptable-use-ip",
                    "heading": "4. Acceptable Use & Intellectual Property",
                    "body": (
                        "Customers retain ownership of all uploaded documents, inventory records, and notices they create. You may not probe private networks, "
                        "bypass multi-tenant authentication boundaries, upload malicious executables, or resell platform access without written permission."
                    ),
                },
                {
                    "id": "availability-liability",
                    "heading": "5. Service Availability, Suspension, Termination & Governing Law",
                    "body": (
                        "TrustAudit uses reasonable engineering safeguards detailed at /trust and permits immediate tenant export and self-service deletion. "
                        "Accounts violating Acceptable Use policies may be suspended. To the maximum extent permitted by applicable Indian law, liability for "
                        "operational readiness tooling excludes consequential regulatory penalties imposed on your business, and disputes shall be governed by laws of India."
                    ),
                },
            ],
        }

    if slug == "acceptable-use":
        return {
            "slug": "acceptable-use",
            "title": "TrustAudit Acceptable Use Policy",
            "version": LEGAL_DOC_VERSIONS["acceptable_use"],
            "effective_date": "27 November 2026",
            "subtitle": "Authorised scanning boundaries, upload hygiene, and tenant conduct requirements.",
            "sections": [
                {
                    "id": "authorised-scanning",
                    "heading": "1. Authorised Website Inspection Only",
                    "body": (
                        "You must confirm ownership or written authorisation before submitting any domain to Website Privacy Check. "
                        "Attempts to scan internal RFC1918 networks, localhost, cloud metadata IPs, or third-party targets without permission are blocked and logged."
                    ),
                },
                {
                    "id": "prohibited-content",
                    "heading": "2. Data Minimisation & Prohibited Uploads",
                    "body": (
                        "Do not upload bulk raw patient health histories, Aadhaar numbers, payment PANs, or unrequested special-category citizen dumps into notes "
                        "or test forms. Executable binaries and oversized files above 5 MB are rejected by magic-byte and size controls."
                    ),
                },
                {
                    "id": "portal-integrity",
                    "heading": "3. Customer Portal & Anti-Abuse Limits",
                    "body": (
                        "Automated credential stuffing, brute-force logins, cross-tenant probing, or automated spam against Customer Privacy Portals violate "
                        "rate-limiting protections and may result in immediate suspension."
                    ),
                },
            ],
        }

    if slug == "data-processing":
        return {
            "slug": "data-processing",
            "title": "Data Processing Overview (Customer Workspace Data)",
            "version": LEGAL_DOC_VERSIONS["data_processing"],
            "effective_date": "27 November 2026",
            "subtitle": "How TrustAudit handles workspace records as a Data Processor for customer organisations.",
            "sections": [
                {
                    "id": "roles-instructions",
                    "heading": "1. Roles & Documented Customer Instructions",
                    "body": (
                        "When customer organisations store Data Principal request tickets, vendor records, consent logs, or compliance documents in TrustAudit, "
                        "the customer acts as Data Fiduciary/Controller and TrustAudit processes such workspace data strictly on documented customer instructions."
                    ),
                },
                {
                    "id": "safeguards-isolation",
                    "heading": "2. Tenant Isolation & Technical Safeguards",
                    "body": (
                        "Every API validates session tenant membership server-side before reading or mutating any organisation bucket. Audit logs track workspace "
                        "actions cleanly without exposing plaintext passwords, tokens, or OTP secrets. Application-layer encryption status is transparently published at /trust."
                    ),
                },
                {
                    "id": "return-deletion",
                    "heading": "3. Portability, Breach Escalation & Erasure",
                    "body": (
                        "Organisations can export complete workspace ZIP Evidence Bundles, PDFs, CSVs, and JSON snapshots on demand, or trigger immediate "
                        "permanent organisation deletion via /api/account/delete."
                    ),
                },
            ],
        }

    return {
        "slug": "ai-disclosure",
        "title": "TrustAudit AI Processing & Data Minimisation Disclosure",
        "version": LEGAL_DOC_VERSIONS["ai_disclosure"],
        "effective_date": "27 November 2026",
        "subtitle": "Exact disclosure of how TrustAudit's AI Privacy Assistant handles prompts and legal sources.",
        "sections": [
            {
                "id": "local-corpus",
                "heading": "1. Local Grounded Knowledge Engine by Default",
                "body": (
                    "TrustAudit's primary AI Privacy Assistant matches user queries locally against TrustAudit's versioned legal registry "
                    "(DPDP Act 2023, DPDP Rules 2025, G.S.R. 892(E), G.S.R. 843(E), G.S.R. 846(E), S.O. 5458(E)). No prompts leave the TrustAudit server "
                    "unless an administrator explicitly configures an external LLM key (GEMINI_API_KEY)."
                ),
            },
            {
                "id": "pii-redaction",
                "heading": "2. Automatic PII Redaction Layer",
                "body": (
                    "Before constructing any contextual prompt or external request, TrustAudit strips email addresses, phone numbers, tax/PAN formats, "
                    "and credential patterns. Evidence Vault binary documents and raw Customer Privacy Portal tickets are never transmitted to public LLMs."
                ),
            },
            {
                "id": "not-legal-advice",
                "heading": "3. Advisory Scope & Citation Transparency",
                "body": (
                    "Every response separates in-force rules (13 Nov 2025 & 13 Nov 2026) from upcoming obligations (13 May 2027), marks S.O. 5458(E) wording "
                    "updates accurately without distorting effective dates, and is informational readiness guidance—not formal legal representation."
                ),
            },
        ],
    }
