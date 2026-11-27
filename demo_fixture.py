"""
Canonical Sample / Demo Workspace Fixture for TrustAudit.

Single source of truth for demo organisation identity across:
- /demo
- /portal/demo-sandbox & /p/demo-sandbox
- saas_store.py (org-default seed)
- dpdp_store.py (demo workspace inventory, vendors, notices, requests, retention, incidents, evidence, profile)
- dpdp_website_scanner.py (generate_demo_website_scan)
- compliance_frameworks.py

Strictly ensures all demo surfaces display the SAME consistent sample
organisation with clear non-production framing ("DEMO DATA — FOR ILLUSTRATION ONLY.").
"""

import datetime
import re
import time
from typing import Any, Dict, List, Optional


DEMO_ORG_ID = "org-default"
DEMO_ORG_SLUG = "demo-sandbox"
DEMO_ORG_NAME = "Arogya Diagnostics Clinic — Demo Workspace"
DEMO_SHORT_NAME = "Arogya Diagnostics Clinic"
DEMO_INDUSTRY = "Healthcare (Clinics & Diagnostics)"
DEMO_WEBSITE = "https://arogyaclinic.example.in"
DEMO_PRIVACY_CONTACT_NAME = "Demo Grievance Contact (Sample)"
DEMO_PRIVACY_EMAIL = "demo-privacy@arogya-demo.trustaudit.example"
DEMO_PORTAL_SUBDOMAIN = "privacy.arogya-demo.trustaudit.example"
DEMO_DISCLAIMER = "DEMO DATA — FOR ILLUSTRATION ONLY."
DEMO_BANNER = (
    "DEMO DATA — FOR ILLUSTRATION ONLY. Viewing sample workspace "
    "(Arogya Diagnostics Clinic — Demo Workspace). Changes made here are sample-only; "
    "create a free account to manage your real business records."
)
DEMO_REVIEW_DATE = "2026-11-26"


def is_demo_org(org_id: Optional[str], profile: Optional[Dict[str, Any]] = None, org: Optional[Dict[str, Any]] = None) -> bool:
    """Identifies the canonical sample/demo workspace without ever matching real customer orgs."""
    oid = str(org_id or "").strip().lower()
    if oid in ("org-default", "demo", "acme") or oid.startswith("demo-"):
        return True
    if profile and profile.get("is_demo") is True:
        return True
    if org and org.get("is_demo") is True:
        return True
    return False


def is_demo_slug(slug: Optional[str]) -> bool:
    clean = re.sub(r"[^a-z0-9-]", "", str(slug or "").strip().lower())
    return clean in ("demo-sandbox", "demo", "org-default")


def get_demo_org_record() -> Dict[str, Any]:
    return {
        "id": DEMO_ORG_ID,
        "name": DEMO_ORG_NAME,
        "slug": DEMO_ORG_SLUG,
        "plan": "starter",
        "is_demo": True,
        "created_at": 1764000000.0,
        "max_projects": 10,
        "scans_count": 1,
    }


def get_demo_onboarding_profile() -> Dict[str, Any]:
    return {
        "org_id": DEMO_ORG_ID,
        "company_name": DEMO_ORG_NAME,
        "industry": DEMO_INDUSTRY,
        "website_url": DEMO_WEBSITE,
        "website": DEMO_WEBSITE,
        "organisation_size": "11-50 (Small / Medium)",
        "employee_count": 25,
        "contact_email": DEMO_PRIVACY_EMAIL,
        "grievance_officer": DEMO_PRIVACY_CONTACT_NAME,
        "locations": "Bengaluru & Mumbai, India",
        "customer_types": ["Indian Citizens (Patients)", "Minors / Children (<18 years)"],
        "onboarding_completed": True,
        "is_demo": True,
        "updated_at": f"{DEMO_REVIEW_DATE}T09:00:00+00:00",
    }


def get_demo_portal_config() -> Dict[str, Any]:
    return {
        "enabled": True,
        "is_demo": True,
        "demo_banner": DEMO_BANNER,
        "slug": DEMO_ORG_SLUG,
        "brand_name": DEMO_ORG_NAME,
        "contact_email": DEMO_PRIVACY_EMAIL,
        "intro_text": (
            f"{DEMO_DISCLAIMER} Sample Customer Privacy Request Portal for {DEMO_ORG_NAME}. "
            "Try submitting a sample request or checking an existing reference ID."
        ),
        "custom_domain_preview": DEMO_PORTAL_SUBDOMAIN,
        "require_human_verification": True,
        "updated_at": f"{DEMO_REVIEW_DATE}T09:00:00+00:00",
    }


def get_demo_privacy_profile_config() -> Dict[str, Any]:
    return {
        "published": True,
        "is_demo": True,
        "demo_banner": DEMO_DISCLAIMER,
        "headline": DEMO_ORG_NAME,
        "privacy_contact_name": DEMO_PRIVACY_CONTACT_NAME,
        "privacy_contact_email": DEMO_PRIVACY_EMAIL,
        "show_approved_notice": True,
        "show_portal_link": True,
        "show_last_review_date": True,
        "selected_practices": [
            "Sample notice: Plain-English healthcare data collection summary (Demo illustration)",
            "Sample contact: Dedicated Grievance Desk link for access, correction & erasure enquiries",
            "Sample portal: Customer Privacy Request Portal active for demo exploration",
        ],
        "approved_document_ids": [],
        "last_reviewed_at": DEMO_REVIEW_DATE,
    }


def get_demo_seed_collections() -> Dict[str, Any]:
    """
    Consistent sample records across all TrustAudit modules for Arogya Diagnostics Clinic — Demo Workspace.
    All dates are anchored deterministically and records carry is_demo=True for clarity.
    """
    ts = f"{DEMO_REVIEW_DATE}T09:30:00+00:00"
    due_upcoming = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=12)).strftime("%Y-%m-%d")

    inventory: List[Dict[str, Any]] = [
        {
            "id": "INV-DEMO-01",
            "category": "Health information",
            "fields": ["Patient Name", "Age / DOB", "Diagnostic Test Name", "Lab Report Summary"],
            "principal_type": "Patients & Guardians",
            "source": "Appointment Desk & Diagnostic Lab Software",
            "purpose": "Conducting diagnostic tests and delivering clinical reports",
            "legal_basis": "Consent (Section 6) & Medical care records",
            "storage_system": "Clinic LIMS (AWS ap-south-1)",
            "retention_period": "5 years (Clinical record schedule)",
            "confirmation_status": "Confirmed by business",
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        },
        {
            "id": "INV-DEMO-02",
            "category": "Contact information",
            "fields": ["Full Name", "Mobile Number", "Email Address"],
            "principal_type": "Patients",
            "source": "Public Booking Form (/book)",
            "purpose": "Booking diagnostic slots and sending test report notifications",
            "legal_basis": "Consent (Section 6)",
            "storage_system": "Appointment CRM",
            "retention_period": "3 years after last visit",
            "confirmation_status": "Confirmed by business",
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        },
        {
            "id": "INV-DEMO-03",
            "category": "Billing information",
            "fields": ["Payer Name", "Invoice Number", "UPI Reference", "GST Details"],
            "principal_type": "Patients",
            "source": "Front Desk Billing & Checkout",
            "purpose": "Fee invoicing, payment reconciliation, and statutory tax compliance",
            "legal_basis": "Legal Obligation / Finance (Section 7)",
            "storage_system": "Razorpay & Clinic Accounting Ledger",
            "retention_period": "8 years (Income Tax & GST statutory rule)",
            "confirmation_status": "Confirmed by business",
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        },
        {
            "id": "INV-DEMO-04",
            "category": "Employee information",
            "fields": ["Staff Name", "PAN", "Bank Account", "Attendance Log"],
            "principal_type": "Clinic Staff",
            "source": "HR & Payroll Register",
            "purpose": "Employment payroll and statutory PF/ESI compliance",
            "legal_basis": "Employment Purpose (Section 7(i))",
            "storage_system": "Payroll Portal",
            "retention_period": "Termination + 5 years",
            "confirmation_status": "Confirmed by business",
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        },
        {
            "id": "INV-DEMO-05",
            "category": "Website and application information",
            "fields": ["Session Cookie", "Page Events", "IP Address"],
            "principal_type": "Website Visitors",
            "source": "Clinic Public Website Scripts",
            "purpose": "Appointment funnel analytics and ad conversion measurement",
            "legal_basis": "Needs review (Unverified third-party tracking scripts)",
            "storage_system": "Google Tag Manager & Meta Pixel",
            "retention_period": "90 days",
            "confirmation_status": "SUGGESTED — NEEDS CONFIRMATION",
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        },
    ]

    vendors: List[Dict[str, Any]] = [
        {
            "id": "VND-DEMO-01",
            "name": "AWS Asia Pacific (Mumbai)",
            "category": "Cloud Infrastructure",
            "service": "Clinic LIMS & encrypted database hosting",
            "data_shared": "Patient demographic & diagnostic report files",
            "dpa_status": "SIGNED",
            "data_location": "India (ap-south-1)",
            "status": "Approved",
            "security_review": "SOC 2 Type II & ISO 27001 reviewed (Sample)",
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        },
        {
            "id": "VND-DEMO-02",
            "name": "Razorpay Software Pvt Ltd",
            "category": "Payment Gateway",
            "service": "Online test booking payments & receipts",
            "data_shared": "Payer name, phone, email, transaction token",
            "dpa_status": "SIGNED",
            "data_location": "India",
            "status": "Approved",
            "security_review": "PCI-DSS compliant gateway (Sample)",
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        },
        {
            "id": "VND-DEMO-03",
            "name": "PathCare Reference Lab",
            "category": "Partner Diagnostic Lab",
            "service": "Specialised pathology sample testing",
            "data_shared": "Patient ID, sample details, clinical query",
            "dpa_status": "PENDING",
            "data_location": "Bengaluru, India",
            "status": "Needs DPA review",
            "security_review": "",
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        },
    ]

    notices: List[Dict[str, Any]] = [
        {
            "id": "NTC-DEMO-01",
            "title": f"{DEMO_SHORT_NAME} — Patient Privacy Notice (Sample)",
            "version": "v1.0",
            "status": "APPROVED_PUBLISHED",
            "language": "English",
            "grievance_officer": DEMO_PRIVACY_CONTACT_NAME,
            "grievance_email": DEMO_PRIVACY_EMAIL,
            "content": (
                f"{DEMO_DISCLAIMER}\n\n"
                f"1. Who we are: {DEMO_ORG_NAME} collects personal information needed for clinical appointments, "
                "diagnostic laboratory testing, report delivery, and statutory billing.\n"
                "2. Why we collect data: To schedule visits, run prescribed tests, issue reports, and satisfy Indian medical & tax records.\n"
                "3. Third-party processors: Hosting (AWS Mumbai), Payments (Razorpay), and Reference Labs.\n"
                "4. Minors & guardians: For children under 18 and persons with disabilities who have lawful guardians (Section 9(1)), "
                "verifiable parent or lawful guardian consent is required prior to processing.\n"
                f"5. Your rights & Grievance Officer: Email {DEMO_PRIVACY_EMAIL} or use /portal/{DEMO_ORG_SLUG}."
            ),
            "is_demo": True,
            "created_at": ts,
            "updated_at": ts,
        }
    ]

    requests_list: List[Dict[str, Any]] = [
        {
            "id": "REQ-DEMO-01",
            "type": "ACCESS",
            "requester_name": "Sample Patient One",
            "requester_email": "patient1-demo@arogya-demo.trustaudit.example",
            "description": "Demo sample: Requesting copy of past 12-month diagnostic checkup consent log.",
            "status": "UNDER_REVIEW",
            "verification_code": "DEMO01",
            "source_channel": "Customer Privacy Portal (Demo)",
            "due_date": due_upcoming,
            "received_at": ts,
            "updated_at": ts,
            "is_demo": True,
        },
        {
            "id": "REQ-DEMO-02",
            "type": "CORRECTION",
            "requester_name": "Sample Patient Two",
            "requester_email": "patient2-demo@arogya-demo.trustaudit.example",
            "description": "Demo sample: Requesting mobile number update on clinic booking profile.",
            "status": "COMPLETED",
            "verification_code": "DEMO02",
            "source_channel": "Customer Privacy Portal (Demo)",
            "due_date": due_upcoming,
            "received_at": ts,
            "updated_at": ts,
            "is_demo": True,
        },
    ]

    retention: List[Dict[str, Any]] = [
        {"id": "RET-DEMO-01", "data_category": "Appointment Enquiries (Unconverted)", "retention_period": "6 months", "trigger": "No visit within 180 days", "legal_exception": "None", "status": "Active", "is_demo": True, "created_at": ts},
        {"id": "RET-DEMO-02", "data_category": "Diagnostic Lab Reports", "retention_period": "5 years", "trigger": "Report delivery completion", "legal_exception": "Clinical Establishments Act & clinical continuity", "status": "Active", "is_demo": True, "created_at": ts},
        {"id": "RET-DEMO-03", "data_category": "Invoices & Tax Receipts", "retention_period": "8 years", "trigger": "Financial year end", "legal_exception": "Income Tax Act & GST Act", "status": "Active", "is_demo": True, "created_at": ts},
        {"id": "RET-DEMO-04", "data_category": "Website Analytics Logs", "retention_period": "90 days", "trigger": "Rolling log rotation", "legal_exception": "Rule 8 minimal security logs (1 year)", "status": "Needs review", "is_demo": True, "created_at": ts},
    ]

    incidents: List[Dict[str, Any]] = [
        {
            "id": "INC-DEMO-01",
            "title": "Demo Table-Top Drill: Misdirected Lab SMS Test",
            "severity": "MEDIUM",
            "status": "CONTAINED_DRILL",
            "board_notification_status": "DRILL_ONLY_NO_SEND",
            "affected_records": 1,
            "description": f"{DEMO_DISCLAIMER} Example tabletop exercise testing SMS template validation and 72-hour readiness SOP.",
            "created_at": ts,
            "updated_at": ts,
            "is_demo": True,
        }
    ]

    evidence: List[Dict[str, Any]] = [
        {
            "id": "EVI-DEMO-NOTICE",
            "title": "Itemised Clinic Privacy Notice v1.0 (Sample)",
            "category": "Privacy Notices",
            "control_id": "DPDP-SEC-05",
            "filename": "arogya_demo_privacy_notice_v1.pdf",
            "file_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "uploaded_by": DEMO_PRIVACY_CONTACT_NAME,
            "uploaded_at": ts,
            "expiry_date": "2027-11-20",
            "status": "Verified",
            "review_notes": "Demo illustration record.",
            "reviewed_by": "Demo Privacy Reviewer",
            "reviewed_at": ts,
            "is_demo": True,
            "audit_trail": [{"action": "DEMO_SEEDED", "timestamp": ts, "actor": "System"}],
        },
        {
            "id": "EVI-DEMO-DPA",
            "title": "Signed AWS Mumbai Cloud Hosting DPA (Sample)",
            "category": "Processor Contracts",
            "control_id": "DPDP-SEC-08-01",
            "filename": "arogya_demo_aws_mumbai_dpa.pdf",
            "file_hash": "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            "uploaded_by": DEMO_PRIVACY_CONTACT_NAME,
            "uploaded_at": ts,
            "expiry_date": "2028-05-15",
            "status": "Verified",
            "review_notes": "Demo illustration record.",
            "reviewed_by": "Demo Privacy Reviewer",
            "reviewed_at": ts,
            "is_demo": True,
            "audit_trail": [{"action": "DEMO_SEEDED", "timestamp": ts, "actor": "System"}],
        },
        {
            "id": "EVI-DEMO-BACKUP",
            "title": "Clinic LIMS Access & Backup Checklist (Sample)",
            "category": "Security Safeguards",
            "control_id": "DPDP-SEC-08-05",
            "filename": "arogya_demo_security_checklist.pdf",
            "file_hash": "sha256:88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589",
            "uploaded_by": DEMO_PRIVACY_CONTACT_NAME,
            "uploaded_at": ts,
            "expiry_date": "2027-08-10",
            "status": "Pending review",
            "review_notes": "Sample awaiting review illustration.",
            "is_demo": True,
            "audit_trail": [{"action": "DEMO_SEEDED", "timestamp": ts, "actor": "System"}],
        },
    ]

    consents: List[Dict[str, Any]] = [
        {
            "id": "CNS-DEMO-01",
            "principal_id": "patient1-demo@arogya-demo.trustaudit.example",
            "purpose": "Diagnostic test booking updates via SMS & Email",
            "status": "GRANTED",
            "channel": "Public Clinic Booking Form",
            "recorded_at": ts,
            "is_demo": True,
        }
    ]

    return {
        "profile": get_demo_onboarding_profile(),
        "inventory": inventory,
        "vendors": vendors,
        "notices": notices,
        "requests": requests_list,
        "retention": retention,
        "incidents": incidents,
        "evidence": evidence,
        "consents": consents,
        "portal": get_demo_portal_config(),
        "privacy_profile": get_demo_privacy_profile_config(),
    }


def reset_demo_workspace(actor: str = "Administrator") -> Dict[str, Any]:
    """
    Cleanly restores org-default (Arogya Diagnostics Clinic — Demo Workspace)
    across both saas_data.json and dpdp_store.json to the canonical fixture state.
    Never modifies any real customer organisation.
    """
    import dpdp_store
    import dpdp_website_scanner
    import saas_store
    from security_utils import append_audit_log

    seed = get_demo_seed_collections()
    sample_scan = dpdp_website_scanner.generate_demo_website_scan(
        business_name=DEMO_ORG_NAME,
        target_url=DEMO_WEBSITE,
        industry="Healthcare",
    )

    saas_data = saas_store._load_data()
    saas_data.setdefault("organizations", {})[DEMO_ORG_ID] = get_demo_org_record()
    saas_data.setdefault("org_profiles", {})[DEMO_ORG_ID] = {
        "company_name": DEMO_ORG_NAME,
        "country": "India",
        "industry": DEMO_INDUSTRY,
        "website": DEMO_WEBSITE,
        "company_size": "11-50",
        "employee_count": "11-50",
        "business_activities": "Example healthcare clinic workspace for product demonstration.",
        "customer_types": ["Indian Citizens (Patients)", "Minors / Children (<18 years)"],
        "personal_data_categories": ["Health information", "Contact information", "Billing information"],
        "infrastructure": ["AWS Asia Pacific (Mumbai)"],
        "vendors": ["AWS Asia Pacific (Mumbai)", "Razorpay Software Pvt Ltd", "PathCare Reference Lab"],
        "selected_frameworks": ["DPDP"],
        "privacy_contact_name": DEMO_PRIVACY_CONTACT_NAME,
        "privacy_contact_email": DEMO_PRIVACY_EMAIL,
        "is_demo": True,
    }
    saas_store._save_data(saas_data)

    dpdp_data = dpdp_store._load_dpdp_store()
    dpdp_data.setdefault("onboarding_profiles", {})[DEMO_ORG_ID] = seed["profile"]
    dpdp_data.setdefault("data_inventories", {})[DEMO_ORG_ID] = seed["inventory"]
    dpdp_data.setdefault("vendors", {})[DEMO_ORG_ID] = seed["vendors"]
    dpdp_data.setdefault("privacy_notices", {})[DEMO_ORG_ID] = seed["notices"]
    dpdp_data.setdefault("rights_requests", {})[DEMO_ORG_ID] = seed["requests"]
    dpdp_data.setdefault("retention_schedules", {})[DEMO_ORG_ID] = seed["retention"]
    dpdp_data.setdefault("breach_incidents", {})[DEMO_ORG_ID] = seed["incidents"]
    dpdp_data.setdefault("evidence_vault", {})[DEMO_ORG_ID] = seed["evidence"]
    dpdp_data.setdefault("consent_records", {})[DEMO_ORG_ID] = seed["consents"]
    dpdp_data.setdefault("website_scans", {})[DEMO_ORG_ID] = [sample_scan]
    dpdp_data.setdefault("portal_configs", {})[DEMO_ORG_ID] = seed["portal"]
    dpdp_data.setdefault("privacy_profiles", {})[DEMO_ORG_ID] = seed["privacy_profile"]
    dpdp_data.setdefault("organisational_assessments", {}).pop(DEMO_ORG_ID, None)
    dpdp_data.setdefault("assessments", {}).pop(DEMO_ORG_ID, None)
    dpdp_store._save_dpdp_store(dpdp_data)

    append_audit_log(
        DEMO_ORG_ID,
        actor,
        "DEMO_WORKSPACE_RESET",
        {"slug": DEMO_ORG_SLUG, "org_name": DEMO_ORG_NAME, "timestamp": time.time()},
    )
    return {
        "org_id": DEMO_ORG_ID,
        "org_name": DEMO_ORG_NAME,
        "slug": DEMO_ORG_SLUG,
        "is_demo": True,
        "demo_banner": DEMO_BANNER,
        "counts": {
            "inventory_count": len(seed["inventory"]),
            "vendor_count": len(seed["vendors"]),
            "notice_count": len(seed["notices"]),
            "request_count": len(seed["requests"]),
            "retention_count": len(seed["retention"]),
            "incident_count": len(seed["incidents"]),
            "evidence_count": len(seed["evidence"]),
            "scan_count": 1,
        },
    }
