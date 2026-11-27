"""
TrustAudit - Data Intelligence & Safe Data Flow Mapping Engine.
Provides safe, read-only metadata inspection and automated data flow mapping.

Principles:
- Zero raw personal data extraction: inspects schema, field names, and column headers only.
- Strict heuristic categorization (General, Health, Financial, Minor, Biometric).
- Generates draft data inventory entries for human compliance review.
- Builds an interactive Data Flow Graph: Customer -> Website -> DB -> CRM -> Vendor -> Analytics.
"""

import re
import datetime
import uuid
from typing import Dict, Any, List, Optional
import dpdp_store

# Heuristic patterns for personal data detection in column names / schemas
FIELD_DETECTION_PATTERNS = [
    {
        "category": "Patient Health & Medical Diagnostic Data",
        "principal_type": "Patients",
        "sensitivity": "HIGH",
        "patterns": [r"diagnos", r"patient", r"medical", r"blood", r"lab_res", r"prescri", r"symptom", r"ehr", r"emr", r"dicom", r"pacs"],
        "reason": "Matches clinical and healthcare nomenclature. Section 8(5) high-security safeguards required.",
        "suggested_retention": "3 to 5 years per Clinical Establishments Act and NABL",
        "lawful_basis": "DPDP Section 6 (Consent) & Section 7(e) Medical Emergency"
    },
    {
        "category": "Government Identifiers (Aadhaar Reference / PAN)",
        "principal_type": "Indian Citizens / Taxpayers",
        "sensitivity": "HIGH",
        "patterns": [r"aadhaar", r"uidai", r"pan_no", r"pan_card", r"voter_id", r"passport", r"driving_lic"],
        "reason": "Matches statutory national identity records. Requires strict access control and masking.",
        "suggested_retention": "8 years for tax records / duration of service",
        "lawful_basis": "DPDP Section 7(c) Legal Obligation (Income Tax / Statutory filings)"
    },
    {
        "category": "Financial & Payment Transaction Records",
        "principal_type": "Customers / Billing Contacts",
        "sensitivity": "HIGH",
        "patterns": [r"bank_acc", r"ifsc", r"credit_card", r"payment", r"invoice", r"gst_in", r"billing", r"salary", r"income", r"upi", r"card_number", r"account_no"],
        "reason": "Matches financial transaction records. PCI-DSS tokenization and statutory tax retention apply.",
        "suggested_retention": "8 years per Income Tax Act Section 44AB",
        "lawful_basis": "DPDP Section 7(c) Statutory Obligation"
    },
    {
        "category": "Children's & Protected Persons' Records",
        "principal_type": "Children (<18) & Persons with Lawful Guardians",
        "sensitivity": "CRITICAL",
        "patterns": [r"minor", r"child", r"student_dob", r"guardian", r"parent_consent", r"grade", r"school_id"],
        "reason": "Under Section 9(1), processing personal data of children under 18 or persons with disabilities who have lawful guardians requires verifiable parent or lawful guardian consent, and prohibits behavioral tracking of children.",
        "suggested_retention": "Duration of enrollment + 3 years",
        "lawful_basis": "DPDP Section 9(1) (Verifiable Parent / Lawful Guardian Consent)"
    },
    {
        "category": "Customer Contact & Demographic Information",
        "principal_type": "Customers / App Users",
        "sensitivity": "MEDIUM",
        "patterns": [r"email", r"phone", r"mobile", r"contact", r"first_name", r"last_name", r"address", r"pincode", r"city"],
        "reason": "Directly identifying contact details. Requires Section 5 itemised notice and affirmative consent.",
        "suggested_retention": "Account lifetime + 30 days post-deletion",
        "lawful_basis": "DPDP Section 6 (Consent)"
    },
    {
        "category": "Web Access Telemetry & Security Audit Logs",
        "principal_type": "Website Visitors / System Users",
        "sensitivity": "LOW",
        "patterns": [r"ip_addr", r"user_agent", r"session_id", r"cookie", r"device_id", r"referrer"],
        "reason": "Observable digital footprints. Mandatory 180-day log retention under CERT-In Cyber Security Directions.",
        "suggested_retention": "180 days per CERT-In Cyber Security Directions",
        "lawful_basis": "DPDP Section 8(5) Reasonable Security Safeguards"
    }
]


def inspect_schema_metadata(table_name: str, column_names: List[str], source_system: str = "Primary Database") -> List[Dict[str, Any]]:
    """
    Safely inspects a list of column names or field keys without reading any row data.
    Identifies potential personal data fields and explains why each was flagged.
    """
    discovered_fields = []

    for col in column_names:
        clean_col = col.lower().strip()
        matched = False

        for rule in FIELD_DETECTION_PATTERNS:
            for pat in rule["patterns"]:
                if re.search(pat, clean_col):
                    discovered_fields.append({
                        "field_name": col,
                        "table_name": table_name,
                        "source_system": source_system,
                        "detected_category": rule["category"],
                        "principal_type": rule["principal_type"],
                        "sensitivity": rule["sensitivity"],
                        "reason": rule["reason"],
                        "suggested_retention": rule["suggested_retention"],
                        "suggested_lawful_basis": rule["lawful_basis"],
                        "review_status": "DRAFT_PENDING_REVIEW"
                    })
                    matched = True
                    break
            if matched:
                break

    return discovered_fields


def generate_data_flow_map(org_id: str) -> Dict[str, Any]:
    """
    Constructs a comprehensive, interactive Data Flow Graph from actual tenant records.
    Graph Structure:
    Data Principal -> Intake Channel -> Storage/Database -> Internal Processing (CRM/ERP) -> External Processors/Vendors -> Archive/Deletion
    """
    profile = dpdp_store.get_onboarding_profile(org_id) or {}
    inventory = dpdp_store.get_data_inventory(org_id)
    vendors = dpdp_store.get_vendors(org_id)
    retention_scheds = dpdp_store.get_retention_schedules(org_id)

    org_name = profile.get("company_name", "Your Organisation")
    is_empty = len(inventory) == 0

    if is_empty:
        return {
            "is_empty": True,
            "message": "No data inventory mapped yet. Add inventory entries or load an industry template to view your Data Flow Map.",
            "nodes": [],
            "edges": [],
            "flows": []
        }

    nodes = [
        {"id": "node-principals", "label": "Data Principals", "type": "origin", "category": "Principals", "subtext": "Customers, Patients, Users, Minors"},
        {"id": "node-intake", "label": "Website & App Intake", "type": "intake", "category": "Collection Channel", "subtext": "HTTPS Web Forms, APIs, Kiosks"},
        {"id": "node-db", "label": f"{org_name} Database", "type": "storage", "category": "Primary Storage", "subtext": "AES-256 Encrypted Store (India)"},
        {"id": "node-crm", "label": "Internal Operations (ERP / CRM)", "type": "processing", "category": "Processing", "subtext": "Billing, Support & Service Execution"},
        {"id": "node-vendors", "label": f"Third-Party Processors ({len(vendors)} Registered)", "type": "processor", "category": "Data Processors", "subtext": "Cloud Hosts, SMS Gateways, Labs"},
        {"id": "node-archive", "label": "Statutory Retention & Erasure", "type": "archive", "category": "Lifecycle End", "subtext": "Automated Purpose-Cessation Purge"}
    ]

    edges = [
        {"from": "node-principals", "to": "node-intake", "label": "Voluntary Provision / Consent", "basis": "Section 6 Consent"},
        {"from": "node-intake", "to": "node-db", "label": "TLS 1.3 Ingestion", "basis": "Section 8(5) Safeguards"},
        {"from": "node-db", "to": "node-crm", "label": "RBAC Role Access", "basis": "Section 4 Processing Purpose"},
        {"from": "node-crm", "to": "node-vendors", "label": "Sec 8(2) DPA Contract", "basis": f"{len(vendors)} Processors Linked"},
        {"from": "node-db", "to": "node-archive", "label": "Sec 8(7) Erasure Schedule", "basis": f"{len(retention_scheds)} Retention Rules"}
    ]

    flows = []
    for item in inventory:
        flows.append({
            "flow_id": item.get("id"),
            "category": item.get("category"),
            "principal_type": item.get("principal_type"),
            "collection_source": item.get("source"),
            "processing_purpose": item.get("purpose"),
            "storage_system": item.get("storage_system"),
            "receiving_vendors": item.get("external_recipients") or item.get("processor") or "Internal Only",
            "legal_basis": item.get("legal_basis"),
            "retention_period": item.get("retention_period"),
            "review_status": item.get("review_status", "CONFIRMED")
        })

    return {
        "is_empty": False,
        "nodes": nodes,
        "edges": edges,
        "flows": flows,
        "summary": {
            "total_streams": len(inventory),
            "vendors_linked": len(vendors),
            "retention_rules_linked": len(retention_scheds)
        }
    }
