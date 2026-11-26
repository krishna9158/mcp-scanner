"""
TrustAudit - Intelligent Document & Data Extraction Engine (Pure Python, Zero Native Binary Deps)
==================================================================================================
Supports extraction and draft suggestion generation from:
- CSV & XLSX spreadsheets (with automatic privacy-register column mapping)
- DOCX documents (OOXML word/document.xml parser + valid OOXML DOCX exporter)
- PDF files (pure-Python stream / FlateDecode text extractor with honest scanned-PDF fallback)
- Plain text / Markdown / JSON documents
- Public websites (via DPDPWebsiteScanner adapter)

Guardrails:
- Every extracted item starts with status 'Needs review' and confirmed=False.
- Never silently overwrites confirmed business inventory or marks extracted items as legally verified.
- Never fabricates text when a scanned or unreadable binary document contains no extractable text.
"""

from __future__ import annotations

import csv
import datetime
import html
import io
import json
import re
import uuid
import xml.etree.ElementTree as ET
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Tuple


STANDARD_INVENTORY_CATEGORIES = [
    "Contact information",
    "Customer accounts",
    "Billing information",
    "Employee information",
    "Health information",
    "Student information",
    "Website and application information",
    "Other personal information",
]

KNOWN_VENDOR_DIRECTORY: List[Dict[str, str]] = [
    {"name": "Amazon Web Services (AWS)", "category": "Cloud hosting", "role": "Infrastructure Hosting", "data_location": "India (Mumbai / Hyderabad) or configured region"},
    {"name": "Google Cloud Platform (GCP)", "category": "Cloud hosting", "role": "Cloud Compute & Storage", "data_location": "India (Mumbai / Delhi) or configured region"},
    {"name": "Microsoft Azure", "category": "Cloud hosting", "role": "Enterprise Cloud & Database", "data_location": "Central India / South India"},
    {"name": "DigitalOcean", "category": "Cloud hosting", "role": "Application Server Hosting", "data_location": "Bengaluru / Singapore"},
    {"name": "Render", "category": "Cloud hosting", "role": "Web Application Hosting", "data_location": "US / EU region (Verify configured region)"},
    {"name": "Razorpay", "category": "Payment gateway", "role": "Online Payment Processing", "data_location": "India"},
    {"name": "Cashfree Payments", "category": "Payment gateway", "role": "Payment Gateway & Payouts", "data_location": "India"},
    {"name": "Stripe", "category": "Payment gateway", "role": "Card & Subscription Billing", "data_location": "Global / Multi-region"},
    {"name": "PayU India", "category": "Payment gateway", "role": "Payment Gateway", "data_location": "India"},
    {"name": "Zoho CRM", "category": "CRM", "role": "Customer Relationship Management", "data_location": "India"},
    {"name": "HubSpot", "category": "CRM", "role": "Sales & Marketing CRM", "data_location": "Global / US / EU"},
    {"name": "Salesforce", "category": "CRM", "role": "Enterprise CRM", "data_location": "Configured Salesforce Instance"},
    {"name": "LeadSquared", "category": "CRM", "role": "Lead & Patient Intake CRM", "data_location": "India"},
    {"name": "WhatsApp Business / Meta", "category": "Messaging", "role": "Customer Notifications & Support", "data_location": "Global"},
    {"name": "Gupshup", "category": "Messaging", "role": "WhatsApp & SMS Messaging", "data_location": "India"},
    {"name": "MSG91", "category": "Messaging", "role": "Transactional SMS & OTP", "data_location": "India"},
    {"name": "Twilio", "category": "Messaging", "role": "SMS, Voice & Verification API", "data_location": "Global"},
    {"name": "Zoho Mail / Google Workspace", "category": "Email services", "role": "Business Email & Docs", "data_location": "India / Global"},
    {"name": "SendGrid", "category": "Email services", "role": "Transactional Email Delivery", "data_location": "US / Global"},
    {"name": "Postmark", "category": "Email services", "role": "Transactional Email Delivery", "data_location": "Global"},
    {"name": "Google Analytics", "category": "Analytics", "role": "Website Traffic Analytics", "data_location": "Global"},
    {"name": "Mixpanel", "category": "Analytics", "role": "Product Usage Analytics", "data_location": "US / EU"},
    {"name": "Microsoft Clarity", "category": "Analytics", "role": "Session Analytics", "data_location": "Global"},
    {"name": "Zoho Books", "category": "Billing software", "role": "Invoicing & GST Billing", "data_location": "India"},
    {"name": "TallyPrime", "category": "Billing software", "role": "Accounting & Billing", "data_location": "Local / India"},
    {"name": "Freshdesk", "category": "Customer support", "role": "Support Ticketing", "data_location": "India / Global"},
    {"name": "Intercom", "category": "Customer support", "role": "In-App Chat & Support", "data_location": "US / EU"},
    {"name": "Zendesk", "category": "Customer support", "role": "Customer Service Desk", "data_location": "Global"},
]

CATEGORY_KEYWORDS = {
    "Health information": ["patient", "medical", "diagnostic", "lab report", "prescription", "clinic", "hospital", "blood", "uhid", "doctor", "abha"],
    "Billing information": ["invoice", "payment", "gst", "pan", "bank", "upi", "card", "billing", "fee receipt", "transaction", "salary", "payroll"],
    "Employee information": ["employee", "staff", "hr", "pf", "esi", "payroll", "resume", "candidate", "attendance"],
    "Student information": ["student", "parent", "guardian", "school", "marks", "exam", "admission", "roll number"],
    "Customer accounts": ["login", "account", "username", "password", "profile", "subscription", "signup"],
    "Website and application information": ["cookie", "ip address", "analytics", "pixel", "browser", "session", "device id", "telemetry"],
    "Contact information": ["name", "phone", "mobile", "email", "address", "whatsapp", "enquiry"],
}

COLUMN_ALIASES = {
    "category": ["category", "data category", "data_category", "classification", "type", "group"],
    "fields": ["fields", "data fields", "data_fields", "personal data", "elements", "attributes", "columns"],
    "data_subject": ["data subject", "data_subject", "principal", "data principal", "person", "subject"],
    "source": ["source", "collection source", "collected from", "channel", "origin"],
    "purpose": ["purpose", "processing purpose", "reason", "usage", "why"],
    "lawful_basis": ["lawful basis", "legal basis", "lawful_basis", "ground", "consent or section 7"],
    "storage_location": ["storage", "storage system", "storage_location", "system", "database", "location", "where stored"],
    "third_parties": ["vendors", "vendor", "processors", "third_parties", "shared with", "receiving vendor"],
    "retention_period": ["retention", "retention_period", "keep for", "expiry", "duration"],
    "owner": ["owner", "responsible owner", "steward", "department"],
}


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _infer_category(text: str) -> str:
    low = (text or "").lower()
    for cat, kws in CATEGORY_KEYWORDS.items():
        if any(kw in low for kw in kws):
            return cat
    return "Other personal information"


def _map_columns(headers: List[str]) -> Dict[str, str]:
    """Maps spreadsheet headers to TrustAudit inventory schema fields."""
    mapping: Dict[str, str] = {}
    for target, aliases in COLUMN_ALIASES.items():
        for h in headers:
            h_norm = re.sub(r"[^a-z0-9 ]", " ", (h or "").lower()).strip()
            if h_norm == target.replace("_", " ") or h_norm in aliases:
                mapping[target] = h
                break
        if target not in mapping:
            for h in headers:
                h_norm = re.sub(r"[^a-z0-9 ]", " ", (h or "").lower()).strip()
                if any(a in h_norm for a in aliases):
                    mapping[target] = h
                    break
    return mapping


def _parse_csv_bytes(file_bytes: bytes) -> Tuple[List[str], List[Dict[str, str]]]:
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = file_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            text = ""
    if not text.strip():
        return [], []
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return [], []
    try:
        dialect = csv.Sniffer().sniff("\n".join(lines[:10]), delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO("\n".join(lines)), dialect=dialect)
    headers = [str(h or "").strip() for h in (reader.fieldnames or []) if str(h or "").strip()]
    rows = []
    for row in reader:
        cleaned = {str(k or "").strip(): str(v or "").strip() for k, v in row.items() if k is not None}
        if any(cleaned.values()):
            rows.append(cleaned)
        if len(rows) >= 500:
            break
    return headers, rows


def _col_letters_to_idx(ref: str) -> int:
    letters = "".join(ch for ch in ref if ch.isalpha()).upper()
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return max(0, idx - 1)


def _parse_xlsx_bytes(file_bytes: bytes) -> Tuple[List[str], List[Dict[str, str]]]:
    """Pure-Python OOXML XLSX reader parsing xl/sharedStrings.xml and first worksheet."""
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
        names = zf.namelist()
        shared: List[str] = []
        if "xl/sharedStrings.xml" in names:
            ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            for si in ss_root.findall(".//{*}si"):
                txt = "".join(t.text or "" for t in si.findall(".//{*}t"))
                shared.append(txt)

        sheet_candidates = sorted(n for n in names if re.match(r"^xl/worksheets/sheet\d+\.xml$", n))
        if not sheet_candidates:
            return [], []

        ws_root = ET.fromstring(zf.read(sheet_candidates[0]))
        raw_rows: List[List[str]] = []
        for row_el in ws_root.findall(".//{*}row"):
            cells: Dict[int, str] = {}
            max_idx = -1
            for c_el in row_el.findall("{*}c"):
                ref = c_el.attrib.get("r", "")
                c_type = c_el.attrib.get("t", "")
                idx = _col_letters_to_idx(ref) if ref else (max_idx + 1)
                val = ""
                if c_type == "inlineStr":
                    val = "".join(t.text or "" for t in c_el.findall(".//{*}t"))
                else:
                    v_el = c_el.find("{*}v")
                    raw_v = (v_el.text or "").strip() if v_el is not None else ""
                    if c_type == "s" and raw_v.isdigit():
                        s_idx = int(raw_v)
                        val = shared[s_idx] if 0 <= s_idx < len(shared) else ""
                    else:
                        val = raw_v
                cells[idx] = val.strip()
                if idx > max_idx:
                    max_idx = idx
            if max_idx >= 0 and any(cells.values()):
                raw_rows.append([cells.get(i, "") for i in range(max_idx + 1)])
            if len(raw_rows) >= 501:
                break

        if not raw_rows:
            return [], []
        headers = [h or f"Column {i+1}" for i, h in enumerate(raw_rows[0])]
        rows: List[Dict[str, str]] = []
        for r in raw_rows[1:]:
            row_dict = {headers[i]: (r[i] if i < len(r) else "") for i in range(len(headers))}
            if any(row_dict.values()):
                rows.append(row_dict)
        return headers, rows


def _parse_docx_bytes(file_bytes: bytes) -> str:
    """Pure-Python OOXML DOCX text extractor from word/document.xml paragraphs and tables."""
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zf:
        if "word/document.xml" not in zf.namelist():
            return ""
        root = ET.fromstring(zf.read("word/document.xml"))
        paras: List[str] = []
        for p in root.findall(".//{*}p"):
            txt = "".join(t.text or "" for t in p.findall(".//{*}t")).strip()
            if txt:
                paras.append(txt)
        return "\n".join(paras)


def _decode_pdf_literal(raw: str) -> str:
    out = raw.replace(r"\(", "(").replace(r"\)", ")").replace(r"\\", "\\")
    out = out.replace(r"\n", "\n").replace(r"\r", " ").replace(r"\t", " ")
    return re.sub(r"\\[0-7]{1,3}", " ", out)


def _parse_pdf_bytes(file_bytes: bytes) -> str:
    """Best-effort pure-Python PDF text extractor for uncompressed & FlateDecode text streams."""
    extracted: List[str] = []
    # 1. Inspect uncompressed PDF text blocks directly
    latin = file_bytes.decode("latin-1", errors="ignore")
    for block in re.findall(r"BT\s*(.*?)\s*ET", latin, flags=re.S):
        for s in re.findall(r"\(((?:\\.|[^\\)])+)\)\s*(?:Tj|'|\"|TJ)", block):
            dec = _decode_pdf_literal(s).strip()
            if dec:
                extracted.append(dec)

    # 2. Decompress FlateDecode streams
    for stream_bytes in re.findall(rb"stream\r?\n(.*?)\r?\nendstream", file_bytes, flags=re.S):
        data = stream_bytes
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 32):
            try:
                data = zlib.decompress(stream_bytes, wbits)
                break
            except Exception:
                continue
        txt = data.decode("latin-1", errors="ignore")
        for block in re.findall(r"BT\s*(.*?)\s*ET", txt, flags=re.S):
            for s in re.findall(r"\(((?:\\.|[^\\)])+)\)", block):
                dec = _decode_pdf_literal(s).strip()
                if dec:
                    extracted.append(dec)

    joined = "\n".join(extracted).strip()
    if len(joined) >= 20:
        return joined[:80000]
    return ""


def _extract_from_prose(text: str, source_name: str) -> List[Dict[str, Any]]:
    """Extracts candidate DPDP inventory, vendor, contact, notice, and retention drafts from prose text."""
    suggestions: List[Dict[str, Any]] = []
    seen_vals = set()
    now = _now_iso()
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]

    # Emails / Privacy contacts
    for em in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text or "")[:5]:
        key = ("contact", em.lower())
        if key not in seen_vals:
            seen_vals.add(key)
            suggestions.append({
                "id": f"ext-{uuid.uuid4().hex[:8]}",
                "extracted_type": "contact",
                "value": f"Contact / Grievance Email: {em}",
                "category": "Grievance & Contact",
                "fields": [em],
                "purpose": "Customer privacy enquiries and grievance redressal",
                "storage_location": source_name,
                "retention_period": "",
                "source_document": source_name,
                "confidence": "HIGH",
                "status": "Needs review",
                "verified": False,
                "created_at": now,
            })

    # Known vendors mentioned
    low_all = (text or "").lower()
    for v in KNOWN_VENDOR_DIRECTORY:
        short_tok = v["name"].split("(")[0].strip().lower()
        if short_tok in low_all or any(part in low_all for part in short_tok.split() if len(part) >= 5):
            key = ("vendor", v["name"].lower())
            if key not in seen_vals:
                seen_vals.add(key)
                suggestions.append({
                    "id": f"ext-{uuid.uuid4().hex[:8]}",
                    "extracted_type": "vendor",
                    "value": v["name"],
                    "category": v["category"],
                    "fields": [v["role"]],
                    "purpose": v["role"],
                    "storage_location": v["data_location"],
                    "retention_period": "",
                    "source_document": source_name,
                    "confidence": "MEDIUM",
                    "status": "Needs review",
                    "verified": False,
                    "created_at": now,
                })

    # Retention clauses
    for ln in lines:
        if any(w in ln.lower() for w in ("retain", "retention", "erase", "delete", "years", "months")):
            m = re.search(r"(\d+\s+(?:years?|months?|days?))", ln, flags=re.I)
            if m:
                key = ("retention", ln[:80].lower())
                if key not in seen_vals:
                    seen_vals.add(key)
                    suggestions.append({
                        "id": f"ext-{uuid.uuid4().hex[:8]}",
                        "extracted_type": "retention",
                        "value": ln[:180],
                        "category": _infer_category(ln),
                        "fields": [m.group(1)],
                        "purpose": "Documented retention schedule draft",
                        "storage_location": source_name,
                        "retention_period": m.group(1),
                        "source_document": source_name,
                        "confidence": "MEDIUM",
                        "status": "Needs review",
                        "verified": False,
                        "created_at": now,
                    })
                    if len([s for s in suggestions if s["extracted_type"] == "retention"]) >= 4:
                        break

    # Data activities & categories
    activity_signals = [
        ("Patient appointments & clinical intake", "Health information", ["Name", "Phone Number", "Appointment Date", "Medical Symptoms"], "Healthcare consultation and clinical records"),
        ("Diagnostic & lab test reporting", "Health information", ["Patient Name", "Lab Report", "Doctor Referral"], "Diagnostic testing and report delivery"),
        ("Customer account & login profiles", "Customer accounts", ["Name", "Work/Personal Email", "Account ID"], "User account provisioning and authentication"),
        ("Billing, invoices & payment records", "Billing information", ["Customer Name", "Invoice Amount", "Payment Reference", "Tax/GST Details"], "Invoicing, payments and GST compliance"),
        ("Employee payroll & HR files", "Employee information", ["Employee Name", "Bank Account", "Tax ID / PAN", "Attendance"], "Payroll and employment administration (Section 7(i))"),
        ("Student admission & guardian records", "Student information", ["Student Name", "Parent/Guardian Contact", "Fee & Attendance Records"], "Educational administration and fee billing"),
        ("Website enquiry forms & cookies", "Website and application information", ["Name", "Email", "Phone", "Browser Cookie / IP"], "Responding to enquiries and site operation"),
    ]
    for title, cat, fields, purpose in activity_signals:
        kws = CATEGORY_KEYWORDS.get(cat, [])
        if any(kw in low_all for kw in kws):
            key = ("data_activity", title.lower())
            if key not in seen_vals:
                seen_vals.add(key)
                suggestions.append({
                    "id": f"ext-{uuid.uuid4().hex[:8]}",
                    "extracted_type": "data_activity",
                    "value": title,
                    "category": cat,
                    "fields": fields,
                    "purpose": purpose,
                    "storage_location": "To be confirmed by business",
                    "retention_period": "",
                    "source_document": source_name,
                    "confidence": "MEDIUM",
                    "status": "Needs review",
                    "verified": False,
                    "created_at": now,
                })

    if "privacy notice" in low_all or "privacy policy" in low_all or "personal data" in low_all:
        suggestions.append({
            "id": f"ext-{uuid.uuid4().hex[:8]}",
            "extracted_type": "privacy_notice",
            "value": f"Draft Privacy Notice text extracted from {source_name} ({len(lines)} lines)",
            "category": "Privacy Notice",
            "fields": [(text or "")[:1200]],
            "purpose": "Review against Section 5 & Rule 3 notice requirements",
            "storage_location": source_name,
            "retention_period": "",
            "source_document": source_name,
            "confidence": "HIGH",
            "status": "Needs review",
            "verified": False,
            "created_at": now,
        })

    return suggestions


def extract_from_uploaded_file(filename: str, file_bytes: bytes) -> Dict[str, Any]:
    """
    Extracts structured DPDP discovery drafts from CSV, XLSX, DOCX, PDF, TXT, MD, or JSON.
    Always returns unverified draft suggestions requiring human acceptance/editing/rejection.
    """
    ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in (filename or "") else ""
    now = _now_iso()
    suggestions: List[Dict[str, Any]] = []
    column_mapping: Dict[str, str] = {}
    headers: List[str] = []
    rows_count = 0
    warnings: List[str] = []
    raw_preview = ""

    if ext in (".csv", ".xlsx"):
        if ext == ".csv":
            headers, rows = _parse_csv_bytes(file_bytes)
        else:
            headers, rows = _parse_xlsx_bytes(file_bytes)
        rows_count = len(rows)
        column_mapping = _map_columns(headers)
        raw_preview = ", ".join(headers[:10])
        if not rows:
            warnings.append("No tabular data rows detected inside uploaded spreadsheet.")
        for row in rows[:200]:
            cat_val = row.get(column_mapping.get("category", ""), "") or _infer_category(" ".join(row.values()))
            fields_raw = row.get(column_mapping.get("fields", ""), "") or row.get(column_mapping.get("data_subject", ""), "")
            fields_list = [f.strip() for f in re.split(r"[,;/|]+", fields_raw) if f.strip()] if fields_raw else [
                f"{k}: {v}" for k, v in list(row.items())[:4] if v
            ]
            purpose_val = row.get(column_mapping.get("purpose", ""), "") or "Verify business processing purpose"
            storage_val = row.get(column_mapping.get("storage_location", ""), "") or "To be confirmed"
            vendor_val = row.get(column_mapping.get("third_parties", ""), "")
            ret_val = row.get(column_mapping.get("retention_period", ""), "")
            label = fields_list[0] if fields_list else cat_val
            suggestions.append({
                "id": f"ext-{uuid.uuid4().hex[:8]}",
                "extracted_type": "data_activity",
                "value": f"{cat_val} — {label}"[:140],
                "category": cat_val if cat_val in STANDARD_INVENTORY_CATEGORIES else _infer_category(cat_val + " " + " ".join(fields_list)),
                "fields": fields_list[:10],
                "data_subject": row.get(column_mapping.get("data_subject", ""), "Customer / Data Principal"),
                "source": row.get(column_mapping.get("source", ""), filename),
                "purpose": purpose_val,
                "lawful_basis": row.get(column_mapping.get("lawful_basis", ""), "Needs Review"),
                "storage_location": storage_val,
                "third_parties": [v.strip() for v in re.split(r"[,;/]+", vendor_val) if v.strip()] if vendor_val else [],
                "retention_period": ret_val,
                "owner": row.get(column_mapping.get("owner", ""), ""),
                "source_document": filename,
                "confidence": "HIGH" if column_mapping else "MEDIUM",
                "status": "Needs review",
                "verified": False,
                "created_at": now,
            })
            if vendor_val:
                for vn in [v.strip() for v in re.split(r"[,;/]+", vendor_val) if v.strip()]:
                    suggestions.append({
                        "id": f"ext-{uuid.uuid4().hex[:8]}",
                        "extracted_type": "vendor",
                        "value": vn[:100],
                        "category": "Third-Party Processor",
                        "fields": [cat_val],
                        "purpose": purpose_val,
                        "storage_location": storage_val,
                        "retention_period": ret_val,
                        "source_document": filename,
                        "confidence": "MEDIUM",
                        "status": "Needs review",
                        "verified": False,
                        "created_at": now,
                    })
    elif ext == ".docx":
        text = _parse_docx_bytes(file_bytes)
        raw_preview = text[:400]
        if not text.strip():
            warnings.append("DOCX document contained no readable paragraph text.")
        else:
            suggestions = _extract_from_prose(text, filename)
    elif ext == ".pdf":
        text = _parse_pdf_bytes(file_bytes)
        raw_preview = text[:400]
        if not text.strip():
            warnings.append("Scanned or compressed PDF detected without embedded text streams; enter key items manually or upload CSV/DOCX.")
        else:
            suggestions = _extract_from_prose(text, filename)
    elif ext in (".txt", ".md", ".json"):
        text = file_bytes.decode("utf-8", errors="ignore")
        raw_preview = text[:400]
        suggestions = _extract_from_prose(text, filename)
    else:
        warnings.append(f"Unsupported extraction extension '{ext}'. Supported types: .csv, .xlsx, .docx, .pdf, .txt, .md, .json.")

    return {
        "filename": filename,
        "file_type": ext or "unknown",
        "headers": headers,
        "column_mapping": column_mapping,
        "rows_parsed": rows_count,
        "suggestions_count": len(suggestions),
        "suggestions": suggestions,
        "warnings": warnings,
        "raw_preview": raw_preview,
        "legal_verification_note": "Extracted records are drafts marked 'Needs review'. Confirm or edit each item before treating it as an active business record.",
        "extracted_at": now,
    }


def generate_docx_bytes(title: str, content: str, org_name: str = "TrustAudit Customer") -> bytes:
    """
    Generates a genuine standards-compliant OOXML (.docx) binary file purely in Python
    without external libraries so Privacy Notices and SOP drafts export cleanly as Word files.
    """
    buf = io.BytesIO()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [ln for ln in (content or "").splitlines()]

    body_xml_parts = [
        "<w:p><w:pPr><w:pStyle w:val=\"Title\"/></w:pPr>"
        f"<w:r><w:t xml:space=\"preserve\">{html.escape(title or 'TrustAudit Document')}</w:t></w:r></w:p>",
        "<w:p><w:r><w:rPr><w:i/><w:color w:val=\"555555\"/></w:rPr>"
        f"<w:t xml:space=\"preserve\">{html.escape(org_name)} | Exported from TrustAudit on {now_str} | Draft for business and legal review</w:t></w:r></w:p>",
    ]
    for ln in lines:
        escaped = html.escape(ln)
        body_xml_parts.append(f"<w:p><w:r><w:t xml:space=\"preserve\">{escaped}</w:t></w:r></w:p>")

    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body>"
        + "".join(body_xml_parts)
        + "<w:sectPr/></w:body></w:document>"
    )
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", rels_xml)
        zf.writestr("word/document.xml", document_xml)
    return buf.getvalue()
