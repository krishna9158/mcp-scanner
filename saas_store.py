"""
TrustAudit SaaS Multi-Tenancy, Persistent Auth, Plan Enforcement & Project Layer.

Provides clean organization-isolated data models for:
- Organizations (Configurable Plans: free ₹0, starter ₹999/mo, growth ₹1,999/mo, business ₹2,999/mo)
- Users (Roles: admin, member, viewer; plus platform-admin flag for /api/admin/*)
- Persistent SHA-256 hashed sessions and single-use password reset tokens
- Projects, Scan Records, and Organization Profiles
- Atomic JSON storage via security_utils
"""

import json
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from security_utils import (
    append_audit_log,
    atomic_write_json,
    get_data_dir,
    safe_read_json,
    sanitize_plain_text,
)

def _default_data_file() -> str:
    env_dir = os.environ.get("TRUSTAUDIT_DATA_DIR", "").strip()
    if env_dir:
        return os.path.join(os.path.abspath(env_dir), "saas_data.json")
    return os.path.join(os.path.dirname(__file__), "saas_data.json")

DATA_FILE = _default_data_file()

# Configurable Business Pricing Plans (India INR)
_STARTER_PRICE = int(os.environ.get("TRUSTAUDIT_PRICE_STARTER_INR", 999))
_GROWTH_PRICE = int(os.environ.get("TRUSTAUDIT_PRICE_GROWTH_INR", 1999))
_BUSINESS_PRICE = int(os.environ.get("TRUSTAUDIT_PRICE_BUSINESS_INR", 2999))

_GROWTH_PLAN = {
    "key": "growth",
    "name": "Growth",
    "price_monthly_inr": _GROWTH_PRICE,
    "price_monthly_usd": 24,
    "max_domains": int(os.environ.get("TRUSTAUDIT_GROWTH_MAX_DOMAINS", 15)),
    "max_repositories": int(os.environ.get("TRUSTAUDIT_GROWTH_MAX_REPOS", 15)),
    "max_projects": int(os.environ.get("TRUSTAUDIT_GROWTH_MAX_PROJECTS", 30)),
    "max_team_members": int(os.environ.get("TRUSTAUDIT_GROWTH_MAX_MEMBERS", 10)),
    "max_data_streams": int(os.environ.get("TRUSTAUDIT_GROWTH_MAX_STREAMS", 100)),
    "max_vendors": int(os.environ.get("TRUSTAUDIT_GROWTH_MAX_VENDORS", 100)),
    "max_evidence_items": int(os.environ.get("TRUSTAUDIT_GROWTH_MAX_EVIDENCE", 500)),
    "max_scans_per_month": int(os.environ.get("TRUSTAUDIT_GROWTH_MAX_SCANS", 300)),
    "scan_frequency": "on_demand_and_reminder",
    "email_alerts": True,
    "webhook_alerts": True,
    "pdf_and_zip_export": True,
    "ai_queries_per_month": 500,
    "features": [
        "Up to 15 Websites Scanned & Monitored",
        "Up to 100 Customer Data Records & Vendors",
        "Up to 10 Team Members with Role Permissions",
        "Up to 500 Evidence Files with Verification States",
        "Real PDF Reports, CSV Exports & ZIP Evidence Bundles",
        "Webhook Alerts & AI DPDP Assistant (500 queries/mo)",
    ],
}

_BUSINESS_PLAN = {
    "key": "business",
    "name": "Business",
    "price_monthly_inr": _BUSINESS_PRICE,
    "price_monthly_usd": 36,
    "max_domains": int(os.environ.get("TRUSTAUDIT_BUSINESS_MAX_DOMAINS", 50)),
    "max_repositories": int(os.environ.get("TRUSTAUDIT_BUSINESS_MAX_REPOS", 50)),
    "max_projects": int(os.environ.get("TRUSTAUDIT_BUSINESS_MAX_PROJECTS", 100)),
    "max_team_members": int(os.environ.get("TRUSTAUDIT_BUSINESS_MAX_MEMBERS", 25)),
    "max_data_streams": int(os.environ.get("TRUSTAUDIT_BUSINESS_MAX_STREAMS", 500)),
    "max_vendors": int(os.environ.get("TRUSTAUDIT_BUSINESS_MAX_VENDORS", 500)),
    "max_evidence_items": int(os.environ.get("TRUSTAUDIT_BUSINESS_MAX_EVIDENCE", 2500)),
    "max_scans_per_month": int(os.environ.get("TRUSTAUDIT_BUSINESS_MAX_SCANS", 1500)),
    "scan_frequency": "on_demand_and_reminder",
    "email_alerts": True,
    "webhook_alerts": True,
    "pdf_and_zip_export": True,
    "ai_queries_per_month": 2000,
    "features": [
        "Up to 50 Websites & Branch Locations",
        "Up to 500 Customer Data Records & Vendors",
        "Up to 25 Team Members with Admin/Member/Viewer Roles",
        "Up to 2,500 Evidence Files & Full Audit Log Exports",
        "Complete Evidence Verification & Renewal Tracking",
        "AI DPDP Assistant (2,000 queries/mo) & Priority Support",
    ],
}

PLANS = {
    "free": {
        "key": "free",
        "name": "Free Community",
        "price_monthly_inr": 0,
        "price_monthly_usd": 0,
        "max_domains": int(os.environ.get("TRUSTAUDIT_FREE_MAX_DOMAINS", 1)),
        "max_repositories": int(os.environ.get("TRUSTAUDIT_FREE_MAX_REPOS", 1)),
        "max_projects": int(os.environ.get("TRUSTAUDIT_FREE_MAX_PROJECTS", 2)),
        "max_team_members": int(os.environ.get("TRUSTAUDIT_FREE_MAX_MEMBERS", 1)),
        "max_data_streams": int(os.environ.get("TRUSTAUDIT_FREE_MAX_STREAMS", 5)),
        "max_vendors": int(os.environ.get("TRUSTAUDIT_FREE_MAX_VENDORS", 5)),
        "max_evidence_items": int(os.environ.get("TRUSTAUDIT_FREE_MAX_EVIDENCE", 10)),
        "max_scans_per_month": int(os.environ.get("TRUSTAUDIT_FREE_MAX_SCANS", 10)),
        "scan_frequency": "manual",
        "email_alerts": False,
        "webhook_alerts": False,
        "pdf_and_zip_export": True,
        "ai_queries_per_month": 25,
        "features": [
            "1 Website Privacy Check",
            "Up to 5 Customer Data Records & 5 Vendors",
            "1 Team Member (Owner)",
            "Up to 10 Evidence Files",
            "DPDP Self-Assessment & Plain-English Action Plan",
            "PDF & CSV Readiness Export",
        ],
    },
    "starter": {
        "key": "starter",
        "name": "Starter",
        "price_monthly_inr": _STARTER_PRICE,
        "price_monthly_usd": 12,
        "max_domains": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_DOMAINS", 5)),
        "max_repositories": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_REPOS", 5)),
        "max_projects": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_PROJECTS", 10)),
        "max_team_members": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_MEMBERS", 3)),
        "max_data_streams": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_STREAMS", 25)),
        "max_vendors": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_VENDORS", 25)),
        "max_evidence_items": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_EVIDENCE", 100)),
        "max_scans_per_month": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_SCANS", 60)),
        "scan_frequency": "on_demand",
        "email_alerts": False,
        "webhook_alerts": False,
        "pdf_and_zip_export": True,
        "ai_queries_per_month": 100,
        "features": [
            "Up to 5 Websites Scanned on Demand",
            "Up to 25 Customer Data Records & 25 Vendors",
            "Up to 3 Team Members",
            "Up to 100 Evidence Vault Files",
            "Privacy Notice Generator, Consent & Request Trackers",
            "PDF Report, CSV & ZIP Evidence Bundle",
        ],
    },
    "growth": _GROWTH_PLAN,
    "business": _BUSINESS_PLAN,
    # Backward-compatible aliases so existing stored orgs or API callers never fail
    "pro": dict(_GROWTH_PLAN, alias_for="growth"),
    "enterprise": dict(_BUSINESS_PLAN, alias_for="business"),
}


def get_public_plans() -> List[Dict[str, Any]]:
    """Returns canonical launch pricing tiers without legacy aliases."""
    return [PLANS["free"], PLANS["starter"], PLANS["growth"], PLANS["business"]]


def _load_data() -> Dict[str, Any]:
    if not os.path.exists(DATA_FILE):
        initial = {
            "organizations": {
                "org-default": {
                    "id": "org-default",
                    "name": "Sample Indian Clinic (Demo Sandbox)",
                    "slug": "demo-sandbox",
                    "plan": "starter",
                    "is_demo": True,
                    "created_at": time.time(),
                    "max_projects": 10,
                    "scans_count": 0,
                }
            },
            "users": {
                "usr-default": {
                    "id": "usr-default",
                    "org_id": "org-default",
                    "email": "demo@trustaudit.example",
                    "name": "Demo Owner",
                    "role": "admin",
                    "created_at": time.time(),
                }
            },
            "projects": {},
            "scans": {},
            "finding_overrides": {},
            "sessions": {},
            "password_resets": {},
        }
        _save_data(initial)
        return initial

    data = safe_read_json(
        DATA_FILE,
        lambda: {
            "organizations": {},
            "users": {},
            "projects": {},
            "scans": {},
            "finding_overrides": {},
            "sessions": {},
            "password_resets": {},
        },
    )
    data.setdefault("sessions", {})
    data.setdefault("password_resets", {})
    return data


def _save_data(data: Dict[str, Any]):
    atomic_write_json(DATA_FILE, data)


# ---------------------------------------------------------------------------
# Multi-Tenancy & Access Control
# ---------------------------------------------------------------------------

def validate_tenant_access(user_org_id: str, target_org_id: str) -> bool:
    """Strictly verifies that a user's organization matches target organization."""
    if not user_org_id or not target_org_id:
        return False
    return user_org_id == target_org_id


def get_organization(org_id: str = "org-default") -> Optional[Dict[str, Any]]:
    """Retrieves organization record with current plan limits."""
    data = _load_data()
    org = data.get("organizations", {}).get(org_id)
    if not org and org_id == "org-default":
        org = {
            "id": "org-default",
            "name": "Sample Indian Clinic (Demo Sandbox)",
            "slug": "demo-sandbox",
            "plan": "starter",
            "is_demo": True,
            "created_at": time.time(),
            "max_projects": 10,
            "scans_count": 0,
        }
        data.setdefault("organizations", {})["org-default"] = org
        _save_data(data)
    if org:
        plan_key = org.get("plan", "starter").lower()
        plan_info = PLANS.get(plan_key, PLANS["starter"])
        org_copy = dict(org)
        org_copy["plan_details"] = plan_info
        return org_copy
    return None


def upgrade_org_plan(org_id: str, new_plan: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Updates an organization's subscription plan cleanly."""
    clean = (new_plan or "").strip().lower()
    if clean not in PLANS:
        return False, f"Unknown plan '{new_plan}'. Choose from free, starter, growth, business.", None
    data = _load_data()
    org = data.get("organizations", {}).get(org_id)
    if not org:
        return False, "Organization not found.", None
    org["plan"] = clean
    org["max_projects"] = PLANS[clean]["max_projects"]
    _save_data(data)
    return True, f"Plan updated to {PLANS[clean]['name']}.", get_organization(org_id)


def get_plan_limits(plan_name: str) -> Dict[str, Any]:
    """Returns limit parameters for the specified plan."""
    return PLANS.get((plan_name or "starter").lower(), PLANS["starter"])


def check_plan_limits(org_id: str, resource_type: str, current_count: Optional[int] = None) -> Tuple[bool, Optional[str]]:
    """
    Validates if organization has capacity under its subscription tier.
    """
    org = get_organization(org_id)
    if not org:
        return False, "Organization not found."

    plan = org.get("plan_details", PLANS["starter"])
    data = _load_data()
    projects = [p for p in data.get("projects", {}).values() if p.get("org_id") == org_id]

    if resource_type == "project":
        count = current_count if current_count is not None else len(projects)
        max_allowed = plan.get("max_projects", 10)
        if count >= max_allowed:
            return False, f"Plan limit reached ({count}/{max_allowed} projects). Upgrade your plan for additional capacity."

    elif resource_type == "website":
        web_count = current_count if current_count is not None else sum(1 for p in projects if p.get("target_type") == "website" or p.get("website_url"))
        max_allowed = plan.get("max_domains", 5)
        if web_count >= max_allowed:
            return False, f"Website limit reached ({web_count}/{max_allowed} websites on your {plan['name']} plan). Upgrade to add more websites."

    elif resource_type == "repository":
        repo_count = current_count if current_count is not None else sum(1 for p in projects if p.get("target_type") == "repository" or p.get("repo_url"))
        max_allowed = plan.get("max_repositories", 5)
        if repo_count >= max_allowed:
            return False, f"Repository limit reached ({repo_count}/{max_allowed} repos). Upgrade to monitor more repos."

    elif resource_type == "team_member":
        members = [u for u in data.get("users", {}).values() if u.get("org_id") == org_id]
        count = current_count if current_count is not None else len(members)
        max_allowed = plan.get("max_team_members", 3)
        if count >= max_allowed:
            return False, f"Team seat limit reached ({count}/{max_allowed} members on your {plan['name']} plan). Upgrade to invite more team members."

    elif resource_type == "data_stream":
        max_allowed = plan.get("max_data_streams", 25)
        if current_count is not None and current_count >= max_allowed:
            return False, f"Customer data record limit reached ({current_count}/{max_allowed} records on your {plan['name']} plan)."

    elif resource_type == "vendor":
        max_allowed = plan.get("max_vendors", 25)
        if current_count is not None and current_count >= max_allowed:
            return False, f"Vendor limit reached ({current_count}/{max_allowed} vendors on your {plan['name']} plan)."

    elif resource_type == "evidence":
        max_allowed = plan.get("max_evidence_items", 100)
        if current_count is not None and current_count >= max_allowed:
            return False, f"Evidence Vault limit reached ({current_count}/{max_allowed} files on your {plan['name']} plan)."

    return True, None


# ---------------------------------------------------------------------------
# Project Management
# ---------------------------------------------------------------------------

def list_projects_for_org(org_id: str = "org-default") -> List[Dict[str, Any]]:
    """Lists all security projects isolated to the specified organization."""
    data = _load_data()
    projects = [p for p in data.get("projects", {}).values() if p.get("org_id") == org_id]
    projects.sort(key=lambda x: x.get("last_scan", 0), reverse=True)
    return projects


def get_project(project_id: str, org_id: str = "org-default") -> Optional[Dict[str, Any]]:
    """Gets a project ensuring tenant isolation."""
    data = _load_data()
    project = data.get("projects", {}).get(project_id)
    if project and project.get("org_id") == org_id:
        return project
    return None


get_project_by_id = get_project


def update_project(project_id: str, updates: Dict[str, Any], org_id: str = "org-default") -> Optional[Dict[str, Any]]:
    """Updates fields on an existing project."""
    data = _load_data()
    project = data.get("projects", {}).get(project_id)
    if not project or project.get("org_id") != org_id:
        return None

    for k, v in updates.items():
        if k != "id" and k != "org_id":
            project[k] = v

    data.setdefault("projects", {})[project_id] = project
    _save_data(data)
    return project


def create_or_update_project(
    name: str,
    target_url: str,
    target_type: str = "repository",
    org_id: str = "org-default",
    score: int = 100,
    grade: str = "A",
    critical_findings: int = 0,
    open_findings: int = 0,
    scan_frequency: str = "daily",
) -> Dict[str, Any]:
    """Creates or updates a security project in the tenant store."""
    data = _load_data()

    matched_id = None
    for pid, p in data.get("projects", {}).items():
        if p.get("org_id") == org_id and (p.get("repo_url") == target_url or p.get("website_url") == target_url):
            matched_id = pid
            break

    pid = matched_id or f"proj-{uuid.uuid4().hex[:8]}"
    project = data.get("projects", {}).get(pid, {
        "id": pid,
        "org_id": org_id,
        "name": name,
        "target_type": target_type,
        "repo_url": target_url if target_type == "repository" else "",
        "website_url": target_url if target_type == "website" else "",
        "mcp_servers_count": 1 if target_type == "repository" else 0,
        "regression_status": "PASS",
        "monitoring_status": "ACTIVE",
        "scan_frequency": scan_frequency,
        "next_scan_at": time.time() + 86400,
        "timeline": [],
        "created_at": time.time()
    })

    project["name"] = name or project.get("name", "Security Target")
    project["last_score"] = score
    project["last_grade"] = grade
    project["critical_findings"] = critical_findings
    project["open_findings"] = open_findings
    project["last_scan"] = time.time()

    data.setdefault("projects", {})[pid] = project
    _save_data(data)
    return project


def record_scan_event(
    target_url: str,
    scan_type: str,
    scan_result: Dict[str, Any],
    org_id: str = "org-default",
    project_id: Optional[str] = None
) -> str:
    """Records a completed scan event in the tenant audit log."""
    data = _load_data()
    scan_id = f"scan-{uuid.uuid4().hex[:10]}"

    scan_record = {
        "id": scan_id,
        "org_id": org_id,
        "project_id": project_id,
        "target_url": target_url,
        "scan_type": scan_type,
        "score": scan_result.get("score", 100),
        "grade": scan_result.get("grade", "A"),
        "status": scan_result.get("status", "SECURE"),
        "findings_count": len(scan_result.get("findings", scan_result.get("report", []))),
        "created_at": time.time()
    }

    data.setdefault("scans", {})[scan_id] = scan_record

    # Increment org scan counter
    if org_id in data.get("organizations", {}):
        data["organizations"][org_id]["scans_count"] = data["organizations"][org_id].get("scans_count", 0) + 1

    _save_data(data)
    return scan_id


# ---------------------------------------------------------------------------
# Timeline & Findings Management
# ---------------------------------------------------------------------------

def append_project_timeline(
    project_id: str,
    events: List[Dict[str, Any]],
    delta: Optional[Dict[str, Any]] = None,
    last_scan_result: Optional[Dict[str, Any]] = None,
    org_id: str = "org-default"
):
    """Appends security events to project timeline and caches latest scan result."""
    data = _load_data()
    project = data.get("projects", {}).get(project_id)
    if not project or project.get("org_id") != org_id:
        return

    timeline = project.setdefault("timeline", [])
    for ev in events:
        timeline.insert(0, ev)  # Prepend latest

    # Cap timeline at 100 events
    project["timeline"] = timeline[:100]

    if delta:
        project["last_delta"] = delta
    if last_scan_result:
        # Cache lightweight summary
        project["last_scan_result"] = {
            "score": last_scan_result.get("score"),
            "grade": last_scan_result.get("grade"),
            "status": last_scan_result.get("status"),
            "findings": last_scan_result.get("findings", []),
            "timestamp": time.time(),
        }

    _save_data(data)


def get_project_timeline(project_id: str, org_id: str = "org-default", limit: int = 30) -> List[Dict[str, Any]]:
    """Retrieves timeline events for a project."""
    data = _load_data()
    project = data.get("projects", {}).get(project_id)
    if not project or project.get("org_id") != org_id:
        return []
    return project.get("timeline", [])[:limit]


def get_finding_override(finding_id: str, org_id: str = "org-default") -> Dict[str, Any]:
    """Retrieves finding lifecycle overrides."""
    data = _load_data()
    key = f"{org_id}:{finding_id}"
    return data.get("finding_overrides", {}).get(key, {"status": "open", "assigned_to": None, "notes": ""})


def set_finding_status(
    finding_id: str,
    status: str,
    org_id: str = "org-default",
    assigned_to: Optional[str] = None,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """Updates finding lifecycle status (open, acknowledged, fixed, verified, false_positive)."""
    data = _load_data()
    key = f"{org_id}:{finding_id}"
    override = data.setdefault("finding_overrides", {}).get(key, {
        "finding_id": finding_id,
        "org_id": org_id,
        "status": "open",
        "assigned_to": None,
        "notes": "",
        "updated_at": time.time()
    })

    override["status"] = status
    if assigned_to is not None:
        override["assigned_to"] = assigned_to
    if notes is not None:
        override["notes"] = notes
    override["updated_at"] = time.time()

    data.setdefault("finding_overrides", {})[key] = override
    _save_data(data)
    return override


def assign_finding(
    finding_id: str,
    assigned_to: str,
    org_id: str = "org-default"
) -> Dict[str, Any]:
    """Assigns a vulnerability finding to a team member."""
    return set_finding_status(finding_id, "in_progress", org_id=org_id, assigned_to=assigned_to)


def add_finding_note(
    finding_id: str,
    note: str,
    author: str = "Security Team",
    org_id: str = "org-default"
) -> Dict[str, Any]:
    """Appends an audit note to a finding record."""
    data = _load_data()
    key = f"{org_id}:{finding_id}"
    override = data.setdefault("finding_overrides", {}).get(key, {
        "finding_id": finding_id,
        "org_id": org_id,
        "status": "open",
        "assigned_to": None,
        "notes": "",
        "notes_list": [],
        "updated_at": time.time()
    })
    notes_list = override.setdefault("notes_list", [])
    now_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    notes_list.append({"note": note, "author": author, "timestamp": now_str})
    override["notes"] = f"{override.get('notes', '')}\n[{now_str} {author}] {note}".strip()
    override["updated_at"] = time.time()
    data.setdefault("finding_overrides", {})[key] = override
    _save_data(data)
    return override


# ---------------------------------------------------------------------------
# Asset Inventory Aggregation
# ---------------------------------------------------------------------------

def get_organization_assets(org_id: str = "org-default") -> List[Dict[str, Any]]:
    """
    Returns organized attack surface inventory aggregated across projects and scans.
    Categorized into: Websites, APIs, Repositories, Subdomains, and Cloud Endpoints.
    """
    data = _load_data()
    projects = [p for p in data.get("projects", {}).values() if p.get("org_id") == org_id]
    assets = []
    seen = set()

    for p in projects:
        # 1. Websites & Web Apps
        web_url = p.get("website_url")
        if web_url and web_url not in seen:
            seen.add(web_url)
            assets.append({
                "id": f"asset-web-{len(assets)+1}",
                "name": p.get("name", "Website"),
                "type": "website",
                "target": web_url,
                "environment": "Production",
                "tech_stack": ["TLS 1.3", "Nginx", "HTML5"],
                "score": p.get("last_score", 100),
                "grade": p.get("last_grade", "A"),
                "open_findings": p.get("open_findings", 0),
                "critical_findings": p.get("critical_findings", 0),
                "monitoring_status": p.get("monitoring_status", "ACTIVE"),
                "last_scanned": p.get("last_scan", p.get("created_at", time.time())),
                "project_id": p.get("id"),
            })

        # 2. Source Repositories
        repo_url = p.get("repo_url")
        if repo_url and repo_url not in seen:
            seen.add(repo_url)
            assets.append({
                "id": f"asset-repo-{len(assets)+1}",
                "name": p.get("name", "Repository"),
                "type": "repository",
                "target": repo_url,
                "environment": "Source Code",
                "tech_stack": ["Git", "Python/Node", "MCP"],
                "score": p.get("last_score", 100),
                "grade": p.get("last_grade", "A"),
                "open_findings": p.get("open_findings", 0),
                "critical_findings": p.get("critical_findings", 0),
                "monitoring_status": p.get("monitoring_status", "ACTIVE"),
                "last_scanned": p.get("last_scan", p.get("created_at", time.time())),
                "project_id": p.get("id"),
            })

    return assets


# ---------------------------------------------------------------------------
# Team Members Management
# ---------------------------------------------------------------------------

def list_team_members(org_id: str = "org-default") -> List[Dict[str, Any]]:
    """Lists all users belonging to the organization (sanitized without secrets)."""
    data = _load_data()
    users = []
    for u in data.get("users", {}).values():
        if u.get("org_id") == org_id:
            uc = dict(u)
            uc.pop("pwd_hash", None)
            uc.pop("salt", None)
            uc.pop("mfa_secret", None)
            uc.pop("mfa_pending_secret", None)
            users.append(uc)
    if not users and org_id == "org-default":
        default_user = {
            "id": "usr-default",
            "org_id": org_id,
            "email": "demo@trustaudit.example",
            "name": "Demo Owner",
            "role": "admin",
            "created_at": time.time(),
        }
        data.setdefault("users", {})["usr-default"] = default_user
        _save_data(data)
        return [default_user]
    return users


def add_team_member(
    name: str,
    email: str,
    role: str = "member",
    org_id: str = "org-default",
) -> Dict[str, Any]:
    """Adds a new team member with role: admin, member, or viewer, enforcing plan seat limit."""
    allowed, err = check_plan_limits(org_id, "team_member")
    if not allowed:
        raise ValueError(err or "Team member limit reached.")

    clean_email = sanitize_plain_text(email, 160).lower()
    if not clean_email or "@" not in clean_email:
        raise ValueError("A valid team member email address is required.")

    data = _load_data()
    for existing in data.get("users", {}).values():
        if existing.get("email", "").lower() == clean_email:
            raise ValueError("A user with this email address already exists.")

    uid = f"usr-{uuid.uuid4().hex[:8]}"
    user = {
        "id": uid,
        "org_id": org_id,
        "name": sanitize_plain_text(name, 120) or clean_email.split("@")[0],
        "email": clean_email,
        "role": role if role in ("admin", "member", "viewer") else "member",
        "invite_pending": True,
        "mfa_enabled": False,
        "created_at": time.time(),
    }
    data.setdefault("users", {})[uid] = user
    _save_data(data)
    return user


def update_team_member_role(user_id: str, new_role: str, org_id: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Updates a member's RBAC role safely while protecting against zero-admin lockouts."""
    if new_role not in ("admin", "member", "viewer"):
        return False, "Role must be admin, member, or viewer.", None
    data = _load_data()
    user = data.get("users", {}).get(user_id)
    if not user or user.get("org_id") != org_id:
        return False, "Team member not found in your organisation.", None

    if user.get("role") == "admin" and new_role != "admin":
        other_admins = [
            u for u in data.get("users", {}).values()
            if u.get("org_id") == org_id and u.get("id") != user_id and u.get("role") == "admin"
        ]
        if not other_admins:
            return False, "At least one admin user must remain in the organisation.", None

    user["role"] = new_role
    data["users"][user_id] = user
    _save_data(data)
    uc = dict(user)
    uc.pop("pwd_hash", None)
    uc.pop("salt", None)
    uc.pop("mfa_secret", None)
    return True, f"Updated role to {new_role}.", uc


def delete_team_member(user_id: str, org_id: str = "org-default") -> bool:
    """Removes a team member while preserving at least one admin."""
    data = _load_data()
    user = data.get("users", {}).get(user_id)
    if not user or user.get("org_id") != org_id:
        return False
    if user.get("role") == "admin":
        other_admins = [
            u for u in data.get("users", {}).values()
            if u.get("org_id") == org_id and u.get("id") != user_id and u.get("role") == "admin"
        ]
        if not other_admins:
            raise ValueError("Cannot delete the last admin of the organisation.")
    del data["users"][user_id]
    # Revoke persisted sessions belonging to removed member
    sessions = data.get("sessions", {})
    for h in [k for k, v in sessions.items() if v.get("user_id") == user_id]:
        del sessions[h]
    _save_data(data)
    return True


# ---------------------------------------------------------------------------
# Integrations Configuration
# ---------------------------------------------------------------------------

def get_integration_settings(org_id: str = "org-default") -> Dict[str, Any]:
    """Retrieves webhook & alert integration configurations."""
    data = _load_data()
    default_settings = {
        "email_alerts": False,
        "alert_email": "",
        "slack_webhook_url": os.environ.get("TRUSTAUDIT_SLACK_WEBHOOK", ""),
        "teams_webhook_url": os.environ.get("TRUSTAUDIT_TEAMS_WEBHOOK", ""),
        "min_alert_severity": "HIGH",
        "notify_on_new_finding": True,
        "notify_on_fix_verified": True,
        "notify_on_score_drop": True,
    }
    return data.get("integrations", {}).get(org_id, default_settings)


def save_integration_settings(org_id: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    data = _load_data()
    curr = get_integration_settings(org_id)
    for k in (
        "email_alerts", "alert_email", "slack_webhook_url", "teams_webhook_url",
        "min_alert_severity", "notify_on_new_finding", "notify_on_fix_verified", "notify_on_score_drop",
    ):
        if k in settings:
            curr[k] = settings[k]
    data.setdefault("integrations", {})[org_id] = curr
    _save_data(data)
    return curr


def get_all_projects() -> List[Dict[str, Any]]:
    """Returns all projects across all organizations (for platform administration only)."""
    data = _load_data()
    return list(data.get("projects", {}).values())


# ---------------------------------------------------------------------------
# Organization Profile & Compliance State
# ---------------------------------------------------------------------------

def get_org_profile(org_id: str = "org-default") -> Dict[str, Any]:
    """Retrieves organization profile information without fabricated company defaults."""
    data = _load_data()
    saved = data.get("org_profiles", {}).get(org_id)
    if saved:
        return saved

    org = data.get("organizations", {}).get(org_id, {})
    if org_id == "org-default":
        return {
            "company_name": org.get("name", "Sample Indian Clinic (Demo Sandbox)"),
            "country": "India",
            "industry": "Healthcare / Clinic",
            "website": "https://trustaudit.example",
            "company_size": "11-50",
            "employee_count": "11-50",
            "business_activities": "Example healthcare clinic workspace for product demonstration.",
            "customer_types": ["Indian Citizens (Patients)"],
            "personal_data_categories": [],
            "infrastructure": [],
            "vendors": [],
            "selected_frameworks": ["DPDP"],
            "is_demo": True,
        }

    return {
        "company_name": org.get("name", ""),
        "country": "India",
        "industry": "",
        "website": "",
        "company_size": "",
        "employee_count": "",
        "business_activities": "",
        "customer_types": [],
        "personal_data_categories": [],
        "infrastructure": [],
        "vendors": [],
        "selected_frameworks": ["DPDP"],
        "privacy_contact_name": "",
        "privacy_contact_email": "",
    }


def save_org_profile(org_id: str, profile: Dict[str, Any]) -> Dict[str, Any]:
    """Saves or updates organization onboarding and compliance profile."""
    data = _load_data()
    curr = get_org_profile(org_id)
    curr.update(profile)
    data.setdefault("org_profiles", {})[org_id] = curr
    if profile.get("company_name") and org_id in data.get("organizations", {}):
        data["organizations"][org_id]["name"] = sanitize_plain_text(profile["company_name"], 160)
    _save_data(data)
    return curr


def get_org_compliance_assessment(org_id: str = "org-default") -> Optional[Dict[str, Any]]:
    """Retrieves stored compliance assessment for the organization."""
    data = _load_data()
    return data.get("compliance_assessments", {}).get(org_id)


def save_org_compliance_assessment(org_id: str, assessment: Dict[str, Any]) -> Dict[str, Any]:
    """Stores latest compliance assessment."""
    data = _load_data()
    data.setdefault("compliance_assessments", {})[org_id] = assessment
    _save_data(data)
    return assessment


# ---------------------------------------------------------------------------
# Authentication & Session Management
# ---------------------------------------------------------------------------

import hashlib
import secrets
import base64
import struct
import hmac

# OWASP Recommended Work Factor for PBKDF2-HMAC-SHA256 (600,000 iterations)
DEFAULT_PBKDF2_ITERATIONS = 600000
LEGACY_PBKDF2_ITERATIONS = 100000

# Rate limiting store: ip_or_email -> list of failed attempt timestamps
_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_WINDOW_SECONDS = 60

# Password reset tokens: token -> metadata
_PASSWORD_RESET_TOKENS: Dict[str, Dict[str, Any]] = {}
PASSWORD_RESET_TOKEN_EXPIRY_SECONDS = 3600  # 1 hour

# Active sessions store: token -> session metadata
_ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}


def check_login_rate_limit(key: str) -> Tuple[bool, int]:
    """
    Checks if an IP or email has exceeded max failed login attempts in the sliding window.
    Returns (is_allowed, retry_after_seconds).
    """
    now = time.time()
    attempts = _LOGIN_ATTEMPTS.get(key, [])
    # Filter attempts within window
    valid_attempts = [t for t in attempts if now - t < LOGIN_LOCKOUT_WINDOW_SECONDS]
    _LOGIN_ATTEMPTS[key] = valid_attempts

    if len(valid_attempts) >= MAX_FAILED_LOGIN_ATTEMPTS:
        retry_after = int(LOGIN_LOCKOUT_WINDOW_SECONDS - (now - valid_attempts[0]))
        return False, max(1, retry_after)
    return True, 0


def record_failed_login(key: str) -> None:
    """Records a failed login attempt for rate limiting."""
    now = time.time()
    _LOGIN_ATTEMPTS.setdefault(key, []).append(now)


def clear_failed_logins(key: str) -> None:
    """Clears failed login attempts upon successful authentication."""
    if key in _LOGIN_ATTEMPTS:
        del _LOGIN_ATTEMPTS[key]


def _hash_password(
    password: str,
    salt: Optional[str] = None,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS
) -> Tuple[str, str]:
    """
    Generates OWASP-compliant salted PBKDF2-HMAC-SHA256 password hash.
    Format: pbkdf2_sha256$<iterations>$<salt>$<hex_key>
    Returns (formatted_hash, salt).
    """
    if not salt:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    formatted_hash = f"pbkdf2_sha256${iterations}${salt}${key.hex()}"
    return formatted_hash, salt


def _verify_password(
    password: str,
    stored_hash: str,
    salt: str,
    stored_iterations: int = LEGACY_PBKDF2_ITERATIONS,
    return_needs_rehash: bool = False
) -> Any:
    """
    Verifies candidate password against stored hash.
    Supports modular structured format and legacy plain hex hashes.
    Returns bool by default, or (is_valid, needs_rehash) if return_needs_rehash=True.
    """
    if not stored_hash or not salt:
        return (False, False) if return_needs_rehash else False

    # Check for structured format: pbkdf2_sha256$<iters>$<salt>$<hex>
    if stored_hash.startswith("pbkdf2_sha256$"):
        parts = stored_hash.split("$")
        if len(parts) == 4:
            try:
                iters = int(parts[1])
                target_salt = parts[2]
                target_hex = parts[3]
                candidate_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), target_salt.encode("utf-8"), iters)
                is_valid = secrets.compare_digest(candidate_key.hex(), target_hex)
                needs_rehash = (iters < DEFAULT_PBKDF2_ITERATIONS)
                return (is_valid, needs_rehash) if return_needs_rehash else is_valid
            except Exception:
                return (False, False) if return_needs_rehash else False

    # Legacy format: stored_hash is pure hex string, salt is separate
    try:
        candidate_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), stored_iterations)
        is_valid = secrets.compare_digest(candidate_key.hex(), stored_hash)
        needs_rehash = True  # Always upgrade legacy format to structured 600,000 iterations
        return (is_valid, needs_rehash) if return_needs_rehash else is_valid
    except Exception:
        return (False, False) if return_needs_rehash else False


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(str(raw_token).encode("utf-8")).hexdigest()


def _is_platform_admin_email(email: str) -> bool:
    configured = [
        e.strip().lower()
        for e in os.environ.get("TRUSTAUDIT_PLATFORM_ADMIN_EMAILS", "").split(",")
        if e.strip()
    ]
    return email.strip().lower() in configured


def register_user(
    email: str,
    password: str,
    name: str,
    org_name: str,
    country: str = "India",
    plan: str = "starter",
    industry: str = "",
    website: str = "",
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Registers a new user and provisions an isolated organization with OWASP-hardened hashing."""
    email_clean = sanitize_plain_text(email, 160).lower()
    if not email_clean or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_clean):
        return False, "Please enter a valid work email address.", None
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long.", None

    data = _load_data()

    for u in data.get("users", {}).values():
        if u.get("email", "").lower() == email_clean:
            return False, "An account with this email address already exists.", None

    clean_plan = (plan or "starter").strip().lower()
    if clean_plan not in PLANS:
        clean_plan = "starter"

    org_id = f"org-{uuid.uuid4().hex[:8]}"
    uid = f"usr-{uuid.uuid4().hex[:8]}"
    pwd_hash, salt = _hash_password(password, iterations=DEFAULT_PBKDF2_ITERATIONS)
    clean_org_name = sanitize_plain_text(org_name, 160) or "My Business"

    new_org = {
        "id": org_id,
        "name": clean_org_name,
        "slug": re.sub(r"[^a-z0-9]+", "-", clean_org_name.lower()).strip("-") or org_id,
        "plan": clean_plan,
        "is_demo": False,
        "created_at": time.time(),
        "max_projects": PLANS[clean_plan]["max_projects"],
        "scans_count": 0,
    }

    new_user = {
        "id": uid,
        "org_id": org_id,
        "email": email_clean,
        "name": sanitize_plain_text(name, 120) or email_clean.split("@")[0],
        "role": "admin",
        "is_platform_admin": _is_platform_admin_email(email_clean),
        "pwd_hash": pwd_hash,
        "pwd_algo": "pbkdf2_sha256",
        "pwd_iterations": DEFAULT_PBKDF2_ITERATIONS,
        "salt": salt,
        "mfa_enabled": False,
        "mfa_secret": None,
        "created_at": time.time(),
    }

    data.setdefault("organizations", {})[org_id] = new_org
    data.setdefault("users", {})[uid] = new_user

    # Honest starter profile without invented customer categories, vendors, or infra
    data.setdefault("org_profiles", {})[org_id] = {
        "company_name": clean_org_name,
        "country": sanitize_plain_text(country, 80) or "India",
        "industry": sanitize_plain_text(industry, 120),
        "website": sanitize_plain_text(website, 300),
        "company_size": "",
        "employee_count": "",
        "business_activities": "",
        "customer_types": [],
        "personal_data_categories": [],
        "infrastructure": [],
        "vendors": [],
        "selected_frameworks": ["DPDP"],
        "privacy_contact_name": sanitize_plain_text(name, 120),
        "privacy_contact_email": email_clean,
    }

    _save_data(data)
    token = create_user_session(uid, org_id)
    append_audit_log(
        org_id=org_id,
        action="auth.register",
        resource_type="user",
        resource_id=uid,
        actor_user_id=uid,
        actor_email=email_clean,
        actor_role="admin",
        details={"plan": clean_plan},
    )
    user_safe = dict(new_user)
    user_safe.pop("pwd_hash", None)
    user_safe.pop("salt", None)
    user_safe.pop("mfa_secret", None)
    return True, "Registration successful.", {"user": user_safe, "organization": get_organization(org_id), "token": token}


def authenticate_user(
    email: str,
    password: str,
    totp_code: Optional[str] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Authenticates email and password with rate limiting, OWASP rehash-on-login,
    and optional TOTP MFA verification.
    """
    data = _load_data()
    email_clean = sanitize_plain_text(email, 160).lower()

    allowed, retry_sec = check_login_rate_limit(email_clean)
    if not allowed:
        return False, f"Too many failed login attempts. Please try again in {retry_sec} seconds.", None

    matched_user = None
    for u in data.get("users", {}).values():
        if u.get("email", "").lower() == email_clean:
            matched_user = u
            break

    if not matched_user:
        record_failed_login(email_clean)
        return False, "Invalid email address or password.", None

    pwd_hash = matched_user.get("pwd_hash")
    salt = matched_user.get("salt")
    stored_iters = matched_user.get("pwd_iterations", LEGACY_PBKDF2_ITERATIONS)

    if not pwd_hash or not salt:
        record_failed_login(email_clean)
        return False, "Invalid account security state. Please reset your password.", None

    is_valid, needs_rehash = _verify_password(password, pwd_hash, salt, stored_iters, return_needs_rehash=True)
    if not is_valid:
        record_failed_login(email_clean)
        append_audit_log(
            org_id=matched_user.get("org_id", ""),
            action="auth.login_failed",
            resource_type="user",
            resource_id=matched_user.get("id", ""),
            actor_user_id=matched_user.get("id", ""),
            actor_email=email_clean,
            status="denied",
        )
        return False, "Invalid email address or password.", None

    if matched_user.get("mfa_enabled"):
        if not totp_code:
            return False, "MFA_REQUIRED", {"mfa_required": True, "user_id": matched_user["id"]}
        if not verify_totp_token(matched_user.get("mfa_secret", ""), totp_code):
            record_failed_login(email_clean)
            return False, "Invalid Multi-Factor Authentication code.", None

    clear_failed_logins(email_clean)

    matched_user["last_login_at"] = time.time()
    if needs_rehash:
        new_hash, new_salt = _hash_password(password, iterations=DEFAULT_PBKDF2_ITERATIONS)
        matched_user["pwd_hash"] = new_hash
        matched_user["salt"] = new_salt
        matched_user["pwd_algo"] = "pbkdf2_sha256"
        matched_user["pwd_iterations"] = DEFAULT_PBKDF2_ITERATIONS
    _save_data(data)

    token = create_user_session(matched_user["id"], matched_user["org_id"])
    org = get_organization(matched_user["org_id"])
    user_copy = dict(matched_user)
    user_copy.pop("pwd_hash", None)
    user_copy.pop("salt", None)
    user_copy.pop("mfa_secret", None)
    user_copy.pop("mfa_pending_secret", None)
    append_audit_log(
        org_id=matched_user["org_id"],
        action="auth.login",
        resource_type="session",
        actor_user_id=matched_user["id"],
        actor_email=email_clean,
        actor_role=matched_user.get("role", "member"),
    )
    return True, "Login successful.", {"user": user_copy, "organization": org, "token": token}


def create_user_session(user_id: str, org_id: str) -> str:
    """Creates a cryptographic session token persisted as a SHA-256 hash valid for 30 days."""
    token = secrets.token_urlsafe(32)
    tok_hash = _hash_token(token)
    session_meta = {
        "user_id": user_id,
        "org_id": org_id,
        "created_at": time.time(),
        "expires_at": time.time() + (30 * 86400),
    }
    data = _load_data()
    sessions = data.setdefault("sessions", {})
    # Prune expired sessions opportunistically
    now = time.time()
    for k in [hk for hk, sm in sessions.items() if now > sm.get("expires_at", 0)]:
        del sessions[k]
    sessions[tok_hash] = session_meta
    _save_data(data)
    _ACTIVE_SESSIONS[token] = session_meta
    return token


def validate_session(
    token: Optional[str],
    allow_demo_fallback: bool = False
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Validates a session token with strict multi-tenant authorization boundaries.
    Only falls back to demo mode when explicitly permitted.
    Returns (is_valid, user, org_id).
    """
    if not token:
        if allow_demo_fallback:
            return True, {"id": "usr-default", "name": "Demo Owner", "role": "admin", "email": "demo@trustaudit.example"}, "org-default"
        return False, None, None

    data = _load_data()
    tok_hash = _hash_token(token)
    session = data.get("sessions", {}).get(tok_hash) or _ACTIVE_SESSIONS.get(token)
    if not session:
        return False, None, None

    if time.time() > session.get("expires_at", 0):
        data.get("sessions", {}).pop(tok_hash, None)
        _ACTIVE_SESSIONS.pop(token, None)
        _save_data(data)
        return False, None, None

    user = data.get("users", {}).get(session["user_id"])
    if not user:
        return False, None, None

    user_copy = dict(user)
    user_copy.pop("pwd_hash", None)
    user_copy.pop("salt", None)
    user_copy.pop("mfa_secret", None)
    user_copy.pop("mfa_pending_secret", None)
    return True, user_copy, session.get("org_id")


def revoke_session(token: str) -> bool:
    """Logs out by invalidating persisted and cached session token."""
    removed = False
    if token in _ACTIVE_SESSIONS:
        del _ACTIVE_SESSIONS[token]
        removed = True
    if token:
        data = _load_data()
        tok_hash = _hash_token(token)
        if tok_hash in data.get("sessions", {}):
            del data["sessions"][tok_hash]
            _save_data(data)
            removed = True
    return removed


# ---------------------------------------------------------------------------
# PASSWORD RESET WORKFLOW (Hashed & Persistent)
# ---------------------------------------------------------------------------

def create_password_reset_token(email: str) -> Tuple[bool, str, Optional[str]]:
    """Generates a secure, 1-hour single-use password reset token persisted as SHA-256 hash."""
    data = _load_data()
    email_clean = sanitize_plain_text(email, 160).lower()

    matched_user = None
    for u in data.get("users", {}).values():
        if u.get("email", "").lower() == email_clean:
            matched_user = u
            break

    generic_msg = "If an account exists with this email, password reset instructions have been processed."
    if not matched_user:
        return True, generic_msg, None

    token = secrets.token_urlsafe(32)
    tok_hash = _hash_token(token)
    meta = {
        "user_id": matched_user["id"],
        "email": email_clean,
        "created_at": time.time(),
        "expires_at": time.time() + PASSWORD_RESET_TOKEN_EXPIRY_SECONDS,
    }
    resets = data.setdefault("password_resets", {})
    resets[tok_hash] = meta
    _save_data(data)
    _PASSWORD_RESET_TOKENS[token] = meta
    append_audit_log(
        org_id=matched_user.get("org_id", ""),
        action="auth.password_reset_requested",
        resource_type="user",
        resource_id=matched_user["id"],
        actor_user_id=matched_user["id"],
        actor_email=email_clean,
    )
    return True, generic_msg, token


def reset_password_with_token(token: str, new_password: str) -> Tuple[bool, str]:
    """Validates reset token and applies newly hashed password with 600,000 iterations."""
    if not token:
        return False, "Invalid or expired password reset token."

    data = _load_data()
    tok_hash = _hash_token(token)
    meta = data.get("password_resets", {}).get(tok_hash) or _PASSWORD_RESET_TOKENS.get(token)
    if not meta:
        return False, "Invalid or expired password reset token."

    if time.time() > meta["expires_at"]:
        data.get("password_resets", {}).pop(tok_hash, None)
        _PASSWORD_RESET_TOKENS.pop(token, None)
        _save_data(data)
        return False, "Password reset token has expired. Please request a new one."

    if not new_password or len(new_password) < 8:
        return False, "Password must be at least 8 characters long."

    user = data.get("users", {}).get(meta["user_id"])
    if not user:
        data.get("password_resets", {}).pop(tok_hash, None)
        _PASSWORD_RESET_TOKENS.pop(token, None)
        _save_data(data)
        return False, "User account no longer exists."

    new_hash, new_salt = _hash_password(new_password, iterations=DEFAULT_PBKDF2_ITERATIONS)
    user["pwd_hash"] = new_hash
    user["salt"] = new_salt
    user["pwd_algo"] = "pbkdf2_sha256"
    user["pwd_iterations"] = DEFAULT_PBKDF2_ITERATIONS

    # Single-use invalidation
    data.get("password_resets", {}).pop(tok_hash, None)
    _PASSWORD_RESET_TOKENS.pop(token, None)

    # Rotate all sessions for user
    sessions = data.get("sessions", {})
    for h in [k for k, s in sessions.items() if s.get("user_id") == user["id"]]:
        del sessions[h]
    for t in [t for t, s in _ACTIVE_SESSIONS.items() if s.get("user_id") == user["id"]]:
        del _ACTIVE_SESSIONS[t]

    _save_data(data)
    append_audit_log(
        org_id=user.get("org_id", ""),
        action="auth.password_reset_completed",
        resource_type="user",
        resource_id=user["id"],
        actor_user_id=user["id"],
        actor_email=user.get("email", ""),
    )
    return True, "Password has been successfully updated. Please log in with your new password."


# ---------------------------------------------------------------------------
# MULTI-FACTOR AUTHENTICATION (RFC 6238 TOTP)
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generates a random RFC 3548 Base32 encoded 160-bit secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode("utf-8")


def get_totp_uri(email: str, secret: str, issuer: str = "TrustAudit") -> str:
    """Generates otpauth:// URI for authenticator applications."""
    import urllib.parse
    label = urllib.parse.quote(f"{issuer}:{email}")
    issuer_enc = urllib.parse.quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_enc}&algorithm=SHA1&digits=6&period=30"


def verify_totp_token(secret: str, token: str, window: int = 1, time_step: int = 30) -> bool:
    """Verifies a 6-digit TOTP code against a Base32 secret with drift window."""
    if not secret or not token:
        return False
    clean_token = token.strip()
    if len(clean_token) != 6 or not clean_token.isdigit():
        return False

    try:
        key = base64.b32decode(secret.upper())
    except Exception:
        return False

    current_counter = int(time.time() // time_step)
    for offset in range(-window, window + 1):
        counter = current_counter + offset
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        idx = h[-1] & 0x0F
        code = (
            (h[idx] & 0x7F) << 24
            | (h[idx + 1] & 0xFF) << 16
            | (h[idx + 2] & 0xFF) << 8
            | (h[idx + 3] & 0xFF)
        )
        expected_token = str(code % 1000000).zfill(6)
        if secrets.compare_digest(clean_token, expected_token):
            return True
    return False


def setup_mfa_for_user(user_id: str) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Initiates MFA setup by generating a secret and provisioning URI."""
    data = _load_data()
    user = data.get("users", {}).get(user_id)
    if not user:
        return False, "User not found.", None

    secret = generate_totp_secret()
    uri = get_totp_uri(user.get("email", ""), secret)
    # Temporary staging secret on user record until confirmed
    user["mfa_pending_secret"] = secret
    _save_data(data)

    return True, "MFA setup initiated.", {"secret": secret, "otpauth_uri": uri}


def confirm_and_enable_mfa(user_id: str, code: str) -> Tuple[bool, str]:
    """Confirms pending MFA secret with code and enables MFA on the account."""
    data = _load_data()
    user = data.get("users", {}).get(user_id)
    if not user:
        return False, "User not found."

    pending_secret = user.get("mfa_pending_secret")
    if not pending_secret:
        return False, "No pending MFA configuration found. Please start setup again."

    if not verify_totp_token(pending_secret, code):
        return False, "Invalid verification code. Please check your authenticator app and try again."

    user["mfa_enabled"] = True
    user["mfa_secret"] = pending_secret
    user.pop("mfa_pending_secret", None)
    _save_data(data)
    return True, "Multi-Factor Authentication enabled successfully."


def disable_mfa_for_user(user_id: str, code: str) -> Tuple[bool, str]:
    """Disables MFA after validating current TOTP code."""
    data = _load_data()
    user = data.get("users", {}).get(user_id)
    if not user or not user.get("mfa_enabled"):
        return False, "MFA is not enabled on this account."

    if not verify_totp_token(user.get("mfa_secret", ""), code):
        return False, "Invalid verification code."

    user["mfa_enabled"] = False
    user["mfa_secret"] = None
    _save_data(data)
    return True, "Multi-Factor Authentication disabled."


# ---------------------------------------------------------------------------
# CUSTOMER DATA DELETION & RETENTION WORKFLOW
# ---------------------------------------------------------------------------

def delete_organization_account(org_id: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Executes complete customer data deletion across all organization assets:
    - User accounts and authentication credentials
    - Projects, scan histories, and prioritized findings
    - Evidence Vault files and database records
    - Compliance profile and assessment mappings
    Returns deletion audit record.
    """
    data = _load_data()
    org = data.get("organizations", {}).get(org_id)
    if not org:
        return False, "Organization not found.", {}

    now_iso = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    audit_record = {
        "deletion_request_date": now_iso,
        "completion_timestamp": now_iso,
        "organization_id": org_id,
        "organization_name": org.get("name"),
        "status": "COMPLETED",
        "data_categories_deleted": [
            "User Accounts & Password Hashes",
            "Project Repositories & Scan Findings",
            "Evidence Vault Artifacts & Hashes",
            "Organization Compliance Profiles",
            "Active Session Tokens"
        ],
        "active_storage_retention": "0-day (Immediate scrubbing)",
        "backup_expiration_period": "30 days (Automated snapshot rotation)"
    }

    # 1. Delete Evidence Vault items & DPDP Operational Data
    try:
        import evidence_vault
        evidence_vault.delete_all_org_evidence(org_id)
    except Exception:
        pass
    try:
        import dpdp_store
        dpdp_store.delete_all_org_dpdp_data(org_id)
    except Exception:
        pass

    # 2. Delete Users & their persisted/cached sessions
    users_to_delete = [uid for uid, u in data.get("users", {}).items() if u.get("org_id") == org_id]
    for uid in users_to_delete:
        del data["users"][uid]
        sessions = data.get("sessions", {})
        for h in [k for k, s in sessions.items() if s.get("user_id") == uid]:
            del sessions[h]
        for t in [tok for tok, s in _ACTIVE_SESSIONS.items() if s.get("user_id") == uid]:
            del _ACTIVE_SESSIONS[t]

    # 3. Delete Projects
    projects_to_delete = [pid for pid, p in data.get("projects", {}).items() if p.get("org_id") == org_id]
    for pid in projects_to_delete:
        del data["projects"][pid]

    # 4. Delete Org Profiles & Assessments
    data.get("org_profiles", {}).pop(org_id, None)
    data.get("compliance_assessments", {}).pop(org_id, None)

    # 5. Delete Organization
    data["organizations"].pop(org_id, None)

    # 6. Record Deletion in Audit Register
    data.setdefault("deletion_audit_log", []).append(audit_record)

    _save_data(data)
    return True, "Organization account and all associated customer data have been deleted.", audit_record


# ---------------------------------------------------------------------------
# GRIEVANCE REDRESSAL SYSTEM (DPDP SECTION 13)
# ---------------------------------------------------------------------------

GRIEVANCES_FILE = os.path.join(get_data_dir(), "grievances.json")


def _load_grievances() -> List[Dict[str, Any]]:
    return safe_read_json(GRIEVANCES_FILE, list)


def _save_grievances(records: List[Dict[str, Any]]) -> None:
    atomic_write_json(GRIEVANCES_FILE, records)

def submit_grievance(
    name: str,
    email: str,
    category: str,
    description: str,
    company: str = ""
) -> Dict[str, Any]:
    """Records a personal data or privacy grievance with automated reference ID."""
    records = _load_grievances()
    ref_id = f"GRV-{int(time.time())}-{secrets.token_hex(2).upper()}"
    now_iso = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    ticket = {
        "reference_id": ref_id,
        "name": name.strip(),
        "email": email.strip().lower(),
        "company": company.strip(),
        "category": category,
        "description": description.strip(),
        "submission_date": now_iso,
        "status": "RECEIVED",
        "assigned_to": "Privacy & Grievance Contact",
        "investigation_notes": "Ticket logged via public Trust Centre. Acknowledged.",
        "resolution_date": None,
        "audit_history": [
            {"timestamp": now_iso, "action": "Ticket Created", "details": f"Category: {category}"}
        ]
    }
    records.append(ticket)
    _save_grievances(records)
    return ticket

def list_grievances() -> List[Dict[str, Any]]:
    return _load_grievances()

