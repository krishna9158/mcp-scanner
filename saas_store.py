"""
TrustAudit SaaS Multi-Tenancy & Project Management Data Layer.

Provides clean organization-isolated data models for:
- Organizations (Configurable Plans: free, starter ₹999/mo, pro ₹1,999/mo, enterprise)
- Users (Roles: admin, member, viewer)
- Projects (Connected code repositories, websites, and MCP systems)
- Scans (Historical scan records and results)
- Findings (Finding lifecycle state: open, acknowledged, fixed, verified, false_positive)
- Continuous Monitoring Schedulers & Timeline Event Store
- Security Subscriptions & Configurable Plan Limits
"""

import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

DATA_FILE = os.path.join(os.path.dirname(__file__), "saas_data.json")

# Configurable Startup Pricing Plans
PLANS = {
    "free": {
        "name": "Free Community",
        "price_monthly_inr": 0,
        "price_monthly_usd": 0,
        "max_domains": int(os.environ.get("TRUSTAUDIT_FREE_MAX_DOMAINS", 1)),
        "max_repositories": int(os.environ.get("TRUSTAUDIT_FREE_MAX_REPOS", 1)),
        "max_projects": int(os.environ.get("TRUSTAUDIT_FREE_MAX_PROJECTS", 2)),
        "max_scans_per_month": int(os.environ.get("TRUSTAUDIT_FREE_MAX_SCANS", 50)),
        "scan_frequency": "manual",
        "email_alerts": False,
        "webhook_alerts": False,
        "features": [
            "1 Website / Web Application Audit",
            "1 GitHub Repository Scanner",
            "Manual Security Audits",
            "Executive PDF / HTML Report",
            "Community Support"
        ]
    },
    "starter": {
        "name": "Starter",
        "price_monthly_inr": 999,
        "price_monthly_usd": 12,
        "max_domains": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_DOMAINS", 5)),
        "max_repositories": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_REPOS", 5)),
        "max_projects": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_PROJECTS", 10)),
        "max_scans_per_month": int(os.environ.get("TRUSTAUDIT_STARTER_MAX_SCANS", 500)),
        "scan_frequency": "daily",
        "email_alerts": True,
        "webhook_alerts": False,
        "features": [
            "Up to 5 Websites & 5 Repositories",
            "Daily Continuous Security Monitoring",
            "Automated 'What Changed?' Delta Engine",
            "'Fix These First' Prioritization Cards",
            "Email Security Alerts for Critical Risks",
            "Interactive AI Security Advisor"
        ]
    },
    "pro": {
        "name": "Pro",
        "price_monthly_inr": 1999,
        "price_monthly_usd": 24,
        "max_domains": int(os.environ.get("TRUSTAUDIT_PRO_MAX_DOMAINS", 20)),
        "max_repositories": int(os.environ.get("TRUSTAUDIT_PRO_MAX_REPOS", 20)),
        "max_projects": int(os.environ.get("TRUSTAUDIT_PRO_MAX_PROJECTS", 40)),
        "max_scans_per_month": int(os.environ.get("TRUSTAUDIT_PRO_MAX_SCANS", 2500)),
        "scan_frequency": "hourly",
        "email_alerts": True,
        "webhook_alerts": True,
        "features": [
            "Up to 20 Websites & 20 Repositories",
            "Hourly & Daily Continuous Monitoring",
            "Deep AI-Code & MCP Poisoning Audits",
            "Find → Fix → Verify Automated Rescan",
            "Slack & Webhook Alert Integrations",
            "CI/CD Quality Gates & Baseline Drift",
            "Priority Support & Multi-Team Members"
        ]
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly_inr": 9999,
        "price_monthly_usd": 120,
        "max_domains": 500,
        "max_repositories": 500,
        "max_projects": 500,
        "max_scans_per_month": 100000,
        "scan_frequency": "continuous",
        "email_alerts": True,
        "webhook_alerts": True,
        "features": [
            "Unlimited Domains & Repositories",
            "Continuous Custom Scheduled Scans",
            "Dedicated VPC / Self-Hosted Runners",
            "Custom Compliance Frameworks",
            "99.9% SLA & Dedicated Security Lead"
        ]
    }
}


def _load_data() -> Dict[str, Any]:
    if not os.path.exists(DATA_FILE):
        initial = {
            "organizations": {
                "org-default": {
                    "id": "org-default",
                    "name": "Acme AI Labs",
                    "slug": "acme-ai",
                    "plan": "starter",
                    "created_at": time.time(),
                    "max_projects": 10,
                    "scans_count": 0
                }
            },
            "users": {
                "usr-default": {
                    "id": "usr-default",
                    "org_id": "org-default",
                    "email": "security@acme.ai",
                    "name": "Tech Lead",
                    "role": "admin",
                    "created_at": time.time()
                }
            },
            "projects": {
                "proj-demo-1": {
                    "id": "proj-demo-1",
                    "org_id": "org-default",
                    "name": "Customer AI Assistant",
                    "target_type": "repository",
                    "repo_url": "https://github.com/example/support-agent-mcp",
                    "website_url": "https://agent.example.com",
                    "mcp_servers_count": 2,
                    "last_score": 84,
                    "last_grade": "B",
                    "critical_findings": 1,
                    "open_findings": 4,
                    "regression_status": "PASS",
                    "monitoring_status": "ACTIVE",
                    "scan_frequency": "daily",
                    "next_scan_at": time.time() + 86400,
                    "last_scan": time.time() - 3600,
                    "timeline": [],
                    "created_at": time.time() - 86400 * 7
                },
                "proj-demo-2": {
                    "id": "proj-demo-2",
                    "org_id": "org-default",
                    "name": "SaaS Marketing Website",
                    "target_type": "website",
                    "repo_url": "",
                    "website_url": "https://testphp.vulnweb.com/",
                    "mcp_servers_count": 0,
                    "last_score": 78,
                    "last_grade": "C",
                    "critical_findings": 1,
                    "open_findings": 6,
                    "regression_status": "PASS",
                    "monitoring_status": "ACTIVE",
                    "scan_frequency": "daily",
                    "next_scan_at": time.time() + 86400,
                    "last_scan": time.time() - 7200,
                    "timeline": [],
                    "created_at": time.time() - 86400 * 3
                }
            },
            "scans": {},
            "finding_overrides": {}
        }
        _save_data(initial)
        return initial

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"organizations": {}, "users": {}, "projects": {}, "scans": {}, "finding_overrides": {}}


def _save_data(data: Dict[str, Any]):
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[SAAS_STORE] Error saving data: {e}", flush=True)


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
            "name": "Acme AI Labs",
            "slug": "acme-ai",
            "plan": "starter",
            "created_at": time.time(),
            "max_projects": 10,
            "scans_count": 0
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
            return False, f"Plan limit reached ({count}/{max_allowed} projects). Upgrade to Pro for increased capacity."

    elif resource_type == "website":
        web_count = current_count if current_count is not None else sum(1 for p in projects if p.get("target_type") == "website" or p.get("website_url"))
        max_allowed = plan.get("max_domains", 5)
        if web_count >= max_allowed:
            return False, f"Domain limit reached ({web_count}/{max_allowed} domains). Upgrade plan to monitor more domains."

    elif resource_type == "repository":
        repo_count = current_count if current_count is not None else sum(1 for p in projects if p.get("target_type") == "repository" or p.get("repo_url"))
        max_allowed = plan.get("max_repositories", 5)
        if repo_count >= max_allowed:
            return False, f"Repository limit reached ({repo_count}/{max_allowed} repos). Upgrade plan to monitor more repos."

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
    """Lists all users belonging to the organization."""
    data = _load_data()
    users = [u for u in data.get("users", {}).values() if u.get("org_id") == org_id]
    if not users:
        # Default admin
        default_user = {
            "id": "usr-default",
            "org_id": org_id,
            "email": "security@acme.ai",
            "name": "Tech Lead (Admin)",
            "role": "admin",
            "created_at": time.time()
        }
        data.setdefault("users", {})["usr-default"] = default_user
        _save_data(data)
        return [default_user]
    return users


def add_team_member(
    name: str,
    email: str,
    role: str = "member",
    org_id: str = "org-default"
) -> Dict[str, Any]:
    """Adds a new team member with role: admin, member, or viewer."""
    data = _load_data()
    uid = f"usr-{uuid.uuid4().hex[:8]}"
    user = {
        "id": uid,
        "org_id": org_id,
        "name": name,
        "email": email,
        "role": role if role in ("admin", "member", "viewer") else "member",
        "created_at": time.time()
    }
    data.setdefault("users", {})[uid] = user
    _save_data(data)
    return user


def delete_team_member(user_id: str, org_id: str = "org-default") -> bool:
    """Removes a team member."""
    data = _load_data()
    user = data.get("users", {}).get(user_id)
    if user and user.get("org_id") == org_id:
        del data["users"][user_id]
        _save_data(data)
        return True
    return False


# ---------------------------------------------------------------------------
# Integrations Configuration
# ---------------------------------------------------------------------------

def get_integration_settings(org_id: str = "org-default") -> Dict[str, Any]:
    """Retrieves webhook & alert integration configurations."""
    data = _load_data()
    default_settings = {
        "email_alerts": True,
        "alert_email": "security@acme.ai",
        "slack_webhook_url": os.environ.get("TRUSTAUDIT_SLACK_WEBHOOK", ""),
        "teams_webhook_url": os.environ.get("TRUSTAUDIT_TEAMS_WEBHOOK", ""),
        "min_alert_severity": "HIGH",
        "notify_on_new_finding": True,
        "notify_on_fix_verified": True,
        "notify_on_score_drop": True,
    }
    return data.get("integrations", {}).get(org_id, default_settings)


def update_integration_settings(org_id: str, settings: Dict[str, Any]) -> Dict[str, Any]:
    """Updates integration settings."""
    data = _load_data()
    curr = get_integration_settings(org_id)
    curr.update(settings)
    data.setdefault("integrations", {})[org_id] = curr
    _save_data(data)
    return curr
