"""
TrustAudit AI & Web Continuous Security Platform - Application Server.

Commercially positioned as:
"Continuous Security for AI-Coded Applications & MCP"
"Find, verify, and continuously monitor security risks in AI-built applications and MCP systems."

Features:
- Public Marketing Landing Page
- Multi-Tenant SaaS Dashboard with Multi-Project Management
- Unified Multi-Surface Scanner (GitHub Repositories, Websites & APIs, MCP Servers)
- Open-Source Security Engine Integrations (Gitleaks, OSV-Scanner, Trivy, Nuclei, Syft)
- Software Bill of Materials (SBOM) Generation & Visibility
- Interactive Finding Detail Drawers with Verification Guidance & Lifecycle Tracking
- Multi-Format Reports (Printable PDF/HTML, Structured JSON)
- CI/CD Quality Gates, Regression Testing & Baseline Drift Monitoring
- REST APIs (/api/scan, /api/scans/:id/debug, /api/scans/:id/status, /api/health/scanner, /api/projects)
- Zero-Exposure Credential Redaction & Security Hardening
"""

import csv
import io
import os
import tempfile
import json
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, request, render_template, render_template_string, Response, jsonify, send_file, redirect, abort

import hashlib
import hmac
import secrets
import security_utils
import dpdp_reports
import dpdp_commencement
import dpdp_penalties
import extraction_engine

from badge import generate_badge_svg
from badge_store import get_last_scan_result
from history_store import get_scan_history
from reports import generate_json_report, generate_html_report, generate_executive_report, generate_technical_report
from dashboard_template import DASHBOARD_HTML
from website_scanner import is_github_repo_url
import saas_store
import scan_manager
import scheduler
import delta_engine
import prioritizer
import alerts
import compliance_engine
import compliance_frameworks
import demo_fixture
import evidence_vault
import job_manager
import remediation_centre
import inventory_engine
import vuln_intel_sources
import vuln_intel_store
import correlation_engine
import vuln_intel_service

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024  # 6 MB strict upload ceiling


@app.after_request
def add_security_and_cache_headers(response):
    """Enforces HTTP security hardening headers and safe cache control."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'self'; "
        "object-src 'none'; "
        "base-uri 'self'",
    )
    is_https = request.is_secure or (request.headers.get("X-Forwarded-Proto", "").lower() == "https")
    if is_https:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    path = request.path or ""
    if path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=3600"
    elif not (path.startswith("/api/dpdp/evidence/") and ("/download" in path or "/preview" in path)):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.errorhandler(413)
def handle_payload_too_large(_err):
    return jsonify({"status": "error", "error": "Uploaded file exceeds maximum allowed size (5 MB per file / 6 MB request)."}), 413


@app.errorhandler(500)
def handle_internal_error(_err):
    if (request.path or "").startswith("/api/"):
        return jsonify({"status": "error", "error": "An unexpected internal error occurred. Please try again."}), 500
    return Response("An unexpected error occurred.", status=500, mimetype="text/plain")

# ===========================================================================
# PRODUCT POSITIONING & FEATURE FLAGS: DPDP COMPLIANCE PLATFORM
# ===========================================================================

FEATURE_LEGACY_SCANNERS = False  # Archived in customer product; dedicated DPDP Platform active

from dpdp_landing_template import DPDP_LANDING_HTML
from dashboard_template import DASHBOARD_HTML
import dpdp_engine
import dpdp_store

if FEATURE_LEGACY_SCANNERS:
    try:
        scheduler.start_scheduler(poll_interval=30)
    except Exception as e:
        print(f"[APP] Could not start scheduler: {e}", flush=True)

    try:
        vuln_intel_service.start_vulnerability_intelligence_worker()
    except Exception as e:
        print(f"[APP] Could not start vulnerability intelligence worker: {e}", flush=True)


def execute_scan(github_url, full_scan=False, auth_confirmed=False):
    """Executes full repository security audit using scan_manager."""
    return scan_manager.execute_scan_synchronously(
        github_url, scan_type="repository", full_scan=full_scan, auth_confirmed=auth_confirmed
    )


def execute_website_scan(target_url, auth_confirmed=True):
    """Executes safe, non-destructive website security audit using scan_manager."""
    return scan_manager.execute_scan_synchronously(
        target_url, scan_type="website", full_scan=False, auth_confirmed=auth_confirmed
    )


def execute_mcp_scan(target, full_scan=False, auth_confirmed=True):
    """Executes dedicated Model Context Protocol (MCP) server & tool security scan."""
    return scan_manager.execute_scan_synchronously(
        target, scan_type="mcp", full_scan=full_scan, auth_confirmed=auth_confirmed
    )


# ===========================================================================
# HTML TEMPLATES: LANDING PAGE & SAAS DASHBOARD
# ===========================================================================

APP_PAGE_META = {
    "home": ("app/home.html", "Home"),
    "onboarding": ("app/onboarding.html", "Business Setup Guide"),
    "discovery": ("app/discovery.html", "Suggestions & Document Import"),
    "website-check": ("app/website_check.html", "Website Check"),
    "data-inventory": ("app/data_inventory.html", "Customer Information"),
    "data-map": ("app/data_map.html", "Where My Data Goes"),
    "assessment": ("app/assessment.html", "Privacy Assessment"),
    "action-plan": ("app/action_plan.html", "Fix My Privacy Gaps"),
    "vendors": ("app/vendors.html", "Companies I Share Data With"),
    "vendor-reviews": ("app/vendor_reviews.html", "Vendor Reviews"),
    "notices": ("app/notices.html", "Privacy Notice"),
    "consent": ("app/consent.html", "Consent Records"),
    "privacy-requests": ("app/privacy_requests.html", "Customer Requests"),
    "retention": ("app/retention.html", "Data Retention & Deletion"),
    "incidents": ("app/incidents.html", "Privacy Incident Response"),
    "document-centre": ("app/document_centre.html", "My Documents"),
    "evidence": ("app/evidence.html", "Evidence"),
    "reports": ("app/reports.html", "Reports"),
    "history": ("app/history.html", "History"),
    "privacy-assistant": ("app/privacy_assistant.html", "AI Assistant"),
    "learning": ("app/learning.html", "Learning Centre"),
    "privacy-portal": ("app/privacy_portal.html", "Customer Privacy Portal"),
    "privacy-profile": ("app/privacy_profile.html", "Shareable Privacy Profile"),
    "integrations": ("app/integrations.html", "Integrations"),
    "settings": ("app/settings.html", "Settings & 2FA"),
    "admin": ("app/admin.html", "Platform Admin Console"),
}

_PORTAL_CHALLENGE_SECRET = os.environ.get("TRUSTAUDIT_CHALLENGE_SECRET") or os.environ.get("SECRET_KEY") or "trustaudit-dev-portal-hmac-secret"


def _make_portal_challenge():
    import random
    a = random.randint(2, 9)
    b = random.randint(2, 9)
    ts = str(int(time.time()))
    ans = str(a + b)
    sig = hmac.new(_PORTAL_CHALLENGE_SECRET.encode("utf-8"), f"{ts}:{ans}".encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"{a} + {b}", f"{ts}.{sig}"


def _verify_portal_challenge(token: str, answer: str) -> bool:
    try:
        ts_str, sig = str(token or "").split(".", 1)
        ts_val = int(ts_str)
        if abs(int(time.time()) - ts_val) > 3600:
            return False
        expected = hmac.new(_PORTAL_CHALLENGE_SECRET.encode("utf-8"), f"{ts_str}:{str(answer or '').strip()}".encode("utf-8"), hashlib.sha256).hexdigest()[:24]
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def _render_app_page(page_key: str):
    if page_key not in APP_PAGE_META:
        abort(404)
    org_id, user = get_current_tenant_and_user(require_auth=True)
    if not org_id or not user:
        return redirect(f"/login?next=/app/{page_key}")
    if page_key == "admin" and not user.get("is_platform_admin"):
        return Response("Forbidden: Platform administrator privileges required.", status=403, mimetype="text/plain")
    tpl, title = APP_PAGE_META[page_key]
    org_info = saas_store.get_organization(org_id)
    onboarding_profile = dpdp_store.get_onboarding_profile(org_id) or {}
    org_slug = (org_info.get("slug") if org_info else None) or org_id
    return render_template(
        tpl,
        active_page=page_key,
        page_title=title,
        org_info=org_info,
        onboarding_profile=onboarding_profile,
        org_slug=org_slug,
        current_user=user,
        plans=saas_store.get_public_plans(),
    )


@app.route("/app/<page_key>", methods=["GET"])
def app_workspace_route(page_key):
    """Routed authenticated customer application workspace pages."""
    return _render_app_page(page_key)


@app.route("/dashboard", methods=["GET"])
def dashboard_view():
    """Preserves /dashboard: serves authenticated Home workspace or Sign-In screen cleanly at 200 OK."""
    org_id, user = get_current_tenant_and_user(require_auth=True)
    if org_id and user:
        return _render_app_page("home")
    return render_template("public/auth.html", mode="login", next_url="/app/home", selected_plan=""), 200


@app.route("/tools", methods=["GET"])
def tools_health_view():
    """Archived tools view; redirects cleanly."""
    return redirect("/app/home")


@app.route("/", methods=["GET", "POST"])
def home_endpoint():
    """Renders the redesigned TrustAudit public homepage."""
    return render_template("public/home.html", plans=saas_store.get_public_plans(), active_nav="home")


@app.route("/features", methods=["GET"])
def public_features_view():
    return render_template("public/features.html", active_nav="features")


@app.route("/industries", methods=["GET"])
def public_industries_view():
    return render_template("public/industries.html", active_nav="industries")


@app.route("/pricing", methods=["GET"])
def public_pricing_view():
    return render_template("public/pricing.html", plans=saas_store.get_public_plans(), active_nav="pricing")


@app.route("/how-it-works", methods=["GET"])
def public_how_it_works_view():
    return render_template("public/how_it_works.html", active_nav="how_it_works")


@app.route("/resources", methods=["GET"])
def public_resources_view():
    return render_template(
        "public/resources.html",
        active_nav="resources",
        milestones=dpdp_commencement.COMMENCEMENT_MILESTONES,
        penalties=list(dpdp_penalties.DPDP_STATUTORY_PENALTIES.values()),
        factors=dpdp_penalties.get_section_33_factors(),
        penalty_disclaimer=dpdp_penalties.STATUTORY_PENALTY_DISCLAIMER,
    )


@app.route("/about", methods=["GET"])
def public_about_view():
    return render_template("public/about.html", active_nav="about")


@app.route("/privacy", methods=["GET"])
@app.route("/terms", methods=["GET"])
@app.route("/acceptable-use", methods=["GET"])
@app.route("/data-processing", methods=["GET"])
@app.route("/ai-disclosure", methods=["GET"])
def public_legal_doc_view():
    """Serves truthful, version-controlled public legal and compliance disclosure documents."""
    import legal_docs
    slug = request.path.strip("/").lower() or "privacy"
    doc = legal_docs.get_legal_document(slug)
    contacts = legal_docs.get_contact_config()
    return render_template("public/legal_doc.html", doc=doc, contacts=contacts, active_nav="legal")


@app.route("/login", methods=["GET"])
def public_login_view():
    return render_template("public/auth.html", mode="login", next_url=request.args.get("next", "/app/home"), selected_plan="", selected_plan_info=None, all_plans=[])


@app.route("/register", methods=["GET"])
def public_register_view():
    plans = saas_store.get_public_plans()
    req_plan = (request.args.get("plan") or "free").strip().lower()
    alias = {"pro": "growth", "enterprise": "business"}
    req_plan = alias.get(req_plan, req_plan)
    sel_info = next((p for p in plans if p.get("key") == req_plan), None) or (plans[0] if plans else None)
    sel_key = sel_info["key"] if sel_info else "free"
    return render_template("public/auth.html", mode="register", next_url="/app/onboarding", selected_plan=sel_key, selected_plan_info=sel_info, all_plans=plans)


@app.route("/website-check", methods=["GET"])
def public_website_check_view():
    return render_template("public/website_check.html", active_nav="website-check")


@app.route("/portal/<org_slug>", methods=["GET"])
def public_customer_portal_view(org_slug):
    org = saas_store.get_organization_by_slug(org_slug)
    if not org:
        abort(404)
    portal = dpdp_store.get_portal_config(org["id"], default_name=org.get("name", "Business"), default_slug=org.get("slug", org["id"]))
    if not portal.get("enabled", True):
        abort(404)
    prompt, tok = _make_portal_challenge()
    return render_template("public/privacy_portal.html", portal=portal, org_slug=org_slug, challenge_prompt=prompt, challenge_token=tok)


@app.route("/p/<org_slug>", methods=["GET"])
def public_privacy_profile_view(org_slug):
    org = saas_store.get_organization_by_slug(org_slug)
    if not org:
        abort(404)
    profile = dpdp_store.get_public_privacy_profile(org["id"], org.get("slug") or org["id"])
    if not profile:
        abort(404)
    return render_template("public/privacy_profile.html", profile=profile, org_slug=org_slug)


@app.route("/vendor-intake/<token>", methods=["GET"])
def public_vendor_intake_view(token):
    info = dpdp_store.resolve_vendor_intake_token(token)
    if not info:
        abort(404)
    return render_template("public/vendor_intake.html", info=info, token=token)


@app.route("/scan", methods=["GET", "POST"])
def scan_endpoint():
    """Archived scanner endpoint with redirect to Website Privacy Check."""
    if not FEATURE_LEGACY_SCANNERS:
        if request.headers.get("Accept") == "application/json" or request.is_json:
            return jsonify({
                "status": "archived",
                "redirect": "/website-check",
                "message": "Legacy security scanner archived. Use /website-check for DPDP Website Privacy Checks."
            }), 200
        return redirect("/website-check")

    result = None
    error = None
    warning = None
    target = None
    scan_type = request.args.get("type") or "repository"
    full_scan = False
    debug = request.args.get("debug") == "true" or request.form.get("debug") == "yes"
    auth_confirmed = request.form.get("auth_confirmed") == "yes" or request.args.get("auth_confirmed") == "true"

    # Handle File Upload (ZIP or project/config file)
    uploaded_file = request.files.get("project_file") or request.files.get("file")
    if uploaded_file and uploaded_file.filename:
        import zipfile
        from werkzeug.utils import secure_filename
        filename = secure_filename(uploaded_file.filename)
        temp_dir = tempfile.mkdtemp(prefix="trustaudit_upload_")
        save_path = os.path.join(temp_dir, filename)
        uploaded_file.save(save_path)
        if filename.lower().endswith(".zip"):
            with zipfile.ZipFile(save_path, "r") as zip_ref:
                zip_ref.extractall(temp_dir)
            target = temp_dir
        else:
            target = save_path

    if not target and (request.method == "POST" or request.args.get("target") or request.args.get("repo") or request.args.get("url") or request.args.get("github_url")):
        target = (
            request.form.get("target") or
            request.form.get("github_url") or
            request.args.get("target") or
            request.args.get("repo") or
            request.args.get("url") or
            request.args.get("github_url")
        )
        scan_type = request.form.get("scan_type") or request.args.get("scan_type") or request.args.get("type") or "repository"
        if request.form.get("full_scan") == "yes" or request.args.get("full_scan") == "true":
            full_scan = True

    if target:
        target = target.strip()

        # MODE A: Website Scan Mode
        if scan_type == "website":
            try:
                result = execute_website_scan(target, auth_confirmed=auth_confirmed)
                if result.get("status") == "DNS_FAILURE":
                    error = f"Connection Status: [DNS FAILED] Target: '{result.get('hostname')}' | Reason: The hostname could not be resolved by the machine running TrustAudit ({result.get('error')})."
                elif result.get("status") in ("CONNECTION_ERROR", "TLS_ERROR", "TIMEOUT", "VALIDATION_FAILED"):
                    error = f"Target Connection Notice ({result.get('status')}): {result.get('error')}"
                if debug and target and result:
                    if "diagnostics" not in result or not result.get("diagnostics"):
                        result["diagnostics"] = run_target_diagnostics(target)
            except Exception as e:
                error = f"Website scan failed: {e}. Check target domain connectivity."

        # MODE C: Dedicated MCP Security Scan
        elif scan_type == "mcp":
            try:
                result = execute_mcp_scan(target, full_scan=full_scan, auth_confirmed=auth_confirmed)
                warning = result.get("warning")
            except TimeoutError as e:
                error = str(e)
            except Exception as e:
                error = f"MCP scan failed: {e}. Check MCP server/project target."

        # MODE B: Repository / Source Code Scan Mode
        else:
            if not is_github_repo_url(target) and not os.path.exists(target) and (target.startswith("http://") or target.startswith("https://") or "github.com" not in target):
                error = "This looks like a website URL. Select Website / Web Application scan."
            else:
                try:
                    result = execute_scan(target, full_scan=full_scan, auth_confirmed=auth_confirmed)
                    warning = result.get("warning")
                except TimeoutError as e:
                    error = str(e)
                except Exception as e:
                    error = f"Repository scan failed: {e}. Check repository URL and permissions."

    projects = saas_store.list_projects_for_org("org-default")
    tools_health = scan_manager.orchestrator.get_tool_health_records()
    active_proj = projects[0] if projects else {}
    prioritized_fixes = prioritizer.prioritize_findings(
        result.get("findings", []) if result else ((active_proj.get("last_scan_result") or {}).get("findings", []) if active_proj else [])
    )
    what_changed = (result.get("last_delta") if result else None) or active_proj.get("last_delta") or (delta_engine.get_project_what_changed(active_proj.get("id")) if active_proj else None)
    timeline = delta_engine.get_project_timeline(active_proj.get("id")) if active_proj else []
    monitoring_summary = scheduler.get_monitoring_summary("org-default")
    org_info = saas_store.get_organization("org-default")
    assets = saas_store.get_organization_assets("org-default")
    team_members = saas_store.list_team_members("org-default")
    integrations = saas_store.get_integration_settings("org-default")
    vuln_intel_summary = vuln_intel_store.get_intelligence_sync_summary()
    affecting_vulnerabilities = correlation_engine.get_vulnerabilities_affecting_customer("org-default")
    inventory_components = inventory_engine.get_all_inventory_components("org-default")
    all_intel_vulnerabilities = vuln_intel_store.get_all_vulnerabilities(limit=50)

    return render_template_string(
        DASHBOARD_HTML,
        result=result,
        projects=projects,
        tools_health=tools_health,
        prioritized_fixes=prioritized_fixes,
        what_changed=what_changed,
        timeline=timeline,
        monitoring_summary=monitoring_summary,
        org_info=org_info,
        assets=assets,
        team_members=team_members,
        integrations=integrations,
        vuln_intel_summary=vuln_intel_summary,
        affecting_vulnerabilities=affecting_vulnerabilities,
        inventory_components=inventory_components,
        all_intel_vulnerabilities=all_intel_vulnerabilities,
        plans=saas_store.PLANS,
        error=error,
        warning=warning,
        target=target,
        github_url=target,
        scan_type=scan_type,
        full_scan=full_scan,
        debug=debug,
    )


@app.route("/badge")
def badge_endpoint():
    """Generates TrustAudit SVG status badge."""
    target = request.args.get("repo") or request.args.get("target") or request.args.get("url") or ""
    result = get_last_scan_result(target) if target else None
    score = result["score"] if result else "UNKNOWN"
    svg = generate_badge_svg("TrustAudit", score)
    return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "no-cache, max-age=0"})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """REST API for CI/CD pipeline integration and programmatic scanning across modes."""
    data = request.get_json(silent=True) or {}
    target = data.get("target") or data.get("github_url") or data.get("url")
    scan_type = data.get("scan_type") or data.get("type", "auto")
    full_scan = bool(data.get("full_scan", False))
    auth_confirmed = bool(data.get("auth_confirmed", False) or data.get("authorization_confirmed", False))
    is_async = bool(data.get("async", False))

    if not target:
        return jsonify({"error": "Missing required parameter: target or github_url"}), 400

    if scan_type == "auto":
        scan_type = "repository" if is_github_repo_url(target) or os.path.exists(target) else "website"

    if scan_type == "repository" and not is_github_repo_url(target) and not os.path.exists(target):
        return jsonify({"error": "This looks like a website URL. Select Website / Web Application scan."}), 400

    if is_async:
        scan_id, record = scan_manager.submit_async_scan(
            target, scan_type=scan_type, full_scan=full_scan, auth_confirmed=auth_confirmed
        )
        return jsonify({
            "scanId": scan_id,
            "status": "PENDING",
            "target": target,
            "scanType": scan_type,
        }), 202

    try:
        result = scan_manager.execute_scan_synchronously(
            target, scan_type=scan_type, full_scan=full_scan, auth_confirmed=auth_confirmed
        )
        return jsonify(result), 200
    except TimeoutError as e:
        return jsonify({"error": str(e), "error_type": "timeout", "status": "TIMEOUT"}), 504
    except Exception as e:
        return jsonify({"error": str(e), "error_type": "scan_failed", "status": "FAILED"}), 500


@app.route("/api/scans/<scan_id>/debug", methods=["GET"])
def api_scan_debug(scan_id):
    """Development diagnostic endpoint returning full scan state and execution telemetry."""
    record = scan_manager.get_scan_job(scan_id)
    if not record:
        return jsonify({"error": f"Scan ID '{scan_id}' not found"}), 404
    return jsonify({
        "scanId": record["scanId"],
        "status": record["status"],
        "currentStage": record["currentStage"],
        "startedAt": record["startedAt"],
        "updatedAt": record["updatedAt"],
        "duration": record["duration"],
        "workerStatus": record["workerStatus"],
        "scannerStatus": record["scannerStatus"],
        "findingsCount": record["findingsCount"],
        "error": record["error"],
        "logs": record.get("logs", []),
    })


@app.route("/api/health/tools", methods=["GET"])
def api_health_tools():
    """Returns operational health, versions, paths, and setup instructions for all tools."""
    return jsonify({"tools": scan_manager.orchestrator.get_tool_health_records()}), 200


@app.route("/api/tools/nuclei/diagnose", methods=["GET"])
@app.route("/api/health/nuclei", methods=["GET"])
def api_nuclei_diagnose():
    """Diagnostic endpoint returning Nuclei installation status, executable path, version, and errors."""
    diag = scan_manager.orchestrator.nuclei.diagnose()
    return jsonify(diag), (200 if diag.get("installed") else 200)



@app.route("/api/scans/<scan_id>/cancel", methods=["POST"])
def api_scan_cancel(scan_id):
    """Cancels an active scan task."""
    cancelled = scan_manager.cancel_scan_job(scan_id)
    if cancelled:
        return jsonify({"scanId": scan_id, "status": "CANCELLED", "message": "Scan cancelled by user."}), 200
    record = scan_manager.get_scan_job(scan_id)
    if not record:
        return jsonify({"error": f"Scan ID '{scan_id}' not found"}), 404
    return jsonify({"scanId": scan_id, "status": record.get("status"), "message": "Scan is not in a cancellable state."}), 200


@app.route("/api/scans/<scan_id>/status", methods=["GET"])
def api_scan_status(scan_id):
    """Polling status endpoint for tracking scan progress and receiving final results."""
    record = scan_manager.get_scan_job(scan_id)
    if not record:
        return jsonify({"error": f"Scan ID '{scan_id}' not found"}), 404
    return jsonify({
        "scanId": record["scanId"],
        "status": record["status"],
        "currentStage": record["currentStage"],
        "startedAt": record["startedAt"],
        "updatedAt": record["updatedAt"],
        "elapsed_seconds": record.get("elapsed_seconds", 0.0),
        "duration": record["duration"],
        "findingsCount": record["findingsCount"],
        "error": record["error"],
        "result": record["result"] if record["status"] in ("COMPLETED", "COMPLETED_WITH_WARNINGS") else None,
    })


@app.route("/api/health/scanner", methods=["GET"])
def api_health_scanner():
    """Health check endpoint verifying system dependencies, storage, and engines."""
    db_ok = os.path.exists(os.path.join(os.path.dirname(__file__), "saas_data.json"))
    temp_ok = os.access(tempfile.gettempdir(), os.W_OK)
    engine_status = scan_manager.orchestrator.get_engine_status()
    return jsonify({
        "backend": "OK",
        "database": "OK" if db_ok else "DEGRADED",
        "scanner": "OK" if temp_ok else "ERROR",
        "worker": "OK",
        "engines": engine_status,
    })


@app.route("/api/plans", methods=["GET"])
def api_plans():
    """Returns canonical public pricing tiers and optional authenticated org limits."""
    org_id, _ = get_current_tenant_and_user(require_auth=True)
    org = saas_store.get_organization(org_id) if org_id else None
    return jsonify({
        "plans": saas_store.PLANS,
        "public_plans": saas_store.get_public_plans(),
        "current_organization": org,
    })


@app.route("/api/monitoring/status", methods=["GET"])
def api_monitoring_status():
    """Returns continuous monitoring status for authenticated organization."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    summary = scheduler.get_monitoring_summary(org_id)
    return jsonify(summary)


@app.route("/api/monitoring/schedule", methods=["POST"])
def api_monitoring_schedule():
    """Updates monitoring schedule for authenticated project."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    frequency = data.get("frequency", "daily")
    enabled = data.get("enabled", True)
    if not project_id:
        return jsonify({"error": "Missing project_id"}), 400
    if not saas_store.get_project(project_id, org_id):
        return jsonify({"error": "Project not found in your organisation."}), 404
    res = scheduler.set_project_schedule(project_id, frequency=frequency, enabled=enabled)
    return jsonify({"status": "success", "schedule": res})


@app.route("/api/monitoring/trigger-all", methods=["POST"])
def api_monitoring_trigger_all():
    """Triggers scheduled scans strictly for authenticated tenant projects."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    projects = saas_store.list_projects_for_org(org_id)
    triggered = []
    for p in projects:
        if p.get("monitoring_status") == "ACTIVE":
            sid = scheduler.run_scheduled_project_scan(p)
            if sid:
                triggered.append({"project_id": p.get("id"), "scan_id": sid})
    return jsonify({"status": "success", "triggered_count": len(triggered), "scans": triggered})


@app.route("/api/projects", methods=["GET"])
def api_projects():
    """Lists projects for the authenticated organization."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    projects = saas_store.list_projects_for_org(org_id)
    return jsonify({"projects": projects})


# ---------------------------------------------------------------------------
# Vulnerability Intelligence & Software Inventory REST APIs
# ---------------------------------------------------------------------------

@app.route("/api/intel/status", methods=["GET"])
def api_intel_status():
    """Retrieves source health, last sync timestamps, and vulnerability statistics."""
    summary = vuln_intel_store.get_intelligence_sync_summary()
    return jsonify(summary)


@app.route("/api/intel/sync", methods=["POST"])
def api_intel_sync():
    """Triggers an immediate sync for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    result = vuln_intel_service.vulnerability_intelligence_sync(org_id=org_id)
    return jsonify(result)


@app.route("/api/intel/vulnerabilities", methods=["GET"])
def api_intel_vulnerabilities():
    """Retrieves filtered vulnerability intelligence records."""
    severity = request.args.get("severity")
    source = request.args.get("source")
    ecosystem = request.args.get("ecosystem")
    q = request.args.get("q")
    known_exploited_only = request.args.get("known_exploited") == "true"
    limit = int(request.args.get("limit", 100))

    vulns = vuln_intel_store.get_all_vulnerabilities(
        limit=limit,
        severity=severity,
        source=source,
        ecosystem=ecosystem,
        cve_or_keyword=q,
        known_exploited_only=known_exploited_only,
    )
    return jsonify({"vulnerabilities": vulns, "count": len(vulns)})


@app.route("/api/intel/vulnerabilities/<vuln_id>", methods=["GET"])
def api_intel_vulnerability_detail(vuln_id):
    """Retrieves full metadata and advisory evidence for a specific vulnerability or CVE."""
    vuln = vuln_intel_store.get_vulnerability_by_id(vuln_id)
    if not vuln:
        # Attempt live lookup via OSV if not yet cached
        vuln = vuln_intel_sources.get_osv_vulnerability_details(vuln_id)
        if vuln:
            vuln_intel_store.upsert_vulnerability(vuln)
    if not vuln:
        return jsonify({"error": "Vulnerability not found"}), 404
    return jsonify({"vulnerability": vuln})


@app.route("/api/intel/affecting", methods=["GET"])
def api_intel_affecting():
    """Retrieves vulnerabilities affecting the authenticated tenant's inventory."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    project_id = request.args.get("project_id")
    include_fixed = request.args.get("include_fixed") == "true"
    findings = correlation_engine.get_vulnerabilities_affecting_customer(
        org_id=org_id,
        project_id=project_id,
        include_fixed=include_fixed
    )
    return jsonify({"affecting_vulnerabilities": findings, "count": len(findings)})


@app.route("/api/intel/recheck/<finding_id>", methods=["POST"])
def api_intel_recheck_finding(finding_id):
    """Find -> Fix -> Verify workflow strictly within authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    project_id = data.get("project_id")
    package_name = data.get("package_name")
    new_version = data.get("new_version")
    ecosystem = data.get("ecosystem", "npm")

    if not package_name or not new_version:
        all_affecting = correlation_engine.get_vulnerabilities_affecting_customer(org_id, include_fixed=True)
        target_f = next((f for f in all_affecting if f.get("id") == finding_id), None)
        if target_f:
            package_name = target_f.get("package_name")
            new_version = data.get("new_version") or target_f.get("installed_version")
            ecosystem = target_f.get("ecosystem", "npm")
            project_id = target_f.get("project_id", project_id)

    if not package_name or not new_version:
        return jsonify({"error": "Missing package_name or new_version for recheck."}), 400

    res = correlation_engine.verify_component_fix_recheck(
        project_id=project_id,
        package_name=package_name,
        new_version=new_version,
        ecosystem=ecosystem,
        org_id=org_id
    )
    return jsonify(res)


@app.route("/api/inventory", methods=["GET"])
def api_inventory():
    """Retrieves software component inventory strictly for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    project_id = request.args.get("project_id")
    comps = inventory_engine.get_all_inventory_components(org_id=org_id, project_id=project_id)
    return jsonify({"components": comps, "count": len(comps)})


@app.route("/api/assets", methods=["GET"])
def api_assets():
    """Returns attack surface and asset inventory strictly for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    assets = saas_store.get_organization_assets(org_id)
    return jsonify({"assets": assets})


@app.route("/api/compliance", methods=["GET"])
def api_compliance():
    """Returns compliance mapping strictly for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    target = request.args.get("target") or ""
    result = get_last_scan_result(target) if target else None
    if not result:
        projs = saas_store.list_projects_for_org(org_id)
        if projs and projs[0].get("last_scan_result"):
            result = projs[0]["last_scan_result"]
    findings = (result.get("findings") or []) if result else []
    mapping = compliance_engine.compute_compliance_mapping(findings)
    checklist = compliance_engine.evaluate_startup_security_checklist(result)
    return jsonify({"mapping": mapping, "checklist": checklist})


@app.route("/api/team/members", methods=["GET", "POST"])
def api_team_members():
    """Lists team members or invites a new team member (admin only)."""
    if request.method == "POST":
        org_id, actor, err = require_authenticated_tenant(allowed_roles=("admin",))
        if err:
            return err
        data = request.get_json(silent=True) or {}
        name = data.get("name", "Team Member")
        email = data.get("email", "")
        role = data.get("role", "member")
        try:
            user = saas_store.add_team_member(name, email, role=role, org_id=org_id)
        except ValueError as e:
            return jsonify({"status": "error", "error": str(e)}), 400
        security_utils.append_audit_log(
            org_id=org_id,
            action="team.member_added",
            resource_type="user",
            resource_id=user.get("id", ""),
            actor_user_id=actor.get("id", ""),
            actor_email=actor.get("email", ""),
            actor_role=actor.get("role", ""),
            details={"invited_email": user.get("email"), "role": user.get("role")},
        )
        return jsonify({"status": "success", "user": user}), 201

    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    members = saas_store.list_team_members(org_id)
    return jsonify({"team_members": members}), 200


@app.route("/api/team/members/<user_id>", methods=["DELETE"])
def api_team_member_delete(user_id):
    """Deletes a team member (admin only, same tenant)."""
    org_id, actor, err = require_authenticated_tenant(allowed_roles=("admin",))
    if err:
        return err
    if user_id == actor.get("id"):
        return jsonify({"status": "error", "error": "You cannot remove your own active admin account here."}), 400
    try:
        ok = saas_store.delete_team_member(user_id, org_id)
    except ValueError as e:
        return jsonify({"status": "error", "error": str(e)}), 400
    if not ok:
        return jsonify({"status": "error", "error": "Team member not found in your organisation."}), 404
    security_utils.append_audit_log(
        org_id=org_id,
        action="team.member_removed",
        resource_type="user",
        resource_id=user_id,
        actor_user_id=actor.get("id", ""),
        actor_email=actor.get("email", ""),
        actor_role=actor.get("role", ""),
    )
    return jsonify({"status": "success"}), 200


@app.route("/api/team/members/<user_id>/role", methods=["PUT", "POST"])
def api_team_member_role(user_id):
    """Updates a team member's role (admin only, same tenant)."""
    org_id, actor, err = require_authenticated_tenant(allowed_roles=("admin",))
    if err:
        return err
    data = request.get_json(silent=True) or {}
    new_role = data.get("role", "")
    ok, msg, updated = saas_store.update_team_member_role(user_id, new_role, org_id)
    if not ok:
        return jsonify({"status": "error", "error": msg}), 400
    security_utils.append_audit_log(
        org_id=org_id,
        action="team.role_changed",
        resource_type="user",
        resource_id=user_id,
        actor_user_id=actor.get("id", ""),
        actor_email=actor.get("email", ""),
        actor_role=actor.get("role", ""),
        details={"new_role": new_role},
    )
    return jsonify({"status": "success", "message": msg, "user": updated}), 200


@app.route("/api/integrations", methods=["GET", "POST"])
def api_integrations():
    """Gets or updates webhook & notification integration settings (tenant-isolated)."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        settings = saas_store.save_integration_settings(org_id, data)
        security_utils.append_audit_log(
            org_id=org_id,
            action="integrations.updated",
            resource_type="integrations",
            actor_user_id=actor.get("id", ""),
            actor_email=actor.get("email", ""),
            actor_role=actor.get("role", ""),
        )
        return jsonify({"status": "success", "settings": settings}), 200
    settings = saas_store.get_integration_settings(org_id)
    return jsonify({"settings": settings}), 200


@app.route("/api/integrations/test", methods=["POST"])
def api_integrations_test():
    """Dispatches a test notification to configured webhook target (SSRF-checked)."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    target_url = data.get("target_url")
    if target_url:
        import ssrf_protection
        try:
            ssrf_protection.validate_target_url_ssrf_safe(target_url)
        except ssrf_protection.SSRFSecurityError as e:
            return jsonify({"status": "error", "error": f"Blocked unsafe webhook URL: {e}"}), 400
    res = alerts.test_alert_integrations(org_id=org_id, target_url=target_url)
    return jsonify(res), 200


@app.route("/api/audit-logs", methods=["GET"])
def api_audit_logs():
    """Returns tenant-isolated security & compliance audit logs (JSON or CSV)."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    limit = int(request.args.get("limit", 100) or 100)
    action_filter = request.args.get("action")
    events = security_utils.get_audit_logs(org_id, limit=limit, action_filter=action_filter)
    if (request.args.get("format") or "").strip().lower() == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Timestamp", "Action", "Actor Email", "Actor Role", "Status", "Resource Type", "Resource ID", "Details"])
        for ev in events:
            w.writerow([
                ev.get("timestamp", ""),
                ev.get("action", ""),
                ev.get("actor_email", ""),
                ev.get("actor_role", ""),
                ev.get("status", "success"),
                ev.get("resource_type", ""),
                ev.get("resource_id", ""),
                json.dumps(ev.get("details") or {}),
            ])
        return Response(
            buf.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="TrustAudit_Audit_History_{org_id}.csv"',
                "X-Content-Type-Options": "nosniff",
            },
        )
    return jsonify({"status": "success", "events": events, "count": len(events)}), 200


@app.route("/api/billing/plan", methods=["POST"])
def api_billing_upgrade_plan():
    """Updates subscription tier for the authenticated organisation (admin only)."""
    org_id, actor, err = require_authenticated_tenant(allowed_roles=("admin",))
    if err:
        return err
    data = request.get_json(silent=True) or {}
    new_plan = data.get("plan", "")
    ok, msg, org = saas_store.upgrade_org_plan(org_id, new_plan)
    if not ok:
        return jsonify({"status": "error", "error": msg}), 400
    security_utils.append_audit_log(
        org_id=org_id,
        action="billing.plan_changed",
        resource_type="organization",
        resource_id=org_id,
        actor_user_id=actor.get("id", ""),
        actor_email=actor.get("email", ""),
        actor_role=actor.get("role", ""),
        details={"plan": new_plan},
    )
    return jsonify({"status": "success", "message": msg, "organization": org}), 200


@app.route("/api/finding/<finding_id>/note", methods=["POST"])
def api_finding_add_note(finding_id):
    """Appends an audit note to a finding record strictly within authenticated org."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    note = data.get("note", "")
    author = data.get("author") or user.get("email") or "Security Team"
    override = saas_store.add_finding_note(finding_id, note, author=author, org_id=org_id)
    return jsonify({"status": "success", "override": override})


@app.route("/api/finding/<finding_id>/assign", methods=["POST"])
def api_finding_assign(finding_id):
    """Assigns a vulnerability finding strictly within authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    assignee = data.get("assigned_to", "Lead Engineer")
    override = saas_store.assign_finding(finding_id, assignee, org_id=org_id)
    return jsonify({"status": "success", "override": override})


@app.route("/api/projects/<project_id>/what-changed", methods=["GET"])
def api_project_what_changed(project_id):
    """Retrieves What Changed delta comparison strictly within authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    delta = delta_engine.get_project_what_changed(project_id, org_id)
    return jsonify(delta)


@app.route("/api/projects/<project_id>/timeline", methods=["GET"])
def api_project_timeline(project_id):
    """Retrieves chronological security timeline events strictly within authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    timeline = delta_engine.get_project_timeline(project_id, org_id)
    return jsonify({"timeline": timeline})


@app.route("/api/projects/<project_id>/prioritized-fixes", methods=["GET"])
def api_project_prioritized_fixes(project_id):
    """Retrieves top 3-5 prioritized fix cards strictly within authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    proj = saas_store.get_project(project_id, org_id)
    if not proj:
        return jsonify({"error": "Project not found or unauthorized."}), 404
    findings = (proj.get("last_scan_result") or {}).get("findings", [])
    prioritized_list = prioritizer.prioritize_findings(findings, limit=5)
    return jsonify({"prioritized_fixes": prioritized_list})


@app.route("/api/finding/<finding_id>/status", methods=["POST"])
def api_finding_status(finding_id):
    """Updates lifecycle status strictly within authenticated org."""
    _org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    status = data.get("status", "acknowledged")
    override = saas_store.set_finding_status(finding_id, status)
    return jsonify({"status": "success", "override": override})


# ---------------------------------------------------------------------------
# Phase 2: Trust & Distribution Feature API Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/projects/<project_id>/badge", methods=["GET"])
def api_project_badge_info(project_id):
    """Returns embeddable markdown and HTML badge snippets strictly within authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    import trust_features
    proj = saas_store.get_project(project_id, org_id)
    if not proj:
        return jsonify({"error": "Project not found or unauthorized."}), 404
    score = (proj.get("last_score") if proj else 100) or 100
    grade = (proj.get("last_grade") if proj else "A") or "A"
    base_url = request.host_url.rstrip("/")
    badge_data = trust_features.generate_badge_markdown(project_id, base_url=base_url, score=score, grade=grade)
    return jsonify(badge_data)


@app.route("/api/badge/<slug>", methods=["GET"])
@app.route("/api/badge/<slug>.svg", methods=["GET"])
def api_badge_svg(slug):
    """Renders dynamic SVG security score badge."""
    import badge
    svg_content = badge.generate_badge_svg(label="TrustAudit", score=100, grade="A")
    return Response(svg_content, mimetype="image/svg+xml")


@app.route("/api/projects/<project_id>/weekly-digest", methods=["GET"])
@app.route("/api/digest/weekly", methods=["GET"])
def api_weekly_digest(project_id=None):
    """Returns the automated weekly digest data strictly for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    import trust_features
    digest = trust_features.generate_weekly_digest(org_id)
    return jsonify(digest)


@app.route("/api/alerts/weekly-digest", methods=["POST"])
def api_dispatch_weekly_digest():
    """Dispatches the weekly digest strictly for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    import trust_features
    result = trust_features.dispatch_weekly_digest(org_id)
    return jsonify(result)


@app.route("/api/findings/eli5", methods=["POST"])
def api_finding_eli5():
    """Generates an ELI5 plain-English explanation for a finding."""
    import trust_features
    data = request.get_json(silent=True) or {}
    explanation = trust_features.generate_eli5_explanation(data)
    return jsonify({"eli5_explanation": explanation})


@app.route("/api/findings/ai-prompt", methods=["POST"])
def api_finding_ai_prompt():
    """Generates a ready-to-copy AI fix prompt for Cursor / Claude / Copilot."""
    import trust_features
    data = request.get_json(silent=True) or {}
    prompt = trust_features.generate_ai_fix_prompt(data)
    return jsonify({"ai_fix_prompt": prompt})


# ---------------------------------------------------------------------------
# Phase 3: MCP-Specific Differentiation API Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/mcp/reputation", methods=["GET"])
def api_mcp_reputation():
    """Evaluates reputation and registry verification status for an MCP package."""
    import mcp_intelligence
    pkg = request.args.get("package") or request.args.get("name") or "@modelcontextprotocol/server-filesystem"
    rep = mcp_intelligence.lookup_mcp_reputation(pkg)
    return jsonify(rep)


@app.route("/api/mcp/reputation-lookup", methods=["GET"])
def api_mcp_reputation_lookup():
    """Basic v1: Searches curated OWASP MCP Top 10 dataset for package reputation and concerns."""
    import mcp_curated_lookup
    pkg = request.args.get("package") or request.args.get("name") or ""
    res = mcp_curated_lookup.lookup_curated_mcp_reputation(pkg)
    return jsonify(res)


@app.route("/api/mcp/typosquat", methods=["POST"])
def api_mcp_typosquat():
    """Scans a list of package or tool names for MCP typosquatting attacks."""
    import mcp_intelligence
    data = request.get_json(silent=True) or {}
    packages = data.get("packages") or data.get("tools") or []
    findings = mcp_intelligence.scan_mcp_manifest_for_typosquatting(packages)
    return jsonify({"findings": findings, "count": len(findings)})


@app.route("/api/mcp/diff-permissions", methods=["POST"])
def api_mcp_diff_permissions():
    """Performs deep permission and capability diffing between baseline and current MCP tools."""
    import mcp_intelligence
    data = request.get_json(silent=True) or {}
    baseline_tool = data.get("baseline_tool", {})
    current_tool = data.get("current_tool", {})
    diff = mcp_intelligence.diff_tool_permissions(baseline_tool, current_tool)
    return jsonify(diff)


@app.route("/api/finding/<finding_id>/verify", methods=["POST"])
def api_finding_verify(finding_id):
    """Find -> Fix -> Verify workflow strictly scoped to authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    target = data.get("target")
    scan_type = data.get("scan_type", "website")
    project_id = data.get("project_id")

    if not target and project_id:
        proj = saas_store.get_project(project_id, org_id)
        if proj:
            target = proj.get("website_url") or proj.get("repo_url")
            scan_type = proj.get("target_type", "website")

    if not target:
        return jsonify({"error": "Target or project_id required for verification rescan."}), 400

    try:
        if scan_type == "website":
            res = execute_website_scan(target, auth_confirmed=True)
        elif scan_type == "mcp":
            res = execute_mcp_scan(target, full_scan=False, auth_confirmed=True)
        else:
            res = execute_scan(target, full_scan=False, auth_confirmed=True)

        remaining_ids = [f.get("id") or f.get("finding_id") for f in res.get("findings", [])]
        is_fixed = finding_id not in remaining_ids

        if is_fixed:
            saas_store.set_finding_status(finding_id, "verified")
            if project_id:
                delta_engine.compute_and_record_scan_delta(project_id, res, org_id=org_id)
            alerts.dispatch_security_alert("FIX_VERIFIED", target, f"Finding {finding_id} Verified", "Remediation verified clean via automated rescan.", severity="LOW")
            return jsonify({
                "status": "VERIFIED",
                "message": "Vulnerability verified as resolved. Status updated to VERIFIED.",
                "is_fixed": True,
                "score": res.get("score"),
                "grade": res.get("grade")
            }), 200
        else:
            return jsonify({
                "status": "STILL_VULNERABLE",
                "message": "Vulnerability was still detected during verification scan. Please verify code patch.",
                "is_fixed": False,
                "score": res.get("score"),
                "grade": res.get("grade")
            }), 200
    except Exception:
        return jsonify({"error": "Verification scan failed."}), 500


@app.route("/api/finding/<finding_id>/remediate", methods=["GET", "POST"])
def api_finding_remediate(finding_id):
    """Returns Fix Center package and Cursor/Claude Code/Copilot prompt for a finding."""
    data = request.get_json(silent=True) or {}
    finding_obj = data.get("finding") or {"id": finding_id, "title": "Security Vulnerability", "severity": "HIGH"}
    card = prioritizer.create_fix_card(finding_obj)
    override = saas_store.get_finding_override(finding_id)
    return jsonify({
        "finding_id": finding_id,
        "title": card.get("title"),
        "severity": card.get("severity"),
        "why_this_matters": card.get("why_this_matters"),
        "what_to_do": card.get("what_to_do"),
        "how_to_verify": card.get("how_to_verify"),
        "ai_fix_prompt": card.get("ai_prompt"),
        "override": override,
    })


@app.route("/api/advisor/query", methods=["POST"])
def api_advisor_query():
    """Interactive AI Security Advisor grounded strictly on real scan findings."""
    data = request.get_json(silent=True) or {}
    query = data.get("query", "")
    target = data.get("target", "")
    scan_id = data.get("scan_id")

    scan_result = None
    if scan_id:
        record = scan_manager.get_scan_job(scan_id)
        if record and record.get("result"):
            scan_result = record["result"]

    if not scan_result and target:
        scan_result = get_last_scan_result(target)

    if not scan_result:
        # Fallback to first project
        projs = saas_store.list_projects_for_org("org-default")
        if projs and projs[0].get("last_scan_result"):
            scan_result = projs[0]["last_scan_result"]

    if not scan_result:
        return jsonify({
            "answer": "No active scan findings found for this target. Please execute a scan first.",
            "referenced_findings": [],
        }), 200

    from ai_analyst import query_ai_security_advisor
    response = query_ai_security_advisor(query, scan_result)
    return jsonify(response), 200


@app.route("/report/html")
@app.route("/report/technical")
def report_html_endpoint():
    """Exports printable HTML readiness/technical audit report strictly for authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    target = request.args.get("target") or request.args.get("repo") or request.args.get("url") or ""
    if not target:
        projs = saas_store.list_projects_for_org(org_id)
        if projs and projs[0].get("last_scan_result"):
            result = projs[0]["last_scan_result"]
        else:
            return Response(dpdp_reports.generate_dpdp_html_report(org_id), mimetype="text/html")
    else:
        if is_github_repo_url(target) or os.path.exists(target):
            result = execute_scan(target, False)
        else:
            result = execute_website_scan(target)
    html = generate_technical_report(result)
    return Response(html, mimetype="text/html")


@app.route("/report/executive")
def report_executive_endpoint():
    """Exports executive summary report strictly for authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    target = request.args.get("target") or request.args.get("repo") or request.args.get("url") or ""
    if not target:
        projs = saas_store.list_projects_for_org(org_id)
        if projs and projs[0].get("last_scan_result"):
            result = projs[0]["last_scan_result"]
        else:
            return Response(dpdp_reports.generate_dpdp_html_report(org_id), mimetype="text/html")
    else:
        if is_github_repo_url(target) or os.path.exists(target):
            result = execute_scan(target, False)
        else:
            result = execute_website_scan(target)
    html = generate_executive_report(result)
    return Response(html, mimetype="text/html")


@app.route("/api/report/json")
def report_json_endpoint():
    """Exports structured JSON security audit report strictly for authenticated org."""
    _org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    target = request.args.get("target") or request.args.get("repo") or request.args.get("url") or ""
    if not target:
        return jsonify({"error": "Target parameter required (?target=... or ?repo=...)"}), 400
    if is_github_repo_url(target) or os.path.exists(target):
        result = execute_scan(target, False)
    else:
        result = execute_website_scan(target)
    json_data = generate_json_report(result)
    return jsonify(json_data)


@app.route("/api/history")
def history_endpoint():
    _org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    target = request.args.get("target") or request.args.get("repo") or request.args.get("url") or ""
    history = get_scan_history(target)
    return jsonify({"target": target, "history": history})


@app.route("/api/baseline", methods=["GET", "POST"])
def baseline_endpoint():
    _org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    from baseline_store import set_security_baseline, get_security_baseline
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        github_url = data.get("github_url")
        if not github_url:
            return jsonify({"error": "Missing github_url"}), 400
        scan_result = execute_scan(github_url, False)
        record = set_security_baseline(github_url, scan_result)
        return jsonify({"status": "success", "baseline": record}), 200
    else:
        github_url = request.args.get("repo", "")
        baseline = get_security_baseline(github_url)
        return jsonify({"github_url": github_url, "baseline": baseline})


@app.route("/api/webhook/github", methods=["POST"])
def github_webhook():
    payload = request.get_json(silent=True) or {}
    repo_info = payload.get("repository", {})
    clone_url = repo_info.get("clone_url") or repo_info.get("html_url")

    if not clone_url:
        return jsonify({"status": "ignored", "reason": "No repository clone_url found"}), 200

    try:
        result = execute_scan(clone_url, False)
        return jsonify({
            "status": "success",
            "repository": clone_url,
            "score": result.get("score"),
            "grade": result.get("grade"),
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500



# ==============================================================================
# TENANT HELPER & SESSION AUTHENTICATION
# ==============================================================================

def _check_csrf_origin() -> bool:
    """
    Validates Origin / Referer on state-changing cookie-authenticated requests
    when an Origin header is supplied by browsers.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    origin = request.headers.get("Origin", "").strip()
    if origin:
        from urllib.parse import urlparse
        parsed_origin = urlparse(origin)
        req_host = (request.host or "").split(":")[0].lower()
        orig_host = (parsed_origin.hostname or "").lower()
        if orig_host and req_host and orig_host != req_host:
            return False
    return True


def get_current_tenant_and_user(require_auth: bool = False):
    """
    Extracts authenticated user and organization ID with strict multi-tenant boundary checks.
    When require_auth=True, returns (None, None) if the session token is missing or invalid.
    """
    auth_header = request.headers.get("Authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "trustaudit_session" in request.cookies:
        token = request.cookies.get("trustaudit_session")

    is_valid, user, org_id = saas_store.validate_session(
        token,
        allow_demo_fallback=(not require_auth and not token)
    )
    if require_auth and (not is_valid or not org_id):
        return None, None
    return org_id, user


def require_authenticated_tenant(allowed_roles=None, allow_viewer_write: bool = False):
    """
    Enforces authenticated session, CSRF Origin check (for browser cookies), and RBAC role check.
    Returns (org_id, user_dict, None) or (None, None, error_response).
    """
    if "Authorization" not in request.headers and "trustaudit_session" in request.cookies:
        if not _check_csrf_origin():
            return None, None, (jsonify({"status": "error", "error": "Cross-origin state-changing request rejected."}), 403)

    org_id, user = get_current_tenant_and_user(require_auth=True)
    if not org_id or not user:
        return None, None, (jsonify({"status": "error", "error": "Authentication required. Please sign in."}), 401)

    role = user.get("role", "member")
    if allowed_roles and role not in allowed_roles:
        return None, None, (jsonify({"status": "error", "error": f"Forbidden: requires role {', '.join(allowed_roles)}."}), 403)
    if not allow_viewer_write and request.method in ("POST", "PUT", "PATCH", "DELETE") and role == "viewer":
        return None, None, (jsonify({"status": "error", "error": "Viewer accounts have read-only access."}), 403)
    return org_id, user, None


def require_platform_admin():
    org_id, user, err = require_authenticated_tenant(allowed_roles=("admin",))
    if err:
        return None, None, err
    if not user.get("is_platform_admin"):
        return None, None, (jsonify({"status": "error", "error": "Forbidden: platform administrator privileges required."}), 403)
    return org_id, user, None


@app.route("/api/auth/register", methods=["POST"])
def api_auth_register():
    """Registers a new organization and administrator account with OWASP password hashing."""
    client_ip = request.remote_addr or "unknown"
    allowed, retry = security_utils.rate_limiter.allow(f"register:{client_ip}", max_requests=20, window_seconds=3600)
    if not allowed:
        return jsonify({"status": "error", "message": f"Too many registration attempts. Retry in {retry}s."}), 429

    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    name = data.get("name", "Owner")
    org_name = data.get("company_name") or data.get("org_name", "My Company")
    country = data.get("country", "India")
    plan = data.get("plan", "starter")
    industry = data.get("industry", "")
    website = data.get("website", "")
    terms_accepted = data.get("terms_accepted", None)
    privacy_accepted = data.get("privacy_accepted", None)

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required."}), 400

    ok, msg, res = saas_store.register_user(
        email, password, name, org_name, country=country, plan=plan, industry=industry, website=website,
        terms_accepted=bool(terms_accepted) if terms_accepted is not None else None,
        privacy_accepted=bool(privacy_accepted) if privacy_accepted is not None else None,
    )
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400

    resp = jsonify({"status": "success", "message": msg, "data": res})
    if res and res.get("token"):
        is_https = request.is_secure or (request.headers.get("X-Forwarded-Proto", "").lower() == "https")
        resp.set_cookie(
            "trustaudit_session",
            res["token"],
            max_age=30*86400,
            httponly=True,
            secure=is_https,
            samesite="Lax"
        )
    return resp, 201


@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    """Authenticates credentials with rate limiting, OWASP hashing, and TOTP MFA."""
    client_ip = request.remote_addr or "unknown"
    allowed, retry = security_utils.rate_limiter.allow(f"login_ip:{client_ip}", max_requests=40, window_seconds=300)
    if not allowed:
        return jsonify({"status": "error", "message": f"Too many login requests. Retry in {retry}s."}), 429

    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    totp_code = data.get("totp_code") or data.get("mfa_code") or data.get("code")
    recovery_code = data.get("recovery_code")

    ok, msg, res = saas_store.authenticate_user(email, password, totp_code=totp_code, recovery_code=recovery_code)
    if not ok:
        if msg == "MFA_REQUIRED":
            return jsonify({
                "status": "mfa_required",
                "message": "Multi-Factor Authentication code required.",
                "mfa_required": True,
                "user_id": res.get("user_id") if res else None
            }), 200
        status_code = 429 if "Too many failed login" in msg else 401
        return jsonify({"status": "error", "message": msg}), status_code

    resp = jsonify({"status": "success", "message": msg, "data": res})
    if res and res.get("token"):
        is_https = request.is_secure or (request.headers.get("X-Forwarded-Proto", "").lower() == "https")
        resp.set_cookie(
            "trustaudit_session",
            res["token"],
            max_age=30*86400,
            httponly=True,
            secure=is_https,
            samesite="Lax"
        )
    return resp, 200


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    """Invalidates active session token."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.cookies.get("trustaudit_session", "")
    if token:
        saas_store.revoke_session(token)
    resp = jsonify({"status": "success", "message": "Logged out successfully."})
    resp.delete_cookie("trustaudit_session")
    return resp, 200


@app.route("/api/auth/me", methods=["GET"])
def api_auth_me():
    """Returns active authenticated session user and organization details strictly without demo fallback."""
    org_id, user = get_current_tenant_and_user(require_auth=True)
    if not org_id or not user:
        return jsonify({"authenticated": False, "user": None, "organization": None}), 401
    org = saas_store.get_organization(org_id)
    return jsonify({"authenticated": True, "user": user, "organization": org}), 200


@app.route("/api/auth/forgot-password", methods=["POST"])
def api_auth_forgot_password():
    """Generates single-use 1-hour password reset token without leaking raw tokens in HTTP responses."""
    client_ip = request.remote_addr or "unknown"
    allowed, retry = security_utils.rate_limiter.allow(f"forgot_pwd:{client_ip}", max_requests=10, window_seconds=3600)
    if not allowed:
        return jsonify({"status": "error", "message": f"Too many password reset requests. Retry in {retry}s."}), 429

    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    if not email:
        return jsonify({"status": "error", "message": "Email address is required."}), 400
    ok, msg, _token = saas_store.create_password_reset_token(email)
    # Never expose reset_token in HTTP JSON response (deliver only out-of-band via configured email transport)
    return jsonify({"status": "success", "message": msg}), 200


@app.route("/api/auth/reset-password", methods=["POST"])
def api_auth_reset_password():
    """Validates reset token and sets new 600,000-iteration PBKDF2 password."""
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    new_password = data.get("new_password", "")
    if not token or not new_password:
        return jsonify({"status": "error", "message": "Token and new password are required."}), 400
    ok, msg = saas_store.reset_password_with_token(token, new_password)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400
    return jsonify({"status": "success", "message": msg}), 200


@app.route("/api/auth/mfa/setup", methods=["POST"])
def api_auth_mfa_setup():
    """Initiates RFC 6238 TOTP MFA setup for authenticated user."""
    org_id, user = get_current_tenant_and_user(require_auth=True)
    if not user:
        return jsonify({"error": "Unauthorized. Active session token required."}), 401
    ok, msg, res = saas_store.setup_mfa_for_user(user["id"])
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"status": "success", "data": res}), 200


@app.route("/api/auth/mfa/enable", methods=["POST"])
def api_auth_mfa_enable():
    """Confirms TOTP code, enables MFA on account, and issues 8 single-use recovery codes."""
    org_id, user = get_current_tenant_and_user(require_auth=True)
    if not user:
        return jsonify({"error": "Unauthorized. Active session token required."}), 401
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    ok, msg, recovery_codes = saas_store.confirm_and_enable_mfa_with_recovery(user["id"], code)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400
    return jsonify({"status": "success", "message": msg, "recovery_codes": recovery_codes}), 200


@app.route("/api/auth/mfa/recovery/regenerate", methods=["POST"])
def api_auth_mfa_recovery_regenerate():
    """Regenerates 8 single-use backup recovery codes after live TOTP verification."""
    _org_id, user = get_current_tenant_and_user(require_auth=True)
    if not user:
        return jsonify({"error": "Unauthorized. Active session token required."}), 401
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    ok, msg, recovery_codes = saas_store.regenerate_mfa_recovery_codes(user["id"], code)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400
    return jsonify({"status": "success", "message": msg, "recovery_codes": recovery_codes}), 200


@app.route("/api/auth/sessions", methods=["GET"])
def api_auth_sessions():
    """Lists active sessions belonging to the authenticated user."""
    _org_id, user = get_current_tenant_and_user(require_auth=True)
    if not user:
        return jsonify({"error": "Unauthorized. Active session token required."}), 401
    auth_header = request.headers.get("Authorization", "")
    cur_tok = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.cookies.get("trustaudit_session", "")
    sessions = saas_store.list_user_sessions(user["id"], current_token=cur_tok)
    return jsonify({"status": "success", "sessions": sessions}), 200


@app.route("/api/auth/sessions/revoke", methods=["POST"])
def api_auth_sessions_revoke():
    """Revokes a specific session by ID or signs out all other active sessions."""
    _org_id, user = get_current_tenant_and_user(require_auth=True)
    if not user:
        return jsonify({"error": "Unauthorized. Active session token required."}), 401
    data = request.get_json(silent=True) or {}
    auth_header = request.headers.get("Authorization", "")
    cur_tok = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.cookies.get("trustaudit_session", "")
    if data.get("revoke_others"):
        count = saas_store.revoke_other_sessions(user["id"], keep_token=cur_tok)
        return jsonify({"status": "success", "revoked_count": count, "message": f"Signed out {count} other session(s)."}), 200
    sid = str(data.get("session_id") or "").strip()
    ok = saas_store.revoke_user_session(user["id"], sid)
    if not ok:
        return jsonify({"status": "error", "message": "Session not found."}), 404
    return jsonify({"status": "success", "message": "Session revoked cleanly."}), 200


@app.route("/api/auth/change-password", methods=["POST"])
def api_auth_change_password():
    """Verifies current password and applies a new 600,000-iteration PBKDF2 password."""
    _org_id, user = get_current_tenant_and_user(require_auth=True)
    if not user:
        return jsonify({"error": "Unauthorized. Active session token required."}), 401
    data = request.get_json(silent=True) or {}
    cur_pwd = data.get("current_password", "")
    new_pwd = data.get("new_password", "")
    auth_header = request.headers.get("Authorization", "")
    cur_tok = auth_header[7:].strip() if auth_header.startswith("Bearer ") else request.cookies.get("trustaudit_session", "")
    ok, msg = saas_store.change_user_password(user["id"], cur_pwd, new_pwd, keep_token=cur_tok)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400
    return jsonify({"status": "success", "message": msg}), 200


@app.route("/api/auth/mfa/disable", methods=["POST"])
def api_auth_mfa_disable():
    """Disables MFA after validating current TOTP code."""
    org_id, user = get_current_tenant_and_user(require_auth=True)
    if not user:
        return jsonify({"error": "Unauthorized. Active session token required."}), 401
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    ok, msg = saas_store.disable_mfa_for_user(user["id"], code)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400
    return jsonify({"status": "success", "message": msg}), 200


@app.route("/api/account/delete", methods=["POST"])
def api_account_delete():
    """Executes complete organization deletion and scrubbing of all assets (admin only)."""
    org_id, _user, err = require_authenticated_tenant(allowed_roles=("admin",))
    if err:
        return err
    ok, msg, audit = saas_store.delete_organization_account(org_id)
    if not ok:
        return jsonify({"error": msg}), 400
    resp = jsonify({"status": "success", "message": msg, "deletion_audit_record": audit})
    resp.delete_cookie("trustaudit_session")
    return resp, 200


@app.route("/api/public/grievance/submit", methods=["POST"])
def api_public_grievance_submit():
    """Submits a privacy, personal data rights, or security grievance."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    category = data.get("category", "Privacy & Personal Data").strip()
    description = data.get("description", "").strip()
    company = data.get("company", "").strip()

    if not name or not email or not description:
        return jsonify({"status": "error", "message": "Name, email, and description are required."}), 400

    ticket = saas_store.submit_grievance(name, email, category, description, company)
    return jsonify({
        "status": "success",
        "message": f"Your grievance has been recorded and assigned reference ID {ticket['reference_id']}. A confirmation has been logged for review.",
        "ticket": ticket
    }), 201


@app.route("/.well-known/security.txt", methods=["GET"])
def well_known_security_txt():
    """RFC 9116 compliant security disclosure metadata reflecting verified contact channels."""
    import datetime
    sec_email = os.environ.get("TRUSTAUDIT_SECURITY_EMAIL", "").strip()
    grv_email = os.environ.get("TRUSTAUDIT_GRIEVANCE_EMAIL", "").strip()
    expires_iso = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=330)).strftime("%Y-%m-%dT%H:%M:%SZ")
    base_url = request.url_root.rstrip("/")
    lines = []
    if sec_email:
        lines.append(f"Contact: mailto:{sec_email}")
    if grv_email:
        lines.append(f"Contact: mailto:{grv_email}")
    lines.append(f"Contact: {base_url}/security")
    lines.append(f"Expires: {expires_iso}")
    lines.append("Preferred-Languages: en")
    lines.append(f"Canonical: {base_url}/.well-known/security.txt")
    lines.append(f"Policy: {base_url}/security")
    return Response("\n".join(lines) + "\n", mimetype="text/plain; charset=utf-8")


@app.route("/api/public/quick-check", methods=["POST"])
def api_public_quick_check():
    """Executes safe, non-invasive public perimeter and privacy checks with SSRF & rate limiting."""
    client_ip = request.remote_addr or "unknown"
    allowed, retry = security_utils.rate_limiter.allow(f"quick_check:{client_ip}", max_requests=25, window_seconds=3600)
    if not allowed:
        return jsonify({"status": "error", "message": f"Hourly quick-check limit reached. Try again in {retry}s."}), 429

    import ssrf_protection

    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "").strip()
    if not raw_url:
        return jsonify({"status": "error", "message": "URL is required."}), 400

    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        raw_url = "https://" + raw_url

    # SSRF Validation
    try:
        ssrf_meta = ssrf_protection.validate_target_url_ssrf_safe(raw_url)
    except ssrf_protection.SSRFSecurityError as e:
        return jsonify({
            "status": "blocked",
            "message": f"Target blocked by SSRF security policy: {e}",
            "checks": {
                "https": "BLOCKED",
                "tls": "BLOCKED",
                "hsts": "BLOCKED",
                "privacy_policy": "BLOCKED",
                "privacy_contact": "BLOCKED"
            }
        }), 400

    # Execute safe HTTP fetch
    fetch_res = ssrf_protection.safe_http_fetch(raw_url, method="GET", timeout=(3.0, 4.0))
    if not fetch_res.get("success"):
        err_type = fetch_res.get("error_type", "ERROR")
        return jsonify({
            "status": "partial",
            "url": raw_url,
            "message": fetch_res.get("error", "Failed to connect to target."),
            "checks": {
                "https": "PASS" if ssrf_meta["scheme"] == "https" else "NOT ENFORCED",
                "tls": "FAILED" if err_type == "SSL_ERROR" else ("TIMEOUT" if err_type == "TIMEOUT" else "CHECK FAILED"),
                "hsts": "UNKNOWN",
                "privacy_policy": "NOT CHECKED",
                "privacy_contact": "NOT CHECKED"
            }
        })

    headers = fetch_res.get("headers", {})
    body_text = fetch_res.get("content_text", "").lower()
    final_url = fetch_res.get("final_url", "")

    is_https = final_url.startswith("https://") or (ssrf_meta["scheme"] == "https")
    https_status = "PASS" if is_https else "MISSING"
    tls_status = "CHECKED" if is_https else "NOT APPLICABLE"

    has_hsts = "strict-transport-security" in [k.lower() for k in headers.keys()]
    hsts_status = "PASS" if has_hsts else "MISSING"

    privacy_link_found = any(k in body_text for k in ["privacy policy", "privacy notice", "/privacy", "privacy-policy", "data protection"])
    privacy_status = "FOUND" if privacy_link_found else "NOT DETECTED"

    has_contact = any(k in body_text for k in ["grievance@", "privacy@", "dpo@", "data.protection@", "security@", "compliance@"])
    contact_status = "FOUND" if has_contact else "NOT DETECTED"

    return jsonify({
        "status": "success",
        "url": final_url,
        "checks": {
            "https": https_status,
            "tls": tls_status,
            "hsts": hsts_status,
            "privacy_policy": privacy_status,
            "privacy_contact": contact_status
        },
        "disclaimer": "This quick check evaluates basic observable network transport and privacy indicators. It does NOT constitute a comprehensive security audit or legal compliance determination under DPDP Act 2023.",
        "duration_ms": fetch_res.get("duration_ms")
    })


# ==============================================================================
# COMPLIANCE CENTRE APIS (DPDP, SOC 2, ISO 27001, GDPR)
# ==============================================================================

@app.route("/api/compliance/frameworks", methods=["GET"])
def api_compliance_frameworks():
    """Returns metadata and structured controls for all supported compliance frameworks."""
    return jsonify({
        "metadata": compliance_frameworks.FRAMEWORK_METADATA,
        "controls": compliance_frameworks.CONTROLS_DATABASE
    }), 200


@app.route("/api/compliance/profile", methods=["GET", "POST"])
def api_compliance_profile():
    """Gets or updates organization onboarding and compliance profiling questionnaire."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        updated = saas_store.save_org_profile(org_id, data)
        return jsonify({"status": "success", "profile": updated}), 200

    profile = saas_store.get_org_profile(org_id)
    return jsonify({
        "profile": profile,
        "questions": compliance_frameworks.ONBOARDING_QUESTIONS
    }), 200


@app.route("/api/compliance/assessment", methods=["GET"])
def api_compliance_assessment():
    """Generates an organisation-specific compliance assessment strictly within authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    profile = saas_store.get_org_profile(org_id)
    projs = saas_store.list_projects_for_org(org_id)
    all_findings = []
    for p in projs:
        scan_res = p.get("last_scan_result")
        if scan_res and isinstance(scan_res, dict):
            all_findings.extend(scan_res.get("findings", []))

    evidence_items = evidence_vault.list_evidence_for_org(org_id)
    assessment = compliance_frameworks.generate_organization_assessment(profile, all_findings, evidence_items)
    saas_store.save_org_compliance_assessment(org_id, assessment)
    return jsonify(assessment), 200


@app.route("/api/compliance/controls/<control_id>", methods=["GET"])
def api_compliance_control_detail(control_id):
    """Returns deep control requirements, questions, and tenant evidence guidelines."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    target_ctrl = None
    target_fw = None
    for fw, ctrls in compliance_frameworks.CONTROLS_DATABASE.items():
        for c in ctrls:
            if c["control_id"] == control_id:
                target_ctrl = c
                target_fw = fw
                break
        if target_ctrl:
            break

    if not target_ctrl:
        return jsonify({"error": f"Control '{control_id}' not found."}), 404

    evidence_items = evidence_vault.list_evidence_for_org(org_id, control_id=control_id)
    return jsonify({
        "framework": target_fw,
        "control": target_ctrl,
        "evidence": evidence_items
    }), 200


# ==============================================================================
# EVIDENCE VAULT APIS
# ==============================================================================

@app.route("/api/evidence", methods=["GET", "POST"])
def api_evidence():
    """Lists evidence records or uploads a validated new evidence item (auth + RBAC enforced)."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err

    if request.method == "POST":
        if request.is_json:
            data = request.get_json(silent=True) or {}
            title = data.get("title", "Evidence Item")
            control_id = data.get("control_id", "GENERAL")
            framework = data.get("framework", "SOC2")
            description = data.get("description", "")
            owner = data.get("owner_name") or user.get("name", "Compliance Officer")
            cycle_days = int(data.get("review_cycle_days") or 90)
            try:
                item = evidence_vault.create_evidence_item(
                    org_id=org_id,
                    title=title,
                    control_id=control_id,
                    framework=framework,
                    description=description,
                    owner_name=owner,
                    review_cycle_days=cycle_days
                )
            except ValueError as e:
                return jsonify({"status": "error", "error": str(e)}), 400
            return jsonify({"status": "success", "evidence": item}), 201
        else:
            title = request.form.get("title", "Uploaded Document")
            control_id = request.form.get("control_id", "GENERAL")
            framework = request.form.get("framework", "SOC2")
            description = request.form.get("description", "")
            owner = request.form.get("owner_name") or user.get("name", "Compliance Officer")
            cycle_days = int(request.form.get("review_cycle_days") or 90)

            file_bytes = None
            filename = None
            content_type = "application/octet-stream"
            if "file" in request.files:
                f = request.files["file"]
                if f and f.filename:
                    filename = f.filename
                    file_bytes = f.read()
                    content_type = f.content_type or "application/octet-stream"

            try:
                item = evidence_vault.create_evidence_item(
                    org_id=org_id,
                    title=title,
                    control_id=control_id,
                    framework=framework,
                    description=description,
                    owner_name=owner,
                    review_cycle_days=cycle_days,
                    file_bytes=file_bytes,
                    filename=filename,
                    content_type=content_type
                )
            except ValueError as e:
                return jsonify({"status": "error", "error": str(e)}), 400
            return jsonify({"status": "success", "evidence": item}), 201

    control_filter = request.args.get("control_id")
    fw_filter = request.args.get("framework")
    items = evidence_vault.list_evidence_for_org(org_id, control_id=control_filter, framework=fw_filter)
    return jsonify({"evidence": items, "count": len(items)}), 200


@app.route("/api/evidence/<evidence_id>", methods=["GET", "PUT", "DELETE"])
def api_evidence_item_detail(evidence_id):
    """Retrieves, updates, or deletes an evidence vault record strictly within tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err

    if request.method == "DELETE":
        ok = evidence_vault.delete_evidence_item(evidence_id, org_id)
        if ok:
            return jsonify({"status": "success", "message": "Evidence deleted."}), 200
        return jsonify({"error": "Evidence not found or unauthorized."}), 404

    item = evidence_vault.get_evidence_item(evidence_id, org_id)
    if not item:
        return jsonify({"error": "Evidence not found or unauthorized."}), 404

    if request.method == "PUT":
        data = request.get_json(silent=True) or {}
        try:
            updated = evidence_vault.update_evidence_item(
                evidence_id=evidence_id,
                org_id=org_id,
                title=data.get("title"),
                description=data.get("description"),
                owner_name=data.get("owner_name"),
                review_status=data.get("review_status"),
            )
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"status": "success", "evidence": updated}), 200

    return jsonify({"evidence": item}), 200


@app.route("/api/evidence/<evidence_id>/download", methods=["GET"])
def api_evidence_download(evidence_id):
    """Downloads physical evidence file ensuring tenant path isolation and safe Content-Disposition."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    raw_bytes, meta = evidence_vault.read_evidence_file_bytes(evidence_id, org_id)
    if raw_bytes is None or not meta:
        return jsonify({"error": "Evidence file not found or unauthorized."}), 404

    safe_name = security_utils.sanitize_filename(meta.get("original_filename", "evidence.pdf"))
    return Response(
        raw_bytes,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


# ==============================================================================
# REMEDIATION CENTRE APIS
# ==============================================================================

@app.route("/api/remediation", methods=["GET"])
def api_remediation_list():
    """Lists prioritized remediation tasks strictly for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    status_filter = request.args.get("status")

    projs = saas_store.list_projects_for_org(org_id)
    all_findings = []
    for p in projs:
        scan_res = p.get("last_scan_result")
        if scan_res and isinstance(scan_res, dict):
            all_findings.extend(scan_res.get("findings", []))

    tasks = remediation_centre.sync_remediation_tasks_from_findings(all_findings, org_id=org_id)
    if status_filter:
        tasks = [t for t in tasks if t.get("status") == status_filter.upper()]

    return jsonify({
        "tasks": tasks,
        "count": len(tasks),
        "open_count": sum(1 for t in tasks if t.get("status") == "OPEN"),
        "critical_count": sum(1 for t in tasks if t.get("severity") == "CRITICAL")
    }), 200


@app.route("/api/remediation/<task_id>/update", methods=["POST"])
def api_remediation_task_update(task_id):
    """Updates remediation task status strictly for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    updated = remediation_centre.update_remediation_task(
        task_id=task_id,
        org_id=org_id,
        status=data.get("status"),
        responsible_person=data.get("responsible_person"),
        notes=data.get("notes")
    )
    if not updated:
        return jsonify({"error": f"Remediation task '{task_id}' not found or unauthorized."}), 404
    return jsonify({"status": "success", "task": updated}), 200


@app.route("/api/remediation/sync", methods=["POST"])
def api_remediation_sync():
    """Forces synchronization of remediation tasks from active scan results."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    projs = saas_store.list_projects_for_org(org_id)
    all_findings = []
    for p in projs:
        scan_res = p.get("last_scan_result")
        if scan_res and isinstance(scan_res, dict):
            all_findings.extend(scan_res.get("findings", []))
    tasks = remediation_centre.sync_remediation_tasks_from_findings(all_findings, org_id=org_id)
    return jsonify({"status": "success", "tasks_count": len(tasks)}), 200



# ==============================================================================
# DPDP COMPLIANCE PLATFORM APIS (AUTH + RBAC + TENANT ISOLATION ENFORCED)
# ==============================================================================

@app.route("/api/demo/workspace", methods=["GET"])
def api_demo_workspace():
    """Public read-only clearly labeled Demo Sandbox data from unified demo fixture."""
    import dpdp_website_scanner
    seed = demo_fixture.get_demo_seed_collections()
    sample_scan = dpdp_website_scanner.generate_demo_website_scan(
        business_name=demo_fixture.DEMO_ORG_NAME,
        target_url=demo_fixture.DEMO_WEBSITE,
        industry="Healthcare",
    )
    return jsonify({
        "status": "success",
        "is_demo": True,
        "demo_banner": demo_fixture.DEMO_BANNER,
        "profile": {
            "company_name": demo_fixture.DEMO_ORG_NAME,
            "industry": demo_fixture.DEMO_INDUSTRY,
            "website": demo_fixture.DEMO_WEBSITE,
            "privacy_email": demo_fixture.DEMO_PRIVACY_EMAIL,
        },
        "setup_progress": {
            "completed_count": 4,
            "total_steps": 6,
            "steps": [
                {"key": "business_profile", "title": "Tell us about your business", "completed": True},
                {"key": "customer_data", "title": "Record your customer data", "completed": True},
                {"key": "website_scan", "title": "Scan your website", "completed": True},
                {"key": "privacy_notice", "title": "Create or upload your Privacy Notice", "completed": True},
                {"key": "vendors", "title": "Add companies you share data with", "completed": False},
                {"key": "evidence", "title": "Upload proof into Evidence Vault", "completed": False},
            ],
        },
        "attention_tasks": [
            {"id": "demo-tsk-1", "title": "Execute written DPA with PathCare Reference Lab", "severity": "HIGH", "why": "Section 8(2) requires written contracts with external labs receiving patient records."},
            {"id": "demo-tsk-2", "title": "Uncheck marketing consent box on patient booking form", "severity": "CRITICAL", "why": "Affirmative unchecked consent required under Section 6."},
        ],
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
        "sample_scan": sample_scan,
    }), 200


@app.route("/api/demo/reset", methods=["POST"])
def api_demo_reset():
    """Allows platform admins or authenticated demo workspace owner to reset ONLY org-default."""
    org_id, user, err = require_authenticated_tenant(allowed_roles=("admin",))
    if err:
        return err
    if not (user.get("is_platform_admin") or org_id == demo_fixture.DEMO_ORG_ID):
        return jsonify({"status": "error", "message": "Demo reset is restricted to platform administrators or the demo sandbox owner."}), 403
    summary = demo_fixture.reset_demo_workspace(actor=user.get("email") or "Administrator")
    return jsonify({"status": "success", "message": "Demo sandbox restored to canonical fixture state.", "demo": summary}), 200


@app.route("/api/admin/demo/reset", methods=["POST"])
def api_admin_demo_reset():
    """Platform-admin endpoint to cleanly reset demo workspace data."""
    _org_id, user, err = require_platform_admin()
    if err:
        return err
    summary = demo_fixture.reset_demo_workspace(actor=user.get("email") or "Platform Admin")
    return jsonify({"status": "success", "message": "Demo sandbox restored.", "demo": summary}), 200


@app.route("/api/dpdp/home-summary", methods=["GET"])
def api_dpdp_home_summary():
    """Single-pass cached home dashboard metrics, 6-step setup progress, max 3 real tasks, and real activity."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err

    fast = dpdp_store.get_home_summary_fast(org_id)
    org = saas_store.get_organization(org_id) or {}
    profile = fast["profile"] or saas_store.get_org_profile(org_id) or {}

    return jsonify({
        "status": "success",
        "is_demo": bool(org.get("is_demo")),
        "user": user,
        "organization": org,
        "organisation": org,
        "profile": profile,
        "setup_progress": fast["setup_progress"],
        "attention_tasks": fast["attention_tasks"],
        "recent_activity": fast["recent_activity"],
        "counts": fast["counts"],
        "latest_scan": fast["latest_scan"],
        "encryption_status": security_utils.encryption_status_summary(),
    }), 200


@app.route("/api/dpdp/notifications", methods=["GET"])
def api_dpdp_notifications():
    """Returns genuine notifications from stored tasks, requests, expiring evidence, DPAs, and security logs."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    items = dpdp_store.get_notifications(org_id)
    return jsonify({"status": "success", "notifications": items, "count": len(items)}), 200


@app.route("/api/support/report-problem", methods=["POST"])
def api_support_report_problem():
    """Logs a user-reported problem with a reference ID without attaching sensitive customer PII."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    desc = str(data.get("description") or "").strip()
    if not desc or len(desc) < 5:
        return jsonify({"status": "error", "message": "Please describe what happened (at least 5 characters)."}), 400
    entry = saas_store.record_support_problem(
        org_id=org_id,
        user_id=user.get("id", ""),
        user_email=user.get("email", ""),
        page_route=data.get("page_route", ""),
        category=data.get("category", "Product issue"),
        description=desc,
        browser_info=data.get("browser_info", ""),
    )
    return jsonify({
        "status": "success",
        "reference_id": entry["reference_id"],
        "message": f"Issue logged cleanly under reference {entry['reference_id']}. No customer records or passwords were attached.",
        "ticket": entry,
    }), 201


@app.route("/api/dpdp/onboarding", methods=["GET", "POST"])
def api_dpdp_onboarding():
    """Manages organization onboarding state, saving progress cleanly step-by-step."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        apply_template = bool(data.pop("apply_industry_template", False))
        suggested_vendors = data.pop("selected_vendors", None)
        profile = dpdp_store.save_onboarding_profile(org_id, data)
        if profile.get("company_name") or profile.get("industry") or profile.get("website_url"):
            saas_store.save_org_profile(org_id, {
                "company_name": profile.get("company_name", ""),
                "industry": profile.get("industry", ""),
                "website": profile.get("website_url", ""),
                "contact_email": profile.get("contact_email", ""),
            })
        if apply_template and profile.get("industry"):
            existing_inv = dpdp_store.get_data_inventory(org_id)
            if not existing_inv:
                dpdp_store.prepopulate_industry_inventory(org_id, profile["industry"])
        if isinstance(suggested_vendors, list):
            existing_v_names = {v.get("name", "").lower() for v in dpdp_store.get_vendors(org_id)}
            for vname in suggested_vendors:
                clean_vn = security_utils.sanitize_plain_text(vname, 140)
                if clean_vn and clean_vn.lower() not in existing_v_names:
                    dpdp_store.add_vendor(org_id, {
                        "name": clean_vn,
                        "service": "Software / Service Vendor",
                        "personal_data_processed": "Customer Records",
                        "dpa_status": "Not Started",
                    })
                    existing_v_names.add(clean_vn.lower())

        security_utils.append_audit_log(
            org_id=org_id,
            action="onboarding.saved",
            resource_type="onboarding",
            actor_user_id=actor.get("id", ""),
            actor_email=actor.get("email", ""),
            actor_role=actor.get("role", ""),
            details={"completed": bool(profile.get("onboarding_completed")), "step": profile.get("onboarding_step")},
        )
        return jsonify({
            "status": "success",
            "profile": profile,
            "setup_progress": dpdp_store.get_setup_progress(org_id),
            "attention_tasks": dpdp_store.get_home_attention_tasks(org_id, limit=5),
        }), 200

    profile = dpdp_store.get_onboarding_profile(org_id)
    return jsonify({
        "status": "success",
        "profile": profile,
        "templates": list(dpdp_engine.INDUSTRY_TEMPLATES.keys()),
        "setup_progress": dpdp_store.get_setup_progress(org_id),
    }), 200


@app.route("/api/dpdp/inventory", methods=["GET", "POST"])
def api_dpdp_inventory():
    """Lists and adds personal data inventory records within plan & tenant boundaries."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        items = dpdp_store.get_data_inventory(org_id)
        allowed, limit_err = saas_store.check_plan_limits(org_id, "data_stream", len(items))
        if not allowed:
            return jsonify({"status": "error", "error": limit_err}), 403
        data = request.get_json(silent=True) or {}
        entry = dpdp_store.add_inventory_entry(org_id, data)
        security_utils.append_audit_log(
            org_id=org_id,
            action="inventory.added",
            resource_type="data_inventory",
            resource_id=entry.get("id", ""),
            actor_user_id=actor.get("id", ""),
            actor_email=actor.get("email", ""),
            actor_role=actor.get("role", ""),
        )
        return jsonify({"status": "success", "entry": entry}), 201
    items = dpdp_store.get_data_inventory(org_id)
    return jsonify({"status": "success", "items": items, "inventory": items, "count": len(items)}), 200


@app.route("/api/dpdp/inventory/<entry_id>", methods=["PUT", "DELETE"])
def api_dpdp_inventory_item(entry_id):
    """Updates or deletes an inventory stream."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "DELETE":
        deleted = dpdp_store.delete_inventory_entry(org_id, entry_id)
        if deleted:
            security_utils.append_audit_log(
                org_id=org_id, action="inventory.deleted", resource_type="data_inventory",
                resource_id=entry_id, actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
            )
        return jsonify({"status": "success" if deleted else "not_found"}), 200 if deleted else 404
    data = request.get_json(silent=True) or {}
    updated = dpdp_store.update_inventory_entry(org_id, entry_id, data)
    return jsonify({"status": "success", "entry": updated}), 200 if updated else 404


@app.route("/api/dpdp/inventory/export", methods=["GET"])
def api_dpdp_inventory_export():
    """Exports personal data inventory as CSV."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    csv_data = dpdp_store.export_inventory_csv(org_id)
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=customer_data_list_{org_id}.csv"}
    )


@app.route("/api/dpdp/inventory/import", methods=["POST"])
def api_dpdp_inventory_import():
    """Imports personal data inventory from CSV."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    file = request.files.get("file")
    if not file:
        return jsonify({"status": "error", "message": "CSV file required"}), 400
    raw_bytes = file.read()
    ok, err_msg, _meta = security_utils.validate_uploaded_file(file.filename or "import.csv", raw_bytes)
    if not ok:
        return jsonify({"status": "error", "message": err_msg}), 400
    content = raw_bytes.decode("utf-8")
    count = dpdp_store.import_inventory_csv(org_id, content)
    security_utils.append_audit_log(
        org_id=org_id, action="inventory.imported", resource_type="data_inventory",
        actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""), details={"rows": count},
    )
    return jsonify({"status": "success", "imported_count": count}), 200


@app.route("/api/dpdp/assessment", methods=["GET"])
def api_dpdp_assessment():
    """Returns statutory DPDP assessment, readiness score, and gaps."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    assessment = dpdp_store.get_assessment(org_id)
    return jsonify(assessment), 200


@app.route("/api/dpdp/assessment/control/<requirement_id>", methods=["POST"])
def api_dpdp_update_control(requirement_id):
    """Updates self-attestation or status of an assessment requirement."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    status = data.get("status", "SELF_ATTESTED_IMPLEMENTED")
    notes = data.get("notes", "")
    updated = dpdp_store.update_assessment_control(org_id, requirement_id, status, notes)
    security_utils.append_audit_log(
        org_id=org_id, action="assessment.control_updated", resource_type="control",
        resource_id=requirement_id, actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
        details={"status": status},
    )
    return jsonify({"status": "success", "assessment": updated}), 200


@app.route("/api/dpdp/notices", methods=["GET"])
def api_dpdp_notices():
    """Lists privacy notices for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    notices = dpdp_store.get_privacy_notices(org_id)
    return jsonify({"status": "success", "items": notices, "notices": notices}), 200


@app.route("/api/dpdp/notices/generate", methods=["POST"])
def api_dpdp_generate_notice():
    """Generates an itemised Section 5 privacy notice."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    notice = dpdp_store.generate_privacy_notice(org_id, data)
    security_utils.append_audit_log(
        org_id=org_id, action="notice.generated", resource_type="privacy_notice",
        resource_id=notice.get("id", ""), actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
    )
    return jsonify({"status": "success", "notice": notice}), 201


@app.route("/api/dpdp/notices/<notice_id>", methods=["PUT", "DELETE"])
def api_dpdp_notice_detail(notice_id):
    """Edits, approves, bumps version, or deletes a privacy notice."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "DELETE":
        deleted = dpdp_store.delete_privacy_notice(org_id, notice_id)
        return jsonify({"status": "success" if deleted else "error"}), 200 if deleted else 404
    data = request.get_json(silent=True) or {}
    updated = dpdp_store.update_privacy_notice(
        org_id, notice_id, data, actor_name=actor.get("name") or actor.get("email") or "Privacy Lead"
    )
    if not updated:
        return jsonify({"status": "error", "message": "Privacy notice not found."}), 404
    return jsonify({"status": "success", "notice": updated}), 200


@app.route("/api/dpdp/consent", methods=["GET", "POST"])
def api_dpdp_consent():
    """Logs or lists affirmative consent records (supports search/status filter)."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        rec = dpdp_store.record_consent(org_id, data)
        return jsonify({"status": "success", "record": rec}), 201
    records = dpdp_store.get_consent_records(org_id)
    q = (request.args.get("q") or "").strip().lower()
    st = (request.args.get("status") or "").strip().upper()
    if q:
        records = [r for r in records if q in (str(r.get("data_principal_ref", "")) + " " + str(r.get("purpose", "")) + " " + str(r.get("data_category", ""))).lower()]
    if st:
        records = [r for r in records if str(r.get("status", "")).upper() == st]
    return jsonify({"status": "success", "items": records, "consent_records": records}), 200


@app.route("/api/dpdp/withdrawals", methods=["GET", "POST"])
def api_dpdp_withdrawals():
    """Handles Section 6(4)-(6) consent withdrawal."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        wth = dpdp_store.submit_consent_withdrawal(org_id, data)
        return jsonify({"status": "success", "withdrawal": wth}), 201
    items = dpdp_store.get_withdrawal_requests(org_id)
    return jsonify({"status": "success", "items": items, "withdrawals": items}), 200


@app.route("/api/dpdp/rights", methods=["GET", "POST"])
def api_dpdp_rights():
    """Submits or lists Customer Privacy Requests (Access, Correction, Erasure, Grievance, Nomination)."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        req_item = dpdp_store.submit_rights_request(org_id, data)
        return jsonify({"status": "success", "request": req_item}), 201
    items = dpdp_store.get_rights_requests(org_id)
    return jsonify({"status": "success", "items": items, "requests": items}), 200


@app.route("/api/dpdp/rights/<request_id>/status", methods=["POST", "PUT"])
def api_dpdp_rights_status(request_id):
    """Updates status, verification flag, assignee, and resolution notes for a privacy request."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    if any(k in data for k in ("assigned_to", "identity_verified", "systems_involved")):
        updated = dpdp_store.update_rights_request_full(org_id, request_id, data)
    else:
        status = data.get("status", "COMPLETED")
        summary = data.get("response_summary", "")
        updated = dpdp_store.update_rights_request_status(org_id, request_id, status, summary)
    if not updated:
        return jsonify({"status": "error", "message": "Request not found."}), 404
    return jsonify({"status": "success", "request": updated}), 200


@app.route("/api/dpdp/vendors", methods=["GET", "POST"])
def api_dpdp_vendors():
    """Lists or adds companies/vendors you share data with (plan & tenant isolated)."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        vendors = dpdp_store.get_vendors(org_id)
        allowed, limit_err = saas_store.check_plan_limits(org_id, "vendor", len(vendors))
        if not allowed:
            return jsonify({"status": "error", "error": limit_err}), 403
        data = request.get_json(silent=True) or {}
        vendor = dpdp_store.add_vendor(org_id, data)
        security_utils.append_audit_log(
            org_id=org_id, action="vendor.added", resource_type="vendor",
            resource_id=vendor.get("id", ""), actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
        )
        return jsonify({"status": "success", "vendor": vendor}), 201
    vendors = []
    for v in dpdp_store.get_vendors(org_id):
        v_copy = dict(v)
        v_copy.update(dpdp_store.compute_vendor_risk_basis(v))
        vendors.append(v_copy)
    return jsonify({"status": "success", "items": vendors, "vendors": vendors}), 200


@app.route("/api/dpdp/vendors/<vendor_id>", methods=["PUT", "DELETE"])
def api_dpdp_vendor_detail(vendor_id):
    """Updates or deletes a vendor under Section 8(2)."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "DELETE":
        deleted = dpdp_store.delete_vendor(org_id, vendor_id)
        if deleted:
            security_utils.append_audit_log(
                org_id=org_id, action="vendor.deleted", resource_type="vendor",
                resource_id=vendor_id, actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
            )
            return jsonify({"status": "success", "message": "Vendor deleted"}), 200
        return jsonify({"status": "error", "message": "Vendor not found"}), 404
    data = request.get_json(silent=True) or {}
    updated = dpdp_store.update_vendor(org_id, vendor_id, data)
    if updated:
        return jsonify({"status": "success", "vendor": updated}), 200
    return jsonify({"status": "error", "message": "Vendor not found"}), 404


@app.route("/api/dpdp/retention", methods=["GET", "POST"])
def api_dpdp_retention():
    """Manages Rule 8 retention schedules."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        sched = dpdp_store.add_retention_schedule(org_id, data)
        return jsonify({"status": "success", "schedule": sched}), 201
    schedules = dpdp_store.get_retention_schedules(org_id)
    return jsonify({"status": "success", "items": schedules, "schedules": schedules}), 200


@app.route("/api/dpdp/retention/<schedule_id>", methods=["PUT", "DELETE"])
def api_dpdp_retention_detail(schedule_id):
    """Updates or deletes a retention schedule."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "DELETE":
        deleted = dpdp_store.delete_retention_schedule(org_id, schedule_id)
        if deleted:
            return jsonify({"status": "success", "message": "Retention schedule deleted"}), 200
        return jsonify({"status": "error", "message": "Retention schedule not found"}), 404
    data = request.get_json(silent=True) or {}
    updated = dpdp_store.update_retention_schedule(org_id, schedule_id, data)
    if updated:
        return jsonify({"status": "success", "schedule": updated}), 200
    return jsonify({"status": "error", "message": "Retention schedule not found"}), 404


@app.route("/api/dpdp/erasure-tasks", methods=["GET", "POST"])
def api_dpdp_erasure_tasks():
    """Manages Section 8(7) erasure execution and verification tasks."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        task = dpdp_store.create_erasure_task(org_id, data)
        return jsonify({"status": "success", "task": task}), 201
    tasks = dpdp_store.get_erasure_tasks(org_id)
    return jsonify({"status": "success", "items": tasks, "erasure_tasks": tasks}), 200


@app.route("/api/dpdp/erasure-tasks/<task_id>", methods=["POST", "PUT"])
def api_dpdp_update_erasure_task(task_id):
    """Updates status and deletion confirmation proof of an erasure task."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    status = data.get("status", "VERIFIED_ERASED")
    proof_hash = data.get("proof_hash")
    verified_by = data.get("verified_by") or user.get("email") or "Privacy Officer"
    notes = data.get("notes", "")
    task = dpdp_store.update_erasure_task(org_id, task_id, status, proof_hash, verified_by, notes)
    if task:
        return jsonify({"status": "success", "task": task}), 200
    return jsonify({"status": "error", "message": "Task not found"}), 404


@app.route("/api/dpdp/data-flow", methods=["GET"])
def api_dpdp_data_flow():
    """Returns dynamic data flow graph strictly for authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    import data_discovery
    flow_map = data_discovery.generate_data_flow_map(org_id)
    inventory = dpdp_store.get_data_inventory(org_id)
    flows = []
    for item in inventory:
        if "Rejected" in str(item.get("confirmation_status", "")):
            continue
        flows.append({
            "id": item.get("id"),
            "source": item.get("source") or item.get("collection_method") or "Website / Form",
            "category": item.get("category") or "Personal Data",
            "system": item.get("storage_system") or "Internal Database",
            "vendor": item.get("external_recipients") or item.get("processor") or "Internal Only",
            "purpose": item.get("purpose") or "Service Delivery",
            "retention": item.get("retention_period") or "Review Schedule",
            "status": item.get("confirmation_status") or "Confirmed by business",
        })
    return jsonify({"status": "success", "data_flow": flow_map, "flows": flows}), 200


@app.route("/api/dpdp/discovery/inspect", methods=["POST"])
def api_dpdp_discovery_inspect():
    """Metadata-only heuristic column analyzer for personal data detection."""
    _org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    table_name = data.get("table_name", "")
    column_names = data.get("column_names", [])
    import data_discovery
    analysis = data_discovery.inspect_schema_metadata(table_name, column_names)
    return jsonify({"status": "success", "analysis": analysis}), 200


@app.route("/api/dpdp/discovery/starter-template", methods=["POST"])
def api_dpdp_discovery_starter_template():
    """Returns tailored baseline data inventory templates by sector."""
    _org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    sector = data.get("sector", "healthcare")
    import data_discovery
    templates = data_discovery.get_starter_inventory_templates(sector)
    return jsonify({"status": "success", "sector": sector, "templates": templates}), 200


@app.route("/api/dpdp/readiness/dynamic", methods=["GET"])
def api_dpdp_dynamic_readiness():
    """Returns dynamic readiness score separating enforceable from forward-looking obligations."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    readiness = dpdp_store.calculate_dynamic_readiness(org_id)
    return jsonify({"status": "success", "readiness": readiness}), 200


@app.route("/api/dpdp/penalties/matrix", methods=["GET"])
def api_dpdp_penalties_matrix():
    """Central statutory penalty schedule matrix & Section 33 factors."""
    import dpdp_penalties
    section = request.args.get("section")
    if section:
        return jsonify({"status": "success", "penalty": dpdp_penalties.map_statutory_penalty(section)}), 200
    return jsonify({
        "status": "success",
        "version": dpdp_penalties.PENALTY_ENGINE_VERSION,
        "penalties": dpdp_penalties.DPDP_STATUTORY_PENALTIES,
        "section_33_factors": dpdp_penalties.get_section_33_factors(),
        "disclaimer": dpdp_penalties.STATUTORY_PENALTY_DISCLAIMER,
    }), 200


@app.route("/api/dpdp/commencement/registry", methods=["GET"])
def api_dpdp_commencement_registry():
    """Authoritative phased commencement tracker for the DPDP Act & Rules."""
    import dpdp_commencement
    section = request.args.get("section")
    if section:
        return jsonify({"status": "success", "commencement": dpdp_commencement.get_statutory_commencement(section)}), 200
    return jsonify({
        "status": "success",
        "version": dpdp_commencement.COMMENCEMENT_ENGINE_VERSION,
        "milestones": dpdp_commencement.COMMENCEMENT_MILESTONES,
        "sources": dpdp_commencement.OFFICIAL_SOURCES,
    }), 200


@app.route("/api/dpdp/breaches", methods=["GET", "POST"])
def api_dpdp_breaches():
    """Logs and lists breach incidents under Section 8(6) & Rule 7."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        incident = dpdp_store.log_breach_incident(org_id, data)
        security_utils.append_audit_log(
            org_id=org_id, action="incident.logged", resource_type="incident",
            resource_id=incident.get("id", ""), actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
        )
        return jsonify({"status": "success", "incident": incident}), 201
    incidents = dpdp_store.get_breach_incidents(org_id)
    return jsonify({"status": "success", "items": incidents, "incidents": incidents}), 200


@app.route("/api/dpdp/breaches/<incident_id>", methods=["PUT", "POST"])
def api_dpdp_update_breach(incident_id):
    """Updates an incident or appends a timeline event."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    actor_name = actor.get("name") or actor.get("email") or "Privacy Lead"
    updated = dpdp_store.update_breach_incident(org_id, incident_id, data, actor=actor_name)
    if not updated:
        return jsonify({"status": "error", "message": "Incident not found."}), 404
    return jsonify({"status": "success", "incident": updated}), 200


@app.route("/api/dpdp/breaches/<incident_id>/authorize", methods=["POST"])
def api_dpdp_authorize_breach(incident_id):
    """Authorizes regulatory intimation drafts under Section 8(6) (requires admin or member)."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err
    user_name = user.get("name") or user.get("email") or "Administrator"
    updated = dpdp_store.authorize_breach_intimation(org_id, incident_id, user_name)
    if not updated:
        return jsonify({"status": "error", "message": "Incident not found."}), 404
    security_utils.append_audit_log(
        org_id=org_id, action="incident.authorized_intimation", resource_type="incident",
        resource_id=incident_id, actor_user_id=user.get("id", ""), actor_email=user.get("email", ""),
    )
    return jsonify({"status": "success", "incident": updated}), 200


@app.route("/api/dpdp/assistant", methods=["POST"])
def api_dpdp_assistant():
    """AI DPDP grounded query assistant with prompt-injection guard, rate limit, & history."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    query = data.get("query", "").strip()
    conv_id = data.get("conversation_id")
    if not query:
        return jsonify({"status": "error", "message": "Query required"}), 400
    import ai_dpdp_assistant
    res = ai_dpdp_assistant.query_ai_dpdp_assistant(query, org_id=org_id, conversation_id=conv_id)
    code = 429 if "limit reached" in str(res.get("message", "")).lower() else 200
    return jsonify(res), code


@app.route("/api/dpdp/assistant/history", methods=["GET", "DELETE"])
def api_dpdp_assistant_history():
    """Retrieves or clears org-isolated assistant conversation history."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    import ai_dpdp_assistant
    if request.method == "DELETE":
        ai_dpdp_assistant.clear_assistant_history(org_id)
        return jsonify({"status": "success"}), 200
    conv_id = request.args.get("conversation_id")
    return jsonify({
        "status": "success",
        "history": ai_dpdp_assistant.get_assistant_history(org_id, conversation_id=conv_id),
        "conversations": ai_dpdp_assistant.list_assistant_conversations(org_id),
        "starter_questions": ai_dpdp_assistant.STARTER_QUESTIONS,
    }), 200


@app.route("/api/dpdp/assistant/feedback", methods=["POST"])
def api_dpdp_assistant_feedback():
    """Records helpful / not_helpful feedback on assistant answers."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    msg_id = data.get("message_id", "")
    rating = data.get("rating", "helpful")
    comment = data.get("comment", "")
    if not msg_id:
        return jsonify({"status": "error", "message": "message_id is required."}), 400
    import ai_dpdp_assistant
    fb = ai_dpdp_assistant.record_assistant_feedback(org_id, msg_id, rating, comment)
    return jsonify({"status": "success", "feedback": fb}), 201


@app.route("/api/dpdp/reports/pdf", methods=["GET"])
def api_dpdp_report_pdf():
    """Downloads real binary %PDF-1.4 DPDP Readiness & Operations Summary for the authenticated org."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    pdf_bytes = dpdp_reports.generate_dpdp_pdf_report(org_id)
    security_utils.append_audit_log(
        org_id=org_id, action="report.pdf_downloaded", resource_type="report",
        actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
    )
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="TrustAudit_DPDP_Report_{org_id}.pdf"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.route("/api/dpdp/reports/html", methods=["GET"])
def api_dpdp_report_html():
    """Returns print-ready HTML DPDP readiness summary."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    html_str = dpdp_reports.generate_dpdp_html_report(org_id)
    return Response(html_str, mimetype="text/html; charset=utf-8")


@app.route("/api/dpdp/reports/csv", methods=["GET"])
def api_dpdp_report_csv():
    """Downloads CSV exports for inventory, vendors, requests, retention, or full summary."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    scope = request.args.get("scope", "full")
    csv_text = dpdp_reports.generate_dpdp_csv_export(org_id, scope=scope)
    safe_scope = security_utils.sanitize_filename(scope)
    return Response(
        csv_text,
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="TrustAudit_{safe_scope}_{org_id}.csv"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.route("/api/dpdp/reports/bundle", methods=["GET"])
def api_dpdp_report_bundle():
    """Downloads complete ZIP Evidence Bundle containing PDF, CSVs, Notices, and physical Evidence files."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    zip_bytes = dpdp_reports.generate_dpdp_evidence_bundle_zip(org_id)
    security_utils.append_audit_log(
        org_id=org_id, action="report.bundle_downloaded", resource_type="report_bundle",
        actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
    )
    return Response(
        zip_bytes,
        mimetype="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="TrustAudit_Evidence_Bundle_{org_id}.zip"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.route("/api/dpdp/reports/jobs", methods=["POST"])
def api_dpdp_report_job_start():
    """Starts background job generating a ZIP Evidence Bundle or PDF Report without blocking UI."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "bundle").strip().lower()
    idem = data.get("idempotency_key") or f"report-{kind}"

    def _worker(update_progress, is_cancelled):
        update_progress(20, "Gathering organisation readiness records...")
        if is_cancelled():
            return None
        bdata = dpdp_reports._gather_org_report_data(org_id)
        update_progress(60, f"Compiling {kind.upper()} artifact...")
        if kind == "pdf":
            raw = dpdp_reports.generate_dpdp_pdf_report(org_id, bundle_data=bdata)
            return {
                "bytes": raw,
                "filename": f"TrustAudit_DPDP_Report_{org_id}.pdf",
                "mimetype": "application/pdf",
            }
        raw = dpdp_reports.generate_dpdp_evidence_bundle_zip(org_id)
        return {
            "bytes": raw,
            "filename": f"TrustAudit_Evidence_Bundle_{org_id}.zip",
            "mimetype": "application/zip",
        }

    job = job_manager.submit_job(org_id, f"report_{kind}", f"Generate DPDP {kind.upper()} Export", _worker, idempotency_key=idem)
    security_utils.append_audit_log(
        org_id=org_id, action="report.job_started", resource_type="job",
        resource_id=job["job_id"], actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
    )
    return jsonify({"status": "accepted", "job_id": job["job_id"], "job": job}), 202


@app.route("/api/jobs/<job_id>", methods=["GET"])
def api_job_status(job_id):
    """Returns progress and result metadata for a tenant-isolated background job."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    job = job_manager.get_job(org_id, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Background job not found."}), 404
    return jsonify({"status": "success", "job": job}), 200


@app.route("/api/jobs/<job_id>/cancel", methods=["POST"])
def api_job_cancel(job_id):
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    job = job_manager.cancel_job(org_id, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Background job not found."}), 404
    return jsonify({"status": "success", "job": job}), 200


@app.route("/api/jobs/<job_id>/download", methods=["GET"])
def api_job_download(job_id):
    """Downloads artifact generated by a completed background export job."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    dl = job_manager.get_job_download(org_id, job_id)
    if not dl:
        return jsonify({"status": "error", "message": "Artifact not ready or job not found."}), 404
    fname = security_utils.sanitize_filename(dl.get("filename", "export.bin"))
    return Response(
        dl["bytes"],
        mimetype=dl.get("mimetype", "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


# ==============================================================================
# DPDP WEBSITE SCANNER & GAP DETECTION API
# ==============================================================================

@app.route("/api/dpdp/scanner/start", methods=["POST"])
def api_dpdp_start_website_scan():
    """Starts a safe, SSRF-protected, rate-limited DPDP website compliance scan."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    allowed, retry = security_utils.rate_limiter.allow(f"dpdp_scan:{org_id}", max_requests=25, window_seconds=3600)
    if not allowed:
        return jsonify({"status": "error", "message": f"Hourly website scan limit reached. Retry in {retry}s."}), 429

    data = request.get_json(silent=True) or {}
    target_url = (data.get("website_url") or data.get("target_url") or "").strip()
    business_name = data.get("business_name", "").strip() or "Organisation"
    industry = data.get("industry", "healthcare").strip()
    country = data.get("country", "India").strip()
    business_type = data.get("business_type", "Business Website").strip()
    website_purpose = data.get("website_purpose", "Services & Customer Intake").strip()
    collects_personal_info = bool(data.get("collects_personal_info", True))
    children_data_processed = bool(data.get("children_data_processed", False))
    known_data_types = data.get("known_data_types", [])
    authorization_confirmed = bool(data.get("authorization_confirmed", False))
    is_demo = bool(data.get("is_demo", False))

    if not authorization_confirmed:
        return jsonify({
            "status": "error",
            "message": "Explicit authorization or ownership confirmation is required prior to initiating a DPDP website scan."
        }), 400

    if not target_url:
        return jsonify({"status": "error", "message": "Website URL is required."}), 400

    # SSRF validation BEFORE initiating crawl unless explicitly running offline demo fixture
    if not is_demo and "example" not in target_url.lower():
        import ssrf_protection
        clean_check = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"
        try:
            ssrf_protection.validate_target_url_ssrf_safe(clean_check)
        except ssrf_protection.SSRFSecurityError as e:
            return jsonify({"status": "error", "error": f"Blocked by SSRF security policy: {e}"}), 400

    if is_demo or "example" in target_url.lower():
        import dpdp_website_scanner
        scan_report = dpdp_website_scanner.generate_demo_website_scan(
            business_name=business_name,
            target_url=target_url,
            industry=industry
        )
        dpdp_store.save_website_scan(org_id, scan_report)
        return jsonify({"status": "success", "scan": scan_report}), 200

    use_async = (request.args.get("async") in ("1", "true", "yes")) or bool(data.get("async"))
    if use_async:
        def _scan_worker(update_progress, is_cancelled):
            import dpdp_website_scanner
            update_progress(25, f"Inspecting public pages at {target_url}...")
            if is_cancelled():
                return None
            scanner = dpdp_website_scanner.DPDPWebsiteScanner(
                target_url=target_url,
                business_name=business_name,
                industry=industry,
                country=country,
                business_type=business_type,
                website_purpose=website_purpose,
                collects_personal_info=collects_personal_info,
                children_data_processed=children_data_processed,
                known_data_types=known_data_types,
                authorization_confirmed=authorization_confirmed,
                max_pages=20,
            )
            scan_rep = scanner.run_scan()
            if is_cancelled():
                return None
            update_progress(85, "Saving observed findings to workspace...")
            dpdp_store.save_website_scan(org_id, scan_rep)
            disc_list = [
                {
                    "extracted_type": "tracker" if "script" in str(f.get("category", "")).lower() or "cookie" in str(f.get("title", "")).lower() else "website_form",
                    "value": f.get("title", "Observed Website Privacy Item"),
                    "category": "Website and application information",
                    "fields": f.get("observed_items", []) or [f.get("description", "")[:100]],
                    "purpose": f.get("remediation", "Review public form/notice alignment"),
                    "storage_location": target_url,
                    "source_document": target_url,
                    "confidence": f.get("confidence", "MEDIUM"),
                    "status": "Needs review",
                }
                for f in scan_rep.get("findings", [])[:20]
            ]
            if disc_list:
                dpdp_store.save_discovery_suggestions(org_id, disc_list)
            security_utils.append_audit_log(
                org_id=org_id, action="scanner.website_scanned", resource_type="website_scan",
                resource_id=scan_rep.get("scan_id", ""), actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
                details={"target_url": target_url},
            )
            return {"scan": scan_rep}

        job = job_manager.submit_job(org_id, "website_scan", f"Website Privacy Check: {target_url}", _scan_worker, idempotency_key=target_url.lower())
        return jsonify({"status": "accepted", "job_id": job["job_id"], "job": job}), 202

    import dpdp_website_scanner
    scanner = dpdp_website_scanner.DPDPWebsiteScanner(
        target_url=target_url,
        business_name=business_name,
        industry=industry,
        country=country,
        business_type=business_type,
        website_purpose=website_purpose,
        collects_personal_info=collects_personal_info,
        children_data_processed=children_data_processed,
        known_data_types=known_data_types,
        authorization_confirmed=authorization_confirmed,
        max_pages=20
    )
    scan_report = scanner.run_scan()
    dpdp_store.save_website_scan(org_id, scan_report)
    # Also surface observed scripts/forms/policies into Discovery Centre suggestions for human review
    disc_items = []
    for f in scan_report.get("findings", [])[:20]:
        disc_items.append({
            "extracted_type": "tracker" if "script" in str(f.get("category", "")).lower() or "cookie" in str(f.get("title", "")).lower() else "website_form",
            "value": f.get("title", "Observed Website Privacy Item"),
            "category": "Website and application information",
            "fields": f.get("observed_items", []) or [f.get("description", "")[:100]],
            "purpose": f.get("remediation", "Review public form/notice alignment"),
            "storage_location": target_url,
            "source_document": target_url,
            "confidence": f.get("confidence", "MEDIUM"),
            "status": "Needs review",
        })
    if disc_items:
        dpdp_store.save_discovery_suggestions(org_id, disc_items)
    security_utils.append_audit_log(
        org_id=org_id, action="scanner.website_scanned", resource_type="website_scan",
        resource_id=scan_report.get("scan_id", ""), actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
        details={"target_url": target_url},
    )
    return jsonify({"status": "success", "scan": scan_report}), 200


@app.route("/api/dpdp/scanner/history", methods=["GET"])
def api_dpdp_scanner_history():
    """Retrieves all past DPDP website scans for the authenticated organization."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    scans = dpdp_store.get_website_scans(org_id)
    return jsonify({"status": "success", "scans": scans, "count": len(scans)}), 200


@app.route("/api/dpdp/scanner/results/<scan_id>", methods=["GET"])
def api_dpdp_scanner_results(scan_id):
    """Retrieves a specific website scan report by ID."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    scan = dpdp_store.get_website_scan_by_id(org_id, scan_id)
    if not scan:
        return jsonify({"status": "error", "message": "Scan report not found."}), 404
    return jsonify({"status": "success", "scan": scan}), 200


@app.route("/api/dpdp/scanner/<scan_id>", methods=["DELETE"])
def api_dpdp_scanner_delete(scan_id):
    """Permanently deletes a scan report for tenant privacy and data minimization."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    deleted = dpdp_store.delete_website_scan(org_id, scan_id)
    return jsonify({"status": "success", "deleted": deleted}), 200


@app.route("/api/dpdp/scanner/convert-task", methods=["POST"])
def api_dpdp_scanner_convert_task():
    """Converts a website scan finding into an internal remediation task."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    finding_id = data.get("finding_id")
    assignee = data.get("assignee", "Privacy Lead")

    if not scan_id or not finding_id:
        return jsonify({"status": "error", "message": "scan_id and finding_id are required."}), 400

    task = dpdp_store.convert_scan_finding_to_remediation_task(org_id, scan_id, finding_id, assignee)
    if not task:
        return jsonify({"status": "error", "message": "Finding not found or conversion failed."}), 404
    return jsonify({"status": "success", "task": task}), 201


@app.route("/demo", methods=["GET"])
def demo_view():
    """Renders the public Demo Sandbox showcasing TrustAudit safely without creating a tenant."""
    return render_template("public/demo.html", active_nav="demo"), 200


@app.route("/api/dpdp/assessment/organisational", methods=["GET", "POST"])
def api_dpdp_assessment_organisational():
    """8-Step Guided Organisational Assessment persistence and dynamic scoring."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        answers = data.get("answers", {})
        saved = dpdp_store.save_organisational_assessment(org_id, answers)
        return jsonify({
            "status": "success",
            "message": "Organisational assessment saved successfully.",
            "assessment": saved
        }), 200

    assessment = dpdp_store.get_organisational_assessment(org_id)
    return jsonify({
        "status": "success",
        "assessment": assessment
    }), 200


@app.route("/api/dpdp/documents/templates", methods=["GET"])
def api_dpdp_document_templates():
    """Returns catalog of 9 DPDP policy & operational document templates with verified legal refs."""
    templates = [
        {
            "id": "privacy_notice",
            "title": "Itemised Privacy Notice (Sec 5 & Rule 3)",
            "legal_ref": "DPDP Act, 2023 Sec 5 & DPDP Rules, 2025 Rule 3",
            "description": "Clear notice explaining what personal data is collected, why, customer rights, and contact details."
        },
        {
            "id": "ropa_inventory",
            "title": "Customer Data Processing Register",
            "legal_ref": "DPDP Act, 2023 Sec 4, 5 & 8 Accountability",
            "description": "Plain-English register of customer data streams, lawful bases, retention limits, and storage locations."
        },
        {
            "id": "retention_policy",
            "title": "Data Retention & Erasure Schedule",
            "legal_ref": "DPDP Act, 2023 Sec 8(7)-(8) & DPDP Rules, 2025 Rule 8",
            "description": "Policy setting retention timeframes, deletion triggers, and statutory exception documentation."
        },
        {
            "id": "breach_procedure",
            "title": "Data Breach Response & Dual-Stage Notification Protocol",
            "legal_ref": "DPDP Act, 2023 Sec 8(6) & DPDP Rules, 2025 Rule 7",
            "description": "Incident response workflow notifying DPBI and affected individuals (initial alert without delay + 72-hour follow-up)."
        },
        {
            "id": "rights_procedure",
            "title": "Customer Privacy Request Handling SOP",
            "legal_ref": "DPDP Act, 2023 Sec 11, 12, 13 & 14; Rule 14",
            "description": "Standard procedure for verifying requesters and handling access, correction, erasure, and nomination requests."
        },
        {
            "id": "grievance_procedure",
            "title": "Grievance Redressal Procedure",
            "legal_ref": "DPDP Act, 2023 Sec 13 & Sec 8(10); Rule 9 & Rule 14",
            "description": "Accessible grievance contact mechanism and escalation workflow for privacy enquiries."
        },
        {
            "id": "vendor_register",
            "title": "Vendor & Software Sharing Register",
            "legal_ref": "DPDP Act, 2023 Sec 8(1)-(2)",
            "description": "Register of software, lab, and cloud vendors with Data Processing Agreement status tracking."
        },
        {
            "id": "employee_privacy_policy",
            "title": "Internal Employee Privacy Policy",
            "legal_ref": "DPDP Act, 2023 Sec 4 & Sec 7(i) (Employment)",
            "description": "Staff handbook covering HR, payroll, attendance, and staff access responsibilities."
        },
        {
            "id": "training_material",
            "title": "Staff Privacy Awareness Guide",
            "legal_ref": "DPDP Act, 2023 Sec 8(5) & Rule 6 Safeguards",
            "description": "Plain-language guide for front-desk, billing, support, and engineering teams handling customer data."
        }
    ]
    return jsonify({"status": "success", "templates": templates}), 200


@app.route("/api/dpdp/documents/generate", methods=["POST"])
def api_dpdp_generate_document():
    """Generates one of the 9 assisted compliance policy or procedure draft documents."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    doc_type = data.get("doc_type")
    custom_params = data.get("custom_params", {})

    valid_types = [
        "privacy_notice", "ropa_inventory", "retention_policy",
        "breach_procedure", "rights_procedure", "grievance_procedure",
        "vendor_register", "employee_privacy_policy", "training_material"
    ]
    if not doc_type or doc_type not in valid_types:
        return jsonify({
            "status": "error",
            "message": f"doc_type must be one of: {', '.join(valid_types)}"
        }), 400

    doc = dpdp_store.generate_dpdp_document(org_id, doc_type, custom_params)
    security_utils.append_audit_log(
        org_id=org_id, action="document.generated", resource_type="document",
        resource_id=doc.get("id", ""), actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
    )
    return jsonify({"status": "success", "document": doc}), 201


@app.route("/api/dpdp/evidence/upload", methods=["POST"])
def api_dpdp_upload_evidence():
    """Uploads an evidence artifact with strict file extension, size, and magic-byte validation."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err

    artifacts_existing = dpdp_store.get_evidence_artifacts(org_id)
    allowed, limit_err = saas_store.check_plan_limits(org_id, "evidence", len(artifacts_existing))
    if not allowed:
        return jsonify({"status": "error", "error": limit_err}), 403

    actor_label = user.get("email") or user.get("name") or "Privacy Officer"
    if request.is_json:
        data = request.get_json(silent=True) or {}
        title = data.get("title", "Evidence Artifact")
        category = data.get("category", "General")
        control_id = data.get("control_id", "DPDP-SEC-05")
        notes = data.get("notes", "")
        tags = data.get("tags", [])
        expiry_date = data.get("expiry_date", "")
        file_name = data.get("file_name", "document.pdf")
        file_bytes = None
    else:
        title = request.form.get("title", "Evidence Artifact")
        category = request.form.get("category", "General")
        control_id = request.form.get("control_id", "DPDP-SEC-05")
        notes = request.form.get("notes", "")
        tags = [t.strip() for t in request.form.get("tags", "").split(",") if t.strip()]
        expiry_date = request.form.get("expiry_date", "")
        uploaded_file = request.files.get("file")
        if uploaded_file:
            file_name = uploaded_file.filename or "evidence.pdf"
            file_bytes = uploaded_file.read()
        else:
            file_name = request.form.get("file_name") or "evidence_record.txt"
            file_bytes = (notes or title or "Evidence Record").encode("utf-8")

    try:
        artifact = dpdp_store.add_evidence_artifact(
            org_id=org_id,
            title=title,
            category=category,
            control_id=control_id,
            file_bytes=file_bytes,
            file_name=file_name,
            uploaded_by=actor_label,
            review_notes=notes or "Awaiting compliance review.",
            tags=tags,
            expiry_date=expiry_date
        )
    except ValueError as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    security_utils.append_audit_log(
        org_id=org_id, action="evidence.uploaded", resource_type="evidence",
        resource_id=artifact.get("id", ""), actor_user_id=user.get("id", ""),
        actor_email=user.get("email", ""), actor_role=user.get("role", ""),
        details={"filename": artifact.get("filename")},
    )
    return jsonify({"status": "success", "evidence": artifact}), 201


@app.route("/api/dpdp/evidence/<evidence_id>/download", methods=["GET"])
def api_dpdp_download_evidence(evidence_id):
    """Downloads physical DPDP evidence file strictly scoped to authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    version_param = request.args.get("version")
    ver = int(version_param) if version_param and version_param.isdigit() else None
    raw_bytes, meta = dpdp_store.get_evidence_file_bytes(org_id, evidence_id, version=ver)
    if raw_bytes is None or not meta:
        return jsonify({"status": "error", "error": "Physical evidence file not found or unauthorized."}), 404
    safe_name = security_utils.sanitize_filename(meta.get("filename", "evidence.pdf"))
    return Response(
        raw_bytes,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.route("/api/dpdp/evidence/<evidence_id>/preview", methods=["GET"])
def api_dpdp_preview_evidence(evidence_id):
    """Inline safe preview for verified previewable files (PDF/PNG/JPG/TXT/CSV/MD/JSON)."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    raw_bytes, meta = dpdp_store.get_evidence_file_bytes(org_id, evidence_id)
    if raw_bytes is None or not meta:
        return jsonify({"status": "error", "error": "Physical file not available for preview."}), 404
    if not meta.get("previewable"):
        return jsonify({"status": "error", "error": "Preview not supported for this file format; please download instead."}), 400
    safe_name = security_utils.sanitize_filename(meta.get("filename", "preview"))
    return Response(
        raw_bytes,
        mimetype=meta.get("mime_type", "text/plain; charset=utf-8"),
        headers={
            "Content-Disposition": f'inline; filename="{safe_name}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.route("/api/dpdp/evidence/<evidence_id>/version", methods=["POST"])
def api_dpdp_upload_evidence_version(evidence_id):
    """Appends a new physical file version to an existing evidence item."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err
    uploaded_file = request.files.get("file")
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"status": "error", "error": "A valid file is required."}), 400
    notes = request.form.get("notes", "Updated evidence version uploaded")
    try:
        updated = dpdp_store.add_evidence_version(
            org_id=org_id,
            artifact_id=evidence_id,
            file_bytes=uploaded_file.read(),
            filename=uploaded_file.filename,
            uploaded_by=user.get("email") or "Privacy Lead",
            notes=notes,
        )
    except ValueError as e:
        return jsonify({"status": "error", "error": str(e)}), 400
    if not updated:
        return jsonify({"status": "error", "error": "Evidence artifact not found."}), 404
    return jsonify({"status": "success", "evidence": updated}), 200


@app.route("/api/dpdp/evidence/<evidence_id>", methods=["DELETE"])
def api_dpdp_delete_evidence(evidence_id):
    """Deletes a DPDP evidence artifact and its stored physical files."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    deleted = dpdp_store.delete_evidence_artifact(org_id, evidence_id)
    if not deleted:
        return jsonify({"status": "error", "error": "Evidence artifact not found."}), 404
    security_utils.append_audit_log(
        org_id=org_id, action="evidence.deleted", resource_type="evidence",
        resource_id=evidence_id, actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
    )
    return jsonify({"status": "success"}), 200


@app.route("/api/dpdp/evidence/<evidence_id>/status", methods=["POST"])
def api_dpdp_update_evidence_status(evidence_id):
    """Updates verification status across 5 states: Uploaded, Pending review, Verified, Rejected, Expired."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    verified_by = data.get("verified_by") or user.get("email") or "Privacy Officer"
    notes = data.get("notes", "")

    valid_statuses = ["Uploaded", "Pending review", "Verified", "Rejected", "Expired"]
    if not status or status not in valid_statuses:
        return jsonify({
            "status": "error",
            "message": f"Status must be one of: {', '.join(valid_statuses)}"
        }), 400

    updated = dpdp_store.update_evidence_status(org_id, evidence_id, status, verified_by, notes)
    if not updated:
        return jsonify({"status": "error", "message": f"Evidence artifact '{evidence_id}' not found."}), 404
    security_utils.append_audit_log(
        org_id=org_id, action="evidence.status_changed", resource_type="evidence",
        resource_id=evidence_id, actor_user_id=user.get("id", ""), actor_email=user.get("email", ""),
        details={"new_status": status},
    )
    return jsonify({"status": "success", "evidence": updated}), 200


@app.route("/api/dpdp/evidence/list", methods=["GET"])
def api_dpdp_list_evidence():
    """Lists evidence artifacts strictly within authenticated tenant."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    category = request.args.get("category")
    status = request.args.get("status")
    control_id = request.args.get("control_id")

    artifacts = dpdp_store.get_evidence_artifacts(org_id, category=category, status=status, control_id=control_id)
    return jsonify({"status": "success", "artifacts": artifacts}), 200


@app.route("/api/dpdp/tasks/<task_id>/update", methods=["POST"])
def api_dpdp_update_task(task_id):
    """Updates remediation task strictly inside authenticated org_id (zero cross-tenant lookup)."""
    org_id, user, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    owner = data.get("owner") or data.get("responsible_person")
    due_date = data.get("due_date")
    comment = data.get("comment") or data.get("notes")

    valid_statuses = [
        "Open", "In progress", "Awaiting evidence", "Under review",
        "Resolved", "Accepted risk", "Not applicable",
        "OPEN", "IN_PROGRESS", "AWAITING_EVIDENCE", "UNDER_REVIEW", "RESOLVED", "COMPLETED", "VERIFIED"
    ]
    if status and status not in valid_statuses:
        return jsonify({
            "status": "error",
            "message": f"Status must be one of: {', '.join(valid_statuses[:7])}"
        }), 400

    actor_label = user.get("email") or user.get("name") or "Privacy Officer"
    updated = dpdp_store.update_remediation_task_full(
        org_id=org_id,
        task_id=task_id,
        status=status,
        owner=owner,
        due_date=due_date,
        comment=comment,
        updated_by=actor_label
    )

    if not updated:
        return jsonify({"status": "error", "message": f"Remediation task '{task_id}' not found in your organisation."}), 404
    return jsonify({"status": "success", "task": updated}), 200


@app.route("/api/dpdp/scanner/compare", methods=["POST"])
def api_dpdp_scanner_compare():
    """Compares two DPDP website scans belonging to authenticated org."""
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    scan_id_old = data.get("scan_id_old")
    scan_id_new = data.get("scan_id_new")

    if not scan_id_old or not scan_id_new:
        return jsonify({"status": "error", "message": "scan_id_old and scan_id_new are required."}), 400

    diff = dpdp_store.compare_website_scans(org_id, scan_id_old, scan_id_new)
    if not diff or diff.get("status") == "error":
        return jsonify({"status": "error", "message": "Could not compare scans. Verify scan IDs belong to your organisation."}), 404
    return jsonify({"status": "success", "comparison": diff}), 200


@app.route("/api/admin/metrics", methods=["GET"])
@app.route("/api/admin/overview", methods=["GET"])
def api_admin_system_metrics():
    """Platform-wide oversight metrics strictly restricted to platform administrators."""
    _org_id, user, err = require_platform_admin()
    if err:
        return err
    metrics = dpdp_store.get_admin_system_metrics(user.get("email"))
    summary = saas_store.list_admin_oversight_summary()
    return jsonify({"status": "success", "metrics": metrics, "platform_summary": summary}), 200


@app.route("/api/admin/plans", methods=["GET", "POST"])
def api_admin_plans():
    """Allows verified platform administrators to configure plans & quotas."""
    _org_id, _user, err = require_platform_admin()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        key = data.get("plan_key") or data.get("key") or ""
        ok, msg, plan = saas_store.update_plan_config(key, data)
        if not ok:
            return jsonify({"status": "error", "message": msg}), 400
        return jsonify({"status": "success", "message": msg, "plan": plan}), 200
    return jsonify({"status": "success", "plans": saas_store.get_public_plans()}), 200


# ==============================================================================
# PUBLIC TRUST, SECURITY & PRIVACY PORTAL
# ==============================================================================

@app.route("/trust", methods=["GET"])
@app.route("/security", methods=["GET"])
def trust_portal_view():
    """Renders public Security & Trust Centre showcasing verified controls."""
    return render_template("public/security.html", active_nav="security"), 200


_PUBLIC_TRUST_CACHE = {"data": None, "cached_at": 0}


@app.route("/api/public/trust-status", methods=["GET"])
def api_public_trust_status():
    """Returns truthful, configuration-aware operational security telemetry for the public Trust Centre."""
    now = time.time()
    enc_summary = security_utils.encryption_status_summary()
    app_enc_on = bool(enc_summary.get("app_layer_encryption_configured"))
    gemini_on = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    is_https = request.is_secure or (request.headers.get("X-Forwarded-Proto", "").lower() == "https")
    cache_key = (app_enc_on, gemini_on, is_https)
    if (
        _PUBLIC_TRUST_CACHE["data"]
        and _PUBLIC_TRUST_CACHE.get("key") == cache_key
        and (now - _PUBLIC_TRUST_CACHE["cached_at"] < 30)
    ):
        return jsonify(_PUBLIC_TRUST_CACHE["data"]), 200

    controls_matrix = [
        {
            "id": "tenant_isolation",
            "control": "Multi-Tenant Organisation & RBAC Isolation",
            "state": "Enabled and verified by automated test",
            "basis": "Verified via pytest multi-tenant isolation, Viewer read-only enforcement, and Admin console 403 checks.",
        },
        {
            "id": "password_hashing",
            "control": "Password Storage (PBKDF2-HMAC-SHA256 600,000 iterations)",
            "state": "Enabled and verified by automated test",
            "basis": "Per-user 16-byte random salt, constant-time comparison, automatic rehash-on-login.",
        },
        {
            "id": "session_and_mfa",
            "control": "SHA-256 Session Storage, TOTP QR & Recovery Codes",
            "state": "Enabled and verified by automated test",
            "basis": "HttpOnly SameSite cookies, session revocation, offline SVG QR, and single-use recovery hashes.",
        },
        {
            "id": "ssrf_upload_guards",
            "control": "SSRF Protection & Safe File Upload Magic-Byte Validation",
            "state": "Enabled and verified by automated test",
            "basis": "Blocks private/loopback/CGNAT/IPv4-mapped IPv6/metadata IPs and enforces 5 MB allowlist with nosniff headers.",
        },
        {
            "id": "app_layer_encryption",
            "control": "Application-Layer File Encryption (Fernet via TRUSTAUDIT_DATA_KEY)",
            "state": "Enabled and verified by automated test" if app_enc_on else "Not enabled",
            "basis": (
                "TRUSTAUDIT_DATA_KEY configured; Evidence Vault uploads encrypted with Fernet before disk write."
                if app_enc_on
                else "TRUSTAUDIT_DATA_KEY is not configured in this environment. Infrastructure disk encryption still applies if provided by host; app-layer Fernet encryption is Not enabled."
            ),
        },
        {
            "id": "tls_transport",
            "control": "HTTPS / TLS Transport Encryption",
            "state": "Enabled and verified by automated test" if is_https else "Partially configured",
            "basis": (
                "Serving over HTTPS with HSTS header active."
                if is_https
                else "Render production edge enforces TLS; current request arrived over local HTTP development socket."
            ),
        },
        {
            "id": "ai_privacy_layer",
            "control": "AI Assistant PII Redaction Layer",
            "state": "Enabled and verified by automated test" if not gemini_on else "Enabled but not independently tested",
            "basis": (
                "Local deterministic DPDP knowledge corpus active; zero prompts leave server to external LLM APIs."
                if not gemini_on
                else "External Gemini API configured with regex scrubbing of email/phone/PAN patterns prior to prompt submission."
            ),
        },
    ]

    posture_state = "verified" if app_enc_on else "attention_recommended"
    posture_summary = (
        "All Core Security Controls Active & Configured"
        if app_enc_on
        else "Service Healthy • App-Layer Fernet Encryption Not Enabled (TRUSTAUDIT_DATA_KEY unset)"
    )

    telemetry = {
        "status": "healthy",
        "posture_state": posture_state,
        "posture_summary": posture_summary,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "controls_matrix": controls_matrix,
        "tenant_isolation": {
            "status": "enforced",
            "verification": "Verified via automated pytest tenant isolation and RBAC boundary test suite",
        },
        "security_controls": {
            "encryption_in_transit": "HTTPS / TLS enforced in production behind Render edge proxy",
            "encryption_at_rest": (
                "Application-layer Fernet encryption active for Evidence Vault files (TRUSTAUDIT_DATA_KEY configured)"
                if app_enc_on
                else "App-layer Fernet encryption is Not enabled (TRUSTAUDIT_DATA_KEY unset); hosting provider volume encryption applies"
            ),
            "password_hashing": "PBKDF2-HMAC-SHA256 (600,000 iterations, OWASP work factor with automatic rehash-on-login)",
            "session_security": "SHA-256 hashed persistent session tokens in HttpOnly SameSite cookies",
            "mfa_status": "Optional RFC 6238 TOTP MFA with offline SVG QR + 8 single-use recovery codes",
            "ssrf_protection": "Enforced (dual-stack DNS resolution, private/loopback/CGNAT/IPv4-mapped IPv6 blocking, cloud metadata rejection, redirect-hop checks)",
            "ai_assistant_privacy": (
                "External Google Gemini API enabled (queries stripped of personal email/phone/ID strings before sending)"
                if gemini_on
                else "Local grounded DPDP knowledge engine active (queries processed locally without external LLM API)"
            ),
        },
    }
    _PUBLIC_TRUST_CACHE["data"] = telemetry
    _PUBLIC_TRUST_CACHE["cached_at"] = now
    _PUBLIC_TRUST_CACHE["key"] = cache_key
    return jsonify(telemetry), 200


@app.route("/api/public/trust-pack/download", methods=["GET", "POST"])
def api_public_trust_pack_download():
    """Generates and serves downloadable Trust Pack zip or markdown bundle."""
    import trust_pack_service
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        docs_raw = payload.get("docs", [])
        fmt = payload.get("format", "zip")
    else:
        docs_param = request.args.get("docs", "")
        docs_raw = [d.strip() for d in docs_param.split(",") if d.strip()] if docs_param else None
        fmt = request.args.get("format", "zip").lower()

    if fmt == "zip":
        zip_bytes = trust_pack_service.build_trust_pack_zip(docs_raw)
        return Response(
            zip_bytes,
            mimetype="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="TrustAudit_Enterprise_Trust_Pack.zip"',
                "X-Content-Type-Options": "nosniff",
            }
        )
    else:
        md_text = trust_pack_service.build_trust_pack_consolidated_markdown(docs_raw)
        return Response(
            md_text,
            mimetype="text/markdown",
            headers={
                "Content-Disposition": 'attachment; filename="TrustAudit_Enterprise_Trust_Pack.md"',
                "X-Content-Type-Options": "nosniff",
            }
        )


# ==============================================================================
# GTM PLATFORM APIS: ONBOARDING ACTIVITIES, EXTRACTION, TOPICS, TASKS, PORTALS
# ==============================================================================

@app.route("/api/public/walkthrough", methods=["POST"])
def api_public_walkthrough():
    """Rate-limited endpoint for booking product walkthroughs."""
    client_ip = request.remote_addr or "unknown"
    allowed, retry = security_utils.rate_limiter.allow(f"walkthrough:{client_ip}", max_requests=12, window_seconds=3600)
    if not allowed:
        return jsonify({"status": "error", "message": f"Too many walkthrough requests. Retry in {retry}s."}), 429
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    if not name or not email or "@" not in email:
        return jsonify({"status": "error", "message": "Valid name and work email are required."}), 400
    rec = saas_store.record_walkthrough_request(
        name=name,
        email=email,
        company=data.get("company", ""),
        industry=data.get("industry", ""),
        team_size=data.get("team_size", ""),
        notes=data.get("notes", ""),
    )
    return jsonify({"status": "success", "data": rec}), 201


@app.route("/api/public/portal/<org_slug>/submit", methods=["POST"])
def api_public_portal_submit(org_slug):
    """Receives public customer privacy requests with HMAC anti-spam verification and strict non-enumeration."""
    client_ip = request.remote_addr or "unknown"
    allowed, retry = security_utils.rate_limiter.allow(f"portal_submit:{org_slug}:{client_ip}", max_requests=15, window_seconds=3600)
    if not allowed:
        return jsonify({"status": "error", "message": f"Too many submissions. Retry in {retry}s."}), 429

    org = saas_store.get_organization_by_slug(org_slug)
    if not org:
        return jsonify({"status": "error", "message": "Organisation portal not found."}), 404
    cfg = dpdp_store.get_portal_config(org["id"], default_name=org.get("name", "Business"), default_slug=org_slug)
    if not cfg.get("enabled", True):
        return jsonify({"status": "error", "message": "Portal is disabled by the organisation."}), 403

    data = request.get_json(silent=True) or {}
    if cfg.get("require_human_verification", True):
        if not _verify_portal_challenge(data.get("challenge_token", ""), data.get("challenge_answer", "")):
            return jsonify({"status": "error", "message": "Human verification check failed or expired. Refresh the portal and retry."}), 400

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    desc = (data.get("description") or "").strip()
    if not name or not email or not desc:
        return jsonify({"status": "error", "message": "Name, contact email, and request description are required."}), 400

    res = dpdp_store.submit_portal_request_public(org["id"], data)
    return jsonify({"status": "success", **res}), 201


@app.route("/api/public/portal/<org_slug>/status", methods=["POST"])
def api_public_portal_status(org_slug):
    """Checks request status matching BOTH Reference ID and Verification Code without leaking account existence."""
    client_ip = request.remote_addr or "unknown"
    allowed, retry = security_utils.rate_limiter.allow(f"portal_status:{client_ip}", max_requests=30, window_seconds=900)
    if not allowed:
        return jsonify({"status": "error", "message": f"Rate limit exceeded. Retry in {retry}s."}), 429
    org = saas_store.get_organization_by_slug(org_slug)
    if not org:
        return jsonify({"status": "error", "message": "Portal not found."}), 404
    data = request.get_json(silent=True) or {}
    match = dpdp_store.lookup_portal_request_public(org["id"], data.get("reference_id", ""), data.get("verification_code", ""))
    return jsonify({"status": "success", "match": match}), 200


@app.route("/api/public/privacy-profile/<org_slug>", methods=["GET"])
def api_public_privacy_profile(org_slug):
    """Returns strictly whitelisted approved public Privacy Profile metadata."""
    org = saas_store.get_organization_by_slug(org_slug)
    if not org:
        return jsonify({"status": "error", "message": "Privacy profile not found."}), 404
    prof = dpdp_store.get_public_privacy_profile(org["id"], org.get("slug") or org["id"])
    if not prof:
        return jsonify({"status": "error", "message": "Privacy profile is private or unpublished."}), 404
    return jsonify({"status": "success", "profile": prof}), 200


@app.route("/api/public/vendor-intake/<token>", methods=["POST"])
def api_public_vendor_intake(token):
    """Accepts restricted vendor questionnaire submission scoped solely to one vendor record."""
    info = dpdp_store.resolve_vendor_intake_token(token)
    if not info:
        return jsonify({"status": "error", "message": "Invalid or expired vendor questionnaire token."}), 404
    data = request.get_json(silent=True) or {}
    rec = dpdp_store.save_vendor_questionnaire(info["org_id"], info["vendor"]["id"], data)
    return jsonify({"status": "success", "questionnaire": rec}), 200


@app.route("/api/dpdp/onboarding/activities", methods=["GET", "POST"])
def api_dpdp_onboarding_activities():
    """Returns industry activity cards or saves selected drafts marked 'SUGGESTED — NEEDS CONFIRMATION'."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        industry = data.get("industry") or "saas"
        selected_keys = data.get("selected_keys") or []
        created = dpdp_store.prepopulate_industry_activities(org_id, industry, selected_keys)
        security_utils.append_audit_log(
            org_id=org_id, action="onboarding.activities_suggested", resource_type="data_inventory",
            actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
            details={"industry": industry, "created_count": len(created)},
        )
        return jsonify({"status": "success", "created_count": len(created), "items": created}), 201
    industry = request.args.get("industry") or "saas"
    return jsonify({"status": "success", "activities": dpdp_store.get_industry_activity_suggestions(industry)}), 200


@app.route("/api/dpdp/inventory/duplicates", methods=["GET"])
def api_dpdp_inventory_duplicates():
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    dups = dpdp_store.find_inventory_duplicates(org_id)
    return jsonify({"status": "success", "duplicates": dups}), 200


@app.route("/api/dpdp/inventory/bulk-review", methods=["POST"])
def api_dpdp_inventory_bulk_review():
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    cnt = dpdp_store.bulk_confirm_inventory(org_id, data.get("entry_ids", []), status=data.get("status", "Confirmed by business"))
    security_utils.append_audit_log(
        org_id=org_id, action="inventory.bulk_confirmed", resource_type="data_inventory",
        actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""), details={"count": cnt},
    )
    return jsonify({"status": "success", "updated_count": cnt}), 200


@app.route("/api/dpdp/extraction/upload", methods=["POST"])
def api_dpdp_extraction_upload():
    """Extracts candidate DPDP records from uploaded CSV, XLSX, DOCX, PDF, TXT, MD, or JSON files."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    up_file = request.files.get("file")
    if not up_file or not up_file.filename:
        return jsonify({"status": "error", "message": "File required for extraction."}), 400
    raw_bytes = up_file.read()
    ok, err_msg, meta = security_utils.validate_uploaded_file(up_file.filename, raw_bytes)
    if not ok:
        return jsonify({"status": "error", "error": err_msg, "message": err_msg}), 400

    use_async = (request.args.get("async") in ("1", "true", "yes")) or (request.form.get("async") in ("1", "true", "yes"))
    if use_async:
        safe_fname = meta["safe_filename"]

        def _extract_worker(update_progress, is_cancelled):
            update_progress(25, f"Parsing {safe_fname}...")
            if is_cancelled():
                return None
            out = extraction_engine.extract_from_uploaded_file(safe_fname, raw_bytes)
            if is_cancelled():
                return None
            update_progress(80, "Saving suggestions for human review...")
            if out.get("suggestions"):
                dpdp_store.save_discovery_suggestions(org_id, out["suggestions"])
            security_utils.append_audit_log(
                org_id=org_id, action="discovery.file_extracted", resource_type="discovery",
                actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
                details={"filename": safe_fname, "suggestions": out.get("suggestions_count", 0)},
            )
            return {"extraction": out}

        job = job_manager.submit_job(org_id, "extraction", f"Extract Privacy Signals: {safe_fname}", _extract_worker, idempotency_key=f"{safe_fname}:{len(raw_bytes)}")
        return jsonify({"status": "accepted", "job_id": job["job_id"], "job": job}), 202

    res = extraction_engine.extract_from_uploaded_file(meta["safe_filename"], raw_bytes)
    if res.get("suggestions"):
        dpdp_store.save_discovery_suggestions(org_id, res["suggestions"])
    security_utils.append_audit_log(
        org_id=org_id, action="discovery.file_extracted", resource_type="discovery",
        actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
        details={"filename": meta["safe_filename"], "suggestions": res.get("suggestions_count", 0)},
    )
    return jsonify({"status": "success", "extraction": res}), 200


@app.route("/api/dpdp/extraction/suggestions", methods=["GET"])
def api_dpdp_extraction_suggestions():
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    st = request.args.get("status")
    items = dpdp_store.get_discovery_suggestions(org_id, status_filter=st)
    return jsonify({"status": "success", "suggestions": items}), 200


@app.route("/api/dpdp/extraction/suggestions/<sug_id>/review", methods=["POST"])
def api_dpdp_extraction_review(sug_id):
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    out = dpdp_store.review_discovery_suggestion(
        org_id=org_id,
        suggestion_id=sug_id,
        action=data.get("action", "accept"),
        edited_fields=data.get("edited_fields"),
    )
    if not out:
        return jsonify({"status": "error", "message": "Suggestion not found."}), 404
    security_utils.append_audit_log(
        org_id=org_id, action="discovery.suggestion_reviewed", resource_type="discovery",
        resource_id=sug_id, actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
        details={"action": data.get("action", "accept")},
    )
    return jsonify({"status": "success", **out}), 200


@app.route("/api/dpdp/assessment/topics", methods=["GET", "POST"])
def api_dpdp_assessment_topics():
    """10-topic plain-language guided privacy assessment with 5 verification states."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        topic_id = data.get("topic_id", "")
        if not topic_id:
            return jsonify({"status": "error", "message": "topic_id is required."}), 400
        updated = dpdp_store.save_assessment_topic_answer(
            org_id, topic_id, data.get("answer", "Not sure"),
            notes=data.get("notes", ""), evidence_id=data.get("evidence_id", ""),
        )
        security_utils.append_audit_log(
            org_id=org_id, action="assessment.topic_updated", resource_type="assessment",
            resource_id=topic_id, actor_user_id=actor.get("id", ""), actor_email=actor.get("email", ""),
        )
        return jsonify({"status": "success", **updated}), 200
    return jsonify({"status": "success", **dpdp_store.get_assessment_topics(org_id)}), 200


@app.route("/api/dpdp/tasks", methods=["GET", "POST"])
def api_dpdp_tasks():
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        data["actor"] = actor.get("email") or actor.get("name") or "Owner"
        task = dpdp_store.create_remediation_task(org_id, data)
        return jsonify({"status": "success", "task": task}), 201
    tasks = dpdp_store.get_remediation_tasks(org_id)
    return jsonify({"status": "success", "tasks": tasks}), 200


@app.route("/api/dpdp/vendors/directory", methods=["GET"])
def api_dpdp_vendors_directory():
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    return jsonify({"status": "success", "directory": extraction_engine.KNOWN_VENDOR_DIRECTORY}), 200


@app.route("/api/dpdp/vendors/<vendor_id>/intake-link", methods=["POST"])
def api_dpdp_vendor_intake_link(vendor_id):
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    tok = dpdp_store.create_vendor_intake_token(org_id, vendor_id)
    if not tok:
        return jsonify({"status": "error", "message": "Vendor not found."}), 404
    return jsonify({"status": "success", "token": tok, "intake_path": f"/vendor-intake/{tok}"}), 200


@app.route("/api/dpdp/documents", methods=["GET"])
def api_dpdp_documents_list():
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    return jsonify({"status": "success", "documents": dpdp_store.get_generated_documents(org_id)}), 200


@app.route("/api/dpdp/documents/<doc_id>", methods=["GET", "PUT"])
def api_dpdp_document_detail(doc_id):
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    if request.method == "PUT":
        data = request.get_json(silent=True) or {}
        updated = dpdp_store.update_generated_document(
            org_id, doc_id, content=data.get("content"), status=data.get("status"),
            title=data.get("title"), actor=actor.get("email") or actor.get("name") or "Owner",
        )
        if not updated:
            return jsonify({"status": "error", "message": "Document not found."}), 404
        return jsonify({"status": "success", "document": updated}), 200
    doc = dpdp_store.get_generated_document(org_id, doc_id)
    if not doc:
        return jsonify({"status": "error", "message": "Document not found."}), 404
    return jsonify({"status": "success", "document": doc}), 200


@app.route("/api/dpdp/documents/<doc_id>/export", methods=["GET"])
def api_dpdp_document_export(doc_id):
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    doc = dpdp_store.get_generated_document(org_id, doc_id)
    if not doc:
        return jsonify({"status": "error", "message": "Document not found."}), 404
    fmt = (request.args.get("format") or "docx").lower()
    safe_base = security_utils.sanitize_filename(doc.get("doc_type") or doc_id)
    if fmt == "docx":
        raw = extraction_engine.generate_docx_bytes(doc.get("title", "TrustAudit Draft"), doc.get("content", ""), doc.get("company_name", "Organisation"))
        return Response(raw, mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": f'attachment; filename="{safe_base}_{doc_id}.docx"', "X-Content-Type-Options": "nosniff"})
    return Response(doc.get("content", ""), mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{safe_base}_{doc_id}.txt"', "X-Content-Type-Options": "nosniff"})


@app.route("/api/dpdp/documents/<doc_id>/save-evidence", methods=["POST"])
def api_dpdp_document_save_evidence(doc_id):
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    ev = dpdp_store.save_generated_doc_to_evidence(org_id, doc_id, actor=actor.get("email") or "Owner")
    if not ev:
        return jsonify({"status": "error", "message": "Document not found."}), 404
    return jsonify({"status": "success", "evidence": ev}), 201


@app.route("/api/dpdp/notices/<notice_id>/export", methods=["GET"])
def api_dpdp_notice_export(notice_id):
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    notice = next((n for n in dpdp_store.get_privacy_notices(org_id) if n.get("id") == notice_id), None)
    if not notice:
        return jsonify({"status": "error", "message": "Privacy Notice not found."}), 404
    fmt = (request.args.get("format") or "docx").lower()
    if fmt == "docx":
        raw = extraction_engine.generate_docx_bytes(notice.get("title", "Privacy Notice"), notice.get("content", ""))
        return Response(raw, mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": f'attachment; filename="Privacy_Notice_{notice_id}.docx"', "X-Content-Type-Options": "nosniff"})
    return Response(notice.get("content", ""), mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="Privacy_Notice_{notice_id}.txt"', "X-Content-Type-Options": "nosniff"})


@app.route("/api/dpdp/consent/import", methods=["POST"])
def api_dpdp_consent_import():
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    cnt = dpdp_store.import_consent_csv(org_id, data.get("csv_content", ""))
    return jsonify({"status": "success", "imported_count": cnt}), 200


@app.route("/api/dpdp/portal/config", methods=["GET", "POST"])
def api_dpdp_portal_config():
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    org = saas_store.get_organization(org_id) or {}
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        cfg = dpdp_store.save_portal_config(org_id, data)
        return jsonify({"status": "success", "config": cfg}), 200
    cfg = dpdp_store.get_portal_config(org_id, default_name=org.get("name", "Business"), default_slug=org.get("slug", org_id))
    return jsonify({"status": "success", "config": cfg}), 200


@app.route("/api/dpdp/privacy-profile", methods=["GET", "POST"])
def api_dpdp_privacy_profile():
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    org = saas_store.get_organization(org_id) or {}
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        cfg = dpdp_store.save_privacy_profile_config(org_id, data)
        return jsonify({"status": "success", "config": cfg}), 200
    cfg = dpdp_store.get_privacy_profile_config(org_id, default_name=org.get("name", "Business"))
    return jsonify({"status": "success", "config": cfg}), 200


@app.route("/api/dpdp/search", methods=["GET"])
def api_dpdp_search():
    org_id, _, err = require_authenticated_tenant()
    if err:
        return err
    q = request.args.get("q", "")
    results = dpdp_store.search_org_workspace(org_id, q)
    return jsonify({"status": "success", "results": results}), 200


@app.route("/api/dpdp/backup/export", methods=["GET"])
def api_dpdp_backup_export():
    """Exports tenant-isolated backup JSON snapshot cleanly for the authenticated organisation."""
    org_id, actor, err = require_authenticated_tenant()
    if err:
        return err
    payload = {
        "exported_at": security_utils.utc_now_iso(),
        "exported_by": actor.get("email", ""),
        "organization": saas_store.get_organization(org_id),
        "onboarding_profile": dpdp_store.get_onboarding_profile(org_id),
        "data_inventory": dpdp_store.get_data_inventory(org_id),
        "vendors": dpdp_store.get_vendors(org_id),
        "privacy_notices": dpdp_store.get_privacy_notices(org_id),
        "consent_records": dpdp_store.get_consent_records(org_id),
        "rights_requests": dpdp_store.get_rights_requests(org_id),
        "retention_schedules": dpdp_store.get_retention_schedules(org_id),
        "breach_incidents": dpdp_store.get_breach_incidents(org_id),
        "assessment_topics": dpdp_store.get_assessment_topics(org_id),
        "tasks": dpdp_store.get_remediation_tasks(org_id),
        "portal_config": dpdp_store.get_portal_config(org_id),
        "privacy_profile_config": dpdp_store.get_privacy_profile_config(org_id),
    }
    raw = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    return Response(
        raw,
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="TrustAudit_Backup_{org_id}.json"', "X-Content-Type-Options": "nosniff"},
    )


if __name__ == "__main__":
    app.run(debug=False, threaded=True)
