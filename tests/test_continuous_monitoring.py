"""
Tests for TrustAudit Continuous Security Monitoring, Delta Engine, Prioritization,
Scheduler, Alerts, and SaaS Plan Limits.
"""

import json
import time
import pytest
from app import app
import scheduler
import delta_engine
import prioritizer
import alerts
import saas_store
from finding_model import Finding


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# ===========================================================================
# 1. Scheduler Tests
# ===========================================================================

def test_calculate_next_run():
    now = 1000000.0
    assert scheduler.calculate_next_run("hourly", now) == now + 3600
    assert scheduler.calculate_next_run("daily", now) == now + 86400
    assert scheduler.calculate_next_run("weekly", now) == now + 604800
    assert scheduler.calculate_next_run("manual", now) is None


def test_set_project_schedule_and_summary():
    # Configure project schedule
    updated = scheduler.set_project_schedule("proj-demo-1", frequency="daily", enabled=True, org_id="org-default")
    assert updated["monitoring_status"] == "ACTIVE"
    assert updated["scan_frequency"] == "daily"
    assert updated["next_scan_at"] is not None

    summary = scheduler.get_monitoring_summary("org-default")
    assert summary["total_projects"] >= 1
    assert summary["monitored_projects"] >= 1


def test_scheduler_start_stop():
    scheduler.start_scheduler(poll_interval=1)
    assert scheduler._scheduler_running is True
    scheduler.stop_scheduler()
    assert scheduler._scheduler_running is False


# ===========================================================================
# 2. Delta & Timeline Engine Tests
# ===========================================================================

def test_compute_scan_delta_initial():
    scan1 = {
        "score": 85,
        "findings": [
            {"id": "FIND-001", "category": "secrets", "title": "Exposed API Key", "severity": "CRITICAL", "file": ".env"}
        ]
    }
    delta = delta_engine.compute_scan_delta(scan1, previous_scan=None)
    assert delta["is_initial_scan"] is True
    assert delta["new_count"] == 1
    assert delta["fixed_count"] == 0
    assert delta["score_delta"] == 0


def test_compute_scan_delta_progression():
    scan1 = {
        "score": 80,
        "findings": [
            {"id": "FIND-001", "category": "secrets", "title": "Exposed API Key", "severity": "CRITICAL", "file": ".env"},
            {"id": "FIND-002", "category": "code_security", "title": "SQL Injection", "severity": "HIGH", "file": "app.py"}
        ]
    }
    # Second scan: FIND-001 fixed, FIND-003 newly introduced
    scan2 = {
        "score": 90,
        "findings": [
            {"id": "FIND-002", "category": "code_security", "title": "SQL Injection", "severity": "HIGH", "file": "app.py"},
            {"id": "FIND-003", "category": "dependencies", "title": "Vulnerable PyYAML", "severity": "MEDIUM", "file": "requirements.txt"}
        ]
    }
    delta = delta_engine.compute_scan_delta(scan2, previous_scan=scan1)
    assert delta["is_initial_scan"] is False
    assert delta["new_count"] == 1
    assert delta["new_findings"][0]["id"] == "FIND-003"
    assert delta["fixed_count"] == 1
    assert delta["fixed_findings"][0]["id"] == "FIND-001"
    assert delta["score_delta"] == 10  # 90 - 80


def test_compute_and_record_scan_delta_persists():
    proj = saas_store.create_or_update_project("Customer AI Assistant", "https://github.com/example/support-agent-mcp", "repository", org_id="org-default")
    pid = proj.get("id", "proj-demo-1")
    scan_res = {
        "score": 92,
        "grade": "A",
        "status": "SECURE",
        "findings": [
            {"id": "FIND-TEST-1", "category": "headers", "title": "Missing HSTS Header", "severity": "MEDIUM", "file": "server.py"}
        ]
    }
    delta = delta_engine.compute_and_record_scan_delta(pid, scan_res, org_id="org-default")
    assert delta is not None

    timeline = delta_engine.get_project_timeline(pid, org_id="org-default")
    assert isinstance(timeline, list)
    assert len(timeline) >= 1

    what_changed = delta_engine.get_project_what_changed(pid, org_id="org-default")
    assert what_changed is not None


# ===========================================================================
# 3. Prioritizer ("Fix These First") Tests
# ===========================================================================

def test_prioritize_findings_ranking():
    raw_findings = [
        {"id": "F-LOW", "severity": "LOW", "confidence": "CONFIRMED", "category": "headers", "title": "Server Banner", "file": "app.py", "evidence": "nginx/1.18"},
        {"id": "F-CRIT", "severity": "CRITICAL", "confidence": "CONFIRMED", "category": "secrets", "title": "Supabase Service Role Key Exposed", "file": "src/api.ts", "evidence": "SUPABASE_SERVICE_ROLE_KEY=ey..."},
        {"id": "F-HIGH", "severity": "HIGH", "confidence": "CONFIRMED", "category": "code_security", "title": "SQL Injection in Search Route", "file": "routes/search.py", "evidence": "execute(f'SELECT...')"}
    ]
    cards = prioritizer.prioritize_findings(raw_findings, limit=2)
    assert len(cards) == 2
    assert cards[0]["id"] == "F-CRIT"
    assert cards[0]["rank"] == 1
    assert "Why This Matters" in cards[0]["why_this_matters"] or len(cards[0]["why_this_matters"]) > 10
    assert "What to Do" in cards[0]["what_to_do"] or len(cards[0]["what_to_do"]) > 10
    assert "Verify" in cards[0]["how_to_verify"]
    assert "Fix security issue" in cards[0]["ai_prompt"]


# ===========================================================================
# 4. Alerts & Notifications Tests
# ===========================================================================

def test_alert_threshold():
    assert alerts.should_trigger_alert("CRITICAL", "NEW_VULNERABILITY") is True
    assert alerts.should_trigger_alert("HIGH", "NEW_VULNERABILITY") is True
    assert alerts.should_trigger_alert("LOW", "NEW_VULNERABILITY") is False
    assert alerts.should_trigger_alert("LOW", "FIX_VERIFIED") is True


def test_dispatch_security_alert():
    res = alerts.dispatch_security_alert(
        event_type="NEW_VULNERABILITY",
        project_name="Customer Support Agent",
        title="Supabase Key Leak",
        details="Hardcoded key detected in src/api.ts",
        severity="CRITICAL",
        org_id="org-default"
    )
    assert res["dispatched"] is True
    assert res["channels"]["email_sent"] is True


# ===========================================================================
# 5. SaaS Plans & Tenancy Tests
# ===========================================================================

def test_plan_definitions_and_limits():
    plans = saas_store.PLANS
    assert "free" in plans
    assert "starter" in plans
    assert "pro" in plans
    assert plans["starter"]["price_monthly_inr"] == 999
    assert plans["pro"]["price_monthly_inr"] == 1999

    # Limit check on default org (starter plan)
    ok, err = saas_store.check_plan_limits("org-default", "website", current_count=2)
    assert ok is True
    assert err is None

    # Limit exceeded check
    ok_exceeded, err_msg = saas_store.check_plan_limits("org-default", "project", current_count=50)
    assert ok_exceeded is False
    assert "limit reached" in err_msg.lower()


def test_validate_tenant_access():
    assert saas_store.validate_tenant_access("org-1", "org-1") is True
    assert saas_store.validate_tenant_access("org-1", "org-2") is False
    assert saas_store.validate_tenant_access("", "org-1") is False


# ===========================================================================
# 6. REST API Endpoints Tests
# ===========================================================================

def test_api_plans(client):
    res = client.get("/api/plans")
    assert res.status_code == 200
    data = res.get_json()
    assert "plans" in data
    assert "starter" in data["plans"]


def test_api_monitoring_status(client):
    res = client.get("/api/monitoring/status")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_projects" in data
    assert "scheduler_active" in data


def test_api_monitoring_schedule(client):
    res = client.post("/api/monitoring/schedule", json={
        "project_id": "proj-demo-1",
        "frequency": "daily",
        "enabled": True
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"


def test_api_monitoring_trigger_all(client, monkeypatch):
    monkeypatch.setattr(scheduler, "run_scheduled_project_scan", lambda *args, **kwargs: {"status": "SUCCESS"})
    res = client.post("/api/monitoring/trigger-all")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "success"
    assert "triggered_count" in data


def test_api_project_what_changed(client):
    res = client.get("/api/projects/proj-demo-1/what-changed")
    assert res.status_code == 200
    data = res.get_json()
    assert "summary" in data


def test_api_project_timeline(client):
    proj = saas_store.create_or_update_project("Customer AI Assistant", "https://github.com/example/support-agent-mcp", "repository", org_id="org-default")
    pid = proj.get("id", "proj-demo-1")
    res = client.get(f"/api/projects/{pid}/timeline")
    assert res.status_code == 200
    data = res.get_json()
    assert "timeline" in data


def test_api_project_prioritized_fixes(client):
    proj = saas_store.create_or_update_project("Customer AI Assistant", "https://github.com/example/support-agent-mcp", "repository", org_id="org-default")
    pid = proj.get("id", "proj-demo-1")
    scan_res = {"score": 84, "grade": "B", "findings": [{"id": "F1", "severity": "HIGH", "category": "code_security", "title": "SQL Injection", "file": "app.py"}]}
    saas_store.record_scan_event("https://github.com/example/support-agent-mcp", "repository", scan_res, org_id="org-default", project_id=pid)
    res = client.get(f"/api/projects/{pid}/prioritized-fixes")
    assert res.status_code == 200
    data = res.get_json()
    assert "prioritized_fixes" in data


def test_api_advisor_queries(client):
    # Test "What is my biggest security problem?"
    res1 = client.post("/api/advisor/query", json={"query": "What is my biggest security problem?"})
    assert res1.status_code == 200
    assert "answer" in res1.get_json()

    # Test "What changed today?"
    res2 = client.post("/api/advisor/query", json={"query": "What changed today?"})
    assert res2.status_code == 200
    assert "answer" in res2.get_json()

    # Test "Which vulnerabilities should I fix first?"
    res3 = client.post("/api/advisor/query", json={"query": "Which vulnerabilities should I fix first?"})
    assert res3.status_code == 200
    assert "answer" in res3.get_json()

    # Test "What should my developer do?"
    res4 = client.post("/api/advisor/query", json={"query": "What should my developer do?"})
    assert res4.status_code == 200
    assert "answer" in res4.get_json()


def test_api_finding_verify_and_remediate(client, monkeypatch):
    mock_clean_result = {
        "status": "SECURE",
        "score": 100,
        "grade": "A",
        "findings": []
    }
    monkeypatch.setattr("app.execute_scan", lambda *args, **kwargs: mock_clean_result)
    monkeypatch.setattr("app.execute_website_scan", lambda *args, **kwargs: mock_clean_result)
    
    # Test verify endpoint
    res_v = client.post("/api/finding/FIND-MOCK-1/verify", json={"finding_id": "FIND-MOCK-1", "target": "https://example.com"})
    assert res_v.status_code == 200
    data_v = res_v.get_json()
    assert data_v["is_fixed"] is True
    assert data_v["status"] == "VERIFIED"

    # Test remediate guidance endpoint
    res_r = client.post("/api/finding/FIND-MOCK-1/remediate", json={
        "finding": {
            "id": "FIND-MOCK-1",
            "title": "Exposed API Key",
            "severity": "CRITICAL",
            "evidence": "SUPABASE_KEY=eyJ...",
            "file": ".env"
        }
    })
    assert res_r.status_code == 200
    data_r = res_r.get_json()
    assert "ai_fix_prompt" in data_r
    assert "why_this_matters" in data_r
