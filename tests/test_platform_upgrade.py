"""
Formal automated test suite for TrustAudit Startup Security Platform Upgrade.
"""
import pytest
from app import app
import prioritizer
import compliance_engine
import saas_store


@pytest.fixture
def client():
    return app.test_client()


def test_dashboard_15_sections(client):
    """Verifies all 15 core SaaS sections render cleanly."""
    res = client.get("/dashboard")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    expected_sections = [
        "dash-main", "dash-assets", "dash-scans", "dash-findings",
        "dash-fix-center", "dash-monitoring", "dash-attack-surface",
        "dash-score", "dash-what-changed", "dash-compliance",
        "dash-reports", "dash-advisor", "dash-integrations",
        "dash-team", "dash-settings", "dash-tools"
    ]
    for sec in expected_sections:
        assert f'id="{sec}"' in html, f"Missing section {sec}"


def test_api_compliance(client):
    """Verifies compliance mappings and 24-point checklist evaluation."""
    res = client.get("/api/compliance")
    assert res.status_code == 200
    data = res.get_json()
    assert "mapping" in data
    assert "checklist" in data
    assert data["checklist"]["total_count"] == 24
    assert data["checklist"]["passed_count"] >= 0


def test_api_assets(client):
    """Verifies asset inventory aggregation."""
    res = client.get("/api/assets")
    assert res.status_code == 200
    data = res.get_json()
    assert "assets" in data


def test_api_team_and_integrations(client):
    """Verifies team members and integrations management."""
    # Team
    res = client.get("/api/team/members")
    assert res.status_code == 200
    assert "team_members" in res.get_json()

    # Integrations
    res_int = client.get("/api/integrations")
    assert res_int.status_code == 200
    assert "settings" in res_int.get_json()

    # Test alert
    res_alert = client.post("/api/integrations/test", json={"target_url": ""})
    assert res_alert.status_code == 200
    assert res_alert.get_json()["dispatched"] is True


def test_prioritizer_business_risk():
    """Verifies business risk score calculation and fix card generation."""
    dummy_finding = {
        "id": "F-CRIT-01",
        "title": "Exposed Cloud Secret Key",
        "category": "secrets",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED"
    }
    cards = prioritizer.prioritize_findings([dummy_finding])
    assert len(cards) == 1
    assert cards[0]["risk_score"] == 100
    assert "why_this_matters" in cards[0]
    assert "what_to_do" in cards[0]
    assert "ai_prompt" in cards[0]
