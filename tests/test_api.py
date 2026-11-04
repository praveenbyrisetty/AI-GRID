"""
Integration Tests for AI-GRID REST API & Endpoints (v4.0)
Questionnaire-Based AI Governance & Compliance Auditing Platform
"""

import json
import pytest
from server import app
import server


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_headers():
    return {"X-API-Key": server.API_KEY}


def test_api_status(client):
    """Verify /api/status returns 200, version 4.0.0, 7 dimensions, and legal disclaimer."""
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["version"] == "4.0.0"
    assert data["dimensions"] == 7
    assert "evidence_tiers" in data
    assert "disclaimer" in data


def test_api_security_headers(client):
    """Verify standard security headers are applied to API responses."""
    resp = client.get("/api/status")
    assert resp.status_code == 200
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "Content-Security-Policy" in resp.headers


def test_api_questions(client):
    """Verify /api/questions returns question banks organized in steps."""
    resp = client.get("/api/questions")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["data"]["total_questions"] >= 30


def test_api_questionnaire_audit(client, auth_headers):
    """Verify /api/audit/questionnaire accepts valid answers with API key and persists to SQLite."""
    payload = {
        "answers": {
            "model_name": "Diagnostic-AI",
            "domain": "healthcare",
            "architecture": "ResNet-50",
            "q1_threat_model": "formal_stride",
            "q2_adversarial_testing": "frequent",
            "q22_autonomy_level": "human_in_loop",
        }
    }
    resp = client.post("/api/audit/questionnaire", json=payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "audit_id" in data
    assert "scoring" in data["data"]
    assert "dimensions" in data["data"]
    assert "compliance" in data["data"]


def test_api_questionnaire_input_validation(client, auth_headers):
    """Verify endpoint rejects malformed input."""
    # Not JSON
    resp = client.post("/api/audit/questionnaire", data="not json", content_type="text/plain", headers=auth_headers)
    assert resp.status_code == 400

    # JSON not a dict
    resp = client.post("/api/audit/questionnaire", json=["not", "a", "dict"], headers=auth_headers)
    assert resp.status_code == 400


def test_api_mcp_returns_410_gone(client, auth_headers):
    """Verify /api/audit/mcp returns 410 Gone indicating removal."""
    resp = client.post("/api/audit/mcp", json={"demo_profile": "good"}, headers=auth_headers)
    assert resp.status_code == 410
    data = resp.get_json()
    assert data["success"] is False
    assert "removed" in data["error"].lower()


def test_api_audit_history_and_get(client, auth_headers):
    """Verify audit records can be retrieved by ID and listed from SQLite."""
    # Run a questionnaire audit
    resp = client.post("/api/audit/questionnaire", json={"answers": {"model_name": "HistoryTestAI"}}, headers=auth_headers)
    assert resp.status_code == 200
    audit_id = resp.get_json()["audit_id"]

    # Retrieve history
    hist_resp = client.get("/api/audit/history")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.get_json()
    assert hist_data["success"] is True
    assert any(a["audit_id"] == audit_id for a in hist_data["data"])

    # Retrieve specific audit
    get_resp = client.get(f"/api/audit/{audit_id}")
    assert get_resp.status_code == 200
    assert get_resp.get_json()["data"]["model_metadata"]["model_name"] == "HistoryTestAI"


def test_api_model_card_and_remediation(client, auth_headers):
    """Verify model card generator and remediation ranker endpoints."""
    # Run audit first
    resp = client.post("/api/audit/questionnaire", json={"answers": {"model_name": "ModelCardAI", "domain": "finance"}}, headers=auth_headers)
    assert resp.status_code == 200

    # Get model card
    card_resp = client.get("/api/model-card")
    assert card_resp.status_code == 200
    card_data = card_resp.get_json()
    assert card_data["success"] is True
    assert "json_schema" in card_data["data"]
    assert "markdown" in card_data["data"]
    assert "model_details" in card_data["data"]["json_schema"]

    # Remediation ranker
    rem_resp = client.post("/api/rai/counterfactual", json={"target_score": 80.0})
    assert rem_resp.status_code == 200
    rem_data = rem_resp.get_json()
    assert rem_data["success"] is True


def test_api_sensitivity_analysis(client, auth_headers):
    """Verify alpha sensitivity curve analysis endpoint."""
    dims = {
        "Safety & Reliability": 85.0,
        "Transparency & Explainability": 70.0,
        "Fairness & Non-Discrimination": 80.0,
        "Privacy & Data Governance": 90.0,
        "Human Oversight & Accountability": 65.0,
        "Security & Robustness": 75.0,
    }
    resp = client.post("/api/analysis/sensitivity", json={"dimensions": dims})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert len(data["data"]) == 9
