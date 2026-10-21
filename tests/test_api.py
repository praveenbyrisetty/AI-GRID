"""
Integration Tests for AI-GRID REST API & Endpoints (v4.0)
"""

import json
import pytest
from server import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_status(client):
    """Verify /api/status returns 200, version 4.0.0, 6 dimensions, and legal disclaimer."""
    resp = client.get("/api/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["version"] == "4.0.0"
    assert data["dimensions"] == 6
    assert "evidence_tiers" in data
    assert "T1" in data["evidence_tiers"]
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


def test_api_questionnaire_audit(client):
    """Verify /api/audit/questionnaire accepts valid answers and persists to SQLite."""
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
    resp = client.post("/api/audit/questionnaire", json=payload)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert "audit_id" in data
    assert "scoring" in data["data"]
    assert "dimensions" in data["data"]


def test_api_questionnaire_input_validation(client):
    """Verify endpoint rejects malformed input."""
    # Not JSON
    resp = client.post("/api/audit/questionnaire", data="not json", content_type="text/plain")
    assert resp.status_code == 400

    # JSON not a dict
    resp = client.post("/api/audit/questionnaire", json=["not", "a", "dict"])
    assert resp.status_code == 400


def test_api_mcp_audit_empty_or_missing_body_rejected(client):
    """Verify /api/audit/mcp rejects missing or empty request bodies with 400."""
    # Empty body
    resp = client.post("/api/audit/mcp", json={})
    assert resp.status_code == 400
    assert "cannot be empty" in resp.get_json()["error"]

    # No JSON body
    resp = client.post("/api/audit/mcp", data="", content_type="application/json")
    assert resp.status_code == 400


def test_api_mcp_audit_validation(client):
    """Verify /api/audit/mcp rejects invalid profile name."""
    resp = client.post("/api/audit/mcp", json={"profile": "malicious_unregistered_profile"})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["success"] is False
    assert "Invalid demo profile" in data["error"]


def test_api_mcp_live_target_requires_authorization(client):
    """Verify live target commands require explicit 'authorized': true."""
    # Without authorized flag
    resp = client.post("/api/audit/mcp", json={
        "target_command": ["python", "demo_servers/good_server.py"]
    })
    assert resp.status_code == 403
    assert "require explicit authorization" in resp.get_json()["error"]


def test_api_mcp_live_target_command_validation(client):
    """Verify disallowed executables and shell metacharacters are rejected."""
    # Disallowed executable
    resp = client.post("/api/audit/mcp", json={
        "target_command": ["bash", "-c", "echo hello"],
        "authorized": True
    })
    assert resp.status_code == 400
    assert "not permitted" in resp.get_json()["error"]

    # Shell injection metacharacters
    resp = client.post("/api/audit/mcp", json={
        "target_command": ["python", "test.py; rm -rf /"],
        "authorized": True
    })
    assert resp.status_code == 400
    assert "disallowed shell character" in resp.get_json()["error"]


def test_api_mcp_demo_audit_execution(client):
    """Verify valid demo profile runs successfully and is labeled as DEMO_BENCHMARK."""
    resp = client.post("/api/audit/mcp", json={"demo_profile": "good"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True
    assert data["data"]["execution_mode"] == "DEMO_BENCHMARK"
    assert data["data"]["is_demo"] is True
    assert "scoring" in data["data"]
    assert "dimensions" in data["data"]


def test_api_audit_history_and_get(client):
    """Verify audit records can be retrieved by ID and listed from SQLite."""
    # Run a questionnaire audit
    resp = client.post("/api/audit/questionnaire", json={"answers": {"model_name": "HistoryTestAI"}})
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
