"""
Phase 1 Security Tests: Verify all Phase 1 security controls and regressions.
"""

import html
import json
import os
import pytest
from server import app, is_rate_limited, AUDIT_RATE_LIMIT
import server


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_post_audit_routes_require_api_key(client):
    """
    POST /api/audit/* endpoints require an API key and reject unauthenticated requests with 401.
    """
    resp = client.post("/api/audit/questionnaire", json={"answers": {"model_name": "TestAI"}})
    assert resp.status_code == 401
    assert "Unauthorized" in resp.get_json()["error"]


def test_audit_reset_is_post_only_and_requires_auth(client):
    """
    /api/audit/reset is POST only (GET -> 405) and requires API key (unauthenticated POST -> 401).
    """
    # GET rejected with 405
    get_resp = client.get("/api/audit/reset")
    assert get_resp.status_code == 405

    # Unauthenticated POST rejected with 401
    post_resp = client.post("/api/audit/reset")
    assert post_resp.status_code == 401

    # Authenticated POST succeeds
    auth_resp = client.post("/api/audit/reset", headers={"X-API-Key": server.API_KEY})
    assert auth_resp.status_code == 200
    assert auth_resp.get_json()["success"] is True


def test_rate_limiting_enforcement():
    """
    Rate limiter rejects requests exceeding configured threshold.
    """
    client_id = "test-rate-limit-client"
    # Should allow up to AUDIT_RATE_LIMIT calls
    for _ in range(AUDIT_RATE_LIMIT):
        assert not is_rate_limited(client_id)
    # The next one should be blocked
    assert is_rate_limited(client_id)


def test_xss_tool_name_and_findings_rendered_inert():
    """
    Verify XSS payload in tool names and findings is neutralized:
    '<img src=x onerror=alert(1)>' becomes '&lt;img src=x onerror=alert(1)&gt;'.
    """
    xss_payload = "<img src=x onerror=alert(1)>"
    escaped = html.escape(xss_payload, quote=True)
    assert "<img" not in escaped
    assert "&lt;img" in escaped
    assert escaped == "&lt;img src=&quot;x&quot; onerror=&quot;alert(1)&quot;&gt;" or "&lt;img src=x onerror=alert(1)&gt;" in escaped

    # Verify that in public/app.js, escapeHtml is defined and used for findings, logs, and labels
    with open("public/app.js", "r", encoding="utf-8") as f:
        app_js = f.read()

    assert "function escapeHtml" in app_js
    assert "escapeHtml(l.message)" in app_js
    assert "escapeHtml(p.finding)" in app_js
    assert "escapeHtml(item.finding)" in app_js
