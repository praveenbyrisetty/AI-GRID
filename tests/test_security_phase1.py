"""
Phase 1 Security Tests: Verify all Phase 1 security controls and regressions.
"""

import html
import json
import os
import pytest
from server import app, is_rate_limited, AUDIT_RATE_LIMIT
from mcp_client import get_minimal_env


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
    import server
    auth_resp = client.post("/api/audit/reset", headers={"X-API-Key": server.API_KEY})
    assert auth_resp.status_code == 200
    assert auth_resp.get_json()["success"] is True


def test_mcp_audit_rejects_interpreter_flags_and_eval(client):
    """
    /api/audit/mcp rejects interpreter flags (-c, -m, -e, -r, --eval) with 400.
    """
    import server
    headers = {"X-API-Key": server.API_KEY}

    flags_to_test = ["-c", "-m", "-e", "-r", "--eval"]
    for flag in flags_to_test:
        payload = {
            "target_command": ["python", flag, "import sys; sys.exit(0)"],
            "authorized": True
        }
        resp = client.post("/api/audit/mcp", json=payload, headers=headers)
        assert resp.status_code in (400, 403), f"Flag {flag} was not rejected: {resp.status_code}"
        assert "disallowed" in resp.get_json()["error"].lower()


def test_mcp_audit_rejects_unallowlisted_or_out_of_tree_scripts(client):
    """
    /api/audit/mcp rejects arbitrary scripts outside the allowlist or outside approved directory with 403.
    """
    import server
    headers = {"X-API-Key": server.API_KEY}

    # Path traversal
    payload1 = {
        "target_command": ["python", "../../etc/malicious_server.py"],
        "authorized": True
    }
    resp1 = client.post("/api/audit/mcp", json=payload1, headers=headers)
    assert resp1.status_code == 403

    # Unallowlisted script name
    payload2 = {
        "target_command": ["python", "random_unregistered_script.py"],
        "authorized": True
    }
    resp2 = client.post("/api/audit/mcp", json=payload2, headers=headers)
    assert resp2.status_code == 403


def test_client_authorized_flag_is_dropped_as_control(client):
    """
    The client-supplied 'authorized' flag is dropped as a control.
    An unapproved command is rejected regardless of 'authorized': True.
    """
    import server
    headers = {"X-API-Key": server.API_KEY}

    payload = {
        "target_command": ["python", "-m", "http.server"],
        "authorized": True
    }
    resp = client.post("/api/audit/mcp", json=payload, headers=headers)
    assert resp.status_code in (400, 403)


def test_mcp_audit_accepts_allowlisted_script(client):
    """
    /api/audit/mcp accepts allowlisted script in approved directory when authenticated.
    """
    import server
    headers = {"X-API-Key": server.API_KEY}

    payload = {
        "target_command": ["good_server.py"]
    }
    resp = client.post("/api/audit/mcp", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True


def test_minimal_environment_strips_sensitive_keys():
    """
    get_minimal_env prevents leakage of AIGRID_API_KEY and other sensitive credentials.
    """
    os.environ["AIGRID_API_KEY"] = "super-secret-api-token-12345"
    os.environ["SECRET_AWS_KEY"] = "secret-aws-key"
    try:
        clean_env = get_minimal_env()
        assert "AIGRID_API_KEY" not in clean_env
        assert "SECRET_AWS_KEY" not in clean_env
        assert clean_env.get("PYTHONUNBUFFERED") == "1"
    finally:
        os.environ.pop("AIGRID_API_KEY", None)
        os.environ.pop("SECRET_AWS_KEY", None)


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
