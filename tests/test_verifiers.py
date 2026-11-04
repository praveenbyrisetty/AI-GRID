"""
Unit and Integration Tests for AI-GRID Empirical Evidence Verifiers (v5.0)
Testing all 5 verifiers, edge cases, security controls, and audit integration.
"""

import hashlib
import json
import io
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

from verifiers import (
    verify_fairness,
    verify_dependencies,
    verify_tls,
    verify_log_integrity,
    verify_robustness,
    _is_ssrf_blocked_ip,
)
from server import app
from audit_store import AuditStore


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


# =========================================================================
# 1. FAIRNESS VERIFIER TESTS
# =========================================================================
def test_verify_fairness_high_conformance():
    """DIR >= 0.80 and |SPD| <= 0.10 yields verified_score = 1.0."""
    # 100 male (privileged), 100 female (unprivileged)
    # male: 80 favorable (p_fav_priv = 0.80), female: 72 favorable (p_fav_unpriv = 0.72)
    # DIR = 0.72 / 0.80 = 0.90 >= 0.80; SPD = 0.72 - 0.80 = -0.08, |SPD| <= 0.10
    rows = ["protected_attribute,y_true,y_pred"]
    for _ in range(80):
        rows.append("male,1,1")
    for _ in range(20):
        rows.append("male,0,0")
    for _ in range(72):
        rows.append("female,1,1")
    for _ in range(28):
        rows.append("female,0,0")

    csv_data = "\n".join(rows)
    res = verify_fairness(csv_data, privileged_value="male")
    assert res["verified_score"] == 1.0
    assert res["claim_supported"] is True
    assert res["metrics"]["disparate_impact_ratio"] == 0.90
    assert res["metrics"]["statistical_parity_difference"] == -0.08
    assert res["dimension"] == "Fairness & Non-Discrimination"


def test_verify_fairness_partial_conformance():
    """DIR >= 0.70 and |SPD| <= 0.15 yields verified_score = 0.5."""
    # male: 80/100 (0.80), female: 60/100 (0.60)
    # DIR = 0.60 / 0.80 = 0.75; SPD = -0.20 -> wait, |SPD| is 0.20 > 0.15.
    # Let's adjust: male 70/100 (0.70), female 50/100 -> DIR = 0.50/0.70 = 0.714, SPD = -0.14 (|SPD| <= 0.15)
    rows = ["protected_attribute,y_true,y_pred"]
    for _ in range(50):
        rows.append("male,1,1")
    for _ in range(50):
        rows.append("male,0,0")
    for _ in range(36):
        rows.append("female,1,1")
    for _ in range(64):
        rows.append("female,0,0")

    csv_data = "\n".join(rows)
    res = verify_fairness(csv_data, privileged_value="male")
    assert res["verified_score"] == 0.5
    assert res["claim_supported"] is False
    assert 0.70 <= res["metrics"]["disparate_impact_ratio"] <= 0.75
    assert abs(res["metrics"]["statistical_parity_difference"]) <= 0.15


def test_verify_fairness_disparate_impact_failure():
    """Severe disparate impact (DIR < 0.70) yields verified_score = 0.0."""
    rows = ["protected_attribute,y_true,y_pred"]
    for _ in range(90):
        rows.append("male,1,1")
    for _ in range(10):
        rows.append("male,0,0")
    for _ in range(20):
        rows.append("female,1,1")
    for _ in range(80):
        rows.append("female,0,0")

    csv_data = "\n".join(rows)
    res = verify_fairness(csv_data, privileged_value="male")
    assert res["verified_score"] == 0.0
    assert res["claim_supported"] is False


def test_verify_fairness_edge_cases():
    """Empty CSV and missing columns return 0.0 with clear error details."""
    # Empty
    res_empty = verify_fairness("")
    assert res_empty["verified_score"] == 0.0
    assert "Empty" in res_empty["details"]

    # Missing columns
    res_bad_cols = verify_fairness("gender,income,score\nmale,50000,700")
    assert res_bad_cols["verified_score"] == 0.0
    assert "Missing required CSV columns" in res_bad_cols["details"]

    # No unprivileged group
    res_single = verify_fairness("protected_attribute,y_true,y_pred\nmale,1,1\nmale,0,0")
    assert res_single["verified_score"] == 0.0
    assert "Both privileged and unprivileged" in res_single["details"]


# =========================================================================
# 2. DEPENDENCIES VERIFIER TESTS
# =========================================================================
def test_verify_dependencies_cyclonedx_clean():
    """Valid CycloneDX with no high CVSS vulnerabilities yields 1.0."""
    cyclonedx_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"name": "requests", "version": "2.31.0"},
            {"name": "click", "version": "8.1.7"},
            {"name": "pydantic", "version": "2.5.0"}
        ]
    }
    res = verify_dependencies(json.dumps(cyclonedx_sbom))
    assert res["verified_score"] == 1.0
    assert res["claim_supported"] is True
    assert res["metrics"]["format"] == "CycloneDX"
    assert res["metrics"]["high_severity_vulnerabilities_count"] == 0


def test_verify_dependencies_cyclonedx_with_vulnerabilities():
    """CycloneDX containing a high CVSS vulnerability (e.g. TorchServe / torch) yields 0.5."""
    cyclonedx_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"name": "torch", "version": "1.13.0"},
            {"name": "requests", "version": "2.31.0"}
        ]
    }
    res = verify_dependencies(json.dumps(cyclonedx_sbom))
    assert res["verified_score"] == 0.5
    assert res["claim_supported"] is False
    assert res["metrics"]["high_severity_vulnerabilities_count"] > 0


def test_verify_dependencies_requirements_only():
    """Plain requirements.txt without CycloneDX yields at most 0.5."""
    req_text = "requests==2.31.0\nclick==8.1.7\npydantic>=2.0.0\n"
    res = verify_dependencies(req_text)
    assert res["verified_score"] == 0.5
    assert res["metrics"]["format"] == "requirements.txt"


def test_verify_dependencies_edge_cases():
    """Empty or invalid content handled safely."""
    res_empty = verify_dependencies("")
    assert res_empty["verified_score"] == 0.0
    assert "Empty" in res_empty["details"]

    res_comment_only = verify_dependencies("# Just a comment\n# Another comment\n")
    assert res_comment_only["verified_score"] == 0.0


# =========================================================================
# 3. TLS VERIFIER & SSRF DEFENSE TESTS
# =========================================================================
def test_ssrf_ip_filtering():
    """Verify that private, loopback, link-local, and cloud metadata addresses are rejected."""
    blocked_ips = [
        "127.0.0.1",
        "127.0.0.2",
        "::1",
        "10.0.0.5",
        "172.16.0.1",
        "192.168.1.100",
        "169.254.169.254",  # AWS/GCP metadata
        "169.254.1.1",      # Link-local
        "224.0.0.1",        # Multicast
        "0.0.0.0",
    ]
    for ip in blocked_ips:
        blocked, reason = _is_ssrf_blocked_ip(ip)
        assert blocked is True, f"IP {ip} should have been blocked by SSRF filter!"

    # Public IP should pass
    blocked, _ = _is_ssrf_blocked_ip("8.8.8.8")
    assert blocked is False
    blocked, _ = _is_ssrf_blocked_ip("104.26.10.228")
    assert blocked is False


def test_verify_tls_port_restriction():
    """Non-standard ports (e.g., 80, 22, 8080) are rejected for TLS verification."""
    res = verify_tls("example.com", port=80)
    assert res["verified_score"] == 0.0
    assert "Security restriction" in res["details"]

    res_ssh = verify_tls("example.com", port=22)
    assert res_ssh["verified_score"] == 0.0


def test_verify_tls_ssrf_rejection():
    """Resolving to localhost or internal network trips SSRF protection."""
    res = verify_tls("localhost", port=443)
    assert res["verified_score"] == 0.0
    assert "SSRF Protection" in res["details"]

    res_internal = verify_tls("127.0.0.1", port=443)
    assert res_internal["verified_score"] == 0.0
    assert "SSRF Protection" in res_internal["details"]


def test_verify_tls_mock_handshake_scores():
    """Verify scoring logic for TLS 1.3 (1.0), TLS 1.2 (0.6), and expired certificates (0.0)."""
    future_date = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")
    past_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")

    # Mock socket and ssl
    mock_ssock = MagicMock()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.getpeercert.return_value = {"notAfter": future_date}

    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]), \
         patch("socket.create_connection"), \
         patch("ssl.create_default_context") as mock_ctx:

        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock

        # 1. TLS 1.3 + valid cert -> 1.0
        res = verify_tls("example.com", port=443, client_ip="test-client-1")
        assert res["verified_score"] == 1.0
        assert res["claim_supported"] is True

        # 2. TLS 1.2 + valid cert -> 0.6
        mock_ssock.version.return_value = "TLSv1.2"
        res_12 = verify_tls("example.com", port=443, client_ip="test-client-2")
        assert res_12["verified_score"] == 0.6
        assert res_12["claim_supported"] is False

        # 3. TLS 1.3 + expired cert -> 0.0
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.getpeercert.return_value = {"notAfter": past_date}
        res_exp = verify_tls("example.com", port=443, client_ip="test-client-3")
        assert res_exp["verified_score"] == 0.0


# =========================================================================
# 4. LOG INTEGRITY VERIFIER TESTS
# =========================================================================
def test_verify_log_integrity_valid_chain():
    """Unbroken SHA-256 hash chain starting from GENESIS yields 1.0."""
    entry1_data = {"action": "model_inference", "user": "alice", "prediction": 1}
    c_data1 = json.dumps(entry1_data, sort_keys=True, separators=(',', ':'))
    hash1 = hashlib.sha256(("GENESIS" + c_data1).encode("utf-8")).hexdigest()

    entry2_data = {"action": "guardrail_check", "status": "passed"}
    c_data2 = json.dumps(entry2_data, sort_keys=True, separators=(',', ':'))
    hash2 = hashlib.sha256((hash1 + c_data2).encode("utf-8")).hexdigest()

    lines = [
        json.dumps({"prev_hash": "GENESIS", "data": entry1_data, "hash": hash1}),
        json.dumps({"prev_hash": hash1, "data": entry2_data, "hash": hash2}),
    ]
    log_content = "\n".join(lines)

    res = verify_log_integrity(log_content)
    assert res["verified_score"] == 1.0
    assert res["claim_supported"] is True
    assert res["metrics"]["verified_records"] == 2


def test_verify_log_integrity_zero_genesis():
    """Hash chain starting from 64 zeros is valid and yields 1.0."""
    genesis = "0" * 64
    entry_data = {"event": "startup"}
    c_data = json.dumps(entry_data, sort_keys=True, separators=(',', ':'))
    h = hashlib.sha256((genesis + c_data).encode("utf-8")).hexdigest()

    log_content = json.dumps({"prev_hash": genesis, "data": entry_data, "hash": h})
    res = verify_log_integrity(log_content)
    assert res["verified_score"] == 1.0


def test_verify_log_integrity_tamper_detected():
    """Data mutation breaking the SHA-256 digest is detected and yields 0.0."""
    entry1_data = {"action": "model_inference", "prediction": 1}
    c_data1 = json.dumps(entry1_data, sort_keys=True, separators=(',', ':'))
    hash1 = hashlib.sha256(("GENESIS" + c_data1).encode("utf-8")).hexdigest()

    # Tamper with the data without recomputing the hash
    tampered_entry = {"prev_hash": "GENESIS", "data": {"action": "model_inference", "prediction": 999}, "hash": hash1}

    res = verify_log_integrity(json.dumps(tampered_entry))
    assert res["verified_score"] == 0.0
    assert res["claim_supported"] is False
    assert "Cryptographic tamper detected" in res["details"]


def test_verify_log_integrity_broken_link():
    """Line 2 with mismatched prev_hash is detected and yields 0.0."""
    line1 = json.dumps({"prev_hash": "GENESIS", "data": "first", "hash": "abc"})
    line2 = json.dumps({"prev_hash": "mismatched_hash", "data": "second", "hash": "def"})
    res = verify_log_integrity(f"{line1}\n{line2}")
    assert res["verified_score"] == 0.0


# =========================================================================
# 5. ROBUSTNESS VERIFIER TESTS
# =========================================================================
def test_verify_robustness_drop_thresholds():
    """Verifies drop <= 0.05 -> 1.0, drop <= 0.15 -> 0.5, and drop > 0.15 -> 0.0."""
    # 1. 2% drop: 100 samples, 100 clean correct, 98 perturbed correct
    rows1 = ["clean_prediction,perturbed_prediction,ground_truth"]
    for _ in range(98):
        rows1.append("1,1,1")
    for _ in range(2):
        rows1.append("1,0,1")
    res1 = verify_robustness("\n".join(rows1))
    assert res1["verified_score"] == 1.0
    assert res1["claim_supported"] is True
    assert res1["metrics"]["accuracy_drop_pct"] == 2.0

    # 2. 10% drop: 100 clean correct, 90 perturbed correct -> drop 0.10 -> 0.5
    rows2 = ["clean_prediction,perturbed_prediction,ground_truth"]
    for _ in range(90):
        rows2.append("1,1,1")
    for _ in range(10):
        rows2.append("1,0,1")
    res2 = verify_robustness("\n".join(rows2))
    assert res2["verified_score"] == 0.5
    assert res2["claim_supported"] is False

    # 3. 25% drop: 100 clean correct, 75 perturbed correct -> drop 0.25 -> 0.0
    rows3 = ["clean_prediction,perturbed_prediction,ground_truth"]
    for _ in range(75):
        rows3.append("1,1,1")
    for _ in range(25):
        rows3.append("1,0,1")
    res3 = verify_robustness("\n".join(rows3))
    assert res3["verified_score"] == 0.0


def test_verify_robustness_edge_cases():
    """Empty or malformed CSV handled safely."""
    assert verify_robustness("")["verified_score"] == 0.0
    assert verify_robustness("col1,col2\n1,2")["verified_score"] == 0.0


# =========================================================================
# 6. INTEGRATION TESTS (API ROUTES & ATTESTATION GAP)
# =========================================================================
def test_api_verify_endpoints(client):
    """Test all /api/verify/<module> routes over HTTP."""
    # 1. Fairness
    csv_data = "protected_attribute,y_true,y_pred\nmale,1,1\nmale,0,0\nfemale,1,1\nfemale,0,0\n"
    resp = client.post("/api/verify/fairness", json={"csv_data": csv_data, "privileged_value": "male"})
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True
    assert resp.get_json()["data"]["verified_score"] == 1.0

    # 2. Dependencies
    req_txt = "requests==2.31.0\n"
    resp = client.post("/api/verify/dependencies", json={"content": req_txt})
    assert resp.status_code == 200
    assert resp.get_json()["data"]["metrics"]["format"] == "requirements.txt"

    # 3. Log Integrity
    genesis = "0" * 64
    d = {"test": 1}
    cd = json.dumps(d, sort_keys=True, separators=(',', ':'))
    h = hashlib.sha256((genesis + cd).encode("utf-8")).hexdigest()
    log_jsonl = json.dumps({"prev_hash": genesis, "data": d, "hash": h})
    resp = client.post("/api/verify/log_integrity", json={"content": log_jsonl})
    assert resp.status_code == 200
    assert resp.get_json()["data"]["verified_score"] == 1.0

    # 4. Robustness
    rob_csv = "clean_prediction,perturbed_prediction,ground_truth\n1,1,1\n0,0,0\n"
    resp = client.post("/api/verify/robustness", json={"csv_data": rob_csv})
    assert resp.status_code == 200
    assert resp.get_json()["data"]["verified_score"] == 1.0

    # 5. Invalid module returns 400
    resp_bad = client.post("/api/verify/nonexistent", json={})
    assert resp_bad.status_code == 400


def test_questionnaire_audit_with_verified_evidence_and_gap(client):
    """
    Submitting questionnaire answers WITH verified_evidence:
    - Overrides item score with verified score
    - Upgrades evidence tier to T1 (weight 1.0)
    - Computes attestation_gap between claimed and verified assurance
    - Persists verified evidence into SQLite audit_evidence table
    """
    answers = {
        "model_name": "VerifiedAuditAI",
        "domain": "finance",
        "architecture": "Gradient Boosted Trees",
        # Claim optimal answers on questionnaire (score 1.0 each)
        "q10_fairness_audit": "formal_audit",  # Claimed 1.0
        "q1_adversarial_tested": "comprehensive",         # Claimed 1.0
    }

    # Verified evidence provides poor score for fairness (e.g. 0.0) and high for robustness (1.0)
    verified_evidence = [
        {
            "module": "fairness",
            "item_id": "q10_fairness_audit",
            "dimension": "Fairness & Non-Discrimination",
            "verified_score": 0.0,  # Empirically failed fairness!
            "claim_supported": False,
            "details": "Empirical DIR = 0.55 failed compliance threshold."
        },
        {
            "module": "robustness",
            "item_id": "q1_adversarial_tested",
            "dimension": "Security & Robustness",
            "verified_score": 1.0,
            "claim_supported": True,
            "details": "Degradation drop 1.5% verified."
        }
    ]

    resp = client.post("/api/audit/questionnaire", json={
        "answers": answers,
        "verified_evidence": verified_evidence
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["success"] is True

    audit_data = data["data"]
    audit_id = data["audit_id"]

    # Verify Attestation Gap is reported
    assert "attestation_gap" in audit_data
    gap = audit_data["attestation_gap"]
    assert "Fairness & Non-Discrimination" in gap["dimensions"]

    # Fairness claimed score was 100.0, verified score is penalized by T1 weight 1.0!
    fair_gap = gap["dimensions"]["Fairness & Non-Discrimination"]
    assert fair_gap["claimed_score"] > fair_gap["verified_score"]
    assert fair_gap["gap"] > 0

    # Verify persistence into audit_evidence table
    store = AuditStore()
    with store._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_evidence WHERE audit_id = ?", (audit_id,))
        rows = cursor.fetchall()
        assert len(rows) == 2
        sources = [r["source"] for r in rows]
        assert "fairness" in sources
        assert "robustness" in sources
