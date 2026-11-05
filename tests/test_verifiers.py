"""
Unit and Integration Tests for AI-GRID Empirical Evidence Verifiers (v5.0)
Testing all 5 verifiers, edge cases, security controls, and audit integration.
All external network calls are mocked; no real network used.
"""

import hashlib
import json
import urllib.error
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta, timezone

from verifiers import (
    _tls_rate_limits,
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
# 1. FAIRNESS VERIFIER TESTS (DETERMINISTIC 20-ROW CSV)
# =========================================================================
def test_verify_fairness_high_conformance():
    """
    Deterministic 20-row predictions CSV with hand-calculated DIR, SPD, and TPR gap (Equal Opportunity Difference).
    - 10 male (privileged), 10 female (unprivileged).
    - Privileged (male): 8 favorable (y_true=1, y_pred=1), 2 non-favorable (y_true=0, y_pred=0).
      p_fav_priv = 8/10 = 0.80.
      TPR_priv = 8 / 8 = 1.0.
    - Unprivileged (female): 7 favorable (y_true=1, y_pred=1), 3 non-favorable (y_true=0, y_pred=0).
      p_fav_unpriv = 7/10 = 0.70.
      TPR_unpriv = 7 / 7 = 1.0.
    - Hand-calculated metrics:
      DIR = 0.70 / 0.80 = 0.875 (>= 0.80 -> compliant)
      SPD = 0.70 - 0.80 = -0.100 (|SPD| <= 0.10 -> compliant)
      TPR gap = 1.0 - 1.0 = 0.000 (Equal Opportunity Difference)
    -> verified_score = 1.0, claim_supported = True.
    """
    rows = [
        "protected_attribute,y_true,y_pred",
        "male,1,1", "male,1,1", "male,1,1", "male,1,1",
        "male,1,1", "male,1,1", "male,1,1", "male,1,1",
        "male,0,0", "male,0,0",
        "female,1,1", "female,1,1", "female,1,1", "female,1,1",
        "female,1,1", "female,1,1", "female,1,1",
        "female,0,0", "female,0,0", "female,0,0",
    ]
    csv_data = "\n".join(rows)
    res = verify_fairness(csv_data, privileged_value="male")
    assert res["verified_score"] == 1.0
    assert res["claim_supported"] is True
    assert res["metrics"]["total_samples"] == 20
    assert res["metrics"]["disparate_impact_ratio"] == 0.875
    assert res["metrics"]["statistical_parity_difference"] == -0.1
    assert res["metrics"]["equal_opportunity_difference"] == 0.0
    assert res["dimension"] == "Fairness & Non-Discrimination"


def test_verify_fairness_partial_conformance():
    """DIR >= 0.70 and |SPD| <= 0.15 yields verified_score = 0.5."""
    # 50 male (0.80 fav), 50 female (0.58 fav)
    # DIR = 0.58 / 0.80 = 0.725 (>= 0.70); SPD = 0.58 - 0.80 = -0.22 -> wait, need |SPD| <= 0.15.
    # If male: 35/50 = 0.70; female: 25/50 = 0.50 -> DIR = 0.50/0.70 = 0.714, SPD = -0.20
    # If male: 30/60 = 0.50; female: 18/50 = 0.36 -> DIR = 0.72, SPD = -0.14 (|SPD| <= 0.15)
    rows = ["protected_attribute,y_true,y_pred"]
    for _ in range(30):
        rows.append("male,1,1")
    for _ in range(30):
        rows.append("male,0,0")
    for _ in range(18):
        rows.append("female,1,1")
    for _ in range(32):
        rows.append("female,0,0")

    csv_data = "\n".join(rows)
    res = verify_fairness(csv_data, privileged_value="male")
    assert res["verified_score"] == 0.5
    assert res["claim_supported"] is False
    assert 0.70 <= res["metrics"]["disparate_impact_ratio"] <= 0.75
    assert abs(res["metrics"]["statistical_parity_difference"]) <= 0.15


def test_verify_fairness_disparate_impact_failure():
    """Severe disparate impact (DIR < 0.70) yields verified_score = 0.0."""
    rows = [
        "protected_attribute,y_true,y_pred",
        "male,1,1", "male,1,1", "male,1,1", "male,1,1", "male,1,1",
        "male,1,1", "male,1,1", "male,1,1", "male,1,1", "male,0,0",
        "female,0,0", "female,0,0", "female,0,0", "female,0,0", "female,0,0",
        "female,0,0", "female,0,0", "female,0,0", "female,1,1", "female,1,1",
    ]
    csv_data = "\n".join(rows)
    res = verify_fairness(csv_data, privileged_value="male")
    assert res["verified_score"] == 0.0
    assert res["claim_supported"] is False


def test_verify_fairness_edge_cases():
    """Empty CSV and missing columns return 0.0 with clear error details."""
    res_empty = verify_fairness("")
    assert res_empty["verified_score"] == 0.0
    assert "Empty" in res_empty["details"]

    res_bad_cols = verify_fairness("gender,income,score\nmale,50000,700")
    assert res_bad_cols["verified_score"] == 0.0
    assert "Missing required CSV columns" in res_bad_cols["details"]

    res_single = verify_fairness("protected_attribute,y_true,y_pred\nmale,1,1\nmale,0,0")
    assert res_single["verified_score"] == 0.0
    assert "Both privileged and unprivileged" in res_single["details"]


# =========================================================================
# 2. DEPENDENCIES VERIFIER TESTS (OSV API WITH MOCKED HTTP)
# =========================================================================
@patch("urllib.request.urlopen")
def test_verify_dependencies_cyclonedx_clean(mock_urlopen):
    """Valid CycloneDX with no high CVSS vulnerabilities via OSV yields 1.0."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "results": [
            {"vulns": []},
            {"vulns": []}
        ]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    cyclonedx_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"name": "requests", "version": "2.31.0"},
            {"name": "click", "version": "8.1.7"}
        ]
    }
    res = verify_dependencies(json.dumps(cyclonedx_sbom))
    assert res["verified_score"] == 1.0
    assert res["claim_supported"] is True
    assert res["metrics"]["format"] == "CycloneDX"
    assert res["metrics"]["high_severity_count"] == 0
    assert mock_urlopen.called


@patch("urllib.request.urlopen")
def test_verify_dependencies_cyclonedx_with_vulnerabilities(mock_urlopen):
    """CycloneDX containing a high CVSS vulnerability (CVSS>=7.0 via OSV) yields 0.5."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "results": [
            {
                "vulns": [
                    {
                        "id": "GHSA-1234",
                        "severity": [{"type": "CVSS_V3", "score": "8.8"}],
                        "database_specific": {"severity": "HIGH"}
                    }
                ]
            }
        ]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    cyclonedx_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {"name": "torch", "version": "1.13.0"}
        ]
    }
    res = verify_dependencies(json.dumps(cyclonedx_sbom), claimed_value="formal_sbom")
    assert res["verified_score"] == 0.5
    assert res["claim_supported"] is False
    assert res["metrics"]["high_severity_count"] > 0
    assert res["metrics"]["highest_severity"] == 8.8


@patch("urllib.request.urlopen")
def test_verify_dependencies_requirements_only(mock_urlopen):
    """Plain requirements.txt without CycloneDX yields at most 0.5."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"results": [{"vulns": []}]}).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    req_text = "requests==2.31.0\nclick==8.1.7\n"
    res = verify_dependencies(req_text)
    assert res["verified_score"] == 0.5
    assert res["metrics"]["format"] == "requirements.txt"


@patch("urllib.request.urlopen")
def test_verify_dependencies_offline_fallback(mock_urlopen):
    """When OSV API is offline or lookup fails, returns lookup unavailable and preserves claimed score."""
    mock_urlopen.side_effect = urllib.error.URLError("Connection timed out")

    cyclonedx_sbom = {
        "bomFormat": "CycloneDX",
        "components": [{"name": "requests", "version": "2.31.0"}]
    }
    res = verify_dependencies(json.dumps(cyclonedx_sbom), claimed_value="formal_sbom")
    assert "vulnerability lookup unavailable" in res["status"]
    assert res["verified_score"] == 1.0  # claimed score preserved, never 0 due to network error!
    assert res["metrics"]["offline"] is True


def test_verify_dependencies_edge_cases():
    """Empty or comment-only content handled safely without network calls."""
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
    _tls_rate_limits.clear()
    """Mock socket and SSL handshake to test scoring rules."""
    mock_cert = {
        "notAfter": (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%b %d %H:%M:%S %Y GMT")
    }

    import socket as sock_mod
    mock_addr = [(sock_mod.AF_INET, sock_mod.SOCK_STREAM, 6, "", ("104.16.132.229", 443))]

    # 1. TLS 1.3 + valid cert -> 1.0
    with patch("socket.getaddrinfo", return_value=mock_addr), \
         patch("socket.create_connection") as mock_conn, \
         patch("ssl.create_default_context") as mock_ctx:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_sslsock = MagicMock()
        mock_sslsock.version.return_value = "TLSv1.3"
        mock_sslsock.getpeercert.return_value = mock_cert
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_sslsock

        res = verify_tls("cloudflare.com", port=443)
        assert res["verified_score"] == 1.0
        assert res["claim_supported"] is True
        assert res["metrics"]["tls_version"] == "TLSv1.3"

    # 2. TLS 1.2 + valid cert -> 0.6
    with patch("socket.getaddrinfo", return_value=mock_addr), \
         patch("socket.create_connection") as mock_conn, \
         patch("ssl.create_default_context") as mock_ctx:
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_sslsock = MagicMock()
        mock_sslsock.version.return_value = "TLSv1.2"
        mock_sslsock.getpeercert.return_value = mock_cert
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_sslsock

        res = verify_tls("legacy.example.com", port=443)
        assert res["verified_score"] == 0.6
        assert res["metrics"]["tls_version"] == "TLSv1.2"


# =========================================================================
# 4. LOG INTEGRITY VERIFIER TESTS
# =========================================================================
def test_verify_log_integrity_valid_chain():
    """Unbroken SHA-256 hash chain from GENESIS yields 1.0."""
    entries = []
    prev_hash = "GENESIS"
    for i in range(5):
        data = {"event": f"audit_action_{i}", "user": "compliance_officer"}
        canonical_data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        curr_hash = hashlib.sha256((prev_hash + canonical_data).encode("utf-8")).hexdigest()
        entries.append(json.dumps({
            "prev_hash": prev_hash,
            "data": data,
            "hash": curr_hash
        }))
        prev_hash = curr_hash

    content = "\n".join(entries)
    res = verify_log_integrity(content)
    assert res["verified_score"] == 1.0
    assert res["claim_supported"] is True
    assert res["metrics"]["verified_records"] == 5


def test_verify_log_integrity_zero_genesis():
    """Genesis using 64 zeros is valid."""
    genesis = "0" * 64
    data = {"system": "init"}
    canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
    h = hashlib.sha256((genesis + canonical).encode("utf-8")).hexdigest()
    line = json.dumps({"prev_hash": genesis, "data": data, "hash": h})
    res = verify_log_integrity(line)
    assert res["verified_score"] == 1.0


def test_verify_log_integrity_tamper_detected():
    """Tampered data field in middle of chain yields 0.0."""
    entries = []
    prev_hash = "GENESIS"
    for i in range(3):
        data = {"event": f"action_{i}"}
        canonical = json.dumps(data, sort_keys=True, separators=(',', ':'))
        curr_hash = hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
        if i == 1:
            data["event"] = "TAMPERED_ACTION"
        entries.append(json.dumps({
            "prev_hash": prev_hash,
            "data": data,
            "hash": curr_hash
        }))
        prev_hash = curr_hash

    res = verify_log_integrity("\n".join(entries))
    assert res["verified_score"] == 0.0
    assert res["claim_supported"] is False
    assert "tamper detected" in res["details"].lower()


def test_verify_log_integrity_broken_link():
    """Broken prev_hash link yields 0.0."""
    line1 = json.dumps({"prev_hash": "GENESIS", "data": "d1", "hash": hashlib.sha256(b"GENESISd1").hexdigest()})
    line2 = json.dumps({"prev_hash": "WRONG_PREV", "data": "d2", "hash": hashlib.sha256(b"WRONG_PREVd2").hexdigest()})
    res = verify_log_integrity(f"{line1}\n{line2}")
    assert res["verified_score"] == 0.0
    assert "broken chain" in res["details"].lower()


# =========================================================================
# 5. ROBUSTNESS VERIFIER TESTS
# =========================================================================
def test_verify_robustness_drop_thresholds():
    """Accuracy drop <= 5% -> 1.0; drop <= 15% -> 0.5; drop > 15% -> 0.0."""
    # 1. Zero drop: 100% clean, 100% perturbed -> drop 0.0 -> 1.0
    rows1 = ["clean_prediction,perturbed_prediction,ground_truth"]
    for _ in range(100):
        rows1.append("1,1,1")
    res1 = verify_robustness("\n".join(rows1))
    assert res1["verified_score"] == 1.0
    assert res1["claim_supported"] is True
    assert res1["metrics"]["accuracy_drop_pct"] == 0.0

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
@patch("urllib.request.urlopen")
def test_api_verify_endpoints(mock_urlopen, client):
    """Test all /api/verify/<module> routes over HTTP with mocked external calls."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"results": [{"vulns": []}]}).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

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
        "q10_fairness_audit": "formal_audit",
        "q1_adversarial_tested": "comprehensive",
    }

    verified_evidence = [
        {
            "module": "fairness",
            "item_id": "q10_fairness_audit",
            "dimension": "Fairness & Non-Discrimination",
            "verified_score": 0.0,
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

    assert "attestation_gap" in audit_data
    gap = audit_data["attestation_gap"]
    assert "Fairness & Non-Discrimination" in gap["dimensions"]

    fair_gap = gap["dimensions"]["Fairness & Non-Discrimination"]
    assert fair_gap["claimed_score"] > fair_gap["verified_score"]
    assert fair_gap["gap"] > 0

    store = AuditStore()
    with store._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_evidence WHERE audit_id = ?", (audit_id,))
        rows = cursor.fetchall()
        assert len(rows) == 2
        sources = [r["source"] for r in rows]
        assert "fairness" in sources
        assert "robustness" in sources
