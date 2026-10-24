"""
AI-GRID Web Server (v4.0)

Hosts REST APIs for Questionnaire-Based AI Governance & Compliance Auditing:
1. Structured Research-Grounded Questionnaire (QB4AIRA, EU AI Act, NIST AI 100-1)
2. EU AI Act Regulation (EU) 2024/1689 Article 9-15 Evaluation
3. NIST AI 100-1 (AI RMF) Function & Subcategory Crosswalk
4. OWASP LLM Top 10 & MITRE ATLAS Threat Crosswalk
5. Algorithmic Fairness & Disparate Impact Evaluation
6. Remediation Priority Ranker & Alpha Sensitivity Analysis
7. AI Supply Chain Vulnerability Scanner (CVE/EPSS Snapshot)
8. Google Model Card Generator (Mitchell et al., 2019)

Features:
- Strong input validation and size constraints on all endpoints
- Sanitized, safe client error responses (no internal traceback leakage)
- SQLite audit persistence via AuditStore (survives server restarts)
- Audit history and record retrieval APIs
- Explicit legal & regulatory disclaimers
"""

from collections import defaultdict
import hmac
import logging
import os
import secrets
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from aigrid_auditor import AIGRIDAuditor
from ai_profile_engine import get_questions, compute_aas_and_bottleneck
from audit_store import AuditStore
from compliance_engines import (
    compute_fairness_metrics,
    analyze_risk_cohorts,
    solve_remediation_priority,
    generate_google_model_card,
    scan_ai_vulnerabilities,
    get_dataset_catalog,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aigrid.server")

app = Flask(__name__, static_folder="public", static_url_path="")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB max payload limit

# Restrict CORS to trusted origins
_allowed_origins_env = os.environ.get("AIGRID_ALLOWED_ORIGINS", "")
if _allowed_origins_env:
    ALLOWED_ORIGINS = [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
else:
    ALLOWED_ORIGINS = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=False,
)

# API Key Authentication
API_KEY = os.environ.get("AIGRID_API_KEY")
if not API_KEY:
    API_KEY = secrets.token_hex(24)
    print(f"[SECURITY] Generated random API key: {API_KEY}")

# Rate Limiting for audit routes
AUDIT_RATE_LIMIT = int(os.environ.get("AIGRID_RATE_LIMIT", "30"))
AUDIT_RATE_WINDOW = 60.0  # seconds
_client_audit_timestamps: Dict[str, List[float]] = defaultdict(list)


def is_rate_limited(client_id: str) -> bool:
    now = time.time()
    timestamps = _client_audit_timestamps[client_id]
    valid = [t for t in timestamps if now - t < AUDIT_RATE_WINDOW]
    _client_audit_timestamps[client_id] = valid
    if len(valid) >= AUDIT_RATE_LIMIT:
        return True
    _client_audit_timestamps[client_id].append(now)
    return False


@app.before_request
def enforce_audit_security():
    """Enforces API key authentication and rate limiting on all POST /api/audit/* routes."""
    if request.method == "POST" and request.path.startswith("/api/audit/"):
        client_key = request.headers.get("X-API-Key")
        if not client_key:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                client_key = auth_header[7:].strip()
        if not client_key:
            client_key = request.cookies.get("aigrid_session")

        if not client_key or not hmac.compare_digest(client_key, API_KEY):
            return jsonify({
                "success": False,
                "error": "Unauthorized: Invalid or missing API Key for audit execution."
            }), 401

        if not app.config.get("TESTING"):
            client_ip = request.remote_addr or "unknown"
            if is_rate_limited(client_ip):
                return jsonify({
                    "success": False,
                    "error": "Rate limit exceeded. Please wait before submitting another audit."
                }), 429


auditor = AIGRIDAuditor()
store = AuditStore()

# In-memory working cache (backed by SQLite store)
last_audit_data: Dict[str, Any] = {}

DISCLAIMER_TEXT = (
    "AI-GRID assessments are technical indicators for governance risk evaluation and "
    "do not constitute formal legal advice or regulatory certification under the EU AI Act "
    "or other statutory frameworks."
)


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response


# ================================================================
# INPUT VALIDATION UTILITIES
# ================================================================
def validate_json_body() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Ensures request content is valid JSON object."""
    if not request.is_json:
        return None, "Request Content-Type must be application/json"
    try:
        body = request.get_json()
        if not isinstance(body, dict):
            return None, "JSON body must be a dictionary object"
        return body, None
    except Exception:
        return None, "Malformed JSON syntax in request body"


# ================================================================
# STATIC FRONTEND ROUTES
# ================================================================
@app.route("/")
def index():
    resp = send_from_directory("public", "index.html")
    if not app.config.get("TESTING"):
        resp.set_cookie("aigrid_session", API_KEY, httponly=False, samesite="Lax", max_age=86400)
    return resp


@app.route("/<path:path>")
def static_files(path):
    safe_path = os.path.normpath(path)
    if safe_path.startswith("..") or os.path.isabs(safe_path):
        return jsonify({"success": False, "error": "Invalid path"}), 400
    if safe_path == "api" or safe_path.startswith("api\\") or safe_path.startswith("api/"):
        return jsonify({"success": False, "error": "Not Found"}), 404

    full_path = os.path.join("public", safe_path)
    if os.path.exists(full_path) and os.path.isfile(full_path):
        return send_from_directory("public", safe_path)
    return send_from_directory("public", "index.html")


# ================================================================
# HEALTH & STATUS ENDPOINT
# ================================================================
@app.route("/api/status", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "AI-GRID Trust & Assurance Framework (Questionnaire Governance Engine)",
        "version": "4.0.0",
        "dimensions": 7,
        "question_bank_size": 35,
        "session_token": API_KEY,
        "evidence_tiers": {
            "T1": {"description": "Declared Architecture & Specifications", "weight": 1.0},
            "T2": {"description": "Benchmark & Technical Evidence Validation", "weight": 0.8},
            "T3": {"description": "Self-Attested Structured Questionnaire", "weight": 0.6},
        },
        "compliance_engines": [
            "Custom Fairness Metrics (DIR, SPD, Sample Reweighing)",
            "Rule-Based Risk Cohort Slicing",
            "Remediation Priority Ranker",
            "EU AI Act Article-by-Article Evaluation (Articles 9-15)",
            "NIST AI 100-1 Function & Subcategory Crosswalk",
            "OWASP LLM Top 10 Threat Crosswalk",
            "MITRE ATLAS Matrix Mapper",
            "AI Supply Chain Vulnerability Scanner (CVE/EPSS Snapshot)",
            "Google Model Card Generator (Mitchell et al., 2019)",
        ],
        "datasets": [
            "Statlog German Credit (UCI)",
            "Clinical Patient Safety Benchmark",
            "NIST NVD / EPSS AI Registry Snapshot",
        ],
        "disclaimer": DISCLAIMER_TEXT,
    })


# ================================================================
# QUESTIONNAIRE QUESTIONS ENDPOINT
# ================================================================
@app.route("/api/questions", methods=["GET"])
def get_question_list():
    try:
        questions = get_questions()
        steps = {}
        for q in questions:
            step = q["step"]
            if step not in steps:
                steps[step] = {"step": step, "title": q["step_title"], "questions": []}
            steps[step]["questions"].append(q)

        return jsonify({
            "success": True,
            "data": {
                "steps": list(steps.values()),
                "total_questions": len(questions),
                "identity_questions": sum(1 for q in questions if q.get("is_identity")),
                "scored_questions": sum(1 for q in questions if not q.get("is_identity")),
            },
        })
    except Exception as e:
        logger.exception("Failed to retrieve questions")
        return jsonify({"success": False, "error": "Internal error loading questions"}), 500


# ================================================================
# ENDPOINT: Questionnaire-based audit (Evidence Tier T3, weight 0.6)
# ================================================================
@app.route("/api/audit/questionnaire", methods=["POST"])
def run_questionnaire_audit():
    global last_audit_data
    body, err = validate_json_body()
    if err:
        return jsonify({"success": False, "error": err}), 400

    answers = body.get("answers", body)
    if not isinstance(answers, dict):
        return jsonify({"success": False, "error": "'answers' must be a JSON dictionary"}), 400

    try:
        results = auditor.run_questionnaire_audit(answers)
        results["disclaimer"] = DISCLAIMER_TEXT

        # Persist audit run to SQLite
        audit_id = store.save_audit(results)
        results["audit_id"] = audit_id

        last_audit_data = results
        return jsonify({"success": True, "data": results, "audit_id": audit_id})
    except Exception as e:
        logger.exception("Error executing questionnaire audit")
        return jsonify({"success": False, "error": "Failed to process questionnaire audit"}), 500


# ================================================================
# DEPRECATED / REMOVED MCP & COMPARISON ENDPOINTS (410 GONE)
# ================================================================
@app.route("/api/audit/mcp", methods=["POST"])
def mcp_removed():
    return jsonify({
        "success": False,
        "error": "MCP protocol probing has been removed. AI-GRID operates exclusively as a questionnaire-based governance auditing engine."
    }), 410


@app.route("/api/audit/compare", methods=["POST"])
def compare_removed():
    return jsonify({
        "success": False,
        "error": "Attestation Discrepancy comparison against MCP has been removed. Platform operates exclusively as a questionnaire-based governance engine."
    }), 410


# ================================================================
# ENDPOINT: Current Active Audit State
# ================================================================
@app.route("/api/audit/current", methods=["GET"])
def get_current_audit():
    global last_audit_data
    if last_audit_data and "dimensions" in last_audit_data:
        return jsonify({"success": True, "active": True, "data": last_audit_data})

    # Fallback to latest stored audit
    latest = store.get_latest_audit()
    if latest and "dimensions" in latest:
        last_audit_data = latest
        return jsonify({"success": True, "active": True, "data": latest})

    return jsonify({"success": True, "active": False, "data": None})


# ================================================================
# ENDPOINT: Audit History and Records (SQLite Persistence)
# ================================================================
@app.route("/api/audit/history", methods=["GET"])
def get_audit_history():
    try:
        limit = min(100, max(1, int(request.args.get("limit", 20))))
        history = store.list_audits(limit=limit)
        return jsonify({"success": True, "count": len(history), "data": history})
    except Exception as e:
        logger.exception("Error listing audit history")
        return jsonify({"success": False, "error": "Failed to load audit history"}), 500


@app.route("/api/audit/<audit_id>", methods=["GET"])
def get_audit_by_id(audit_id: str):
    try:
        audit = store.get_audit(audit_id)
        if not audit:
            return jsonify({"success": False, "error": f"Audit {audit_id} not found"}), 404
        return jsonify({"success": True, "data": audit})
    except Exception as e:
        logger.exception(f"Error fetching audit {audit_id}")
        return jsonify({"success": False, "error": "Failed to retrieve audit"}), 500


# ================================================================
# ENDPOINT: Reset Audit State to Standby
# ================================================================
@app.route("/api/audit/reset", methods=["GET", "POST"])
def reset_audit_state():
    if request.method != "POST":
        return jsonify({"success": False, "error": "Method Not Allowed. /api/audit/reset requires POST."}), 405
    global last_audit_data
    last_audit_data = {}
    try:
        store.clear_all()
    except Exception as e:
        logger.warning(f"Store clear_all exception during reset: {e}")
    logger.info("Audit state, cache, and persistent store reset to clean standby.")
    return jsonify({
        "success": True,
        "message": "Platform reset complete: all audit caches and persistent records cleared.",
    })


# ================================================================
# ENDPOINT: Google Model Card Generator (Mitchell et al., 2019)
# ================================================================
@app.route("/api/model-card", methods=["GET", "POST"])
def get_model_card():
    global last_audit_data
    audit_data = None
    if request.is_json:
        body, _ = validate_json_body()
        if body and body.get("dimensions"):
            audit_data = body

    if not audit_data:
        audit_data = last_audit_data or store.get_latest_audit()

    if not audit_data or not audit_data.get("dimensions"):
        return jsonify({
            "success": False,
            "error": "No audit has been conducted yet. Please complete an audit first.",
        }), 404

    try:
        card = audit_data.get("model_card") or generate_google_model_card(audit_data)
        return jsonify({"success": True, "data": card})
    except Exception as e:
        logger.exception("Error generating Model Card")
        return jsonify({"success": False, "error": "Failed to generate Model Card"}), 500


# ================================================================
# ENDPOINT: Remediation Priority Ranker
# ================================================================
@app.route("/api/rai/counterfactual", methods=["POST"])
def get_counterfactual():
    global last_audit_data
    body = {}
    if request.is_json:
        parsed, _ = validate_json_body()
        if parsed:
            body = parsed

    try:
        target_score = float(body.get("target_score", 76.0))
        target_score = max(10.0, min(100.0, target_score))

        audit_data = body.get("audit_data") or last_audit_data or store.get_latest_audit()
        if not audit_data:
            return jsonify({
                "success": False,
                "error": "No audit data available. Please complete an audit first.",
            }), 404

        raw_aas = audit_data.get("scoring", {}).get("aas_score")
        current_aas = float(raw_aas) if raw_aas is not None else None
        dimensions = audit_data.get("dimensions", {})
        findings = audit_data.get("remediation_plan", [])

        cf_res = solve_remediation_priority(current_aas, dimensions, findings, target_score)
        return jsonify({"success": True, "data": cf_res})
    except Exception as e:
        logger.exception("Error solving remediation priority")
        return jsonify({"success": False, "error": "Failed to calculate remediation priorities"}), 500


# ================================================================
# ENDPOINT: CVSS, EPSS & CVE AI Supply Chain Vulnerability Scanner
# ================================================================
@app.route("/api/security/cve-scan", methods=["GET", "POST"])
def run_cve_scan():
    global last_audit_data
    body = {}
    if request.is_json:
        parsed, _ = validate_json_body()
        if parsed:
            body = parsed

    try:
        domain = str(body.get(
            "domain",
            last_audit_data.get("model_metadata", {}).get("domain", "General Purpose AI")
        ))
        asset_criticality = str(body.get("asset_criticality", "Mission-Critical"))
        vuln_res = scan_ai_vulnerabilities(domain=domain, asset_criticality=asset_criticality)
        return jsonify({"success": True, "data": vuln_res})
    except Exception as e:
        logger.exception("Error executing CVE scan")
        return jsonify({"success": False, "error": "Failed to execute vulnerability scan"}), 500


# ================================================================
# ENDPOINT: Empirical Datasets Catalog
# ================================================================
@app.route("/api/datasets", methods=["GET"])
def get_datasets():
    try:
        catalog = get_dataset_catalog()
        return jsonify({"success": True, "data": catalog})
    except Exception as e:
        logger.exception("Error fetching datasets catalog")
        return jsonify({"success": False, "error": "Failed to load datasets"}), 500


# ================================================================
# ENDPOINT: Alpha Sensitivity Curve Analysis
# ================================================================
@app.route("/api/analysis/sensitivity", methods=["POST"])
def get_sensitivity_analysis():
    global last_audit_data
    body = {}
    if request.is_json:
        parsed, _ = validate_json_body()
        if parsed:
            body = parsed

    try:
        dimensions = body.get("dimensions") or last_audit_data.get("dimensions", {})
        if not dimensions and store.get_latest_audit():
            dimensions = store.get_latest_audit().get("dimensions", {})

        if not dimensions:
            return jsonify({"success": False, "error": "No dimension scores available."}), 400

        res = compute_aas_and_bottleneck(dimensions, alpha=0.6)
        return jsonify({"success": True, "data": res.get("sensitivity_curve", [])})
    except Exception as e:
        logger.exception("Error computing sensitivity curve")
        return jsonify({"success": False, "error": "Failed to compute sensitivity curve"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("AIGRID_HOST", "127.0.0.1")
    print("=================================================================")
    print(f" AI-GRID Trust Assurance & GRC Server (v4.0) Running on port {port}")
    print(f" Dashboard URL: http://{host}:{port}")
    print(" Architecture: Questionnaire-Based AI Governance & Compliance Auditing")
    print(" Frameworks: EU AI Act (Arts 9-15) | NIST AI 100-1 | OWASP LLM Top 10")
    print(" Persistence: SQLite (data/aigrid_audits.db)")
    print("=================================================================")
    app.run(host=host, port=port, debug=False)
