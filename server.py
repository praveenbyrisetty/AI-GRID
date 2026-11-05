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
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from aigrid_auditor import AIGRIDAuditor
from ai_profile_engine import get_questions, compute_aas_and_bottleneck
from audit_store import AuditStore
from compliance_engines import (
    solve_remediation_priority,
    generate_google_model_card,
)
from verifiers import (
    verify_fairness,
    verify_dependencies,
    verify_tls,
    verify_log_integrity,
    verify_robustness,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aigrid.server")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(BASE_DIR, "public")

app = Flask(__name__, static_folder=PUBLIC_DIR, static_url_path="")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2MB max payload limit

# Configure CORS
_allowed_origins_env = os.environ.get("AIGRID_ALLOWED_ORIGINS", "").strip()
if _allowed_origins_env == "*":
    ALLOWED_ORIGINS = "*"
elif _allowed_origins_env:
    ALLOWED_ORIGINS = [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
else:
    ALLOWED_ORIGINS = "*"

CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=False,
)

# Authentication: None (Local/Demo deployment mode)

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


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "success": False,
        "error": "Payload exceeds 2 MB upload limit."
    }), 413


@app.before_request
def enforce_rate_limiting():
    """Enforces per-IP rate limiting on all POST requests."""
    if request.method == "POST":
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
    return send_from_directory(PUBLIC_DIR, "index.html")


@app.route("/<path:path>")
def static_files(path):
    safe_path = os.path.normpath(path)
    if safe_path.startswith("..") or os.path.isabs(safe_path):
        return jsonify({"success": False, "error": "Invalid path"}), 400
    if safe_path == "api" or safe_path.startswith("api\\") or safe_path.startswith("api/"):
        return jsonify({"success": False, "error": "Not Found"}), 404

    full_path = os.path.join(PUBLIC_DIR, safe_path)
    if os.path.exists(full_path) and os.path.isfile(full_path):
        return send_from_directory(PUBLIC_DIR, safe_path)
    return send_from_directory(PUBLIC_DIR, "index.html")


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
        "evidence_tiers": {
            "T1": {"description": "Declared Architecture & Specifications", "weight": 1.0},
            "T2": {"description": "Benchmark & Technical Evidence Validation", "weight": 0.8},
            "T3": {"description": "Self-Attested Structured Questionnaire", "weight": 0.6},
        },
        "compliance_engines": [
            "Custom Fairness Metrics (DIR, SPD from predictions)",
            "Remediation Priority Ranker",
            "EU AI Act Article-by-Article Evaluation (Articles 9-15)",
            "NIST AI 100-1 Function & Subcategory Crosswalk",
            "OWASP LLM Top 10 Threat Crosswalk",
            "MITRE ATLAS Matrix Mapper",
            "Google Model Card Generator (Mitchell et al., 2019)",
        ],
        "verifiers": [
            "fairness",
            "dependencies",
            "tls",
            "log-integrity",
            "robustness",
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
    except Exception:
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

    verified_evidence = body.get("verified_evidence", [])
    if not isinstance(verified_evidence, list):
        verified_evidence = []

    try:
        results = auditor.run_questionnaire_audit(answers, verified_evidence=verified_evidence)
        results["disclaimer"] = DISCLAIMER_TEXT

        # Persist audit run to SQLite
        audit_id = store.save_audit(results)
        results["audit_id"] = audit_id

        last_audit_data = results
        return jsonify({"success": True, "data": results, "audit_id": audit_id})
    except Exception:
        logger.exception("Error executing questionnaire audit")
        return jsonify({"success": False, "error": "Failed to process questionnaire audit"}), 500





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
# ENDPOINT: Empirical Evidence Verifiers (Tier T1, weight 1.0)
# ================================================================
ALLOWED_EXTENSIONS = {"csv", "json", "txt", "jsonl"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/api/verify/<module>", methods=["POST"])
def verify_module(module: str):
    valid_modules = {"fairness", "dependencies", "tls", "log_integrity", "robustness"}
    if module not in valid_modules:
        return jsonify({
            "success": False,
            "error": f"Invalid verifier module '{module}'. Supported modules: {', '.join(sorted(valid_modules))}."
        }), 400

    client_ip = request.remote_addr or "unknown"
    claimed_value = None
    content_str = ""
    params = {}

    if request.content_type and "multipart/form-data" in request.content_type:
        if "file" in request.files:
            file_obj = request.files["file"]
            if file_obj.filename == "":
                return jsonify({"success": False, "error": "No file selected for upload."}), 400
            if not allowed_file(file_obj.filename):
                return jsonify({"success": False, "error": "File extension not allowed. Must be CSV, JSON, TXT, or JSONL."}), 400
            content_bytes = file_obj.read(2 * 1024 * 1024 + 1)
            if len(content_bytes) > 2 * 1024 * 1024:
                return jsonify({"success": False, "error": "File exceeds 2 MB upload limit."}), 413
            content_str = content_bytes.decode("utf-8", errors="replace")

        params = request.form.to_dict()
        claimed_value = params.get("claimed_value")
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        content_str = body.get("content") or body.get("csv_data") or body.get("log_data") or ""
        claimed_value = body.get("claimed_value")
        params = body
    else:
        content_str = request.get_data(as_text=True)

    try:
        if module == "fairness":
            priv_val = params.get("privileged_value", "male")
            res = verify_fairness(content_str, privileged_value=priv_val, claimed_value=claimed_value)
        elif module == "dependencies":
            res = verify_dependencies(content_str, claimed_value=claimed_value)
        elif module == "tls":
            host = str(params.get("host", "")).strip()
            port_val = params.get("port", 443)
            try:
                port_num = int(port_val)
            except (ValueError, TypeError):
                port_num = 443
            res = verify_tls(host=host, port=port_num, claimed_value=claimed_value, client_ip=client_ip)
        elif module == "log_integrity":
            res = verify_log_integrity(content_str, claimed_value=claimed_value)
        elif module == "robustness":
            res = verify_robustness(content_str, claimed_value=claimed_value)
        else:
            return jsonify({"success": False, "error": "Unknown module"}), 400

        return jsonify({"success": True, "data": res})
    except Exception as e:
        logger.exception(f"Error executing verifier '{module}'")
        return jsonify({"success": False, "error": f"Verification error in {module}: {str(e)}"}), 500


# ================================================================
# ENDPOINT: Audit History and Records (SQLite Persistence)
# ================================================================
@app.route("/api/audit/history", methods=["GET"])
def get_audit_history():
    try:
        limit = min(100, max(1, int(request.args.get("limit", 20))))
        raw_history = store.list_audits(limit=limit)
        # Return only summary fields, never full stored answers
        history_summaries = []
        for r in raw_history:
            history_summaries.append({
                "id": r.get("audit_id"),
                "audit_id": r.get("audit_id"),
                "model_name": r.get("model_name"),
                "timestamp": r.get("created_at"),
                "created_at": r.get("created_at"),
                "aas": r.get("aas_score"),
                "aas_score": r.get("aas_score"),
                "grade": r.get("trust_grade"),
                "trust_grade": r.get("trust_grade"),
                "domain": r.get("domain", "General Purpose AI"),
                "model_version": r.get("model_version", "1.0.0"),
                "bottleneck_dimension": r.get("bottleneck_dimension"),
                "bottleneck_score": r.get("bottleneck_score"),
            })
        return jsonify({"success": True, "count": len(history_summaries), "data": history_summaries})
    except Exception:
        logger.exception("Error listing audit history")
        return jsonify({"success": False, "error": "Failed to load audit history"}), 500


@app.route("/api/audit/<audit_id>", methods=["GET"])
def get_audit_by_id(audit_id: str):
    try:
        audit = store.get_audit(audit_id)
        if not audit:
            return jsonify({"success": False, "error": f"Audit {audit_id} not found"}), 404
        # Strip raw answers if present to guarantee summary exposure only
        if "answers" in audit:
            del audit["answers"]
        return jsonify({"success": True, "data": audit})
    except Exception:
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
    except Exception:
        logger.exception("Error generating Model Card")
        return jsonify({"success": False, "error": "Failed to generate Model Card"}), 500


# ================================================================
# ENDPOINT: Remediation Priority Ranker
# ================================================================
@app.route("/api/rai/counterfactual", methods=["POST"])
def get_counterfactual():
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
    except Exception:
        logger.exception("Error solving remediation priority")
        return jsonify({"success": False, "error": "Failed to calculate remediation priorities"}), 500





# ================================================================
# ENDPOINT: Alpha Sensitivity Curve Analysis
# ================================================================
@app.route("/api/analysis/sensitivity", methods=["POST"])
def get_sensitivity_analysis():
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
    except Exception:
        logger.exception("Error computing sensitivity curve")
        return jsonify({"success": False, "error": "Failed to compute sensitivity curve"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("AIGRID_HOST", os.environ.get("HOST", "0.0.0.0"))
    print("=================================================================")
    print(f" AI-GRID Trust Assurance & GRC Server (v4.0) Running on port {port}")
    print(f" Dashboard URL: http://{host}:{port}")
    print(" Architecture: Questionnaire-Based AI Governance & Compliance Auditing")
    print(" Frameworks: EU AI Act (Arts 9-15) | NIST AI 100-1 | OWASP LLM Top 10")
    print(" Persistence: SQLite (aigrid_audits.db)")
    print("=================================================================")
    app.run(host=host, port=port, debug=False)
