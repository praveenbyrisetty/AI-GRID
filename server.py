"""
AI-GRID Web Server (v4.0)

Hosts REST APIs for dual-mode auditing:
1. Mode 1: Automated MCP Protocol Probes (Evidence Tier T1, weight 1.0)
2. Mode 2: Structured Research-Grounded Questionnaire (Evidence Tier T3, weight 0.6)
3. Mode 3: Attestation Discrepancy Comparative Engine (ADI)

Features:
- Strong input validation and size constraints on all endpoints
- Sanitized, safe client error responses (no internal traceback leakage)
- SQLite audit persistence via AuditStore (survives server restarts)
- Audit history and record retrieval APIs
- Explicit legal & regulatory disclaimers
"""

import asyncio
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

from aigrid_auditor import AIGRIDMCPAuditor
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
# Defaults to localhost/127.0.0.1, configurable via AIGRID_ALLOWED_ORIGINS env var
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

ALLOWED_LIVE_EXECUTABLES = {"python", "python3", "python.exe"}
DISALLOWED_SHELL_CHARS = {";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r"}
DISALLOWED_INTERPRETER_FLAGS = {"-c", "-m", "-e", "-r", "--eval"}

# Base and approved scripts directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APPROVED_SCRIPTS_DIR = os.path.realpath(os.environ.get("AIGRID_APPROVED_DIR", os.path.join(BASE_DIR, "demo_servers")))
ALLOWED_SCRIPTS = {
    "good_server.py",
    "moderate_server.py",
    "poor_server.py",
}
_extra_allowed = os.environ.get("AIGRID_ALLOWED_SCRIPTS", "")
if _extra_allowed:
    ALLOWED_SCRIPTS.update(s.strip() for s in _extra_allowed.split(",") if s.strip())

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

auditor = AIGRIDMCPAuditor()
store = AuditStore()

# In-memory working cache (backed by SQLite store)
last_audit_data: Dict[str, Any] = {}
last_mcp_data: Dict[str, Any] = {}

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
    return send_from_directory("public", "index.html")


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
        "service": "AI-GRID Trust & Assurance Framework",
        "version": "4.0.0",
        "dimensions": 6,
        "question_bank_size": 30,
        "evidence_tiers": {
            "T1": {"description": "Automated MCP Protocol Probe", "weight": 1.0},
            "T2": {"description": "Declared Metadata & Schema Inspection", "weight": 0.8},
            "T3": {"description": "Self-Attested Structured Questionnaire", "weight": 0.6},
        },
        "compliance_engines": [
            "Custom Fairness Metrics (DIR, SPD, Sample Reweighing)",
            "Rule-Based Risk Cohort Slicing",
            "Remediation Priority Ranker",
            "EU AI Act Article-by-Article Evaluation (Articles 9-15)",
            "NIST AI RMF 1.0 Function & Subcategory Crosswalk",
            "OWASP LLM & MCP Top 10 Threat Crosswalk",
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

        # Persist audit run
        audit_id = store.save_audit(results)
        results["audit_id"] = audit_id

        last_audit_data = results
        return jsonify({"success": True, "data": results, "audit_id": audit_id})
    except Exception as e:
        logger.exception("Error executing questionnaire audit")
        return jsonify({"success": False, "error": "Failed to process questionnaire audit"}), 500


# ================================================================
# ENDPOINT: MCP-based live audit (Evidence Tier T1, weight 1.0)
# ================================================================
@app.route("/api/audit/mcp", methods=["POST"])
def run_mcp_audit():
    global last_mcp_data, last_audit_data
    body, err = validate_json_body()
    if err:
        return jsonify({
            "success": False,
            "error": f"Invalid request body: {err}. Specify 'demo_profile' ('good', 'moderate', 'poor') or an approved target script."
        }), 400

    if not body:
        return jsonify({
            "success": False,
            "error": "Request body cannot be empty. Specify either 'demo_profile' ('good', 'moderate', 'poor') or an approved target script."
        }), 400

    demo_profile = body.get("demo_profile") or body.get("profile")
    target_command = body.get("target_command")

    # Mode 1: Certified Demo Benchmark Profile
    if demo_profile is not None:
        if not isinstance(demo_profile, str) or demo_profile not in ("good", "moderate", "poor"):
            return jsonify({
                "success": False,
                "error": "Invalid demo profile parameter. Must be one of: 'good', 'moderate', 'poor'",
            }), 400

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                results = loop.run_until_complete(
                    asyncio.wait_for(auditor.run_live_audit(profile=demo_profile), timeout=45.0)
                )
            finally:
                loop.close()

            results["disclaimer"] = DISCLAIMER_TEXT
            audit_id = store.save_audit(results)
            results["audit_id"] = audit_id
            last_mcp_data = results
            last_audit_data = results
            return jsonify({"success": True, "data": results, "audit_id": audit_id})
        except asyncio.TimeoutError:
            return jsonify({"success": False, "error": "Demo benchmark audit timed out after 45 seconds"}), 504
        except Exception as e:
            logger.exception("Error executing demo MCP benchmark audit")
            return jsonify({"success": False, "error": f"Demo benchmark audit failed: {e}"}), 500

    # Mode 2: Allowlisted Target Script (arbitrary target_command removed; 'authorized' dropped as control)
    elif target_command is not None:
        if not isinstance(target_command, list) or len(target_command) == 0:
            return jsonify({
                "success": False,
                "error": "'target_command' must be a list containing an approved script path."
            }), 400

        # Reject interpreter flags anywhere in target_command
        for arg in target_command:
            arg_str = str(arg).strip().lower()
            for flag in DISALLOWED_INTERPRETER_FLAGS:
                if arg_str == flag or arg_str.startswith(flag + "=") or arg_str.startswith(flag + ":"):
                    return jsonify({
                        "success": False,
                        "error": f"Interpreter flag '{flag}' is strictly disallowed."
                    }), 400

        # Extract target script argument
        script_arg = None
        for arg in target_command:
            arg_s = str(arg).strip()
            base = os.path.basename(arg_s).lower()
            if base in ("python", "python3", "python.exe"):
                continue
            script_arg = arg_s
            break

        if not script_arg:
            return jsonify({
                "success": False,
                "error": "No target script specified in target_command."
            }), 400

        for ch in DISALLOWED_SHELL_CHARS:
            if ch in script_arg:
                return jsonify({
                    "success": False,
                    "error": f"Script argument contains disallowed shell character: '{ch}'"
                }), 400

        # Resolve realpath
        if os.path.isabs(script_arg):
            candidate_path = os.path.realpath(script_arg)
        else:
            c1 = os.path.realpath(os.path.join(APPROVED_SCRIPTS_DIR, script_arg))
            c2 = os.path.realpath(os.path.join(BASE_DIR, script_arg))
            candidate_path = c1 if os.path.exists(c1) else c2

        # Verify realpath is inside APPROVED_SCRIPTS_DIR
        try:
            common = os.path.commonpath([APPROVED_SCRIPTS_DIR, candidate_path])
        except ValueError:
            common = ""

        if common != APPROVED_SCRIPTS_DIR or not os.path.isfile(candidate_path):
            return jsonify({
                "success": False,
                "error": "Target script is outside the approved directory or does not exist."
            }), 403

        script_basename = os.path.basename(candidate_path)
        if script_basename not in ALLOWED_SCRIPTS:
            return jsonify({
                "success": False,
                "error": f"Script '{script_basename}' is not in the configured allowlist."
            }), 403

        cmd_exec = sys.executable
        cmd_args = [candidate_path]

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                results = loop.run_until_complete(
                    asyncio.wait_for(auditor.run_live_audit(mcp_command=cmd_exec, mcp_args=cmd_args), timeout=45.0)
                )
            finally:
                loop.close()

            results["disclaimer"] = DISCLAIMER_TEXT
            audit_id = store.save_audit(results)
            results["audit_id"] = audit_id
            last_mcp_data = results
            last_audit_data = results
            return jsonify({"success": True, "data": results, "audit_id": audit_id})
        except asyncio.TimeoutError:
            return jsonify({"success": False, "error": "Live MCP protocol audit timed out after 45 seconds"}), 504
        except Exception as e:
            logger.exception("Error executing live MCP target audit")
            return jsonify({"success": False, "error": f"Live MCP protocol audit failed: {e}"}), 500

    else:
        return jsonify({
            "success": False,
            "error": "Missing audit target specification. Specify 'demo_profile' ('good', 'moderate', 'poor') or an approved target script."
        }), 400


# ================================================================
# ENDPOINT: Attestation Discrepancy Analysis (Comparative Engine)
# ================================================================
@app.route("/api/audit/compare", methods=["POST"])
def compare_audits():
    global last_audit_data, last_mcp_data
    body = {}
    if request.is_json:
        parsed, err = validate_json_body()
        if not err and parsed:
            body = parsed

    # Use provided data or fallback to cached audits or SQLite latest
    q_data = body.get("questionnaire_data") or last_audit_data
    if not q_data or q_data.get("audit_mode") != "questionnaire":
        q_data = store.get_latest_audit("questionnaire")

    m_data = body.get("mcp_data") or last_mcp_data
    if not m_data or m_data.get("audit_mode") != "mcp":
        m_data = store.get_latest_audit("mcp")

    if not q_data or not m_data:
        return jsonify({
            "success": False,
            "error": (
                "Both Questionnaire audit (Tier T3) and MCP Probe audit (Tier T1) "
                "are required for discrepancy calculation. Please run both audits first."
            ),
        }), 400

    try:
        comparison = auditor.compare_attestation_vs_probe(q_data, m_data)
        comparison["disclaimer"] = (
            "Attestation Discrepancy Index (ADI) quantifies the gap between self-declared "
            "and runtime-verified controls. It is an empirical indicator, not legal proof of misrepresentation."
        )
        return jsonify({"success": True, "data": comparison})
    except Exception as e:
        logger.exception("Error comparing audits")
        return jsonify({"success": False, "error": "Failed to calculate Attestation Discrepancy"}), 500


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
    global last_audit_data, last_mcp_data
    last_audit_data = {}
    last_mcp_data = {}
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
# ENDPOINT: What-If Simulation
# ================================================================
@app.route("/api/simulate", methods=["POST"])
def run_simulation():
    global last_audit_data
    body = {}
    if request.is_json:
        parsed, _ = validate_json_body()
        if parsed:
            body = parsed

    try:
        active_score = (
            last_audit_data.get("scoring", {}).get("aas_score", 50.0)
            if last_audit_data else 50.0
        )
        base_aas = float(body.get("base_aas", active_score))
        base_aas = max(0.0, min(100.0, base_aas))

        domain = str(body.get(
            "domain",
            last_audit_data.get("model_metadata", {}).get("domain", "General Purpose AI")
        ))
        scale_users = max(100, min(10000000, int(body.get("scale_users", 50000))))

        sim_res = auditor.simulate_scenario(base_aas, domain, scale_users)
        return jsonify({"success": True, "data": sim_res})
    except Exception as e:
        logger.exception("Simulation execution error")
        return jsonify({"success": False, "error": "Failed to run risk simulation"}), 500


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

        current_aas = float(audit_data.get("scoring", {}).get("aas_score", 50.0))
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
    print(" Modes: Structured Questionnaire (T3) | MCP Automated Probe (T1)")
    print(" Frameworks: EU AI Act (Arts 9-15) | NIST AI RMF | OWASP MCP Top 10")
    print(" Persistence: SQLite (data/aigrid_audits.db)")
    print("=================================================================")
    app.run(host=host, port=port, debug=False)
