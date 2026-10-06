"""
AI-GRID Web Server: Hosts the REST APIs for dual-mode auditing
(MCP + Questionnaire), Simulation, and serves the Web Dashboard.
"""

import asyncio
import os
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from aigrid_auditor import AIGRIDMCPAuditor
from ai_profile_engine import get_questions
from rai_engines import (
    compute_aif360_fairness,
    analyze_risk_cohorts,
    solve_prescriptive_counterfactual,
    generate_google_model_card,
    scan_ai_vulnerabilities,
    get_dataset_catalog,
)

app = Flask(__name__, static_folder="public", static_url_path="")
CORS(app)
auditor = AIGRIDMCPAuditor()

# Cache latest audit data for Model Card export & counterfactual queries
last_audit_data = {}

@app.route("/")
def index():
    return send_from_directory("public", "index.html")

@app.route("/<path:path>")
def static_files(path):
    if os.path.exists(os.path.join("public", path)):
        return send_from_directory("public", path)
    return send_from_directory("public", "index.html")

@app.route("/api/status", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "service": "AI-GRID Governance Engine",
        "version": "2.2.0",
        "rai_modules": ["IBM AIF360", "Google Model Cards", "Microsoft RAI Toolkit", "CVSS/EPSS AI-BOM"]
    })

# ================================================================
# ENDPOINT: Get questions for the wizard
# ================================================================
@app.route("/api/questions", methods=["GET"])
def get_question_list():
    """Returns the full question list for the frontend wizard."""
    questions = get_questions()
    # Organize by steps
    steps = {}
    for q in questions:
        step = q["step"]
        if step not in steps:
            steps[step] = {"step": step, "title": q["step_title"], "questions": []}
        steps[step]["questions"].append(q)
    return jsonify({"success": True, "data": {"steps": list(steps.values()), "total_questions": len(questions)}})

# ================================================================
# ENDPOINT: Questionnaire-based audit (NO MCP required)
# ================================================================
@app.route("/api/audit/questionnaire", methods=["POST"])
def run_questionnaire_audit():
    """
    Accepts user questionnaire answers and generates the full
    7-dimension trust audit + AIF360, MS RAI, and Google Model Card.
    """
    global last_audit_data
    try:
        body = request.get_json() or {}
        answers = body.get("answers", body)
        results = auditor.run_questionnaire_audit(answers)
        last_audit_data = results
        return jsonify({"success": True, "data": results})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ================================================================
# ENDPOINT: MCP-based live audit (requires MCP server)
# ================================================================
@app.route("/api/audit/mcp", methods=["POST"])
def run_mcp_audit():
    """
    Connects to a real MCP server and runs live probing.
    Expects 'mcp_url' or 'mcp_command' in the request body.
    """
    try:
        body = request.get_json() or {}
        mcp_url = body.get("mcp_url", "")
        mcp_command = body.get("mcp_command", "")

        if not mcp_url and not mcp_command:
            return jsonify({
                "success": False,
                "error": "No MCP server configuration provided. Provide 'mcp_url' (for SSE/HTTP transport) or 'mcp_command' (for STDIO transport)."
            }), 400

        # For now, return an error if we can't connect
        # In production, this would use the MCP client SDK to connect
        return jsonify({
            "success": False,
            "error": f"MCP connection to '{mcp_url or mcp_command}' is not yet configured. Use the Questionnaire mode for assessment, or configure a running MCP server."
        }), 501

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ================================================================
# ENDPOINT: What-If Simulation
# ================================================================
@app.route("/api/simulate", methods=["POST"])
def run_simulation():
    try:
        body = request.get_json() or {}
        base_aas = float(body.get("base_aas", 58.1))
        domain = str(body.get("domain", "General Purpose AI"))
        scale_users = int(body.get("scale_users", 50000))

        sim_res = auditor.simulate_scenario(base_aas, domain, scale_users)
        return jsonify({"success": True, "data": sim_res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ================================================================
# ENDPOINT: Google Model Card Generator (Mitchell et al., 2019)
# ================================================================
@app.route("/api/model-card", methods=["GET", "POST"])
def get_model_card():
    """Returns the Google-style Model Card (Markdown + JSON) for the latest audit."""
    global last_audit_data
    try:
        body = request.get_json(silent=True) or {}
        audit_data = body if body.get("dimensions") else last_audit_data

        if not audit_data:
            return jsonify({
                "success": False,
                "error": "No audit has been conducted yet. Please complete an audit first."
            }), 404

        card = audit_data.get("model_card") or generate_google_model_card(audit_data)
        return jsonify({"success": True, "data": card})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ================================================================
# ENDPOINT: Microsoft RAI Prescriptive Counterfactual Solver
# ================================================================
@app.route("/api/rai/counterfactual", methods=["POST"])
def get_counterfactual():
    """Calculates the minimal intervention path to reach target AAS."""
    global last_audit_data
    try:
        body = request.get_json() or {}
        target_score = float(body.get("target_score", 76.0))
        audit_data = body.get("audit_data") or last_audit_data

        if not audit_data:
            return jsonify({
                "success": False,
                "error": "No audit data available. Please complete an audit first."
            }), 404

        current_aas = audit_data.get("scoring", {}).get("aas_score", 50.0)
        dimensions = audit_data.get("dimensions", {})
        findings = audit_data.get("remediation_plan", [])

        cf_res = solve_prescriptive_counterfactual(current_aas, dimensions, findings, target_score)
        return jsonify({"success": True, "data": cf_res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ================================================================
# ENDPOINT: CVSS, EPSS & CVE AI Supply Chain Vulnerability Scanner
# ================================================================
@app.route("/api/security/cve-scan", methods=["GET", "POST"])
def run_cve_scan():
    """
    Evaluates AI agent & supply chain vulnerabilities using CVSS v3.1/v4.0,
    FIRST.org EPSS exploit probabilities, and Asset Criticality tiers.
    """
    global last_audit_data
    try:
        body = request.get_json(silent=True) or {}
        domain = body.get("domain") or last_audit_data.get("model_metadata", {}).get("domain", "General Purpose AI")
        asset_criticality = body.get("asset_criticality", "Operational / Advisory")

        vuln_res = scan_ai_vulnerabilities(domain=domain, asset_criticality=asset_criticality)
        return jsonify({"success": True, "data": vuln_res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ================================================================
# ENDPOINT: Downloaded Empirical Datasets Catalog
# ================================================================
@app.route("/api/datasets", methods=["GET"])
def get_datasets():
    """
    Returns full metadata for the 3 real public datasets downloaded
    and used for sample reweighing, clinical safety, and CVE scanning.
    """
    try:
        catalog = get_dataset_catalog()
        return jsonify({"success": True, "data": catalog})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    print("=================================================================")
    print(" AI-GRID GRC Dashboard & Audit Server Running on port 8000")
    print(" Dashboard URL: http://localhost:8000")
    print(" Modes: Questionnaire | MCP Live Audit")
    print(" RAI Modules: IBM AIF360 | Google Model Cards | Microsoft RAI | CVSS/EPSS")
    print(" Empirical Datasets: German Credit | Clinical Patient Safety | NIST NVD")
    print("=================================================================")
    app.run(host="0.0.0.0", port=8000, debug=False)
