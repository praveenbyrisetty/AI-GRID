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

app = Flask(__name__, static_folder="public", static_url_path="")
CORS(app)
auditor = AIGRIDMCPAuditor()

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
    return jsonify({"status": "healthy", "service": "AI-GRID Governance Engine", "version": "2.0.0"})

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
    7-dimension trust audit. No MCP connection required.
    """
    try:
        body = request.get_json() or {}
        answers = body.get("answers", body)
        results = auditor.run_questionnaire_audit(answers)
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

if __name__ == "__main__":
    print("=================================================================")
    print(" AI-GRID GRC Dashboard & Audit Server Running on port 8000")
    print(" Dashboard URL: http://localhost:8000")
    print(" Modes: Questionnaire | MCP Live Audit")
    print("=================================================================")
    app.run(host="0.0.0.0", port=8000, debug=False)
