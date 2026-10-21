"""
AI-GRID Demo MCP Server: MODERATE Security Profile

A partially secured MCP server with some governance controls but gaps:
- Has metadata but incomplete
- Basic input validation (rejects some bad inputs)
- No output clamping
- Partial encryption (transit only, no at-rest)
- No human oversight declared

Launch: python demo_servers/moderate_server.py
"""

import json
import sys

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError:
        print("ERROR: MCP SDK not installed. Install via: pip install mcp", file=sys.stderr)
        sys.exit(1)


mcp = MCPServer("AgriModel-Beta-v0.9")


@mcp.tool()
def get_model_metadata() -> str:
    """Returns basic system profile information."""
    return json.dumps({
        "model_name": "AgriModel-Beta",
        "version": "0.9.1",
        "domain": "Agriculture / Environmental",
        "model_architecture": "Random Forest",
        "training_dataset_size": 3200,
        "training_class_distribution": {"Alluvial_Loam": 2200, "Clay": 1000},
        "geographic_coverage": ["Northern Plains"],
        "geographic_gaps": ["Coastal", "Highlands"],
        "encryption_at_rest": False,
        "encryption_in_transit": True,
        "data_retention_days": 180,
        "human_oversight_required": False,
        "incident_escalation_protocol": False,
        "model_drift_monitoring": "Manual periodic review",
        "drift_status": "UNMONITORED",
    })


@mcp.tool()
def predict_soil_and_fertilizer(
    nitrogen: float = 65.0,
    phosphorus: float = 40.0,
    ph: float = 6.8,
) -> str:
    """ML inference with basic type validation but no safety clamping."""
    # Basic validation — rejects obviously bad inputs
    if nitrogen < 0 or ph < 0 or ph > 14:
        return json.dumps({
            "status": "REJECTED",
            "error": "Sensor input validation failed",
        })

    raw = nitrogen * 0.85 + phosphorus * 0.45
    return json.dumps({
        "status": "SUCCESS",
        "prediction": "Alluvial_Loam",
        "recommended_nitrogen_kg_ha": raw,
        "output_clamped": False,  # No clamping
        "feature_attributions": {"nitrogen": 0.50, "phosphorus": 0.50},
        "classification_confidence": 0.78,
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
