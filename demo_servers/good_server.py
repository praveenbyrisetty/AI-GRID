"""
AI-GRID Demo MCP Server: GOOD Security Profile

A well-secured MCP server demonstrating comprehensive governance controls:
- Full metadata introspection
- Input validation and safety clamping
- Feature attributions (explainability)
- Adversarial robustness endpoint
- Data governance declarations
- Human oversight flags

Used as a test target for AI-GRID MCP security probing.
Launch: python demo_servers/good_server.py
"""

import json
import sys
from typing import Any, Dict

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError:
        print("ERROR: MCP SDK not installed. Install via: pip install mcp", file=sys.stderr)
        sys.exit(1)


mcp = MCPServer("AgriTrust-SoilNet-MCP-v2")


@mcp.tool()
def get_model_metadata() -> str:
    """
    Returns comprehensive model identity, architecture, training data profile,
    and governance declarations for automated compliance auditing.
    """
    return json.dumps({
        "model_name": "AgriTrust-SoilNet",
        "version": "2.1.0",
        "domain": "Agriculture / Environmental",
        "model_architecture": "Gradient Boosted Decision Trees (XGBoost) + MLP Agronomic Classifier",
        "model_hash": "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        "training_dataset_size": 10000,
        "training_class_distribution": {
            "Alluvial_Loam": 3200,
            "Black_Cotton_Soil": 2800,
            "Red_Sandy_Soil": 2200,
            "Laterite_Soil": 1800,
        },
        "supported_classes": ["Alluvial_Loam", "Black_Cotton_Soil", "Red_Sandy_Soil", "Laterite_Soil"],
        "geographic_coverage": [
            "Northern Indo-Gangetic Plains",
            "Deccan Plateau",
            "Coastal Alluvium Belt",
            "Eastern Highlands",
            "Western Semi-Arid Zone",
        ],
        "geographic_gaps": [],
        "operational_boundaries": {
            "min_ph": 4.5,
            "max_ph": 8.5,
            "max_nitrogen_dosage_kg_ha": 150.0,
            "min_nitrogen_dosage_kg_ha": 10.0,
            "input_validation_enforced": True,
        },
        "encryption_at_rest": True,
        "encryption_in_transit": True,
        "data_retention_days": 90,
        "human_oversight_required": True,
        "incident_escalation_protocol": True,
        "model_drift_monitoring": "Automated Kolmogorov-Smirnov & PSI drift detection (Daily)",
        "drift_status": "MONITORED",
        "last_validated": "2026-10-01T00:00:00Z",
    })


@mcp.tool()
def predict_soil_and_fertilizer(
    nitrogen: float = 65.0,
    phosphorus: float = 40.0,
    potassium: float = 45.0,
    ph: float = 6.8,
    moisture: float = 35.0,
    temperature: float = 26.5,
) -> str:
    """
    Executes soil classification and computes optimal fertilizer dosage
    with feature attributions and output safety clamping.
    Includes input validation guardrails and human review flags.
    """
    # Input Validation Guardrail (both physiological lower and upper agronomic bounds)
    if (
        nitrogen < 0 or nitrogen > 250 or
        phosphorus < 0 or phosphorus > 200 or
        potassium < 0 or potassium > 200 or
        ph < 0 or ph > 14 or
        moisture < 0 or moisture > 100 or
        temperature < -20 or temperature > 65
    ):
        return json.dumps({
            "status": "REJECTED",
            "error": "Input validation failure: physiological/agronomic limits exceeded.",
            "output_clamped": False,
            "human_review_required": True,
            "reasoning_summary": "Corrupted or impossible sensor values detected and safely rejected.",
        })

    # Output Clamping Guardrail
    raw_dosage = round(nitrogen * 0.85 + phosphorus * 0.45 + (7.0 - ph) * 5.0, 1)
    clamped = False
    if raw_dosage > 150.0:
        final_dosage = 150.0
        clamped = True
    elif raw_dosage < 10.0:
        final_dosage = 10.0
        clamped = True
    else:
        final_dosage = raw_dosage

    confidence = 0.942 if (5.5 <= ph <= 7.5 and moisture >= 25) else 0.810
    needs_hitl = confidence < 0.85 or clamped

    # Feature Attributions (simulated TreeSHAP-style)
    total_val = abs(nitrogen) + abs(phosphorus) + abs(potassium) + abs(ph * 10) + abs(moisture)
    attributions = {
        "Nitrogen (N)": round(abs(nitrogen) / max(total_val, 1), 3),
        "Phosphorus (P)": round(abs(phosphorus) / max(total_val, 1), 3),
        "Potassium (K)": round(abs(potassium) / max(total_val, 1), 3),
        "Soil pH": round(abs(ph * 10) / max(total_val, 1), 3),
        "Soil Moisture": round(abs(moisture) / max(total_val, 1), 3),
    }

    return json.dumps({
        "status": "SUCCESS",
        "predicted_soil_class": "Alluvial Clay Loam",
        "classification_confidence": confidence,
        "recommended_fertilizer": "NPK 14-35-14 Controlled-Release Granules",
        "recommended_dosage_kg_ha": final_dosage,
        "raw_unclamped_dosage_kg_ha": raw_dosage,
        "output_clamped": clamped,
        "human_review_required": needs_hitl,
        "active_guardrails": ["InputRangeValidator", "DosageSafetyClamp", "AnomalyFilter"],
        "feature_attributions": attributions,
        "reasoning_summary": (
            f"Soil pH of {ph:.1f} and NPK balance ({nitrogen:.0f}/{phosphorus:.0f}/{potassium:.0f}) "
            f"indicate high fertility alluvial loam. Dosage safely calibrated to {final_dosage} kg/ha."
        ),
    })


@mcp.tool()
def test_adversarial_perturbation(noise_level: float = 0.05) -> str:
    """
    Evaluates model resilience under sensor noise and adversarial perturbation.
    Computes output divergence to detect vulnerability to input poisoning.
    """
    if noise_level < 0.0 or noise_level > 1.0:
        return json.dumps({
            "status": "REJECTED",
            "error": "Input validation failure: noise_level must be between 0.0 and 1.0.",
        })

    noise = max(0.001, min(0.50, float(noise_level)))
    divergence = round(noise * 0.428, 4)
    status = "ROBUST" if divergence < 0.05 else "VULNERABLE"

    return json.dumps({
        "noise_level_applied": noise,
        "divergence_score": divergence,
        "max_allowable_divergence": 0.05,
        "robustness_status": status,
        "adversarial_resilience_tier": "ENTERPRISE_ROBUST" if status == "ROBUST" else "REQUIRES_HARDENING",
        "tested_features": ["nitrogen", "phosphorus", "potassium", "ph", "moisture"],
        "noise_distribution": "Gaussian N(0, noise_level)",
    })


@mcp.tool()
def get_data_governance_record() -> str:
    """
    Returns data protection records including encryption status,
    key rotation policies, and data retention configuration.
    """
    return json.dumps({
        "encryption_at_rest": {
            "enabled": True,
            "algorithm": "AES-256-GCM",
            "key_rotation_days": 90,
        },
        "encryption_in_transit": {
            "enabled": True,
            "protocol": "TLS 1.3 / HTTPS",
            "ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
        },
        "data_retention_days": 90,
        "compliance_certifications": ["ISO/IEC 27001", "EU AI Act Article 10"],
        "human_in_the_loop_mandatory": True,
        "incident_escalation_protocol": True,
        "pii_redacted": True,
    })


if __name__ == "__main__":
    mcp.run(transport="stdio")
