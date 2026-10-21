"""
Unit & Protocol Tests for AI-GRID MCP Probes & Client (v4.0)
"""

import asyncio
import os
import sys
import pytest
from aigrid_auditor import AIGRIDMCPAuditor


@pytest.mark.asyncio
async def test_demo_profile_audit_labeling():
    """Verify demo benchmark audit correctly sets DEMO_BENCHMARK mode and is_demo=True."""
    auditor = AIGRIDMCPAuditor()
    res = await auditor.run_live_audit(profile="good")
    assert res is not None
    assert res.get("execution_mode") == "DEMO_BENCHMARK"
    assert res.get("is_demo") is True
    assert "Certified Demo Benchmark Audit" in res["model_metadata"]["audit_mode_label"]
    assert "scoring" in res
    assert "dimensions" in res


@pytest.mark.asyncio
async def test_live_custom_target_failure_does_not_silently_fallback():
    """Verify that a failing custom live MCP target returns an explicit error without silent simulation."""
    auditor = AIGRIDMCPAuditor()
    # Provide non-existent target command
    res = await auditor.run_live_audit(
        mcp_command="non_existent_fake_mcp_executable_binary_12345",
        mcp_args=["arg1"]
    )
    assert res is not None
    # Must report failure, not fake a successful audit
    assert res.get("success") is False or "failed" in res.get("error", "").lower() or any(
        "failed" in log.get("message", "").lower() for log in res.get("audit_logs", [])
    )
