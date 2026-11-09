"""
AI-GRID Deterministic Evidence Verifiers Engine (v5.0)

Standard library only: csv, json, ssl, socket, hashlib, datetime, ipaddress, re, os, typing, urllib.parse.
NEVER uses pickle, eval, exec, or loads uploaded model files.
"""

import csv
import io
import json
import re
import socket
import ssl
import time
import ipaddress
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Rate limiting for TLS verifier (max 5 requests per minute per IP)
_tls_rate_limits: Dict[str, List[float]] = {}
TLS_RATE_LIMIT = 5
TLS_RATE_WINDOW = 60.0


# =========================================================================
# 1. FAIRNESS VERIFIER (Item: q10_fairness_audit, Dimension: Fairness)
# =========================================================================
def verify_fairness(
    csv_content: str,
    privileged_value: str = "male",
    claimed_value: Any = None
) -> Dict[str, Any]:
    """
    Verifies demographic fairness and disparate impact metrics from predictions CSV.
    Expected columns: protected_attribute, y_true, y_pred.
    """
    item_id = "q10_fairness_audit"
    dimension = "Fairness & Non-Discrimination"

    if not csv_content or not csv_content.strip():
        return {
            "module": "fairness",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: Empty CSV content provided."
        }

    try:
        raw_lines = [ln for ln in csv_content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if not raw_lines:
            return {
                "module": "fairness",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {},
                "details": "Error: Empty CSV content provided."
            }
        reader = csv.DictReader(io.StringIO("\n".join(raw_lines)))
        if not reader.fieldnames:
            return {
                "module": "fairness",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {},
                "details": "Error: Missing CSV header row."
            }

        # Normalize column header names
        fields = {f.strip().lower(): f for f in reader.fieldnames}
        req_cols = ["protected_attribute", "y_true", "y_pred"]
        missing = [c for c in req_cols if c not in fields]
        if missing:
            return {
                "module": "fairness",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {},
                "details": f"Error: Missing required CSV columns: {', '.join(missing)}"
            }

        col_prot = fields["protected_attribute"]
        col_true = fields["y_true"]
        col_pred = fields["y_pred"]

        priv_target = str(privileged_value).strip().lower()

        priv_count = 0
        unpriv_count = 0
        priv_fav = 0
        unpriv_fav = 0
        priv_pos_true = 0
        unpriv_pos_true = 0
        priv_tpr_num = 0
        unpriv_tpr_num = 0

        total_rows = 0
        for row in reader:
            total_rows += 1
            prot_val = str(row.get(col_prot, "")).strip().lower()
            is_priv = (prot_val == priv_target)

            # Standardize binary target: 1 if in (1, 1.0, true, yes)
            t_raw = str(row.get(col_true, "")).strip().lower()
            p_raw = str(row.get(col_pred, "")).strip().lower()
            y_true = 1 if t_raw in ("1", "1.0", "true", "yes") else 0
            y_pred = 1 if p_raw in ("1", "1.0", "true", "yes") else 0

            if is_priv:
                priv_count += 1
                if y_pred == 1:
                    priv_fav += 1
                if y_true == 1:
                    priv_pos_true += 1
                    if y_pred == 1:
                        priv_tpr_num += 1
            else:
                unpriv_count += 1
                if y_pred == 1:
                    unpriv_fav += 1
                if y_true == 1:
                    unpriv_pos_true += 1
                    if y_pred == 1:
                        unpriv_tpr_num += 1

        if total_rows == 0 or priv_count == 0 or unpriv_count == 0:
            return {
                "module": "fairness",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {
                    "total_samples": total_rows,
                    "privileged_count": priv_count,
                    "unprivileged_count": unpriv_count,
                },
                "details": "Error: Both privileged and unprivileged groups must have at least one sample."
            }

        p_fav_unpriv = unpriv_fav / unpriv_count
        p_fav_priv = priv_fav / priv_count

        if p_fav_priv > 0:
            dir_val = round(p_fav_unpriv / p_fav_priv, 4)
        else:
            dir_val = 1.0 if p_fav_unpriv == 0.0 else 0.0

        spd_val = round(p_fav_unpriv - p_fav_priv, 4)

        tpr_unpriv = (unpriv_tpr_num / unpriv_pos_true) if unpriv_pos_true > 0 else 0.0
        tpr_priv = (priv_tpr_num / priv_pos_true) if priv_pos_true > 0 else 0.0
        eod_val = round(tpr_unpriv - tpr_priv, 4)

        # Scoring: DIR>=0.80 and |SPD|<=0.10 -> 1.0; DIR>=0.70 and |SPD|<=0.15 -> 0.5; else 0.0
        if dir_val >= 0.80 and abs(spd_val) <= 0.10:
            score = 1.0
        elif dir_val >= 0.70 and abs(spd_val) <= 0.15:
            score = 0.5
        else:
            score = 0.0

        claim_supported = bool(score >= 0.7)

        return {
            "module": "fairness",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": score,
            "claim_supported": claim_supported,
            "metrics": {
                "disparate_impact_ratio": dir_val,
                "statistical_parity_difference": spd_val,
                "equal_opportunity_difference": eod_val,
                "privileged_group": privileged_value,
                "privileged_count": priv_count,
                "unprivileged_count": unpriv_count,
                "total_samples": total_rows
            },
            "details": f"Computed DIR = {dir_val:.3f}, SPD = {spd_val:.3f}, EOD = {eod_val:.3f} across {total_rows} evaluated records."
        }
    except Exception as e:
        return {
            "module": "fairness",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": f"Execution error parsing fairness dataset: {str(e)}"
        }


# =========================================================================
# 2. DEPENDENCIES VERIFIER (Item: q3_sbom_tracking, Dimension: Security)
# =========================================================================
def verify_dependencies(
    content: str,
    claimed_value: Any = None
) -> Dict[str, Any]:
    """
    Verifies supply chain dependencies by querying the public OSV API.
    POST https://api.osv.dev/v1/querybatch (PyPI ecosystem, urllib only).
    Timeout: 5 seconds. Package limit: at most 200 packages.
    Score: valid CycloneDX with no CVSS>=7 match -> 1.0; requirements-only or any high match -> 0.5.
    If lookup fails or is offline: returns 'vulnerability lookup unavailable' and preserves claimed score.
    """
    item_id = "q3_sbom_tracking"
    dimension = "Security & Robustness"

    # Compute claimed_score to preserve on offline/network failure
    if isinstance(claimed_value, (int, float)):
        claimed_score = float(claimed_value)
    elif isinstance(claimed_value, str):
        val = claimed_value.strip().lower()
        if val in ("formal_sbom", "cyclonedx", "1.0", "1"):
            claimed_score = 1.0
        elif val in ("internal_inventory", "requirements_only", "0.5"):
            claimed_score = 0.5
        elif val in ("none", "untracked", "0.0", "0"):
            claimed_score = 0.0
        else:
            claimed_score = 0.5
    else:
        claimed_score = 0.5

    if not content or not content.strip():
        return {
            "module": "dependencies",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: Empty dependency payload provided."
        }

    is_cyclonedx = False
    packages: List[Dict[str, Optional[str]]] = []

    # Attempt CycloneDX JSON parse
    trimmed = content.strip()
    if trimmed.startswith("{"):
        try:
            data = json.loads(trimmed)
            if isinstance(data, dict):
                bom_format = str(data.get("bomFormat", "")).lower()
                components = data.get("components")
                if bom_format == "cyclonedx" or (components is not None and isinstance(components, list)):
                    is_cyclonedx = True
                    for c in components:
                        if isinstance(c, dict) and "name" in c:
                            pkg_name = str(c["name"]).strip().lower().replace("-", "_")
                            pkg_ver = str(c["version"]).strip() if "version" in c else None
                            packages.append({"name": pkg_name, "version": pkg_ver})
        except Exception:
            pass

    # Fallback to requirements.txt parse if not CycloneDX
    if not is_cyclonedx:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "@")):
                continue
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:==([a-zA-Z0-9_\-\.]+))?", line)
            if match:
                pkg_name = match.group(1).lower().replace("-", "_")
                pkg_ver = match.group(2) if match.group(2) else None
                packages.append({"name": pkg_name, "version": pkg_ver})

    if not packages:
        return {
            "module": "dependencies",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: Could not parse any package names from submitted manifest."
        }

    # At most 200 packages
    packages = packages[:200]

    # Prepare queries for OSV querybatch
    queries = []
    for p in packages:
        q_item: Dict[str, Any] = {
            "package": {
                "name": p["name"],
                "ecosystem": "PyPI"
            }
        }
        if p.get("version"):
            q_item["version"] = p["version"]
        queries.append(q_item)

    req_body = json.dumps({"queries": queries}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=req_body,
        headers={"Content-Type": "application/json", "User-Agent": "AI-GRID-Verifier/5.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, Exception) as err:
        return {
            "module": "dependencies",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": claimed_score,
            "claim_supported": True,
            "status": "vulnerability lookup unavailable",
            "details": "vulnerability lookup unavailable",
            "metrics": {
                "format": "CycloneDX" if is_cyclonedx else "requirements.txt",
                "packages_checked": len(packages),
                "offline": True,
                "error": str(err)
            }
        }

    results = resp_data.get("results", [])
    highest_severity = 0.0
    high_vulns = []
    total_vulns = 0

    def _parse_vuln_severity(vuln_obj: Dict[str, Any]) -> float:
        max_s = 0.0
        for s in vuln_obj.get("severity", []):
            score_val = s.get("score")
            if isinstance(score_val, (int, float)):
                max_s = max(max_s, float(score_val))
            elif isinstance(score_val, str):
                try:
                    max_s = max(max_s, float(score_val))
                except ValueError:
                    if "/C:H" in score_val and "/I:H" in score_val:
                        max_s = max(max_s, 8.5)
                    elif "/C:H" in score_val or "/I:H" in score_val or "/A:H" in score_val:
                        max_s = max(max_s, 7.5)
        db_spec = vuln_obj.get("database_specific", {})
        if isinstance(db_spec, dict):
            sev_text = str(db_spec.get("severity", "")).upper()
            if sev_text == "CRITICAL":
                max_s = max(max_s, 9.5)
            elif sev_text == "HIGH":
                max_s = max(max_s, 7.5)
            elif sev_text in ("MODERATE", "MEDIUM"):
                max_s = max(max_s, 5.0)
            elif sev_text == "LOW":
                max_s = max(max_s, 2.5)
            if "cvss" in db_spec:
                try:
                    max_s = max(max_s, float(db_spec["cvss"].get("score", 0.0)))
                except Exception:
                    pass
        return max_s

    for res in results:
        vulns = res.get("vulns", [])
        total_vulns += len(vulns)
        for v in vulns:
            sev = _parse_vuln_severity(v)
            highest_severity = max(highest_severity, sev)
            if sev >= 7.0:
                high_vulns.append(v.get("id", "UNKNOWN"))

    has_high_match = (highest_severity >= 7.0)

    if is_cyclonedx and not has_high_match:
        verified_score = 1.0
        claim_supported = True
        details = f"Valid CycloneDX SBOM parsed: {len(packages)} packages queried against OSV, 0 CVSS>=7 vulnerabilities found (max severity: {highest_severity:.1f})."
    elif is_cyclonedx and has_high_match:
        verified_score = 0.5
        claim_supported = False
        details = f"CycloneDX SBOM contains high-severity vulnerabilities via OSV query (max severity: {highest_severity:.1f}, {len(high_vulns)} CVSS>=7 issues)."
    else:
        verified_score = 0.5
        claim_supported = (claimed_score <= 0.5)
        details = f"Parsed plain requirements.txt ({len(packages)} packages). Requirements-only manifest is capped at 0.5 (needs CycloneDX for 1.0; OSV max severity: {highest_severity:.1f})."

    return {
        "module": "dependencies",
        "item_id": item_id,
        "dimension": dimension,
        "claimed_value": claimed_value,
        "verified_score": verified_score,
        "claim_supported": claim_supported,
        "metrics": {
            "format": "CycloneDX" if is_cyclonedx else "requirements.txt",
            "package_count": len(packages),
            "total_vulnerabilities_count": total_vulns,
            "high_severity_count": len(high_vulns),
            "highest_severity": highest_severity,
            "high_vulnerabilities": high_vulns[:10]
        },
        "details": details
    }

# =========================================================================
# 3. TLS VERIFIER (Item: q17_encryption_transit, Dimension: Privacy)
# =========================================================================
def _is_ssrf_blocked_ip(ip_str: str) -> Tuple[bool, str]:
    """Checks whether an IP address is private, loopback, link-local, multicast, or cloud metadata."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return True, "Loopback address rejected."
        if ip.is_private:
            return True, "Private subnet address rejected."
        if ip.is_link_local:
            return True, "Link-local address rejected."
        if ip.is_multicast:
            return True, "Multicast address rejected."
        if ip.is_reserved:
            return True, "Reserved IP space rejected."
        if ip.is_unspecified:
            return True, "Unspecified 0.0.0.0 IP rejected."
        if str(ip) == "169.254.169.254":
            return True, "Cloud metadata endpoint rejected."
        return False, ""
    except ValueError:
        return True, "Invalid IP address representation."


def check_tls_rate_limit(client_id: str) -> bool:
    """Returns True if request exceeds 5 per minute."""
    now = time.time()
    ts_list = _tls_rate_limits.setdefault(client_id, [])
    valid = [t for t in ts_list if now - t < TLS_RATE_WINDOW]
    _tls_rate_limits[client_id] = valid
    if len(valid) >= TLS_RATE_LIMIT:
        return True
    _tls_rate_limits[client_id].append(now)
    return False


def verify_tls(
    host: str,
    port: int = 443,
    claimed_value: Any = None,
    client_ip: str = "unknown"
) -> Dict[str, Any]:
    """
    Connects to external host using Python ssl (5-sec timeout), reading TLS version & cert expiry.
    Includes strict SSRF defenses: only ports 443/8443 allowed; private/loopback/cloud IP addresses rejected.
    Score: TLS1.3 and valid cert -> 1.0; TLS1.2 and valid -> 0.6; else 0.0.
    """
    item_id = "q17_encryption_transit"
    dimension = "Privacy & Data Governance"

    # Rate limiting
    if check_tls_rate_limit(client_ip):
        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: TLS verification rate limit exceeded (maximum 5 requests per minute)."
        }

    # Port restriction: accept only 443 and 8443
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: Port must be an integer."
        }

    if port_num not in (443, 8443):
        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": f"Security restriction: Only standard TLS ports 443 and 8443 are allowed (received {port_num})."
        }

    clean_host = host.strip()
    if clean_host.startswith(("http://", "https://")):
        clean_host = urlparse(clean_host).hostname or clean_host
    if ":" in clean_host and not clean_host.startswith("["):
        clean_host = clean_host.split(":")[0]

    if not clean_host:
        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: Host name cannot be empty."
        }

    # SSRF: Resolve hostname and check every resolved IP address
    try:
        addr_info = socket.getaddrinfo(clean_host, port_num, proto=socket.IPPROTO_TCP)
        resolved_ips = list({item[4][0] for item in addr_info})
    except socket.gaierror as e:
        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": f"DNS resolution failed for '{clean_host}': {str(e)}"
        }

    for ip_str in resolved_ips:
        is_blocked, reason = _is_ssrf_blocked_ip(ip_str)
        if is_blocked:
            return {
                "module": "tls",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {"resolved_ip": ip_str},
                "details": f"SSRF Protection: Host resolved to prohibited address {ip_str} ({reason})"
            }

    # Perform SSL connection
    context = ssl.create_default_context()
    try:
        with socket.create_connection((clean_host, port_num), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=clean_host) as ssock:
                tls_version = ssock.version()
                cert = ssock.getpeercert()

        # Parse certificate expiration
        not_after_str = cert.get("notAfter", "")
        # Format: 'May 15 12:00:00 2026 GMT'
        cert_valid = False
        expiry_iso = None
        if not_after_str:
            try:
                exp_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                cert_valid = exp_dt > datetime.now(timezone.utc)
                expiry_iso = exp_dt.isoformat()
            except Exception:
                cert_valid = False

        if tls_version == "TLSv1.3" and cert_valid:
            score = 1.0
            claim_supported = True
        elif tls_version == "TLSv1.2" and cert_valid:
            score = 0.6
            claim_supported = False
        else:
            score = 0.0
            claim_supported = False

        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": score,
            "claim_supported": claim_supported,
            "metrics": {
                "host": clean_host,
                "port": port_num,
                "tls_version": tls_version,
                "certificate_valid": cert_valid,
                "certificate_expiry": expiry_iso,
                "resolved_ips": resolved_ips,
            },
            "details": f"Observed {tls_version} on {clean_host}:{port_num} (Certificate valid until: {expiry_iso})."
        }
    except ssl.SSLError as e:
        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {"host": clean_host, "port": port_num},
            "details": f"TLS handshake failed: {str(e)}"
        }
    except socket.timeout:
        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {"host": clean_host, "port": port_num},
            "details": f"Connection timed out (5s) attempting to reach {clean_host}:{port_num}."
        }
    except Exception as e:
        return {
            "module": "tls",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {"host": clean_host, "port": port_num},
            "details": f"Network error during TLS probe: {str(e)}"
        }


# =========================================================================
# 4. LOG INTEGRITY VERIFIER (Item: q25_decision_logging, Dimension: Accountability)
# =========================================================================
def verify_log_integrity(
    log_content: str,
    claimed_value: Any = None
) -> Dict[str, Any]:
    """
    Verifies cryptographic hash chain in a JSONL log file.
    Format: Each line is a JSON object with "prev_hash", "data", "hash".
    Line 1 prev_hash must be 'GENESIS' or 64 zeros.
    hash = SHA-256(prev_hash + canonical_data).
    Score: valid chain -> 1.0; any break or empty file -> 0.0.
    """
    item_id = "q25_decision_logging"
    dimension = "Accountability & Governance"

    if not log_content or not log_content.strip():
        return {
            "module": "log_integrity",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: Empty log file provided."
        }

    lines = [ln.strip() for ln in log_content.strip().splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return {
            "module": "log_integrity",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: No log entries found in file."
        }

    prev_expected_hash: Optional[str] = None
    verified_records = 0

    for idx, line_str in enumerate(lines):
        try:
            entry = json.loads(line_str)
        except Exception:
            return {
                "module": "log_integrity",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {"failed_line": idx + 1},
                "details": f"Error: Line {idx + 1} is not valid JSON."
            }

        if not isinstance(entry, dict) or "prev_hash" not in entry or "data" not in entry or "hash" not in entry:
            return {
                "module": "log_integrity",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {"failed_line": idx + 1},
                "details": f"Error: Line {idx + 1} must contain 'prev_hash', 'data', and 'hash' fields."
            }

        prev_hash = str(entry["prev_hash"]).strip()
        data_field = entry["data"]
        claimed_hash = str(entry["hash"]).strip().lower()

        # Line 1 check
        if idx == 0:
            genesis_valid = (
                prev_hash.upper() == "GENESIS" or
                prev_hash == ("0" * 64)
            )
            if not genesis_valid:
                return {
                    "module": "log_integrity",
                    "item_id": item_id,
                    "dimension": dimension,
                    "claimed_value": claimed_value,
                    "verified_score": 0.0,
                    "claim_supported": False,
                    "metrics": {"failed_line": 1, "found_prev_hash": prev_hash},
                    "details": "Error: Line 1 'prev_hash' must be 'GENESIS' or 64 zeros."
                }
        else:
            if prev_hash.lower() != prev_expected_hash:
                return {
                    "module": "log_integrity",
                    "item_id": item_id,
                    "dimension": dimension,
                    "claimed_value": claimed_value,
                    "verified_score": 0.0,
                    "claim_supported": False,
                    "metrics": {
                        "failed_line": idx + 1,
                        "expected_prev_hash": prev_expected_hash,
                        "found_prev_hash": prev_hash
                    },
                    "details": f"Broken chain at line {idx + 1}: prev_hash does not match previous entry's hash."
                }

        # Canonicalize data
        if isinstance(data_field, (dict, list)):
            canonical_data = json.dumps(data_field, sort_keys=True, separators=(',', ':'))
        else:
            canonical_data = str(data_field)

        computed_hash = hashlib.sha256((prev_hash + canonical_data).encode("utf-8")).hexdigest()

        if computed_hash != claimed_hash:
            return {
                "module": "log_integrity",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {
                    "failed_line": idx + 1,
                    "computed_hash": computed_hash,
                    "claimed_hash": claimed_hash
                },
                "details": f"Cryptographic tamper detected at line {idx + 1}: SHA-256 digest mismatch."
            }

        prev_expected_hash = claimed_hash
        verified_records += 1

    return {
        "module": "log_integrity",
        "item_id": item_id,
        "dimension": dimension,
        "claimed_value": claimed_value,
        "verified_score": 1.0,
        "claim_supported": True,
        "metrics": {
            "verified_records": verified_records,
            "chain_head_hash": prev_expected_hash
        },
        "details": f"Verified unbroken SHA-256 cryptographic chain across {verified_records} log entries."
    }


# =========================================================================
# 5. ROBUSTNESS VERIFIER (Item: q1_adversarial_tested, Dimension: Security)
# =========================================================================
def verify_robustness(
    csv_content: str,
    claimed_value: Any = None
) -> Dict[str, Any]:
    """
    Measures accuracy degradation under adversarial perturbations.
    Input CSV columns: clean_prediction, perturbed_prediction, ground_truth.
    drop = (acc_clean - acc_pert) / acc_clean.
    Score: drop <= 0.05 -> 1.0; drop <= 0.15 -> 0.5; else 0.0.
    """
    item_id = "q1_adversarial_tested"
    dimension = "Security & Robustness"

    if not csv_content or not csv_content.strip():
        return {
            "module": "robustness",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": "Error: Empty CSV content provided."
        }

    try:
        raw_lines = [ln for ln in csv_content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if not raw_lines:
            return {
                "module": "robustness",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {},
                "details": "Error: Empty CSV content provided."
            }
        reader = csv.DictReader(io.StringIO("\n".join(raw_lines)))
        if not reader.fieldnames:
            return {
                "module": "robustness",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {},
                "details": "Error: Missing CSV header row."
            }

        fields = {f.strip().lower(): f for f in reader.fieldnames}
        req_cols = ["clean_prediction", "perturbed_prediction", "ground_truth"]
        missing = [c for c in req_cols if c not in fields]
        if missing:
            return {
                "module": "robustness",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {},
                "details": f"Error: Missing required CSV columns: {', '.join(missing)}"
            }

        col_clean = fields["clean_prediction"]
        col_pert = fields["perturbed_prediction"]
        col_gt = fields["ground_truth"]

        total_rows = 0
        clean_correct = 0
        pert_correct = 0

        for row in reader:
            total_rows += 1
            clean_p = str(row.get(col_clean, "")).strip()
            pert_p = str(row.get(col_pert, "")).strip()
            gt = str(row.get(col_gt, "")).strip()

            if clean_p == gt:
                clean_correct += 1
            if pert_p == gt:
                pert_correct += 1

        if total_rows == 0:
            return {
                "module": "robustness",
                "item_id": item_id,
                "dimension": dimension,
                "claimed_value": claimed_value,
                "verified_score": 0.0,
                "claim_supported": False,
                "metrics": {},
                "details": "Error: Evaluation CSV contains 0 rows."
            }

        acc_clean = clean_correct / total_rows
        acc_pert = pert_correct / total_rows

        if acc_clean > 0:
            acc_drop = (acc_clean - acc_pert) / acc_clean
        else:
            acc_drop = 0.0 if acc_pert == 0.0 else 1.0

        acc_drop = max(0.0, round(acc_drop, 4))

        # Score: drop <= 0.05 -> 1.0; drop <= 0.15 -> 0.5; else 0.0
        if acc_drop <= 0.05:
            score = 1.0
        elif acc_drop <= 0.15:
            score = 0.5
        else:
            score = 0.0

        claim_supported = bool(score >= 0.7)

        return {
            "module": "robustness",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": score,
            "claim_supported": claim_supported,
            "metrics": {
                "clean_accuracy": round(acc_clean, 4),
                "perturbed_accuracy": round(acc_pert, 4),
                "accuracy_drop_pct": round(acc_drop * 100, 2),
                "total_evaluation_samples": total_rows
            },
            "details": f"Clean Accuracy = {acc_clean*100:.1f}%, Perturbed Accuracy = {acc_pert*100:.1f}%, Degradation Drop = {acc_drop*100:.1f}%."
        }
    except Exception as e:
        return {
            "module": "robustness",
            "item_id": item_id,
            "dimension": dimension,
            "claimed_value": claimed_value,
            "verified_score": 0.0,
            "claim_supported": False,
            "metrics": {},
            "details": f"Execution error computing robustness degradation: {str(e)}"
        }
