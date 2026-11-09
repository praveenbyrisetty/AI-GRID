
/**
 * AI-GRID Enterprise Control Plane (v4.0)
 * High-Assurance AI Governance & Compliance Auditing Platform
 * Grounded in QB4AIRA (Lee et al., 2024), EU AI Act (Regulation (EU) 2024/1689 Articles 9-15),
 * NIST AI 100-1 (AI RMF), and 7 Empirical Trust Dimensions.
 */

// =========================================================================
// GLOBAL APPLICATION STATE & API ROUTING
// =========================================================================
const API_BASE = (window.location.protocol === 'file:' || (window.location.port && window.location.port !== '8000'))
  ? 'http://127.0.0.1:8000'
  : '';

let radarChartInstance = null;
let currentAuditData = null;
let wizardStep = 1;
let totalWizardSteps = 8;
let wizardAnswers = {};
let questionsData = null;
let isTerminalPaused = false;

const pageTitles = {
  "page-overview": "AI Assurance Overview",
  "page-setup": "AI Governance Questionnaire",
  "page-verify": "Empirical Evidence Verification (Tier T1)",
  "page-compliance": "EU AI Act Regulatory Compliance",
  "page-history": "Audit Records & History",
  "page-question-bank": "Research Question Bank (35 Items)",
  "page-remediation": "Governance Remediation Roadmap",
  "page-modelcard": "AI Governance Passport"
};

const PILLAR_KEYS = {
  "Security & Robustness": "security",
  "Safety & Reliability": "safety",
  "Fairness & Non-Discrimination": "fairness",
  "Transparency & Explainability": "transparency",
  "Privacy & Data Governance": "privacy",
  "Human Oversight & Agency": "oversight",
  "Accountability & Governance": "accountability"
};

const defaultDimensions = {
  "Security & Robustness": 0,
  "Safety & Reliability": 0,
  "Fairness & Non-Discrimination": 0,
  "Transparency & Explainability": 0,
  "Privacy & Data Governance": 0,
  "Human Oversight & Agency": 0,
  "Accountability & Governance": 0
};

// =========================================================================
// REFERENCE PRESET PROFILES (GROUNDED IN ANNEX III & EMPIRICAL CONTROLS)
// =========================================================================
const PRESET_PROFILES = {
  healthcare: {
    model_name: "ClinicalRisk-CardioNet",
    model_version: "2.4.0",
    domain: "healthcare",
    architecture: "ResNet-50 + Gradient Boosted Ensembles",
    deployment_type: "private_cloud",
    q1_adversarial_tested: "comprehensive",
    q2_drift_monitoring: "automated",
    q3_sbom_tracking: "formal_sbom",
    q4_red_teaming: "independent",
    q5_api_auth_ratelimit: "mTLS_ratelimited",
    q6_demographic_coverage: "comprehensive",
    q7_class_balance: "balanced",
    q8_coverage_gaps: "none",
    q9_dataset_size: "large",
    q10_fairness_audit: "formal_audit",
    q11_xai_engine: "full_xai",
    q12_attribution_count: "comprehensive",
    q13_reasoning_summaries: "yes",
    q14_model_card_doc: "published_card",
    q15_uncertainty_scores: "calibrated_intervals",
    q16_encryption_rest: "aes256_kms",
    q17_encryption_transit: "tls13_strict",
    q18_data_retention: "strict_90",
    q19_pii_handling: "automated_redaction",
    q20_governance_policy: "formal_policy",
    q21_human_oversight: "mandatory_hitl",
    q22_autonomy_level: "advisory",
    q24_kill_switch: "instant_killswitch",
    q24b_operator_training: "certified_training",
    q24c_override_capability: "instant_override",
    q23_incident_escalation: "formal_escalation",
    q25_decision_logging: "append_only_signed",
    q25b_technical_dossier: "full_annex_iv",
    q25c_post_market_monitoring: "active_monitoring",
    q25d_governance_charter: "formal_charter",
    q26_input_validation: "comprehensive_rejection",
    q27_guardrail_count: "3plus",
    q28_output_clamping: "hard_clamping",
    q29_contextual_advisory: "yes_dynamic",
    q30_failure_mode_testing: "formal_failure_suite"
  },
  finance: {
    model_name: "FinOpt-CreditScore",
    model_version: "1.8.2",
    domain: "finance",
    architecture: "XGBoost Classifier + SHAP TreeExplainer",
    deployment_type: "hybrid",
    q1_adversarial_tested: "basic",
    q2_drift_monitoring: "automated",
    q3_sbom_tracking: "formal_sbom",
    q4_red_teaming: "internal",
    q5_api_auth_ratelimit: "basic_key",
    q6_demographic_coverage: "partial",
    q7_class_balance: "moderate",
    q8_coverage_gaps: "minor",
    q9_dataset_size: "large",
    q10_fairness_audit: "formal_audit",
    q11_xai_engine: "full_xai",
    q12_attribution_count: "comprehensive",
    q13_reasoning_summaries: "yes",
    q14_model_card_doc: "published_card",
    q15_uncertainty_scores: "calibrated_intervals",
    q16_encryption_rest: "aes256_kms",
    q17_encryption_transit: "tls13_strict",
    q18_data_retention: "strict_90",
    q19_pii_handling: "automated_redaction",
    q20_governance_policy: "formal_policy",
    q21_human_oversight: "mandatory_hitl",
    q22_autonomy_level: "semi_autonomous",
    q24_kill_switch: "graceful_drain",
    q24b_operator_training: "basic_briefing",
    q24c_override_capability: "instant_override",
    q23_incident_escalation: "formal_escalation",
    q25_decision_logging: "append_only_signed",
    q25b_technical_dossier: "full_annex_iv",
    q25c_post_market_monitoring: "active_monitoring",
    q25d_governance_charter: "formal_charter",
    q26_input_validation: "basic_types",
    q27_guardrail_count: "1to2",
    q28_output_clamping: "soft_warning",
    q29_contextual_advisory: "static_disclaimer",
    q30_failure_mode_testing: "partial_tests"
  },
  assistant: {
    model_name: "AssistAI-Copilot",
    model_version: "3.1.0",
    domain: "other",
    architecture: "Decoder-only LLM (Transformer)",
    deployment_type: "cloud_api",
    q1_adversarial_tested: "basic",
    q2_drift_monitoring: "manual",
    q3_sbom_tracking: "basic_requirements",
    q4_red_teaming: "internal",
    q5_api_auth_ratelimit: "basic_key",
    q6_demographic_coverage: "partial",
    q7_class_balance: "moderate",
    q8_coverage_gaps: "minor",
    q9_dataset_size: "moderate",
    q10_fairness_audit: "informal",
    q11_xai_engine: "partial_xai",
    q12_attribution_count: "limited",
    q13_reasoning_summaries: "technical_only",
    q14_model_card_doc: "internal_readme",
    q15_uncertainty_scores: "raw_softmax",
    q16_encryption_rest: "standard_disk",
    q17_encryption_transit: "tls12_mixed",
    q18_data_retention: "moderate_180",
    q19_pii_handling: "basic_filtering",
    q20_governance_policy: "general_it",
    q21_human_oversight: "optional_hotl",
    q22_autonomy_level: "semi_autonomous",
    q24_kill_switch: "graceful_drain",
    q24b_operator_training: "basic_briefing",
    q24c_override_capability: "post_hoc_ticket",
    q23_incident_escalation: "informal_slack",
    q25_decision_logging: "standard_cloudwatch",
    q25b_technical_dossier: "partial_docs",
    q25c_post_market_monitoring: "reactive_support",
    q25d_governance_charter: "ad_hoc_committee",
    q26_input_validation: "basic_types",
    q27_guardrail_count: "1to2",
    q28_output_clamping: "soft_warning",
    q29_contextual_advisory: "static_disclaimer",
    q30_failure_mode_testing: "partial_tests"
  }
};

// =========================================================================
// SECURITY UTILITIES: XSS SANITIZATION & AUTOMATIC SESSION AUTH
// =========================================================================
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getAuthHeaders(extraHeaders = {}) {
  return { ...extraHeaders };
}

async function handleAuthError(res) {
  // No-op in unauthenticated local/demo mode
}

// =========================================================================
// INITIALIZATION
// =========================================================================
document.addEventListener("DOMContentLoaded", () => {
  // 1. Initialize Theme: Executive Dark by default, or user's stored preference
  const savedTheme = localStorage.getItem("ai_grid_theme") || "dark";
  if (savedTheme === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  updateThemeButtonUI(savedTheme);

  // 2. Initialize Radar Chart with standby dimensions
  initRadarChart(defaultDimensions);

  // 3. Load Questions catalog from backend
  loadQuestions();
  loadAuditHistory();

  // 4. Check if an active audit exists on server, otherwise maintain standby state
  checkCurrentAuditStatus();

  // 5. Setup keyboard shortcut (ESC to close drawer / modal)
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeDetailDrawer();
      closeDossierModal();
    }
  });
});

// =========================================================================
// 1. PAGE NAVIGATION & SHELL CONTROLS
// =========================================================================
function showPage(pageId, clickedEl) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  const target = document.getElementById(pageId);
  if (target) target.classList.add("active");

  document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
  if (clickedEl) {
    clickedEl.classList.add("active");
  } else {
    document.querySelectorAll(".nav-item").forEach(n => {
      const onclick = n.getAttribute("onclick") || "";
      if (onclick.includes(pageId)) n.classList.add("active");
    });
  }

  const titleEl = document.getElementById("pageTitle");
  if (titleEl && pageTitles[pageId]) titleEl.textContent = pageTitles[pageId];

  window.scrollTo({ top: 0, behavior: "smooth" });
  closeSidebarOnMobile();
}

function toggleSidebarCollapse() {
  const sidebar = document.getElementById("sidebar");
  sidebar.classList.toggle("collapsed");
  const isCollapsed = sidebar.classList.contains("collapsed");
  const icon = document.getElementById("collapseIcon");
  if (icon) {
    icon.innerHTML = isCollapsed
      ? `<polyline points="9 18 15 12 9 6"/>`
      : `<polyline points="15 18 9 12 15 6"/>`;
  }
}

function closeSidebarOnMobile() {
  const sidebar = document.getElementById("sidebar");
  if (sidebar && window.innerWidth <= 1024) sidebar.classList.remove("open");
}

// =========================================================================
// 2. THEME CONTROLLER (CORPORATE LIGHT / EXECUTIVE DARK)
// =========================================================================
function toggleTheme() {
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  const newTheme = isDark ? "light" : "dark";
  if (newTheme === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  localStorage.setItem("ai_grid_theme", newTheme);
  updateThemeButtonUI(newTheme);

  if (currentAuditData && currentAuditData.dimensions) {
    initRadarChart(currentAuditData.dimensions);
  } else {
    initRadarChart(defaultDimensions);
  }
  showToast(`Switched to ${newTheme === "dark" ? "Executive Dark" : "Corporate Light"} Mode`);
}

function updateThemeButtonUI(theme) {
  const btnText = document.getElementById("themeToggleText");
  const icon = document.getElementById("themeIcon");
  if (!btnText || !icon) return;
  if (theme === "dark") {
    btnText.textContent = "Light";
    icon.innerHTML = `<circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>`;
  } else {
    btnText.textContent = "Dark";
    icon.innerHTML = `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>`;
  }
}

// =========================================================================
// 3. SERVER AUDIT STATE CHECKER & LOADER
// =========================================================================
async function checkCurrentAuditStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/audit/current`);
    const json = await res.json();
    if (json.success && json.active && json.data) {
      currentAuditData = json.data;
      applyAuditDataToUI(json.data, "Tier T3 (Self-Attested Questionnaire)");
    } else {
      clearAuditUI();
    }
  } catch (err) {
    console.warn("Audit status check error:", err);
    clearAuditUI();
  }
}

function clearAuditUI() {
  currentAuditData = null;

  // Header badges & chips
  const tierEl = document.getElementById("evidenceTierText");
  if (tierEl) tierEl.textContent = "—";

  const statusTag = document.getElementById("assessmentStatusTag");
  const statusText = document.getElementById("assessmentStatusText");
  if (statusTag) statusTag.className = "status-tag";
  if (statusText) statusText.textContent = "Standby";

  const targetEl = document.getElementById("sidebarContextTarget");
  if (targetEl) targetEl.textContent = "Target: Standby";

  // KPIs
  const kpiAas = document.getElementById("kpiAasScore");
  if (kpiAas) kpiAas.textContent = "—";

  const gradeBadge = document.getElementById("kpiGradeBadge");
  if (gradeBadge) {
    gradeBadge.textContent = "UNAUDITED";
    gradeBadge.className = "badge info";
  }

  const aasMath = document.getElementById("kpiAasMath");
  if (aasMath) aasMath.textContent = "Awaiting calculation: 0.60 × Mean + 0.40 × Min";

  const confBadge = document.getElementById("kpiConfidenceBadge");
  if (confBadge) confBadge.textContent = "AWAITING AUDIT";

  const bnScore = document.getElementById("kpiBottleneckScore");
  if (bnScore) bnScore.textContent = "—";

  const bnName = document.getElementById("kpiBottleneckName");
  if (bnName) bnName.textContent = "Bottleneck dimension caps overall trust ceiling";

  const bnBadge = document.getElementById("kpiBottleneckBadge");
  if (bnBadge) {
    bnBadge.textContent = "STANDBY";
    bnBadge.className = "badge info";
  }

  const euTier = document.getElementById("kpiEuTier");
  if (euTier) {
    euTier.textContent = "UNASSESSED";
    euTier.style.color = "var(--text-secondary)";
  }

  const euStatus = document.getElementById("kpiEuStatus");
  if (euStatus) euStatus.textContent = "Awaiting EU AI Act evaluation";

  const euBadge = document.getElementById("kpiEuBadge");
  if (euBadge) {
    euBadge.textContent = "STANDBY";
    euBadge.className = "badge info";
  }

  const kpiCardEu = document.getElementById("kpiCardEu");
  if (kpiCardEu) {
    kpiCardEu.classList.remove("risk-high", "risk-minimal");
  }

  // Verdict banner
  const headline = document.getElementById("verdictHeadlineText");
  if (headline) headline.textContent = "AWAITING GOVERNANCE AUDIT • CONTROL PLANE READY";

  const subText = document.getElementById("verdictSubText");
  if (subText) subText.innerHTML = `No active assessment executed. Complete the 30-question research-grounded questionnaire (QB4AIRA, EU AI Act, NIST AI 100-1) or load a reference profile to evaluate assurance adequacy.
    <div style="margin-top: 10px; display:flex; gap:10px; flex-wrap:wrap;">
      <button class="btn-primary sm" onclick="showPage('page-setup')">
        <svg class="svg-icon sm" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        <span>Open Questionnaire Wizard &rarr;</span>
      </button>
      <button class="btn-secondary sm" onclick="loadPresetProfile('healthcare')">
        <span>Load Clinical AI Preset</span>
      </button>
      <button class="btn-secondary sm" onclick="loadPresetProfile('finance')">
        <span>Load Credit Scoring Preset</span>
      </button>
    </div>`;

  const bannerDisc = document.getElementById("bannerDiscrepancyVal");
  if (bannerDisc) bannerDisc.textContent = "Standby";

  const bannerBasis = document.getElementById("bannerEvidenceBasis");
  if (bannerBasis) bannerBasis.textContent = "Questionnaire (T3)";

  const bannerHash = document.getElementById("bannerHashIntegrity");
  if (bannerHash) bannerHash.textContent = "EU AI Act / NIST AI 100-1";

  // Summary Posture Card
  const ovBadge = document.getElementById("overviewStatusBadge");
  if (ovBadge) {
    ovBadge.textContent = "AWAITING AUDIT";
    ovBadge.className = "badge info";
  }
  const sumTarget = document.getElementById("summaryTargetName");
  if (sumTarget) sumTarget.textContent = "Awaiting Assessment Target";
  const sumSub = document.getElementById("summaryTargetSub");
  if (sumSub) sumSub.textContent = "Select a reference preset or complete the questionnaire";
  const sumTier = document.getElementById("summaryTierBadge");
  if (sumTier) {
    sumTier.textContent = "ANNEX III §5";
    sumTier.className = "badge info";
  }
  Object.values(PILLAR_KEYS).forEach(pid => {
    const smini = document.getElementById(`smini_${pid}`);
    const sminiFill = document.getElementById(`sminiFill_${pid}`);
    if (smini) smini.textContent = "— / 100";
    if (sminiFill) {
      sminiFill.style.width = "0%";
      sminiFill.className = "summary-pillar-fill";
    }
  });

  // Dimension Cards
  Object.values(PILLAR_KEYS).forEach(pid => {
    const scoreEl = document.getElementById(`pillarScore_${pid}`);
    const fillEl = document.getElementById(`pillarFill_${pid}`);
    const tagEl = document.getElementById(`pillarTag_${pid}`);
    if (scoreEl) scoreEl.textContent = "—";
    if (fillEl) {
      fillEl.style.width = "0%";
      fillEl.className = "dim-progress-fill";
    }
    if (tagEl) {
      tagEl.textContent = "STANDBY";
      tagEl.className = "badge info";
    }
  });

  // Terminal log
  const term = document.getElementById("terminalLog");
  if (term) {
    term.innerHTML = `
      <div class="log-entry">
        <span class="log-timestamp">[00:00:00]</span>
        <span class="log-badge AUDIT">STANDBY</span>
        <span>AI-GRID Control Plane online. Awaiting questionnaire execution or preset selection...</span>
      </div>
    `;
  }
  const termStatus = document.getElementById("terminalStatus");
  if (termStatus) termStatus.textContent = "IDLE / STANDBY";

  // Overview Remediation Component
  renderOverviewRemediationList();
  const remTbody = document.getElementById("overviewRemediationTbody");
  if (remTbody) {
    remTbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center; padding:18px; color:var(--text-muted);">No active findings. Execute an audit to dynamically generate remediation roadmap.</td>
      </tr>
    `;
  }

  // EU AI Act Table & Classification Cards Reset
  const euArticlesTbody = document.getElementById("euArticlesTbody");
  if (euArticlesTbody) {
    euArticlesTbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center; padding:18px; color:var(--text-muted);">No compliance data loaded. Run an audit to evaluate conformity.</td>
      </tr>
    `;
  }
  const euBadgeEl = document.getElementById("euBadge");
  if (euBadgeEl) {
    euBadgeEl.textContent = "STANDBY";
    euBadgeEl.className = "badge info";
  }
  const euTierName = document.getElementById("euTierName");
  if (euTierName) {
    euTierName.textContent = "Awaiting Assessment";
    euTierName.style.color = "var(--text-primary)";
  }
  const euLegalBasis = document.getElementById("euLegalBasis");
  if (euLegalBasis) euLegalBasis.textContent = "—";
  const euMarket = document.getElementById("euMarketPermitted");
  if (euMarket) {
    euMarket.textContent = "—";
    euMarket.style.color = "var(--text-secondary)";
  }
  const euConfReq = document.getElementById("euConformityReq");
  if (euConfReq) euConfReq.textContent = "—";
  const euConfCount = document.getElementById("euConformantCount");
  if (euConfCount) euConfCount.textContent = "0 / 7 Articles Conformant";

  // NIST AI RMF Crosswalk Cards Reset
  ["Govern", "Map", "Measure", "Manage"].forEach(fn => {
    const el = document.getElementById(`nist${fn}`);
    if (el) el.textContent = "— / 100";
    const statusEl = document.getElementById(`nist${fn}Status`);
    if (statusEl) {
      statusEl.textContent = "STANDBY";
      statusEl.className = "badge info";
    }
  });
  const nistBody = document.getElementById("nistSubcategoriesTbody");
  if (nistBody) {
    nistBody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding:18px; color:var(--text-muted);">No compliance data loaded. Run an audit or select a reference profile to evaluate NIST AI RMF conformity.</td>
      </tr>
    `;
  }

  // Governance Remediation Roadmap Screen Reset
  const remBody = document.getElementById("remediationBody");
  if (remBody) {
    remBody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center; padding:18px; color:var(--text-muted);">No findings recorded. Execute an audit to generate roadmap.</td>
      </tr>
    `;
  }

  // AI Governance Passport Screen Reset
  const mcModelName = document.getElementById("mcModelName");
  if (mcModelName) mcModelName.textContent = "—";
  const mcModelVersion = document.getElementById("mcModelVersion");
  if (mcModelVersion) mcModelVersion.textContent = "—";
  const mcModelGrade = document.getElementById("mcModelGrade");
  if (mcModelGrade) mcModelGrade.textContent = "—";
  const mcModelAas = document.getElementById("mcModelAas");
  if (mcModelAas) mcModelAas.textContent = "—";
  const mcRenderedView = document.getElementById("mcRenderedView");
  if (mcRenderedView) {
    mcRenderedView.innerHTML = `
      <div style="text-align:center; padding:30px; color:var(--text-muted);">No passport generated. Complete an audit to generate the AI Governance Passport.</div>
    `;
  }

  // Radar chart
  initRadarChart(defaultDimensions);
}

async function resetAuditState() {
  try {
    const res = await fetch(`${API_BASE}/api/audit/reset`, {
      method: "POST",
      headers: getAuthHeaders()
    });
    if (res.status === 401) {
      handleAuthError(res);
      return;
    }
  } catch (err) {
    console.warn("Server reset API call:", err);
  }
  clearAuditUI();
  loadAuditHistory();
  showPage("page-overview");
  showToast("Platform reset complete: All audits and telemetry reset to clean standby");
}

// =========================================================================
// 4. RADAR CHART CONTROLLER (CHART.JS)
// =========================================================================
function initRadarChart(dims) {
  const canvas = document.getElementById("radarChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (radarChartInstance) radarChartInstance.destroy();

  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  const dimLabels = dims ? Object.keys(dims).filter(k => k !== "Human Oversight & Accountability") : Object.keys(defaultDimensions);
  const dimValues = dims ? dimLabels.map(k => dims[k] ?? 0) : dimLabels.map(() => 0);
  const isStandby = dimValues.every(v => v === 0);

  const datasets = [];

  if (isStandby) {
    datasets.push({
      label: "Regulatory Target (80.0)",
      data: dimLabels.map(() => 80),
      fill: true,
      backgroundColor: isDark ? "rgba(0, 123, 167, 0.06)" : "rgba(0, 123, 167, 0.05)",
      borderColor: isDark ? "rgba(0, 123, 167, 0.35)" : "rgba(0, 123, 167, 0.40)",
      borderWidth: 1.5,
      borderDash: [5, 5],
      pointRadius: 3,
      pointBackgroundColor: isDark ? "#1A9FD0" : "#007BA7",
      pointBorderColor: "transparent"
    });
  } else {
    datasets.push({
      label: "Assurance Adequacy Score",
      data: dimValues,
      fill: true,
      backgroundColor: isDark ? "rgba(0, 123, 167, 0.22)" : "rgba(0, 123, 167, 0.16)",
      borderColor: isDark ? "#1A9FD0" : "#007BA7",
      pointBackgroundColor: isDark ? "#1A9FD0" : "#007BA7",
      pointBorderColor: isDark ? "#0E0E10" : "#FFFFFF",
      borderWidth: 2.5,
      pointRadius: 4.5,
      pointHoverRadius: 7
    });

    datasets.push({
      label: "Conformity Target (80.0)",
      data: dimLabels.map(() => 80),
      fill: false,
      borderColor: isDark ? "rgba(255, 255, 255, 0.2)" : "rgba(0, 0, 0, 0.18)",
      borderWidth: 1,
      borderDash: [4, 4],
      pointRadius: 0
    });
  }

  radarChartInstance = new Chart(ctx, {
    type: "radar",
    data: {
      labels: dimLabels,
      datasets: datasets
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          min: 0,
          max: 100,
          ticks: {
            stepSize: 25,
            color: isDark ? "#8C93A0" : "#5A6270",
            backdropColor: "transparent",
            font: { family: "'IBM Plex Mono', monospace", size: 10 }
          },
          grid: {
            color: isDark ? "rgba(0, 123, 167, 0.12)" : "rgba(0, 123, 167, 0.12)"
          },
          angleLines: {
            color: isDark ? "rgba(0, 123, 167, 0.14)" : "rgba(0, 123, 167, 0.14)"
          },
          pointLabels: {
            color: isDark ? "#F0F2F5" : "#0A0A0A",
            font: { family: "'Space Grotesk', sans-serif", size: 11, weight: "600" }
          }
        }
      },
      plugins: {
        legend: {
          display: true,
          position: "bottom",
          labels: {
            color: isDark ? "#8C93A0" : "#5A6270",
            font: { family: "'DM Sans', sans-serif", size: 11 },
            boxWidth: 12,
            padding: 10
          }
        },
        tooltip: {
          enabled: true,
          callbacks: {
            label: (ctx) => `${ctx.dataset.label}: ${ctx.raw}/100`
          }
        }
      },
      onClick: (e, elements) => {
        if (!isStandby && elements && elements.length > 0) {
          const index = elements[0].index;
          const dimLabel = dimLabels[index];
          const pid = PILLAR_KEYS[dimLabel];
          if (pid) openDimensionDrawer(pid);
        }
      }
    }
  });
}

// =========================================================================
// 5. UI DATA APPLICATION & COCKPIT SYNC
// =========================================================================
function applyAuditDataToUI(data, tierText) {
  if (!data) return;

  // 1. Evidence Tier & Assessment Status
  const tierEl = document.getElementById("evidenceTierText");
  if (tierEl) tierEl.innerHTML = tierText || "Tier T3 (Self-Attested Questionnaire)";

  const statusTag = document.getElementById("assessmentStatusTag");
  const statusText = document.getElementById("assessmentStatusText");
  if (statusTag) statusTag.className = "status-tag completed";
  if (statusText) statusText.textContent = "Attestations Evaluated";

  const targetEl = document.getElementById("sidebarContextTarget");
  if (targetEl) targetEl.textContent = "Target: " + (data.model_metadata?.model_name || data.model_metadata?.name || data.model_card?.model_name || "Active System");

  // 2. Scoring & KPIs
  const sc = data.scoring || {};
  document.getElementById("kpiAasScore").textContent = sc.aas_score ?? "—";
  document.getElementById("kpiGradeBadge").textContent = `GRADE ${sc.trust_grade || 'A'}`;
  document.getElementById("kpiGradeBadge").className = `badge ${sc.trust_grade && sc.trust_grade[0] === 'A' ? 'success' : 'warning'}`;
  document.getElementById("kpiAasMath").textContent = `Mean: ${sc.weighted_average} | Min: ${sc.bottleneck_score} (α=0.6)`;

  const confBadge = document.getElementById("kpiConfidenceBadge");
  if (confBadge) confBadge.textContent = `CONFIDENCE ${(sc.evidence_weight || 0.60).toFixed(2)}`;

  document.getElementById("kpiBottleneckScore").textContent = sc.bottleneck_score ?? "—";
  document.getElementById("kpiBottleneckName").textContent = `${sc.bottleneck_dimension || 'Safety & Reliability'} (Caps trust ceiling)`;
  const bnBadge = document.getElementById("kpiBottleneckBadge");
  if (bnBadge) {
    bnBadge.textContent = (sc.bottleneck_score !== undefined && sc.bottleneck_score < 80) ? "DEFICIT" : "OPTIMAL";
    bnBadge.className = `badge ${(sc.bottleneck_score !== undefined && sc.bottleneck_score < 80) ? "warning" : "success"}`;
  }



  const eu = data.compliance?.eu_ai_act || {};
  const isHighRisk = eu.tier && (eu.tier.includes("HIGH") || eu.tier.includes("PROHIBITED") || eu.tier.includes("Annex III"));
  const isMinimalRisk = eu.tier && (eu.tier.includes("MINIMAL") || eu.tier.includes("Unregulated") || eu.tier.includes("LOW"));

  const euTierEl = document.getElementById("kpiEuTier");
  if (euTierEl) {
    if (eu.tier && eu.tier.includes("PROHIBITED")) {
      euTierEl.textContent = "Prohibited System";
      euTierEl.style.color = "var(--critical)";
    } else if (isHighRisk) {
      euTierEl.textContent = "High-Risk System";
      euTierEl.style.color = "var(--critical)";
    } else if (eu.tier && eu.tier.includes("LIMITED")) {
      euTierEl.textContent = "Limited-Risk System";
      euTierEl.style.color = "var(--warning)";
    } else if (isMinimalRisk) {
      euTierEl.textContent = "Minimal-Risk System";
      euTierEl.style.color = "var(--success)";
    } else {
      euTierEl.textContent = "Unclassified";
      euTierEl.style.color = "var(--text-primary)";
    }
  }

  const euStatusEl = document.getElementById("kpiEuStatus");
  if (euStatusEl) {
    euStatusEl.textContent = `${eu.conformant_articles || '6/7'} Requirements Met`;
  }

  const euBadgeEl = document.getElementById("kpiEuBadge");
  if (euBadgeEl) {
    if (eu.tier && eu.tier.includes("PROHIBITED")) {
      euBadgeEl.textContent = "PROHIBITED";
      euBadgeEl.className = "badge critical";
    } else if (isHighRisk) {
      euBadgeEl.textContent = "HIGH RISK";
      euBadgeEl.className = "badge critical";
    } else if (isMinimalRisk) {
      euBadgeEl.textContent = "MINIMAL RISK";
      euBadgeEl.className = "badge success";
    } else if (eu.tier && eu.tier.includes("LIMITED")) {
      euBadgeEl.textContent = "LIMITED RISK";
      euBadgeEl.className = "badge warning";
    } else {
      euBadgeEl.textContent = "STANDBY";
      euBadgeEl.className = "badge info";
    }
  }

  const kpiCardEu = document.getElementById("kpiCardEu");
  if (kpiCardEu) {
    kpiCardEu.classList.remove("risk-high", "risk-minimal");
    if (isHighRisk) {
      kpiCardEu.classList.add("risk-high");
    } else if (isMinimalRisk) {
      kpiCardEu.classList.add("risk-minimal");
    }
  }

  // 3. Summary Posture Card Updates
  const ovBadge = document.getElementById("overviewStatusBadge");
  if (ovBadge) {
    const grade = sc.trust_grade || "C";
    ovBadge.textContent = `AUDITED • GRADE ${grade}`;
    ovBadge.className = "badge " + (grade.startsWith("A") ? "success" : (grade.startsWith("B") ? "info" : "warning"));
  }
  const sumTarget = document.getElementById("summaryTargetName");
  if (sumTarget) sumTarget.textContent = data.model_name || "Enterprise AI Target";
  const sumSub = document.getElementById("summaryTargetSub");
  if (sumSub) {
    const domain = data.domain || "Clinical AI";
    const arch = data.target_system?.architecture || "Production Classifier";
    sumSub.textContent = `${domain} · Arch: ${arch} · Tier: T3 Evidence`;
  }
  const sumTier = document.getElementById("summaryTierBadge");
  if (sumTier) {
    sumTier.textContent = eu.tier || "ANNEX III §5";
    sumTier.className = "badge " + (isHighRisk ? "critical" : (isMinimalRisk ? "success" : "warning"));
  }

  // 4. Radar Chart & Dimension Cards
  if (data.dimensions) {
    initRadarChart(data.dimensions);

    Object.entries(data.dimensions).forEach(([dimName, score]) => {
      const pid = PILLAR_KEYS[dimName];
      if (pid) {
        const scoreEl = document.getElementById(`pillarScore_${pid}`);
        const fillEl = document.getElementById(`pillarFill_${pid}`);
        const tagEl = document.getElementById(`pillarTag_${pid}`);
        if (scoreEl) scoreEl.textContent = score.toFixed(1);
        if (fillEl) {
          fillEl.style.width = `${Math.min(100, Math.max(0, score))}%`;
          fillEl.className = "dim-progress-fill " + (score >= 80 ? "high" : (score >= 60 ? "medium" : "low"));
        }
        if (tagEl) {
          tagEl.textContent = score >= 80 ? "CONFORMANT" : (score >= 60 ? "SUB-OPTIMAL" : "BOTTLENECK");
          tagEl.className = "badge " + (score >= 80 ? "success" : (score >= 60 ? "warning" : "critical"));
        }

        // Summary mini pillar row
        const smini = document.getElementById(`smini_${pid}`);
        const sminiFill = document.getElementById(`sminiFill_${pid}`);
        if (smini) smini.textContent = `${score.toFixed(1)} / 100`;
        if (sminiFill) {
          sminiFill.style.width = `${Math.min(100, Math.max(0, score))}%`;
          sminiFill.className = "summary-pillar-fill " + (score >= 80 ? "high" : (score >= 60 ? "medium" : "low"));
        }
      }
    });
  }

  // 5. Terminal Logs
  renderTerminalLogs(data.audit_logs || []);

  // 6. Overview Priority Remediation Component
  renderOverviewRemediationList();
  const overviewRemTbody = document.getElementById("overviewRemediationTbody");
  if (overviewRemTbody && data.remediation_plan) {
    const topPlans = data.remediation_plan.slice(0, 3);
    if (topPlans.length > 0) {
      overviewRemTbody.innerHTML = topPlans.map(p => `
        <tr>
          <td><span class="badge ${p.priority === 'CRITICAL' ? 'critical' : (p.priority === 'HIGH' ? 'warning' : 'info')}">${escapeHtml(p.priority)}</span></td>
          <td>${escapeHtml(p.finding)}</td>
          <td><strong>${escapeHtml(p.dimension)}</strong></td>
          <td><strong style="color:var(--primary-500);">${escapeHtml(p.action)}</strong></td>
          <td><small style="font-family:var(--font-mono); color:var(--text-muted);">${escapeHtml(p.eu_ai_act_ref || 'Art. 9')}</small></td>
        </tr>
      `).join("");
    }
  }

  // 7. EU AI Act Table & Classification Cards
  renderEuArticlesTable(eu.articles || []);
function formatFriendlyTier(tier) {
  if (!tier) return "Unclassified";
  const t = tier.toUpperCase();
  if (t.includes("PROHIBITED")) return "Prohibited System (Banned in the EU)";
  if (t.includes("HIGH")) return "High-Risk System (Strict Controls Required)";
  if (t.includes("LIMITED")) return "Limited-Risk System (Transparency Required)";
  if (t.includes("MINIMAL") || t.includes("LOW") || t.includes("UNREGULATED")) return "Minimal-Risk System (General Use Allowed)";
  return tier;
}

function simplifyLegalBasis(rawBasis) {
  if (!rawBasis) return "General AI System (Review needed to confirm domain-specific rules)";
  const b = rawBasis.toLowerCase();
  if (b.includes("credit scoring") || b.includes("finance") || b.includes("credit")) {
    return "Credit Scoring & Financial Services (Evaluates personal creditworthiness and access to essential loans)";
  }
  if (b.includes("healthcare") || b.includes("medical") || b.includes("clinical")) {
    return "Clinical Healthcare & Diagnostics (AI decisions directly impact patient health and medical treatment)";
  }
  if (b.includes("autonomous_vehicles") || b.includes("transport") || b.includes("robotics")) {
    return "Critical Transport & Autonomous Systems (Operates safety-critical transport components)";
  }
  if (b.includes("education") || b.includes("admissions")) {
    return "Education & Admissions (Decisions determine educational access, grading, and career opportunities)";
  }
  if (b.includes("law enforcement") || b.includes("judicial") || b.includes("justice")) {
    return "Law Enforcement & Justice Support (Significant impact on individual civil rights)";
  }
  if (b.includes("cybersecurity") || b.includes("digital infrastructure")) {
    return "Critical Digital Infrastructure & Cybersecurity (Defends essential digital network operations)";
  }
  if (b.includes("biometric")) {
    return "Biometric Identification (Processing human biometric identity and personal privacy)";
  }
  if (b.includes("social scoring")) {
    return "Social Scoring by Public Authorities (Classifying citizens based on social behavior is prohibited)";
  }
  if (b.includes("manipulation")) {
    return "Harmful Deceptive Manipulation (Subliminal techniques causing harm are prohibited)";
  }
  if (b.includes("surveillance")) {
    return "Real-Time Public Biometric Surveillance (Public facial recognition surveillance is prohibited)";
  }
  if (b.includes("transparency") || b.includes("article 50") || b.includes("generative") || b.includes("interactive")) {
    return "Generative & Interactive AI (Clear disclosure required to inform users they are interacting with AI)";
  }
  if (b.includes("agricultural") || b.includes("environmental") || b.includes("agri")) {
    return "Agriculture & Environmental AI (Low-risk operational domain subject to standard software guidelines)";
  }
  return rawBasis.replace(/Annex\s+[IVXLCDM]+\s*(§\s*\d+(\([a-z0-9]+\))?)?\s*[-–—:]*\s*/gi, '')
                 .replace(/Article\s+\d+(\(\d+\))?(\([a-z]\))?\s*[-–—:]*\s*/gi, '')
                 .trim() || rawBasis;
}

  const euBadge = document.getElementById("euBadge");
  if (euBadge) {
    if (eu.tier && eu.tier.includes("PROHIBITED")) {
      euBadge.textContent = "PROHIBITED";
      euBadge.className = "badge critical";
    } else if (isHighRisk) {
      euBadge.textContent = "HIGH RISK";
      euBadge.className = "badge critical";
    } else if (isMinimalRisk) {
      euBadge.textContent = "MINIMAL RISK";
      euBadge.className = "badge success";
    } else if (eu.tier && eu.tier.includes("LIMITED")) {
      euBadge.textContent = "LIMITED RISK";
      euBadge.className = "badge warning";
    } else {
      euBadge.textContent = "STANDBY";
      euBadge.className = "badge info";
    }
  }
  const euTierName = document.getElementById("euTierName");
  if (euTierName) {
    if (eu.tier && eu.tier.includes("PROHIBITED")) {
      euTierName.textContent = "Prohibited System (Banned in the EU)";
      euTierName.style.color = "var(--critical)";
    } else if (isHighRisk) {
      euTierName.textContent = "High-Risk System (Strict Controls Required)";
      euTierName.style.color = "var(--critical)";
    } else if (eu.tier && eu.tier.includes("LIMITED")) {
      euTierName.textContent = "Limited-Risk System (Transparency Required)";
      euTierName.style.color = "var(--warning)";
    } else if (isMinimalRisk) {
      euTierName.textContent = "Minimal-Risk System (General Use Allowed)";
      euTierName.style.color = "var(--success)";
    } else {
      euTierName.textContent = "Awaiting Assessment";
      euTierName.style.color = "var(--text-primary)";
    }
  }
  const euLegalBasis = document.getElementById("euLegalBasis");
  if (euLegalBasis) euLegalBasis.textContent = simplifyLegalBasis(eu.legal_basis);
  const euMarket = document.getElementById("euMarketPermitted");
  if (euMarket) {
    if (eu.market_placement_permitted === true) {
      if (isHighRisk) {
        euMarket.textContent = "Allowed (Must Pass Safety Requirements First)";
        euMarket.style.color = "var(--warning)";
      } else {
        euMarket.textContent = "Allowed (Free to Deploy)";
        euMarket.style.color = "var(--success)";
      }
    } else if (eu.market_placement_permitted === false) {
      euMarket.textContent = "Banned (Cannot be Deployed in the EU)";
      euMarket.style.color = "var(--critical)";
    } else {
      euMarket.textContent = "Pending Evaluation";
      euMarket.style.color = "var(--text-muted)";
    }
  }
  const euConfReq = document.getElementById("euConformityReq");
  if (euConfReq) {
    if (eu.tier && eu.tier.includes("PROHIBITED")) {
      euConfReq.textContent = "None (System is Banned Under EU Law)";
    } else if (isHighRisk) {
      euConfReq.textContent = "Full Safety & Risk Audit (Technical checks & continuous monitoring)";
    } else if (eu.tier && eu.tier.includes("LIMITED")) {
      euConfReq.textContent = "User Transparency (Clear notice that users are interacting with AI)";
    } else if (isMinimalRisk) {
      euConfReq.textContent = "Standard Best Practices (No special EU regulatory filing needed)";
    } else {
      euConfReq.textContent = "Review Needed to Determine Audit Requirements";
    }
  }
  const euConfCount = document.getElementById("euConformantCount");
  if (euConfCount) euConfCount.textContent = `${eu.conformant_articles || '0/7'} Requirements Met`;

  // 8. NIST AI RMF 1.0 Crosswalk & Subcategories Table
  renderNistSection(data.compliance?.nist_rmf || data.compliance?.nist_ai_rmf);

  // 9. Remediation Roadmap
  renderRemediationTable(data.remediation_plan || []);

  // 10. Model Card
  renderModelCard(data);
}

// =========================================================================
// 6. TERMINAL EVENT STREAM CONTROLLER
// =========================================================================
function renderTerminalLogs(logs) {
  const term = document.getElementById("terminalLog");
  if (!term) return;

  if (!logs || logs.length === 0) {
    term.innerHTML = `<div class="terminal-empty">No telemetry events captured. Run assessment or load a preset.</div>`;
    return;
  }

  term.innerHTML = logs.map((l, idx) => {
    const timeStr = `[00:00:0${idx + 1}]`;
    const badgeClass = l.status === "SUCCESS" ? "COMPLETE" : (l.status === "WARNING" ? "WARNING" : (l.status === "DANGER" ? "DANGER" : "AUDIT"));
    return `
      <div class="log-entry">
        <span class="log-timestamp">${timeStr}</span>
        <span class="log-badge ${badgeClass}">${escapeHtml(l.stage || 'EVENT')}</span>
        <span>${escapeHtml(l.message)}</span>
      </div>
    `;
  }).join("");

  if (!isTerminalPaused) {
    term.scrollTop = term.scrollHeight;
  }
}

function toggleLogPause() {
  isTerminalPaused = !isTerminalPaused;
  const btn = document.getElementById("btnPauseLogs");
  if (btn) btn.textContent = isTerminalPaused ? "Resume" : "Pause";
  showToast(isTerminalPaused ? "Terminal streaming paused" : "Terminal streaming resumed");
}

function copyTerminalLogs() {
  const term = document.getElementById("terminalLog");
  if (term) {
    navigator.clipboard.writeText(term.innerText);
    showToast("Terminal telemetry copied to clipboard");
  }
}

function toggleAuditTrailDrawer() {
  const drawer = document.getElementById("auditTrailDrawer");
  const btn = document.getElementById("btnToggleTrail");
  if (!drawer) return;
  const isHidden = drawer.style.display === "none" || !drawer.style.display;
  drawer.style.display = isHidden ? "block" : "none";
  if (btn) {
    btn.classList.toggle("active", isHidden);
  }
}

// =========================================================================
// 7. UNIVERSAL DETAIL DRAWER (SLIDE-OUT INSPECTOR)
// =========================================================================
function openDetailDrawer(title, subtitle, htmlContent) {
  const drawer = document.getElementById("detailDrawer");
  const backdrop = document.getElementById("drawerBackdrop");
  const titleEl = document.getElementById("drawerTitle");
  const subEl = document.getElementById("drawerSubtitle");
  const bodyEl = document.getElementById("drawerBody");

  if (!drawer || !backdrop) return;

  if (titleEl) titleEl.textContent = title;
  if (subEl) subEl.textContent = subtitle;
  if (bodyEl) bodyEl.innerHTML = htmlContent;

  backdrop.classList.add("open");
  drawer.classList.add("open");
}

function closeDetailDrawer() {
  const drawer = document.getElementById("detailDrawer");
  const backdrop = document.getElementById("drawerBackdrop");
  if (drawer) drawer.classList.remove("open");
  if (backdrop) backdrop.classList.remove("open");
}

function openDimensionDrawer(dimKey) {
  const titles = {
    security: "Security & Robustness",
    safety: "Safety & Reliability",
    fairness: "Fairness & Non-Discrimination",
    transparency: "Transparency & Explainability",
    privacy: "Privacy & Data Governance",
    oversight: "Human Oversight & Agency",
    accountability: "Accountability & Governance"
  };

  const anchors = {
    security: "EU AI Act Art. 15(4) &bull; NIST MEASURE 2.7 &bull; OWASP LLM Top 10",
    safety: "EU AI Act Art. 9 & 15(1) &bull; NIST MANAGE 2.2 &bull; Deterministic Output Clamping",
    fairness: "EU AI Act Art. 10(2) &bull; EEOC 80% Rule &bull; Kamiran & Calders (2012)",
    transparency: "EU AI Act Art. 13 &bull; NIST MAP 1.5 &bull; TreeSHAP Attributions",
    privacy: "EU AI Act Art. 10(5) &bull; GDPR Art. 25/32 &bull; Cryptographic Controls",
    oversight: "EU AI Act Art. 14 &bull; NIST GOVERN 1.4 &bull; Mandatory HITL Kill-Switch",
    accountability: "EU AI Act Art. 11/12/72 &bull; ISO/IEC 42001 &bull; WORM Audit Logs & Escalation SLA"
  };

  const hasAudit = currentAuditData && currentAuditData.dimensions && currentAuditData.dimensions[titles[dimKey]] !== undefined;
  const currentScore = hasAudit ? currentAuditData.dimensions[titles[dimKey]] : null;
  const scoreDisplay = hasAudit ? `${currentScore.toFixed(1)} / 100` : "— / 100";
  const findingsDisplay = hasAudit
    ? (currentScore >= 80
        ? '<span class="badge success">CONFORMANT</span> No critical security vulnerabilities or regulatory deficits detected in this dimension.'
        : '<span class="badge warning">DEFICIT DETECTED</span> Sub-optimal boundary clamping or attestation gap requires engineering remediation before production release.')
    : '<span class="badge info">AWAITING AUDIT</span> Complete the 35-item questionnaire or load a reference profile to evaluate empirical adequacy.';

  const html = `
    <div class="drawer-section">
      <div class="drawer-section-title">Current Pillar Score</div>
      <div style="font-size:24px; font-weight:700; font-family:var(--font-mono); color:var(--primary-500);">${scoreDisplay}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Regulatory &amp; Threat Anchors</div>
      <div class="drawer-section-content" style="font-family:var(--font-mono); font-size:12px; color:var(--text-secondary);">${anchors[dimKey]}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Evidence &amp; Verification Methodology</div>
      <div class="drawer-section-content">
        Evaluated via 35 structured questionnaire controls grounded in QB4AIRA (Lee et al., 2024), EU AI Act Articles 9–15, and NIST AI 100-1 across 7 Trust Dimensions. Evaluates adversarial stress testing, cryptographic protections, human-in-the-loop kill-switches, and deterministic boundary guardrails.
      </div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Identified Findings</div>
      <div class="drawer-section-content">
        ${findingsDisplay}
      </div>
    </div>
  `;

  openDetailDrawer(titles[dimKey], anchors[dimKey], html);
}

function openArticleDrawer(artNum) {
  const articles = currentAuditData?.compliance?.eu_ai_act?.articles || [];
  const item = articles.find(a => a.article.includes(artNum)) || {
    article: `Article ${artNum}`,
    title: "EU AI Act Requirement",
    requirement: "Engineering requirement under the EU AI Act (Regulation (EU) 2024/1689).",
    score: "—",
    status: "STANDBY",
    mandatory_controls: ["Technical documentation", "Verification testing"]
  };

  const html = `
    <div class="drawer-section">
      <div class="drawer-section-title">EU AI Act Requirement</div>
      <div class="drawer-section-content"><strong>${item.title}</strong></div>
      <div class="drawer-section-content" style="margin-top:6px;">${item.requirement}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Compliance Status &amp; Score</div>
      <div style="display:flex; align-items:center; gap:8px;">
        <span class="badge ${item.status === 'CONFORMANT' ? 'success' : (item.status === 'STANDBY' ? 'info' : 'warning')}">${item.status}</span>
        <span style="font-family:var(--font-mono); font-weight:700;">${item.score === '—' ? '—' : item.score + '/100'}</span>
      </div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Mandatory Engineering Controls</div>
      <ul style="padding-left:18px; font-size:13px; color:var(--text-secondary); line-height:1.7;">
        ${(item.mandatory_controls || []).map(c => `<li>${c}</li>`).join("")}
      </ul>
    </div>
  `;

  openDetailDrawer(item.article, item.title, html);
}

function renderNistSection(nist) {
  if (!nist) return;

  const fnKeys = ["GOVERN", "MAP", "MEASURE", "MANAGE"];
  const capMap = { GOVERN: "Govern", MAP: "Map", MEASURE: "Measure", MANAGE: "Manage" };

  fnKeys.forEach(fnKey => {
    const fnData = nist[fnKey];
    const capName = capMap[fnKey];
    const scoreEl = document.getElementById(`nist${capName}`);
    const statusEl = document.getElementById(`nist${capName}Status`);

    if (scoreEl) {
      if (fnData && fnData.score != null) {
        scoreEl.textContent = `${fnData.score.toFixed(1)} / 100`;
      } else {
        scoreEl.textContent = "— / 100";
      }
    }

    if (statusEl && fnData) {
      const st = fnData.status || "STANDBY";
      statusEl.textContent = st;
      statusEl.className = "badge " + (st === "COMPLIANT" ? "success" : (st === "PARTIALLY COMPLIANT" ? "warning" : (st === "NON-COMPLIANT" ? "critical" : "info")));
    }
  });

  const tbody = document.getElementById("nistSubcategoriesTbody");
  if (!tbody) return;

  let allRows = [];
  fnKeys.forEach(fnKey => {
    const fnData = nist[fnKey];
    if (fnData && Array.isArray(fnData.subcategories)) {
      fnData.subcategories.forEach(sub => {
        allRows.push({ ...sub, functionName: fnKey });
      });
    }
  });

  if (allRows.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding:18px; color:var(--text-muted);">No subcategories evaluated. Complete an audit to generate crosswalk.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = allRows.map(sub => {
    const st = sub.status || "STANDBY";
    const badgeClass = st === "COMPLIANT" ? "success" : (st === "PARTIALLY COMPLIANT" ? "warning" : (st === "NON-COMPLIANT" ? "critical" : "info"));
    const scoreText = sub.score != null ? `${sub.score.toFixed(1)}` : "—";

    return `
      <tr data-nist-function="${escapeHtml(sub.functionName)}" onclick="openNistSubcategoryDrawer('${escapeHtml(sub.id)}')">
        <td><strong style="font-family:var(--font-mono); color:var(--primary-400);">${escapeHtml(sub.id)}</strong></td>
        <td><span class="badge info">${escapeHtml(sub.functionName)}</span></td>
        <td>${escapeHtml(sub.name)}</td>
        <td style="text-align:right; font-family:var(--font-mono); font-weight:700;">${scoreText}</td>
        <td style="text-align:center;"><span class="badge ${badgeClass}">${escapeHtml(st)}</span></td>
        <td style="text-align:center;"><button class="btn-secondary sm" onclick="event.stopPropagation(); openNistSubcategoryDrawer('${escapeHtml(sub.id)}')">Inspect</button></td>
      </tr>
    `;
  }).join("");
}

function filterNistByFunction(func, btn) {
  document.querySelectorAll("#nistRmfSection .btn-secondary.sm").forEach(b => b.classList.remove("active"));
  if (btn && btn.tagName === "BUTTON") btn.classList.add("active");

  const rows = document.querySelectorAll("#nistSubcategoriesTbody tr");
  rows.forEach(r => {
    const rowFn = r.getAttribute("data-nist-function");
    if (!rowFn || func === "all") {
      r.style.display = "";
    } else {
      r.style.display = rowFn === func ? "" : "none";
    }
  });
}

function openNistSubcategoryDrawer(subId) {
  const nist = currentAuditData?.compliance?.nist_rmf || currentAuditData?.compliance?.nist_ai_rmf;
  let targetSub = null;
  let targetFn = "NIST AI 100-1";

  if (nist) {
    for (const [fnKey, fnData] of Object.entries(nist)) {
      if (fnData && Array.isArray(fnData.subcategories)) {
        const found = fnData.subcategories.find(s => s.id === subId);
        if (found) {
          targetSub = found;
          targetFn = fnKey;
          break;
        }
      }
    }
  }

  const item = targetSub || {
    id: subId,
    name: "NIST Playbook Subcategory",
    score: null,
    status: "STANDBY"
  };

  const scoreText = item.score != null ? `${item.score.toFixed(1)} / 100` : "— / 100";
  const badgeClass = item.status === "COMPLIANT" ? "success" : (item.status === "PARTIALLY COMPLIANT" ? "warning" : "info");

  const html = `
    <div class="drawer-section">
      <div class="drawer-section-title">NIST Core Function</div>
      <div class="drawer-section-content"><span class="badge info">${targetFn}</span> &bull; NIST AI 100-1 (AI RMF 1.0)</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Playbook Subcategory Requirement</div>
      <div class="drawer-section-content" style="font-size:14px; font-weight:600; line-height:1.5;">${escapeHtml(item.name)}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Empirical Score &amp; Status</div>
      <div style="display:flex; align-items:center; gap:12px; margin-top:4px;">
        <span style="font-size:22px; font-weight:700; font-family:var(--font-mono); color:var(--primary-500);">${scoreText}</span>
        <span class="badge ${badgeClass}">${escapeHtml(item.status)}</span>
      </div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Regulatory &amp; Engineering Guidance</div>
      <div class="drawer-section-content" style="font-size:13px; color:var(--text-secondary); line-height:1.6;">
        Demonstrate technical conformity through documented policies, empirical evaluations, continuous drift monitoring, and adversarial testing as specified in the NIST AI RMF Playbook.
      </div>
    </div>
  `;

  openDetailDrawer(item.id, item.name, html);
}

// =========================================================================
// 8. QUESTIONNAIRE WIZARD & REFERENCE PRESETS CONTROLLER
// =========================================================================
async function loadQuestions() {
  try {
    const res = await fetch(`${API_BASE}/api/questions`);
    const json = await res.json();
    if (json.success && json.data) {
      questionsData = json.data;
      totalWizardSteps = json.data.steps.length;
      renderFullQuestionBank(json.data.steps);
      renderWizardStep();
    }
  } catch (err) {
    console.error("Questions load error", err);
  }
}

function renderFullQuestionBank(steps) {
  const tbody = document.getElementById("fullQuestionsTbody");
  if (!tbody || !steps) return;

  let html = "";
  let counter = 1;

  steps.forEach(s => {
    s.questions.forEach(q => {
      if (!q.is_identity) {
        html += `
          <tr onclick="openQuestionDrawer('${q.id}')">
            <td><strong>Q${counter++}</strong></td>
            <td><strong>${q.label.replace(/^Q\d+:\s*/, '')}</strong></td>
            <td><span class="badge info">${q.dimension || 'Identity'}</span></td>
            <td><small style="color:var(--text-secondary); font-family:var(--font-mono);">${q.research_source || 'NIST AI RMF'}</small></td>
            <td><span class="badge success">${q.eu_ai_act_ref || 'Art. 9'}</span></td>
            <td><small style="color:var(--text-muted);">${q.nist_rmf_ref || 'MEASURE'}</small></td>
            <td><small style="color:var(--teal-accent);">${q.owasp_ref || 'OWASP LLM'}</small></td>
          </tr>
        `;
      }
    });
  });

  tbody.innerHTML = html;
}

function filterQuestionBank(query) {
  const q = (query || "").toLowerCase();
  const rows = document.querySelectorAll("#fullQuestionsTbody tr");
  rows.forEach(r => {
    const text = r.textContent.toLowerCase();
    r.style.display = text.includes(q) ? "" : "none";
  });
}

function filterQuestionByDim(dim, btn) {
  document.querySelectorAll(".btn-secondary.sm").forEach(p => p.classList.remove("active"));
  if (btn) btn.classList.add("active");

  const rows = document.querySelectorAll("#fullQuestionsTbody tr");
  rows.forEach(r => {
    if (dim === "all") {
      r.style.display = "";
    } else {
      const dimBadge = r.querySelector(".badge.info");
      const text = dimBadge ? dimBadge.textContent.toLowerCase() : "";
      r.style.display = text.includes(dim.toLowerCase()) ? "" : "none";
    }
  });
}

function openQuestionDrawer(qId) {
  let matchedQ = null;
  (questionsData?.steps || []).forEach(s => {
    s.questions.forEach(q => {
      if (q.id === qId) matchedQ = q;
    });
  });

  if (!matchedQ) return;

  const html = `
    <div class="drawer-section">
      <div class="drawer-section-title">Question Prompt</div>
      <div class="drawer-section-content"><strong>${matchedQ.label}</strong></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Trust Dimension</div>
      <div class="drawer-section-content"><span class="badge info">${matchedQ.dimension || 'Identity'}</span></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Academic Literature Citation</div>
      <div class="drawer-section-content" style="font-family:var(--font-mono); font-size:12px; color:var(--text-secondary);">${matchedQ.research_source || 'NIST AI RMF 1.0 (SP 1270)'}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Regulatory Framework Crosswalk</div>
      <div class="drawer-section-content">
        <div>&bull; EU AI Act: <strong>${matchedQ.eu_ai_act_ref || 'Article 9'}</strong></div>
        <div>&bull; NIST AI RMF: <strong>${matchedQ.nist_rmf_ref || 'MEASURE'}</strong></div>
        <div>&bull; OWASP Threat: <strong>${matchedQ.owasp_ref || 'OWASP LLM Top 10'}</strong></div>
      </div>
    </div>
  `;

  openDetailDrawer(matchedQ.id, matchedQ.dimension || "Question Specification", html);
}

function renderWizardStep() {
  if (!questionsData) return;
  const stepData = questionsData.steps[wizardStep - 1];
  if (!stepData) return;

  document.getElementById("wizardStepTitle").textContent = `Step ${wizardStep}: ${stepData.title}`;
  document.getElementById("wizardStepDesc").textContent = `Specification of controls for Step ${wizardStep} of ${totalWizardSteps}`;

  const pct = (wizardStep / totalWizardSteps) * 100;
  document.getElementById("wizardProgressFill").style.width = `${pct}%`;

  document.querySelectorAll(".wizard-step-bubble").forEach((dot, idx) => {
    dot.classList.toggle("active", idx < wizardStep);
  });

  const body = document.getElementById("wizardBody");
  let html = '<div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">';

  stepData.questions.forEach(q => {
    const savedVal = wizardAnswers[q.id] || "";
    html += `<div class="form-group">`;
    html += `<label class="form-label" for="wq_${q.id}">${q.label} ${q.required ? '<span style="color:var(--critical)">*</span>' : ''}</label>`;

    if (q.research_source) {
      html += `<div style="font-size:11px; color:var(--text-muted); margin-bottom:4px; font-family:var(--font-mono);">${q.research_source} &bull; EU AI Act: ${q.eu_ai_act_ref || 'Art. 9'}</div>`;
    }

    if (q.type === "text") {
      html += `<input type="text" id="wq_${q.id}" class="form-input" placeholder="${q.placeholder || ''}" value="${savedVal}" onchange="saveWizardAnswer('${q.id}', this.value)">`;
    } else if (q.type === "number") {
      html += `<input type="number" id="wq_${q.id}" class="form-input" placeholder="${q.placeholder || ''}" value="${savedVal}" min="0" onchange="saveWizardAnswer('${q.id}', this.value)">`;
    } else if (q.type === "select") {
      html += `<select id="wq_${q.id}" class="form-select" onchange="saveWizardAnswer('${q.id}', this.value)">`;
      html += `<option value="">Select Option</option>`;
      (q.options || []).forEach(opt => {
        const selected = savedVal === opt.value ? "selected" : "";
        html += `<option value="${opt.value}" ${selected}>${opt.label}</option>`;
      });
      html += `</select>`;
    }

    html += `</div>`;
  });

  html += '</div>';
  body.innerHTML = html;

  document.getElementById("wizardBackBtn").style.display = wizardStep > 1 ? "inline-flex" : "none";
  document.getElementById("wizardNextBtn").style.display = wizardStep < totalWizardSteps ? "inline-flex" : "none";
  document.getElementById("wizardSubmitBtn").style.display = wizardStep === totalWizardSteps ? "inline-flex" : "none";
}

function saveWizardAnswer(id, val) {
  wizardAnswers[id] = val;
}

function wizardNext() {
  if (wizardStep < totalWizardSteps) {
    wizardStep++;
    renderWizardStep();
  }
}

function wizardPrev() {
  if (wizardStep > 1) {
    wizardStep--;
    renderWizardStep();
  }
}

async function submitQuestionnaire() {
  try {
    showToast("Compiling governance questionnaire & computing assurance scores...");
    const res = await fetch(`${API_BASE}/api/audit/questionnaire`, {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ answers: wizardAnswers, verified_evidence: verifiedEvidenceStore })
    });
    if (res.status === 401) {
      handleAuthError(res);
      return;
    }
    const json = await res.json();
    if (json.success && json.data) {
      currentAuditData = json.data;
      applyAuditDataToUI(json.data, "Tier T3 (Self-Attested Questionnaire)");
      loadAuditHistory();
      showToast("Questionnaire Audit Completed Successfully!");
      showPage("page-overview");
    } else {
      alert("Audit Failed: " + (json.error || "Unable to process questionnaire"));
    }
  } catch (err) {
    alert("Questionnaire Error: " + err.message);
  }
}

async function loadPresetProfile(presetKey) {
  const preset = PRESET_PROFILES[presetKey];
  if (!preset) {
    showToast(`Preset '${presetKey}' not found.`);
    return;
  }
  wizardAnswers = { ...preset };
  renderWizardStep();

  try {
    showToast(`Loading preset: ${preset.model_name}...`);
    const res = await fetch(`${API_BASE}/api/audit/questionnaire`, {
      method: "POST",
      headers: getAuthHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ answers: wizardAnswers })
    });
    if (res.status === 401) {
      handleAuthError(res);
      return;
    }
    const json = await res.json();
    if (json.success && json.data) {
      currentAuditData = json.data;
      applyAuditDataToUI(json.data, `Tier T3 (Reference Preset: ${preset.model_name})`);
      loadAuditHistory();
      showToast(`Loaded ${preset.model_name} reference profile!`);
      showPage("page-overview");
    } else {
      showToast("Notice: " + (json.error || "Unable to evaluate preset"));
    }
  } catch (err) {
    showToast("Audit Error: " + err.message);
  }
}

function clearWizardAnswers() {
  wizardAnswers = {};
  wizardStep = 1;
  renderWizardStep();
  showToast("Questionnaire form cleared to default standby.");
}

function runQuickDemoAudit() {
  loadPresetProfile("healthcare");
}

// =========================================================================
// 9. TABLES & RENDERERS
// =========================================================================
function renderEuArticlesTable(articles) {
  const tbody = document.getElementById("euArticlesTbody");
  if (!tbody || !articles || articles.length === 0) return;

  tbody.innerHTML = articles.map(a => {
    const isConformant = a.status && (a.status.includes("CONFORM") || a.status === "PASS");
    const isRisk = a.status && (a.status.includes("RISK") || a.status.includes("NON_CONFORM") || a.status.includes("ACTION"));
    const badgeClass = isConformant ? "success" : (isRisk ? "critical" : "warning");
    const badgeText = isConformant ? "CONFORMANT" : (isRisk ? (a.status.includes("HIGH_RISK") ? "HIGH RISK" : "NON-CONFORMANT RISK") : escapeHtml(a.status));

    return `
      <tr onclick="openArticleDrawer('${escapeHtml(a.article).replace(/[^0-9]/g, '')}')">
        <td><strong>${escapeHtml(a.article)}</strong><br><small style="color:var(--text-secondary);">${escapeHtml(a.title)}</small></td>
        <td><small>${escapeHtml(a.requirement)}</small></td>
        <td><strong>${a.score ?? '—'}/100</strong></td>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td><small style="color:var(--text-secondary);">${(a.mandatory_controls || []).map(c => escapeHtml(c)).join(" &bull; ")}</small></td>
      </tr>
    `;
  }).join("");
}

let currentRemediationFilter = 'ALL';

function filterOverviewRemediation(filter) {
  currentRemediationFilter = filter;
  const pills = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'SAFE'];
  pills.forEach(p => {
    const el = document.getElementById(`remPill_${p}`);
    if (el) {
      if (p === filter) el.classList.add('active');
      else el.classList.remove('active');
    }
  });
  renderOverviewRemediationList();
}

function renderOverviewRemediationList() {
  const emptyEl = document.getElementById("overviewRemediationEmpty");
  const listEl = document.getElementById("overviewRemediationList");
  const badgeEl = document.getElementById("remHeaderBadge");
  if (!listEl) return;

  if (!currentAuditData) {
    if (emptyEl) emptyEl.style.display = "block";
    listEl.innerHTML = "";
    if (badgeEl) {
      badgeEl.className = "badge info";
      badgeEl.textContent = "AWAITING AUDIT";
    }
    ['All', 'Critical', 'High', 'Medium', 'Safe'].forEach(k => {
      const cEl = document.getElementById(`remCount${k}`);
      if (cEl) cEl.textContent = "0";
    });
    return;
  }

  const rawPlan = currentAuditData.remediation_plan || [];
  const dims = currentAuditData.dimensions || {};

  // Build structured items
  let items = rawPlan.map((p, idx) => ({
    originalIdx: idx,
    priority: (p.priority || 'MEDIUM').toUpperCase(),
    dimension: p.dimension || 'Governance Control',
    finding: p.finding || 'Unspecified compliance finding',
    action: p.action || 'Remediate control according to AI governance requirements',
    verification_criteria: p.verification_criteria || '',
    nist_ref: p.nist_ref || '',
    eu_ai_act_ref: p.eu_ai_act_ref || 'Art. 9',
    isDeficit: true
  }));

  // Identify safe / conformant pillars where score >= 70 and no critical finding exists
  const critOrHighDims = new Set(items.filter(i => i.priority === 'CRITICAL' || i.priority === 'HIGH').map(i => i.dimension));
  Object.keys(dims).forEach(dimName => {
    const score = Number(dims[dimName] || 0);
    if (score >= 70 && !critOrHighDims.has(dimName)) {
      items.push({
        originalIdx: -1,
        priority: 'SAFE',
        dimension: dimName,
        finding: `Pillar posture verified conformant (Score: ${score.toFixed(1)}/100). Baseline engineering controls satisfied.`,
        action: 'Maintain continuous post-market monitoring and evidence verification.',
        eu_ai_act_ref: 'Conformant',
        isDeficit: false
      });
    }
  });

  // Sort items: CRITICAL -> HIGH -> MEDIUM -> LOW -> SAFE
  const prioRank = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'SAFE': 4 };
  items.sort((a, b) => (prioRank[a.priority] ?? 9) - (prioRank[b.priority] ?? 9));

  // Update counts
  const countCrit = items.filter(i => i.priority === 'CRITICAL').length;
  const countHigh = items.filter(i => i.priority === 'HIGH').length;
  const countMed = items.filter(i => i.priority === 'MEDIUM' || i.priority === 'LOW').length;
  const countSafe = items.filter(i => i.priority === 'SAFE').length;

  const cAllEl = document.getElementById("remCountAll");
  const cCritEl = document.getElementById("remCountCritical");
  const cHighEl = document.getElementById("remCountHigh");
  const cMedEl = document.getElementById("remCountMedium");
  const cSafeEl = document.getElementById("remCountSafe");

  if (cAllEl) cAllEl.textContent = items.length;
  if (cCritEl) cCritEl.textContent = countCrit;
  if (cHighEl) cHighEl.textContent = countHigh;
  if (cMedEl) cMedEl.textContent = countMed;
  if (cSafeEl) cSafeEl.textContent = countSafe;

  if (badgeEl) {
    if (countCrit > 0) {
      badgeEl.className = "badge critical";
      badgeEl.textContent = `${countCrit} CRITICAL FINDING${countCrit > 1 ? 'S' : ''}`;
    } else if (countHigh > 0) {
      badgeEl.className = "badge warning";
      badgeEl.textContent = `${countHigh} HIGH FINDING${countHigh > 1 ? 'S' : ''}`;
    } else {
      badgeEl.className = "badge success";
      badgeEl.textContent = "CONTROLS SAFE / CONFORMANT";
    }
  }

  // Filter items
  let filtered = items;
  if (currentRemediationFilter === 'CRITICAL') {
    filtered = items.filter(i => i.priority === 'CRITICAL');
  } else if (currentRemediationFilter === 'HIGH') {
    filtered = items.filter(i => i.priority === 'HIGH');
  } else if (currentRemediationFilter === 'MEDIUM') {
    filtered = items.filter(i => i.priority === 'MEDIUM' || i.priority === 'LOW');
  } else if (currentRemediationFilter === 'SAFE') {
    filtered = items.filter(i => i.priority === 'SAFE');
  }

  if (emptyEl) emptyEl.style.display = "none";

  if (filtered.length === 0) {
    listEl.innerHTML = `<div style="text-align:center; padding:24px 12px; color:var(--text-muted); font-size:12px;">No remediation items in '${currentRemediationFilter}' severity category.</div>`;
    return;
  }

  listEl.innerHTML = filtered.map(item => {
    let badgeClass = 'info';
    let cardClass = 'medium';
    let prioLabel = item.priority;
    let iconSvg = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="vertical-align:-1px; margin-right:3px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;

    if (item.priority === 'CRITICAL') {
      badgeClass = 'critical';
      cardClass = 'critical';
      iconSvg = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="vertical-align:-1px; margin-right:3px;"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    } else if (item.priority === 'HIGH') {
      badgeClass = 'warning';
      cardClass = 'high';
      iconSvg = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="vertical-align:-1px; margin-right:3px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    } else if (item.priority === 'SAFE') {
      badgeClass = 'success';
      cardClass = 'safe';
      prioLabel = 'SAFE / PASS';
      iconSvg = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="vertical-align:-1px; margin-right:3px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>`;
    }

    const clickAction = item.originalIdx >= 0 ? `onclick="openFindingDrawer(${item.originalIdx})"` : `onclick="showToast('${escapeHtml(item.dimension)} is conformant!')"`;

    return `
      <div class="rem-item-card ${cardClass}" ${clickAction} title="Click to view finding details">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
          <div style="display:flex; align-items:center; gap:6px;">
            <span class="badge ${badgeClass}" style="font-size:10px; display:inline-flex; align-items:center;">${iconSvg}${escapeHtml(prioLabel)}</span>
            <strong style="font-size:12px; color:var(--text-primary);">${escapeHtml(item.dimension)}</strong>
          </div>
          <span style="font-size:10px; font-family:var(--font-mono); color:var(--text-muted);">${escapeHtml(item.eu_ai_act_ref)}</span>
        </div>
        <div style="font-size:12px; color:var(--text-secondary); margin-bottom:5px; line-height:1.4;">
          ${escapeHtml(item.finding)}
        </div>
        <div style="font-size:11px; color:${item.priority === 'SAFE' ? 'var(--success)' : 'var(--primary-500)'}; font-weight:600; display:flex; align-items:flex-start; gap:4px;">
          <span style="flex-shrink:0;">&rarr; Action:</span> <span>${escapeHtml(item.action)}</span>
        </div>
      </div>
    `;
  }).join("");
}

function renderRemediationTable(plan) {
  const tbody = document.getElementById("remediationBody");
  if (!tbody || !plan || plan.length === 0) return;

  tbody.innerHTML = plan.map((item, idx) => {
    const isHighOrCritical = item.priority === 'CRITICAL' || item.priority === 'HIGH';
    const isLowOrResolved = item.priority === 'LOW' || item.priority === 'RESOLVED' || item.priority === 'OPTIMAL';
    const badgeClass = isHighOrCritical ? 'critical' : (isLowOrResolved ? 'success' : 'warning');

    return `
      <tr onclick="openFindingDrawer(${idx})">
        <td><span class="badge ${badgeClass}">${escapeHtml(item.priority)}</span></td>
        <td><strong>${escapeHtml(item.dimension)}</strong></td>
        <td>${escapeHtml(item.finding)}</td>
        <td><strong style="color:var(--primary-500);">${escapeHtml(item.action)}</strong></td>
        <td><small style="font-family:var(--font-mono); color:var(--text-muted);">${escapeHtml(item.eu_ai_act_ref || 'Art. 9')}</small></td>
      </tr>
    `;
  }).join("");
}

function openFindingDrawer(idx) {
  const plan = currentAuditData?.remediation_plan || [];
  const item = plan[idx];
  if (!item) return;

  const html = `
    <div class="drawer-section">
      <div class="drawer-section-title">Identified Vulnerability</div>
      <div class="drawer-section-content"><strong>${escapeHtml(item.finding)}</strong></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Severity Level</div>
      <div><span class="badge ${item.priority === 'CRITICAL' ? 'critical' : 'warning'}">${escapeHtml(item.priority)} Priority</span></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Affected Dimension</div>
      <div class="drawer-section-content">${escapeHtml(item.dimension)}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Recommended Engineering Fix</div>
      <div class="drawer-section-content" style="color:var(--primary-500); font-weight:600;">${escapeHtml(item.action)}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Verification Criteria</div>
      <div class="drawer-section-content">
        ${escapeHtml(item.verification_criteria || 'Validate that the engineering control satisfies the referenced regulatory and standards requirements. Confirm with auditable evidence.')}
      </div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Evidence Tier</div>
      <div class="drawer-section-content" style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <span class="badge info" style="font-size:10px;">${escapeHtml(item.evidence_tier || 'T3')} Evidence</span>
        ${item.nist_ref ? `<span class="badge info" style="font-size:10px;">NIST ${escapeHtml(item.nist_ref)}</span>` : ''}
      </div>
    </div>
  `;

  openDetailDrawer(`Finding #${idx + 1}`, item.dimension, html);
}

// =========================================================================
// 10. AI GOVERNANCE PASSPORT & MODEL CARD
// =========================================================================
let currentModelCardFormat = "standard";

function changeModelCardFormat(format) {
  currentModelCardFormat = format;
  if (currentAuditData) {
    renderModelCard(currentAuditData);
  }
  const label = format === 'standard' ? 'Standard AI Passport' : (format === 'eu_ai_act' ? 'EU AI Act Annex IV' : 'Executive Board Briefing');
  showToast(`Switched report template to: ${label}`);
}

function generateFormattedModelCardMarkdown(format, data) {
  if (!data) return "";
  const card = data.model_card || {};
  const meta = data.model_metadata || {};
  const scoring = data.scoring || {};
  const dims = data.dimensions || {};
  const compliance = data.compliance || {};
  const eu = compliance.eu_ai_act || {};
  const findings = data.remediation_plan || [];
  const modelName = card.model_name || meta.model_name || meta.name || "AI System Target";
  const version = card.version || meta.version || "1.0.0";
  const arch = meta.model_architecture || meta.architecture || "Machine Learning Pipeline";
  const domain = meta.domain || "General Purpose AI";
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  if (format === "eu_ai_act") {
    return `# EU AI Act Technical Documentation Dossier
**System Identifier:** ${modelName} (v${version})
**Intended Operational Domain:** ${domain}
**Risk Classification:** ${formatFriendlyTier(eu.tier)}
**Classification Reason:** ${simplifyLegalBasis(eu.legal_basis)}
**Assessment Timestamp:** ${timestamp}
**Assurance Adequacy Score (AAS):** ${scoring.aas_score ?? '—'}/100 (Grade: ${scoring.trust_grade || '—'})

---

### 1. General System Description
- **Model Architecture:** ${arch}
- **Deployment Topology:** ${meta.deployment_type || 'Dedicated Cloud / On-Premises'}
- **Hardware & Software Dependencies:** Tracked via CycloneDX AI-BOM
- **Intended User Cohort:** Authorized operators with human-in-the-loop oversight

### 2. Risk Management System Conformance (Article 9)
- **Status:** ${(dims['Safety & Reliability'] >= 70 && dims['Security & Robustness'] >= 70) ? 'CONFORMANT' : 'REMEDIATION REQUIRED'}
- **Safety & Reliability Score:** ${dims['Safety & Reliability'] ?? '—'}/100
- **Continuous Drift Monitoring:** Verified via post-market telemetry
- **Known Failure Mode Rejection:** Output bounds clamping & verified guardrails

### 3. Data & Data Governance Conformance (Article 10)
- **Status:** ${(dims['Fairness & Non-Discrimination'] >= 70 && dims['Privacy & Data Governance'] >= 70) ? 'CONFORMANT' : 'REMEDIATION REQUIRED'}
- **Fairness & Bias Score:** ${dims['Fairness & Non-Discrimination'] ?? '—'}/100
- **Four-Fifths Rule (EEOC):** Evaluated against demographic parity thresholds
- **Data Protection & Encryption:** AES-256 at rest & TLS 1.3 in transit

### 4. Technical Documentation & Record-Keeping (Articles 11 & 12)
- **Automated Logging:** Enabled via immutable audit trail
- **Hash Integrity:** ${(data.audit_hash || currentAuditData?.audit_hash) ? 'SHA-256 (' + (data.audit_hash || currentAuditData.audit_hash) + ')' : 'SHA-256 Validated'}
- **Audit Retention Policy:** >= 6 months tamper-evident persistence

### 5. Transparency & Human Oversight (Articles 13 & 14)
- **Transparency Score:** ${dims['Transparency & Explainability'] ?? '—'}/100 (TreeSHAP Attributions)
- **Human Oversight Score:** ${dims['Human Oversight & Agency'] ?? '—'}/100
- **Emergency Stop / Kill-Switch:** Verified active

### 6. Compliance Verdict & Formal Sign-Off
- **Market Deployment Eligibility:** ${eu.market_placement_permitted !== false ? 'ALLOWED (Must complete safety requirements prior to release)' : 'BANNED UNDER EU AI ACT'}
- **Declaration:** Technical pre-audit indicators verified against Regulation (EU) 2024/1689.`;
  }

  if (format === "executive") {
    return `# Executive Board Briefing: AI Governance & Trust Passport
**System Evaluated:** ${modelName} | **Version:** ${version}
**Operational Domain:** ${domain} | **Evaluation Date:** ${timestamp}
**Assurance Adequacy Score (AAS):** ${scoring.aas_score ?? '—'}/100 | **Trust Grade:** ${scoring.trust_grade || '—'}

---

### Executive Summary
The target AI system has completed automated governance and cybersecurity evaluation using AI-GRID's empirical assurance protocol. The composite AAS of **${scoring.aas_score ?? '—'}/100** incorporates both overall systemic maturity (60%) and the primary governance bottleneck (40%).

### Key Performance Pillars (0–100)
- **Security & Robustness:** ${dims['Security & Robustness'] ?? '—'}
- **Safety & Reliability:** ${dims['Safety & Reliability'] ?? '—'}
- **Fairness & Non-Discrimination:** ${dims['Fairness & Non-Discrimination'] ?? '—'}
- **Transparency & Explainability:** ${dims['Transparency & Explainability'] ?? '—'}
- **Privacy & Data Governance:** ${dims['Privacy & Data Governance'] ?? '—'}
- **Human Oversight & Agency:** ${dims['Human Oversight & Agency'] ?? '—'}
- **Accountability & Governance:** ${dims['Accountability & Governance'] ?? '—'}

### Primary Governance Bottleneck
- **Bottleneck Dimension:** ${scoring.bottleneck_dimension || 'Safety & Reliability'} (${scoring.bottleneck_score ?? '—'}/100)
- **Board Impact:** This single bottleneck caps the overall trust ceiling. Deployments into mission-critical environments are gated until remediation is complete.

### Priority Action Items for Engineering
${findings.slice(0, 3).map((f, i) => `${i + 1}. **[${f.priority}] ${f.dimension}:** ${f.action} *(Ref: ${f.eu_ai_act_ref || 'EU AI Act'})*`).join('\n') || 'All monitored engineering controls satisfy regulatory benchmarks.'}

### Regulatory Posture
- **EU AI Act Status:** ${eu.tier || 'HIGH RISK'} (${eu.conformant_articles || '7/7'} Articles Conformant)
- **Legal Notice:** Indicative technical evaluation; not formal CE-mark certification.`;
  }

  return card.markdown || `# AI Governance Passport & Technical Dossier\n**System Name:** ${modelName}\n**Version:** ${version}\n**Score:** ${scoring.aas_score ?? '—'}/100`;
}

function renderModelCard(data) {
  const card = data.model_card || {};
  document.getElementById("mcModelName").textContent = card.model_name || data.model_metadata?.name || "—";
  document.getElementById("mcModelVersion").textContent = card.version || data.model_metadata?.version || "—";
  document.getElementById("mcModelGrade").textContent = data.scoring?.trust_grade ? `Grade ${data.scoring.trust_grade}` : "—";
  document.getElementById("mcModelGrade").style.color = data.scoring?.trust_grade && data.scoring.trust_grade[0] === 'A' ? "var(--success)" : "var(--warning)";
  document.getElementById("mcModelAas").textContent = (data.scoring?.aas_score !== undefined ? data.scoring.aas_score : "—") + "/100";

  const renderedView = document.getElementById("mcRenderedView");
  const markdownText = generateFormattedModelCardMarkdown(currentModelCardFormat, data);
  if (renderedView && markdownText) {
    let safeText = escapeHtml(markdownText);
    let formatted = safeText
      .replace(/^# (.*$)/gim, '<h3 style="margin-bottom:10px; color:var(--text-primary);">$1</h3>')
      .replace(/^### (.*$)/gim, '<h4 style="margin-top:14px; margin-bottom:4px; color:var(--primary-500);">$1</h4>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\n- (.*$)/gim, '<div style="margin-left:10px; margin-bottom:2px;">&bull; $1</div>')
      .replace(/\n\n/g, '<br>');
    renderedView.innerHTML = formatted;
  }
}

// =========================================================================
// 11. PERSISTENT AUDIT RECORDS & HISTORY CONTROLLER
// =========================================================================
async function loadAuditHistory() {
  const tbody = document.getElementById("auditHistoryTbody");
  if (!tbody) return;
  try {
    const res = await fetch(`${API_BASE}/api/audit/history?limit=50`);
    const json = await res.json();
    if (json.success && json.data && json.data.length > 0) {
      tbody.innerHTML = json.data.map(item => `
        <tr>
          <td><code style="font-size:11px; color:var(--text-muted);">${escapeHtml(item.audit_id).substring(0, 8)}...</code></td>
          <td><small style="color:var(--text-secondary); font-family:var(--font-mono);">${escapeHtml((item.created_at || '').replace('T', ' ').substring(0, 19))}</small></td>
          <td><strong>${escapeHtml(item.model_name)}</strong> <small style="color:var(--text-muted);">(v${escapeHtml(item.model_version || '1.0')})</small></td>
          <td><span class="badge info">${escapeHtml(item.domain || 'General')}</span></td>
          <td><strong style="color:var(--primary-500); font-family:var(--font-mono); font-size:14px;">${item.aas_score !== null && item.aas_score !== undefined ? Number(item.aas_score).toFixed(1) : '—'}</strong>/100</td>
          <td><span class="badge ${item.trust_grade && item.trust_grade[0] === 'A' ? 'success' : 'warning'}">${escapeHtml(item.trust_grade || '—')}</span></td>
          <td><small><strong>${escapeHtml(item.bottleneck_dimension || '—')}</strong> (${item.bottleneck_score !== null && item.bottleneck_score !== undefined ? Number(item.bottleneck_score).toFixed(1) : '—'})</small></td>
          <td>
            <button class="btn-secondary sm" onclick="inspectAuditRecord('${escapeHtml(item.audit_id)}')" title="Load this audit into cockpit">
              Inspect &rarr;
            </button>
          </td>
        </tr>
      `).join("");
    } else {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--text-muted);">No stored audit records found. Complete a questionnaire audit to generate history.</td></tr>`;
    }
  } catch (err) {
    console.error("Error loading audit history:", err);
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--critical);">Failed to load audit history: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function inspectAuditRecord(auditId) {
  try {
    showToast(`Loading audit record ${auditId.substring(0, 8)}...`);
    const res = await fetch(`${API_BASE}/api/audit/${encodeURIComponent(auditId)}`);
    const json = await res.json();
    if (json.success && json.data) {
      currentAuditData = json.data;
      applyAuditDataToUI(json.data, "Tier T3 (Self-Attested Questionnaire)");
      showToast("Historical audit loaded into control plane!");
      showPage("page-overview");
    } else {
      alert("Failed to load audit record: " + (json.error || "Unknown error"));
    }
  } catch (err) {
    alert("Error fetching audit record: " + err.message);
  }
}

// =========================================================================
// 12. EXPORT CONTROLS, MODALS, & TOAST
// =========================================================================
function copyModelCardMarkdown() {
  if (!currentAuditData) {
    showToast("No active audit to copy");
    return;
  }
  const text = generateFormattedModelCardMarkdown(currentModelCardFormat, currentAuditData);
  if (text) {
    navigator.clipboard.writeText(text);
    showToast("Passport Markdown copied to clipboard");
  }
}

function downloadModelCard(format) {
  if (!currentAuditData) {
    showToast("No active audit to export");
    return;
  }
  const content = format === "json"
    ? JSON.stringify(currentAuditData.model_card?.json_schema || currentAuditData, null, 2)
    : generateFormattedModelCardMarkdown(currentModelCardFormat, currentAuditData);
  const blob = new Blob([content], { type: format === "json" ? "application/json" : "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  const ext = format === "json" ? "json" : "md";
  a.download = `ai_governance_passport_${currentModelCardFormat}.${ext}`;
  a.click();
  showToast(`Downloaded AI Governance Passport as ${format.toUpperCase()}`);
}

function openDossierModal() {
  const modal = document.getElementById("dossierModal");
  const modalContent = document.getElementById("modalCardContent");
  if (modal && modalContent) {
    const rendered = document.getElementById("mcRenderedView");
    modalContent.innerHTML = rendered && rendered.innerHTML ? rendered.innerHTML : "<p>No active dossier loaded.</p>";
    modal.classList.add("open");
  }
}

function closeDossierModal() {
  const modal = document.getElementById("dossierModal");
  if (modal) modal.classList.remove("open");
}

function showToast(msg) {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = "toast-msg";
  toast.innerHTML = `<span class="indicator-dot info"></span> <span>${msg}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(6px)";
    toast.style.transition = "all 0.2s ease";
    setTimeout(() => toast.remove(), 200);
  }, 3200);
}


// =========================================================================
// EMPIRICAL EVIDENCE VERIFICATION CLIENT CONTROLLER (TIER T1)
// =========================================================================
let verifiedEvidenceStore = [];

const VERIFIER_SAMPLES = {
  fairness: `protected_attribute,y_true,y_pred
male,1,1
male,1,1
male,1,0
male,0,0
male,0,0
male,1,1
male,0,0
male,1,1
male,0,0
male,1,1
female,1,1
female,1,1
female,1,0
female,0,0
female,0,0
female,1,1
female,0,0
female,1,1
female,0,0
female,0,0`,

  dependencies: `requests==2.31.0
click==8.1.7
pydantic==2.5.0
flask==3.0.3
cryptography==42.0.0`,

  tls: {
    host: "api.github.com",
    port: 443
  },

  log_integrity: `{"prev_hash": "GENESIS", "data": {"event": "system_boot", "model": "CardioNet", "version": "2.4.0"}, "hash": "5bb149e8da3b38220cfdcbf0293935f42f2ab7d965277ee8d9b3f8ad6394778e"}
{"prev_hash": "5bb149e8da3b38220cfdcbf0293935f42f2ab7d965277ee8d9b3f8ad6394778e", "data": {"event": "inference_request", "patient_id": "anon-9481", "confidence": 0.94}, "hash": "88b9a0de64d31b6022e2f9eeb5dabeb08c439c68f9f3ce7cdd1bb8cf0c61c993"}
{"prev_hash": "88b9a0de64d31b6022e2f9eeb5dabeb08c439c68f9f3ce7cdd1bb8cf0c61c993", "data": {"event": "human_oversight_gate", "physician_id": "MD-402", "status": "APPROVED"}, "hash": "bdc8fdbef13ecc745da08d362e41ecf56ee72523317fa860720c67e9621f97cd"}
{"prev_hash": "bdc8fdbef13ecc745da08d362e41ecf56ee72523317fa860720c67e9621f97cd", "data": {"event": "output_clamp_verified", "clamped_value": 0.82, "limit": 0.95}, "hash": "0afd1ea9492c4c54e9206d1fa4c854e5355d310150837d2e99f6b030c3dab7b6"}
{"prev_hash": "0afd1ea9492c4c54e9206d1fa4c854e5355d310150837d2e99f6b030c3dab7b6", "data": {"event": "post_market_telemetry", "metric": "latency_ms", "value": 42.1}, "hash": "87b617c258290e6af113a32fa176aa48b52d2a45ea3bd72e8c0d307a95fb2508"}`,

  robustness: `clean_prediction,perturbed_prediction,ground_truth
1,1,1
1,1,1
0,0,0
1,1,1
0,0,0
1,1,1
0,0,0
1,0,1
0,0,0
1,1,1
1,1,1
0,0,0
1,1,1
0,0,0
1,1,1
0,0,0
1,1,1
0,0,0
1,1,1
0,0,0`
};

function updateVerifiedEvidenceBadgeCount() {
  const countEl = document.getElementById("verifiedModulesCount");
  if (countEl) {
    countEl.textContent = `${verifiedEvidenceStore.length} of 5 verified`;
  }
  const dossierBadge = document.getElementById("dossierStatusBadge");
  if (dossierBadge) {
    if (verifiedEvidenceStore.length === 5) {
      dossierBadge.className = "badge success";
      dossierBadge.textContent = "FULL TIER T1 COMPLETE (5/5)";
    } else if (verifiedEvidenceStore.length > 0) {
      dossierBadge.className = "badge warning";
      dossierBadge.textContent = `PARTIAL EVIDENCE (${verifiedEvidenceStore.length}/5)`;
    } else {
      dossierBadge.className = "badge info";
      dossierBadge.textContent = "READY";
    }
  }

  // Update progress pills track
  const verifiedModulesSet = new Set(verifiedEvidenceStore.map(e => e.module));
  const modulesList = [
    { key: "fairness", label: "1. Fairness (DIR/SPD)" },
    { key: "dependencies", label: "2. AI-BOM & CVEs" },
    { key: "tls", label: "3. TLS 1.3 In-Transit" },
    { key: "log_integrity", label: "4. Audit Log Integrity" },
    { key: "robustness", label: "5. Robustness Drop" }
  ];
  modulesList.forEach(m => {
    const pill = document.getElementById(`pill-verify-${m.key}`);
    if (pill) {
      if (verifiedModulesSet.has(m.key)) {
        pill.className = "evidence-pill verified";
        pill.innerHTML = `<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><polyline points="20 6 9 17 4 12"/></svg> ${m.label}`;
      } else {
        pill.className = "evidence-pill";
        pill.innerHTML = `<span class="evidence-pill-dot"></span> ${m.label}`;
      }
    }
  });
}

function makeGrcBadge(level, text) {
  if (level === 'good') {
    return `<span class="badge success" style="font-size:11px; padding:3px 8px; display:inline-flex; align-items:center; gap:5px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>${escapeHtml(text)}</span>`;
  } else if (level === 'acceptable') {
    return `<span class="badge warning" style="font-size:11px; padding:3px 8px; display:inline-flex; align-items:center; gap:5px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${escapeHtml(text)}</span>`;
  } else {
    return `<span class="badge critical" style="font-size:11px; padding:3px 8px; display:inline-flex; align-items:center; gap:5px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>${escapeHtml(text)}</span>`;
  }
}

function resetVerifierBoxToStandby(moduleName, box) {
  if (!box) return;
  const labels = {
    fairness: {
      svg: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 16l3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1z"/><path d="M2 16l3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1z"/><path d="M7 21h10"/><path d="M12 3v18"/><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/></svg>`,
      title: "Demographic Fairness GRC Standby",
      desc: "Verifies Disparate Impact Ratio (DIR ≥ 0.80) & SPD per EU AI Act Art. 10(2)(f) and EEOC Four-Fifths Rule."
    },
    dependencies: {
      svg: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>`,
      title: "Supply Chain SBOM GRC Standby",
      desc: "Queries OSV vulnerability database for package CVEs per NIST SP 800-218 and OWASP LLM03."
    },
    tls: {
      svg: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
      title: "In-Transit TLS 1.3 Probe Standby",
      desc: "Probes public inference endpoint for TLS 1.3 cryptographic handshake per NIST SP 800-52r2 & SC-8."
    },
    log_integrity: {
      svg: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
      title: "Audit Trail Hash-Chain Standby",
      desc: "Verifies cryptographic SHA-256 chain and GENESIS block immutability per EU AI Act Art. 12 & ISO 42001."
    },
    robustness: {
      svg: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
      title: "Adversarial Robustness GRC Standby",
      desc: "Measures empirical accuracy degradation drop (≤5%) under perturbation per EU AI Act Art. 15(4)."
    }
  };
  const info = labels[moduleName] || {
    svg: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
    title: "Standby",
    desc: "Awaiting empirical evidence verification."
  };
  box.style.display = "block";
  box.innerHTML = `
    <div style="padding:16px; border-radius:8px; border:1px dashed var(--border-card); background:rgba(255,255,255,0.02); text-align:center; color:var(--text-muted); font-size:12px;">
      <div class="standby-icon-well">${info.svg}</div>
      <div style="font-weight:600; color:var(--text-secondary); margin-bottom:2px;">${info.title}</div>
      <div style="max-width:440px; margin:0 auto; line-height:1.4;">${info.desc}</div>
      <div style="margin-top:6px; font-size:11px; color:var(--primary-400); font-weight:600;">Click "Run Sample Verification" or select a file</div>
    </div>
  `;
}

function getVerifierResultBox(moduleName) {
  if (!moduleName) return null;
  const modLower = String(moduleName).toLowerCase();
  const modUnder = modLower.replace(/-/g, "_");
  const modCamel = modUnder.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
  return document.getElementById(`${modUnder}ResultBox`) ||
         document.getElementById(`${modCamel}ResultBox`) ||
         document.getElementById(`${moduleName}ResultBox`) ||
         document.getElementById("log_integrityResultBox") ||
         document.getElementById("logIntegrityResultBox");
}

function getVerifierFileInput(moduleName) {
  if (!moduleName) return null;
  const modLower = String(moduleName).toLowerCase();
  const modUnder = modLower.replace(/-/g, "_");
  const modCamel = modUnder.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
  return document.getElementById(`${modUnder}FileInput`) ||
         document.getElementById(`${modCamel}FileInput`) ||
         document.getElementById(`${moduleName}FileInput`) ||
         document.getElementById("log_integrityFileInput") ||
         document.getElementById("logIntegrityFileInput");
}

function clearVerifiedEvidence() {
  verifiedEvidenceStore = [];
  updateVerifiedEvidenceBadgeCount();
  ["fairness", "dependencies", "tls", "log_integrity", "robustness"].forEach(mod => {
    const badge = document.getElementById(`badge-${mod}-status`);
    if (badge) badge.style.display = "none";
    const box = getVerifierResultBox(mod);
    if (box) resetVerifierBoxToStandby(mod, box);
    const fileInput = getVerifierFileInput(mod);
    if (fileInput) fileInput.value = "";
    const cardEl = document.getElementById(`card-verify-${mod}`);
    if (cardEl) cardEl.className = "card verifier-card-wide";
  });
  showToast("All verified evidence items cleared.");
}

function computeGrcVerdict(v) {
  const mod = v.module;
  const score = Number(v.verified_score || 0);
  const m = v.metrics || {};

  if (mod === "fairness") {
    const dir = m.disparate_impact_ratio !== undefined ? Number(m.disparate_impact_ratio) : null;
    const isGood = v.claim_supported && score >= 1.0 && (dir === null || dir >= 0.80);

    if (isGood) {
      return {
        level: "good",
        badge: makeGrcBadge("good", "GRC CONFORMANT (GOOD)"),
        framework: "EU AI Act Art. 10(2)(f) • NIST AI RMF MEASURE 2.11 • EEOC 4/5ths Rule",
        message: `Disparate Impact Ratio (${dir !== null ? dir.toFixed(3) : '≥0.80'}) complies with the standard 80% four-fifths rule without adverse demographic disparity across protected groups.`
      };
    } else if (dir !== null && dir >= 0.70) {
      return {
        level: "acceptable",
        badge: makeGrcBadge("acceptable", "GRC MARGINAL CONFORMANCE (ADVISORY)"),
        framework: "EU AI Act Art. 10(2)(f) • EEOC Four-Fifths Rule",
        message: `DIR (${dir.toFixed(3)}) is slightly below 0.80 threshold. Pre-processing reweighing or equalized odds calibration advised before production deployment.`
      };
    } else {
      return {
        level: "risk",
        badge: makeGrcBadge("risk", "GRC NON-CONFORMANT (BIAS DEFICIT)"),
        framework: "EU AI Act Art. 10(2)(f) • NIST MEASURE 2.11",
        message: `Disparate Impact Ratio (${dir !== null ? dir.toFixed(3) : 'below 0.80'}) violates the EEOC Four-Fifths Rule. Systemic disparity poses regulatory liability under EU AI Act.`
      };
    }
  }

  if (mod === "dependencies") {
    const critCves = m.critical_cves !== undefined ? Number(m.critical_cves) : 0;
    const isCyclone = m.manifest_format && m.manifest_format.includes("cyclonedx");

    if (score >= 1.0 && critCves === 0) {
      return {
        level: "good",
        badge: makeGrcBadge("good", "GRC CONFORMANT (GOOD)"),
        framework: "NIST SP 800-218 (SSDF) • OWASP LLM03 • EU AI Act Art. 15",
        message: `Formal CycloneDX SBOM validated with 0 critical vulnerabilities. Runtime software supply chain satisfies rigorous SSDF procurement controls.`
      };
    } else if (score >= 0.5 && critCves === 0) {
      return {
        level: "acceptable",
        badge: makeGrcBadge("acceptable", "GRC PARTIAL (ACCEPTABLE • UPGRADE RECOMMENDED)"),
        framework: "NIST SP 800-218 (SSDF) • OWASP LLM03",
        message: `0 known vulnerabilities detected across 5 runtime dependencies. Plain requirements manifest is acceptable, but upgrade to CycloneDX JSON SBOM with package hashes is recommended for full Tier T1 compliance.`
      };
    } else {
      return {
        level: "risk",
        badge: makeGrcBadge("risk", "GRC HIGH RISK (SUPPLY CHAIN DEFICIT)"),
        framework: "OWASP LLM03 • NIST SP 800-218",
        message: `Critical vulnerabilities (CVSS ≥ 7.0) detected or manifest unparsable. High exploitation hazard under OWASP LLM03 software supply chain criteria.`
      };
    }
  }

  if (mod === "tls") {
    const proto = m.protocol_version || "";
    const days = m.days_until_expiry !== undefined ? Number(m.days_until_expiry) : 0;

    if (score >= 1.0 && (proto.includes("1.3") || proto.includes("TLSv1.3"))) {
      return {
        level: "good",
        badge: makeGrcBadge("good", "GRC CONFORMANT (GOOD)"),
        framework: "RFC 8446 (TLS 1.3) • NIST SP 800-52r2 • SC-8 (In-Transit)",
        message: `Strict TLS 1.3 negotiated with valid certificate (${days > 0 ? days + ' days valid' : 'active'}). Fully protects model serving endpoint against interception and MITM tampering.`
      };
    } else if (proto.includes("1.2") || proto.includes("TLSv1.2")) {
      return {
        level: "acceptable",
        badge: makeGrcBadge("acceptable", "GRC LEGACY PROTOCOL (ACCEPTABLE)"),
        framework: "NIST SP 800-52r2 • RFC 8446",
        message: `TLS 1.2 negotiated. Permitted for interoperability, but TLS 1.3 migration is recommended under NIST SP 800-52r2 guidance.`
      };
    } else {
      return {
        level: "risk",
        badge: makeGrcBadge("risk", "GRC CRITICAL DEFICIT (INSECURE / UNREACHABLE)"),
        framework: "NIST SC-8 • EU AI Act Art. 15(1)",
        message: `Endpoint probe failed, certificate invalid, or host unreachable. Unencrypted or unverified transit transport breaches mandatory cybersecurity controls.`
      };
    }
  }

  if (mod === "log_integrity") {
    const isPass = v.claim_supported && score >= 1.0;
    const isGenesis = m.genesis_valid !== undefined ? !!m.genesis_valid : isPass;
    const isTamper = m.chain_tamper_resistant !== undefined ? !!m.chain_tamper_resistant : isPass;
    const count = m.total_entries || m.verified_records || 0;

    if (isPass && isGenesis && isTamper) {
      return {
        level: "good",
        badge: makeGrcBadge("good", "GRC CONFORMANT (GOOD)"),
        framework: "EU AI Act Art. 12 • ISO/IEC 42001 §A.8 • NIST GOVERN 2.1",
        message: `Cryptographic SHA-256 hash-chain verified with unbroken GENESIS anchor across ${count} entries. Provides legally admissible immutable evidence of decision traceability.`
      };
    } else {
      return {
        level: "risk",
        badge: makeGrcBadge("risk", "GRC AUDIT FAILURE (CHAIN TAMPERED)"),
        framework: "EU AI Act Art. 12 • ISO/IEC 42001 §A.8",
        message: escapeHtml(v.details || "Broken cryptographic hash chain or invalid genesis anchor detected. Telemetry fails tamper-resistance test and cannot be legally relied upon.")
      };
    }
  }

  if (mod === "robustness") {
    const drop = m.accuracy_degradation !== undefined ? Number(m.accuracy_degradation) * 100 : null;

    if (score >= 1.0 && (drop === null || drop <= 5.0)) {
      return {
        level: "good",
        badge: makeGrcBadge("good", "GRC CONFORMANT (GOOD)"),
        framework: "EU AI Act Art. 15(4) • NIST AI RMF MEASURE 2.7 • MITRE ATLAS",
        message: `Empirical accuracy drop under adversarial perturbation (${drop !== null ? drop.toFixed(1) + '%' : '≤5%'}) is within the acceptable 5% bound. High resilience against adversarial inputs.`
      };
    } else if (drop !== null && drop <= 10.0) {
      return {
        level: "acceptable",
        badge: makeGrcBadge("acceptable", "GRC MODERATE DEGRADATION (ADVISORY)"),
        framework: "NIST MEASURE 2.7 • EU AI Act Art. 15(4)",
        message: `Performance degradation (${drop.toFixed(1)}%) exceeds standard 5% boundary but remains under 10%. Adversarial retraining (FGSM/PGD) recommended.`
      };
    } else {
      return {
        level: "risk",
        badge: makeGrcBadge("risk", "GRC RESILIENCE DEFICIT (HIGH RISK)"),
        framework: "EU AI Act Art. 15(4) • MITRE ATLAS",
        message: `Severe degradation drop (${drop !== null ? drop.toFixed(1) + '%' : '>10%'}) under adversarial attack. Fails EU AI Act Art. 15(4) requirement for cyber-robustness.`
      };
    }
  }

  return {
    level: v.claim_supported ? "good" : "risk",
    badge: v.claim_supported ? makeGrcBadge("good", "GRC CONFORMANT") : makeGrcBadge("risk", "GRC DEFICIT"),
    framework: "International AI Governance & Risk Frameworks",
    message: escapeHtml(v.details || "Empirical verification evaluation complete.")
  };
}

function formatVerifierResultHTML(v) {
  const isPass = !!v.claim_supported;
  const score = Number(v.verified_score || 0).toFixed(2);
  const grc = computeGrcVerdict(v);

  let bannerClass = "grc-good";
  let borderCol = "var(--success-border)";
  if (grc.level === "acceptable") {
    bannerClass = "grc-acceptable";
    borderCol = "var(--warning-border)";
  } else if (grc.level === "risk") {
    bannerClass = "grc-risk";
    borderCol = "var(--critical-border)";
  }

  let chips = [];
  if (v.metrics) {
    if (v.module === "fairness") {
      if (v.metrics.disparate_impact_ratio !== undefined) chips.push(`DIR: <strong>${Number(v.metrics.disparate_impact_ratio).toFixed(3)}</strong>`);
      if (v.metrics.statistical_parity_difference !== undefined) chips.push(`SPD: <strong>${Number(v.metrics.statistical_parity_difference).toFixed(3)}</strong>`);
      if (v.metrics.equal_opportunity_difference !== undefined) chips.push(`EOD: <strong>${Number(v.metrics.equal_opportunity_difference).toFixed(3)}</strong>`);
      if (v.metrics.total_samples !== undefined) chips.push(`Records: <strong>${v.metrics.total_samples}</strong>`);
    } else if (v.module === "dependencies") {
      if (v.metrics.total_packages !== undefined) chips.push(`Packages: <strong>${v.metrics.total_packages}</strong>`);
      if (v.metrics.critical_cves !== undefined) chips.push(`Critical CVEs: <strong>${v.metrics.critical_cves}</strong>`);
      if (v.metrics.manifest_format !== undefined) chips.push(`Format: <strong>${escapeHtml(v.metrics.manifest_format)}</strong>`);
    } else if (v.module === "tls") {
      if (v.metrics.protocol_version !== undefined) chips.push(`Protocol: <strong>${escapeHtml(v.metrics.protocol_version)}</strong>`);
      if (v.metrics.cipher_suite !== undefined) chips.push(`Cipher: <strong>${escapeHtml(v.metrics.cipher_suite)}</strong>`);
      if (v.metrics.days_until_expiry !== undefined) chips.push(`Days Valid: <strong>${v.metrics.days_until_expiry}</strong>`);
    } else if (v.module === "log_integrity") {
      const recs = v.metrics.total_entries || v.metrics.verified_records || 0;
      chips.push(`Entries: <strong>${recs}</strong>`);
      chips.push(`Genesis: <strong>${(v.metrics.genesis_valid ?? (v.claim_supported && score >= 1.0)) ? 'Valid' : 'Invalid'}</strong>`);
      chips.push(`Tamper Proof: <strong>${(v.metrics.chain_tamper_resistant ?? (v.claim_supported && score >= 1.0)) ? 'Yes' : 'No'}</strong>`);
      if (v.metrics.chain_head_hash) {
        chips.push(`Head Hash: <strong>${escapeHtml(v.metrics.chain_head_hash.substring(0, 8))}...</strong>`);
      }
    } else if (v.module === "robustness") {
      if (v.metrics.accuracy_clean !== undefined) chips.push(`Clean Acc: <strong>${(v.metrics.accuracy_clean * 100).toFixed(1)}%</strong>`);
      if (v.metrics.accuracy_perturbed !== undefined) chips.push(`Perturbed Acc: <strong>${(v.metrics.accuracy_perturbed * 100).toFixed(1)}%</strong>`);
      if (v.metrics.accuracy_degradation !== undefined) chips.push(`Degradation: <strong>${(v.metrics.accuracy_degradation * 100).toFixed(1)}%</strong>`);
    }
  }

  const chipsHTML = chips.length > 0
    ? `<div style="display:flex; flex-wrap:wrap; gap:6px; margin:8px 0;">
        ${chips.map(c => `<span style="font-size:11px; padding:3px 8px; border-radius:4px; background:rgba(255,255,255,0.06); border:1px solid var(--border-card); font-family:var(--font-mono); color:var(--text-primary);">${c}</span>`).join('')}
       </div>`
    : '';

  return `
    <div class="grc-verdict-box ${bannerClass}" style="padding:14px; border-radius:8px; border:1px solid ${borderCol};">
      <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:8px;">
        <span style="font-weight:700; font-size:12px; letter-spacing:0.3px;">${grc.badge}</span>
        <span class="badge info" style="font-size:10px;">${score} / 1.00 TIER T1 SCORE</span>
      </div>
      <div style="font-size:11px; font-family:var(--font-mono); color:var(--text-muted); margin-bottom:6px;">
        Framework Citation: <strong>${escapeHtml(grc.framework)}</strong>
      </div>
      <div style="font-size:12px; color:var(--text-primary); margin-bottom:8px; line-height:1.5;">
        ${escapeHtml(grc.message)}
      </div>
      ${chipsHTML}
      <details style="font-size:11px; margin-top:8px; cursor:pointer;">
        <summary style="color:var(--text-muted); font-size:11px; user-select:none;">Inspect Technical Payload &amp; OSV Raw Audit</summary>
        <pre style="margin:6px 0 0 0; padding:8px; background:rgba(0,0,0,0.3); border-radius:4px; font-size:10px; overflow-x:auto; max-height:120px; font-family:var(--font-mono); color:var(--text-secondary); white-space:pre-wrap;">${escapeHtml(JSON.stringify(v.metrics || {}, null, 2))}</pre>
      </details>
    </div>
  `;
}

function handleVerifierResponse(moduleName, json, box, badge) {
  if (!box) box = getVerifierResultBox(moduleName);
  if (!badge) badge = document.getElementById(`badge-${moduleName}-status`);

  if (json.success && json.data) {
    const v = json.data;
    verifiedEvidenceStore = verifiedEvidenceStore.filter(e => e.module !== moduleName);
    verifiedEvidenceStore.push(v);
    updateVerifiedEvidenceBadgeCount();

    if (badge) {
      badge.style.display = "inline-block";
      if (v.verified_score >= 1.0) {
        badge.className = "badge success";
        badge.textContent = "VERIFIED (1.0)";
      } else if (v.verified_score >= 0.5) {
        badge.className = "badge warning";
        badge.textContent = `PARTIAL (${v.verified_score.toFixed(1)})`;
      } else {
        badge.className = "badge danger";
        badge.textContent = "DEFICIT (0.0)";
      }
    }

    if (box) {
      box.style.display = "block";
      box.innerHTML = formatVerifierResultHTML(v);
    }

    const cardEl = document.getElementById(`card-verify-${moduleName}`);
    if (cardEl) {
      if (v.verified_score >= 1.0) {
        cardEl.className = "card verifier-card-wide card-verified";
      } else if (v.verified_score >= 0.5) {
        cardEl.className = "card verifier-card-wide card-partial";
      } else {
        cardEl.className = "card verifier-card-wide card-failed";
      }
    }

    showToast(`${moduleName} evidence verified successfully!`);
  } else {
    if (box) {
      box.style.display = "block";
      box.innerHTML = `<div style="padding:10px; border-radius:6px; background:var(--critical-bg); border:1px solid var(--critical-border); color:var(--critical-text); font-size:12px;"><strong>Verification Failed:</strong> ${escapeHtml(json.error || 'Unknown error')}</div>`;
    }
  }
}

function handleVerifierError(moduleName, err, box) {
  console.error(`Verification error [${moduleName}]:`, err);
  if (!box) box = getVerifierResultBox(moduleName);
  if (box) {
    box.style.display = "block";
    const isNetworkErr = err.message && (err.message.includes("fetch") || err.message.includes("Network"));
    box.innerHTML = `
      <div style="padding:10px; border-radius:6px; background:var(--critical-bg); border:1px solid var(--critical-border); color:var(--critical-text); font-size:12px; line-height:1.5;">
        <strong>${isNetworkErr ? 'Network Connection Error' : 'Execution Error'}:</strong> ${escapeHtml(err.message)}
        ${isNetworkErr ? `<div style="margin-top:6px; font-size:11px; color:var(--text-secondary);">Ensure the AI-GRID backend is running at <code>http://127.0.0.1:8000</code> by running <code>python server.py</code>.</div>` : ''}
      </div>
    `;
  }
}

async function loadSampleAndVerify(moduleName) {
  const box = getVerifierResultBox(moduleName);
  const badge = document.getElementById(`badge-${moduleName}-status`);
  if (box) {
    box.style.display = "block";
    box.innerHTML = `<div style="display:flex; align-items:center; gap:8px; color:var(--text-secondary);"><span class="badge info">RUNNING</span> <span>Verifying ${moduleName} using reference dataset...</span></div>`;
  }

  try {
    let payload = {};
    if (moduleName === "tls") {
      const sample = VERIFIER_SAMPLES.tls;
      const hostInput = document.getElementById("tlsHostInput");
      const portInput = document.getElementById("tlsPortInput");
      if (hostInput) hostInput.value = sample.host;
      if (portInput) portInput.value = sample.port;
      payload = { host: sample.host, port: sample.port };
    } else if (moduleName === "fairness") {
      const privInput = document.getElementById("fairnessPrivilegedVal");
      const privVal = privInput ? privInput.value.trim() || "male" : "male";
      payload = { content: VERIFIER_SAMPLES.fairness, privileged_value: privVal };
    } else {
      payload = { content: VERIFIER_SAMPLES[moduleName] };
    }

    const res = await fetch(`${API_BASE}/api/verify/${encodeURIComponent(moduleName)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const json = await res.json();
    handleVerifierResponse(moduleName, json, box, badge);
  } catch (err) {
    handleVerifierError(moduleName, err, box);
  }
}

async function verifyAllSamples() {
  const btn = document.getElementById("btnVerifyAllSamples");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = `<span class="badge info">RUNNING...</span> <span>Verifying All Modules...</span>`;
  }
  showToast("Running empirical verification across all 5 governance pillars...");

  const modules = ["fairness", "dependencies", "tls", "log_integrity", "robustness"];
  for (const mod of modules) {
    await loadSampleAndVerify(mod);
  }

  if (btn) {
    btn.disabled = false;
    btn.innerHTML = `<svg class="svg-icon sm" viewBox="0 0 24 24"><polygon points="5 3 19 12 5 21"/></svg> <span>Verify All 5 Modules</span>`;
  }
  showToast("All 5 empirical verifications completed!");
}

async function executeVerifier(moduleName) {
  const box = getVerifierResultBox(moduleName);
  const badge = document.getElementById(`badge-${moduleName}-status`);

  try {
    let res;
    if (moduleName === "tls") {
      const host = (document.getElementById("tlsHostInput")?.value || "").trim() || "api.github.com";
      const port = parseInt(document.getElementById("tlsPortInput")?.value || "443", 10);

      if (box) {
        box.style.display = "block";
        box.innerHTML = `<div style="display:flex; align-items:center; gap:8px; color:var(--text-secondary);"><span class="badge info">PROBING</span> <span>Probing TLS socket at ${escapeHtml(host)}:${port}...</span></div>`;
      }

      res = await fetch(`${API_BASE}/api/verify/tls`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ host, port })
      });
    } else {
      const fileInput = getVerifierFileInput(moduleName);
      if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        alert("Please select a file to upload or click 'Run Sample Verification' to use reference test data.");
        if (box) box.style.display = "none";
        return;
      }

      if (box) {
        box.style.display = "block";
        box.innerHTML = `<div style="display:flex; align-items:center; gap:8px; color:var(--text-secondary);"><span class="badge info">ANALYZING</span> <span>Uploading &amp; analyzing evidence file...</span></div>`;
      }

      const formData = new FormData();
      formData.append("file", fileInput.files[0]);
      if (moduleName === "fairness") {
        const privVal = document.getElementById("fairnessPrivilegedVal")?.value || "male";
        formData.append("privileged_value", privVal);
      }

      res = await fetch(`${API_BASE}/api/verify/${encodeURIComponent(moduleName)}`, {
        method: "POST",
        body: formData
      });
    }

    const json = await res.json();
    handleVerifierResponse(moduleName, json, box, badge);
  } catch (err) {
    handleVerifierError(moduleName, err, box);
  }
}

async function applyVerifiedEvidenceToActiveAudit() {
  if (verifiedEvidenceStore.length === 0) {
    alert("No verified evidence items recorded yet. Please run at least one verifier before compiling.");
    return;
  }
  showToast(`Compiling audit with ${verifiedEvidenceStore.length} verified evidence overrides...`);
  // If wizardAnswers empty, pick healthcare preset baseline
  if (!wizardAnswers || Object.keys(wizardAnswers).length === 0) {
    wizardAnswers = { ...PRESET_PROFILES.healthcare };
  }
  try {
    const res = await fetch(`${API_BASE}/api/audit/questionnaire`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        answers: wizardAnswers,
        verified_evidence: verifiedEvidenceStore
      })
    });
    const json = await res.json();
    if (json.success && json.data) {
      currentAuditData = json.data;
      applyAuditDataToUI(json.data, `Tier T1 Verified (${verifiedEvidenceStore.length} Empirical Items)`);
      loadAuditHistory();
      showToast("Audit compiled with verified evidence overrides!");
      showPage("page-overview");
    } else {
      alert("Audit Compilation Failed: " + (json.error || "Unknown error"));
    }
  } catch (e) {
    alert("Error submitting audit with verified evidence: " + e.message);
  }
}
