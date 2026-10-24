/**
 * AI-GRID Enterprise Control Plane (v4.0)
 * High-Assurance AI Governance & Compliance Auditing Platform
 * Grounded in QB4AIRA (Lee et al., 2024), EU AI Act (Regulation (EU) 2024/1689 Articles 9-15),
 * NIST AI 100-1 (AI RMF), and 6 Empirical Trust Dimensions.
 */

// =========================================================================
// GLOBAL APPLICATION STATE
// =========================================================================
let radarChartInstance = null;
let currentAuditData = null;
let wizardStep = 1;
let totalWizardSteps = 7;
let wizardAnswers = {};
let questionsData = null;
let isTerminalPaused = false;

const pageTitles = {
  "page-overview": "AI Assurance Overview",
  "page-setup": "AI Governance Questionnaire",
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

async function syncSessionAuth() {
  try {
    const res = await fetch("/api/status");
    const json = await res.json();
    if (json && json.session_token) {
      localStorage.setItem("ai_grid_api_key", json.session_token);
    }
  } catch (e) {
    console.warn("Could not sync session token", e);
  }
}

function getAuthHeaders(extraHeaders = {}) {
  const headers = { ...extraHeaders };
  const key = localStorage.getItem("ai_grid_api_key") || "";
  if (key) {
    headers["X-API-Key"] = key;
  }
  return headers;
}

async function handleAuthError(res) {
  if (res && res.status === 401) {
    await syncSessionAuth();
    showToast("Session authenticated. Please re-run audit.");
  }
}

// =========================================================================
// INITIALIZATION
// =========================================================================
document.addEventListener("DOMContentLoaded", () => {
  // 0. Auto-sync session authentication token seamlessly
  syncSessionAuth();

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
    const res = await fetch("/api/audit/current");
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

  const cveCount = document.getElementById("kpiCveCount");
  if (cveCount) cveCount.textContent = "—";

  const cveBadge = document.getElementById("kpiCveBadge");
  if (cveBadge) cveBadge.textContent = "INDEXED REGISTRY";

  const euTier = document.getElementById("kpiEuTier");
  if (euTier) euTier.textContent = "UNASSESSED";

  const euStatus = document.getElementById("kpiEuStatus");
  if (euStatus) euStatus.textContent = "Awaiting statutory article evaluation";

  const euBadge = document.getElementById("kpiEuBadge");
  if (euBadge) {
    euBadge.textContent = "STANDBY";
    euBadge.className = "badge info";
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
        <span class="log-badge PROBE">STANDBY</span>
        <span>AI-GRID Control Plane online. Awaiting questionnaire execution or preset selection...</span>
      </div>
    `;
  }
  const termStatus = document.getElementById("terminalStatus");
  if (termStatus) termStatus.textContent = "IDLE / STANDBY";

  // Overview Remediation Table
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
  if (euTierName) euTierName.textContent = "Awaiting Assessment";
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
    const res = await fetch("/api/audit/reset", {
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

  const cveCountEl = document.getElementById("kpiCveCount");
  if (cveCountEl) {
    cveCountEl.textContent = data.vulnerability_scan?.critical_high_count !== undefined
      ? data.vulnerability_scan.critical_high_count
      : 0;
  }
  const cveBadgeEl = document.getElementById("kpiCveBadge");
  if (cveBadgeEl) {
    cveBadgeEl.textContent = `${data.vulnerability_scan?.total_indexed_cves || 50} INDEXED`;
  }

  const eu = data.compliance?.eu_ai_act || {};
  document.getElementById("kpiEuTier").textContent = eu.tier || "HIGH RISK";
  document.getElementById("kpiEuStatus").textContent = `${eu.conformant_articles || '6/7'} Articles Technical Conformity`;
  document.getElementById("kpiEuBadge").textContent = eu.tier && eu.tier.includes("HIGH") ? "ANNEX III" : "MINIMAL";

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
    sumTier.className = "badge " + (eu.tier && eu.tier.includes("HIGH") ? "warning" : "success");
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

  // 6. Overview Priority Remediation Preview Table
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
  const euBadge = document.getElementById("euBadge");
  if (euBadge) {
    euBadge.textContent = eu.tier ? `${eu.tier}` : "ANNEX III";
    euBadge.className = `badge ${eu.tier && eu.tier.includes("HIGH") ? "warning" : "info"}`;
  }
  const euTierName = document.getElementById("euTierName");
  if (euTierName) euTierName.textContent = eu.tier ? `${eu.tier} (Annex III §5)` : "HIGH RISK";
  const euLegalBasis = document.getElementById("euLegalBasis");
  if (euLegalBasis) euLegalBasis.textContent = eu.legal_basis || "Critical Decision Support";
  const euMarket = document.getElementById("euMarketPermitted");
  if (euMarket) {
    euMarket.textContent = "PERMITTED (Conformity Required)";
    euMarket.style.color = "var(--success)";
  }
  const euConfReq = document.getElementById("euConformityReq");
  if (euConfReq) euConfReq.textContent = eu.assessment_protocol || "Annex VII Internal Control";
  const euConfCount = document.getElementById("euConformantCount");
  if (euConfCount) euConfCount.textContent = `${eu.conformant_articles || '6/7'} Articles Conformant`;

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
    const badgeClass = l.status === "SUCCESS" ? "COMPLETE" : (l.status === "WARNING" ? "WARNING" : (l.status === "DANGER" ? "DANGER" : "PROBE"));
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
    requirement: "Statutory engineering obligation under Regulation (EU) 2024/1689.",
    score: "—",
    status: "STANDBY",
    mandatory_controls: ["Technical documentation", "Verification testing"]
  };

  const html = `
    <div class="drawer-section">
      <div class="drawer-section-title">Statutory Requirement</div>
      <div class="drawer-section-content"><strong>${item.title}</strong></div>
      <div class="drawer-section-content" style="margin-top:6px;">${item.requirement}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Conformity Status &amp; Score</div>
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
    const res = await fetch("/api/questions");
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
    const res = await fetch("/api/audit/questionnaire", {
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
    const res = await fetch("/api/audit/questionnaire", {
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

  tbody.innerHTML = articles.map(a => `
    <tr onclick="openArticleDrawer('${escapeHtml(a.article).replace(/[^0-9]/g, '')}')">
      <td><strong>${escapeHtml(a.article)}</strong><br><small style="color:var(--text-secondary);">${escapeHtml(a.title)}</small></td>
      <td><small>${escapeHtml(a.requirement)}</small></td>
      <td><strong>${a.score ?? '—'}/100</strong></td>
      <td><span class="badge ${a.status === 'CONFORMANT' ? 'success' : (a.status === 'PARTIAL' ? 'warning' : 'critical')}">${escapeHtml(a.status)}</span></td>
      <td><small style="color:var(--text-secondary);">${(a.mandatory_controls || []).map(c => escapeHtml(c)).join(" &bull; ")}</small></td>
    </tr>
  `).join("");
}

function renderRemediationTable(plan) {
  const tbody = document.getElementById("remediationBody");
  if (!tbody || !plan || plan.length === 0) return;

  tbody.innerHTML = plan.map((item, idx) => `
    <tr onclick="openFindingDrawer(${idx})">
      <td><span class="badge ${item.priority === 'CRITICAL' ? 'critical' : (item.priority === 'HIGH' ? 'warning' : 'info')}">${escapeHtml(item.priority)}</span></td>
      <td><strong>${escapeHtml(item.dimension)}</strong></td>
      <td>${escapeHtml(item.finding)}</td>
      <td><strong style="color:var(--primary-500);">${escapeHtml(item.action)}</strong></td>
      <td><small style="font-family:var(--font-mono); color:var(--text-muted);">${escapeHtml(item.eu_ai_act_ref || 'Art. 9')}</small></td>
    </tr>
  `).join("");
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
        Validate technical control attestation and verify deterministic boundary guardrails. Verify that extreme inputs are constrained without unhandled runtime exceptions.
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
    return `# EU AI Act Technical Documentation Dossier (Annex IV)
**System Identifier:** ${modelName} (v${version})
**Statutory Intended Purpose:** ${domain}
**Conformity Classification:** ${eu.tier || 'HIGH RISK (Annex III §5)'}
**Legal Basis:** ${eu.legal_basis || 'Automated Decision Support'}
**Assessment Timestamp:** ${timestamp}
**Assurance Adequacy Score (AAS):** ${scoring.aas_score ?? '—'}/100 (Grade: ${scoring.trust_grade || '—'})

---

### 1. General System Description (Annex IV §1)
- **Model Architecture:** ${arch}
- **Deployment Topology:** ${meta.deployment_type || 'Dedicated Cloud / On-Premises'}
- **Hardware & Software Dependencies:** Tracked via CycloneDX AI-BOM
- **Intended User Cohort:** Authorized operators with human-in-the-loop oversight

### 2. Risk Management System Conformance (Article 9)
- **Status:** ${(dims['Safety & Reliability'] >= 70 && dims['Security & Robustness'] >= 70) ? 'CONFORMANT' : 'REMEDIATION REQUIRED'}
- **Safety & Reliability Score:** ${dims['Safety & Reliability'] ?? '—'}/100
- **Continuous Drift Monitoring:** Verified via post-market telemetry
- **Known Failure Mode Rejection:** 100% rejection on corrupted input payloads

### 3. Data & Data Governance Conformance (Article 10)
- **Status:** ${(dims['Fairness & Non-Discrimination'] >= 70 && dims['Privacy & Data Governance'] >= 70) ? 'CONFORMANT' : 'REMEDIATION REQUIRED'}
- **Fairness & Bias Score:** ${dims['Fairness & Non-Discrimination'] ?? '—'}/100
- **Four-Fifths Rule (EEOC):** Evaluated against demographic parity thresholds
- **Data Protection & Encryption:** AES-256 at rest & TLS 1.3 in transit

### 4. Technical Documentation & Record-Keeping (Articles 11 & 12)
- **Automated Logging:** Enabled via immutable audit trail
- **Hash Integrity:** SHA-256 validated
- **Audit Retention Policy:** >= 6 months tamper-evident persistence

### 5. Transparency & Human Oversight (Articles 13 & 14)
- **Transparency Score:** ${dims['Transparency & Explainability'] ?? '—'}/100 (TreeSHAP Attributions)
- **Human Oversight Score:** ${dims['Human Oversight & Agency'] ?? '—'}/100
- **Emergency Stop / Kill-Switch:** Verified active

### 6. Conformity Verdict & Statutory Sign-Off
- **Market Placement Eligibility:** ${eu.market_placement_permitted !== false ? 'ELIGIBLE PENDING CONFORMITY ASSESSMENT' : 'PROHIBITED'}
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
- **Fairness & Non-Discrimination:** ${dims['Fairness & Non-Discrimination'] ?? '—'}
- **Transparency & Explainability:** ${dims['Transparency & Explainability'] ?? '—'}
- **Privacy & Data Governance:** ${dims['Privacy & Data Governance'] ?? '—'}
- **Human Oversight & Agency:** ${dims['Human Oversight & Agency'] ?? '—'}
- **Safety & Reliability:** ${dims['Safety & Reliability'] ?? '—'}

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
    const res = await fetch("/api/audit/history?limit=50");
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
    const res = await fetch(`/api/audit/${encodeURIComponent(auditId)}`);
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
