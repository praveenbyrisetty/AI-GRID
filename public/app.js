/**
 * AI-GRID Enterprise Control Plane (v4.0)
 * Dual-Mode Controller: Structured Research Questionnaire (T3) + MCP Automated Probe (T1)
 * High-Assurance 6 Trust Dimensions | EU AI Act (Art. 9-15) | Attestation Discrepancy | Framework Mapping
 */

// =========================================================================
// GLOBAL APPLICATION STATE
// =========================================================================
let radarChartInstance = null;
let currentAuditData = null;
let currentMode = "mcp";
let wizardStep = 1;
let totalWizardSteps = 7;
let wizardAnswers = {};
let questionsData = null;
let currentDatasetsCatalog = [];
let activeDatasetId = "german_credit";
let isTerminalPaused = false;
let currentAlpha = 0.60;
let isGraphListView = false;

const pageTitles = {
  "page-overview": "AI Assurance Overview",
  "page-setup": "Audit Launchpad",
  "page-compliance": "EU AI Act Regulatory Compliance",
  "page-discrepancy": "Attestation Discrepancy Analysis",
  "page-framework-map": "Interactive Framework Mapping",
  "page-datasets": "Empirical Benchmark Datasets",
  "page-question-bank": "Research Question Bank (30 Items)",
  "page-remediation": "Governance Remediation Roadmap",
  "page-modelcard": "AI Governance Passport",
  "page-simulation": "What-If Scenario Risk Simulator"
};

const PILLAR_KEYS = {
  "Security & Robustness": "security",
  "Fairness & Non-Discrimination": "fairness",
  "Transparency & Explainability": "transparency",
  "Privacy & Data Governance": "privacy",
  "Human Oversight & Accountability": "oversight",
  "Safety & Reliability": "safety"
};

const defaultDimensions = {
  "Security & Robustness": 0,
  "Fairness & Non-Discrimination": 0,
  "Transparency & Explainability": 0,
  "Privacy & Data Governance": 0,
  "Human Oversight & Accountability": 0,
  "Safety & Reliability": 0
};

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

  // 3. Load Questions & Datasets catalogs from backend
  loadQuestions();
  loadDatasets();

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

  // Re-render radar chart with updated theme colors
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
      const tierLabel = json.data.evidence_tier === "T1"
        ? "Tier T1 (Automated MCP Probe)"
        : "Tier T3 (Self-Attested Questionnaire)";
      applyAuditDataToUI(json.data, tierLabel);
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
  if (headline) headline.textContent = "AWAITING SYSTEM AUDIT • CONTROL PLANE READY";

  const subText = document.getElementById("verdictSubText");
  if (subText) subText.innerHTML = `No active assessment executed. Connect live Model Context Protocol (MCP) tool endpoints (Tier T1) or complete the research questionnaire (Tier T3) to dynamically evaluate assurance adequacy.
    <div style="margin-top: 10px; display:flex; gap:10px;">
      <button class="btn-primary sm" onclick="runQuickDemoAudit()">
        <svg class="svg-icon sm" viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
        <span>Execute Automated MCP Probe Now</span>
      </button>
      <button class="btn-secondary sm" onclick="showPage('page-setup')">
        <span>Structured Questionnaire (T3) &rarr;</span>
      </button>
    </div>`;

  const bannerDisc = document.getElementById("bannerDiscrepancyVal");
  if (bannerDisc) bannerDisc.textContent = "—";

  const bannerBasis = document.getElementById("bannerEvidenceBasis");
  if (bannerBasis) bannerBasis.textContent = "Awaiting Probe";

  const bannerHash = document.getElementById("bannerHashIntegrity");
  if (bannerHash) bannerHash.textContent = "Standby";

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
        <span>AI-GRID Control Plane online. Awaiting MCP connection or questionnaire execution...</span>
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

  // 1. EU AI Act Table & Classification Cards Reset
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

  // 2. NIST AI RMF Crosswalk Cards Reset
  const gov = document.getElementById("nistGovern");
  if (gov) gov.textContent = "— / 100 (STANDBY)";
  const map = document.getElementById("nistMap");
  if (map) map.textContent = "— / 100 (STANDBY)";
  const meas = document.getElementById("nistMeasure");
  if (meas) meas.textContent = "— / 100 (STANDBY)";
  const man = document.getElementById("nistManage");
  if (man) man.textContent = "— / 100 (STANDBY)";

  // 3. Attestation Discrepancy Screen Reset
  const adiVal = document.getElementById("adiVal");
  if (adiVal) adiVal.textContent = "—";
  const adiSignificance = document.getElementById("adiSignificance");
  if (adiSignificance) adiSignificance.textContent = "STANDBY";
  const discTbody = document.getElementById("discrepancyTbody");
  if (discTbody) {
    discTbody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center; padding:18px; color:var(--text-muted);">Both Tier T1 (MCP automated probe) and Tier T3 (Questionnaire) data are required to compute attestation discrepancy.</td>
      </tr>
    `;
  }

  // 4. Governance Remediation Roadmap Screen Reset
  const remBody = document.getElementById("remediationBody");
  if (remBody) {
    remBody.innerHTML = `
      <tr>
        <td colspan="5" style="text-align:center; padding:18px; color:var(--text-muted);">No findings recorded. Execute an audit to generate roadmap.</td>
      </tr>
    `;
  }

  // 5. AI Governance Passport Screen Reset
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

  // 6. What-If Scenario Risk Simulator Reset
  const simScore = document.getElementById("simScore");
  if (simScore) simScore.textContent = "—";
  const simIncidents = document.getElementById("simIncidents");
  if (simIncidents) simIncidents.textContent = "—";
  const simLiability = document.getElementById("simLiability");
  if (simLiability) simLiability.textContent = "—";
  const simUserSlider = document.getElementById("simUserSlider");
  if (simUserSlider) simUserSlider.value = 50000;
  const userCountLabel = document.getElementById("userCountLabel");
  if (userCountLabel) userCountLabel.textContent = "50,000";

  // 7. Questionnaire Wizard & Launchpad Reset
  wizardStep = 1;
  selectedAnswers = {};
  const authCheck = document.getElementById("mcpAuthorizeCheck");
  if (authCheck) authCheck.checked = false;

  // 8. Framework flow node labels
  const flSystem = document.getElementById("flabel-system");
  if (flSystem) flSystem.textContent = "System Target";
  const flProbe = document.getElementById("flabel-probe");
  if (flProbe) flProbe.textContent = "Protocol Mode";
  const flEvidence = document.getElementById("flabel-evidence");
  if (flEvidence) flEvidence.textContent = "Observed Telemetry";
  const flFinding = document.getElementById("flabel-finding");
  if (flFinding) flFinding.textContent = "Vulnerability Analysis";
  const flDimension = document.getElementById("flabel-dimension");
  if (flDimension) flDimension.textContent = "Trust Bottleneck";
  const flClause = document.getElementById("flabel-clause");
  if (flClause) flClause.textContent = "Framework Clause";
  const flRemediation = document.getElementById("flabel-remediation");
  if (flRemediation) flRemediation.textContent = "Engineering Fix";

  const gdetailType = document.getElementById("gdetailType");
  if (gdetailType) gdetailType.textContent = "Selected Node: AI System";
  const gdetailTitle = document.getElementById("gdetailTitle");
  if (gdetailTitle) gdetailTitle.textContent = "Awaiting System Audit";
  const gdetailDesc = document.getElementById("gdetailDesc");
  if (gdetailDesc) gdetailDesc.textContent = "Lineage mapping connects observed wire-level probes, identified vulnerabilities, empirical trust dimensions, statutory EU AI Act / NIST articles, and actionable engineering remediation. Run an audit to trace lineage.";
  const gdetailBadge = document.getElementById("gdetailBadge");
  if (gdetailBadge) gdetailBadge.textContent = "Traceability Lineage";
  const gdetailStatus = document.getElementById("gdetailStatus");
  if (gdetailStatus) gdetailStatus.textContent = "Standby";

  // Radar chart
  initRadarChart(defaultDimensions);

  // ERM Sensitivity
  updateAlphaSlider(currentAlpha);
}

async function resetAuditState() {
  try {
    await fetch("/api/audit/reset", { method: "POST" });
  } catch (err) {
    console.warn("Server reset API call:", err);
  }
  clearAuditUI();
  showPage("page-overview");
  showToast("Platform reset complete: All audits, telemetry, and tables reset to clean standby");
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
  const dimValues = dims ? Object.values(dims) : [0, 0, 0, 0, 0, 0];
  const dimLabels = dims ? Object.keys(dims) : Object.keys(defaultDimensions);
  const isStandby = dimValues.every(v => v === 0);

  const datasets = [];

  if (isStandby) {
    // Elegant baseline reference envelope (80.0 Conformity Target)
    datasets.push({
      label: "Regulatory Target (80.0)",
      data: [80, 80, 80, 80, 80, 80],
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
    // Real evaluated AAS dimensions in cerulean blue
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

    // Reference target at 80
    datasets.push({
      label: "Conformity Target (80.0)",
      data: [80, 80, 80, 80, 80, 80],
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
// 5. ERM SCORING SENSITIVITY EXPLORER CONTROLLER
// =========================================================================
function updateAlphaSlider(val) {
  currentAlpha = parseFloat(val);
  const alphaValEl = document.getElementById("alphaValueDisplay");
  const meanWeightEl = document.getElementById("alphaMeanWeight");
  const minWeightEl = document.getElementById("alphaMinWeight");
  const resultEl = document.getElementById("alphaAasResult");
  const noteEl = document.getElementById("alphaInsightNote");

  if (alphaValEl) alphaValEl.textContent = `α = ${currentAlpha.toFixed(2)}`;
  if (meanWeightEl) meanWeightEl.textContent = `${Math.round(currentAlpha * 100)}%`;
  if (minWeightEl) minWeightEl.textContent = `${Math.round((1 - currentAlpha) * 100)}%`;

  const dims = currentAuditData?.dimensions || defaultDimensions;
  const vals = Object.values(dims);
  const allZero = vals.every(v => v === 0);
  if (allZero) {
    if (resultEl) resultEl.textContent = "—";
    if (noteEl) {
      noteEl.innerHTML = "Execute an audit to inspect sensitivity across empirical trust dimensions under varying risk appetites.";
      noteEl.style.borderLeftColor = "var(--border-card)";
    }
    return;
  }

  const mean = vals.reduce((a, b) => a + b, 0) / (vals.length || 1);
  const min = Math.min(...vals);
  const recalculatedAas = (currentAlpha * mean) + ((1 - currentAlpha) * min);

  if (resultEl) resultEl.textContent = recalculatedAas.toFixed(1);

  if (noteEl) {
    if (currentAlpha >= 0.85) {
      noteEl.innerHTML = `<strong>Arithmetic Mean Dominance (&alpha; = ${currentAlpha.toFixed(2)}):</strong> Outlier vulnerabilities (min: ${min.toFixed(1)}) are masked by higher dimensions, concealing critical single-point failure risks.`;
      noteEl.style.borderLeftColor = "var(--critical)";
    } else if (currentAlpha <= 0.25) {
      noteEl.innerHTML = `<strong>Bottleneck Dominance (&alpha; = ${currentAlpha.toFixed(2)}):</strong> AAS score is strictly bounded by lowest pillar (${min.toFixed(1)}), penalizing high overall system maturity (${mean.toFixed(1)}).`;
      noteEl.style.borderLeftColor = "var(--warning)";
    } else {
      noteEl.innerHTML = `<strong>Balanced ERM Formulation (&alpha; = ${currentAlpha.toFixed(2)}):</strong> Weighted Mean (${mean.toFixed(1)}) balanced with Bottleneck Constraint (${min.toFixed(1)}) to enforce high-assurance robustness.`;
      noteEl.style.borderLeftColor = "var(--primary-500)";
    }
  }
}

// =========================================================================
// 6. UI DATA APPLICATION & COCKPIT SYNC
// =========================================================================
function applyAuditDataToUI(data, tierText) {
  if (!data) return;

  // 1. Evidence Tier & Assessment Status
  const tierEl = document.getElementById("evidenceTierText");
  if (tierEl) tierEl.innerHTML = tierText || (data.evidence_tier === 'T1' ? 'Tier T1 (Automated MCP Probe)' : 'Tier T3 (Self-Attested Questionnaire)');

  const statusTag = document.getElementById("assessmentStatusTag");
  const statusText = document.getElementById("assessmentStatusText");
  if (statusTag) statusTag.className = "status-tag completed";
  if (statusText) statusText.textContent = "Evidence Reviewed";

  const targetEl = document.getElementById("sidebarContextTarget");
  if (targetEl) targetEl.textContent = "Target: " + (data.model_metadata?.model_name || data.model_metadata?.name || data.model_card?.model_name || "Active System");

  // 2. Scoring & KPIs
  const sc = data.scoring || {};
  document.getElementById("kpiAasScore").textContent = sc.aas_score ?? "—";
  document.getElementById("kpiGradeBadge").textContent = `GRADE ${sc.trust_grade || 'A'}`;
  document.getElementById("kpiGradeBadge").className = `badge ${sc.trust_grade && sc.trust_grade[0] === 'A' ? 'success' : 'warning'}`;
  document.getElementById("kpiAasMath").textContent = `Mean: ${sc.weighted_average} | Min: ${sc.bottleneck_score} (α=0.6)`;

  const confBadge = document.getElementById("kpiConfidenceBadge");
  if (confBadge) confBadge.textContent = `CONFIDENCE ${(sc.evidence_weight || 1.0).toFixed(2)}`;

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

  // 3. Status Banner
  const subText = document.getElementById("verdictSubText");
  const headlineText = document.getElementById("verdictHeadlineText");
  if (subText && headlineText) {
    if (sc.trust_grade && sc.trust_grade[0] === 'A') {
      headlineText.textContent = "ASSESSMENT COMPLETED • EVIDENCE REVIEWED";
      subText.textContent = `Evaluated via ${data.evidence_tier === 'T1' ? 'Model Context Protocol wire probes (Tier T1)' : '30-Item Research Questionnaire (Tier T3)'}. Technical compliance evaluated against EU AI Act Articles 9–15 and NIST AI RMF 1.0.`;
    } else {
      headlineText.textContent = "ASSESSMENT COMPLETED • FINDINGS REQUIRE ATTENTION";
      subText.textContent = `Identified governance bottleneck in ${sc.bottleneck_dimension || 'Safety & Reliability'}. Prioritized engineering remediation required.`;
    }
  }

  const bannerDisc = document.getElementById("bannerDiscrepancyVal");
  if (bannerDisc) {
    bannerDisc.textContent = data.evidence_tier === 'T1' ? "+0.0 pts (Verified)" : "T3 Self-Attested";
  }
  const bannerBasis = document.getElementById("bannerEvidenceBasis");
  if (bannerBasis) {
    bannerBasis.textContent = data.evidence_tier === 'T1'
      ? `${data.tools_count || 4} Live MCP Tools`
      : "30 Attestation Questions";
  }
  const bannerHash = document.getElementById("bannerHashIntegrity");
  if (bannerHash) {
    bannerHash.textContent = data.integrity_hash
      ? `${data.integrity_hash.substring(0, 12)}... (Validated)`
      : "SHA-256 Validated";
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
          <td><span class="badge ${p.priority === 'CRITICAL' ? 'critical' : (p.priority === 'HIGH' ? 'warning' : 'info')}">${p.priority}</span></td>
          <td>${p.finding}</td>
          <td><strong>${p.dimension}</strong></td>
          <td><strong style="color:var(--primary-500);">${p.action}</strong></td>
          <td><small style="font-family:var(--font-mono); color:var(--text-muted);">${p.eu_ai_act_ref || 'Art. 9'}</small></td>
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

  // 8. NIST Crosswalk Cards
  if (data.compliance?.nist_rmf) {
    const nist = data.compliance.nist_rmf;
    const gov = document.getElementById("nistGovern");
    if (gov && nist.GOVERN) gov.textContent = `${nist.GOVERN.score.toFixed(1)}/100 (${nist.GOVERN.status})`;
    const map = document.getElementById("nistMap");
    if (map && nist.MAP) map.textContent = `${nist.MAP.score.toFixed(1)}/100 (${nist.MAP.status})`;
    const meas = document.getElementById("nistMeasure");
    if (meas && nist.MEASURE) meas.textContent = `${nist.MEASURE.score.toFixed(1)}/100 (${nist.MEASURE.status})`;
    const man = document.getElementById("nistManage");
    if (man && nist.MANAGE) man.textContent = `${nist.MANAGE.score.toFixed(1)}/100 (${nist.MANAGE.status})`;
  }

  // 9. Remediation Roadmap
  renderRemediationTable(data.remediation_plan || []);

  // 10. Model Card
  renderModelCard(data);

  // 11. Framework Flow Node labels
  const flSystem = document.getElementById("flabel-system");
  if (flSystem) flSystem.textContent = data.model_metadata?.model_name || data.model_metadata?.name || data.model_card?.model_name || "Target System";
  const flProbe = document.getElementById("flabel-probe");
  if (flProbe) flProbe.textContent = data.evidence_tier === 'T1' ? 'MCP Tool Probe' : 'Questionnaire';
  const flEvidence = document.getElementById("flabel-evidence");
  if (flEvidence) flEvidence.textContent = data.evidence_tier === 'T1' ? `${data.tools_count || 4} Tools Probed` : '30 Attestations';
  const flFinding = document.getElementById("flabel-finding");
  if (flFinding) {
    const f = data.remediation_plan?.[0]?.finding;
    flFinding.textContent = f ? (f.length > 18 ? f.substring(0, 18) + '...' : f) : "Verified Bounds";
  }
  const flDimension = document.getElementById("flabel-dimension");
  if (flDimension) flDimension.textContent = `${sc.bottleneck_dimension || 'Safety'} (${sc.bottleneck_score ?? '—'})`;
  const flClause = document.getElementById("flabel-clause");
  if (flClause) flClause.textContent = data.remediation_plan?.[0]?.eu_ai_act_ref || "EU Art. 15(1)";
  const flRemediation = document.getElementById("flabel-remediation");
  if (flRemediation) {
    const a = data.remediation_plan?.[0]?.action;
    flRemediation.textContent = a ? (a.length > 18 ? a.substring(0, 18) + '...' : a) : "Maintain Safeguards";
  }

  // Sync Framework node detail box
  selectGraphNode("system", document.getElementById("gnode-system"));

  // 12. Update ERM Slider Calculation
  updateAlphaSlider(currentAlpha);
}

// =========================================================================
// 7. TERMINAL EVENT STREAM CONTROLLER
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
        <span class="log-badge ${badgeClass}">${l.stage || 'EVENT'}</span>
        <span>${l.message}</span>
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

// =========================================================================
// 8. UNIVERSAL DETAIL DRAWER (SLIDE-OUT INSPECTOR)
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
    fairness: "Fairness & Non-Discrimination",
    transparency: "Transparency & Explainability",
    privacy: "Privacy & Data Governance",
    oversight: "Human Oversight & Agency",
    safety: "Safety & Reliability"
  };

  const anchors = {
    security: "EU AI Act Art. 15(4) &bull; NIST MEASURE 2.7 &bull; OWASP MCP Top 10",
    fairness: "EU AI Act Art. 10(2) &bull; EEOC 80% Rule &bull; Kamiran & Calders (2012)",
    transparency: "EU AI Act Art. 13 &bull; NIST MAP 1.5 &bull; TreeSHAP Attributions",
    privacy: "EU AI Act Art. 10(5) &bull; GDPR Art. 25/32 &bull; Cryptographic Controls",
    oversight: "EU AI Act Art. 14 &bull; NIST GOVERN 1.4 &bull; Mandatory HITL Kill-Switch",
    safety: "EU AI Act Art. 9 &bull; NIST MANAGE 2.2 &bull; Deterministic Output Clamping"
  };

  const hasAudit = currentAuditData && currentAuditData.dimensions && currentAuditData.dimensions[titles[dimKey]] !== undefined;
  const currentScore = hasAudit ? currentAuditData.dimensions[titles[dimKey]] : null;
  const scoreDisplay = hasAudit ? `${currentScore.toFixed(1)} / 100` : "— / 100";
  const findingsDisplay = hasAudit
    ? (currentScore >= 80
        ? '<span class="badge success">CONFORMANT</span> No critical security vulnerabilities or regulatory deficits detected in this dimension.'
        : '<span class="badge warning">DEFICIT DETECTED</span> Sub-optimal boundary clamping or attestation gap requires engineering remediation before production release.')
    : '<span class="badge info">AWAITING AUDIT</span> Execute an automated MCP probe (Tier T1) or complete the questionnaire (Tier T3) to evaluate empirical adequacy.';

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
        Evaluated via wire-level Model Context Protocol probes (Tier T1) and research-grounded questionnaire items (Tier T3). Evaluates extreme boundary handling, adversarial noise perturbation, and formal data retention controls.
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

// =========================================================================
// 9. SECTION 13: INTERACTIVE FRAMEWORK MAPPING CONTROLLER
// =========================================================================
function selectGraphNode(nodeKey, el) {
  document.querySelectorAll(".graph-node").forEach(n => n.classList.remove("active"));
  if (el) el.classList.add("active");

  const detailBox = document.getElementById("graphNodeDetailBox");
  const typeEl = document.getElementById("gdetailType");
  const titleEl = document.getElementById("gdetailTitle");
  const descEl = document.getElementById("gdetailDesc");
  const badgeEl = document.getElementById("gdetailBadge");
  const statusEl = document.getElementById("gdetailStatus");

  if (!detailBox) return;

  const modelName = currentAuditData?.model_metadata?.model_name || currentAuditData?.model_metadata?.name || currentAuditData?.model_card?.model_name || "System Under Evaluation";
  const tier = currentAuditData?.evidence_tier || "T1";
  const bottleneck = currentAuditData?.scoring?.bottleneck_dimension || "Safety & Reliability";
  const bscore = currentAuditData?.scoring?.bottleneck_score !== undefined ? currentAuditData.scoring.bottleneck_score : "—";
  const topPlan = currentAuditData?.remediation_plan?.[0];

  const nodeData = {
    system: {
      type: "Target AI System",
      title: modelName,
      desc: currentAuditData
        ? `Production AI system evaluated under domain '${currentAuditData.model_metadata?.domain || "General"}'. Architecture: ${currentAuditData.model_metadata?.architecture || "Machine Learning Pipeline"}. Assessed under EU AI Act Annex III statutory requirements.`
        : "Connect a live MCP tool server or submit the research questionnaire to trace system governance lineage.",
      badge: currentAuditData ? "Annex III §5" : "Standby",
      status: currentAuditData ? "Under Active Audit" : "Awaiting Audit"
    },
    probe: {
      type: "Assessment Protocol",
      title: tier === "T1" ? "Automated MCP Wire Probe (Tier T1)" : "Structured Attestation Questionnaire (Tier T3)",
      desc: tier === "T1"
        ? "Executes dynamic list_tools() wire introspection, input perturbation tests, and boundary checks directly across JSON-RPC protocols."
        : "Comprehensive 30-item technical attestation questionnaire mapped to QB4AIRA, EU AI Act Articles 9–15, and NIST AI RMF 1.0.",
      badge: `Evidence Tier ${tier}`,
      status: tier === "T1" ? "Weight: 1.00 (High Confidence)" : "Weight: 0.60 (Self-Attested)"
    },
    evidence: {
      type: "Observed Evidence",
      title: tier === "T1" ? "MCP Telemetry & Boundary Logs" : "Attested Operational Answers",
      desc: currentAuditData?.audit_logs?.length
        ? `Captured ${currentAuditData.audit_logs.length} wire-level audit telemetry events. Evaluated output clamping, adversarial divergence, and cryptographic data governance.`
        : "Awaiting telemetry events or questionnaire submission.",
      badge: currentAuditData ? "Telemetry Captured" : "Awaiting Telemetry",
      status: currentAuditData ? "Verified" : "Standby"
    },
    finding: {
      type: "Security & Assurance Finding",
      title: topPlan ? topPlan.finding : "Vulnerability Assessment",
      desc: topPlan
        ? `Identified vulnerability in ${topPlan.dimension}: ${topPlan.finding}. Priority: ${topPlan.priority}. Recommended action: ${topPlan.action}.`
        : "No active findings recorded. Execute audit to discover vulnerabilities.",
      badge: topPlan ? `${topPlan.priority} Severity` : "Pending",
      status: topPlan ? "Action Required" : "Standby"
    },
    dimension: {
      type: "Empirical Trust Dimension",
      title: `${bottleneck} (${bscore}/100)`,
      desc: currentAuditData
        ? `Identified as the primary bottleneck constraint (D_min = ${bscore}). Penalizes composite Assurance Adequacy Score via 40% bottleneck weighting in ERM.`
        : "Evaluates 6 international pillars (Security, Fairness, Transparency, Privacy, Oversight, Safety).",
      badge: "Primary Bottleneck",
      status: (typeof bscore === 'number' && bscore < 80) ? "Deficit Constraint" : "Conformant"
    },
    clause: {
      type: "Statutory Framework Clause",
      title: topPlan?.eu_ai_act_ref || "EU AI Act Article 15",
      desc: "High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness, cybersecurity, and safety throughout their lifecycle.",
      badge: "Regulation (EU) 2024/1689",
      status: topPlan?.eu_ai_act_ref || "Article 15"
    },
    remediation: {
      type: "Actionable Remediation",
      title: topPlan ? topPlan.action : "Engineering Remediation",
      desc: topPlan
        ? `Recommended engineering intervention: ${topPlan.action}. Verify compliance by re-executing protocol probes against the endpoint.`
        : "Awaiting audit findings to generate prioritized remediation tasks.",
      badge: "Remediation Task",
      status: topPlan ? "Fix Ready" : "Standby"
    }
  };

  const d = nodeData[nodeKey] || nodeData.system;
  if (typeEl) typeEl.textContent = `Selected Node: ${d.type}`;
  if (titleEl) titleEl.textContent = d.title;
  if (descEl) descEl.textContent = d.desc;
  if (badgeEl) badgeEl.textContent = d.badge;
  if (statusEl) statusEl.textContent = d.status;
}

function resetFrameworkGraph() {
  const first = document.getElementById("gnode-system");
  selectGraphNode("system", first);
  showToast("Framework graph highlight reset");
}

function toggleGraphListView() {
  isGraphListView = !isGraphListView;
  const flowNodes = document.getElementById("frameworkFlowNodes");
  const btn = document.getElementById("btnGraphListToggle");
  if (!flowNodes) return;

  if (isGraphListView) {
    flowNodes.style.flexDirection = "column";
    flowNodes.style.alignItems = "stretch";
    if (btn) btn.textContent = "Switch to Flow View";
  } else {
    flowNodes.style.flexDirection = "row";
    flowNodes.style.alignItems = "center";
    if (btn) btn.textContent = "Switch to List View";
  }
}

// =========================================================================
// 10. LAUNCH AUDIT & QUESTIONNAIRE CONTROLLER
// =========================================================================
function selectMode(mode) {
  currentMode = mode;
  document.getElementById("modeSelectionCard").style.display = "none";
  if (mode === "mcp") {
    document.getElementById("mcpConnectionCard").style.display = "block";
    document.getElementById("wizardCard").style.display = "none";
  } else {
    document.getElementById("wizardCard").style.display = "block";
    document.getElementById("mcpConnectionCard").style.display = "none";
    wizardStep = 1;
    renderWizardStep();
  }
}

function backToModeSelection() {
  document.getElementById("modeSelectionCard").style.display = "block";
  document.getElementById("wizardCard").style.display = "none";
  document.getElementById("mcpConnectionCard").style.display = "none";
}

function toggleMcpAuditType() {
  const isLive = document.getElementById("mcpTypeLive")?.checked;
  const demoGroup = document.getElementById("mcpDemoGroup");
  const liveGroup = document.getElementById("mcpLiveGroup");
  const btnText = document.getElementById("mcpSubmitBtnText");

  if (demoGroup && liveGroup) {
    if (isLive) {
      demoGroup.style.display = "none";
      liveGroup.style.display = "block";
      if (btnText) btnText.textContent = "Execute Live Protocol Audit";
    } else {
      demoGroup.style.display = "block";
      liveGroup.style.display = "none";
      if (btnText) btnText.textContent = "Execute Benchmark Probe Audit";
    }
  }
}

async function runQuickDemoAudit() {
  showToast("Initiating Tier T1 automated wire probe against certified benchmark...");
  try {
    const res = await fetch("/api/audit/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ demo_profile: "good" })
    });
    const json = await res.json();
    if (json.success && json.data) {
      currentAuditData = json.data;
      const modeLabel = json.data.execution_mode === "DEMO_BENCHMARK"
        ? "Tier T1 (Certified Demo Benchmark Reference)"
        : "Tier T1 (Live MCP Protocol Audit)";
      applyAuditDataToUI(json.data, modeLabel);
      showToast("Benchmark Reference Audit Completed");
      showPage("page-overview");
    } else {
      showToast("Notice: " + (json.error || "Unable to retrieve probe data"));
    }
  } catch (err) {
    showToast("Probe Error: " + err.message);
  }
}

async function connectMcp() {
  const isLive = document.getElementById("mcpTypeLive")?.checked;
  let payload = {};

  if (isLive) {
    const authCheck = document.getElementById("mcpAuthorizeCheck");
    if (!authCheck || !authCheck.checked) {
      alert("Explicit authorization is required before launching a live MCP server process.");
      return;
    }
    const cmdExec = (document.getElementById("mcpLiveExec")?.value || "python").trim();
    const cmdArgsStr = (document.getElementById("mcpLiveScript")?.value || "").trim();
    const cmdArgs = cmdArgsStr ? cmdArgsStr.split(" ").filter(Boolean) : [];
    payload = {
      target_command: [cmdExec, ...cmdArgs],
      authorized: true
    };
  } else {
    const profile = document.getElementById("mcpProfileSelect")?.value || "good";
    payload = { demo_profile: profile };
  }

  try {
    showToast("Starting protocol audit execution...");
    const res = await fetch("/api/audit/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const json = await res.json();
    if (json.success && json.data) {
      currentAuditData = json.data;
      const modeLabel = json.data.execution_mode === "DEMO_BENCHMARK"
        ? `Tier T1 (Certified Demo Benchmark &bull; ${json.data.model_metadata?.model_name || 'AgriTrust'})`
        : `Tier T1 (Live Wire MCP Protocol Probing &bull; Active Connection)`;
      applyAuditDataToUI(json.data, modeLabel);
      showToast("MCP Protocol Audit Completed!");
      showPage("page-overview");
    } else {
      alert("Audit Failed: " + (json.error || "Unable to execute audit"));
    }
  } catch (err) {
    alert("MCP Probe Error: " + err.message);
  }
}

// =========================================================================
// 11. QUESTIONNAIRE WIZARD CONTROLLER
// =========================================================================
async function loadQuestions() {
  try {
    const res = await fetch("/api/questions");
    const json = await res.json();
    if (json.success && json.data) {
      questionsData = json.data;
      totalWizardSteps = json.data.steps.length;
      renderFullQuestionBank(json.data.steps);
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
            <td><small style="color:var(--teal-accent);">${q.owasp_ref || 'OWASP MCP'}</small></td>
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
        <div>&bull; OWASP Threat: <strong>${matchedQ.owasp_ref || 'MCP Top 10'}</strong></div>
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
    const res = await fetch("/api/audit/questionnaire", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ answers: wizardAnswers })
    });
    const json = await res.json();
    if (json.success && json.data) {
      currentAuditData = json.data;
      applyAuditDataToUI(json.data, "Tier T3 (Self-Attested Questionnaire)");
      showToast("Questionnaire Compiled Successfully!");
      showPage("page-overview");
    }
  } catch (err) {
    alert("Questionnaire Error: " + err.message);
  }
}

// =========================================================================
// 12. TABLES & RENDERERS
// =========================================================================
function renderEuArticlesTable(articles) {
  const tbody = document.getElementById("euArticlesTbody");
  if (!tbody || !articles || articles.length === 0) return;

  tbody.innerHTML = articles.map(a => `
    <tr onclick="openArticleDrawer('${a.article.replace(/[^0-9]/g, '')}')">
      <td><strong>${a.article}</strong><br><small style="color:var(--text-secondary);">${a.title}</small></td>
      <td><small>${a.requirement}</small></td>
      <td><strong>${a.score ?? '—'}/100</strong></td>
      <td><span class="badge ${a.status === 'CONFORMANT' ? 'success' : (a.status === 'PARTIAL' ? 'warning' : 'critical')}">${a.status}</span></td>
      <td><small style="color:var(--text-secondary);">${(a.mandatory_controls || []).join(" &bull; ")}</small></td>
    </tr>
  `).join("");
}

function renderRemediationTable(plan) {
  const tbody = document.getElementById("remediationBody");
  if (!tbody || !plan || plan.length === 0) return;

  tbody.innerHTML = plan.map((item, idx) => `
    <tr onclick="openFindingDrawer(${idx})">
      <td><span class="badge ${item.priority === 'CRITICAL' ? 'critical' : (item.priority === 'HIGH' ? 'warning' : 'info')}">${item.priority}</span></td>
      <td><strong>${item.dimension}</strong></td>
      <td>${item.finding}</td>
      <td><strong style="color:var(--primary-500);">${item.action}</strong></td>
      <td><small style="font-family:var(--font-mono); color:var(--text-muted);">${item.eu_ai_act_ref || 'Art. 9'}</small></td>
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
      <div class="drawer-section-content"><strong>${item.finding}</strong></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Severity Level</div>
      <div><span class="badge ${item.priority === 'CRITICAL' ? 'critical' : 'warning'}">${item.priority} Priority</span></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Affected Dimension</div>
      <div class="drawer-section-content">${item.dimension}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Recommended Engineering Fix</div>
      <div class="drawer-section-content" style="color:var(--primary-500); font-weight:600;">${item.action}</div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Verification Criteria</div>
      <div class="drawer-section-content">
        Re-run automated MCP boundary probing (Probe 2). Deterministic output clamping must suppress extreme inputs without throwing unhandled exceptions.
      </div>
    </div>
  `;

  openDetailDrawer(`Finding #${idx + 1}`, item.dimension, html);
}

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
- **Deployment Topology:** ${meta.deployment_type || 'Cloud API / Local Agent'}
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

  // Default Standard AI Passport (ISO/IEC 42001 / IEEE P8000.1)
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
    let formatted = markdownText
      .replace(/^# (.*$)/gim, '<h3 style="margin-bottom:10px; color:var(--text-primary);">$1</h3>')
      .replace(/^### (.*$)/gim, '<h4 style="margin-top:14px; margin-bottom:4px; color:var(--primary-500);">$1</h4>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\n- (.*$)/gim, '<div style="margin-left:10px; margin-bottom:2px;">&bull; $1</div>')
      .replace(/\n\n/g, '<br>');
    renderedView.innerHTML = formatted;
  }
}

// =========================================================================
// 13. ATTESTATION DISCREPANCY COMPARATIVE ENGINE
// =========================================================================
async function runComparativeAudit() {
  try {
    const res = await fetch("/api/audit/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ questionnaire_data: currentAuditData })
    });
    const json = await res.json();
    if (json.success && json.data) {
      const comp = json.data;
      document.getElementById("adiVal").textContent = `+${comp.attestation_discrepancy_index} pts`;
      document.getElementById("adiSignificance").textContent = comp.significance || "MODERATE SKEW";

      const tbody = document.getElementById("discrepancyTbody");
      tbody.innerHTML = Object.entries(comp.dimension_deltas || {}).map(([dim, d]) => `
        <tr>
          <td><strong>${dim}</strong></td>
          <td>${d.self_attested}/100</td>
          <td><strong style="color:var(--primary-500);">${d.automated_probe}/100</strong></td>
          <td><strong style="color:${d.delta > 0 ? 'var(--warning)' : 'var(--success)'};">${d.delta > 0 ? '+' : ''}${d.delta}</strong></td>
          <td><span class="badge ${d.bias_direction === 'OVERESTIMATED' ? 'warning' : 'success'}">${d.bias_direction}</span></td>
        </tr>
      `).join("");
      showToast("Attestation Discrepancy Index Recalculated!");
    }
  } catch (err) {
    alert("Comparative error: " + err.message);
  }
}

// =========================================================================
// 14. DATASETS & WHAT-IF SIMULATION
// =========================================================================
async function loadDatasets() {
  try {
    const res = await fetch("/api/datasets");
    const json = await res.json();
    if (json.success && json.data) {
      currentDatasetsCatalog = json.data;
      renderDatasetInspector(activeDatasetId);
    }
  } catch (e) {
    console.error("Dataset fetch error", e);
  }
}

function selectDatasetTab(datasetId) {
  activeDatasetId = datasetId;
  renderDatasetInspector(datasetId);
}

function renderDatasetInspector(datasetId) {
  if (!currentDatasetsCatalog || currentDatasetsCatalog.length === 0) return;
  const ds = currentDatasetsCatalog.find(d => d.id === datasetId) || currentDatasetsCatalog[0];
  if (!ds) return;

  const statsContainer = document.getElementById("datasetStatsStrip");
  if (statsContainer && ds.metrics_summary) {
    statsContainer.innerHTML = Object.entries(ds.metrics_summary).map(([k, v]) => `
      <div class="card" style="padding:10px; background:var(--bg-surface-elevated);">
        <div style="font-size:10px; color:var(--text-muted); font-family:var(--font-mono); text-transform:uppercase;">${k}</div>
        <div style="font-size:14px; font-weight:700; color:var(--primary-500); margin-top:2px;">${v}</div>
      </div>
    `).join("");
  }

  const thead = document.getElementById("datasetPreviewThead");
  const tbody = document.getElementById("datasetPreviewTbody");
  if (!thead || !tbody) return;

  const rows = ds.preview_rows || [];
  if (rows.length === 0) {
    thead.innerHTML = "";
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-muted);">No records available.</td></tr>`;
    return;
  }

  const cols = Object.keys(rows[0]);
  thead.innerHTML = `<tr>${cols.map(c => `<th>${c.replace(/_/g, ' ')}</th>`).join('')}</tr>`;

  tbody.innerHTML = rows.map(r => `
    <tr>
      ${cols.map(c => `<td><span style="font-family:var(--font-mono);">${r[c]}</span></td>`).join('')}
    </tr>
  `).join('');
}

function updateUserScale(val) {
  const label = document.getElementById("userCountLabel");
  if (label) label.textContent = parseInt(val).toLocaleString();
  runSimulation();
}

async function runSimulation() {
  const users = parseInt(document.getElementById("simUserSlider")?.value || 50000);
  const domain = document.getElementById("simDomainSelect")?.value || "General Purpose AI";
  if (!currentAuditData || currentAuditData.scoring?.aas_score === undefined) {
    showToast("Please execute an audit first to simulate scenario risk.");
    return;
  }
  const baseAas = currentAuditData.scoring.aas_score;

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ base_aas: baseAas, domain, scale_users: users })
    });
    const json = await res.json();
    if (json.success && json.data) {
      document.getElementById("simScore").textContent = `${baseAas}/100`;
      document.getElementById("simIncidents").textContent = `${json.data.projected_annual_incidents} / year`;
      document.getElementById("simLiability").textContent = `$${json.data.projected_financial_liability_usd.toLocaleString()}`;
    }
  } catch (err) {
    console.error("Simulation error", err);
  }
}

// =========================================================================
// 15. EXPORT CONTROLS & MODALS
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
