/**
 * AI-GRID GRC Dashboard — Dual-Mode Navigation & Telemetry Controller
 * Supports: Questionnaire-Based Audit + MCP Live Tool Probing
 * Enterprise Dark UI with Real-Time 7-Pillar Scanning Animation Engine
 */

let radarChartInstance = null;
let currentAuditData = null;
let currentMode = null; // 'questionnaire' or 'mcp'
let wizardStep = 1;
let totalWizardSteps = 6;
let wizardAnswers = {};
let questionsData = null;

// Page title map
const pageTitles = {
  "page-setup": "Project Setup",
  "page-profile": "System Profile",
  "page-audit": "Live Telemetry & Probe Stream",
  "page-scores": "7 Pillars & Trust Scores",
  "page-compliance": "Regulatory Alignment",
  "page-modelcard": "Google Model Card",
  "page-simulation": "What-If Simulator",
  "page-remediation": "Remediation Roadmap",
  "page-manual": "Manual Assessment"
};

// 7 Pillars key-to-ID mapping
const PILLAR_KEYS = {
  "Security & Robustness": "security",
  "Transparency": "transparency",
  "Fairness & Bias": "fairness",
  "Privacy & Governance": "privacy",
  "Accountability & Oversight": "accountability",
  "Safety & Reliability": "safety",
  "Societal Impact": "societal"
};

// Initial radar with empty data
const defaultDimensions = {
  "Fairness & Bias": 0,
  "Transparency": 0,
  "Safety & Reliability": 0,
  "Privacy & Governance": 0,
  "Accountability & Oversight": 0,
  "Security & Robustness": 0,
  "Societal Impact": 0
};

document.addEventListener("DOMContentLoaded", () => {
  initRadarChart(defaultDimensions);
  loadQuestions();
});

// =========================================================================
// 1. PAGE NAVIGATION
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

  closeSidebarOnMobile();
}

function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  const content = document.getElementById("contentArea");

  if (window.innerWidth <= 1024) {
    sidebar.classList.toggle("open");
    let overlay = document.querySelector(".sidebar-overlay");
    if (!overlay) {
      overlay = document.createElement("div");
      overlay.className = "sidebar-overlay";
      overlay.onclick = closeSidebarOnMobile;
      document.body.appendChild(overlay);
    }
    overlay.classList.toggle("visible");
  } else {
    sidebar.classList.toggle("collapsed");
    content.classList.toggle("expanded");
  }
}

function closeSidebarOnMobile() {
  if (window.innerWidth <= 1024) {
    document.getElementById("sidebar").classList.remove("open");
    const overlay = document.querySelector(".sidebar-overlay");
    if (overlay) overlay.classList.remove("visible");
  }
}

// =========================================================================
// 2. MODE SELECTION
// =========================================================================
function selectMode(mode) {
  currentMode = mode;
  document.getElementById("modeSelectionCard").style.display = "none";

  if (mode === "questionnaire") {
    document.getElementById("wizardCard").style.display = "block";
    document.getElementById("mcpConnectionCard").style.display = "none";
    wizardStep = 1;
    renderWizardStep();
  } else if (mode === "mcp") {
    document.getElementById("mcpConnectionCard").style.display = "block";
    document.getElementById("wizardCard").style.display = "none";
  }
}

function backToModeSelection() {
  document.getElementById("modeSelectionCard").style.display = "block";
  document.getElementById("wizardCard").style.display = "none";
  document.getElementById("mcpConnectionCard").style.display = "none";
  currentMode = null;
}

// MCP transport toggle
document.addEventListener("DOMContentLoaded", () => {
  const transportEl = document.getElementById("mcpTransport");
  if (transportEl) {
    transportEl.addEventListener("change", function() {
      if (this.value === "stdio") {
        document.getElementById("mcpUrlGroup").style.display = "none";
        document.getElementById("mcpCommandGroup").style.display = "block";
      } else {
        document.getElementById("mcpUrlGroup").style.display = "block";
        document.getElementById("mcpCommandGroup").style.display = "none";
      }
    });
  }
});

// =========================================================================
// 3. QUESTIONNAIRE WIZARD
// =========================================================================
async function loadQuestions() {
  try {
    const res = await fetch("/api/questions");
    const json = await res.json();
    if (json.success && json.data) {
      questionsData = json.data;
      totalWizardSteps = json.data.steps.length;
    }
  } catch (err) {
    console.log("Questions will be loaded when server is available:", err.message);
    questionsData = generateFallbackQuestions();
    totalWizardSteps = questionsData.steps.length;
  }
}

function generateFallbackQuestions() {
  return {
    steps: [
      {
        step: 1, title: "Model Identity",
        questions: [
          { id: "model_name", label: "Model / System Name", type: "text", placeholder: "e.g., ClinicalAssistant-v2", required: true },
          { id: "model_version", label: "Engineering Version", type: "text", placeholder: "e.g., 2.1.0", required: true },
          { id: "domain", label: "Target Domain", type: "select", options: [
            { value: "healthcare", label: "Healthcare / Medical" },
            { value: "finance", label: "Finance / Banking" },
            { value: "agriculture", label: "Commercial Agriculture" },
            { value: "other", label: "General Purpose AI" }
          ], required: true },
          { id: "architecture", label: "Model Architecture", type: "text", placeholder: "e.g., Transformer, XGBoost", required: true },
          { id: "autonomy_level", label: "Autonomy Level", type: "select", options: [
            { value: "advisory", label: "Advisory Only" },
            { value: "semi_autonomous", label: "Semi-Autonomous" },
            { value: "fully_autonomous", label: "Fully Autonomous" }
          ], required: true }
        ]
      }
    ]
  };
}

function renderWizardStep() {
  if (!questionsData) return;
  const stepData = questionsData.steps[wizardStep - 1];
  if (!stepData) return;

  document.getElementById("wizardStepTitle").textContent = `Step ${wizardStep}: ${stepData.title}`;
  document.getElementById("wizardStepDesc").textContent = `Specification of parameters for Step ${wizardStep} of ${totalWizardSteps}`;

  // Progress Bar
  const pct = (wizardStep / totalWizardSteps) * 100;
  document.getElementById("wizardProgressFill").style.width = `${pct}%`;

  // Step dots
  document.querySelectorAll(".step-dot").forEach((dot, idx) => {
    dot.classList.toggle("active", idx < wizardStep);
  });

  const body = document.getElementById("wizardBody");
  let html = '<div class="wizard-questions-grid">';

  stepData.questions.forEach(q => {
    const savedVal = wizardAnswers[q.id] || "";
    html += `<div class="form-group">`;
    html += `<label for="wq_${q.id}">${q.label} ${q.required ? '<span style="color:var(--danger)">*</span>' : ''}</label>`;

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

function saveWizardAnswer(id, value) {
  wizardAnswers[id] = value;
}

function wizardNext() {
  if (!validateCurrentStep()) return;
  if (wizardStep < totalWizardSteps) {
    wizardStep++;
    renderWizardStep();
    document.getElementById("wizardCard").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function wizardPrev() {
  if (wizardStep > 1) {
    wizardStep--;
    renderWizardStep();
    document.getElementById("wizardCard").scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function validateCurrentStep() {
  if (!questionsData) return true;
  const stepData = questionsData.steps[wizardStep - 1];
  if (!stepData) return true;

  for (const q of stepData.questions) {
    if (q.required && (!wizardAnswers[q.id] || wizardAnswers[q.id].toString().trim() === "")) {
      const el = document.getElementById(`wq_${q.id}`);
      if (el) {
        el.classList.add("input-error");
        el.focus();
        setTimeout(() => el.classList.remove("input-error"), 2000);
      }
      return false;
    }
  }
  return true;
}

// =========================================================================
// 4. REAL-TIME 7-PILLARS ANIMATION ENGINE
// =========================================================================
function activatePillarsScanning() {
  const badge = document.getElementById("liveScanStatusBadge");
  const badgeText = document.getElementById("liveScanStatusText");
  if (badge) badge.className = "scan-pulse-badge scanning";
  if (badgeText) badgeText.textContent = "SCANNING ACTIVE";

  // Activate laser sweep animation on each pillar card
  Object.values(PILLAR_KEYS).forEach(id => {
    const card = document.getElementById(`pillarCard_${id}`);
    const scoreEl = document.getElementById(`pillarScore_${id}`);
    const tagEl = document.getElementById(`pillarTag_${id}`);
    const fillEl = document.getElementById(`pillarFill_${id}`);

    if (card) {
      card.classList.add("scanning");
      card.classList.remove("active-probe");
    }
    if (scoreEl) {
      scoreEl.classList.add("counting");
      scoreEl.textContent = "...";
    }
    if (tagEl) {
      tagEl.className = "pillar-status-tag warning";
      tagEl.textContent = "PROBING";
    }
    if (fillEl) {
      fillEl.style.width = "20%";
    }
  });
}

function resolvePillarsLive(dimensions) {
  if (!dimensions) return;

  const entries = Object.entries(dimensions);
  entries.forEach(([dimName, score], index) => {
    const pillarId = PILLAR_KEYS[dimName];
    if (!pillarId) return;

    // Stagger resolution smoothly across pillars for telemetry effect
    setTimeout(() => {
      const card = document.getElementById(`pillarCard_${pillarId}`);
      const scoreEl = document.getElementById(`pillarScore_${pillarId}`);
      const tagEl = document.getElementById(`pillarTag_${pillarId}`);
      const fillEl = document.getElementById(`pillarFill_${pillarId}`);

      if (card) {
        card.classList.remove("scanning");
        card.classList.add("active-probe");
        setTimeout(() => card.classList.remove("active-probe"), 1200);
      }

      // Smooth count-up
      if (scoreEl) {
        scoreEl.classList.remove("counting");
        animateValue(scoreEl, 0, score, 900, 1);
      }

      // Progress bar fill & color
      if (fillEl) {
        fillEl.style.width = `${Math.min(100, Math.max(0, score))}%`;
        fillEl.className = "pillar-progress-fill";
        if (score >= 80) fillEl.classList.add("high");
        else if (score >= 60) fillEl.classList.add("medium");
        else fillEl.classList.add("low");
      }

      // Status tag badge
      if (tagEl) {
        if (score >= 80) {
          tagEl.className = "pillar-status-tag verified";
          tagEl.textContent = "OPTIMAL";
        } else if (score >= 60) {
          tagEl.className = "pillar-status-tag warning";
          tagEl.textContent = "DEFICIT";
        } else {
          tagEl.className = "pillar-status-tag danger";
          tagEl.textContent = "CRITICAL GAP";
        }
      }
    }, index * 140);
  });

  // Finish scanning state on badge
  setTimeout(() => {
    const badge = document.getElementById("liveScanStatusBadge");
    const badgeText = document.getElementById("liveScanStatusText");
    if (badge) badge.className = "scan-pulse-badge";
    if (badgeText) badgeText.textContent = "VERIFIED";
  }, entries.length * 140 + 500);
}

function animateValue(element, start, end, duration, decimals = 1) {
  if (!element) return;
  const startTime = performance.now();
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // Cubic ease-out
    const ease = 1 - Math.pow(1 - progress, 3);
    const current = start + (end - start) * ease;
    element.textContent = current.toFixed(decimals);
    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      element.textContent = end.toFixed(decimals);
    }
  }
  requestAnimationFrame(update);
}

// =========================================================================
// 5. SUBMIT AUDIT
// =========================================================================
async function submitQuestionnaire() {
  if (!validateCurrentStep()) return;

  const btn = document.getElementById("wizardSubmitBtn");
  btn.disabled = true;
  btn.innerHTML = `
    <svg class="svg-icon sm" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
    <span>Compiling Evidence...</span>
  `;

  try {
    const res = await fetch("/api/audit/questionnaire", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ answers: wizardAnswers })
    });
    const json = await res.json();

    if (!json.success || !json.data) {
      throw new Error(json.error || "Failed to generate audit");
    }

    currentAuditData = json.data;
    updateStatusPill("Audited", "online");
    document.getElementById("topbarTarget").textContent = wizardAnswers.model_name || "AI System";

    document.getElementById("btnRunAudit").style.display = "inline-flex";
    document.getElementById("btnRunAudit2").style.display = "inline-flex";

    showPage("page-audit");
    activatePillarsScanning();

    const terminalLog = document.getElementById("terminalLog");
    const terminalStatus = document.getElementById("terminalStatus");
    terminalStatus.textContent = "ANALYZING...";
    terminalStatus.style.color = "#38bdf8";
    terminalLog.innerHTML = `<div class="log-line info"><span class="timestamp">[KERNEL]</span> Executing 7-pillar audit for '${wizardAnswers.model_name || "AI System"}'...</div>`;

    streamLogsToTerminal(json.data.audit_logs, () => {
      applyAuditDataToUI(json.data);
      resolvePillarsLive(json.data.dimensions);
      terminalStatus.textContent = "AUDIT COMPLETE";
      terminalStatus.style.color = "#10b981";
      showProbeSummary(json.data.probe_summary);
    });

  } catch (err) {
    console.error("Audit error:", err);
    alert("Error generating audit: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg class="svg-icon sm" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
      <span>Generate Audit Dossier</span>
    `;
  }
}

async function connectMcp() {
  const transport = document.getElementById("mcpTransport").value;
  const url = document.getElementById("mcpUrlInput").value;
  const command = document.getElementById("mcpCommandInput").value;

  const config = transport === "stdio"
    ? { mcp_command: command }
    : { mcp_url: url };

  if (!config.mcp_url && !config.mcp_command) {
    alert("Please provide the MCP server URL or command.");
    return;
  }

  try {
    const res = await fetch("/api/audit/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config)
    });
    const json = await res.json();

    if (!json.success) {
      alert("MCP Connection Error: " + (json.error || "Failed to connect"));
      return;
    }

    currentAuditData = json.data;
    updateStatusPill("MCP Connected", "online");
    document.getElementById("topbarTarget").textContent = json.data.model_metadata?.model_name || "MCP AI Agent";
    document.getElementById("btnRunAudit").style.display = "inline-flex";

    showPage("page-audit");
    activatePillarsScanning();

    const terminalLog = document.getElementById("terminalLog");
    terminalLog.innerHTML = `<div class="log-line info"><span class="timestamp">[KERNEL]</span> Connected to MCP agent endpoint. Probing tools...</div>`;

    streamLogsToTerminal(json.data.audit_logs, () => {
      applyAuditDataToUI(json.data);
      resolvePillarsLive(json.data.dimensions);
      document.getElementById("terminalStatus").textContent = "AUDIT COMPLETE";
      document.getElementById("terminalStatus").style.color = "#10b981";
      showProbeSummary(json.data.probe_summary);
    });
  } catch (err) {
    alert("Connection error: " + err.message);
  }
}

function submitAudit() {
  if (currentMode === "questionnaire") {
    showPage("page-setup");
  } else if (currentMode === "mcp") {
    connectMcp();
  } else {
    showPage("page-setup");
  }
}

function rerunAudit() {
  showPage("page-setup");
}

function updateStatusPill(text, status) {
  const pill = document.getElementById("mcpStatusPill");
  const textEl = document.getElementById("mcpStatusText");
  textEl.textContent = text;
  pill.className = "mcp-status-pill " + status;
}

// =========================================================================
// 6. RADAR CHART (DARK THEME)
// =========================================================================
function initRadarChart(dims) {
  const ctx = document.getElementById("radarChart").getContext("2d");
  if (radarChartInstance) radarChartInstance.destroy();

  radarChartInstance = new Chart(ctx, {
    type: "radar",
    data: {
      labels: Object.keys(dims),
      datasets: [{
        label: "Assurance Score (0-100)",
        data: Object.values(dims),
        fill: true,
        backgroundColor: "rgba(99, 102, 241, 0.22)",
        borderColor: "#6366f1",
        pointBackgroundColor: "#06b6d4",
        pointBorderColor: "#ffffff",
        pointHoverBackgroundColor: "#38bdf8",
        pointHoverBorderColor: "#6366f1",
        borderWidth: 2.2,
        pointRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          angleLines: { color: "rgba(148, 163, 184, 0.14)" },
          grid: { color: "rgba(148, 163, 184, 0.1)" },
          pointLabels: {
            font: { family: "'Inter', sans-serif", size: 10.5, weight: "600" },
            color: "#cbd5e1"
          },
          ticks: {
            backdropColor: "transparent",
            color: "#64748b",
            stepSize: 20
          },
          suggestedMin: 0,
          suggestedMax: 100
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#0e1526",
          titleColor: "#38bdf8",
          bodyColor: "#f8fafc",
          borderColor: "rgba(99, 102, 241, 0.4)",
          borderWidth: 1,
          padding: 10
        }
      }
    }
  });
}

function updateRadarChart(dims) {
  if (!radarChartInstance) { initRadarChart(dims); return; }
  radarChartInstance.data.labels = Object.keys(dims);
  radarChartInstance.data.datasets[0].data = Object.values(dims);
  radarChartInstance.update();
}

// =========================================================================
// 7. LOG STREAMING
// =========================================================================
function streamLogsToTerminal(logs, onComplete) {
  const terminalLog = document.getElementById("terminalLog");
  let i = 0;

  const interval = setInterval(() => {
    if (i >= logs.length) {
      clearInterval(interval);
      if (onComplete) onComplete();
      return;
    }

    const entry = logs[i];
    const line = document.createElement("div");
    line.className = `log-line ${entry.status.toLowerCase()}`;
    line.innerHTML = `<span class="timestamp">[${entry.stage}]</span> ${entry.message}`;
    terminalLog.appendChild(line);
    terminalLog.scrollTop = terminalLog.scrollHeight;
    i++;
  }, 65);
}

function showProbeSummary(summary) {
  if (!summary) return;
  const card = document.getElementById("probeSummaryCard");
  const stats = document.getElementById("probeStats");
  if (!card || !stats) return;

  card.style.display = "block";
  stats.innerHTML = `
    <div class="probe-stat-item"><div class="stat-num">${summary.total_probes}</div><div class="stat-label">Probes Run</div></div>
    <div class="probe-stat-item"><div class="stat-num">${summary.mcp_tools_called}</div><div class="stat-label">MCP Tools</div></div>
    <div class="probe-stat-item"><div class="stat-num">${summary.guardrails_tested}</div><div class="stat-label">Guardrails Tested</div></div>
    <div class="probe-stat-item"><div class="stat-num">${summary.adversarial_tests}</div><div class="stat-label">Adversarial Probes</div></div>
    <div class="probe-stat-item"><div class="stat-num">${summary.findings_count}</div><div class="stat-label">Audit Findings</div></div>
  `;
}

// =========================================================================
// 8. APPLY AUDIT DATA TO UI
// =========================================================================
function applyAuditDataToUI(data) {
  const meta = data.model_metadata || {};
  const el = id => document.getElementById(id);

  if (el("profModelName")) el("profModelName").textContent = meta.model_name || "—";
  if (el("profDomain")) el("profDomain").textContent = meta.domain || meta.model_name || "—";
  if (el("profArch")) el("profArch").textContent = meta.model_architecture || "—";
  if (el("profAuditMode")) el("profAuditMode").textContent = data.audit_mode === "questionnaire" ? "Questionnaire-Based Pre-Audit" : "MCP Live Protocol Probe";
  if (el("profDataSize")) el("profDataSize").textContent = meta.training_dataset_size ? `${meta.training_dataset_size.toLocaleString()} Samples` : "—";
  if (el("profAutonomy")) {
    const autonomyLabels = { "advisory": "Advisory Only", "semi_autonomous": "Semi-Autonomous", "fully_autonomous": "Fully Autonomous" };
    el("profAutonomy").textContent = autonomyLabels[meta.autonomy_level] || meta.autonomy_level || "—";
  }
  if (el("profVersion")) el("profVersion").textContent = meta.version || "—";

  // Scores
  const scoring = data.scoring;
  const targetAas = scoring.aas_score;
  const aasEl = el("aasScore");
  if (aasEl) animateValue(aasEl, 0, targetAas, 1000, 1);

  el("gradeBadge").textContent = scoring.trust_grade;
  el("mathAvg").textContent = scoring.weighted_average;
  el("mathMin").textContent = scoring.bottleneck_score;
  el("bottleneckDesc").textContent = `${scoring.bottleneck_dimension} (${scoring.bottleneck_score}/100) constitutes the primary governance bottleneck constraint.`;

  // Grade badge styling
  const badge = el("gradeBadge");
  const scoreLbl = el("scoreLabel");
  if (scoring.trust_grade.startsWith("A")) {
    badge.style.borderColor = "var(--success)";
    badge.style.color = "var(--success)";
    badge.style.background = "var(--success-bg)";
    scoreLbl.textContent = "Minimal Governance Risk";
    scoreLbl.style.color = "var(--success)";
  } else if (scoring.trust_grade === "B" || scoring.trust_grade === "C") {
    badge.style.borderColor = "var(--warning)";
    badge.style.color = "var(--warning)";
    badge.style.background = "var(--warning-bg)";
    scoreLbl.textContent = "Moderate Governance Risk";
    scoreLbl.style.color = "var(--warning)";
  } else {
    badge.style.borderColor = "var(--danger)";
    badge.style.color = "var(--danger)";
    badge.style.background = "var(--danger-bg)";
    scoreLbl.textContent = "Elevated Risk Posture";
    scoreLbl.style.color = "var(--danger)";
  }

  // Update Radar
  updateRadarChart(data.dimensions);

  // EU AI Act
  const eu = data.compliance.eu_ai_act;
  const euBadge = el("euBadge");
  euBadge.textContent = `${eu.tier} TIER`;
  el("euDesc").textContent = eu.description;
  if (eu.tier === "MINIMAL RISK") euBadge.className = "comp-badge badge-success";
  else if (eu.tier === "LIMITED RISK") euBadge.className = "comp-badge badge-warning";
  else euBadge.className = "comp-badge badge-danger";

  // NIST
  const nist = data.compliance.nist_ai_rmf;
  updateNistPill("nistGovern", nist.GOVERN);
  updateNistPill("nistMap", nist.MAP);
  updateNistPill("nistMeasure", nist.MEASURE);
  updateNistPill("nistManage", nist.MANAGE);

  // Remediation table
  const tbody = el("remediationBody");
  tbody.innerHTML = "";
  const items = data.remediation_plan || [];
  if (items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No vulnerabilities detected &mdash; all dimensions compliant.</td></tr>`;
  } else {
    items.forEach(item => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="priority-tag ${item.badge}">${item.priority}</span></td>
        <td><strong style="color:#fff;">${item.dimension}</strong></td>
        <td>${item.finding}</td>
        <td style="color:var(--cyan-400); font-weight:500;">${item.action}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  // IBM AIF360 Empirical Fairness
  if (data.aif360) renderAif360(data.aif360);

  // Microsoft RAI Cohorts & Counterfactuals
  if (data.cohort_analysis) renderRaiCohorts(data.cohort_analysis);
  if (data.prescriptive_counterfactual) renderCounterfactual(data.prescriptive_counterfactual);

  // Google Model Card
  if (data.model_card) renderModelCard(data.model_card);

  // Cybersecurity & AI-BOM Vulnerability Scanner
  if (data.vulnerability_scan) renderCveVulnerabilities(data.vulnerability_scan);

  // Run simulation
  runSimulation();
}

function updateNistPill(elementId, obj) {
  const el = document.getElementById(elementId);
  el.textContent = `${obj.score} (${obj.status})`;
  el.className = `nist-badge ${obj.badge}`;
}

// =========================================================================
// 9. SIMULATION ENGINE
// =========================================================================
function updateUserScale(val) {
  document.getElementById("userCountLabel").textContent = Number(val).toLocaleString();
  runSimulation();
}

async function runSimulation() {
  if (!currentAuditData) return;

  const domain = document.getElementById("simDomainSelect").value;
  const users = parseInt(document.getElementById("simUserSlider").value, 10);
  const baseAas = currentAuditData.scoring.aas_score;

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ base_aas: baseAas, domain, scale_users: users })
    });
    const json = await res.json();
    if (json.success && json.data) {
      const sim = json.data;
      document.getElementById("simScore").textContent = sim.simulated_aas;
      document.getElementById("simTier").textContent = sim.simulated_tier;

      const deltaEl = document.getElementById("simDelta");
      if (sim.delta < 0) {
        deltaEl.textContent = `${sim.delta} pts (Elevated Risk)`;
        deltaEl.className = "sim-delta negative";
      } else if (sim.delta > 0) {
        deltaEl.textContent = `+${sim.delta} pts (Reduced Risk)`;
        deltaEl.className = "sim-delta positive";
      } else {
        deltaEl.textContent = "0.0 pts (Baseline)";
        deltaEl.className = "sim-delta neutral";
      }
    }
  } catch (err) {
    console.error("Simulation error:", err);
  }
}

// =========================================================================
// 10. MANUAL RECALCULATION
// =========================================================================
function recalculateManual() {
  if (!currentAuditData) return;
  const f = parseFloat(document.getElementById("q_fairness").value) * 100;
  const t = parseFloat(document.getElementById("q_transparency").value) * 100;
  const s = parseFloat(document.getElementById("q_safety").value) * 100;
  const a = parseFloat(document.getElementById("q_accountability").value) * 100;

  const newDims = { ...currentAuditData.dimensions };
  newDims["Fairness & Bias"] = f;
  newDims["Transparency"] = t;
  newDims["Safety & Reliability"] = s;
  newDims["Accountability & Oversight"] = a;

  const vals = Object.values(newDims);
  const avg = vals.reduce((sum, v) => sum + v, 0) / vals.length;
  const min = Math.min(...vals);
  const aas = Math.round(((0.6 * avg) + (0.4 * min)) * 10) / 10;

  currentAuditData.dimensions = newDims;
  currentAuditData.scoring.aas_score = aas;
  currentAuditData.scoring.weighted_average = Math.round(avg * 10) / 10;
  currentAuditData.scoring.bottleneck_score = min;

  applyAuditDataToUI(currentAuditData);
  resolvePillarsLive(currentAuditData.dimensions);
}

// =========================================================================
// 11. IBM AIF360 FAIRNESS & REWEIGHING
// =========================================================================
function renderAif360(aif) {
  if (!aif) return;
  const dirEl = document.getElementById("aifDirVal");
  const badgeEl = document.getElementById("aifDirBadge");
  const textEl = document.getElementById("aifDirText");
  const spdEl = document.getElementById("aifSpdVal");
  const privEl = document.getElementById("aifPrivRate");
  const unprivEl = document.getElementById("aifUnprivRate");
  const recEl = document.getElementById("aifMitigationRec");
  const tbody = document.getElementById("aifReweighingTbody");

  if (dirEl) dirEl.textContent = aif.disparate_impact_ratio != null ? aif.disparate_impact_ratio.toFixed(3) : "—";
  if (badgeEl && aif.four_fifths_rule) {
    badgeEl.textContent = aif.four_fifths_rule.verdict;
    badgeEl.className = `aif-verdict-badge ${aif.four_fifths_rule.compliant ? "badge-success" : "badge-danger"}`;
  }
  if (textEl && aif.four_fifths_rule) {
    textEl.textContent = aif.four_fifths_rule.status_text;
  }
  if (spdEl) spdEl.textContent = aif.statistical_parity_difference != null ? aif.statistical_parity_difference.toFixed(3) : "—";
  if (privEl && aif.rates) privEl.textContent = `${(aif.rates.privileged_acceptance_rate * 100).toFixed(1)}%`;
  if (unprivEl && aif.rates) unprivEl.textContent = `${(aif.rates.unprivileged_acceptance_rate * 100).toFixed(1)}%`;
  if (recEl) recEl.textContent = aif.recommendation || "—";

  if (tbody && aif.reweighing_weights) {
    tbody.innerHTML = "";
    const w = aif.reweighing_weights;
    const rows = [
      { slice: "Unprivileged (Female Protected)", y: "Favorable (Y=1)", weight: w.unprivileged_favorable, impact: "Upscale positive protected samples" },
      { slice: "Unprivileged (Female Protected)", y: "Unfavorable (Y=0)", weight: w.unprivileged_unfavorable, impact: "Downscale negative protected samples" },
      { slice: "Privileged (Male Majority)", y: "Favorable (Y=1)", weight: w.privileged_favorable, impact: "Normalize majority favorable outcomes" },
      { slice: "Privileged (Male Majority)", y: "Unfavorable (Y=0)", weight: w.privileged_unfavorable, impact: "Normalize majority negative outcomes" }
    ];
    rows.forEach(r => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong style="color:#fff;">${r.slice}</strong></td>
        <td><span class="pillar-status-tag ${r.y.includes('1') ? 'verified' : 'warning'}">${r.y}</span></td>
        <td><strong style="color:var(--cyan-400); font-family:var(--font-mono);">${r.weight}x</strong></td>
        <td style="color:var(--text-secondary);">${r.impact}</td>
      `;
      tbody.appendChild(tr);
    });
  }
}

// =========================================================================
// 12. MICROSOFT RAI COHORTS & COUNTERFACTUAL
// =========================================================================
function renderRaiCohorts(cohorts) {
  const container = document.getElementById("raiCohortGrid");
  if (!container || !cohorts) return;
  container.innerHTML = "";

  cohorts.forEach(c => {
    const card = document.createElement("div");
    card.className = "pillar-card";
    const sevBadge = c.severity === "HIGH" ? "badge-danger" : (c.severity === "MEDIUM" ? "badge-warning" : "badge-success");
    card.innerHTML = `
      <div class="pillar-top">
        <div>
          <div class="pillar-title">${c.name}</div>
          <div class="pillar-anchor">${c.slice_condition}</div>
        </div>
        <span class="comp-badge ${sevBadge}">${c.severity} RISK</span>
      </div>
      <div class="pillar-progress-track">
        <div class="pillar-progress-fill ${c.severity.toLowerCase()}" style="width: ${c.risk_contribution_pct}%;"></div>
      </div>
      <div class="pillar-footer-meta">
        <span>Risk Contribution: <strong>${c.risk_contribution_pct}%</strong></span>
        <span class="pillar-status-tag danger">Bottleneck: ${c.primary_bottleneck}</span>
      </div>
      <p style="font-size:0.75rem; color:var(--text-secondary); margin-top:0.65rem;">${c.description}</p>
    `;
    container.appendChild(card);
  });
}

function renderCounterfactual(cf) {
  const box = document.getElementById("cfResultsBox");
  if (!box || !cf) return;

  if (cf.already_compliant) {
    box.innerHTML = `
      <div style="background:var(--success-bg); border:1px solid var(--success-border); border-radius:8px; padding:1.25rem;">
        <strong style="color:var(--success);">Threshold Compliant: ${cf.current_aas} AAS</strong>
        <p style="margin-top:0.25rem; color:var(--text-secondary); font-size:13px;">${cf.message}</p>
      </div>
    `;
    return;
  }

  let html = `
    <div style="display:flex; gap:1.25rem; flex-wrap:wrap; background:var(--bg-surface-elevated); padding:1rem 1.25rem; border-radius:8px; border:1px solid var(--border-card);">
      <div><span class="sim-lbl">Current AAS:</span> <strong style="color:#fff; font-family:var(--font-mono);">${cf.current_aas}</strong></div>
      <div><span class="sim-lbl">Target AAS:</span> <strong style="color:var(--cyan-400); font-family:var(--font-mono);">${cf.target_score}</strong></div>
      <div><span class="sim-lbl">Projected AAS:</span> <strong style="color:var(--success); font-family:var(--font-mono);">${cf.projected_aas}</strong></div>
      <div><span class="sim-lbl">Score Lift:</span> <strong style="color:var(--indigo-400); font-family:var(--font-mono);">+${cf.score_delta} pts</strong></div>
      <div><span class="sim-lbl">Statutory Tier:</span> <strong class="comp-badge badge-success">${cf.projected_tier}</strong></div>
    </div>
    <div class="roadmap-table-container" style="margin-top:1rem;">
      <table class="roadmap-table">
        <thead>
          <tr>
            <th>Priority</th>
            <th>Dimension</th>
            <th>Prescriptive Intervention</th>
            <th>Dimension Gain</th>
            <th>AAS Lift</th>
            <th>Projected AAS</th>
          </tr>
        </thead>
        <tbody>
  `;

  (cf.required_actions || []).forEach(a => {
    html += `
      <tr>
        <td><strong>${a.step}</strong></td>
        <td><strong style="color:#fff;">${a.dimension}</strong></td>
        <td>${a.intervention}</td>
        <td><span class="priority-tag info">${a.dimension_gain}</span></td>
        <td><strong style="color:var(--success); font-family:var(--font-mono);">${a.aas_lift}</strong></td>
        <td><strong style="color:var(--cyan-400); font-family:var(--font-mono);">${a.resulting_aas}</strong></td>
      </tr>
    `;
  });

  html += `</tbody></table></div>`;
  box.innerHTML = html;
}

async function solveCustomCounterfactual() {
  if (!currentAuditData) {
    alert("Please execute an audit first.");
    return;
  }
  const target = parseFloat(document.getElementById("cfTargetInput").value) || 76.0;
  const box = document.getElementById("cfResultsBox");
  box.innerHTML = `<div class="log-line info"><span class="timestamp">[RAI]</span> Solving prescriptive counterfactual optimization for target AAS ${target}...</div>`;

  try {
    const res = await fetch("/api/rai/counterfactual", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_score: target, audit_data: currentAuditData })
    });
    const json = await res.json();
    if (json.success && json.data) {
      currentAuditData.prescriptive_counterfactual = json.data;
      renderCounterfactual(json.data);
    } else {
      box.innerHTML = `<div class="empty-state">${json.error || "Failed to solve counterfactual optimization."}</div>`;
    }
  } catch (err) {
    box.innerHTML = `<div class="empty-state">Error: ${err.message}</div>`;
  }
}

// =========================================================================
// 13. GOOGLE MODEL CARD
// =========================================================================
function renderModelCard(card) {
  if (!card) return;
  const el = id => document.getElementById(id);

  if (el("mcModelName")) el("mcModelName").textContent = card.model_name || "AI System";
  if (el("mcModelVersion")) el("mcModelVersion").textContent = `v${card.version || "1.0.0"}`;
  if (el("mcModelDomain")) el("mcModelDomain").textContent = card.domain || "—";
  if (el("mcModelGrade") && card.summary) el("mcModelGrade").textContent = card.summary.trust_grade || "—";
  if (el("mcModelTier") && card.summary) el("mcModelTier").textContent = card.summary.eu_tier || "—";

  const rawEl = el("mcRawView");
  if (rawEl) rawEl.value = card.markdown || "";

  const jsonEl = el("mcJsonView");
  if (jsonEl) jsonEl.querySelector("code").textContent = JSON.stringify(card, null, 2);

  const renderedEl = el("mcRenderedView");
  if (renderedEl && card.markdown) {
    renderedEl.innerHTML = parseMarkdownToHtml(card.markdown);
  }
}

function parseMarkdownToHtml(md) {
  let html = md
    .replace(/^# (.*$)/gim, '<h2 style="color:#fff; font-family:var(--font-heading); margin-bottom:0.5rem;">$1</h2>')
    .replace(/^## (.*$)/gim, '<h3 style="color:var(--cyan-400); font-family:var(--font-heading); margin:1.2rem 0 0.4rem;">$1</h3>')
    .replace(/^### (.*$)/gim, '<h4 style="color:#fff; margin:0.8rem 0 0.3rem;">$1</h4>')
    .replace(/^> (.*$)/gim, '<blockquote style="border-left:3px solid var(--indigo-500); padding-left:1rem; color:var(--text-muted); margin:0.75rem 0;">$1</blockquote>')
    .replace(/\*\*(.*?)\*\*/gim, '<strong style="color:#fff;">$1</strong>')
    .replace(/\*(.*?)\*/gim, '<em>$1</em>')
    .replace(/`([^`]+)`/gim, '<code style="background:rgba(99,102,241,0.15); color:var(--cyan-400); padding:2px 6px; border-radius:4px; font-family:var(--font-mono); font-size:12px;">$1</code>')
    .replace(/^\- (.*$)/gim, '<li>$1</li>');

  html = html.replace(/\|(.+)\|/gim, match => {
    if (match.includes("---")) return "";
    const cells = match.split("|").filter(c => c.trim() !== "");
    const cellHtml = cells.map(c => `<td>${c.trim()}</td>`).join("");
    return `<tr>${cellHtml}</tr>`;
  });

  html = html.replace(/(<tr>.+<\/tr>\s*)+/gim, match => `<table class="roadmap-table" style="margin:1rem 0;">${match}</table>`);
  html = html.replace(/(<li>.+<\/li>\s*)+/gim, match => `<ul style="padding-left:1.25rem; margin:0.5rem 0;">${match}</ul>`);
  html = html.replace(/\n\n+/gim, '<br>');

  return html;
}

function switchModelCardTab(tab, clickedEl) {
  document.querySelectorAll(".mc-tab").forEach(t => t.classList.remove("active"));
  if (clickedEl) clickedEl.classList.add("active");

  const rendered = document.getElementById("mcRenderedView");
  const raw = document.getElementById("mcRawView");
  const json = document.getElementById("mcJsonView");

  if (rendered) rendered.style.display = tab === "rendered" ? "block" : "none";
  if (raw) raw.style.display = tab === "raw" ? "block" : "none";
  if (json) json.style.display = tab === "json" ? "block" : "none";
}

function copyModelCardMarkdown() {
  const raw = document.getElementById("mcRawView");
  if (!raw || !raw.value) {
    alert("No model card available. Complete an audit first.");
    return;
  }

  navigator.clipboard.writeText(raw.value).then(() => {
    const btn = document.getElementById("btnCopyModelCard");
    if (btn) {
      const orig = btn.innerHTML;
      btn.innerHTML = `
        <svg class="svg-icon sm" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>
        <span>Copied to Clipboard</span>
      `;
      setTimeout(() => btn.innerHTML = orig, 2000);
    }
  }).catch(err => {
    alert("Could not copy to clipboard: " + err.message);
  });
}

function downloadModelCard(format) {
  if (!currentAuditData || !currentAuditData.model_card) {
    alert("No model card available. Complete an audit first.");
    return;
  }
  const card = currentAuditData.model_card;
  const modelName = (card.model_name || "ai_system").replace(/[^a-zA-Z0-9_-]/g, "_").toLowerCase();

  let content = "";
  let filename = "";
  let type = "";

  if (format === "json") {
    content = JSON.stringify(card, null, 2);
    filename = `model_card_${modelName}.json`;
    type = "application/json";
  } else {
    content = card.markdown || "";
    filename = `model_card_${modelName}.md`;
    type = "text/markdown";
  }

  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =========================================================================
// 14. CVSS, EPSS & CVE VULNERABILITY SCANNER
// =========================================================================
function renderCveVulnerabilities(vuln) {
  if (!vuln) return;
  const el = id => document.getElementById(id);

  if (el("cvePostureVal")) el("cvePostureVal").textContent = vuln.security_posture;
  if (el("cvePostureBadge")) {
    el("cvePostureBadge").textContent = `${vuln.criticality_multiplier}x Multiplier`;
    el("cvePostureBadge").className = `aif-verdict-badge ${vuln.average_compound_risk >= 60 ? "badge-danger" : (vuln.average_compound_risk >= 35 ? "badge-warning" : "badge-success")}`;
  }
  if (el("cveCompoundRiskVal")) el("cveCompoundRiskVal").innerHTML = `${vuln.average_compound_risk}<small>/100</small>`;
  if (el("cveActiveThreatsVal")) el("cveActiveThreatsVal").textContent = `${vuln.active_exploits_count} Active`;
  if (el("cveTotalScannedVal")) el("cveTotalScannedVal").textContent = `${vuln.total_cves_scanned} Packages`;
  if (el("cveCriticalitySelect") && vuln.asset_criticality) {
    el("cveCriticalitySelect").value = vuln.asset_criticality;
  }

  const tbody = document.getElementById("cveTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";

  (vuln.vulnerabilities || []).forEach(v => {
    const tr = document.createElement("tr");
    const epssBadge = v.epss_badge === "danger" ? "badge-danger" : (v.epss_badge === "warning" ? "badge-warning" : "badge-info");

    tr.innerHTML = `
      <td>
        <strong style="color:var(--cyan-400); font-family:var(--font-mono); font-size:13px;">${v.cve_id}</strong>
        <div style="font-size:11px; color:var(--text-dim);">${v.package_type}</div>
      </td>
      <td>
        <strong style="color:#fff;">${v.package}</strong>
        <div style="font-size:11px; color:var(--text-muted);">${v.vulnerability_type}</div>
      </td>
      <td>
        <span class="priority-tag ${v.cvss_tier === 'CRITICAL' ? 'danger' : 'warning'}">${v.cvss_score} ${v.cvss_tier}</span>
      </td>
      <td>
        <span class="comp-badge ${epssBadge}" style="font-size:11px;">${v.epss_pct}</span>
        <div style="font-size:10px; color:var(--text-dim); margin-top:2px;">${v.epss_threat}</div>
      </td>
      <td>
        <strong style="color:${v.compound_risk >= 70 ? 'var(--danger)' : (v.compound_risk >= 45 ? 'var(--warning)' : 'var(--success)')}; font-family:var(--font-mono); font-size:14px;">
          ${v.compound_risk}/100
        </strong>
      </td>
      <td>
        <div style="color:var(--success); font-weight:600; font-size:12px;">${v.remediation_patch}</div>
        <div style="color:var(--text-secondary); font-size:11px; max-width:280px; margin-top:2px;">${v.description}</div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function rescanVulnerabilities() {
  const criticality = document.getElementById("cveCriticalitySelect").value;
  const domain = currentAuditData?.model_metadata?.domain || "General Purpose AI";

  try {
    const res = await fetch("/api/security/cve-scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, asset_criticality: criticality })
    });
    const json = await res.json();
    if (json.success && json.data) {
      if (currentAuditData) currentAuditData.vulnerability_scan = json.data;
      renderCveVulnerabilities(json.data);
    }
  } catch (err) {
    console.error("Vulnerability rescan error:", err);
  }
}
