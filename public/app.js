/**
 * AI-GRID GRC Dashboard — Dual-Mode Navigation Controller
 * Supports: Questionnaire-Based Audit + MCP Live Audit
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
  "page-audit": "Audit Log",
  "page-scores": "Trust Scores",
  "page-compliance": "Regulatory Compliance",
  "page-simulation": "What-If Simulator",
  "page-remediation": "Remediation Roadmap",
  "page-manual": "Manual Assessment"
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
    // Fallback: generate steps from hardcoded structure
    questionsData = generateFallbackQuestions();
    totalWizardSteps = questionsData.steps.length;
  }
}

function generateFallbackQuestions() {
  // Fallback question structure in case API isn't available during initial load
  return {
    steps: [
      {
        step: 1, title: "Model Identity",
        questions: [
          { id: "model_name", label: "What is the name of your AI model/system?", type: "text", placeholder: "e.g., Customer Churn Predictor", required: true },
          { id: "model_version", label: "What is the current version?", type: "text", placeholder: "e.g., 1.0.0", required: true },
          { id: "domain", label: "What domain does this AI operate in?", type: "select", options: [
            {value:"healthcare",label:"Healthcare / Medical"},{value:"finance",label:"Finance / Banking"},{value:"agriculture",label:"Agriculture / Environmental"},
            {value:"education",label:"Education / EdTech"},{value:"autonomous_vehicles",label:"Autonomous Vehicles / Robotics"},
            {value:"criminal_justice",label:"Criminal Justice / Law Enforcement"},{value:"entertainment",label:"Entertainment / Media"},
            {value:"ecommerce",label:"E-Commerce / Retail"},{value:"manufacturing",label:"Manufacturing / Industrial"},
            {value:"cybersecurity",label:"Cybersecurity / Threat Detection"},{value:"other",label:"Other"}
          ], required: true },
          { id: "architecture", label: "What is the model architecture?", type: "text", placeholder: "e.g., Transformer, CNN, Random Forest", required: true },
          { id: "autonomy_level", label: "What is the autonomy level?", type: "select", options: [
            {value:"advisory",label:"Advisory Only"},{value:"semi_autonomous",label:"Semi-Autonomous"},{value:"fully_autonomous",label:"Fully Autonomous"}
          ], required: true }
        ]
      },
      {
        step: 2, title: "Training Data",
        questions: [
          { id: "dataset_size", label: "How large is the training dataset? (samples)", type: "number", placeholder: "e.g., 10000", required: true },
          { id: "num_classes", label: "Number of output classes?", type: "number", placeholder: "e.g., 5", required: true },
          { id: "class_balance", label: "Class distribution balance?", type: "select", options: [
            {value:"balanced",label:"Well-Balanced"},{value:"moderate",label:"Moderately Imbalanced"},{value:"severe",label:"Severely Imbalanced"}
          ], required: true },
          { id: "geographic_coverage", label: "Demographic/geographic coverage?", type: "select", options: [
            {value:"full",label:"Full (>80%)"},{value:"partial",label:"Partial (40-80%)"},{value:"limited",label:"Limited (<40%)"}
          ], required: true },
          { id: "known_gaps", label: "Known demographic gaps?", type: "select", options: [
            {value:"none",label:"No known gaps"},{value:"minor",label:"Minor (1-2 groups)"},{value:"significant",label:"Significant (3+)"}
          ], required: true }
        ]
      },
      {
        step: 3, title: "Safety & Reliability",
        questions: [
          { id: "input_validation", label: "Input validation for corrupted data?", type: "select", options: [
            {value:"comprehensive",label:"Comprehensive validation"},{value:"basic",label:"Basic range checking"},{value:"none",label:"No validation"}
          ], required: true },
          { id: "guardrail_count", label: "Number of safety guardrails?", type: "select", options: [
            {value:"3plus",label:"3+ guardrails"},{value:"1to2",label:"1-2 guardrails"},{value:"0",label:"No guardrails"}
          ], required: true },
          { id: "output_safety", label: "Output clamping for dangerous values?", type: "select", options: [
            {value:"yes",label:"Yes - outputs clamped"},{value:"partial",label:"Partial"},{value:"no",label:"No - raw outputs"}
          ], required: true },
          { id: "env_advisory", label: "Environmental/contextual safety advisories?", type: "select", options: [
            {value:"yes",label:"Yes"},{value:"no",label:"No"}
          ], required: true }
        ]
      },
      {
        step: 4, title: "Transparency & Explainability",
        questions: [
          { id: "explainability_engine", label: "Explainability engine?", type: "select", options: [
            {value:"full",label:"Full XAI (SHAP/LIME/Grad-CAM)"},{value:"partial",label:"Feature importance only"},{value:"none",label:"Black box"}
          ], required: true },
          { id: "attribution_count", label: "Feature attributions per prediction?", type: "select", options: [
            {value:"4plus",label:"4+ features"},{value:"1to3",label:"1-3 features"},{value:"0",label:"None"}
          ], required: true },
          { id: "human_readable_reasoning", label: "Human-readable reasoning summaries?", type: "select", options: [
            {value:"yes",label:"Yes"},{value:"no",label:"No"}
          ], required: true }
        ]
      },
      {
        step: 5, title: "Privacy & Security",
        questions: [
          { id: "encryption_rest", label: "Data encrypted at rest?", type: "select", options: [
            {value:"yes",label:"Yes (AES-256 or equivalent)"},{value:"no",label:"No"}
          ], required: true },
          { id: "encryption_transit", label: "Data encrypted in transit?", type: "select", options: [
            {value:"yes",label:"Yes (TLS/HTTPS)"},{value:"no",label:"No"}
          ], required: true },
          { id: "data_retention", label: "Data retention period?", type: "select", options: [
            {value:"short",label:"≤90 days"},{value:"medium",label:"91-180 days"},{value:"long",label:">180 days"}
          ], required: true },
          { id: "adversarial_tested", label: "Adversarial robustness tested?", type: "select", options: [
            {value:"comprehensive",label:"Comprehensive testing"},{value:"basic",label:"Basic testing"},{value:"none",label:"Not tested"}
          ], required: true },
          { id: "drift_monitoring", label: "Model drift monitoring?", type: "select", options: [
            {value:"yes",label:"Automated detection"},{value:"manual",label:"Manual review"},{value:"none",label:"None"}
          ], required: true }
        ]
      },
      {
        step: 6, title: "Accountability & Impact",
        questions: [
          { id: "human_oversight", label: "Human oversight before AI output is acted upon?", type: "select", options: [
            {value:"mandatory",label:"Mandatory human review"},{value:"optional",label:"Optional review"},{value:"none",label:"No human review"}
          ], required: true },
          { id: "incident_escalation", label: "Incident escalation protocol defined?", type: "select", options: [
            {value:"yes",label:"Yes"},{value:"no",label:"No"}
          ], required: true },
          { id: "societal_risk", label: "Potential societal risk from incorrect outputs?", type: "select", options: [
            {value:"low",label:"Low (minor inconvenience)"},{value:"medium",label:"Medium (financial/operational)"},{value:"high",label:"High (physical harm/legal)"}
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

  // Update header
  document.getElementById("wizardStepTitle").textContent = `Step ${wizardStep}: ${stepData.title}`;

  const stepDescs = {
    1: "Tell us about your AI model — name, version, domain, and architecture.",
    2: "Describe your training dataset — size, balance, and coverage.",
    3: "What safety controls and guardrails does your model have?",
    4: "How transparent and explainable are your model's predictions?",
    5: "Describe your data privacy, security, and robustness measures.",
    6: "Tell us about human oversight, accountability, and societal impact."
  };
  document.getElementById("wizardStepDesc").textContent = stepDescs[wizardStep] || "";

  // Update progress bar
  const progressPct = (wizardStep / totalWizardSteps) * 100;
  document.getElementById("wizardProgressFill").style.width = `${progressPct}%`;

  // Update step dots
  document.querySelectorAll(".step-dot").forEach(dot => {
    const s = parseInt(dot.dataset.step);
    dot.classList.toggle("active", s === wizardStep);
    dot.classList.toggle("completed", s < wizardStep);
  });

  // Render questions
  const body = document.getElementById("wizardBody");
  let html = '<div class="wizard-questions">';

  stepData.questions.forEach(q => {
    const savedVal = wizardAnswers[q.id] || "";
    html += `<div class="wizard-question-group">`;
    html += `<label class="wizard-label" for="wq_${q.id}">${q.label}</label>`;

    if (q.type === "text") {
      html += `<input type="text" id="wq_${q.id}" class="form-input" placeholder="${q.placeholder || ''}" value="${savedVal}" onchange="saveWizardAnswer('${q.id}', this.value)">`;
    } else if (q.type === "number") {
      html += `<input type="number" id="wq_${q.id}" class="form-input" placeholder="${q.placeholder || ''}" value="${savedVal}" min="0" onchange="saveWizardAnswer('${q.id}', this.value)">`;
    } else if (q.type === "select") {
      html += `<select id="wq_${q.id}" class="form-select" onchange="saveWizardAnswer('${q.id}', this.value)">`;
      html += `<option value="">— Select —</option>`;
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

  // Update navigation buttons
  document.getElementById("wizardBackBtn").style.display = wizardStep > 1 ? "inline-flex" : "none";
  document.getElementById("wizardNextBtn").style.display = wizardStep < totalWizardSteps ? "inline-flex" : "none";
  document.getElementById("wizardSubmitBtn").style.display = wizardStep === totalWizardSteps ? "inline-flex" : "none";
}

function saveWizardAnswer(id, value) {
  wizardAnswers[id] = value;
}

function wizardNext() {
  // Validate current step
  if (!validateCurrentStep()) return;

  if (wizardStep < totalWizardSteps) {
    wizardStep++;
    renderWizardStep();
    // Smooth scroll to top of wizard
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
// 4. SUBMIT AUDIT (Both modes)
// =========================================================================
async function submitQuestionnaire() {
  if (!validateCurrentStep()) return;

  const btn = document.getElementById("wizardSubmitBtn");
  btn.disabled = true;
  btn.innerHTML = '<span class="btn-icon">⏳</span> Generating Report...';

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

    // Update MCP status pill
    updateStatusPill("Audit Complete", "online");

    // Update topbar target
    document.getElementById("topbarTarget").textContent = wizardAnswers.model_name || "AI System";

    // Show the run audit button for re-runs
    document.getElementById("btnRunAudit").style.display = "inline-flex";
    document.getElementById("btnRunAudit2").style.display = "inline-flex";

    // Stream logs and apply data
    showPage("page-audit");
    const terminalLog = document.getElementById("terminalLog");
    const terminalStatus = document.getElementById("terminalStatus");
    terminalStatus.textContent = "ANALYZING...";
    terminalStatus.style.color = "#d97706";
    terminalLog.innerHTML = `<div class="log-line info"><span class="timestamp">[SYSTEM]</span> Starting questionnaire-based audit for '${wizardAnswers.model_name || "AI System"}'...</div>`;

    streamLogsToTerminal(json.data.audit_logs, () => {
      applyAuditDataToUI(json.data);
      terminalStatus.textContent = "AUDIT COMPLETE";
      terminalStatus.style.color = "#059669";
      showProbeSummary(json.data.probe_summary);
    });

  } catch (err) {
    console.error("Audit error:", err);
    alert("Error generating audit: " + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="btn-icon">🚀</span> Generate Audit Report';
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
    alert("Please enter the MCP server URL or command.");
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
      alert("MCP Connection: " + (json.error || "Failed to connect"));
      return;
    }

    currentAuditData = json.data;
    updateStatusPill("MCP Connected", "online");
    document.getElementById("topbarTarget").textContent = json.data.model_metadata?.model_name || "MCP AI System";
    document.getElementById("btnRunAudit").style.display = "inline-flex";

    showPage("page-audit");
    const terminalLog = document.getElementById("terminalLog");
    terminalLog.innerHTML = `<div class="log-line info"><span class="timestamp">[SYSTEM]</span> Connected to MCP server...</div>`;

    streamLogsToTerminal(json.data.audit_logs, () => {
      applyAuditDataToUI(json.data);
      document.getElementById("terminalStatus").textContent = "AUDIT COMPLETE";
      document.getElementById("terminalStatus").style.color = "#059669";
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

// =========================================================================
// 5. STATUS PILL
// =========================================================================
function updateStatusPill(text, status) {
  const pill = document.getElementById("mcpStatusPill");
  const textEl = document.getElementById("mcpStatusText");
  textEl.textContent = text;
  pill.className = "mcp-status-pill " + status;
}

// =========================================================================
// 6. RADAR CHART
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
        backgroundColor: "rgba(139, 92, 246, 0.15)",
        borderColor: "#8b5cf6",
        pointBackgroundColor: "#8b5cf6",
        pointBorderColor: "#ffffff",
        pointHoverBackgroundColor: "#7c3aed",
        pointHoverBorderColor: "#8b5cf6",
        borderWidth: 2.5,
        pointRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        r: {
          angleLines: { color: "rgba(139, 92, 246, 0.1)" },
          grid: { color: "rgba(139, 92, 246, 0.08)" },
          pointLabels: {
            font: { family: "'Inter', sans-serif", size: 10, weight: "600" },
            color: "#4c4577"
          },
          ticks: {
            backdropColor: "rgba(255, 255, 255, 0.8)",
            color: "#7c7499",
            stepSize: 20
          },
          suggestedMin: 0,
          suggestedMax: 100
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "#1e1b4b",
          titleColor: "#c4b5fd",
          bodyColor: "#f5f3ff",
          borderColor: "rgba(139, 92, 246, 0.4)",
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
  }, 70);
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
    <div class="probe-stat-item"><div class="stat-num">${summary.guardrails_tested}</div><div class="stat-label">Guardrails</div></div>
    <div class="probe-stat-item"><div class="stat-num">${summary.adversarial_tests}</div><div class="stat-label">Adversarial Tests</div></div>
    <div class="probe-stat-item"><div class="stat-num">${summary.findings_count}</div><div class="stat-label">Findings</div></div>
  `;
}

// =========================================================================
// 8. APPLY AUDIT DATA TO UI
// =========================================================================
function applyAuditDataToUI(data) {
  // Profile
  const meta = data.model_metadata || {};
  const el = (id) => document.getElementById(id);

  if (el("profModelName")) el("profModelName").textContent = meta.model_name || "—";
  if (el("profDomain")) el("profDomain").textContent = meta.domain || meta.model_name || "—";
  if (el("profArch")) el("profArch").textContent = meta.model_architecture || "—";
  if (el("profAuditMode")) el("profAuditMode").textContent = data.audit_mode === "questionnaire" ? "Questionnaire-Based Assessment" : "MCP Live Probe";
  if (el("profDataSize")) el("profDataSize").textContent = meta.training_dataset_size ? `${meta.training_dataset_size.toLocaleString()} Samples` : "—";
  if (el("profAutonomy")) {
    const autonomyLabels = { "advisory": "Advisory Only", "semi_autonomous": "Semi-Autonomous", "fully_autonomous": "Fully Autonomous" };
    el("profAutonomy").textContent = autonomyLabels[meta.autonomy_level] || meta.autonomy_level || "—";
  }
  if (el("profVersion")) el("profVersion").textContent = meta.version || "—";

  // Scores
  const scoring = data.scoring;
  el("aasScore").textContent = scoring.aas_score;
  el("gradeBadge").textContent = scoring.trust_grade;
  el("mathAvg").textContent = scoring.weighted_average;
  el("mathMin").textContent = scoring.bottleneck_score;
  el("bottleneckDesc").textContent = `${scoring.bottleneck_dimension} (${scoring.bottleneck_score}/100) constraints overall adequacy.`;

  // Grade badge styling
  const badge = el("gradeBadge");
  const scoreLbl = el("scoreLabel");
  if (scoring.trust_grade.startsWith("A")) {
    badge.style.borderColor = "#059669"; badge.style.color = "#059669";
    badge.style.background = "linear-gradient(135deg, #ecfdf5, #d1fae5)";
    scoreLbl.textContent = "Minimal Governance Risk"; scoreLbl.style.color = "#059669";
  } else if (scoring.trust_grade === "B" || scoring.trust_grade === "C") {
    badge.style.borderColor = "#d97706"; badge.style.color = "#d97706";
    badge.style.background = "linear-gradient(135deg, #fffbeb, #fef3c7)";
    scoreLbl.textContent = "Moderate Governance Risk"; scoreLbl.style.color = "#d97706";
  } else {
    badge.style.borderColor = "#7c3aed"; badge.style.color = "#7c3aed";
    badge.style.background = "linear-gradient(135deg, #f5f3ff, #ede9fe)";
    scoreLbl.textContent = "High Governance Risk"; scoreLbl.style.color = "#7c3aed";
  }

  // Radar
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
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">No findings — all dimensions passed.</td></tr>`;
  } else {
    items.forEach(item => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span class="priority-tag ${item.badge}">${item.priority}</span></td>
        <td><strong>${item.dimension}</strong></td>
        <td style="color: #4c4577;">${item.finding}</td>
        <td style="color: #6d28d9; font-weight: 500;">${item.action}</td>
      `;
      tbody.appendChild(tr);
    });
  }

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
        deltaEl.textContent = `${sim.delta} (Elevated Risk)`;
        deltaEl.className = "sim-delta negative";
      } else if (sim.delta > 0) {
        deltaEl.textContent = `+${sim.delta} (Reduced Risk)`;
        deltaEl.className = "sim-delta positive";
      } else {
        deltaEl.textContent = "0.0 (Baseline)";
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
}
