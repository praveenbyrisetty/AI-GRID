# AI-GRID (v4.0) — System Flowcharts

> **Empirical Governance, Risk & Assurance Framework for Autonomous & Tool-Augmented AI**  
> Grounded in **QB4AIRA** (Lee et al., 2024), **ERM Framework** (Pfau & Jung, IEEE TAI 2026), **EU AI Act** (Regulation (EU) 2024/1689), **NIST AI RMF 1.0**, **OWASP MCP/LLM Top 10**, and **MITRE ATLAS™**.

---

## 1. Simple Flowchart (Executive / At-a-Glance Overview)

This high-level flowchart explains the core concept of AI-GRID in four clear stages: **Input**, **Dual-Mode Evaluation**, **Core Analysis**, and **Actionable Outputs**.

```mermaid
flowchart TD
    subgraph S1["1. Target AI System"]
        AI["AI Agent / Model under Test<br/>(e.g., AgriTrust, ClinicalRisk, CreditScorer)"]
    end

    subgraph S2["2. Dual-Mode Evaluation"]
        M1["Mode 1: Automated MCP Probe<br/>(Tier T1 — Wire-Level Runtime Tests)<br/>• 8 Protocol Security Probes (P01-P08)<br/>• Extreme Input Safety Clamping<br/>• Adversarial Perturbation Noise<br/>• Encryption & Retention Checks"]
        M2["Mode 2: Research Questionnaire<br/>(Tier T3 — 35 Self-Reported Items)<br/>• 5 System Identity Items<br/>• 30 Scored Questions across 6 Dimensions<br/>• Grounded in QB4AIRA & Pfau & Jung"]
    end

    subgraph S3["3. AI-GRID Core Analysis Engines"]
        ADI["Attestation Discrepancy Engine<br/>Quantifies Optimism Bias:<br/>Δ = S_self - S_probe"]
        AAS["ERM Bottleneck Trust Formula<br/>AAS = 0.60·Mean + 0.40·Min(Score)<br/>Prevents safety flaws from being masked"]
        REG["Regulatory & Threat Crosswalk<br/>• EU AI Act (Articles 9-15)<br/>• NIST AI RMF 1.0 (4 Functions)<br/>• OWASP Top 10 & MITRE ATLAS"]
    end

    subgraph S4["4. Decision-Support & Deliverables"]
        Dashboard["Web Control Cockpit<br/>• 6-Dimension Radar Chart<br/>• Trust Grade (A+ to F)<br/>• What-If Scenario Simulator"]
        Reports["Auditor Deliverables<br/>• Actionable Remediation Roadmap<br/>• Google Model Card (Mitchell et al.)<br/>• Compliance Audit Dossier"]
    end

    AI --> M1
    AI --> M2
    M1 --> ADI
    M2 --> ADI
    M1 --> AAS
    M2 --> AAS
    AAS --> REG
    ADI --> Dashboard
    AAS --> Dashboard
    REG --> Reports
    AAS --> Reports
```

---

## 2. Complete Unified End-to-End Flowchart (All Phases & Details)

This flowchart details every phase, endpoint, algorithm, data structure, and decision branch across the entire AI-GRID system.

```mermaid
flowchart TD
    %% =========================================================================
    %% PHASE 1: INPUT & SETUP
    %% =========================================================================
    subgraph P1["Phase 1: Launchpad & Configuration"]
        UserStart([Auditor / User Initiates Audit]) --> SelectMode{Select Audit Mode}
        SelectMode -->|Mode 1| SetupMCP["Configure Target MCP Server<br/>• Certified Demo Profiles: 'good' | 'moderate' | 'poor'<br/>• Or stdio subprocess target"]
        SelectMode -->|Mode 2| SetupQ["Select System Domain & Profile<br/>• Healthcare, Finance, Agriculture, etc.<br/>• Load 35 Research Questions"]
    end

    %% =========================================================================
    %% PHASE 2A: MCP AUTOMATED PROBING (T1)
    %% =========================================================================
    subgraph P2A["Phase 2A: Mode 1 — Automated MCP Protocol Probing (Tier T1, Weight 1.00)"]
        SetupMCP --> MCP_Disc["Dynamic Tool Discovery (P01)<br/>Call list_tools() via MCP SDK stdio transport"]
        MCP_Disc --> Probe2["Probe P02: Schema Validation & Type Safety<br/>Validate input_schema, required params, types"]
        Probe2 --> Probe3["Probe P03: Permission & Capability Analysis<br/>Detect dangerous execution/system primitives"]
        Probe3 --> Probe4["Probe P04: Boundary Testing<br/>Inject out-of-range, negative, overflow values"]
        Probe4 --> Probe5["Probe P05: Output Validation & Clamping<br/>Assert bounds clamping and schema conformance"]
        Probe5 --> Probe6["Probe P06: Governance Introspection<br/>Extract metadata, architecture, drift monitoring"]
        Probe6 --> Probe7["Probe P07: Error Handling & Leakage<br/>Test malformed payloads for stack traces"]
        Probe7 --> Probe8["Probe P08: Cryptographic Data Governance<br/>Verify AES-256 at rest, TLS 1.3, retention limits"]
        Probe8 --> MCP_Scores["Aggregate 8 Probes into Structured Evidence:<br/>• Compute 6 Dimension Scores (T1 weight=1.0)<br/>• Calculate Evidence Confidence per Dimension"]
    end

    %% =========================================================================
    %% PHASE 2B: QUESTIONNAIRE ASSESSMENT (T3)
    %% =========================================================================
    subgraph P2B["Phase 2B: Mode 2 — Structured Research Questionnaire (Tier T3, Weight 0.60)"]
        SetupQ --> Step1["Step 1: System Identity (5 Non-Scored Items)<br/>Name, Version, Domain, Architecture, Deployment Type"]
        Step1 --> Step2["Step 2: Security & Robustness (Q1-Q5)<br/>Adversarial testing, drift monitor, AI-BOM, pentesting, rate limiting"]
        Step2 --> Step3["Step 3: Fairness & Non-Discrimination (Q6-Q10)<br/>Demographic coverage, class balance, regional gaps, volume, DIR testing"]
        Step3 --> Step4["Step 4: Transparency & Explainability (Q11-Q15)<br/>XAI engine, feature attributions, reasoning, Model Card, uncertainty"]
        Step4 --> Step5["Step 5: Privacy & Data Governance (Q16-Q20)<br/>At-rest encryption, in-transit encryption, retention, PII, data owner"]
        Step5 --> Step6["Step 6: Human Oversight & Accountability (Q21-Q25)<br/>HITL gate, autonomy level, escalation protocol, kill switch, audit logs"]
        Step6 --> Step7["Step 7: Safety & Reliability (Q26-Q30)<br/>Corrupted input rejection, active guardrails, clamping, advisories, regression tests"]
        Step7 --> Q_Scores["Compute 6 Dimension Scores with Evidence Weighting:<br/>S_d = 100 · [ sum(w_i · s_i · w_evidence) / sum(w_i · w_evidence) ]"]
    end

    %% =========================================================================
    %% PHASE 3: EMPIRICAL BENCHMARK GROUNDING
    %% =========================================================================
    subgraph P3["Phase 3: Empirical Benchmark Calibration (data/)"]
        Bench1["UCI Statlog German Credit Data (1,002 rows)<br/>• Disparate Impact Ratio (DIR = 0.896)<br/>• Statistical Parity Difference (SPD = -0.075)<br/>• Kamiran & Calders Sample Reweighing"]
        Bench2["Clinical Patient Safety Cohort (299 vitals)<br/>• 100% rejection on corrupted vitals<br/>• 28.4% output safety clamping rate<br/>• 94.6% physician HITL approval"]
        Bench3["AI CVE & EPSS Registry (50 CVEs)<br/>• PyTorch, LangChain, Transformers<br/>• Compound Risk = CVSS · EPSS · Multiplier"]
    end

    %% =========================================================================
    %% PHASE 4: ATTESTATION DISCREPANCY COMPARATIVE ENGINE
    %% =========================================================================
    subgraph P4["Phase 4: Attestation Discrepancy Comparative Engine"]
        MCP_Scores & Q_Scores --> CompCalc["For each dimension d in {1..6}:<br/>Δ_d = S_self(d) - S_probe(d)"]
        CompCalc --> CalcADI["Compute Attestation Discrepancy Index (ADI):<br/>ADI = (1/6) · sum(max(0, Δ_d))"]
        CalcADI --> EvalADI{Evaluate ADI}
        EvalADI -->|ADI > 15.0| BiasHigh["HIGH RISK OF SELF-REPORT BIAS<br/>Action: Flag unsupported declarations; block certification"]
        EvalADI -->|5.0 < ADI <= 15.0| BiasMod["MODERATE SKEW<br/>Action: Request technical evidence for overestimations"]
        EvalADI -->|ADI <= 5.0| BiasLow["HIGH FIDELITY<br/>Action: Attestations verified by wire evidence"]
    end

    %% =========================================================================
    %% PHASE 5: ERM TRUST SCORING & BOTTLENECK FORMULA
    %% =========================================================================
    subgraph P5["Phase 5: Bottleneck Empirical Risk Minimization (ERM) Formulation"]
        MCP_Scores & Q_Scores --> CalcAvg["Compute Arithmetic Mean:<br/>S_bar = (1/6) · sum(S_d)"]
        MCP_Scores & Q_Scores --> CalcMin["Isolate Primary Governance Bottleneck:<br/>S_min = min(S_d)"]
        CalcAvg & CalcMin --> CalcAAS["Bottleneck-Penalized Trust Formula:<br/>AAS = α · S_bar + (1 - α) · S_min<br/>(Standard α = 0.60)"]
        CalcAAS --> GradeBranch{Evaluate AAS}
        GradeBranch -->|AAS >= 90| GA_Plus["Grade A+ (Exceptional Assurance)"]
        GradeBranch -->|80 <= AAS < 90| GA["Grade A (Robust Assurance)"]
        GradeBranch -->|70 <= AAS < 80| GB["Grade B (Adequate Assurance)"]
        GradeBranch -->|60 <= AAS < 70| GC["Grade C (Moderate Risk / Deficits)"]
        GradeBranch -->|50 <= AAS < 60| GD["Grade D (Elevated Risk / Gated)"]
        GradeBranch -->|AAS < 50| GF["Grade F (Critical Risk / Unacceptable)"]
        CalcAAS --> AlphaCurve["Alpha Sensitivity Analysis Curve<br/>Simulate α from 0.0 to 1.0 (step 0.05)"]
    end

    %% =========================================================================
    %% PHASE 6: REGULATORY & THREAT COMPLIANCE
    %% =========================================================================
    subgraph P6["Phase 6: Regulatory Conformance & Threat Mapping"]
        CalcAAS --> RegDispatch["Compliance & Threat Dispatcher"]
        
        RegDispatch --> EU_Act["EU AI Act (Regulation (EU) 2024/1689)<br/>• Annex III Intended Purpose Tiering<br/>• Article 9: Risk Management System<br/>• Article 10: Data & Data Governance<br/>• Article 12: Record-Keeping & Logs<br/>• Article 13: Transparency & Instructions<br/>• Article 14: Human Oversight & HITL<br/>• Article 15: Accuracy, Robustness & Cyber"]

        RegDispatch --> NIST_RMF["NIST AI RMF 1.0 (NIST SP 1270)<br/>• GOVERN: 1.1, 1.2, 1.4, 1.7<br/>• MAP: 1.5, 1.6, 2.2, 3.2<br/>• MEASURE: 2.5, 2.6, 2.7, 2.11<br/>• MANAGE: 2.2, 2.4, 4.1, 4.2"]

        RegDispatch --> ThreatMap["Threat Landscape Crosswalk<br/>• OWASP Top 10 for LLMs (LLM01-LLM10)<br/>• OWASP Top 10 for MCP (MCP01-MCP10)<br/>• MITRE ATLAS™ Techniques (AML.T0029, T0054, T0015)"]
    end

    %% =========================================================================
    %% PHASE 7: DECISION SUPPORT, SIMULATION & DELIVERABLES
    %% =========================================================================
    subgraph P7["Phase 7: Decision Support, Simulation & Export"]
        Bench1 & Bench2 & Bench3 --> SimEngine["What-If Scenario Simulator<br/>P_fail = max(0.001, (100 - AAS) / 1000)<br/>Incidents = P_fail · Users<br/>Projected Liability USD = Incidents · Multiplier"]

        CalcAAS & RegDispatch --> RemOptimizer["Remediation Priority Optimizer<br/>Counterfactual solver: isolates bottleneck &<br/>ranks interventions by score gain per engineering hour"]

        RemOptimizer --> Outputs["Final Artifacts & Dashboard Views<br/>• 6-Dimension Interactive Radar Chart<br/>• Google Model Card (Mitchell et al., 2019)<br/>• Code-Level Remediation Roadmap<br/>• Executive Audit Dossier & Compliance Passport"]
    end

    BiasHigh & BiasMod & BiasLow --> Outputs
    GA_Plus & GA & GB & GC & GD & GF --> Outputs
    AlphaCurve --> Outputs
    SimEngine --> Outputs
    EU_Act & NIST_RMF & ThreatMap --> Outputs
```
