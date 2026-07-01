# NIST AI RMF Control Mapping — NovaMed Health CDS Platform

**Document ID:** NOVAMED-AI-NIST-NOTES
**Classification:** Internal
**Owner:** CCIO
**Reference:** NIST AI Risk Management Framework (AI RMF 1.0, 2023)

---

## NIST AI RMF Overview

The NIST AI RMF organises AI risk management across four core functions:

| Function | Purpose |
|----------|---------|
| **GOVERN** | Cultivate and implement organisational practices that make AI risk management part of the culture |
| **MAP** | Categorise and contextualise AI risks relative to the organisation's goals and obligations |
| **MEASURE** | Analyse and assess identified AI risks using defined metrics and methods |
| **MANAGE** | Prioritise and action risk treatment plans; monitor effectiveness over time |

---

## Function 1 — GOVERN

*Establishing organisational policies, culture, accountability structures, and processes to manage AI risk across the lifecycle.*

| Sub-Category | NovaMed Control | Status | Document Reference |
|-------------|----------------|--------|-------------------|
| GOVERN 1.1 — AI risk policies established | AI Governance Policy (NOVAMED-POL-AI-003) | ⚠️ Partial | Policy drafted; pending CEO approval |
| GOVERN 1.2 — Accountability for AI risk is clear | AI System Owner (CCIO) appointed; AISC established | ✅ Compliant | AI Governance Policy §4 |
| GOVERN 1.3 — Organisation's risk tolerance for AI is defined | Bias threshold policy and risk rating methodology | ✅ Compliant | Risk Register §Risk Rating Methodology; Bias Assessment §Threshold Policy |
| GOVERN 1.4 — Organisational teams understand roles | AISC Terms of Reference; clinician responsibilities | ⚠️ Partial | Policy §4; ToR pending approval |
| GOVERN 1.5 — AI risk processes integrated into wider governance | AISC reporting to Board; integration with clinical governance | ⚠️ Partial | Policy §4; Board reporting cadence TBD |
| GOVERN 1.6 — Staff AI risk awareness and training | Clinician AI training program | ❌ Gap | Training developed; delivery pre-go-live |
| GOVERN 2.1 — Policies address trustworthy AI characteristics | Safety, fairness, transparency, accountability addressed | ⚠️ Partial | Policy §2 scope; explicit principles section pending |
| GOVERN 2.2 — Policies address human-AI interaction | Human override requirement; advisory-only framing | ✅ Compliant | Policy §5.3 |
| GOVERN 4.1 — Risk management results inform procurement | Vendor due diligence gate; AI risk register pre-deployment | ✅ Compliant | Policy §5.1 deployment gate |
| GOVERN 5.1 — Organisational risk tolerance communicated to vendors | Vendor contract obligations; bias disclosure requirements | ⚠️ Partial | Policy §7; contract pending execution |
| GOVERN 6.1 — Policies for AI lifecycle management | Deployment gate, change management, retirement process | ✅ Compliant | Policy §6 |
| GOVERN 6.2 — Incident management for AI | AI Incident Response Procedure | ✅ Compliant | NOVAMED-AI-IRP-005 |

---

## Function 2 — MAP

*Identifying and categorising AI risks in the specific context of the organisation, use case, and affected populations.*

| Sub-Category | NovaMed Control | Status | Document Reference |
|-------------|----------------|--------|-------------------|
| MAP 1.1 — Context of AI use is understood | CDS platform context documented in project scope | ✅ Compliant | README — Project Context |
| MAP 1.5 — Organisational risk tolerance defined for AI context | Risk rating methodology; bias thresholds | ✅ Compliant | Risk Register; Bias Assessment |
| MAP 2.1 — Scientific basis for AI use assessed | Clinical validation study required pre-deployment | ⚠️ Partial | Risk Register AIR-001 treatment |
| MAP 2.2 — AI system intended use defined | CDS advisory function; prohibited uses documented | ✅ Compliant | AI Governance Policy §5.2 |
| MAP 2.3 — AI system context — clinical, regulatory, ethical | Healthcare clinical AI; TGA, Privacy Act, NSQHS obligations | ✅ Compliant | PIA; TGA assessment (AIR-004); Bias Assessment |
| MAP 3.1 — AI risks identified and categorised | 10 risks across patient safety, bias, privacy, governance, operational categories | ✅ Compliant | NOVAMED-AI-RR-001 |
| MAP 3.2 — Vulnerable populations considered | First Nations zero-tolerance bias threshold; CALD patient assessment | ✅ Compliant | NOVAMED-AI-BIAS-002 |
| MAP 3.5 — Third-party risks identified | Vendor data breach risk (AIR-008); data sovereignty; contractual gaps | ✅ Compliant | Risk Register AIR-008; PIA APP 8 |
| MAP 5.1 — Likelihood and impact of AI risks assessed | Likelihood × Consequence scoring with 5×5 matrix | ✅ Compliant | NOVAMED-AI-RR-001 §Risk Rating Methodology |
| MAP 5.2 — Risk prioritisation established | Inherent risk scores; treatment prioritisation by rating | ✅ Compliant | Risk Register — Risk Summary Dashboard |

---

## Function 3 — MEASURE

*Analysing and quantifying identified AI risks using defined metrics, testing methods, and evaluation processes.*

| Sub-Category | NovaMed Control | Status | Document Reference |
|-------------|----------------|--------|-------------------|
| MEASURE 1.1 — Metrics for AI risks are defined | KPIs: accuracy, acceptance rate, override rate, confidence scores | ✅ Compliant | AI Governance Policy §6.2 |
| MEASURE 2.1 — Testing and evaluation of AI system | Pre-deployment clinical validation study | ⚠️ Partial | Risk Register AIR-001 — study not yet completed |
| MEASURE 2.2 — AI system performance in deployment monitored | Monthly and quarterly monitoring schedule | ✅ Compliant | AI Governance Policy §6.2 |
| MEASURE 2.5 — Bias and fairness testing methodology | Pre-deployment independent bias audit; quarterly post-deployment monitoring | ✅ Compliant | NOVAMED-AI-BIAS-002 |
| MEASURE 2.6 — Explainability of AI outputs assessed | Explainability requirement in vendor contract; SHAP-based explanation requirement | ✅ Compliant | Risk Register AIR-010; AI Governance Policy §7 |
| MEASURE 2.7 — Privacy risk measured | Privacy Impact Assessment completed | ✅ Compliant | NOVAMED-AI-PIA-004 |
| MEASURE 2.8 — Security risks measured | Vendor security assessment required; penetration test in scope | ⚠️ Partial | Risk Register AIR-008 — vendor assessment in progress |
| MEASURE 2.9 — Model drift monitoring defined | Drift threshold and escalation process | ✅ Compliant | Risk Register AIR-006; AI Governance Policy §6.2 |
| MEASURE 4.1 — Risk measurement results documented and communicated | Risk register maintained; AISC reporting | ✅ Compliant | Risk Register; AI Governance Policy §4 |

---

## Function 4 — MANAGE

*Prioritising and implementing risk responses; monitoring treatment effectiveness; learning from incidents.*

| Sub-Category | NovaMed Control | Status | Document Reference |
|-------------|----------------|--------|-------------------|
| MANAGE 1.1 — Responses to identified risks determined | Treatment plans for all 10 risks with owners and timelines | ✅ Compliant | NOVAMED-AI-RR-001 — all risks have treatment plans |
| MANAGE 1.3 — Responses implemented and effectiveness tracked | Treatment plan tracking in risk register; quarterly review | ✅ Compliant | Risk Register — Review Date column |
| MANAGE 2.2 — Mechanisms to respond to incidents | AI Incident Response Procedure — P1 through P4 classification | ✅ Compliant | NOVAMED-AI-IRP-005 |
| MANAGE 2.4 — Bias incidents are addressed | Bias threshold breach protocol; remediation process | ✅ Compliant | NOVAMED-AI-BIAS-002 §Remediation Process |
| MANAGE 3.1 — Risk response prioritised by severity | P1-P4 incident classification and escalation | ✅ Compliant | NOVAMED-AI-IRP-005 §Incident Classification |
| MANAGE 3.2 — Residual risks documented and accepted | Residual risk scores and acceptance sign-off in risk register | ✅ Compliant | NOVAMED-AI-RR-001 — all risks have residual rating and acceptance |
| MANAGE 4.1 — Incidents are documented and reviewed | Post-incident review requirements for P1-P4 | ✅ Compliant | NOVAMED-AI-IRP-005 §Post-Incident Review |
| MANAGE 4.2 — Learning from incidents informs improvement | Lessons learned process; policy review triggers | ✅ Compliant | NOVAMED-AI-IRP-005 §Continuous Improvement |
| MANAGE 4.3 — AI risk management performance reviewed | AISC quarterly review; annual ISO 42001 audit (planned) | ⚠️ Partial | Policy §9.3 management review; audit program pending |

---

## NIST AI RMF Coverage Summary

| Function | Total Sub-Categories | Compliant | Partial | Gap |
|----------|:---:|:-:|:-:|:-:|
| GOVERN | 12 | 5 | 5 | 2 |
| MAP | 10 | 9 | 1 | 0 |
| MEASURE | 9 | 7 | 2 | 0 |
| MANAGE | 9 | 7 | 2 | 0 |
| **Total** | **40** | **28 (70%)** | **10 (25%)** | **2 (5%)** |

**Strongest coverage:** MAP and MANAGE — reflecting the depth of the risk register and incident response documentation
**Gaps to address:** GOVERN 1.6 (staff training — scheduled pre-go-live) and GOVERN 2.1 (AI principles statement — policy amendment required)

---

## Key Distinctions — NIST AI RMF vs ISO 42001

| Dimension | NIST AI RMF | ISO 42001 |
|-----------|------------|-----------|
| Type | Framework (voluntary, guidance-based) | Standard (certifiable management system) |
| Structure | Four functions (GOVERN, MAP, MEASURE, MANAGE) | Ten clauses (management system structure) |
| Focus | Risk management throughout AI lifecycle | Systematic management of AI across the organisation |
| Certifiable | No — used as a reference framework | Yes — third-party certification available |
| Best used for | AI risk assessment and governance programme design | Demonstrating AI governance maturity to regulators and clients |
| NovaMed application | Primary AI risk management methodology | Aspirational compliance target — roadmap to certification readiness |

---

*This document is part of a sample GRC portfolio project. NovaMed Health is a fictional organisation. All scenarios are created for professional skills demonstration.*
