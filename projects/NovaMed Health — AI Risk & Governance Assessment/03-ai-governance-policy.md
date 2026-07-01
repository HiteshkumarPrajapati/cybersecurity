# AI Governance Policy — NovaMed Health

**Document ID:** NOVAMED-POL-AI-003
**Version:** 1.0
**Classification:** Internal — Restricted
**Policy Owner:** Chief Clinical Information Officer (CCIO)
**Approved By:** Chief Executive Officer
**Approval Date:** 2025
**Next Review Date:** 2026 (annual)
**Framework references:** NIST AI RMF · ISO/IEC 42001:2023 · Privacy Act 1988 (AU) · TGA SaMD guidance · NSQHS Standards

---

## 1. Purpose

This policy establishes NovaMed Health's governance framework for the responsible deployment, operation, monitoring, and retirement of artificial intelligence (AI) systems used in clinical and operational environments. It defines accountability structures, decision-making authority, acceptable use boundaries, and control requirements to ensure AI systems operate safely, transparently, and in alignment with NovaMed's clinical, regulatory, and ethical obligations.

---

## 2. Scope

This policy applies to:
- All AI systems deployed or under evaluation by NovaMed Health, including AI-assisted clinical decision support tools, diagnostic AI, administrative automation, and predictive analytics
- All NovaMed staff, contractors, and third-party vendors who develop, procure, configure, operate, or maintain AI systems on behalf of NovaMed
- All patient data and organisational data processed by AI systems

This policy is effective immediately upon CEO approval and applies across all four NovaMed metropolitan facilities.

---

## 3. Definitions

| Term | Definition |
|------|-----------|
| **AI System** | A machine-based system that uses data inputs to generate outputs such as recommendations, decisions, predictions, or content that influences real-world events or decisions |
| **Clinical AI** | An AI system whose outputs influence clinical decisions, patient care pathways, diagnosis, or treatment |
| **AI System Owner** | The designated individual accountable for an AI system's performance, safety, governance, and lifecycle |
| **AISC** | AI Safety and Compliance Committee — NovaMed's governance body for AI risk and compliance oversight |
| **Model Drift** | Degradation of AI model performance over time due to changes in input data patterns, patient population, or clinical practice |
| **SaMD** | Software as a Medical Device — AI software that meets the TGA definition requiring registration under the Therapeutic Goods Act 1989 |
| **Human Override** | A clinician's decision to disregard or modify an AI recommendation based on independent clinical assessment |

---

## 4. Governance Structure

### 4.1 AI Safety and Compliance Committee (AISC)

**Composition:**
- Chief Clinical Information Officer (Chair)
- Chief Medical Officer
- Chief Information Officer
- Privacy Officer
- Clinical Governance Lead
- Legal Counsel
- Patient Safety Representative

**Responsibilities:**
- Approve deployment of all clinical AI systems
- Review quarterly AI risk dashboard and risk register
- Approve AI governance policy updates
- Oversee bias threshold breaches and remediation
- Receive AI incident reports and approve significant corrective actions
- Report AI risk status to the Board bi-annually

**Meeting frequency:** Monthly (standard) · As required (P1/P2 incidents)

---

### 4.2 AI System Owner

Each deployed AI system must have a designated AI System Owner. For the CDS platform, the AI System Owner is the **Chief Clinical Information Officer**.

**Responsibilities:**
- Maintain the AI Risk Register for the assigned system
- Monitor AI system performance against defined KPIs
- Escalate performance degradation, bias threshold breaches, and incidents to AISC
- Manage vendor relationship for AI system obligations
- Ensure AI system documentation is current
- Conduct quarterly performance reviews
- Approve model updates before clinical deployment

---

### 4.3 Clinician Responsibilities

All clinical staff with access to the CDS system must:
- Complete mandatory AI literacy training before access is provisioned
- Treat all AI outputs as decision support — not as a substitute for clinical judgment
- Apply independent clinical assessment before acting on any AI recommendation
- Document the basis for clinical decisions independently of AI output
- Report any unexpected, harmful, or concerning AI output through the AI incident reporting process
- Exercise the human override right at any time — no clinical or administrative pressure may be applied to accept an AI recommendation

---

## 5. AI Deployment Requirements

### 5.1 Pre-Deployment Approval Gate

No AI system may be deployed in a clinical context at NovaMed without AISC approval. The following must be completed before AISC approval is granted:

| Requirement | Responsible | Documentation |
|-------------|-------------|---------------|
| AI Risk Assessment completed and reviewed | AI System Owner | Risk register with treatment plans |
| Bias and Fairness Assessment completed | CCIO / Independent auditor | Bias assessment report |
| TGA SaMD classification assessment | Legal Counsel | Written classification determination |
| Privacy Impact Assessment completed | Privacy Officer | PIA report |
| Vendor security assessment completed | CIO | Vendor security rating and DPA executed |
| Clinical validation study results reviewed | CMO | Accuracy benchmarks vs threshold |
| AI Governance Policy briefing for clinical staff | HR / CMO | Training completion records |
| AISC approval recorded | AISC Chair | Signed AISC approval minute |

**Gate principle:** Any incomplete requirement blocks deployment. There are no waivers for clinical AI systems.

---

### 5.2 Acceptable Use

**Permitted uses of the CDS AI system:**
- Providing ranked differential diagnosis recommendations to credentialled clinical staff as decision support
- Flagging high-priority clinical findings for clinician review
- Summarising relevant patient history for clinical assessment

**Prohibited uses:**
- Autonomous clinical decision-making without clinician review and sign-off
- Using AI recommendations as the sole documented basis for a clinical decision
- Applying AI recommendations to patient populations or clinical specialties outside the validated scope
- Using patient data processed by the AI system for model retraining without explicit patient consent
- Sharing AI output with third parties not involved in the patient's direct care

---

### 5.3 Human Override Requirement

All AI recommendations are advisory. The following control is mandatory:

- The CDS system interface **must** display the label: *"This output is clinical decision support only. It does not constitute a diagnosis. Clinical judgment is required before any action is taken."*
- Clinicians **must** document their independent clinical assessment for every patient encounter, regardless of whether the AI recommendation was accepted or overridden
- Override events **must** be logged automatically by the system — the reason for override is optional but encouraged
- No clinician may be directed by a manager, department head, or administrator to accept an AI recommendation they have assessed as clinically incorrect

---

## 6. AI System Lifecycle Controls

### 6.1 Model Change Management

Any change to the AI model — including retraining, dataset updates, algorithm modifications, or version upgrades — must follow this process:

| Step | Action | Responsible |
|------|--------|-------------|
| 1 | Vendor provides 30 days written notice of proposed model change | Vendor (contractual obligation) |
| 2 | AI System Owner reviews change scope and assesses re-validation requirements | CCIO |
| 3 | Clinical validation re-run if model change affects clinical output | CCIO / CMO |
| 4 | Bias testing re-run for material model changes | CCIO / Independent auditor |
| 5 | AISC approval for material changes before deployment to clinical environment | AISC |
| 6 | Change documented in AI system register with version history | AI System Owner |

**Definition of material change:** Any change that alters model architecture, training data, output format, clinical scope, or performance benchmarks by more than 5%.

---

### 6.2 Performance Monitoring

| KPI | Measurement | Frequency | Alert Threshold |
|-----|-------------|-----------|----------------|
| Recommendation accuracy vs clinical outcome | Clinical audit | Monthly | >5% degradation vs baseline |
| Clinician acceptance rate | System logging | Monthly | <70% acceptance triggers review |
| Override rate | System logging | Monthly | >30% override rate triggers review |
| Confidence score distribution | Model output | Monthly | Mean confidence <80% triggers review |
| Bias metrics — demographic stratification | Data analysis | Quarterly | >10% differential triggers threshold protocol |
| System availability | Infrastructure monitoring | Continuous | <99.5% uptime triggers vendor escalation |

---

### 6.3 AI System Retirement

When an AI system is decommissioned:

1. AISC approves retirement decision and timeline
2. Clinical staff notified minimum 60 days before decommission
3. All patient data processed by the AI system accounted for — retention or deletion in accordance with Privacy Act 1988 obligations
4. Vendor data deletion confirmed in writing within 30 days of decommission
5. AI system register updated — retirement date, reason, and data disposition documented
6. Lessons learned review conducted by AISC

---

## 7. Third-Party AI Vendor Obligations

All AI vendors providing systems to NovaMed must comply with the following contractual requirements:

| Obligation | Standard |
|-----------|---------|
| Security certification | ISO 27001 or SOC 2 Type II — current, in-scope for AI platform |
| Breach notification | 24 hours from vendor awareness of any incident affecting NovaMed data |
| Model change notification | 30 days written notice for material model changes |
| Model card provision | Current model card maintained and provided to NovaMed on request |
| Bias testing disclosure | Annual bias testing results provided to NovaMed |
| Data sovereignty | Patient data not processed outside agreed jurisdiction without written consent |
| Audit rights | NovaMed right to commission annual security and AI governance review |
| Data deletion | Patient data deleted within 30 days of contract termination — confirmed in writing |

---

## 8. AI Incident Reporting

### Incident Classification

| Class | Description | Response Time | Escalation |
|-------|-------------|--------------|------------|
| **P1 — Critical** | Patient harm or near-miss attributable to AI recommendation | Immediate | CEO, CMO, AISC, Legal within 2 hours |
| **P2 — High** | Unexpected or harmful AI outputs; system failure during clinical use | 4 hours | CCIO, CMO, CIO within 4 hours |
| **P3 — Medium** | Performance degradation; bias threshold breach; vendor-side incident | 24 hours | CCIO, AISC at next scheduled meeting |
| **P4 — Low** | Minor output anomalies; user-reported concerns; logging issues | 5 business days | AI System Owner |

### Reporting Process

1. Clinician or staff member identifies AI incident or concern
2. Report submitted via RISKMAN (clinical incidents) or the IT Service Desk (technical incidents)
3. AI System Owner triages and classifies within defined response time
4. Escalation chain activated per classification
5. AI system suspension assessed — P1 incidents trigger immediate suspension pending review
6. Root cause analysis completed within 30 days of P1/P2 incidents
7. AISC reviews root cause and approves corrective action plan
8. Corrective action registered and tracked to closure

---

## 9. Privacy and Data Governance

### Patient Data Handling

- Patient health information processed by AI systems is classified as **sensitive information** under the Privacy Act 1988 and must be handled in accordance with Australian Privacy Principles (APPs) 3, 5, 6, 7, 11, and 12
- Patients must be informed — through updated privacy notice and consent process — that their health information may be processed by AI-based clinical tools
- Data minimisation principle applies — AI systems receive only the minimum patient data required for their defined function
- Patient data processed by AI systems is not to be used for model training, research, or any secondary purpose without explicit informed consent

### Data Retention and Deletion

- AI system inputs and outputs (recommendations) are retained for 7 years in accordance with healthcare records legislation
- Vendor-held patient data is subject to the same retention obligations
- On system retirement or vendor contract termination, vendor confirms deletion within 30 days

---

## 10. Policy Compliance and Review

### Non-Compliance

Breaches of this policy by NovaMed staff will be managed under NovaMed's Code of Conduct and disciplinary framework. Breaches by vendors will be managed under contractual remedies including termination for material breach.

### Policy Review Schedule

| Review Trigger | Action |
|---------------|--------|
| Annual scheduled review | CCIO leads review; AISC approves; CEO signs |
| Material regulatory change (TGA, Privacy Act, APRA) | Out-of-cycle review within 60 days |
| Significant AI incident | Post-incident review incorporated into policy update |
| New AI system deployment | Policy adequacy reviewed before deployment approval |

---

## 11. Related Documents

| Document | Reference |
|----------|-----------|
| AI Risk Register | NOVAMED-AI-RR-001 |
| Bias and Fairness Assessment | NOVAMED-AI-BIAS-002 |
| Privacy Impact Assessment — CDS Platform | NOVAMED-AI-PIA-004 |
| AI Incident Response Procedure | NOVAMED-AI-IRP-005 |
| ISO 42001 Gap Assessment | NOVAMED-AI-GAP-006 |
| Information Security Policy | NOVAMED-POL-ISMS-001 |
| Vendor Risk Management Policy | NOVAMED-POL-VRM-003 |

---

*This document is part of a sample GRC portfolio project. NovaMed Health is a fictional organisation. All content is created for professional skills demonstration.*
