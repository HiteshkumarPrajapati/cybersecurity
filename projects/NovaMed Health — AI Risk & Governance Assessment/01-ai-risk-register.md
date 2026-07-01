# AI Risk Register — NovaMed Health CDS Platform

**Document ID:** NOVAMED-AI-RR-001
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** AI System Owner / Chief Clinical Information Officer (CCIO)
**Review Cycle:** Quarterly
**Last Reviewed:** 2025

---

## Purpose

This risk register identifies, rates, and documents treatment plans for risks arising from NovaMed Health's deployment of an AI-assisted Clinical Decision Support (CDS) tool. The register is structured in accordance with the NIST AI Risk Management Framework (AI RMF) and AS ISO 31000:2018 risk management principles.

Risk ratings are reviewed quarterly and updated following any material change to the AI system, new incident, regulatory guidance update, or audit finding.

---

## Risk Rating Methodology

### Likelihood Scale

| Score | Rating | Description |
|-------|--------|-------------|
| 5 | Almost Certain | Expected to occur in most circumstances |
| 4 | Likely | Will probably occur in most circumstances |
| 3 | Possible | Might occur in some circumstances |
| 2 | Unlikely | Could occur in some circumstances |
| 1 | Rare | May occur only in exceptional circumstances |

### Consequence Scale

| Score | Rating | Description |
|-------|--------|-------------|
| 5 | Critical | Patient harm, death, systemic clinical failure, regulatory shutdown |
| 4 | Major | Serious patient harm, significant regulatory penalty, material data breach |
| 3 | Moderate | Clinical disruption, moderate compliance breach, reputational damage |
| 2 | Minor | Limited clinical impact, recoverable compliance gap, minor incident |
| 1 | Insignificant | Negligible impact, no clinical effect |

### Risk Score = Likelihood × Consequence

| Score Range | Rating | Action Required |
|-------------|--------|----------------|
| 20–25 | 🔴 Critical | Immediate escalation to Board. Treatment mandatory before deployment. |
| 12–19 | 🔴 High | CEO and AISC Committee notification. Treatment plan within 30 days. |
| 6–11 | 🟠 Medium | Management notification. Treatment plan within 90 days. |
| 1–5 | 🟡 Low | Monitor. Review at next quarterly cycle. |

---

## Risk Register

### AIR-001 — Incorrect Diagnosis Recommendation Acted Upon by Clinician

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-001 |
| **Category** | Patient Safety |
| **NIST AI RMF Function** | MANAGE |
| **Likelihood** | 3 — Possible |
| **Consequence** | 5 — Critical |
| **Inherent Risk Score** | 15 — 🔴 High |
| **Risk Owner** | Chief Medical Officer |

**Risk Description**
The AI CDS model generates an incorrect or misleading ranked diagnosis recommendation. A clinician, under time pressure or over-relying on the system, acts on the recommendation without independent clinical assessment, resulting in delayed or incorrect treatment and potential patient harm.

**Existing Controls**
- None formally documented at engagement commencement

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Implement mandatory human clinical override requirement — all AI outputs labelled "Decision Support Only, Not a Diagnosis" in system UI | CIO / Clinical Governance | 30 days | 🔴 Immediate |
| Establish clinical governance review of any adverse event linked to AI recommendation | CMO | 30 days | 🔴 Immediate |
| Define clinician escalation pathway when AI output conflicts with clinical judgment | CMO | 45 days | 🔴 High |
| Conduct pre-deployment clinical validation study — model accuracy vs clinician assessment across 500+ test cases | CCIO | Before go-live | 🔴 High |
| Implement real-time confidence scoring display on all CDS outputs — low-confidence flags require mandatory second opinion | Vendor / CIO | 60 days | 🟠 Medium |

**Residual Risk Score:** 8 — 🟠 Medium (post-treatment)
**Residual Risk Accepted By:** Chief Medical Officer
**Review Date:** Quarterly

---

### AIR-002 — Algorithmic Bias Producing Unequal Clinical Outcomes

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-002 |
| **Category** | Bias / Fairness / Equity |
| **NIST AI RMF Function** | MAP / MEASURE |
| **Likelihood** | 3 — Possible |
| **Consequence** | 5 — Critical |
| **Inherent Risk Score** | 15 — 🔴 High |
| **Risk Owner** | Chief Clinical Information Officer |

**Risk Description**
The AI model produces systematically lower-quality or less accurate diagnosis recommendations for specific patient demographic groups — including age cohorts, gender, ethnicity, or patients with comorbidities — due to imbalanced or non-representative training data, resulting in inequitable care outcomes.

**Existing Controls**
- None documented

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Require vendor to provide model card documenting training dataset composition, demographic representation, and known performance limitations before deployment | CCIO | 30 days | 🔴 Immediate |
| Commission independent pre-deployment bias audit across patient demographic cohorts — age, gender, ethnicity, socioeconomic classification | Clinical Governance Committee | Before go-live | 🔴 High |
| Define bias threshold policy — any demographic group with >10% performance differential vs baseline triggers mandatory remediation before go-live | CCIO / CMO | 45 days | 🔴 High |
| Implement quarterly post-deployment bias monitoring — stratify recommendation acceptance rates and clinical outcomes by demographic | Quality and Safety Team | Ongoing | 🟠 Medium |
| Integrate bias testing into AI system change management process — any model update requires re-validation | CCIO | 60 days | 🟠 Medium |

**Residual Risk Score:** 9 — 🟠 Medium
**Residual Risk Accepted By:** Chief Clinical Information Officer
**Review Date:** Quarterly

---

### AIR-003 — Sensitive Health Information Processed Without Adequate Privacy Controls

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-003 |
| **Category** | Data Privacy / Regulatory |
| **NIST AI RMF Function** | GOVERN / MAP |
| **Likelihood** | 3 — Possible |
| **Consequence** | 4 — Major |
| **Inherent Risk Score** | 12 — 🔴 High |
| **Risk Owner** | Privacy Officer |

**Risk Description**
Patient health information — classified as sensitive information under the Privacy Act 1988 — is processed by the AI model without adequate consent disclosure, appropriate access controls, or data minimisation controls, creating exposure under Australian Privacy Principles (APPs) 3, 5, 6, and 11, and potential notification obligations under the Notifiable Data Breaches (NDB) scheme.

**Existing Controls**
- Standard patient consent form in place (not updated to disclose AI processing)
- Basic access controls on EHR system

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Update patient consent form and privacy notice to explicitly disclose AI-based processing of health information | Privacy Officer / Legal | 30 days | 🔴 Immediate |
| Conduct data minimisation review — define minimum dataset required for AI model input; remove all fields not required for CDS function | CCIO / Privacy Officer | 45 days | 🔴 High |
| Implement role-based access controls on AI system — clinical staff access restricted to patients under their direct care | CIO | 45 days | 🔴 High |
| Encrypt all patient data in transit (TLS 1.3) and at rest (AES-256) between EHR and AI system | CIO | 30 days | 🔴 High |
| Assess vendor data handling agreement — confirm patient data not used for model retraining without explicit consent | Privacy Officer / Legal | 30 days | 🔴 Immediate |

**Residual Risk Score:** 6 — 🟠 Medium
**Residual Risk Accepted By:** Privacy Officer
**Review Date:** Quarterly

---

### AIR-004 — AI System Classified as SaMD Without TGA Registration

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-004 |
| **Category** | Regulatory Compliance |
| **NIST AI RMF Function** | GOVERN |
| **Likelihood** | 3 — Possible |
| **Consequence** | 5 — Critical |
| **Inherent Risk Score** | 15 — 🔴 High |
| **Risk Owner** | Chief Executive Officer / Legal Counsel |

**Risk Description**
The AI CDS tool may meet the TGA's definition of Software as a Medical Device (SaMD) — software intended to influence clinical decisions for diagnosis or treatment. Operating an unregistered SaMD in Australia constitutes a breach of the Therapeutic Goods Act 1989 and carries significant regulatory, financial, and reputational consequences including product recall and prohibition orders.

**Existing Controls**
- No TGA classification assessment conducted

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Commission independent TGA SaMD classification assessment against IMDRF guidance | Legal Counsel / CCIO | 30 days | 🔴 Immediate |
| If classified as SaMD — engage TGA regulatory pathway specialist and halt deployment until registration obtained or exclusion confirmed | CEO / Legal | Immediately post-assessment | 🔴 Critical |
| Document and retain classification assessment rationale regardless of outcome | Legal Counsel | 45 days | 🔴 High |
| Establish ongoing regulatory monitoring process for TGA AI/SaMD guidance updates | Legal / CCIO | 60 days | 🟠 Medium |

**Residual Risk Score:** 5 — 🟡 Low (if SaMD assessment confirms exclusion)
**Residual Risk Accepted By:** Chief Executive Officer
**Review Date:** After TGA assessment; then annually

---

### AIR-005 — No Accountability Owner for AI System Decisions

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-005 |
| **Category** | Governance / Accountability |
| **NIST AI RMF Function** | GOVERN |
| **Likelihood** | 4 — Likely |
| **Consequence** | 4 — Major |
| **Inherent Risk Score** | 16 — 🔴 High |
| **Risk Owner** | Chief Executive Officer |

**Risk Description**
No individual or governance body holds defined accountability for the AI system's performance, safety, clinical outcomes, or lifecycle management. In the event of an adverse clinical outcome or audit, there is no clear chain of accountability — creating regulatory, legal, and reputational exposure for NovaMed.

**Existing Controls**
- None

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Appoint AI System Owner (CCIO recommended) with documented accountability for model performance, safety monitoring, incident escalation, and lifecycle management | CEO | 14 days | 🔴 Immediate |
| Establish AI Safety and Compliance Committee (AISC) — CMO, CIO, Privacy Officer, Clinical Governance Lead, Legal Counsel | CEO | 30 days | 🔴 High |
| Define and publish AI governance policy — roles, responsibilities, escalation paths, decision authority | CCIO / Legal | 45 days | 🔴 High |
| Include AI accountability in board risk reporting — quarterly AI risk dashboard presented to Board | AISC | 60 days | 🟠 Medium |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** Chief Executive Officer
**Review Date:** Quarterly

---

### AIR-006 — Model Drift Degrades Recommendation Quality Undetected

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-006 |
| **Category** | Operational / Performance |
| **NIST AI RMF Function** | MEASURE / MANAGE |
| **Likelihood** | 3 — Possible |
| **Consequence** | 4 — Major |
| **Inherent Risk Score** | 12 — 🔴 High |
| **Risk Owner** | CCIO / AI System Owner |

**Risk Description**
The AI model's recommendation quality degrades over time due to changes in patient population, disease patterns, clinical practice, or data distribution — without any alert or detection mechanism in place. Clinicians continue to rely on recommendations that are becoming progressively less reliable.

**Existing Controls**
- None

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Define model performance KPIs: recommendation accuracy vs clinical outcome, acceptance rate by specialty, confidence score distribution | CCIO | 30 days | 🔴 High |
| Implement automated model performance monitoring dashboard — monthly reports to AI System Owner | CIO / Vendor | 45 days | 🔴 High |
| Define drift thresholds — >5% degradation in accuracy vs baseline triggers mandatory vendor review and potential suspension | CCIO | 30 days | 🔴 High |
| Require vendor notification within 5 business days of any model update, retraining event, or detected performance degradation | CCIO / Legal (contract) | 45 days | 🟠 Medium |

**Residual Risk Score:** 6 — 🟠 Medium
**Residual Risk Accepted By:** CCIO
**Review Date:** Monthly performance review; quarterly risk review

---

### AIR-007 — Clinician Over-Reliance Reduces Independent Clinical Judgment

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-007 |
| **Category** | Human Factors |
| **NIST AI RMF Function** | MANAGE |
| **Likelihood** | 4 — Likely |
| **Consequence** | 4 — Major |
| **Inherent Risk Score** | 16 — 🔴 High |
| **Risk Owner** | Chief Medical Officer |

**Risk Description**
Clinicians progressively defer to AI recommendations without applying independent clinical judgment — a phenomenon known as automation bias. Over time, clinical skills atrophy and the organisation becomes structurally dependent on a system whose reliability has not been established at that level of clinical trust.

**Existing Controls**
- None

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Mandatory clinical training program before access provisioned — includes AI limitations, automation bias risks, and override obligation | CMO / HR | Before go-live | 🔴 High |
| Design UI to reinforce advisory-only framing — recommendation displayed after clinician initial assessment, not before | CIO / Vendor | Before go-live | 🔴 High |
| Implement override logging — all clinician overrides of AI recommendations are recorded and reviewed monthly | CCIO | 45 days | 🟠 Medium |
| Annual simulation exercise — clinicians assessed on independent diagnosis capability without AI assistance | CMO | Annually | 🟠 Medium |

**Residual Risk Score:** 8 — 🟠 Medium
**Residual Risk Accepted By:** Chief Medical Officer
**Review Date:** Quarterly

---

### AIR-008 — Third-Party Vendor Data Breach Exposing Patient Records

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-008 |
| **Category** | Third-Party / Supply Chain |
| **NIST AI RMF Function** | GOVERN / MANAGE |
| **Likelihood** | 2 — Unlikely |
| **Consequence** | 5 — Critical |
| **Inherent Risk Score** | 10 — 🟠 Medium |
| **Risk Owner** | CIO / Privacy Officer |

**Risk Description**
The AI platform vendor suffers a data breach or insider incident that exposes NovaMed patient health records processed through the CDS tool. As the data controller, NovaMed holds primary regulatory liability under the Privacy Act 1988 and Notifiable Data Breaches scheme — regardless of where the breach occurred.

**Existing Controls**
- Vendor selected through procurement process (security assessment not formally documented)

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Require vendor to provide current ISO 27001 certification or SOC 2 Type II report — scope must include AI platform | CIO / Procurement | 30 days | 🔴 High |
| Execute Data Processing Agreement (DPA) with vendor — documented obligations for data handling, access controls, breach notification (24-hour SLA), and deletion | Privacy Officer / Legal | 30 days | 🔴 High |
| Annual vendor security review — include penetration test results, access control audit, incident log review | CIO | Annually | 🟠 Medium |
| Confirm patient data not transferred offshore without APP 8 cross-border disclosure assessment | Privacy Officer | 30 days | 🔴 High |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** CIO / Privacy Officer
**Review Date:** Annually (vendor review) / Quarterly (risk register)

---

### AIR-009 — No AI-Specific Incident Response Capability

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-009 |
| **Category** | Incident Response |
| **NIST AI RMF Function** | MANAGE |
| **Likelihood** | 4 — Likely |
| **Consequence** | 4 — Major |
| **Inherent Risk Score** | 16 — 🔴 High |
| **Risk Owner** | CCIO / CIO |

**Risk Description**
NovaMed has no documented process for responding to AI system failures, unexpected or harmful outputs, model suspension events, or adverse clinical events attributable to AI recommendations. In an incident, the absence of a defined response process extends harm, delays remediation, and creates regulatory and legal exposure.

**Existing Controls**
- General clinical incident process in place (not designed for AI system failures)

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Develop AI-specific incident response procedure covering: unexpected outputs, model suspension, clinical adverse events, vendor-side failures, and data breaches linked to AI system | CCIO / CIO | 45 days | 🔴 High |
| Define AI incident severity classification — P1 (patient harm), P2 (clinical disruption), P3 (performance degradation), P4 (operational) | CCIO | 30 days | 🔴 High |
| Integrate AI incident response into existing clinical governance and incident reporting frameworks (RISKMAN or equivalent) | Clinical Governance | 60 days | 🟠 Medium |
| Conduct tabletop exercise simulating AI system failure mid-clinical shift | CCIO / CMO | 90 days | 🟠 Medium |

**Residual Risk Score:** 6 — 🟠 Medium
**Residual Risk Accepted By:** CCIO
**Review Date:** Quarterly; after each incident

---

### AIR-010 — Explainability Gap — Clinicians Cannot Interrogate AI Recommendations

| Field | Detail |
|-------|--------|
| **Risk ID** | AIR-010 |
| **Category** | Transparency / Explainability |
| **NIST AI RMF Function** | MAP / MEASURE |
| **Likelihood** | 4 — Likely |
| **Consequence** | 3 — Moderate |
| **Inherent Risk Score** | 12 — 🔴 High |
| **Risk Owner** | CCIO |

**Risk Description**
The AI model operates as a black box — clinicians receive a ranked diagnosis recommendation without any explanation of which patient data, symptoms, or clinical indicators drove the output. This prevents critical evaluation of recommendations, undermines clinical accountability, and creates medico-legal risk when recommendations are challenged.

**Existing Controls**
- None

**Treatment Plan**
| Action | Owner | Target Date | Priority |
|--------|-------|-------------|----------|
| Require vendor to implement explainability layer — each recommendation accompanied by top contributing clinical factors (e.g. SHAP values translated into plain clinical language) | CCIO / Vendor | Before go-live | 🔴 High |
| If vendor cannot provide explainability — reconsider deployment of black-box model in clinical decision context | CCIO / CMO / CEO | Assessment: 30 days | 🔴 Critical |
| Document explainability capability in vendor contract — measurable requirement, not best-efforts | Legal / CCIO | 45 days | 🔴 High |
| Include explainability in clinician training — how to read and critically evaluate contributing factors | CMO / HR | Before go-live | 🟠 Medium |

**Residual Risk Score:** 6 — 🟠 Medium
**Residual Risk Accepted By:** CCIO
**Review Date:** Quarterly

---

## Risk Summary Dashboard

| Risk ID | Risk | Category | Inherent Score | Rating | Residual Score | Rating |
|---------|------|----------|:-:|:-:|:-:|:-:|
| AIR-001 | Incorrect diagnosis recommendation acted upon | Patient Safety | 15 | 🔴 High | 8 | 🟠 Medium |
| AIR-002 | Algorithmic bias — unequal clinical outcomes | Bias / Fairness | 15 | 🔴 High | 9 | 🟠 Medium |
| AIR-003 | Health data processed without privacy controls | Data Privacy | 12 | 🔴 High | 6 | 🟠 Medium |
| AIR-004 | SaMD deployed without TGA registration | Regulatory | 15 | 🔴 High | 5 | 🟡 Low |
| AIR-005 | No accountability owner for AI decisions | Governance | 16 | 🔴 High | 4 | 🟡 Low |
| AIR-006 | Model drift degrades recommendation quality | Operational | 12 | 🔴 High | 6 | 🟠 Medium |
| AIR-007 | Clinician over-reliance / automation bias | Human Factors | 16 | 🔴 High | 8 | 🟠 Medium |
| AIR-008 | Vendor data breach exposing patient records | Third-Party | 10 | 🟠 Medium | 4 | 🟡 Low |
| AIR-009 | No AI-specific incident response capability | Incident Response | 16 | 🔴 High | 6 | 🟠 Medium |
| AIR-010 | Black-box model — no explainability for clinicians | Transparency | 12 | 🔴 High | 6 | 🟠 Medium |

**Pre-treatment:** 9 High, 1 Medium
**Post-treatment target:** 0 High, 7 Medium, 3 Low

---

## Tools Used in This Assessment

| Tool / Resource | Purpose |
|----------------|---------|
| NIST AI RMF Playbook | Risk categorisation and treatment mapping |
| Microsoft Purview AI Hub | AI data governance and compliance monitoring |
| IBM OpenPages | GRC risk register management |
| RISKMAN | Clinical incident and risk management platform |
| OneTrust | Privacy impact assessment and consent management |
| Vanta | Compliance monitoring and vendor assessment |
| OAIC guidance — Privacy Act 1988 | APP obligations for health information |
| TGA SaMD guidance — IMDRF framework | Software as a Medical Device classification |
| ISO/IEC 42001:2023 | AI management system gap assessment |

---

*This document is part of a sample GRC portfolio project. NovaMed Health is a fictional organisation. All scenarios, risks, and figures are created for professional skills demonstration purposes only.*
