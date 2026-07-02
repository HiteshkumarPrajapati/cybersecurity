# Vendor AI Risk Assessment — VeriGuard AI Platform

**Document ID:** FINSIGHT-AI-VAR-001
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** GRC Analyst / Chief Risk Officer
**Review Cycle:** Annually and prior to contract renewal
**Frameworks:** NIST AI RMF · ISO/IEC 42001:2023 · APRA CPS 234 · AS ISO 31000:2018

---

## Purpose

This assessment identifies, rates, and documents risk treatment plans for risks arising from FinSight Analytics' proposed procurement of the VeriGuard AI fraud detection platform. The assessment is structured in accordance with the NIST AI RMF (Govern / Map / Measure / Manage) and AS ISO 31000:2018 risk principles.

All risks are assessed from FinSight's perspective as the regulated entity and data controller — not the vendor's. Regulatory liability for customer data handling and AI-driven decisions affecting customers rests with FinSight, regardless of where in the supply chain the failure occurs.

---

## Risk Rating Methodology

### Likelihood Scale

| Score | Rating | Description |
|-------|--------|-------------|
| 5 | Almost Certain | Expected to occur given current controls |
| 4 | Likely | Will probably occur without intervention |
| 3 | Possible | May occur in some circumstances |
| 2 | Unlikely | Could occur but existing controls reduce probability |
| 1 | Rare | Only in exceptional circumstances |

### Impact Scale

| Score | Rating | Description |
|-------|--------|-------------|
| 5 | Critical | Regulatory action, major financial penalty, material customer harm, business disruption |
| 4 | Major | Significant regulatory finding, customer complaint escalation, reputational damage, data breach |
| 3 | Moderate | Compliance gap, operational disruption, minor customer impact, audit finding |
| 2 | Minor | Limited impact, recoverable quickly, no regulatory consequence |
| 1 | Insignificant | Negligible operational or compliance effect |

**Risk Score = Likelihood × Impact**

| Score | Rating | Required Action |
|-------|--------|----------------|
| 20–25 | 🔴 Critical | Halt procurement. Board escalation. Treatment mandatory before any contract execution. |
| 12–19 | 🔴 High | CRO and Board notification. Contractual remediation required before go-live. |
| 6–11 | 🟠 Medium | Senior management notification. Treatment plan in contract or within 90 days of go-live. |
| 1–5 | 🟡 Low | Accept with monitoring. Annual review. |

---

## Risk Register

### VAR-001 — AI Model Produces Incorrect Fraud Flags — Wrongful Customer Transaction Blocks

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-001 |
| **Category** | Model Accuracy / Customer Harm |
| **NIST AI RMF Function** | MEASURE / MANAGE |
| **Likelihood** | 4 — Likely |
| **Impact** | 4 — Major |
| **Inherent Risk Score** | 16 — 🔴 High |
| **Risk Owner** | Chief Operations Officer |

**Risk Description**
The VeriGuard AI model flags legitimate customer transactions as fraudulent (false positives). FinSight blocks the transaction. The customer is denied access to funds, suffers financial or reputational harm, and lodges a complaint with FinSight or escalates to AFCA (Australian Financial Complaints Authority). FinSight cannot explain the AI's decision because the model is a black box.

**Current State**
No false positive rate benchmarks have been provided by the vendor. No explainability capability is available in the current platform version.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Require vendor to provide documented false positive and false negative rate benchmarks from comparable financial services deployments before contract execution | GRC / Procurement | Pre-contract | 🔴 Critical |
| Define contractual SLA for false positive rate — maximum 0.5% of total transaction volume per month; breach triggers mandatory vendor remediation | Legal / GRC | Contract execution | 🔴 High |
| Require explainability layer — each fraud flag must include top contributing transaction factors in plain language | GRC / Legal | Contract execution | 🔴 High |
| Implement FinSight internal review step — all blocked transactions above AUD $500 reviewed by operations analyst before final block | COO | 30 days post-go-live | 🔴 High |
| Establish customer complaint monitoring — track AFCA referrals and disputed fraud flags monthly | Compliance | Ongoing | 🟠 Medium |

**Residual Risk Score:** 8 — 🟠 Medium
**Residual Risk Accepted By:** Chief Operations Officer
**Review Date:** Monthly (SLA monitoring); Annually (risk review)

---

### VAR-002 — AI Decision Cannot Be Explained to Customer or Regulator

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-002 |
| **Category** | Explainability / Regulatory |
| **NIST AI RMF Function** | GOVERN / MAP |
| **Likelihood** | 4 — Likely |
| **Impact** | 4 — Major |
| **Inherent Risk Score** | 16 — 🔴 High |
| **Risk Owner** | Chief Compliance Officer |

**Risk Description**
A customer disputes a fraud flag and requests an explanation. FinSight cannot provide one because the VeriGuard model is a proprietary black box. AFCA requires FinSight to demonstrate that its dispute resolution process is fair, transparent, and effective. ASIC's guidance on AI in financial services expects firms to be able to explain automated decisions. FinSight is unable to comply.

**Current State**
Vendor has not disclosed whether any explainability capability exists. Standard contract terms do not include explainability obligations.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Make explainability a non-negotiable contract requirement — vendor must provide human-readable explanation for each fraud flag (e.g. SHAP values translated to plain language) within 2 business days of request | Legal / GRC | Pre-contract | 🔴 Critical |
| If vendor cannot provide explainability — escalate to Board for deployment decision; consider alternative vendors | CRO / Board | Pre-contract | 🔴 Critical |
| Develop customer-facing dispute resolution procedure specific to AI fraud flags — plain language explanation of how decisions are made | Compliance / Legal | 60 days pre-go-live | 🔴 High |
| Assess AFCA and ASIC regulatory expectations for AI explainability in financial services — document current obligations | Compliance | 30 days | 🔴 High |

**Residual Risk Score:** 6 — 🟠 Medium
**Residual Risk Accepted By:** Chief Compliance Officer
**Review Date:** Quarterly

---

### VAR-003 — Customer Financial Data Processed Offshore Without Adequate Privacy Protections

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-003 |
| **Category** | Data Privacy / Regulatory |
| **NIST AI RMF Function** | GOVERN |
| **Likelihood** | 4 — Likely |
| **Impact** | 5 — Critical |
| **Inherent Risk Score** | 20 — 🔴 Critical |
| **Risk Owner** | Privacy Officer / Chief Compliance Officer |

**Risk Description**
VeriGuard processes FinSight customer financial data (transaction records, account history, device fingerprints) on servers in Singapore and Ireland. This constitutes cross-border disclosure of personal information under Australian Privacy Principle 8. FinSight has not conducted an APP 8 assessment, has no contractual privacy obligations on the vendor, and has not updated its privacy notice to disclose offshore processing to customers.

**Current State**
Offshore processing confirmed. APP 8 assessment not conducted. Privacy notice not updated. No Data Processing Agreement executed.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Conduct formal APP 8 cross-border disclosure assessment — assess adequacy of Singapore and Irish data protection regimes | Privacy Officer | Immediately — blocks contract execution | 🔴 Critical |
| Execute Data Processing Agreement (DPA) with vendor — include APP obligations, data minimisation, purpose limitation, retention, deletion, and breach notification | Privacy Officer / Legal | Pre-contract | 🔴 Critical |
| Update FinSight Privacy Policy and customer disclosure to reference offshore processing by AI fraud detection vendor | Privacy Officer | Before go-live | 🔴 Critical |
| Require vendor to confirm data is not transferred to additional jurisdictions without FinSight written consent | Legal | Contract execution | 🔴 High |
| Assess Singapore PDPA and Irish GDPR adequacy for APP 8 equivalence determination | Privacy Officer / Legal | 30 days | 🔴 High |

**Residual Risk Score:** 6 — 🟠 Medium
**Residual Risk Accepted By:** Chief Compliance Officer / Privacy Officer
**Review Date:** Annually; on any change to vendor data processing locations

---

### VAR-004 — Vendor Data Breach Exposing FinSight Customer Records

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-004 |
| **Category** | Third-Party Security |
| **NIST AI RMF Function** | GOVERN / MANAGE |
| **Likelihood** | 2 — Unlikely |
| **Impact** | 5 — Critical |
| **Inherent Risk Score** | 10 — 🟠 Medium |
| **Risk Owner** | Chief Information Security Officer |

**Risk Description**
VeriGuard AI suffers a data breach or insider incident exposing FinSight customer financial data. As the data controller, FinSight holds primary regulatory liability under the Privacy Act 1988 NDB scheme — including notification obligations to the OAIC and affected customers — regardless of where the breach occurred. A breach of this nature at a regulated financial services firm carries significant APRA and ASIC scrutiny.

**Current State**
Vendor holds claimed ISO 27001 certification (scope not verified). No SOC 2 Type II report available. Breach notification SLA not included in contract.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Obtain and verify current ISO 27001 certificate including scope documentation — confirm AI platform is within scope | CISO / Procurement | Pre-contract | 🔴 High |
| Require SOC 2 Type II report or equivalent — if unavailable, commission FinSight-funded independent security assessment of vendor platform | CISO | Pre-contract | 🔴 High |
| Contractual 24-hour breach notification obligation — vendor must notify FinSight within 24 hours of becoming aware of any incident affecting FinSight data | Legal / GRC | Contract execution | 🔴 High |
| Annual penetration test results — vendor must share results of annual third-party penetration test for AI platform with FinSight | CISO | Contract execution | 🟠 Medium |
| FinSight NDB assessment procedure updated to include vendor-side breach scenarios | Privacy Officer / Compliance | 45 days | 🟠 Medium |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** CISO
**Review Date:** Annually (vendor review); Quarterly (risk register)

---

### VAR-005 — Vendor Uses FinSight Customer Data for Model Training

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-005 |
| **Category** | Data Governance / Privacy |
| **NIST AI RMF Function** | GOVERN / MAP |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major |
| **Inherent Risk Score** | 12 — 🔴 High |
| **Risk Owner** | Privacy Officer |

**Risk Description**
VeriGuard's standard terms permit the vendor to use client data to improve, retrain, and benchmark its AI model. Under APP 6, FinSight may only use customer personal information for the primary purpose of collection — fraud detection for FinSight customers — or a directly related secondary purpose. Model training for the vendor's commercial benefit is neither. This also creates a risk that FinSight customer data patterns could be embedded in a model shared with VeriGuard's other clients.

**Current State**
VeriGuard standard terms reviewed — Section 8.3 permits aggregated data use for "platform improvement." Not negotiated out of proposed contract.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Remove Section 8.3 from contract — or replace with explicit prohibition: vendor may not use FinSight customer data for model training, benchmarking, or any purpose beyond delivering contracted fraud detection service | Legal / GRC | Pre-contract | 🔴 Critical |
| Add data isolation confirmation — vendor must confirm FinSight customer data is not commingled with other client data in the AI training pipeline | Legal / GRC | Pre-contract | 🔴 High |
| Include data audit right — FinSight may request evidence of data isolation controls annually | Legal | Contract execution | 🟠 Medium |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** Privacy Officer
**Review Date:** Annually

---

### VAR-006 — AI Model Drift Reduces Fraud Detection Effectiveness Undetected

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-006 |
| **Category** | Model Performance / Operational |
| **NIST AI RMF Function** | MEASURE / MANAGE |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major |
| **Inherent Risk Score** | 12 — 🔴 High |
| **Risk Owner** | Chief Operations Officer / CISO |

**Risk Description**
The VeriGuard model's fraud detection accuracy degrades over time as fraud patterns evolve and the model's training data becomes stale — without any alert mechanism to FinSight. FinSight continues to operate the platform believing it is functioning as contracted, while actual fraud losses increase undetected.

**Current State**
No model performance reporting obligation in proposed contract. No drift monitoring or notification SLA defined.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Define model performance SLAs in contract — minimum detection rate (e.g. >92%), maximum false positive rate (e.g. <0.5%); breach triggers mandatory vendor review within 10 business days | Legal / GRC | Contract execution | 🔴 High |
| Require quarterly model performance reports — detection rate, false positive rate, model version, last retrain date | Legal / GRC | Contract execution | 🔴 High |
| Require vendor notification within 5 business days of any model update, retrain, or detected performance degradation exceeding defined thresholds | Legal / GRC | Contract execution | 🔴 High |
| FinSight internal KPI monitoring — track fraud loss rate and blocked transaction volumes monthly as independent verification of model effectiveness | COO / Finance | 30 days post-go-live | 🟠 Medium |

**Residual Risk Score:** 6 — 🟠 Medium
**Residual Risk Accepted By:** Chief Operations Officer
**Review Date:** Monthly (performance monitoring); Quarterly (risk review)

---

### VAR-007 — Algorithmic Bias — Disproportionate Fraud Flags on Specific Customer Demographics

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-007 |
| **Category** | Bias / Fairness / Regulatory |
| **NIST AI RMF Function** | MAP / MEASURE |
| **Likelihood** | 3 — Possible |
| **Impact** | 4 — Major |
| **Inherent Risk Score** | 12 — 🔴 High |
| **Risk Owner** | Chief Compliance Officer |

**Risk Description**
The VeriGuard fraud detection model disproportionately flags transactions from customers in specific demographic groups — including CALD customers, customers with non-standard transaction patterns, or customers in lower socioeconomic brackets — resulting in higher rates of wrongful transaction blocks for those groups. This creates discriminatory outcomes, AFCA complaint exposure, and reputational risk. ASIC's guidance on fairness in financial services AI expects firms to identify and address bias in automated decision systems.

**Current State**
No bias testing documentation provided. No model card available. Vendor has not confirmed whether demographic stratification analysis has been conducted.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Require vendor to provide bias testing results stratified by customer demographic — age, gender, cultural background, transaction pattern type | GRC / Compliance | Pre-contract | 🔴 High |
| Define bias threshold in contract — if any demographic group shows >10% higher fraud flag rate than population baseline, vendor must remediate within 60 days | Legal / Compliance | Contract execution | 🔴 High |
| FinSight internal bias monitoring — stratify fraud flag and blocked transaction rates by available demographic indicators quarterly | Compliance / Data Analytics | 60 days post-go-live | 🟠 Medium |
| Assess ASIC and AFCA guidance on AI fairness obligations in financial services — document current compliance position | Compliance | 30 days | 🟠 Medium |

**Residual Risk Score:** 8 — 🟠 Medium
**Residual Risk Accepted By:** Chief Compliance Officer
**Review Date:** Quarterly

---

### VAR-008 — No Vendor Business Continuity — Fraud Detection Unavailable During Critical Period

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-008 |
| **Category** | Vendor Continuity / Operational Resilience |
| **NIST AI RMF Function** | GOVERN / MANAGE |
| **Likelihood** | 2 — Unlikely |
| **Impact** | 4 — Major |
| **Inherent Risk Score** | 8 — 🟠 Medium |
| **Risk Owner** | Chief Operations Officer |

**Risk Description**
VeriGuard experiences an extended platform outage, undergoes acquisition or insolvency, or exits the Australian market — leaving FinSight without fraud detection capability. Under APRA CPS 230 (Operational Resilience), FinSight must ensure continuity of critical operations. Fraud detection for an investment analytics and portfolio management firm is a critical function.

**Current State**
Proposed contract includes standard 99.5% uptime SLA. No business continuity documentation provided. No exit management provisions in contract.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Require vendor to provide current Business Continuity Plan and Disaster Recovery documentation — including RTO/RPO for the AI platform | CISO / Procurement | Pre-contract | 🔴 High |
| Define contractual RTO in contract — maximum 4 hours for platform restoration during business hours | Legal | Contract execution | 🔴 High |
| Exit management provisions — vendor must provide complete data export in agreed format within 30 days of contract termination; confirm data deletion within 60 days | Legal / Privacy Officer | Contract execution | 🔴 High |
| FinSight contingency plan — define interim fraud monitoring procedure using rules-based controls if AI platform is unavailable for >4 hours | COO / Operations | 60 days post-contract | 🟠 Medium |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** Chief Operations Officer
**Review Date:** Annually

---

### VAR-009 — Material Model Change Without FinSight Notification

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-009 |
| **Category** | Governance / Change Management |
| **NIST AI RMF Function** | GOVERN / MANAGE |
| **Likelihood** | 4 — Likely |
| **Impact** | 3 — Moderate |
| **Inherent Risk Score** | 12 — 🔴 High |
| **Risk Owner** | GRC Analyst / CISO |

**Risk Description**
VeriGuard updates the AI model — including retraining on new data, algorithm changes, or feature modifications — without notifying FinSight. The model's behaviour changes. Performance degrades or introduces new bias. FinSight has no visibility, no ability to reassess, and no contractual recourse.

**Current State**
Standard contract terms give vendor the right to update the platform without client notification. No change management SLA defined.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Require 30-day advance written notice for any material model change — defined as any change to model architecture, training data, feature set, or output format | Legal / GRC | Contract execution | 🔴 High |
| Material changes require FinSight sign-off before deployment — include right to reject material changes that affect contractual performance SLAs | Legal | Contract execution | 🔴 High |
| Vendor to provide updated model card after any material change | Legal / GRC | Contract execution | 🟠 Medium |
| FinSight right to independent re-validation testing following material model change | GRC | Contract execution | 🟠 Medium |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** CISO
**Review Date:** On each model change; Quarterly otherwise

---

### VAR-010 — No Audit Right — FinSight Cannot Verify Vendor Security Controls

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-010 |
| **Category** | Governance / Audit |
| **NIST AI RMF Function** | GOVERN |
| **Likelihood** | 4 — Likely |
| **Impact** | 3 — Moderate |
| **Inherent Risk Score** | 12 — 🔴 High |
| **Risk Owner** | GRC Analyst / CISO |

**Risk Description**
The proposed contract does not include an audit right. FinSight cannot independently verify VeriGuard's security controls, AI governance practices, or compliance with contractual obligations. APRA CPS 234 Paragraph 36 requires FinSight to test information security controls at least annually — for controls operated by third parties, this requires audit access or equivalent assurance.

**Current State**
No audit right in proposed contract. Vendor ISO 27001 certification is claimed but scope has not been verified.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Include annual audit right in contract — FinSight may commission an independent security and AI governance review of VeriGuard's platform; vendor must cooperate fully | Legal / GRC | Contract execution | 🔴 High |
| In lieu of on-site audit — vendor must provide annual independent penetration test results, ISO 27001 surveillance audit reports, and AI governance attestation | CISO / GRC | Contract execution | 🔴 High |
| FinSight reserves right to conduct on-site audit with 30-day notice following a security incident, material change, or regulatory request | Legal | Contract execution | 🟠 Medium |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** GRC Analyst / CISO
**Review Date:** Annually

---

### VAR-011 — Regulatory Change Affects Vendor's Ability to Operate in Australia

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-011 |
| **Category** | Regulatory / Compliance |
| **NIST AI RMF Function** | GOVERN |
| **Likelihood** | 2 — Unlikely |
| **Impact** | 4 — Major |
| **Inherent Risk Score** | 8 — 🟠 Medium |
| **Risk Owner** | Chief Compliance Officer |

**Risk Description**
Regulatory changes to AI use in financial services — from ASIC, APRA, Treasury, or international AI regulation affecting the vendor's jurisdiction — require changes to the VeriGuard platform or FinSight's use of it that the vendor cannot meet within required timeframes. FinSight's compliance position is compromised through no direct action of its own.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Regulatory change clause in contract — vendor must notify FinSight within 10 business days of any regulatory change in their jurisdiction that may affect their ability to meet contract obligations | Legal | Contract execution | 🟠 Medium |
| FinSight right to terminate for regulatory non-compliance without penalty — if vendor cannot meet FinSight's regulatory obligations within 90 days of notification | Legal | Contract execution | 🟠 Medium |
| FinSight Compliance team monitors AI regulation developments — ASIC, APRA, Treasury consultations reviewed quarterly | Compliance | Ongoing | 🟠 Medium |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** Chief Compliance Officer
**Review Date:** Quarterly

---

### VAR-012 — Concentration Risk — Single Vendor for Critical Fraud Detection Function

| Field | Detail |
|-------|--------|
| **Risk ID** | VAR-012 |
| **Category** | Concentration Risk / Operational Resilience |
| **NIST AI RMF Function** | GOVERN |
| **Likelihood** | 2 — Unlikely |
| **Impact** | 4 — Major |
| **Inherent Risk Score** | 8 — 🟠 Medium |
| **Risk Owner** | Chief Risk Officer |

**Risk Description**
FinSight would be entirely dependent on a single offshore AI vendor for fraud detection — a function material to the protection of customer assets. APRA CPS 230 addresses concentration risk in critical operational arrangements. A single point of failure in fraud detection exposes FinSight to both operational risk and regulatory scrutiny.

**Treatment Plan**

| Action | Owner | Timeline | Priority |
|--------|-------|----------|----------|
| Document concentration risk assessment and present to Board before contract execution | CRO | Pre-contract | 🟠 Medium |
| Define interim fraud detection controls — rules-based transaction monitoring using existing capabilities | COO / Operations | 60 days post-contract | 🟠 Medium |
| 3-year contract term with annual break clause — preserves FinSight's ability to exit if vendor performance or market alternatives change materially | Legal | Contract execution | 🟠 Medium |
| Annual vendor market review — assess alternative fraud detection vendors at each contract anniversary | GRC / Procurement | Annually | 🟡 Low |

**Residual Risk Score:** 4 — 🟡 Low
**Residual Risk Accepted By:** Chief Risk Officer
**Review Date:** Annually

---

## Risk Summary Dashboard

| Risk ID | Description | Inherent Score | Rating | Residual Score | Rating |
|---------|-------------|:-:|:-:|:-:|:-:|
| VAR-001 | False positives — wrongful customer blocks | 16 | 🔴 High | 8 | 🟠 Medium |
| VAR-002 | No explainability for customer or regulator | 16 | 🔴 High | 6 | 🟠 Medium |
| VAR-003 | Offshore data processing — APP 8 gap | 20 | 🔴 Critical | 6 | 🟠 Medium |
| VAR-004 | Vendor data breach — customer records | 10 | 🟠 Medium | 4 | 🟡 Low |
| VAR-005 | Vendor uses data for model training | 12 | 🔴 High | 4 | 🟡 Low |
| VAR-006 | Model drift — undetected performance degradation | 12 | 🔴 High | 6 | 🟠 Medium |
| VAR-007 | Algorithmic bias — demographic fraud flagging | 12 | 🔴 High | 8 | 🟠 Medium |
| VAR-008 | Vendor outage — no fraud detection capability | 8 | 🟠 Medium | 4 | 🟡 Low |
| VAR-009 | Material model change without notification | 12 | 🔴 High | 4 | 🟡 Low |
| VAR-010 | No audit right — cannot verify vendor controls | 12 | 🔴 High | 4 | 🟡 Low |
| VAR-011 | Regulatory change affects vendor compliance | 8 | 🟠 Medium | 4 | 🟡 Low |
| VAR-012 | Concentration risk — single critical vendor | 8 | 🟠 Medium | 4 | 🟡 Low |

**Pre-treatment:** 1 Critical, 7 High, 4 Medium
**Post-treatment target:** 0 Critical, 0 High, 5 Medium, 7 Low

**Procurement recommendation:** Do not proceed until VAR-001, VAR-002, and VAR-003 treatments are confirmed in contract. All Critical and High items must have contractual protections before execution.

---

*This document is part of a sample GRC portfolio project. All organisations and scenarios are fictional.*
