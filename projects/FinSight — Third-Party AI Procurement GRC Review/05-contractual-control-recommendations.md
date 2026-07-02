# Contractual Control Recommendations — VeriGuard AI Platform

**Document ID:** FINSIGHT-AI-CCR-005
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** GRC Analyst / Legal Counsel
**Purpose:** Contract negotiation brief — recommended provisions for FinSight–VeriGuard vendor agreement
**Framework references:** APRA CPS 234 · Privacy Act 1988 (AU) · ISO/IEC 42001:2023 · NIST AI RMF

---

## Purpose

This document provides GRC-recommended contract provisions for the FinSight Analytics–VeriGuard AI vendor agreement. Each recommendation is mapped to the risk or regulatory requirement it addresses, with the recommended contractual language and rationale.

These recommendations are intended to be provided to Legal Counsel as the GRC team's input into contract negotiation. They represent minimum required protections — Legal may strengthen these provisions. None of the provisions below should be traded away without formal GRC sign-off and CRO approval.

---

## Provision 1 — Information Security Standards

**Regulatory basis:** APRA CPS 234 Paragraph 17
**Risk addressed:** VAR-004 (vendor data breach)

**Recommended clause:**

> **Information Security Requirements.** Throughout the term of this Agreement, the Vendor shall maintain an information security management system certified to ISO/IEC 27001:2022 by an accredited certification body. The certification scope must explicitly include the Services provided under this Agreement. The Vendor shall:
> (a) provide FinSight with a copy of the current ISO 27001 certificate and scope statement within 10 business days of request;
> (b) notify FinSight within 5 business days if certification lapses, is suspended, or the scope is reduced to exclude the Services;
> (c) conduct or commission an annual independent penetration test of all systems processing FinSight data and provide FinSight with the executive summary of results within 30 days of completion;
> (d) provide a SOC 2 Type II report covering the Services within 90 days of the commencement date and annually thereafter.

**Negotiation guidance:** ISO 27001 certification is a minimum. If the vendor does not have it — do not proceed. SOC 2 Type II is preferred but may be accepted as a Year 1 commitment if the vendor is in the process of obtaining it.

---

## Provision 2 — Breach Notification

**Regulatory basis:** APRA CPS 234 Paragraph 21; Privacy Act 1988 NDB Scheme
**Risk addressed:** VAR-004 (vendor data breach)

**Recommended clause:**

> **Security Incident Notification.** The Vendor shall notify FinSight in writing within **24 hours** of becoming aware of any actual or suspected security incident that has affected, or may have affected, FinSight Data. The notification must include:
> (a) the date and time the incident was first detected;
> (b) a description of the incident including the systems and data affected;
> (c) the number and categories of FinSight customers potentially affected;
> (d) immediate containment actions taken;
> (e) the Vendor's incident response lead and contact details.
>
> The Vendor shall provide FinSight with written incident reports at intervals of no longer than 48 hours until the incident is fully contained and remediated. The Vendor acknowledges that FinSight is subject to APRA reporting obligations requiring notification to APRA within 72 hours of becoming aware of a material incident, and that the Vendor's 24-hour notification obligation is designed to enable FinSight to meet this regulatory obligation.

**Negotiation guidance:** 24 hours is non-negotiable. A vendor that will not commit to 24-hour notification is not suitable for handling material regulatory-scope data. If the vendor proposes 48 or 72 hours — this must be escalated to the CRO before any concession is made.

---

## Provision 3 — Data Processing and Privacy Obligations

**Regulatory basis:** Privacy Act 1988 APP 6, APP 8, APP 11
**Risk addressed:** VAR-003 (offshore processing), VAR-005 (data used for model training)

**Recommended clause:**

> **Data Processing Obligations.** The Vendor shall process FinSight Data solely for the purpose of delivering the Services as defined in this Agreement. The Vendor shall not:
> (a) use FinSight Data for model training, model benchmarking, model improvement, product development, or any commercial purpose beyond delivering the Services;
> (b) disclose FinSight Data to any third party, including affiliates, without FinSight's prior written consent;
> (c) transfer FinSight Data to any jurisdiction or data centre not listed in Schedule [X] (Approved Processing Locations) without FinSight's prior written consent;
> (d) aggregate, anonymise, pseudonymise, or de-identify FinSight Data for any purpose other than delivering the Services.
>
> The Vendor shall process FinSight Data in accordance with the Australian Privacy Principles as if it were bound by those principles as an Australian Privacy Act entity, regardless of the jurisdiction in which processing occurs.

**Negotiation guidance:** Sub-clause (a) addresses the most common vendor standard-terms risk. Any vendor that insists on retaining the right to use client data for model improvement should be treated as a high risk — require explicit opt-out and confirmation that the opt-out is technically enforced, not just a policy statement.

---

## Provision 4 — Data Sovereignty and Approved Processing Locations

**Regulatory basis:** Privacy Act 1988 APP 8; APRA CPS 234
**Risk addressed:** VAR-003 (cross-border data processing)

**Recommended clause:**

> **Data Sovereignty.** The Vendor shall process, store, and back up all FinSight Data only in the jurisdictions and data centre locations listed in Schedule [X] (Approved Processing Locations). As at the Commencement Date, Approved Processing Locations are: Singapore (primary) and Ireland (disaster recovery/backup only).
>
> The Vendor shall not transfer FinSight Data to any additional jurisdiction without:
> (a) providing FinSight with at least 60 days' written notice;
> (b) obtaining FinSight's written consent prior to transfer;
> (c) ensuring FinSight has conducted and documented an updated Privacy Act APP 8 cross-border disclosure assessment for the new jurisdiction.
>
> The Vendor acknowledges that FinSight is subject to the Australian Privacy Act 1988 and that FinSight is legally accountable for any Privacy Act breach committed by the Vendor as if the breach were FinSight's own act.

---

## Provision 5 — AI Model Explainability

**Regulatory basis:** NIST AI RMF GOVERN; ISO/IEC 42001:2023; AFCA dispute resolution obligations
**Risk addressed:** VAR-002 (no explainability)

**Recommended clause:**

> **Model Explainability.** For each fraud flag or fraud risk score generated by the Platform in respect of a FinSight customer transaction, the Vendor shall provide, upon request by FinSight:
> (a) a human-readable explanation of the top contributing factors that influenced the fraud flag decision, expressed in plain English suitable for communication to a retail customer;
> (b) the explanation to be available within **2 business days** of FinSight's request;
> (c) the explanation to include a minimum of the top 5 contributing features or indicators, expressed without reference to proprietary model architecture or uninterpretable technical terms.
>
> The Vendor acknowledges that FinSight's ability to explain AI-driven fraud decisions to customers, regulators, and the Australian Financial Complaints Authority (AFCA) is a legal and regulatory obligation, and that failure to provide explanations as required constitutes a material breach of this Agreement.

**Negotiation guidance:** If the vendor cannot technically provide explainability at contract execution — require a written commitment to deliver explainability capability within 6 months, with a right for FinSight to terminate without penalty if the commitment is not met. Do not go live without this.

---

## Provision 6 — AI Model Performance SLAs

**Regulatory basis:** NIST AI RMF MEASURE; ISO/IEC 42001:2023 Clause 9.1
**Risk addressed:** VAR-001 (false positives), VAR-006 (model drift)

**Recommended clause:**

> **Model Performance Service Level Agreements.** The Vendor warrants that the Platform will maintain the following performance benchmarks throughout the Term:
>
> | Metric | Minimum Standard |
> |--------|-----------------|
> | Fraud detection rate (true positive rate) | ≥ 92% of confirmed fraud events flagged |
> | False positive rate | ≤ 0.5% of total transaction volume per month |
> | System availability | ≥ 99.5% measured monthly (excluding scheduled maintenance) |
> | Scheduled maintenance windows | Maximum 4 hours per month; minimum 5 business days' notice |
>
> The Vendor shall provide FinSight with a monthly model performance report within 10 business days of month-end, including:
> (a) actual detection rate and false positive rate for the preceding month;
> (b) model version in production;
> (c) date of last model retrain;
> (d) any anomalies or performance degradations identified.
>
> If the Vendor identifies that actual performance has breached any SLA threshold, the Vendor shall notify FinSight within **5 business days** of identification and provide a written remediation plan within 10 business days.

---

## Provision 7 — Algorithmic Bias and Fairness

**Regulatory basis:** NIST AI RMF MAP / MEASURE; ISO/IEC 42001:2023 Clause 6.1; ASIC AI fairness guidance
**Risk addressed:** VAR-007 (demographic bias)

**Recommended clause:**

> **Bias Testing and Fairness.** The Vendor shall conduct annual algorithmic bias testing of the Platform's fraud detection model across customer demographic dimensions including age, gender, cultural background, and transaction pattern type. The Vendor shall:
> (a) provide FinSight with the results of each annual bias test within 30 days of completion;
> (b) define and maintain a bias threshold policy — where any demographic group shows a fraud flag rate exceeding the population baseline by more than 10%, the Vendor shall provide a root cause analysis and remediation plan within 30 days;
> (c) where a bias threshold breach is confirmed, not return the platform to standard operation until the bias has been demonstrably remediated and a re-test confirms performance within threshold.
>
> FinSight reserves the right to commission an independent bias audit of the Platform at FinSight's cost, with the Vendor's full cooperation, if FinSight's internal monitoring identifies a potential demographic bias concern.

---

## Provision 8 — Model Change Management

**Regulatory basis:** ISO/IEC 42001:2023 Clause 8.4; NIST AI RMF GOVERN
**Risk addressed:** VAR-009 (undisclosed model changes)

**Recommended clause:**

> **Model Change Management.** A "Material Model Change" means any change to the Platform that affects the model architecture, training dataset, feature set, output scoring methodology, or output format. For all Material Model Changes, the Vendor shall:
> (a) provide FinSight with at least **30 days' written notice** prior to deployment;
> (b) include in the notice: a description of the change, the reason for the change, expected performance impact, updated model card, and results of pre-deployment testing;
> (c) obtain FinSight's written acknowledgement before deployment — FinSight's acknowledgement is required within 15 business days of notice; silence after 15 business days constitutes acknowledgement.
>
> FinSight may object to a Material Model Change within 15 business days if the change materially affects contractual performance SLAs or introduces identified bias. The Vendor shall not deploy a Material Model Change over FinSight's written objection without first resolving the concern through the dispute resolution process in this Agreement.
>
> For all model changes (material or non-material), the Vendor shall maintain a model version history and provide FinSight with access to version history records on request.

---

## Provision 9 — Audit Rights

**Regulatory basis:** APRA CPS 234 Paragraphs 36 and 37
**Risk addressed:** VAR-010 (no audit right)

**Recommended clause:**

> **Audit Rights.** FinSight may, upon providing **30 days' written notice**, commission an independent security and AI governance audit of the Vendor's systems and processes as they relate to the Services and FinSight Data. The Vendor shall cooperate fully with such audits, including providing:
> (a) access to relevant documentation, policies, procedures, and system logs;
> (b) access to key personnel for interviews;
> (c) access to technical environments subject to agreed security protocols.
>
> FinSight may exercise the audit right once per calendar year, or at any time following a security incident affecting FinSight Data, a Material Model Change, or a regulatory request from APRA or ASIC. The cost of the audit shall be borne by FinSight, except where the audit reveals material non-compliance by the Vendor, in which case audit costs shall be borne by the Vendor.
>
> In lieu of an on-site audit in a given year, the Vendor may satisfy the audit obligation by providing, within 30 days of FinSight's request: current ISO 27001 surveillance audit report, current SOC 2 Type II report, annual penetration test executive summary, and an AI governance attestation signed by the Vendor's authorised representative.

---

## Provision 10 — Data Retention and Deletion

**Regulatory basis:** Privacy Act 1988 APP 11; APRA CPS 234
**Risk addressed:** VAR-003 (offshore data management)

**Recommended clause:**

> **Data Retention and Deletion.** The Vendor shall retain FinSight Data for the minimum period necessary to deliver the Services and shall delete FinSight Data in accordance with FinSight's data retention schedule as notified from time to time, subject to a maximum retention period of **7 years** unless otherwise required by applicable law.
>
> Upon termination or expiry of this Agreement:
> (a) the Vendor shall provide FinSight with a complete export of all FinSight Data in [agreed format — CSV/JSON/XML] within **30 days** of termination;
> (b) the Vendor shall permanently delete all FinSight Data from all production, backup, development, and archive systems within **60 days** of termination;
> (c) the Vendor shall provide FinSight with a written certification of deletion, signed by the Vendor's authorised representative, within 70 days of termination.
>
> The deletion obligation extends to all subprocessors with access to FinSight Data.

---

## Provision 11 — Subprocessor Management

**Regulatory basis:** Privacy Act 1988 APP 8 (chain of accountability)
**Risk addressed:** Third-party supply chain risk

**Recommended clause:**

> **Subprocessors.** The Vendor shall not engage any subprocessor to process FinSight Data without FinSight's prior written consent. As at the Commencement Date, approved subprocessors are listed in Schedule [Y] (Approved Subprocessors).
>
> The Vendor shall: (a) impose privacy and security obligations on all subprocessors equivalent to those in this Agreement; (b) notify FinSight of any proposed change to approved subprocessors with at least 30 days' written notice; (c) remain fully liable to FinSight for any act or omission of a subprocessor that would constitute a breach of this Agreement if committed by the Vendor.

---

## Provision 12 — Business Continuity and Exit Management

**Regulatory basis:** APRA CPS 230 (Operational Resilience)
**Risk addressed:** VAR-008 (vendor continuity)

**Recommended clause:**

> **Business Continuity and Exit.** The Vendor shall maintain a Business Continuity Plan and Disaster Recovery Plan for the Services and make these available to FinSight on request. The Vendor warrants a maximum Recovery Time Objective (RTO) of **4 hours** for restoration of the Services following an unplanned outage during business hours (8:00am–8:00pm AEST Monday–Friday).
>
> In the event of contract termination (for any reason), the Vendor shall provide transition assistance including: (a) continuation of Services for up to 90 days post-notice at contracted rates; (b) data export in agreed format within 30 days; (c) reasonable cooperation with FinSight's transition to an alternative provider.

---

## Provision 13 — Regulatory Compliance

**Regulatory basis:** APRA CPS 234; Privacy Act 1988; future AI regulation
**Risk addressed:** VAR-011 (regulatory change)

**Recommended clause:**

> **Regulatory Compliance.** The Vendor shall notify FinSight in writing within **10 business days** of becoming aware of any change in applicable law, regulation, or regulatory guidance in any jurisdiction where FinSight Data is processed that may affect the Vendor's ability to comply with its obligations under this Agreement or FinSight's regulatory obligations.
>
> FinSight may terminate this Agreement without penalty if the Vendor is unable to achieve compliance with FinSight's applicable regulatory requirements within 90 days of FinSight providing written notice of the requirement.
>
> The Vendor shall cooperate with any request from APRA, ASIC, or the OAIC for information relating to the Services or the Vendor's handling of FinSight Data.

---

## Provision 14 — Termination for Material Breach

**Regulatory basis:** Risk governance best practice
**Risk addressed:** All material risks

**Recommended clause:**

> **Termination for Material Breach.** Either party may terminate this Agreement with immediate effect upon written notice if the other party:
> (a) commits a material breach that is not remediated within 30 days of written notice;
> (b) suffers a data breach that results in confirmed loss, unauthorised access to, or exfiltration of FinSight Data;
> (c) fails to meet the breach notification obligation (Provision 2) for any security incident affecting FinSight Data;
> (d) is subject to regulatory enforcement action in any jurisdiction that materially affects its ability to deliver the Services;
> (e) enters into insolvency, administration, or similar proceedings.
>
> Material breach includes: failure to maintain required security certifications; use of FinSight Data for model training contrary to Provision 3; failure to meet explainability obligations (Provision 5) for more than 30 days after written notice; or deployment of a Material Model Change without required notification (Provision 8).

---

## Provision 15 — Governing Law and Dispute Resolution

**Regulatory basis:** Australian regulatory jurisdiction
**Risk addressed:** Enforcement risk — offshore vendor

**Recommended clause:**

> **Governing Law.** This Agreement is governed by the laws of New South Wales, Australia. The parties submit to the exclusive jurisdiction of the courts of New South Wales for all disputes arising from or related to this Agreement.
>
> **Dispute Resolution.** The parties shall first attempt to resolve disputes through good faith negotiation at senior management level for a period of 20 business days. If unresolved, disputes shall proceed to mediation before the Australian Disputes Centre prior to commencing litigation.

**Negotiation guidance:** Vendors may propose Singapore or Irish law given their operating jurisdictions. FinSight must insist on Australian governing law. An APRA-regulated Australian entity cannot be subject to a foreign court's jurisdiction for disputes about the handling of Australian customer financial data.

---

## Contract Negotiation Summary

| Provision | Priority | Non-Negotiable | Regulatory Basis |
|-----------|:--------:|:--------------:|-----------------|
| 1 — Security standards (ISO 27001, SOC 2) | 🔴 Critical | Yes | CPS 234 Para 17 |
| 2 — 24-hour breach notification | 🔴 Critical | Yes | CPS 234 Para 21 / NDB |
| 3 — Data processing prohibition (no model training) | 🔴 Critical | Yes | Privacy Act APP 6 |
| 4 — Data sovereignty | 🔴 Critical | Yes | Privacy Act APP 8 |
| 5 — Explainability | 🔴 Critical | Yes | NIST AI RMF / AFCA |
| 6 — Model performance SLAs | 🔴 High | Yes | NIST AI RMF MEASURE |
| 7 — Bias testing | 🔴 High | Yes | ISO 42001 / ASIC |
| 8 — Model change management (30-day notice) | 🔴 High | Yes | ISO 42001 / NIST AI RMF |
| 9 — Audit rights | 🔴 High | Yes | CPS 234 Para 36/37 |
| 10 — Data deletion (30/60 day timelines) | 🟠 Medium | Strongly recommended | Privacy Act APP 11 |
| 11 — Subprocessor management | 🟠 Medium | Strongly recommended | Privacy Act APP 8 |
| 12 — BCP / Exit management | 🟠 Medium | Strongly recommended | CPS 230 |
| 13 — Regulatory compliance notification | 🟠 Medium | Recommended | CPS 234 / Future AI regulation |
| 14 — Termination for material breach | 🔴 High | Yes | Risk governance |
| 15 — Australian governing law | 🔴 Critical | Yes | APRA / Privacy Act jurisdiction |

**GRC sign-off required before any concession on provisions marked Non-Negotiable.**

---

*This document is part of a sample GRC portfolio project. All organisations, scenarios, and contract language are fictional and created for professional skills demonstration purposes.*
