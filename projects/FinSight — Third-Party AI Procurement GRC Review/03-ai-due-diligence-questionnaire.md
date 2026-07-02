# Third-Party AI Due Diligence Questionnaire — VeriGuard AI

**Document ID:** FINSIGHT-AI-DDQ-003
**Version:** 1.0
**Classification:** Internal — Restricted
**Issued By:** FinSight Analytics GRC Team
**Issued To:** VeriGuard AI Pty Ltd
**Response Required By:** [Date — 20 business days from issue]
**Framework references:** ISO/IEC 42001:2023 · NIST AI RMF · APRA CPS 234 · Privacy Act 1988 (AU)

---

## Instructions to Vendor

FinSight Analytics is conducting a governance, risk, and compliance review of the proposed VeriGuard AI fraud detection platform procurement. This questionnaire must be completed by VeriGuard AI's authorised representative and returned with all supporting documentation requested.

**Response format:**
- Answer each question directly and completely
- Where documentation is requested, attach the document and reference the attachment in your response
- Where a capability or control does not exist, state this clearly — do not leave questions unanswered
- Incomplete or evasive responses will be escalated and may result in procurement being declined

**Confidentiality:** All responses will be treated as confidential by FinSight Analytics and used solely for procurement due diligence purposes.

---

## Section 1 — Organisation and AI Governance

**1.1** Provide a current company profile including: legal entity name, registered jurisdiction, Australian presence (if any), corporate structure, and ultimate beneficial ownership.

> *Supporting document required: Company registration certificate or equivalent*

---

**1.2** Describe your organisation's AI governance structure. Who holds ultimate accountability for AI model decisions, safety, and compliance? Provide an organisational chart showing AI governance roles.

> *Supporting document required: AI governance policy or equivalent*

---

**1.3** Does your organisation have a documented AI governance policy or equivalent? If yes, provide the current version. If no, describe how AI governance decisions are made.

> *Supporting document required: AI governance policy (current version)*

---

**1.4** Is your organisation currently undergoing or planning to undergo ISO/IEC 42001:2023 certification? If not, what AI governance standard or framework does your organisation follow?

---

**1.5** How many AI models are currently deployed in production across your client base? How many are deployed in Australian financial services contexts?

---

**1.6** Describe any material AI incidents your organisation has experienced in the past three years — including model failures, data breaches involving AI-processed data, or significant performance degradations. How were these resolved?

---

## Section 2 — AI Model Transparency and Documentation

**2.1** Provide the current Model Card for the VeriGuard fraud detection AI platform. The model card must include:
- Model purpose and intended use
- Model architecture (at a conceptual level — not proprietary source code)
- Training dataset composition — size, sources, geographic coverage, time range, demographic representation
- Known performance limitations and failure modes
- Documented out-of-scope use cases

> *Supporting document required: Model Card (current version)*

---

**2.2** What is the model's documented performance benchmark for fraud detection? Provide:
- True positive rate (fraud detection rate)
- False positive rate (legitimate transactions incorrectly flagged)
- Precision and recall metrics
- Performance benchmarks broken down by transaction type, value range, and client sector

> *Supporting document required: Model performance benchmark report*

---

**2.3** When was the fraud detection model last retrained? What data was used for the most recent retraining? How frequently is the model typically retrained?

---

**2.4** Can the platform provide an explanation for each individual fraud flag decision? If yes:
- Describe the explainability methodology (e.g. SHAP, LIME, attention weights)
- Describe the format of the explanation output
- Is the explanation available in real time or as a post-decision report?
- Can the explanation be provided in plain English suitable for communication to a customer?

If no explainability capability exists — state this clearly.

---

**2.5** What is your process for managing model versioning? How are different model versions tracked, documented, and controlled?

---

## Section 3 — Bias, Fairness, and Ethical AI

**3.1** Has the VeriGuard fraud detection model been tested for algorithmic bias? If yes:
- Describe the bias testing methodology used
- Identify the demographic dimensions tested (age, gender, cultural background, geographic location, socioeconomic indicators)
- Provide the most recent bias testing results — including any demographic groups where performance diverges from the population baseline
- Describe any bias mitigation measures applied

> *Supporting document required: Bias testing report (most recent)*

---

**3.2** Has the model produced disproportionately high fraud flag rates for any identifiable demographic group in any deployment? If yes, describe the circumstances and how this was addressed.

---

**3.3** Does your organisation have a documented bias threshold policy — defining an acceptable performance differential between demographic groups before remediation is triggered? If yes, provide the policy. If no, how are decisions made about acceptable bias levels?

---

**3.4** How does your organisation ensure that CALD (culturally and linguistically diverse) customers and customers with non-standard transaction patterns are not disproportionately affected by fraud flags?

---

**3.5** Is there an ethical AI review process for new model deployments? Describe this process and who is involved.

---

## Section 4 — Data Handling, Privacy, and Sovereignty

**4.1** Where is FinSight customer data processed, stored, and backed up? Provide the specific countries and data centre locations for all environments — production, development, DR/backup, and support.

---

**4.2** Will FinSight customer data be transferred to any jurisdiction not listed in your response to 4.1? Under what circumstances might additional data locations be used?

---

**4.3** Is FinSight customer data logically isolated from other clients' data within the VeriGuard platform? Describe the isolation architecture — at the database, application, and infrastructure levels.

---

**4.4** Will FinSight customer data be used for any purpose other than delivering fraud detection services to FinSight? This includes model training, benchmarking, product improvement, analytics, or sharing with third parties. If yes — for what purpose, under what controls, and with what customer consent mechanism?

---

**4.5** What encryption standards are applied to FinSight data:
- In transit (between FinSight systems and VeriGuard platform)?
- At rest (within VeriGuard infrastructure)?
- In processing (in-memory / in-use)?

Specify the protocols and key lengths used.

---

**4.6** What is your data retention policy for client data? How long is FinSight transaction data retained on VeriGuard systems after processing? What is the deletion process and how is deletion confirmed?

---

**4.7** Provide a copy of your Privacy Policy and your standard Data Processing Agreement (DPA) template. Confirm that you are willing to execute a DPA that includes Australian Privacy Principles obligations.

> *Supporting document required: Current Privacy Policy and DPA template*

---

**4.8** Describe who within VeriGuard has access to FinSight customer data. What access controls, background check requirements, and privileged access management controls apply to personnel with data access?

---

## Section 5 — Information Security and Compliance

**5.1** Provide your current ISO 27001 certificate including the full scope statement. Confirm that the VeriGuard AI fraud detection platform is within scope. If the current certificate does not cover the platform, explain why and what alternative assurance applies.

> *Supporting document required: ISO 27001 certificate with scope*

---

**5.2** Have you completed a SOC 2 Type II audit in the past 12 months? If yes, provide the report (under NDA). If no, explain what alternative independent security assurance is available.

> *Supporting document required: SOC 2 Type II report or alternative assurance documentation*

---

**5.3** When was the VeriGuard AI platform last assessed by an independent penetration testing firm? Provide a summary of findings and remediation status. Are you willing to share the full penetration test report under NDA?

> *Supporting document required: Penetration test executive summary (current year)*

---

**5.4** Describe your vulnerability management process — how vulnerabilities in the VeriGuard platform are identified, prioritised, and remediated. What is your SLA for remediating critical vulnerabilities (CVSS 9.0+)?

---

**5.5** Describe your security incident response process. What is the current documented process for detecting, responding to, and recovering from a security incident affecting client data?

---

**5.6** Have you experienced any data breaches, security incidents, or regulatory enforcement actions in the past three years involving client data or your AI platform? If yes, describe the incident, impact, and outcome.

---

**5.7** What AI-specific security testing have you conducted? This includes testing for adversarial attacks, model extraction attacks, data poisoning, and prompt injection (where applicable). Provide results.

---

**5.8** Describe your third-party and supply chain security management. What subprocessors have access to FinSight data? What security obligations apply to your subprocessors?

> *Supporting document required: Subprocessor list*

---

## Section 6 — Business Continuity and Operational Resilience

**6.1** Provide your Business Continuity Plan (BCP) and Disaster Recovery Plan (DRP) for the VeriGuard AI platform. What is your documented RTO and RPO for the fraud detection service?

> *Supporting document required: BCP/DRP executive summary*

---

**6.2** Describe the redundancy and failover architecture of the VeriGuard platform. What happens to FinSight's fraud detection capability if the primary data centre experiences an outage?

---

**6.3** What is your historical platform availability performance for the past 24 months? Provide uptime statistics.

---

**6.4** How many clients are currently served on the same platform instance as FinSight would be? What is the capacity headroom?

---

**6.5** In the event of contract termination, how is FinSight's data returned? In what format? Within what timeframe? How is deletion of FinSight data from all VeriGuard systems confirmed?

---

## Section 7 — Model Change Management

**7.1** Describe your process for managing changes to the fraud detection AI model — including retraining, algorithm updates, feature changes, and output format changes.

---

**7.2** How will FinSight be notified of planned model changes? What advance notice do you provide? Is there a client approval step before material changes are deployed?

---

**7.3** What change management documentation do you produce for model changes? Do you update the model card after each change?

---

**7.4** What rollback capability exists if a model change causes performance degradation after deployment? Describe the rollback process and timeline.

---

## Section 8 — Contractual and Regulatory

**8.1** Is VeriGuard willing to execute a contract that includes the following obligations? Provide a yes/no response for each, and note any concerns:

| Obligation | Willing to Include? | Notes |
|-----------|:-------------------:|-------|
| 24-hour breach notification SLA | | |
| Annual penetration test results shared with FinSight | | |
| FinSight audit rights (annual, with 30-day notice) | | |
| Prohibition on using FinSight data for model training | | |
| 30-day advance notice for material model changes | | |
| Explainability capability for each fraud flag | | |
| Annual bias testing results shared with FinSight | | |
| Data sovereignty — Australian data residency | | |
| Termination for regulatory non-compliance | | |
| Data deletion within 30 days of contract termination | | |

---

**8.2** Are you aware of any current or pending regulatory investigations, enforcement actions, or legal proceedings involving your organisation, your AI platform, or your handling of client data in any jurisdiction?

---

**8.3** What regulatory notifications or approvals have you obtained for operating an AI fraud detection platform in Australia? Are you aware of any obligations under TGA, ASIC, or other Australian regulatory bodies relevant to your platform?

---

**8.4** Are you willing to provide APRA with direct access to information about your services to FinSight if requested? This is a CPS 234 requirement for APRA-regulated entities engaging third parties.

---

## Vendor Certification

By submitting this questionnaire, the authorised representative of VeriGuard AI Pty Ltd certifies that:
- All responses are accurate and complete to the best of their knowledge
- Supporting documentation provided is current and has not been materially altered
- Any material change to the information provided after submission will be disclosed to FinSight within 5 business days

**Authorised Representative:** ___________________________
**Title:** ___________________________
**Date:** ___________________________
**VeriGuard AI Pty Ltd**

---

*This questionnaire is part of a sample GRC portfolio project. FinSight Analytics and VeriGuard AI are fictional organisations.*
