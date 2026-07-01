# 🤖 NovaMed Health — AI Risk & Governance Assessment

**Organisation:** NovaMed Health *(fictional)*
**Sector:** Healthcare / Clinical Technology
**Project type:** AI Risk Assessment · AI Governance Framework · Privacy Compliance Review

**Frameworks applied:** NIST AI Risk Management Framework (AI RMF) · ISO/IEC 42001:2023 · Australian Privacy Act 1988 · TGA Software as a Medical Device (SaMD) guidance

---

## Project Context

NovaMed Health is a fictional Australian private hospital group operating across four metropolitan facilities. The organisation is implementing an AI-assisted clinical decision support (CDS) tool that analyses patient symptom data, medical history, and diagnostic test results to generate ranked diagnosis recommendations for clinical staff.

The deployment introduces significant risk across multiple dimensions: patient safety if the model produces incorrect or biased recommendations, data privacy obligations for sensitive health information, regulatory exposure under TGA oversight of AI-based medical software, and accountability gaps where no governance structure exists to manage the AI system's lifecycle, performance, or failure modes.

The project was initiated to assess these risks, establish a governance framework, and produce the documentation required to operate the AI system responsibly within a regulated healthcare environment.

---

## Repository Contents

```
grc-novamed-ai/
├── README.md                              ← This file — project overview and methodology
├── 01-ai-risk-register.md                ← AI-specific risk register with ratings and treatment
├── 02-bias-fairness-assessment.md        ← Bias risk assessment across patient demographics
├── 03-ai-governance-policy.md            ← AI governance policy — accountability and controls
├── 04-privacy-impact-assessment.md       ← Privacy Act 1988 obligations for health data
├── 05-ai-incident-response.md            ← Incident response guidance for AI system failures
├── 06-iso42001-gap-assessment.md         ← Gap assessment against ISO/IEC 42001:2023
└── notes/
    └── nist-ai-rmf-mapping.md            ← Control mapping to NIST AI RMF functions
```

---

## Methodology — NIST AI RMF

The assessment was structured around the four core functions of the NIST AI Risk Management Framework:

| Function | Description | Applied to NovaMed |
|----------|-------------|-------------------|
| **GOVERN** | Establish AI risk governance, policies, roles, and accountability | Defined AISC committee, accountability owners, governance policy |
| **MAP** | Identify and categorise AI risks in context | Identified clinical, privacy, bias, and operational risk categories |
| **MEASURE** | Analyse and assess identified AI risks | Scored risks by likelihood, severity, and reversibility |
| **MANAGE** | Prioritise and implement risk treatments | Produced treatment plans, controls, and monitoring requirements |

---

## AI Risk Register Summary

| Risk ID | Risk | Category | Likelihood | Severity | Priority | Treatment |
|---------|------|----------|:-:|:-:|:-:|---------|
| AIR-01 | Model produces incorrect diagnosis recommendation acted on by clinician | Patient Safety | 3 | 5 | 🔴 Critical | Mandatory human clinical override; model outputs labelled as decision support only |
| AIR-02 | Algorithmic bias producing systematically lower-quality recommendations for specific patient demographics | Bias / Fairness | 3 | 5 | 🔴 Critical | Bias audit across age, gender, ethnicity prior to deployment; quarterly bias testing |
| AIR-03 | Sensitive health information processed by AI model without adequate consent or disclosure | Privacy / Legal | 3 | 4 | 🔴 High | Privacy notice update; consent review; health information handling assessment |
| AIR-04 | AI model classified as Software as a Medical Device (SaMD) without TGA registration | Regulatory | 2 | 5 | 🔴 High | TGA SaMD classification assessment; regulatory pathway determination |
| AIR-05 | No accountability owner for AI system decisions or adverse outcomes | Governance | 4 | 4 | 🔴 High | Appoint AI System Owner; define accountability in governance policy |
| AIR-06 | Model drift over time degrades recommendation quality without detection | Operational | 3 | 4 | 🟠 Medium | Implement model performance monitoring; define drift thresholds and escalation |
| AIR-07 | Clinicians over-rely on AI recommendations, reducing independent clinical judgment | Human Factors | 3 | 4 | 🟠 Medium | Clinical training program; UI design that reinforces advisory-only framing |
| AIR-08 | AI training data contains historical clinical biases embedded in past decisions | Data Quality | 3 | 4 | 🟠 Medium | Training data audit; bias testing on representative patient cohorts |
| AIR-09 | Third-party AI vendor suffers data breach exposing patient health data | Third-Party | 2 | 5 | 🟠 Medium | Vendor security assessment; data processing agreement; breach notification SLA |
| AIR-10 | No documented process for AI system failure or unexpected output | Incident Response | 4 | 3 | 🟠 Medium | AI-specific incident response procedure; escalation path to clinical governance |

---

## Key Governance Controls Implemented

### Human Override Requirement
All AI-generated diagnosis recommendations must be reviewed and confirmed by a qualified clinician before any clinical action is taken. The system interface must clearly label all outputs as "decision support" — not diagnosis. No clinical decision may be documented as AI-generated without clinician sign-off.

### AI System Accountability Structure
An AI System Owner is designated with responsibility for model lifecycle governance, performance monitoring, incident escalation, and annual review. An AI Safety and Compliance (AISC) committee — comprising the CMO, CIO, Privacy Officer, and Clinical Governance Lead — holds accountability for AI risk oversight and policy compliance.

### Bias and Fairness Testing Protocol
Prior to deployment, the model must undergo bias testing across demographic cohorts including age groups, gender, and ethnicity. Testing methodology must be documented, results reviewed by the AISC committee, and any statistically significant performance disparity must be remediated before go-live. Bias testing repeats quarterly.

### Model Performance Monitoring
Defined KPIs for model performance include: recommendation acceptance rate by clinicians, frequency of clinician-overridden recommendations, adverse outcome correlation review (quarterly), and model drift indicators measured against baseline accuracy. Thresholds are defined for mandatory escalation to the AI System Owner.

---

## Privacy Act 1988 — Health Information Obligations

Health information is classified as **sensitive information** under the Privacy Act 1988, requiring a higher standard of protection than general personal information.

| APP | Obligation | NovaMed Application |
|-----|-----------|-------------------|
| APP 3 | Collect only information reasonably necessary | Define the minimum data fields required for AI model input |
| APP 5 | Notify individuals of data collection and use | Update privacy notice to disclose AI processing of health data |
| APP 6 | Use and disclose only for the primary purpose | Confirm AI vendor cannot use patient data for model training without consent |
| APP 11 | Protect health information from unauthorised access | Encryption at rest and in transit; access controls on AI input/output data |
| APP 12 | Provide access to personal information on request | Ensure AI-processed data is retrievable and attributable to the patient record |

---

## ISO/IEC 42001:2023 — Gap Assessment Summary

| Clause | Requirement | Status | Gap |
|--------|-------------|--------|-----|
| 4.1 | Understanding the organisation and its context | ⚠️ Partial | AI context not formally documented |
| 5.2 | AI policy | ❌ Not in place | No AI governance policy exists |
| 6.1 | Actions to address AI risks and opportunities | ❌ Not in place | No AI risk assessment process |
| 8.4 | AI system impact assessment | ❌ Not in place | No clinical impact assessment conducted |
| 9.1 | Monitoring, measurement, and evaluation | ⚠️ Partial | Clinical KPIs exist; AI-specific metrics absent |
| 10.1 | Continual improvement | ⚠️ Partial | Clinical governance cycle exists; AI not included |

**Overall:** NovaMed is not currently compliant with ISO/IEC 42001:2023. A structured 6-month implementation program is recommended before any AI clinical deployment proceeds.

---

## Why AI GRC Matters in Healthcare

Organisations deploying AI in clinical or regulated environments face a distinct set of governance obligations that go beyond standard cybersecurity risk management. Incorrect AI outputs in healthcare can cause direct patient harm. Biased models can create systemic inequity in care outcomes. Unexplainable AI decisions create accountability gaps that expose organisations to regulatory and legal risk.

GRC professionals working in healthcare AI need to understand not just how to assess risk — but how to design governance structures that make AI systems accountable, auditable, and safe to operate within a clinical environment.

---

*This is a sample portfolio project. NovaMed Health is a fictional organisation. All scenarios are created for professional skills demonstration.*
