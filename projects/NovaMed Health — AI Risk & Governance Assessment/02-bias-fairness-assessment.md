# Bias and Fairness Assessment — NovaMed Health CDS Platform

**Document ID:** NOVAMED-AI-BIAS-002
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** Chief Clinical Information Officer (CCIO)
**Framework references:** NIST AI RMF (MAP 1.5, MAP 2.3, MEASURE 2.5) · ISO/IEC 42001:2023 Clause 6.1 · WHO Ethics and Governance of AI for Health

---

## Purpose

This assessment identifies, evaluates, and documents bias and fairness risks in NovaMed Health's AI-assisted Clinical Decision Support (CDS) system. It establishes pre-deployment testing requirements, ongoing monitoring protocols, and remediation thresholds — ensuring the AI system delivers equitable clinical recommendations across all patient demographic groups served by NovaMed.

Algorithmic bias in clinical AI is not a theoretical concern. It has resulted in documented inequities in real-world healthcare systems — including models that systematically underperformed for women, elderly patients, and patients from culturally and linguistically diverse (CALD) backgrounds. This assessment treats bias risk with the same seriousness as patient safety risk.

---

## Scope

This assessment covers the CDS model's performance across the following protected attributes and clinically relevant demographic dimensions:

| Dimension | Subgroups Assessed |
|-----------|-------------------|
| Age | 18–34, 35–54, 55–74, 75+ |
| Sex / Gender | Male, Female, Non-binary / gender diverse |
| Ethnicity / Cultural Background | Anglo-Australian, South Asian, East Asian, Southeast Asian, Middle Eastern, African, First Nations |
| Language | English-speaking, CALD patients using interpreter services |
| Socioeconomic status | Private insured, Public patient, DVA, Concession |
| Comorbidity burden | No comorbidities, 1–2 comorbidities, 3+ comorbidities |
| Geographic classification | Metropolitan, Regional (where applicable) |

---

## Bias Risk Framework — NIST AI RMF Alignment

| NIST AI RMF Sub-Category | Bias Dimension Addressed |
|--------------------------|------------------------|
| MAP 1.5 — Organisational risk tolerances | Bias threshold policy — define acceptable performance differential |
| MAP 2.3 — AI system context and use | Clinical context where bias has direct patient safety consequence |
| MEASURE 2.5 — Bias testing and fairness metrics | Pre-deployment and ongoing demographic performance testing |
| MANAGE 2.4 — Treatment of identified bias | Remediation process, suspension criteria, vendor obligations |

---

## Bias Types Assessed

### 1. Historical Bias
**Description:** Training data reflects past clinical decisions that were themselves biased — for example, historical underdiagnosis of cardiac events in women, or underrepresentation of First Nations patients in clinical datasets.

**Risk to NovaMed:** Model trained on historical EHR data may perpetuate documented clinical biases, producing systematically lower-quality recommendations for demographic groups previously underserved by the healthcare system.

**Assessment approach:** Require vendor to provide training data demographics report. Compare representation of each demographic subgroup against Australian population benchmarks and NovaMed patient population.

---

### 2. Representation Bias
**Description:** Specific patient groups are underrepresented in the training dataset, reducing model accuracy for those groups even if no historical bias existed.

**Risk to NovaMed:** CALD patients, elderly patients, and patients with complex comorbidities — groups that form a significant proportion of hospital populations — may receive lower-quality recommendations due to thin training data for their profiles.

**Assessment approach:** Review vendor-provided training dataset composition report. Flag any demographic subgroup representing less than 10% of the Australian hospital patient population benchmark that is also underrepresented in training data relative to their share of NovaMed's patient cohort.

---

### 3. Measurement Bias
**Description:** Data collected systematically differently across demographic groups — for example, different symptom documentation practices, different diagnostic coding rates, or different test ordering patterns — introduces bias into the model inputs themselves.

**Risk to NovaMed:** If clinical data entry practices vary across NovaMed facilities or clinician cohorts, model inputs will carry those inconsistencies, producing inconsistent outputs.

**Assessment approach:** Audit NovaMed's own data collection practices across the four facilities. Assess whether symptom documentation completeness, diagnostic coding, and test ordering rates are consistent across patient demographic groups.

---

### 4. Aggregation Bias
**Description:** A model trained on a generalised population performs differently for specific subgroups who have clinically distinct presentations — for example, diabetes presentations differ significantly across ethnic groups.

**Risk to NovaMed:** Clinically distinct presentations in First Nations patients, CALD populations, or patients with specific comorbidity profiles may not be adequately captured by a model optimised for population-level accuracy.

**Assessment approach:** Stratify model accuracy metrics by demographic subgroup. Identify whether any subgroup shows statistically significant performance divergence from the population baseline.

---

## Pre-Deployment Bias Testing Protocol

### Phase 1 — Vendor Documentation Review

Before any testing begins, require the following from the AI vendor:

| Document | Content Required |
|----------|-----------------|
| Model Card | Model purpose, intended use, limitations, known failure modes, demographic performance data |
| Training Data Report | Dataset size, demographic composition, data sources, representation benchmarks |
| Pre-existing Bias Assessment | Any bias testing conducted during model development — methodology, results, remediation applied |
| Performance Benchmarks | Accuracy, precision, recall, F1 score — overall and stratified by demographic subgroup |

**Gate:** If vendor cannot provide a Model Card and training data demographic breakdown — halt deployment assessment until documentation is produced.

---

### Phase 2 — Independent Bias Audit

Commission an independent clinical AI audit firm to conduct structured bias testing using NovaMed's patient population data (de-identified).

**Testing methodology:**

| Metric | Definition | Application |
|--------|-----------|-------------|
| Demographic Parity | Recommendation quality equal across demographic groups | Compare recommendation accuracy rates by subgroup |
| Equalised Odds | True positive and false positive rates equal across groups | Critical for diagnostic recommendations — a false negative in one group is inequitable |
| Predictive Parity | Confidence scores equally calibrated across groups | A high-confidence recommendation must be equally reliable regardless of patient demographic |
| Individual Fairness | Similar patients receive similar recommendations | Test using matched patient profiles across demographic dimensions |

**Sample size requirement:** Minimum 500 patient cases per major demographic subgroup for statistical significance.

**Reporting:** Independent auditor produces written report with demographic-stratified performance metrics, identified disparities, statistical significance, and remediation recommendations.

---

### Phase 3 — Bias Threshold Assessment

Apply NovaMed's defined bias threshold policy to audit results:

| Performance Differential | Threshold | Action Required |
|--------------------------|-----------|----------------|
| < 5% vs baseline | Within tolerance | Document and monitor |
| 5–10% vs baseline | Caution zone | Vendor notified; remediation plan required within 30 days |
| > 10% vs baseline | Breach threshold | **Deployment suspended** pending remediation and re-audit |
| Any First Nations subgroup | Zero tolerance | Any measured disparity triggers immediate escalation to CMO and AISC |

**Rationale for First Nations zero-tolerance threshold:** First Nations Australians experience disproportionate burden of chronic disease and historical underservice by the healthcare system. An AI system that compounds these inequities — even marginally — is inconsistent with NovaMed's obligations under the National Safety and Quality Health Service (NSQHS) standards and its organisational commitment to equitable care.

---

## Ongoing Monitoring Protocol — Post-Deployment

### Monthly Monitoring

| KPI | Measurement Method | Alert Threshold |
|-----|-------------------|-----------------|
| Recommendation acceptance rate by demographic | System logging — clinician acceptance vs override by patient demographic | >10% differential across any group vs overall acceptance rate |
| Confidence score distribution by demographic | Model output logging | Mean confidence score for any demographic <5% below overall mean |
| Override rate by demographic | Clinical log review | Clinicians overriding recommendations for specific demographic groups at >15% higher rate than baseline |

### Quarterly Monitoring

| Review | Conducted By | Output |
|--------|-------------|--------|
| Bias metric re-run on last 90 days of recommendation data | CCIO / Clinical Data Team | Demographic-stratified performance report |
| AISC review of bias metrics | AI Safety and Compliance Committee | Risk register update; vendor escalation if thresholds breached |
| First Nations patient outcome review | CMO / Clinical Governance | Specific outcome analysis — presented to AISC |

### Annual Review

- Full independent bias re-audit commissioned
- Bias assessment updated and re-presented to Board
- Vendor model card updated — current performance data required

---

## Bias Remediation Process

If a bias threshold breach is identified — pre-deployment or post-deployment:

**Step 1:** CCIO notified within 24 hours of threshold breach identification
**Step 2:** Vendor formally notified — written notice, 5 business days to respond with root cause analysis
**Step 3:** AISC convened within 10 business days — remediation decision made
**Step 4:** Options assessed:
  - Vendor model retraining with corrected dataset (preferred)
  - Application of demographic-specific calibration (interim)
  - Suspension of AI recommendations for affected demographic group
  - Full deployment suspension pending remediation
**Step 5:** Re-audit required before remediated model is returned to clinical use
**Step 6:** Board notified of breach and remediation outcome

---

## Tools and Technologies

| Tool | Purpose |
|------|---------|
| IBM OpenScale (Watson OpenScale) | AI fairness monitoring and bias detection in production |
| Microsoft Fairlearn | Open-source bias assessment and mitigation toolkit |
| SHAP (SHapley Additive exPlanations) | Explainability — identifying which features drive recommendations for each demographic |
| Python (scikit-learn, AIF360) | Statistical bias metric calculation — demographic parity, equalised odds |
| IBM AI Fairness 360 (AIF360) | Comprehensive bias detection and mitigation library |
| OneTrust | Privacy and consent management — patient disclosure tracking |
| Power BI / Tableau | Bias monitoring dashboard visualisation |
| REDCap | De-identified patient data management for bias testing |

---

## Regulatory and Standards References

| Reference | Relevance |
|-----------|-----------|
| NIST AI RMF — MAP 2.3, MEASURE 2.5 | AI fairness assessment and measurement requirements |
| ISO/IEC 42001:2023 — Clause 6.1 | AI risk assessment including bias and fairness |
| WHO Ethics and Governance of AI for Health (2021) | Fairness and equity principles for health AI |
| NSQHS Standards — Standard 1 (Clinical Governance) | Equitable care obligations for Australian health services |
| AHPRA Code of Conduct | Clinician obligations when using AI-assisted tools |
| Privacy Act 1988 (AU) — APP 11 | Protecting sensitive health information processed by AI |

---

*This document is part of a sample GRC portfolio project. NovaMed Health is a fictional organisation. All scenarios are created for professional skills demonstration.*
