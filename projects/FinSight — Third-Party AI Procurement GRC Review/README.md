# FinSight Analytics (Third-Party AI Procurement GRC Review)

**Organisation:** FinSight Analytics *(fictional for Simmulation)*

**Sector:** Financial Services / Fintech

**Project Type:** Third-Party AI Risk Assessment · Vendor Due Diligence · Regulatory Compliance Review

**Classification:** Internal  Restricted

**Project Lead:** GRC Analyst

**Review Date:** 2026

---

## Frameworks Applied

| Framework | Application |
|-----------|-------------|
| ISO/IEC 42001:2023 | AI management system and third-party AI risk controls |
| NIST AI Risk Management Framework (AI RMF 1.0) | AI risk categorisation, measurement, and governance |
| APRA Prudential Standard CPS 234 | Information security obligations for third-party arrangements |
| Australian Privacy Act 1988 | Cross-border data disclosure, APP obligations, NDB scheme |
| AS ISO 31000:2018 | Risk assessment methodology |

---

## Project Context

FinSight Analytics is a fictional Australian financial services firm providing investment analytics and portfolio management services to retail and wholesale clients. The firm is APRA-regulated and holds an Australian Financial Services Licence (AFSL).

The organisation is evaluating procurement of **VeriGuard AI**, a third-party AI-driven fraud detection platform developed by an offshore technology company. The VeriGuard platform uses machine learning models to analyse real-time transaction patterns, flag anomalous activity, and generate fraud risk scores that FinSight's operations team would use to block or escalate suspicious transactions.

The procurement decision carries material regulatory, operational, reputational, and AI governance risk. As an APRA-regulated entity, FinSight must ensure that third-party service providers handling customer financial data or performing functions material to business operations meet the same information security and risk governance standards applied internally, a requirement set out in APRA CPS 234 and reinforced by APRA's broader expectations under CPS 230 (Operational Resilience).

The introduction of AI-based decision-making into transaction fraud detection also creates specific obligations that standard vendor risk assessments do not address  including model transparency, algorithmic explainability, bias risk, and accountability when an AI decision results in wrongful customer harm.

This project conducted a full GRC review of the proposed procurement from a risk, compliance, and AI governance perspective, producing the documentation required to support an informed procurement decision and ensure appropriate contractual protections are in place before any contract is signed.

---

## Vendor Profile  (VeriGuard AI)

| Attribute | Detail |
|-----------|--------|
| **Vendor name** | VeriGuard AI Pty Ltd *(fictional)* |
| **Headquarters** | Singapore |
| **Data processing locations** | Singapore (primary), Ireland (DR/backup) |
| **Platform** | AI-driven real-time fraud detection, transaction anomaly detection, ML-based fraud scoring |
| **Model type** | Gradient Boosting + Neural Network ensemble |
| **Certifications claimed** | ISO 27001 (claimed, scope unverified) |
| **SOC 2 report** | Not provided |
| **Client base** | 12 financial services clients where 3 in Australia, 9 offshore |
| **Data accessed** | Customer transaction records, account history, device fingerprints, behavioural patterns |
| **Contract term proposed** | 3 years with annual renewal |
| **Annual contract value** | AUD $1.2M |

---

## Risk Summary (Pre-Assessment)

Before detailed assessment, the following high-level risk indicators were identified:

| Risk Indicator | Assessment |
|---------------|------------|
| Customer financial data processed offshore (Singapore, Ireland) | APP 8 cross-border disclosure obligations triggered |
| Proprietary AI model, no explainability capability disclosed | Regulatory and customer dispute risk |
| ISO 27001 certification scope not verified | CPS 234 third-party assurance gap |
| No SOC 2 Type II report available | Independent security assurance not available |
| Vendor data used for model improvement (standard terms) | Customer data use beyond primary purpose|
| No model card or bias testing documentation provided | AI governance maturity concern |
| Contract does not include breach notification SLA | CPS 234 Paragraph 21 non-compliance |

**Pre-assessment risk rating: High  (Procurement should not proceed without material contractual and governance remediation)**

---

## Repository Contents

```
grc-finsight-ai/
├── README.md                                  ← Project overview, context, vendor profile
├── 01-vendor-ai-risk-assessment.md           ← AI vendor risk register with ratings and treatment
├── 02-apra-cps234-gap-analysis.md            ← Gap analysis against APRA CPS 234 requirements
├── 03-ai-due-diligence-questionnaire.md      ← Third-party AI due diligence questionnaire (25 questions)
├── 04-data-sovereignty-assessment.md         ← Data sovereignty and Privacy Act 1988 review
├── 05-contractual-control-recommendations.md ← Recommended contract provisions and obligations
└── notes/
    └── iso42001-third-party-mapping.md       ← ISO 42001:2023 third-party AI risk control mapping
```

---

## Key Deliverables

| Deliverable | File | Purpose |
|------------|------|---------|
| Vendor AI Risk Assessment | `01-vendor-ai-risk-assessment.md` | Identify, rate, and treat 12 AI procurement risks |
| APRA CPS 234 Gap Analysis | `02-apra-cps234-gap-analysis.md` | Assess compliance gaps in third-party arrangement |
| AI Due Diligence Questionnaire | `03-ai-due-diligence-questionnaire.md` | 25-question framework for vendor response |
| Data Sovereignty Assessment | `04-data-sovereignty-assessment.md` | Privacy Act APP 8 cross-border disclosure review |
| Contractual Control Recommendations | `05-contractual-control-recommendations.md` | 15 contract clauses to protect FinSight |
| ISO 42001 Mapping | `notes/iso42001-third-party-mapping.md` | Third-party AI risk mapped to ISO 42001 controls |

---

## Tools Used Across This Project

| Tool | Purpose |
|------|---------|
| ServiceNow GRC | Vendor risk register management and workflow |
| OneTrust | Third-party risk assessment and privacy review |
| Vanta | Vendor compliance monitoring and certification verification |
| BitSight | Vendor external security posture rating |
| Microsoft Purview | Data classification and compliance reporting |
| Confluence | GRC documentation and review workflow |
| Archer GRC | Risk scoring and reporting |
| OAIC Privacy Register | Privacy Act obligation reference |
| APRA Prudential Practice Guides | CPS 234 interpretation guidance |

