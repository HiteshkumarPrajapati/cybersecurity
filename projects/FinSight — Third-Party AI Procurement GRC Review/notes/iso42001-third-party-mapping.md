# ISO/IEC 42001:2023 — Third-Party AI Risk Control Mapping

**Document ID:** FINSIGHT-AI-ISO42001-NOTES
**Classification:** Internal
**Owner:** GRC Analyst
**Reference:** ISO/IEC 42001:2023 — Artificial Intelligence Management System (AIMS)

---

## Purpose

This document maps the FinSight–VeriGuard AI vendor arrangement to ISO/IEC 42001:2023 requirements relevant to third-party AI risk management. ISO/IEC 42001 is the first international standard for AI management systems — it provides a framework for organisations to responsibly develop, deploy, and govern AI systems.

While FinSight is not currently pursuing ISO 42001 certification, the standard provides a comprehensive reference for structuring third-party AI governance obligations. This mapping identifies which ISO 42001 controls address the VeriGuard procurement risks and how they have been incorporated into FinSight's contractual and governance framework.

---

## ISO/IEC 42001 Structure — Relevant Clauses for Third-Party AI Risk

ISO 42001 follows the ISO High-Level Structure (HLS) common to ISO 27001, ISO 9001, and ISO 14001. For third-party AI risk, the most relevant clauses are:

| Clause | Title | Third-Party AI Relevance |
|--------|-------|------------------------|
| 4.1 | Understanding the organisation and its context | External context — regulatory environment, vendor landscape |
| 4.2 | Understanding needs and expectations of interested parties | Vendor obligations as interested party |
| 5.2 | AI policy | Policy coverage of third-party AI |
| 6.1 | Actions to address AI risks and opportunities | Third-party AI risk identification and treatment |
| 8.4 | AI system impact assessment | Assessment of vendor AI system impact on FinSight and customers |
| 8.6 | AI system use | Controls on third-party AI system deployment |
| 9.1 | Monitoring, measurement, analysis and evaluation | Vendor performance monitoring |
| Annex A.6 | AI system lifecycle | Third-party system lifecycle governance |
| Annex B.7 | Third-party management | Specific third-party AI risk controls |

---

## Annex B.7 — Third-Party AI Risk Management (Primary Reference)

ISO/IEC 42001 Annex B.7 provides specific guidance on managing AI risks from third parties. This is the most directly applicable section for the VeriGuard procurement.

| B.7 Control | Requirement | FinSight Implementation | Document Reference |
|-------------|-------------|------------------------|-------------------|
| B.7.1 — AI supplier relationships | Establish policies and processes for AI supplier selection, assessment, and management | Vendor risk assessment conducted; DDQ issued; contractual controls defined | VAR-001 to VAR-012; CCR-005 |
| B.7.2 — AI supplier agreements | Include AI-specific obligations in supplier agreements covering security, transparency, performance, and governance | 15 contractual provisions recommended covering all AI-specific obligations | FINSIGHT-AI-CCR-005 |
| B.7.3 — AI system acquisition | Assess AI systems before procurement — risk, performance, bias, explainability | Vendor AI risk assessment completed with 12 identified risks | FINSIGHT-AI-VAR-001 |
| B.7.4 — Third-party data processing | Ensure third parties processing AI data meet equivalent standards | Data Processing Agreement required; APP obligations contractually imposed | FINSIGHT-AI-DSA-004 |
| B.7.5 — Monitoring third-party AI performance | Establish monitoring of third-party AI system performance | Monthly performance reports; quarterly bias monitoring; annual audit right | CCR-005 Provisions 6, 7, 9 |

---

## Full ISO 42001 Control Mapping — Third-Party Scope

### Clause 4 — Context of the Organisation

| Sub-Clause | Requirement | FinSight Status | Finding |
|------------|-------------|-----------------|---------|
| 4.1 | Determine external and internal issues relevant to AIMS — including vendor landscape | ⚠️ Partial | Vendor procurement context assessed in VAR-001; formal AIMS context document not yet produced |
| 4.2 | Identify interested parties and their requirements — VeriGuard as a key interested party | ⚠️ Partial | VeriGuard obligations identified in DDQ and contracts; not in formal interested parties register |
| 4.3 | Define AIMS scope — including third-party AI processing | ❌ Gap | FinSight has not yet defined an AIMS scope |

---

### Clause 5 — Leadership

| Sub-Clause | Requirement | FinSight Status | Finding |
|------------|-------------|-----------------|---------|
| 5.2 | AI policy must address third-party AI use | ❌ Gap | FinSight does not have an AI governance policy covering vendor AI procurement |
| 5.3 | Roles and responsibilities for third-party AI oversight | ⚠️ Partial | GRC Analyst and CISO assigned responsibility in this project; not formally documented in policy |

**Recommendation:** Develop a brief FinSight AI Vendor Governance Policy before the VeriGuard contract is executed — covering procurement criteria, assessment requirements, ongoing monitoring, and Board accountability.

---

### Clause 6 — Planning

| Sub-Clause | Requirement | FinSight Status | Finding |
|------------|-------------|-----------------|---------|
| 6.1.1 | AI risk assessment process | ✅ Compliant | Vendor AI risk assessment conducted using AS ISO 31000 methodology — FINSIGHT-AI-VAR-001 |
| 6.1.2 | AI risk treatment | ✅ Compliant | Treatment plans for all 12 risks with owners, timelines, and contractual implementation |
| 6.1.3 | Opportunities | ❌ Gap | AI opportunities from fraud detection not formally documented |
| 6.2 | AI objectives — third-party performance targets | ⚠️ Partial | SLAs defined in contract provisions; not framed as formal AIMS objectives |

---

### Clause 7 — Support

| Sub-Clause | Requirement | FinSight Status | Finding |
|------------|-------------|-----------------|---------|
| 7.2 | Competence — AI vendor assessment skills | ⚠️ Partial | GRC Analyst conducted assessment; AI-specific technical competency not formally assessed |
| 7.3 | Awareness — relevant staff aware of third-party AI risks | ❌ Gap | Operations team not yet briefed on AI fraud detection risks and limitations |
| 7.5 | Documented information — vendor assessment records | ✅ Compliant | Full documentation suite produced (6 documents) |

---

### Clause 8 — Operation

| Sub-Clause | Requirement | FinSight Status | Finding |
|------------|-------------|-----------------|---------|
| 8.4 | AI system impact assessment | ✅ Compliant | Impact assessed across customer harm, regulatory, privacy, and operational dimensions in VAR-001 |
| 8.6 | AI system use — controls on deployment | ⚠️ Partial | Deployment controls defined in contract provisions; internal operational controls not yet documented |

**ISO 42001 Clause 8.4 — AI System Impact Assessment**

ISO 42001 requires a structured impact assessment before deploying an AI system. For the VeriGuard procurement, the following impacts were assessed:

| Impact Dimension | Assessment | Reference |
|-----------------|------------|-----------|
| Customer financial harm (wrongful blocks) | 🔴 High — 340,000 customers at risk of false positive blocks | VAR-001 |
| Customer privacy harm (offshore processing) | 🔴 Critical — APP 8 obligations triggered | VAR-003; DSA-004 |
| Discriminatory outcomes (algorithmic bias) | 🟠 Medium — demographic bias testing not completed | VAR-007 |
| Regulatory non-compliance (CPS 234, Privacy Act) | 🔴 High — multiple gaps identified | CPS234-002 |
| Operational disruption (vendor failure) | 🟠 Medium — BCP requirements defined | VAR-008 |
| Reputational risk (AI errors, bias, unexplained decisions) | 🟠 Medium | VAR-002, VAR-007 |

---

### Clause 9 — Performance Evaluation

| Sub-Clause | Requirement | FinSight Status | Finding |
|------------|-------------|-----------------|---------|
| 9.1 | Monitoring — vendor AI performance | ✅ Compliant | Monthly performance reports and quarterly bias monitoring defined in contract | 
| 9.2 | Internal audit — third-party AI in scope | ⚠️ Partial | Audit right defined in contract; FinSight internal audit program not yet updated |
| 9.3 | Management review — third-party AI included | ❌ Gap | FinSight management review cycle does not yet include third-party AI vendor risk |

---

### Clause 10 — Improvement

| Sub-Clause | Requirement | FinSight Status | Finding |
|------------|-------------|-----------------|---------|
| 10.1 | Continual improvement — vendor governance | ⚠️ Partial | Annual vendor review defined; not formalised in a continual improvement process |
| 10.2 | Nonconformity and corrective action | ⚠️ Partial | Material breach provisions defined in contract; FinSight internal corrective action process not defined for vendor-side issues |

---

## ISO 42001 vs NIST AI RMF — Comparison for Third-Party AI

| Dimension | ISO/IEC 42001:2023 | NIST AI RMF 1.0 |
|-----------|-------------------|-----------------|
| Type | Certifiable management system standard | Voluntary guidance framework |
| Third-party coverage | Annex B.7 — specific third-party AI controls | GOVERN 4.1, 5.1 — organisational oversight of third-party AI |
| Risk methodology | Aligned to ISO 31000 risk management | Four-function framework (GOVERN, MAP, MEASURE, MANAGE) |
| Explainability | Referenced in Annex B.6 | MEASURE 2.6 — explainability as a measurable characteristic |
| Bias and fairness | Referenced in Annex B.2 | MAP 2.3, MEASURE 2.5 — dedicated bias measurement requirements |
| Audit and assurance | Clause 9.2 — internal audit; external certification | No certification pathway |
| Best for FinSight | Demonstrating governance maturity; regulatory alignment; contract structure | AI risk identification and measurement methodology |
| Combined use | Use ISO 42001 Annex B.7 for contract structure; use NIST AI RMF for risk assessment methodology | Combined approach applied in this project |

---

## ISO 42001 Compliance Gap Summary — FinSight Third-Party AI

| Clause | Status | Key Gap |
|--------|--------|---------|
| 4 — Context | ⚠️ Partial | No formal AIMS scope or interested parties register |
| 5 — Leadership | ❌ Gap | No AI vendor governance policy; no Board-level AI oversight for third-party AI |
| 6 — Planning | ✅ Strong | Risk assessment and treatment fully documented |
| 7 — Support | ⚠️ Partial | Staff awareness and competency not formally assessed |
| 8 — Operation | ✅ Strong | Impact assessment and deployment controls documented |
| 9 — Performance | ⚠️ Partial | Vendor monitoring defined; internal audit scope not updated |
| 10 — Improvement | ⚠️ Partial | Annual vendor review defined; formal improvement process absent |

**Priority actions for ISO 42001 alignment:**
1. Develop FinSight AI Vendor Governance Policy (Clause 5)
2. Update internal audit scope to include third-party AI vendors (Clause 9.2)
3. Include third-party AI vendor risk in FinSight management review (Clause 9.3)
4. Brief operations team on AI system risks and limitations (Clause 7.3)

---

*This document is part of a sample GRC portfolio project. All organisations and scenarios are fictional.*
