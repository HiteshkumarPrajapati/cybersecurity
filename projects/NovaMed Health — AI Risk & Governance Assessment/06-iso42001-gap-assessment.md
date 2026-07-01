# ISO/IEC 42001:2023 Gap Assessment — NovaMed Health

**Document ID:** NOVAMED-AI-GAP-006
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** CCIO
**Assessment Date:** 2025
**Standard:** ISO/IEC 42001:2023 — Artificial Intelligence Management System (AIMS)

---

## Purpose

This gap assessment evaluates NovaMed Health's current state against the requirements of ISO/IEC 42001:2023 — the international standard for AI Management Systems. The assessment was conducted prior to deployment of the AI-assisted Clinical Decision Support (CDS) platform to identify control gaps, establish a remediation roadmap, and determine NovaMed's readiness to operate an AI system within a structured governance framework.

---

## Assessment Methodology

Each ISO/IEC 42001:2023 clause and control requirement was assessed against NovaMed's current documentation, policies, processes, and technical controls. Status is assigned as follows:

| Status | Symbol | Description |
|--------|--------|-------------|
| Compliant | ✅ | Requirement fully met — documented evidence available |
| Partial | ⚠️ | Requirement partially met — gaps identified; remediation required |
| Non-Compliant | ❌ | Requirement not met — no controls in place |
| Not Applicable | N/A | Requirement does not apply to NovaMed's AI scope |

---

## Gap Assessment Results

### Clause 4 — Context of the Organisation

#### 4.1 Understanding the Organisation and Its Context

**Requirement:** The organisation shall determine external and internal issues relevant to its purpose that affect its ability to achieve the intended outcomes of its AIMS.

| Item | Status | Finding |
|------|--------|---------|
| Internal context documented (organisational structure, governance, resources) | ⚠️ Partial | General organisational context documented in strategic plan; AI-specific context not formally captured |
| External context documented (regulatory environment, sector obligations, stakeholder expectations) | ❌ Non-Compliant | No formal assessment of TGA, Privacy Act, NSQHS, or APRA (if applicable) context as it relates to AI |
| AI-specific context analysis conducted | ❌ Non-Compliant | No AI context assessment documented |

**Remediation required:** Produce an AI context document identifying internal factors (governance maturity, clinical culture, technical capability) and external factors (TGA SaMD obligations, Privacy Act, NSQHS, health sector AI guidelines) relevant to the AIMS.

---

#### 4.2 Understanding Needs and Expectations of Interested Parties

**Requirement:** Determine interested parties and their requirements relevant to the AIMS.

| Item | Status | Finding |
|------|--------|---------|
| Interested parties identified | ⚠️ Partial | Clinical stakeholders and regulators identified in project plan; not documented in AIMS context |
| Requirements of interested parties documented | ❌ Non-Compliant | No formal interested parties register for AI governance |
| Compliance obligations mapped | ❌ Non-Compliant | TGA, Privacy Act, NSQHS obligations not mapped to AI system requirements |

**Remediation required:** Develop an interested parties register documenting patients, clinical staff, regulators (TGA, OAIC, AHPRA), the AISC, the Board, and the AI vendor — with their relevant requirements and expectations.

---

#### 4.3 Determining the Scope of the AIMS

**Requirement:** Determine the boundaries and applicability of the AIMS.

| Item | Status | Finding |
|------|--------|---------|
| AIMS scope document produced | ❌ Non-Compliant | No formal AIMS scope document exists |
| Scope covers the AI system lifecycle | ❌ Non-Compliant | No lifecycle boundary defined |
| Scope statement approved | ❌ Non-Compliant | Not applicable — scope document does not exist |

**Remediation required:** Produce a formal AIMS scope document covering the CDS platform from procurement through to retirement, including all facilities, data flows, and vendor interactions within scope.

---

### Clause 5 — Leadership

#### 5.1 Leadership and Commitment

**Requirement:** Top management shall demonstrate leadership and commitment to the AIMS.

| Item | Status | Finding |
|------|--------|---------|
| AI governance supported by executive leadership | ⚠️ Partial | CEO has approved CDS deployment; formal AIMS commitment not documented |
| Resources allocated to AIMS | ⚠️ Partial | Budget allocated to CDS deployment; ongoing AIMS resource allocation not formalised |
| AI governance integrated into organisational governance | ❌ Non-Compliant | AISC established but not formally chartered or integrated into Board governance |

**Remediation required:** CEO to sign AIMS commitment statement. AISC charter to be approved by Board. Ongoing AIMS resource allocation to be documented in operational budget.

---

#### 5.2 AI Policy

**Requirement:** Top management shall establish an AI policy appropriate to the organisation's purpose.

| Item | Status | Finding |
|------|--------|---------|
| AI governance policy exists | ⚠️ Partial | AI Governance Policy (NOVAMED-POL-AI-003) drafted; pending CEO approval |
| Policy covers AI principles — safety, transparency, fairness, accountability | ⚠️ Partial | Policy covers accountability and safety; explicit fairness and transparency principles not stated |
| Policy communicated to relevant staff | ❌ Non-Compliant | Policy not yet communicated — pending approval |
| Policy available to interested parties | ❌ Non-Compliant | Not yet published |

**Remediation required:** CEO to approve AI Governance Policy. Add explicit AI principles section (safety, fairness, transparency, accountability, human oversight). Communicate to all clinical and IT staff. Publish summary version for patients on NovaMed website.

---

#### 5.3 Roles, Responsibilities and Authorities

**Requirement:** Ensure that responsibilities for roles relevant to AI are assigned, communicated, and understood.

| Item | Status | Finding |
|------|--------|---------|
| AI System Owner appointed | ✅ Compliant | CCIO designated as AI System Owner — documented in AI Governance Policy |
| AISC established with documented terms of reference | ⚠️ Partial | AISC membership defined; formal ToR not yet approved |
| Clinician AI responsibilities documented | ⚠️ Partial | Responsibilities described in policy; not yet incorporated into role descriptions or employment contracts |
| Vendor accountability for AI obligations documented | ⚠️ Partial | Obligations defined in vendor contract draft; contract not yet executed |

**Remediation required:** Finalise and approve AISC Terms of Reference. Update clinical role descriptions to include AI system responsibilities. Execute vendor contract.

---

### Clause 6 — Planning

#### 6.1 Actions to Address AI Risks and Opportunities

**Requirement:** Determine risks and opportunities relevant to the AIMS and plan actions to address them.

| Item | Status | Finding |
|------|--------|---------|
| AI risk assessment methodology defined | ✅ Compliant | Risk assessment using NIST AI RMF and AS ISO 31000 methodology documented |
| AI risk register produced | ✅ Compliant | NOVAMED-AI-RR-001 completed with 10 identified risks, ratings, and treatment plans |
| Bias and fairness risks assessed | ✅ Compliant | NOVAMED-AI-BIAS-002 completed |
| Privacy risks assessed | ✅ Compliant | NOVAMED-AI-PIA-004 completed |
| Risk treatment plans have assigned owners and timelines | ✅ Compliant | All treatment actions in risk register have owners and target dates |
| Opportunities from AI identified | ❌ Non-Compliant | No formal documentation of AI opportunities (improved diagnostic speed, clinical workload reduction) |

**Remediation required:** Add AI opportunities assessment to AIMS documentation — clinical efficiency, diagnostic accuracy improvement, staff workload impacts.

---

#### 6.2 AI Objectives and Plans to Achieve Them

**Requirement:** Establish AI objectives and determine how to achieve them.

| Item | Status | Finding |
|------|--------|---------|
| AI system objectives defined | ⚠️ Partial | Clinical objectives for CDS defined in deployment proposal; not framed as AIMS objectives |
| Objectives are measurable | ⚠️ Partial | Recommendation accuracy benchmarks defined; broader AI governance KPIs not formalised |
| Plans to achieve objectives documented | ⚠️ Partial | Deployment plan exists; AIMS-specific achievement plans not structured |

**Remediation required:** Define formal AIMS objectives — safety, fairness, transparency, regulatory compliance — with measurable targets and documented plans. Align with KPIs in AI Governance Policy.

---

### Clause 7 — Support

#### 7.1 Resources

**Requirement:** Determine and provide resources needed for the AIMS.

| Item | Status | Finding |
|------|--------|---------|
| AIMS resource requirements identified | ⚠️ Partial | CDS deployment budget allocated; ongoing AIMS operational resources not formally assessed |
| AI competency resources identified | ⚠️ Partial | CCIO and CIO have relevant capability; no formal competency assessment conducted |

---

#### 7.2 Competence

**Requirement:** Determine necessary competence of persons doing AIMS work.

| Item | Status | Finding |
|------|--------|---------|
| AI competency requirements defined for key roles | ❌ Non-Compliant | No AI competency framework exists |
| Competency gaps assessed | ❌ Non-Compliant | No assessment conducted |
| Training to address gaps implemented | ❌ Non-Compliant | Clinician AI training planned but not yet delivered |

**Remediation required:** Define AI competency requirements for CCIO, CIO, clinical staff, and AISC members. Assess current competency against requirements. Deliver training program before go-live.

---

#### 7.3 Awareness

**Requirement:** Ensure relevant persons are aware of the AI policy and their contribution to AIMS effectiveness.

| Item | Status | Finding |
|------|--------|---------|
| Staff awareness of AI governance policy | ❌ Non-Compliant | Policy not yet communicated |
| Clinical staff trained on AI system use and limitations | ❌ Non-Compliant | Training program developed; delivery scheduled for pre-go-live |

---

#### 7.4 Communication

**Requirement:** Determine internal and external communication needs relevant to the AIMS.

| Item | Status | Finding |
|------|--------|---------|
| Internal communication plan for AI governance | ❌ Non-Compliant | No AIMS communication plan documented |
| Patient communication about AI use | ❌ Non-Compliant | Patient privacy notice not yet updated (APP 5 gap — linked) |
| Regulatory communication plan | ❌ Non-Compliant | No plan for proactive engagement with TGA, OAIC |

---

#### 7.5 Documented Information

**Requirement:** The AIMS shall include documented information required by the standard and determined necessary for AIMS effectiveness.

| Item | Status | Finding |
|------|--------|---------|
| AI risk register | ✅ Compliant | NOVAMED-AI-RR-001 |
| Bias and fairness assessment | ✅ Compliant | NOVAMED-AI-BIAS-002 |
| AI governance policy | ⚠️ Partial | Drafted — pending approval |
| Privacy impact assessment | ✅ Compliant | NOVAMED-AI-PIA-004 |
| Incident response procedure | ✅ Compliant | NOVAMED-AI-IRP-005 |
| AIMS scope document | ❌ Non-Compliant | Not produced |
| Interested parties register | ❌ Non-Compliant | Not produced |
| AI system register (inventory) | ❌ Non-Compliant | No formal AI system inventory maintained |

---

### Clause 8 — Operation

#### 8.1 Operational Planning and Control

**Requirement:** Plan, implement, control and maintain processes needed to meet AIMS requirements.

| Item | Status | Finding |
|------|--------|---------|
| AI system deployment checklist / approval gate | ✅ Compliant | Pre-deployment approval gate defined in AI Governance Policy Clause 5.1 |
| Change management process for AI | ⚠️ Partial | Model change management defined in policy; not yet tested or operationalised |
| AI system retirement process defined | ✅ Compliant | Defined in AI Governance Policy Clause 6.3 |

---

#### 8.4 AI System Impact Assessment

**Requirement:** Conduct an assessment of the impact of the AI system.

| Item | Status | Finding |
|------|--------|---------|
| Clinical impact assessment conducted | ⚠️ Partial | Clinical validation study planned; not yet completed |
| Societal impact assessment conducted | ❌ Non-Compliant | No formal societal impact assessment — equity and access implications not documented |
| Environmental impact considered | N/A | Not applicable to clinical AI in this context |

**Remediation required:** Complete clinical validation study. Produce a brief societal impact assessment covering equity of access, impact on patient populations, and implications for clinical workforce.

---

### Clause 9 — Performance Evaluation

#### 9.1 Monitoring, Measurement, Analysis and Evaluation

**Requirement:** Monitor, measure, analyse and evaluate AI management system performance.

| Item | Status | Finding |
|------|--------|---------|
| AI performance KPIs defined | ✅ Compliant | KPIs defined in AI Governance Policy — accuracy, acceptance rate, override rate, bias metrics |
| Monitoring schedule established | ✅ Compliant | Monthly and quarterly monitoring cadence defined |
| Reporting to management defined | ⚠️ Partial | AISC reporting defined; Board reporting cadence not yet formalised |

---

#### 9.2 Internal Audit

**Requirement:** Conduct internal audits to determine whether the AIMS conforms to requirements and is effectively implemented.

| Item | Status | Finding |
|------|--------|---------|
| Internal audit program established | ❌ Non-Compliant | No AIMS internal audit program — general clinical audit program exists |
| Audit criteria and scope defined | ❌ Non-Compliant | Not documented |
| Audit results reported to management | ❌ Non-Compliant | No AIMS-specific audit reporting |

**Remediation required:** Establish an annual AIMS internal audit program covering all ISO 42001 clause requirements. Assign audit responsibility (internal auditor or external specialist). Report results to AISC and Board.

---

#### 9.3 Management Review

**Requirement:** Top management shall review the AIMS at planned intervals.

| Item | Status | Finding |
|------|--------|---------|
| Management review of AIMS scheduled | ❌ Non-Compliant | No formal AIMS management review established |
| Review inputs defined | ❌ Non-Compliant | Not documented |
| Review outputs documented | ❌ Non-Compliant | Not documented |

**Remediation required:** Integrate AIMS management review into existing Board and Executive governance calendar — bi-annual recommended. Define standard review inputs (risk register status, KPIs, incidents, audit results, regulatory updates).

---

### Clause 10 — Improvement

#### 10.1 Continual Improvement

**Requirement:** Continually improve the suitability, adequacy and effectiveness of the AIMS.

| Item | Status | Finding |
|------|--------|---------|
| Continual improvement process defined | ⚠️ Partial | Post-incident review and quarterly risk register review defined; not formally linked to AIMS improvement cycle |
| Improvement actions tracked | ⚠️ Partial | AI risk register treatment plans tracked; no formal AIMS improvement register |

---

#### 10.2 Nonconformity and Corrective Action

**Requirement:** React to nonconformities and take corrective action.

| Item | Status | Finding |
|------|--------|---------|
| Nonconformity and corrective action process defined | ⚠️ Partial | Incident response procedure covers P1-P4 incidents; formal nonconformity process not documented separately |
| Corrective actions tracked to closure | ⚠️ Partial | AI risk register treatment tracking in place; formal corrective action register not established |

**Remediation required:** Establish a formal AI corrective action register. Define nonconformity categories (policy breach, control failure, incident, audit finding). Document tracking and closure verification process.

---

## Gap Assessment Summary

| Clause | Compliant | Partial | Non-Compliant | N/A |
|--------|:---------:|:-------:|:-------------:|:---:|
| 4 — Context | 0 | 1 | 5 | 0 |
| 5 — Leadership | 1 | 4 | 3 | 0 |
| 6 — Planning | 5 | 2 | 1 | 0 |
| 7 — Support | 0 | 2 | 5 | 0 |
| 8 — Operation | 2 | 1 | 1 | 1 |
| 9 — Performance | 2 | 2 | 4 | 0 |
| 10 — Improvement | 0 | 3 | 1 | 0 |
| **Total** | **10** | **15** | **20** | **1** |

**Overall Compliance: 22% Compliant — Not ready for deployment under ISO 42001 requirements**

---

## Remediation Roadmap

| Priority | Action | Owner | Timeline |
|----------|--------|-------|----------|
| 🔴 Critical | TGA SaMD classification assessment | Legal / CCIO | 30 days — blocks deployment |
| 🔴 Critical | Patient privacy notice and consent updated | Privacy Officer | 30 days — blocks deployment |
| 🔴 Critical | AI Governance Policy approved and communicated | CEO / CCIO | 30 days |
| 🔴 High | AIMS scope document produced | CCIO | 45 days |
| 🔴 High | Interested parties register completed | CCIO | 45 days |
| 🔴 High | AISC Terms of Reference approved | AISC Chair | 45 days |
| 🔴 High | Clinician AI training delivered | CMO / HR | Before go-live |
| 🟠 Medium | AI competency framework developed | CCIO / HR | 60 days |
| 🟠 Medium | AIMS internal audit program established | CCIO | 60 days |
| 🟠 Medium | AIMS management review integrated into Board calendar | CEO | 60 days |
| 🟠 Medium | AI corrective action register established | CCIO | 60 days |
| 🟠 Medium | Societal impact assessment completed | CCIO | 90 days |
| 🟡 Low | AI opportunities assessment documented | CCIO | 90 days |
| 🟡 Low | AIMS communication plan produced | CCIO | 90 days |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| ISO/IEC 42001:2023 standard | Gap assessment criteria |
| Conformio | AIMS documentation management and gap tracking |
| Microsoft Purview AI Hub | AI governance monitoring and policy management |
| Confluence | AIMS documentation repository |
| Vanta | Compliance monitoring and evidence collection |
| OneTrust | Privacy compliance and PIA workflow |

---

*This document is part of a sample GRC portfolio project. NovaMed Health is a fictional organisation. All scenarios are created for professional skills demonstration.*
