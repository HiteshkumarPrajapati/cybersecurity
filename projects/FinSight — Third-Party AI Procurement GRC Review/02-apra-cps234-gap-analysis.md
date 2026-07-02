# APRA CPS 234 Gap Analysis — VeriGuard AI Vendor Arrangement

**Document ID:** FINSIGHT-AI-CPS234-002
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** Chief Compliance Officer / GRC Analyst
**Standard:** APRA Prudential Standard CPS 234 — Information Security
**Assessment Date:** 2025

---

## Purpose

This gap analysis assesses the proposed FinSight Analytics–VeriGuard AI vendor arrangement against the requirements of APRA Prudential Standard CPS 234 (Information Security). CPS 234 applies to all APRA-regulated entities and requires that information assets managed by or accessible to third parties are subject to the same level of information security governance as internally managed assets.

The analysis identifies specific paragraphs of CPS 234 that the proposed arrangement does not currently satisfy, documents the nature of each gap, and recommends remediation actions required before contract execution.

---

## APRA CPS 234 — Scope and Applicability

CPS 234 came into effect for all APRA-regulated entities on 1 July 2019. It applies to:
- ADIs (Authorised Deposit-taking Institutions)
- General and Life Insurers
- Private Health Insurers
- RSE Licensees (superannuation)
- Non-operating holding companies of the above

FinSight Analytics holds an AFSL and is regulated by APRA. CPS 234 applies in full.

**VeriGuard AI's role in CPS 234 context:** VeriGuard is a third-party service provider that will manage, process, and generate outputs from FinSight customer financial data — transaction records, account history, device fingerprints. Under CPS 234 Paragraph 15, FinSight must ensure this information asset receives protection consistent with CPS 234 requirements, regardless of where it is managed.

---

## Gap Analysis

### Paragraph 15 — Information Assets Managed by Third Parties

**CPS 234 Requirement:**
> "Where information assets are managed by a related party or third party, the APRA-regulated entity must assess the information security capability of those parties."

| Assessment Item | Current State | Gap | Severity |
|----------------|--------------|-----|----------|
| FinSight has assessed VeriGuard's information security capability | ISO 27001 certification claimed by vendor — scope not verified. No independent assessment conducted by FinSight. | ❌ Gap | 🔴 High |
| Information assets managed by VeriGuard are classified | Customer transaction data, account records, and device fingerprints transmitted to VeriGuard are not formally classified in FinSight's asset register | ❌ Gap | 🔴 High |
| Third-party risk assessment for VeriGuard is documented | No formal third-party risk assessment has been conducted or documented for this arrangement | ❌ Gap | 🔴 High |

**Remediation Required:**
1. Conduct formal vendor security assessment — obtain current ISO 27001 certificate with scope documentation; verify AI platform is within scope
2. Require SOC 2 Type II report or commission FinSight-funded independent security assessment
3. Add VeriGuard to FinSight's third-party risk register with formal risk rating
4. Classify all information assets to be shared with VeriGuard — assign sensitivity classification and data handling requirements

**Target Completion:** Before contract execution

---

### Paragraph 16 — Information Security Capability

**CPS 234 Requirement:**
> "An APRA-regulated entity must maintain information security capability commensurate with the size and extent of threats to its information assets, and which enables the continued sound operation of the entity."

| Assessment Item | Current State | Gap | Severity |
|----------------|--------------|-----|----------|
| FinSight's capability to oversee third-party AI security | FinSight has no dedicated AI security governance capability; no staff with AI security assessment skills | ⚠️ Partial | 🟠 Medium |
| Capability extends to AI-specific threats | No AI threat model exists for FinSight's use of external AI platforms | ❌ Gap | 🟠 Medium |
| Third-party AI risk included in FinSight risk management framework | VeriGuard risk not in FinSight risk register; no AI third-party risk policy | ❌ Gap | 🔴 High |

**Remediation Required:**
1. Develop third-party AI risk policy and integrate into FinSight's risk management framework
2. Assign internal responsibility for AI vendor oversight to GRC Analyst or CISO
3. Conduct AI threat modelling for fraud detection use case — document threat landscape relevant to AI-driven transaction monitoring
4. Include AI vendor risk in FinSight's annual risk assessment cycle

**Target Completion:** 60 days post-contract execution

---

### Paragraph 17 — Implementation of Controls

**CPS 234 Requirement:**
> "An APRA-regulated entity must implement controls to protect its information assets, including those managed by related parties or third parties, commensurate with identified vulnerabilities and threats."

| Assessment Item | Current State | Gap | Severity |
|----------------|--------------|-----|----------|
| Security controls defined for VeriGuard arrangement | No contractual security requirements drafted; vendor security obligations undefined | ❌ Gap | 🔴 High |
| Data encryption requirements specified | Encryption standards for data in transit and at rest not specified in proposed contract | ❌ Gap | 🔴 High |
| Access controls for FinSight data on vendor platform | Access control requirements not defined; who at VeriGuard can access FinSight data is unknown | ❌ Gap | 🔴 High |
| MFA requirement for vendor access to FinSight data | Not specified | ❌ Gap | 🟠 Medium |

**Remediation Required:**
1. Draft mandatory security schedule as a contractual exhibit — defining encryption standards (TLS 1.3 in transit, AES-256 at rest), access control requirements, MFA obligations, and privileged access management
2. Require vendor to document which personnel have access to FinSight data and under what controls
3. Prohibit vendor from accessing FinSight data without FinSight-approved Data Processing Agreement in place

**Target Completion:** Before contract execution

---

### Paragraph 18 — Board Responsibilities

**CPS 234 Requirement:**
> "The Board of an APRA-regulated entity is ultimately responsible for the entity's information security. The Board must ensure that the entity maintains information security commensurate with the size and extent of threats."

| Assessment Item | Current State | Gap | Severity |
|----------------|--------------|-----|----------|
| Board has been advised of VeriGuard procurement and associated information security risks | Board has not been briefed on this procurement | ❌ Gap | 🔴 High |
| Board risk appetite for third-party AI processing of customer data is defined | No Board-approved risk appetite statement covering third-party AI use | ❌ Gap | 🟠 Medium |

**Remediation Required:**
1. Present VeriGuard procurement risk summary to Board before contract execution — including this CPS 234 gap analysis
2. Obtain formal Board approval for engagement of third-party AI vendor for a critical function
3. Define and document Board risk appetite for third-party AI processing of customer financial data

**Target Completion:** Before contract execution

---

### Paragraph 21 — Notification to APRA

**CPS 234 Requirement:**
> "An APRA-regulated entity must notify APRA as soon as possible, and in any case within 72 hours, after becoming aware of an information security incident that has materially affected, or has the potential to materially affect, the entity or its customers."

| Assessment Item | Current State | Gap | Severity |
|----------------|--------------|-----|----------|
| Vendor breach notification SLA — vendor must notify FinSight within timeframe enabling APRA 72-hour notification | No breach notification SLA in proposed contract | ❌ Gap | 🔴 Critical |
| FinSight internal escalation process for vendor-initiated security incidents | No vendor-specific incident escalation procedure | ❌ Gap | 🔴 High |
| APRA notification process covers vendor-side incidents | FinSight's existing APRA notification procedure does not address third-party AI vendor incidents | ⚠️ Partial | 🔴 High |

**Remediation Required:**
1. Mandate 24-hour vendor breach notification in contract (required to enable FinSight's 72-hour APRA notification — allowing 48 hours for FinSight's own assessment and notification process)
2. Define vendor incident escalation path in FinSight's incident response procedure — including APRA notification decision logic for vendor-side incidents
3. Update FinSight APRA notification procedure to include third-party AI vendor breach scenarios

**Target Completion:** Before contract execution (contractual); 45 days post-execution (procedure update)

---

### Paragraph 36 — Testing Information Security Controls

**CPS 234 Requirement:**
> "An APRA-regulated entity must test the effectiveness of information security controls through a systematic testing program. The frequency and comprehensiveness of testing must be commensurate with the risk."

| Assessment Item | Current State | Gap | Severity |
|----------------|--------------|-----|----------|
| VeriGuard undergoes annual penetration testing | Vendor states annual penetration testing conducted — results not shared with clients | ⚠️ Partial | 🔴 High |
| FinSight has access to VeriGuard penetration test results | Not provided; not included in proposed contract | ❌ Gap | 🔴 High |
| FinSight can commission independent testing of VeriGuard platform | No audit or testing right in proposed contract | ❌ Gap | 🔴 High |
| AI model security testing (adversarial robustness, prompt injection, model extraction) | No evidence of AI-specific security testing by vendor | ❌ Gap | 🟠 Medium |

**Remediation Required:**
1. Contractual right for FinSight to receive annual penetration test results for the VeriGuard AI platform (summary report minimum, full report on request)
2. Contractual audit right — FinSight may commission independent security assessment of VeriGuard platform annually, with vendor cooperation
3. Require vendor to conduct AI-specific security testing — adversarial robustness, model extraction resistance — and provide results to FinSight
4. Include VeriGuard in FinSight's internal third-party control testing schedule

**Target Completion:** Before contract execution

---

### Paragraph 37 — Internal Audit

**CPS 234 Requirement:**
> "An APRA-regulated entity's internal audit function must provide independent assurance on the effectiveness of information security controls, including those maintained by related parties or third parties providing material services."

| Assessment Item | Current State | Gap | Severity |
|----------------|--------------|-----|----------|
| VeriGuard included in FinSight internal audit scope | FinSight's internal audit program does not include third-party AI vendor assurance | ❌ Gap | 🔴 High |
| Internal audit has access to vendor documentation for audit purposes | No contractual provision enabling vendor cooperation with FinSight's internal audit | ❌ Gap | 🔴 High |

**Remediation Required:**
1. Include VeriGuard arrangement in FinSight's annual internal audit scope from first year of operation
2. Contractual obligation for vendor to cooperate with FinSight's internal audit function — including document access and audit interviews as required
3. Define minimum audit evidence package — what documentation VeriGuard must produce annually for FinSight's internal audit

**Target Completion:** Before contract execution (contractual); Year 1 internal audit cycle

---

## CPS 234 Gap Summary

| Paragraph | Requirement | Gaps Found | Severity |
|-----------|------------|:-:|:-:|
| Para 15 | Third-party security assessment | 3 gaps | 🔴 High |
| Para 16 | Information security capability | 3 gaps | 🟠 Medium / High |
| Para 17 | Implementation of controls | 4 gaps | 🔴 High |
| Para 18 | Board responsibilities | 2 gaps | 🔴 High |
| Para 21 | APRA notification | 3 gaps | 🔴 Critical / High |
| Para 36 | Testing of controls | 4 gaps | 🔴 High |
| Para 37 | Internal audit | 2 gaps | 🔴 High |
| **Total** | | **21 gaps** | |

**Compliant paragraphs (no gaps):** None
**Partially compliant:** Para 16, Para 37 (internal audit program exists but does not extend to vendor)
**Non-compliant:** Paragraphs 15, 17, 18, 21, 36

---

## Overall CPS 234 Assessment

**Finding:** The proposed FinSight–VeriGuard arrangement, as currently structured, is **non-compliant with APRA CPS 234**.

Proceeding with contract execution without remediating the identified gaps — particularly Paragraphs 15, 17, 18, and 21 — would expose FinSight to regulatory enforcement action, including APRA supervisory escalation and potential direction from APRA to cease the arrangement.

**Recommendation:** Contract execution must not proceed until:
1. Board has been briefed and approved the engagement (Para 18)
2. Vendor security assessment is complete with verified ISO 27001 scope (Para 15)
3. Security schedule is included in the contract with encryption, access control, and MFA requirements (Para 17)
4. 24-hour breach notification SLA is included in the contract (Para 21)
5. Annual penetration test results and audit right are included in the contract (Para 36 / 37)

---

*This document is part of a sample GRC portfolio project. All organisations and scenarios are fictional.*
