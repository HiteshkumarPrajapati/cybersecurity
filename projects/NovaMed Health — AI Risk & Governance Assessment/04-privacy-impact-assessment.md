# Privacy Impact Assessment — NovaMed Health CDS AI Platform

**Document ID:** NOVAMED-AI-PIA-004
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** Privacy Officer
**Reviewed By:** Legal Counsel, CCIO
**Framework references:** Privacy Act 1988 (AU) · Australian Privacy Principles (APPs 1–13) · OAIC PIA Guide · Notifiable Data Breaches Scheme

---

## 1. Purpose and Background

This Privacy Impact Assessment (PIA) evaluates the privacy risks associated with NovaMed Health's deployment of an AI-assisted Clinical Decision Support (CDS) platform. The CDS system processes sensitive patient health information — classified as sensitive information under the Privacy Act 1988 — to generate ranked diagnosis recommendations for clinical staff.

This PIA was commissioned to fulfil NovaMed's obligations under **APP 1.2**, which requires APP entities to take reasonable steps to implement practices, procedures, and systems that ensure compliance with the APPs. The OAIC recommends PIAs for all projects involving new or changed use of personal information, particularly sensitive information.

---

## 2. Data Flow Assessment

### 2.1 Data Collected and Processed

| Data Type | Classification | Volume | Sensitivity |
|-----------|---------------|--------|-------------|
| Patient name and date of birth | Personal information | Per consultation | Standard |
| Patient medical record number | Personal information | Per consultation | Standard |
| Presenting symptoms | Health information | Per consultation | **Sensitive** |
| Medical history — diagnoses, medications, allergies | Health information | Per consultation | **Sensitive** |
| Diagnostic test results (pathology, imaging) | Health information | Per consultation | **Sensitive** |
| Vital signs | Health information | Per consultation | **Sensitive** |
| Treating clinician ID | Personal information | Per consultation | Standard |
| AI recommendation output | Derived health information | Per consultation | **Sensitive** |

**Classification determination:** All patient health data processed by the CDS system is classified as **sensitive information** under Section 6 of the Privacy Act 1988. The higher standard of protection under the APPs applies.

---

### 2.2 Data Flow Diagram

```
[Patient presents at NovaMed facility]
          │
          ▼
[Clinical staff enters patient data into EHR — Cerner/Epic]
          │
          ▼ (API — encrypted TLS 1.3)
[CDS AI Platform — vendor-hosted (Australian data centre)]
          │
          ├──→ [AI model processes patient data]
          │
          ├──→ [Ranked diagnosis recommendations generated]
          │
          ▼ (API response — encrypted TLS 1.3)
[CDS output displayed in EHR to treating clinician]
          │
          ▼
[Clinician reviews, applies clinical judgment, documents decision]
          │
          ▼
[Patient care pathway proceeds — clinician decision documented in EHR]
```

**Data residency:** Vendor-hosted infrastructure must be located in Australia. Cross-border transfer of patient health data is not permitted without an APP 8 cross-border disclosure assessment and patient consent.

---

## 3. Australian Privacy Principles Assessment

### APP 1 — Open and Transparent Management of Personal Information

**Requirement:** NovaMed must have a clearly expressed and up-to-date privacy policy covering how it manages personal information, including AI-based processing.

**Current state:** NovaMed's existing privacy policy does not disclose the use of AI systems to process patient health information.

**Gap identified:** ⚠️ Non-compliant

**Required action:** Update the NovaMed Privacy Policy to explicitly state that:
- Patient health information may be processed by AI-based clinical decision support tools
- The purpose of AI processing is to assist treating clinicians with diagnosis recommendations
- AI processing does not replace clinical judgment or decision-making authority
- Patients have the right to request that their information not be processed by AI systems (see APP 12)

**Timeline:** Before CDS system go-live
**Responsible:** Privacy Officer / Legal Counsel

---

### APP 3 — Collection of Solicited Personal Information

**Requirement:** NovaMed may only collect health information that is reasonably necessary for its functions or activities — in this case, clinical care.

**Current state:** The CDS system is configured to receive a broad data feed from the EHR including all historical patient data.

**Gap identified:** ⚠️ Potential over-collection

**Assessment:** Not all historical patient data may be reasonably necessary for the CDS tool's diagnosis support function. For example, administrative fields, historical billing information, and data outside the presenting complaint clinical context may not be required.

**Required action:** Conduct data minimisation review with vendor — define the minimum dataset required for AI model input. Remove all fields not directly relevant to the CDS function. Document the justification for each data field included.

**Timeline:** 45 days pre-deployment
**Responsible:** CCIO / Privacy Officer

---

### APP 5 — Notification of Collection

**Requirement:** At or before the time of collection, NovaMed must take reasonable steps to notify patients of how their information will be used, including AI-based processing.

**Current state:** Standard patient admission form does not reference AI processing.

**Gap identified:** ⚠️ Non-compliant

**Required action:**
1. Update patient admission consent and privacy notice to include clear, plain-language disclosure of AI processing
2. Implement patient-facing communication explaining what the CDS tool does, what data it uses, and that clinical staff make all final decisions
3. Ensure patients are informed of their right to discuss AI use with their treating clinician

**Recommended notice language:**
> *"NovaMed Health uses AI-assisted tools to help our clinical teams with diagnosis recommendations. These tools analyse your health information to provide ranked suggestions that our doctors review and assess. Our clinical staff make all final decisions about your care. Your health information will not be shared with third parties for purposes other than your direct care."*

**Timeline:** Before go-live
**Responsible:** Privacy Officer / Patient Administration

---

### APP 6 — Use or Disclosure of Personal Information

**Requirement:** NovaMed may only use or disclose health information for the primary purpose of collection — clinical care — or a directly related secondary purpose.

**Assessment:**
- ✅ Using patient data to generate diagnosis recommendations for treating clinicians: **Permitted** — directly related to primary purpose
- ❌ Vendor using patient data for model retraining: **Not permitted** without explicit patient consent
- ❌ Sharing AI recommendation outputs with parties not involved in patient's direct care: **Not permitted**
- ⚠️ Aggregated de-identified data for model improvement: Requires separate de-identification assessment

**Required action:** Vendor contract must explicitly prohibit use of NovaMed patient data for model training, benchmarking, or any purpose beyond delivering the contracted CDS service. This must be a termination-for-cause clause.

**Timeline:** Contract execution — before deployment
**Responsible:** Legal Counsel / Privacy Officer

---

### APP 7 — Direct Marketing

**Assessment:** Not applicable — patient health data processed by the CDS system will not be used for direct marketing purposes. This prohibition must be explicitly stated in the vendor contract.

---

### APP 8 — Cross-Border Disclosure

**Requirement:** Before disclosing personal information to an overseas recipient, NovaMed must take reasonable steps to ensure the recipient does not breach the APPs.

**Assessment:** The vendor's infrastructure must be assessed for data residency. If any patient data is processed, stored, or accessible from servers outside Australia:
- APP 8 cross-border disclosure assessment is required
- Patient must be notified
- Contractual protections equivalent to APPs must be in place

**Required action:** Confirm with vendor in writing that all patient data remains on Australian-based infrastructure. Obtain contractual commitment to Australian data residency. If any offshore processing identified — halt deployment pending APP 8 assessment.

**Timeline:** Contract due diligence — before deployment
**Responsible:** CIO / Privacy Officer / Legal

---

### APP 11 — Security of Personal Information

**Requirement:** NovaMed must take reasonable steps to protect health information from misuse, interference, loss, unauthorised access, modification, or disclosure.

**Current state:** Standard EHR security controls in place. AI system integration introduces new data flow that has not been security-assessed.

**Gap identified:** ⚠️ New data flow requires security assessment

**Required actions:**

| Control | Requirement | Status |
|---------|-------------|--------|
| Encryption in transit | TLS 1.3 for all data between EHR and AI platform | To be confirmed with vendor |
| Encryption at rest | AES-256 for all patient data stored by AI system | To be confirmed with vendor |
| Access controls | Role-based access — CDS output visible only to treating clinician | To be implemented |
| Audit logging | All access to patient data via AI system logged and reviewable | To be implemented |
| Vendor security certification | ISO 27001 or SOC 2 Type II required | To be verified |
| Penetration testing | AI platform included in annual penetration test scope | To be confirmed |

**Timeline:** Before deployment
**Responsible:** CIO / Privacy Officer

---

### APP 12 — Access to Personal Information

**Requirement:** Patients have the right to access their personal information held by NovaMed, including information processed by AI systems.

**Assessment:** AI recommendation outputs constitute derived health information and are subject to APP 12 access rights. NovaMed must be able to retrieve and provide AI recommendation outputs associated with a specific patient on request.

**Required action:** Confirm with vendor that AI recommendation outputs for individual patients can be retrieved in a format suitable for patient access requests. Ensure AI system logs are retained for 7 years in accordance with healthcare records legislation.

**Timeline:** Before deployment
**Responsible:** Privacy Officer / CCIO

---

### APP 13 — Correction of Personal Information

**Requirement:** If a patient requests correction of personal information that was inaccurate, NovaMed must take reasonable steps to correct it.

**Assessment:** If incorrect patient data was input into the AI system and generated a flawed recommendation, NovaMed must have a process to correct the source data and assess whether the flawed recommendation requires clinical review.

**Required action:** Define process for data correction affecting AI inputs — including clinical review of any recommendations generated from incorrect data.

**Timeline:** 60 days post-deployment
**Responsible:** Privacy Officer / CMO

---

## 4. Notifiable Data Breaches (NDB) Scheme Assessment

### Triggering Conditions

A data breach involving AI-processed patient health information would constitute an **eligible data breach** under the NDB scheme if:
- There is unauthorised access to or disclosure of patient health information processed by the CDS system, AND
- A reasonable person would conclude the breach is likely to result in serious harm to affected individuals

Given that the data involved is sensitive health information, the threshold for serious harm is readily met.

### NDB Obligations

| Obligation | Requirement | NovaMed Readiness |
|-----------|-------------|------------------|
| 30-day assessment period | Assess whether eligible data breach occurred within 30 days of becoming aware | ⚠️ Requires AI-specific incident assessment process |
| OAIC notification | Notify OAIC as soon as practicable after determining eligible data breach | ⚠️ NDB notification process requires update for AI incidents |
| Individual notification | Notify affected individuals as soon as practicable | ⚠️ Patient notification template to be developed |
| Vendor breach notification | Vendor must notify NovaMed within 24 hours of becoming aware | ✅ To be included in vendor contract |

**Required action:** Integrate AI system data breach scenarios into NovaMed's NDB assessment and notification process. AI-specific breach scenarios (vendor-side breach, unauthorised access to AI platform, data exfiltration via API) must be included in the incident response procedure.

---

## 5. PIA Risk Summary

| Privacy Risk | APP Reference | Severity | Status |
|-------------|---------------|:--------:|--------|
| Privacy policy not updated for AI processing | APP 1 | 🔴 High | Action required before go-live |
| Patient consent not updated for AI processing | APP 5 | 🔴 High | Action required before go-live |
| Over-collection of patient data | APP 3 | 🟠 Medium | Data minimisation review required |
| Vendor use of data for model training | APP 6 | 🔴 High | Contractual prohibition required |
| Cross-border data transfer not assessed | APP 8 | 🔴 High | Vendor data residency confirmation required |
| AI data flow not security-assessed | APP 11 | 🔴 High | Security assessment required before go-live |
| Patient access rights to AI outputs | APP 12 | 🟠 Medium | Log retention and retrieval confirmed with vendor |
| NDB process not updated for AI incidents | NDB Scheme | 🔴 High | AI incident scenarios to be added to NDB process |

**PIA outcome:** Deployment must not proceed until all 🔴 High items are resolved. Medium items must have documented remediation plans in place at go-live.

---

## 6. Tools Used

| Tool | Purpose |
|------|---------|
| OneTrust | PIA workflow management and documentation |
| OAIC Privacy Impact Assessment Guide (2014) | Methodology and APP assessment framework |
| Microsoft Purview Compliance Portal | Data classification and privacy policy management |
| Confluence | Policy documentation and stakeholder review workflow |

---

*This document is part of a sample GRC portfolio project. NovaMed Health is a fictional organisation. All scenarios are created for professional skills demonstration.*
