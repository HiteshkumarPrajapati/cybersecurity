# AI Incident Response Procedure — NovaMed Health

**Document ID:** NOVAMED-AI-IRP-005
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** CCIO / CIO
**Framework references:** NIST AI RMF (MANAGE 2.4) · ISO/IEC 42001:2023 Clause 10.2 · Privacy Act 1988 (AU) — NDB Scheme · NSQHS Standard 8 (Recognising and Responding to Acute Deterioration)

---

## 1. Purpose

This procedure defines NovaMed Health's structured response to incidents involving the AI-assisted Clinical Decision Support (CDS) platform. It establishes incident classification criteria, escalation paths, response actions, and post-incident review requirements — ensuring that AI system incidents are identified early, contained effectively, communicated appropriately, and remediated with documented corrective actions.

This procedure supplements NovaMed's existing clinical incident management framework (RISKMAN) and IT incident management process, providing the AI-specific decision logic and escalation paths that general frameworks do not address.

---

## 2. Incident Classification

### Priority Levels

| Priority | Classification | Description | Examples |
|----------|---------------|-------------|---------|
| **P1** | 🔴 Critical | Patient harm or near-miss directly or potentially attributable to an AI recommendation | Clinician acted on incorrect AI recommendation; patient adverse event; wrong diagnosis treatment pathway initiated |
| **P2** | 🟠 High | AI system producing unexpected, harmful, or systematically incorrect outputs; complete system failure during clinical hours | Model generating outputs outside validated clinical scope; system unavailable during a clinical shift; mass incorrect recommendations detected |
| **P3** | 🟡 Medium | Detectable performance degradation; bias threshold breach; vendor-side security incident; suspicious data access | Recommendation accuracy below threshold; demographic bias metric exceeded; vendor reports security event |
| **P4** | 🟢 Low | Minor anomalies; individual user-reported concerns; non-critical logging or display issues | Single unexpected output not causing harm; UI display error; user confusion about AI output interpretation |

---

## 3. Incident Response Team

| Role | Responsibility | Contact |
|------|---------------|---------|
| **AI System Owner (CCIO)** | Incident lead — all P1/P2 incidents | [CCIO contact] |
| **Chief Medical Officer** | Clinical impact assessment and patient safety decisions | [CMO contact] |
| **Chief Information Officer** | Technical containment and vendor coordination | [CIO contact] |
| **Privacy Officer** | Privacy Act / NDB assessment for data-related incidents | [Privacy Officer contact] |
| **Legal Counsel** | Medico-legal risk, regulatory notification advice | [Legal contact] |
| **Clinical Governance Lead** | Clinical incident integration and RISKMAN entry | [CG Lead contact] |
| **On-call IT Manager** | After-hours technical response | [IT Manager contact] |

---

## 4. Incident Detection Sources

| Source | Detection Method |
|--------|----------------|
| Clinician report | Staff reporting via RISKMAN or IT Service Desk |
| Automated monitoring | AI performance dashboard alerts (confidence score, acceptance rate, accuracy metrics) |
| Bias monitoring | Quarterly demographic stratification analysis |
| Vendor notification | Vendor contractual obligation — 24-hour notification for security incidents |
| Audit log review | Anomalous access patterns detected in AI system logs |
| Patient or family report | Complaint raised through Patient Relations |

---

## 5. Incident Response Workflow

### Step 1 — Detection and Initial Triage (0–1 hour for P1/P2)

```
Incident detected (any source)
          │
          ▼
Report submitted to AI System Owner (CCIO) AND IT Service Desk
          │
          ▼
AI System Owner performs initial triage:
  • What AI system is involved?
  • Is there current or potential patient harm?
  • Is the system currently active and generating recommendations?
  • How many patients / clinicians are affected?
          │
          ▼
Classify incident: P1 / P2 / P3 / P4
          │
          ├── P1/P2 → Step 2: Emergency Response
          ├── P3 → Step 3: Standard Response
          └── P4 → Step 4: Low Priority Response
```

---

### Step 2 — P1 / P2 Emergency Response

**Timeline:** P1 = immediate; P2 = within 4 hours

**2a — Immediate notification (P1 — within 1 hour)**

| Notify | Method |
|--------|--------|
| Chief Executive Officer | Direct call |
| Chief Medical Officer | Direct call |
| Chief Information Officer | Direct call |
| Privacy Officer | Direct call |
| Legal Counsel | Direct call |
| AISC Chair | Direct call |

**2b — AI system suspension assessment**

| Question | If YES | If NO |
|----------|--------|-------|
| Is the AI system currently generating recommendations that could cause patient harm? | Suspend AI system immediately | Continue with enhanced monitoring |
| Is the incident attributable to a model failure or incorrect output? | Suspend AI system pending investigation | Assess technical root cause first |
| Has the vendor confirmed a security breach affecting NovaMed patient data? | Suspend data flow to vendor immediately | Vendor investigation to proceed |

**Suspension process:**
1. CIO contacts vendor to suspend API connection
2. EHR team disables CDS module in clinical UI within 30 minutes of suspension decision
3. Clinical staff notified immediately — email and clinical management system announcement: *"The AI Clinical Decision Support tool has been temporarily suspended pending investigation. Please proceed with standard clinical assessment protocols."*
4. Suspension decision and time documented by AI System Owner

**2c — Clinical impact assessment (CMO)**

- Identify all patients whose care was potentially influenced by the incident output
- Assess whether any patients require clinical review or additional assessment
- Initiate clinical review for any patient where harm is suspected
- Document patient safety actions in RISKMAN under the clinical incident category

**2d — Privacy assessment (Privacy Officer)**

- Determine whether patient health data has been accessed, disclosed, or lost without authorisation
- If data breach suspected → initiate NDB assessment (30-day clock starts)
- Notify OAIC if eligible data breach determined (within 30 days of awareness)
- Notify affected patients as soon as practicable if NDB confirmed

---

### Step 3 — P3 Standard Response

**Timeline:** Initial response within 24 hours; resolution plan within 7 days

| Action | Responsible | Timeline |
|--------|-------------|----------|
| AI System Owner documents incident in AI risk register | CCIO | 24 hours |
| Vendor notified — written notice with incident description | CIO | 24 hours |
| Technical investigation commenced — logs reviewed, anomaly confirmed | CIO / Vendor | 48 hours |
| Root cause preliminary assessment | CCIO | 5 business days |
| AISC notified at next scheduled meeting (or earlier if urgent) | AISC Chair | Next AISC meeting |
| Corrective action plan developed | CCIO | 7 business days |
| Clinical staff informed if recommendation quality affected | CMO | As required |

---

### Step 4 — P4 Low Priority Response

**Timeline:** Resolution within 30 days

| Action | Responsible |
|--------|-------------|
| Log incident in IT Service Desk | Reporting staff member |
| AI System Owner reviews and classifies | CCIO |
| Vendor notified if technical issue requires vendor action | CIO |
| Resolution documented in AI system log | AI System Owner |
| Reviewed at next quarterly AI risk register review | CCIO |

---

## 6. Specific Incident Scenarios — Response Guides

### Scenario A — Clinician Reports Unexpected or Harmful AI Output

1. Clinician documents incident in RISKMAN immediately
2. Clinical Governance Lead notified — assesses for patient safety impact
3. AI System Owner notified — classifies as P1 (if patient harm) or P2 (if no harm but systemic risk)
4. Retrieve specific AI recommendation log — patient ID, timestamp, confidence score, recommendation content
5. CIO reviews model logs for similar outputs in past 24 hours — determine if isolated or systemic
6. If systemic → escalate to P1/P2 response and consider suspension
7. CMO determines if affected patients require clinical review

---

### Scenario B — Vendor Reports Security Incident

1. Vendor notification received (within 24-hour contractual obligation)
2. CIO and Privacy Officer notified immediately
3. Classify incident: Is NovaMed patient data likely affected?
   - **YES** → Suspend API connection immediately; escalate to P1
   - **UNCERTAIN** → Suspend API connection pending vendor clarification; treat as P2
   - **NO** → P3 response; monitor for 48 hours
4. Privacy Officer initiates NDB assessment if patient data affected
5. Legal Counsel engaged to assess vendor liability and regulatory notification obligations
6. Vendor required to provide written incident report within 72 hours
7. AI system not reconnected until vendor provides written confirmation that the security issue is resolved and patient data integrity is confirmed

---

### Scenario C — Bias Threshold Breach Detected

1. Quarterly bias monitoring report identifies demographic performance differential exceeding 10% threshold
2. AI System Owner (CCIO) notified immediately by data analyst
3. AISC convened within 10 business days
4. Vendor formally notified in writing — 5 business days to provide root cause analysis
5. AISC determines remediation option:
   - Vendor retraining with corrected dataset
   - Demographic-specific output suppression (interim measure)
   - Deployment suspension for affected use cases
6. Independent re-audit required before remediated model returned to clinical use
7. CMO reviews whether any clinical outcomes may have been affected during the period of bias
8. Board notified of breach, remediation, and outcome

---

### Scenario D — Model Performance Degradation (Drift)

1. Monthly monitoring dashboard identifies accuracy metric below defined threshold
2. AI System Owner reviews trend — single-month anomaly vs sustained degradation
3. Vendor notified — 5 business days to provide explanation and remediation plan
4. AI System Owner assesses whether:
   - Enhanced clinician caution notice should be displayed in UI
   - Specific clinical specialties or use cases should be suspended
   - Full deployment suspension is warranted
5. Clinicians notified if recommendation quality concern cannot be immediately resolved
6. AISC advised at next meeting
7. Model not returned to standard operation until performance benchmark confirmed restored

---

## 7. Post-Incident Review Requirements

| Incident Class | Review Required | Timeframe | Output |
|---------------|-----------------|-----------|--------|
| P1 | Full Root Cause Analysis (RCA) | 30 days | RCA report to AISC and Board |
| P2 | Structured incident review | 30 days | Incident review report to AISC |
| P3 | Standard post-incident report | 60 days | Summary to AISC |
| P4 | Documented in AI system log | 30 days | No formal report required |

### RCA Components (P1 incidents)

1. Chronological timeline of incident from first detection to resolution
2. Root cause determination — model failure, data issue, process gap, human factors, vendor failure
3. Patient impact assessment — clinical outcomes, regulatory obligations
4. Immediate corrective actions taken
5. Systemic contributing factors
6. Recommendations for permanent corrective action
7. Lessons learned
8. Update to AI risk register and governance policy if required

---

## 8. Communication Templates

### Clinical Staff Notification — AI System Suspension

**Subject: AI Clinical Decision Support Tool — Temporary Suspension**

> The AI Clinical Decision Support (CDS) tool has been temporarily suspended as of [TIME] on [DATE] while we investigate a reported issue. Please continue to apply standard clinical assessment protocols without AI support. This situation is being actively managed. Further communication will be provided within [TIMEFRAME]. If you have questions, contact [CCIO name and contact].

---

### Vendor Formal Notification — Security Incident

> **FORMAL INCIDENT NOTIFICATION**
> NovaMed Health is formally notifying [Vendor Name] of a reported security incident potentially affecting NovaMed patient data processed on the [Vendor Platform Name] platform. In accordance with Section [X] of our Data Processing Agreement, you are required to provide a written incident report within 72 hours of this notification. The API connection between NovaMed systems and your platform has been suspended pending investigation. Please contact [CIO name and contact] immediately to coordinate response.

---

## 9. Lessons Learned and Continuous Improvement

After every P1 and P2 incident, the AISC reviews:
- Were detection mechanisms adequate — could the incident have been identified earlier?
- Were escalation thresholds appropriate — was the response proportionate?
- Were vendor obligations met — notification timelines, incident support?
- Does the AI risk register need updating?
- Does this policy need amendment?
- Should the AI system's continued deployment be reviewed?

Lessons learned are documented in the AI system register and incorporated into the next policy review cycle.

---

*This document is part of a sample GRC portfolio project. NovaMed Health is a fictional organisation. All scenarios are created for professional skills demonstration.*
