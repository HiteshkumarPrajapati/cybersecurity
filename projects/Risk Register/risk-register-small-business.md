# Cyber Risk Register — Harrow & Bell Accounting (Fictional Small Accounting Firm)

**Entity profile:** Harrow & Bell is a fictional 18-person accounting and tax advisory firm operating across two offices in Victoria, Australia. Services include tax lodgement, bookkeeping, payroll processing, and SMSF administration for ~600 individual and small-business clients. IT environment is Microsoft 365-based with a legacy on-premises file server, an outsourced part-time IT provider (no in-house IT/security role), and a cloud-based practice management/tax software platform.

**Assessment date:** July 2026 · **Assessed by:** GRC Analyst (portfolio exercise) · **Next review:** Quarterly
**Rating scale, matrix, and methodology:** see [`notes/risk-rating-methodology.md`](notes/risk-rating-methodology.md)

**Context note:** Accounting and professional services firms are a consistently high-value target for Australian cybercriminals given their access to client TFNs, bank details, and trust account information — and typically operate with far lower security maturity and budget than the SaaS provider in this portfolio's companion register. This register reflects that reality: fewer sophisticated controls exist today, so more inherent risk carries through to residual risk, and treatment recommendations are deliberately scoped to be achievable for a firm of this size and budget.

---

## Summary dashboard

| Risk ID | Risk Title | Category | Inherent | Residual | Treatment | Owner | Status |
|---|---|---|---|---|---|---|---|
| HB-R01 | Business email compromise leading to fraudulent payment | Cyber / Social Engineering | Extreme (20) | High (12) | Mitigate | Practice Manager | Open |
| HB-R02 | Ransomware encrypting the on-premises file server | Cyber / Malware | Extreme (20) | High (15) | Mitigate | Principal / Director | Open |
| HB-R03 | Loss or theft of an unencrypted staff laptop | Physical / Data Loss | High (12) | Medium (6) | Mitigate | Practice Manager | Open |
| HB-R04 | No MFA enforced on Microsoft 365 email accounts | Cyber / Identity | Extreme (16) | Medium (8) | Mitigate | Practice Manager | In Progress |
| HB-R05 | Client PII/TFN data sent via unencrypted email | Data Handling | High (12) | Medium (8) | Mitigate | All Client-Facing Staff | Open |
| HB-R06 | Breach at third-party payroll/tax software vendor | Third-Party Risk | High (12) | Medium (6) | Mitigate | Practice Manager | Open |
| HB-R07 | Low staff security awareness / no formal training | People | High (12) | Medium (8) | Mitigate | Practice Manager | Open |
| HB-R08 | Lack of segregation of duties in accounting/banking systems | Fraud / Internal Control | High (12) | Medium (6) | Mitigate | Principal / Director | Open |
| HB-R09 | No documented or tested incident response plan | Governance | High (12) | Medium (6) | Mitigate | Principal / Director | Open |
| HB-R10 | Unauthorised physical access to office / paper records | Physical Security | Medium (8) | Low (4) | Mitigate | Practice Manager | Open |
| HB-R11 | End-of-life legacy tax software still in use | Cyber / Vulnerability Mgmt | High (12) | Medium (8) | Mitigate | Principal / Director | Open |
| HB-R12 | Backup failure / no offsite or tested backups | Business Continuity | High (15) | Medium (8) | Mitigate | Outsourced IT Provider | Open |

**Portfolio view:** 3 Extreme, 9 High inherent risks; after crediting existing (limited) controls, residual sits at 0 Extreme, 1 High, 10 Medium, 1 Low. The single remaining High residual risk (HB-R02, ransomware) reflects the firm's genuine current exposure and is escalated to the Principal for priority action and Board/Director-equivalent visibility, consistent with AS ISO 31000 escalation expectations for risks above appetite.

---

## HB-R01 — Business email compromise leading to fraudulent payment

**Risk description:** If a staff member's email account is compromised, or a client/supplier email is spoofed, an attacker could impersonate a client, supplier, or the Principal to request an urgent change to bank details or an out-of-cycle payment — a well-documented and high-loss scam pattern against Australian accounting firms specifically because of their trusted position in client financial transactions.

**Threat / Vulnerability:** External cybercriminal using social engineering / business email compromise (BEC); no MFA currently enforced (see HB-R04) significantly raises the likelihood of a successful account compromise as the entry point.

**Existing controls:** Informal practice of "checking with the boss" before large payments, but not documented or consistently followed; no dual-authorisation control in online banking; no callback verification policy for bank detail changes.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 5 – Severe | **Extreme (20)** |
| **Residual** | 3 – Possible | 4 – Major | **High (12)** |

**Framework mapping:**
- ACSC Essential Eight: *Multi-Factor Authentication* (ML0 — not enforced; directly relevant, see HB-R04), *User Application Hardening*
- ISO/IEC 27001:2022 Annex A: A.5.14 (Information transfer), A.6.3 (Awareness, education and training)

**Treatment recommendation (Mitigate):**
1. Implement a mandatory, documented policy: no bank detail changes or out-of-cycle payments are actioned without a verbal callback to a known, independently sourced phone number.
2. Enforce dual authorisation for all outgoing payments above a defined threshold (e.g. $2,000) in online banking.
3. Enforce MFA on all email accounts (see HB-R04) as the highest-leverage single control to reduce the likelihood of this risk.

**Owner:** Practice Manager · **Target date:** Within 30 days (low-cost, high-impact — prioritised ahead of other treatments) · **Status:** Open

---

## HB-R02 — Ransomware encrypting the on-premises file server

**Risk description:** If ransomware infects the firm's on-premises file server — which holds working papers, client financial records, and archived tax returns — the firm could lose access to critical client data, be unable to meet lodgement deadlines, and face a significant business interruption during peak tax season.

**Threat / Vulnerability:** Commodity ransomware delivered via phishing or an exposed remote access service (e.g. RDP); the on-premises server is ageing, has known unpatched vulnerabilities, and sits on the same flat network as staff workstations with no segmentation.

**Existing controls:** Basic antivirus (Windows Defender) on the server and workstations; outsourced IT provider applies patches on an ad hoc, reactive basis rather than a defined schedule; local nightly backup to an attached NAS device (not offsite — see also HB-R12).

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 5 – Severe | **Extreme (20)** |
| **Residual** | 3 – Possible | 5 – Severe | **High (15)** |

**Framework mapping:**
- ACSC Essential Eight: *Patch Operating Systems* (ML0 — reactive/ad hoc), *Restrict Administrative Privileges* (ML0), *Regular Backups* (ML0 — no offsite/immutable copy), *Application Control* (ML0 — not implemented)
- ISO/IEC 27001:2022 Annex A: A.8.7 (Protection against malware), A.8.13 (Information backup), A.8.20 (Networks security)

**Treatment recommendation (Mitigate):**
1. **Highest priority:** implement an offsite/cloud, immutable backup separate from the local NAS, specifically to survive a ransomware event that also encrypts attached storage (directly linked to HB-R12).
2. Formalise a monthly patch schedule with the outsourced IT provider, contractually specifying critical-patch turnaround (e.g. 7 days).
3. Segment the network so workstations and the file server are not on a single flat VLAN, limiting lateral spread of any infection.
4. Evaluate migrating file storage to SharePoint/OneDrive (already licensed via Microsoft 365) to retire the on-premises server entirely and gain built-in versioning and ransomware recovery features — a realistic, budget-appropriate option for a firm this size.

**Owner:** Principal / Director (budget approval required) · **Target date:** Q3 2026 for backup remediation (Priority 1); Q4 2026 for network segmentation / server retirement decision · **Status:** Open — **escalated to Principal given residual rating remains High**

---

## HB-R03 — Loss or theft of an unencrypted staff laptop

**Risk description:** If a staff laptop containing locally cached client financial data is lost or stolen (e.g. from a car, café, or during travel between the firm's two offices) and the device is not encrypted, an unauthorised party could access client tax file numbers, bank details, and financial records directly from the device.

**Threat / Vulnerability:** Opportunistic theft or simple loss; device encryption status is inconsistent across the fleet as laptops were purchased at different times without a standard build process.

**Existing controls:** Some newer laptops have BitLocker enabled by default (Windows 11 devices); older devices (approx. 6 of 18) have not been confirmed encrypted; no formal mobile device management (MDM) solution to remotely wipe a lost device.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 3 – Moderate | **Medium (6)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.8.24 (Use of cryptography), A.7.9 (Security of assets off-premises), A.8.1 (User endpoint devices)

**Treatment recommendation (Mitigate):**
1. Confirm and enforce BitLocker (or equivalent) full-disk encryption on all firm laptops as a mandatory baseline before any device is issued for client work.
2. Deploy Microsoft Intune (included in most Microsoft 365 Business Premium licences, which the firm should confirm it holds) to enable remote wipe of lost/stolen devices.
3. Introduce a simple asset register tracking encryption status, ownership, and last-seen date for every firm device.

**Owner:** Practice Manager (with outsourced IT provider) · **Target date:** Q3 2026 · **Status:** Open

---

## HB-R04 — No MFA enforced on Microsoft 365 email accounts

**Risk description:** If MFA is not enforced and a staff member's Microsoft 365 password is compromised (via phishing, credential stuffing, or password reuse from an unrelated breach), an attacker can log directly into that mailbox, read historical client correspondence, and use it to launch further attacks (see HB-R01) — this is consistently the single most common initial access point in real-world accounting firm breaches reported to the ACSC.

**Threat / Vulnerability:** Credential compromise via phishing or reused/breached passwords; MFA is available within the firm's Microsoft 365 licence but has not been switched on tenant-wide.

**Existing controls:** Standard Microsoft 365 password complexity requirements; no Conditional Access policies configured; MFA technically available but not enforced for any user.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 4 – Major | **Extreme (16)** |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ACSC Essential Eight: *Multi-Factor Authentication* (ML0 currently — target ML2 minimum)
- ISO/IEC 27001:2022 Annex A: A.8.5 (Secure authentication), A.5.17 (Authentication information)

**Treatment recommendation (Mitigate):**
1. Enable Microsoft 365 Security Defaults or a Conditional Access policy to enforce MFA for all users tenant-wide — this is a no-additional-licence-cost change and should be treated as the single highest-priority, lowest-cost action in this entire register.
2. Communicate the change to staff with brief guidance on setting up the Microsoft Authenticator app ahead of enforcement to minimise disruption.
3. Extend MFA enforcement to the practice management and tax software platform login where supported.

**Owner:** Practice Manager · **Target date:** Within 14 days (no cost, minimal effort — prioritise immediately) · **Status:** In Progress

---

## HB-R05 — Client PII/TFN data sent via unencrypted email

**Risk description:** If staff routinely email client tax file numbers, bank statements, or identity documents as plain attachments over standard email (as is common practice for efficiency during tax season), that data is exposed to interception risk and creates a durable, searchable record of sensitive data sitting in mailboxes indefinitely — increasing the impact of any future mailbox compromise (see HB-R04).

**Threat / Vulnerability:** Standard business practice that predates a documented secure-file-transfer policy; no client portal currently in use for document exchange.

**Existing controls:** None specific — this is standard current practice at the firm; general awareness among senior staff that this isn't best practice, but no policy or alternative tool has been provided to change the behaviour.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 3 – Moderate | **High (12)** |
| **Residual** | 3 – Possible | 3 – Moderate | **Medium (8)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.5.14 (Information transfer), A.5.34 (Privacy and protection of PII), A.8.24 (Use of cryptography)
- Regulatory reference: *Privacy Act 1988 (Cth)*, Australian Privacy Principle 11 (security of personal information)

**Treatment recommendation (Mitigate):**
1. Implement a client document portal (many practice management platforms include one, or a low-cost add-on is available) as the default channel for exchanging sensitive documents, replacing email attachments.
2. Where email must be used in the interim, mandate password-protected/encrypted attachments (e.g. via Microsoft 365 Message Encryption, already licensed) as a minimum standard.
3. Set a mailbox retention/auto-archive policy so sensitive attachments are not retained indefinitely in active mailboxes beyond what is required.

**Owner:** All client-facing staff (policy owned by Practice Manager) · **Target date:** Q4 2026 (portal rollout); immediate for encrypted-email interim measure · **Status:** Open

---

## HB-R06 — Breach at a third-party payroll or tax software vendor

**Risk description:** If a third-party vendor providing payroll processing or the firm's core tax/practice management software suffers its own data breach, client and firm data held by that vendor could be exposed, and the firm — as the entity with the direct client relationship — would still bear reputational and potentially regulatory consequences even though the breach occurred outside its own systems.

**Threat / Vulnerability:** Vendor-side compromise; the firm has no formal process for assessing vendor security posture before onboarding or on an ongoing basis.

**Existing controls:** Vendors are all well-known, established Australian accounting software providers with their own security certifications (though the firm has not formally reviewed these); standard commercial contracts in place, not specifically reviewed for security/breach-notification terms.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 3 – Moderate | **Medium (6)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.5.19 (Information security in supplier relationships), A.5.20 (Addressing security within supplier agreements)

**Treatment recommendation (Mitigate):**
1. Request and review each key vendor's security certification (e.g. SOC 2, ISO 27001) and incident notification commitments as part of an annual vendor review, even where a full formal risk assessment programme is not yet feasible for a firm this size.
2. Confirm contractual breach-notification timeframes align with the firm's own obligations under the NDB scheme (the firm cannot meet its 30-day assessment window if a vendor delays notifying it).
3. Maintain a simple register of which vendors hold which categories of client data, to speed up impact assessment if a vendor incident occurs.

**Owner:** Practice Manager · **Target date:** Q4 2026 · **Status:** Open

---

## HB-R07 — Low staff security awareness / no formal training programme

**Risk description:** If staff have not received structured security awareness training, they are more likely to fall for phishing and BEC attempts, mishandle client data, or use weak passwords — meaning technical controls alone (MFA, encryption) are undermined by human behaviour, which remains the most common root cause of incidents at firms of this size.

**Threat / Vulnerability:** Absence of any formal, recurring training programme; reliance on informal, ad hoc guidance from senior staff.

**Existing controls:** New staff receive a brief verbal induction covering client confidentiality obligations; no phishing simulation, no recurring refresher training, no measurement of staff awareness levels.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 3 – Moderate | **High (12)** |
| **Residual** | 3 – Possible | 3 – Moderate | **Medium (8)** |

**Framework mapping:**
- ACSC Essential Eight: *User Application Hardening* (supporting behavioural control)
- ISO/IEC 27001:2022 Annex A: A.6.3 (Awareness, education and training)

**Treatment recommendation (Mitigate):**
1. Roll out a low-cost, off-the-shelf security awareness training platform (several Australian providers offer SME-appropriate annual subscriptions) with mandatory annual completion for all staff.
2. Run at least two phishing simulation exercises per year, timed around peak tax season when attacker activity targeting accounting firms typically increases.
3. Add a standing 10-minute security topic to the firm's existing monthly staff meeting to reinforce awareness without requiring a separate training budget line.

**Owner:** Practice Manager · **Target date:** Q3 2026 · **Status:** Open

---

## HB-R08 — Lack of segregation of duties in accounting/banking systems

**Risk description:** If a single staff member (or a small number of staff) can both initiate and approve payments, or has unrestricted access to client trust accounts without independent review, the firm is exposed to both external fraud (if that individual's credentials are compromised) and internal fraud risk.

**Threat / Vulnerability:** Small-firm resourcing constraints have resulted in informal, overlapping responsibilities rather than a deliberately designed control; no independent reconciliation process for trust account activity.

**Existing controls:** The firm's bank provides transaction notifications to the Principal via email, but this is a detective control reviewed inconsistently, not a preventive one; no formal segregation-of-duties matrix exists.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.5.3 (Segregation of duties), A.8.2 (Privileged access rights)
- Regulatory reference: Trust account handling obligations under the *Tax Agent Services Act 2009* and relevant professional body (CPA Australia / Chartered Accountants ANZ) trust account standards

**Treatment recommendation (Mitigate):**
1. Implement dual authorisation for all trust account and general payment transactions, formally documented as a firm policy.
2. Introduce a monthly independent reconciliation of trust account activity, reviewed by someone outside the day-to-day processing function (e.g. the Principal or an external bookkeeper).
3. Document a simple segregation-of-duties matrix appropriate to the firm's size, acknowledging where full separation isn't feasible and compensating detective controls are used instead.

**Owner:** Principal / Director · **Target date:** Q3 2026 · **Status:** Open

---

## HB-R09 — No documented or tested incident response plan

**Risk description:** If a cyber incident occurs (ransomware, BEC, data breach) without a documented response plan, the firm's response is likely to be slower, less coordinated, and more prone to errors (e.g. missing the NDB notification window, failing to preserve evidence, or communicating inconsistently with affected clients) — compounding the impact of the original incident.

**Threat / Vulnerability:** No specific threat — this is a control/preparedness gap that increases the impact of every other risk in this register, particularly HB-R01 and HB-R02.

**Existing controls:** None formally documented; the Principal has an informal understanding of "who to call" (outsourced IT provider, possibly the firm's professional indemnity insurer) but nothing is written down or has been rehearsed.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 3 – Moderate | **Medium (6)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.5.24 (Information security incident management planning and preparation), A.5.26 (Response to information security incidents)
- Regulatory reference: *Privacy Act 1988 (Cth)* Notifiable Data Breaches scheme

**Treatment recommendation (Mitigate):**
1. Document a one-to-two-page incident response plan appropriate to firm size: who to call (IT provider, insurer, legal, OAIC if required), immediate containment steps, and a client communication template.
2. Confirm professional indemnity/cyber insurance coverage explicitly, including whether it covers incident response costs, and pre-identify a panel IT/forensics contact through the insurer if available.
3. Walk through the plan informally with senior staff once a year (a full tabletop exercise is aspirational for a firm this size, but a 30-minute walkthrough is achievable and valuable).

**Owner:** Principal / Director · **Target date:** Q3 2026 · **Status:** Open

---

## HB-R10 — Unauthorised physical access to office / paper records

**Risk description:** If the office is accessed outside business hours by an unauthorised party, or paper client files are not adequately secured, physical theft or viewing of sensitive client financial documents could occur.

**Threat / Vulnerability:** Opportunistic break-in or unauthorised access by a visitor/contractor during business hours; some paper files are stored in unlocked cabinets in a shared work area.

**Existing controls:** Standard building access (key/fob) after hours; alarm system installed; no clean-desk policy currently enforced; visitor sign-in is informal.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 2 – Unlikely | 4 – Major | **Medium (8)** |
| **Residual** | 1 – Rare | 4 – Major | **Low (4)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.7.1 (Physical security perimeters), A.7.3 (Securing offices, rooms and facilities), A.7.7 (Clear desk and clear screen)

**Treatment recommendation (Mitigate — low-cost/low-effort):**
1. Introduce a simple clear-desk policy for client files at the end of each working day, with lockable cabinets for physical storage of active client records.
2. Formalise visitor sign-in and ensure visitors/contractors are not left unattended in work areas containing client files.
3. Continue existing alarm and access control arrangements; no material additional investment assessed as necessary given the already-low residual rating.

**Owner:** Practice Manager · **Target date:** Q4 2026 · **Status:** Open

---

## HB-R11 — End-of-life legacy tax software still in use

**Risk description:** If the firm continues to rely on a legacy tax preparation module that is approaching or past vendor end-of-life/end-of-support, known vulnerabilities will no longer receive security patches, and the software may become incompatible with current operating systems or ATO lodgement requirements, creating both a security and an operational continuity risk.

**Threat / Vulnerability:** Vendor discontinuation of security patching for an unsupported product version; the firm has delayed migration due to cost and disruption concerns during past tax seasons.

**Existing controls:** The software continues to function and is used for a defined subset of complex historical client files; no compensating controls (e.g. network isolation) have been applied to the system running it.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ACSC Essential Eight: *Patch Applications* (ML0 — no longer patchable in current state)
- ISO/IEC 27001:2022 Annex A: A.8.8 (Management of technical vulnerabilities), A.8.9 (Configuration management)

**Treatment recommendation (Mitigate, with an Avoid pathway):**
1. Confirm the vendor's actual end-of-support date and obtain written confirmation of current patch status.
2. In the interim, isolate the system running the legacy software on a separate network segment with no direct internet access, as a compensating control.
3. **Preferred long-term treatment (Avoid):** complete migration of remaining historical client files to the firm's current supported platform, retiring the legacy software entirely — budgeted as a project for the next financial year, outside peak tax season.

**Owner:** Principal / Director (budget approval required) · **Target date:** Interim isolation Q3 2026; full migration FY2026–27 · **Status:** Open

---

## HB-R12 — Backup failure / no offsite or tested backups

**Risk description:** If the firm's only backup is a local NAS device on the same premises and same network as the primary file server, a single event — fire, theft, flood, or ransomware that spreads to attached storage — could destroy both the primary data and its only backup simultaneously, resulting in potentially unrecoverable loss of client records.

**Threat / Vulnerability:** Single point of failure in backup architecture; no backup has ever been test-restored to confirm it would actually work in a real recovery scenario.

**Existing controls:** Nightly automated backup job to an attached NAS device, configured by the outsourced IT provider some years ago; no monitoring/alerting if a backup job silently fails; no offsite or cloud copy.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 5 – Severe | **High (15)** |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ACSC Essential Eight: *Regular Backups* (ML0 — single-site, unmonitored, untested)
- ISO/IEC 27001:2022 Annex A: A.8.13 (Information backup), A.5.29 (Information security during disruption)

**Treatment recommendation (Mitigate — directly linked to HB-R02):**
1. Implement an offsite or cloud-based backup copy (e.g. via Microsoft 365 native retention if migrating to SharePoint/OneDrive per HB-R02, or a low-cost cloud backup product) that is logically or physically separate from the primary network.
2. Configure automated alerting so a failed backup job is flagged and actioned the same day, not discovered during an actual recovery attempt.
3. Perform a full test restoration at least annually, ideally aligned with the incident response plan walkthrough (HB-R09), and document the result.

**Owner:** Outsourced IT Provider (contract to be formally updated to include this scope) · **Target date:** Q3 2026 · **Status:** Open — **directly reduces residual rating of HB-R02 once complete**

---

*This register is a fictional portfolio exercise created to demonstrate GRC risk assessment methodology, appropriately scoped to reflect the realistic constraints (budget, staffing, maturity) of a small Australian professional services firm. Entity, staff numbers, and control detail are illustrative, not a real audit finding.*
