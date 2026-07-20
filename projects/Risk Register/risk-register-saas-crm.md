# Risk Register for CloudReach CRM 

**Entity profile:** CloudReach CRM is a fictional B2B SaaS company providing a multi-tenant customer relationship management platform to ~400 mid-market Australian and NZ customers. It processes customer PII, sales/contract data, and integrates with third-party billing (Stripe) and email providers. Hosted on AWS (ap-southeast-2), ~45 staff, no dedicated CISO, security function sits under the Head of Engineering with GRC support.

**Assessment date:** July 2026 · **Assessed by:** GRC Analyst (portfolio exercise) · **Next review:** Quarterly
**Rating scale, matrix, and methodology:** see [`notes/risk-rating-methodology.md`](notes/risk-rating-methodology.md)

---

## Summary dashboard

| Risk ID | Risk Title | Category | Inherent | Residual | Treatment | Owner | Status |
|---|---|---|---|---|---|---|---|
| CRM-R01 | Ransomware via phishing on engineering endpoint | Cyber / Malware | Extreme (20) | High (12) | Mitigate | Head of Engineering | Open |
| CRM-R02 | Misconfigured cloud storage exposing customer PII | Cyber / Cloud Config | Extreme (20) | High (10) | Mitigate | Cloud Platform Lead | Open |
| CRM-R03 | Privileged insider misuse of production DB access | Insider Threat | High (15) | Medium (8) | Mitigate | Head of Engineering | Open |
| CRM-R04 | Customer account takeover due to weak/no MFA | Cyber / Identity | Extreme (16) | Medium (8) | Mitigate | Product Owner | In Progress |
| CRM-R05 | Unpatched application/OS vulnerabilities exploited | Cyber / Vulnerability Mgmt | High (15) | Medium (6) | Mitigate | Cloud Platform Lead | In Progress |
| CRM-R06 | Multi-tenant data leakage between customer orgs | Application Security | High (15) | Medium (8) | Mitigate | Head of Engineering | Open |
| CRM-R07 | Third-party/API supply chain compromise (billing, email) | Third-Party Risk | High (12) | Medium (6) | Mitigate | GRC Lead | Open |
| CRM-R08 | DDoS attack against customer-facing application | Availability | Medium (8) | Low (4) | Accept | Cloud Platform Lead | Accepted |
| CRM-R09 | Incomplete offboarding leaves former staff with access | Access Management | High (12) | Medium (6) | Mitigate | People & Culture Lead | Open |
| CRM-R10 | Hardcoded API keys/secrets exposed in source repos | Application Security | High (12) | Medium (8) | Mitigate | Head of Engineering | Open |
| CRM-R11 | Business email compromise targeting Finance (invoice fraud) | Cyber / Social Engineering | High (15) | Medium (8) | Mitigate | CFO | Open |
| CRM-R12 | Failure to meet Notifiable Data Breach obligations | Regulatory / Compliance | High (12) | Medium (6) | Mitigate | GRC Lead | Open |
| CRM-R13 | Shadow IT / unsanctioned SaaS tools used by staff | Governance | Medium (8) | Medium (6) | Mitigate | GRC Lead | Open |
| CRM-R14 | Backup restoration failure during a real incident | Business Continuity | High (12) | Medium (6) | Mitigate | Cloud Platform Lead | Open |
| CRM-R15 | Cloud provider regional outage (AWS ap-southeast-2) | Business Continuity | Medium (8) | Low (4) | Accept | Cloud Platform Lead | Accepted |

**Portfolio view:** 2 Extreme, 8 High, 5 Medium inherent risks after crediting existing controls, residual sits at 0 Extreme, 0 High, 13 Medium, 2 Low. No risk currently exceeds the organisation's stated appetite (Low–Medium) without an active treatment plan.

---

## CRM-R01 (Ransomware via phishing on engineering endpoint)

**Risk description:** If an engineer or support staff member opens a malicious attachment or link in a phishing email, malware could execute on their laptop, potentially spreading to shared drives or CI/CD credentials and disrupting product delivery and customer service.

**Threat / Vulnerability:** External threat actor (commodity ransomware-as-a-service) exploiting user susceptibility to phishing and insufficient endpoint hardening.

**Existing controls:** Microsoft Defender for Endpoint on all corporate devices email filtering via Microsoft Defender for Office 365 (Safe Links/Safe Attachments) annual (not quarterly) security awareness training local admin rights not fully restricted on developer laptops.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 5 – Severe | **Extreme (20)** |
| **Residual** | 3 – Possible | 4 – Major | **High (12)** |

**Framework mapping:**
- ACSC Essential Eight: *Patch Applications* (ML1, patching cadence not consistently enforced), *Restrict Administrative Privileges* (ML1, local admin still granted to engineers), *User Application Hardening* (ML1), *Regular Backups* (ML2)
- ISO/IEC 27001:2022 Annex A: A.8.7 (Protection against malware), A.6.3 (Awareness, education and training), A.8.23 (Web filtering)

**Treatment recommendation (Mitigate):**
1. Move security awareness training to a quarterly cadence with phishing simulations and measured click/report rates.
2. Remove standing local admin rights from developer laptops implement a just-in-time elevation process.
3. Formalise a patch SLA (critical patches within 7 days) and track compliance via Intune/Defender dashboards.

**Owner:** Head of Engineering · **Target date:** Q3 2026 · **Status:** Open

---

## CRM-R02 (Misconfigured cloud storage exposing customer PII)

**Risk description:** If an S3 bucket or equivalent storage resource used to hold customer export files or backups is misconfigured with public or overly broad access, customer PII (names, emails, phone numbers, and CRM notes) could be exposed to unauthorised parties.

**Threat / Vulnerability:** Human error during infrastructure changes absence of automated configuration guardrails opportunistic external scanning for open cloud storage.

**Existing controls:** AWS Config rules flag public S3 buckets block-public-access set as an account-level default infrastructure changes go through Terraform with peer review, but exceptions have historically been made for "temporary" manual changes.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 5 – Severe | **Extreme (20)** |
| **Residual** | 2 – Unlikely | 5 – Severe | **High (10)** |

**Framework mapping:**
- ACSC Essential Eight: no direct E8 strategy (cloud configuration sits outside the Essential Eight's on-prem/endpoint focus) treated as a supplementary control area
- ISO/IEC 27001:2022 Annex A: A.8.9 (Configuration management), A.8.12 (Data leakage prevention), A.5.10 (Acceptable use of information and assets), A.5.34 (Privacy and protection of PII)

**Treatment recommendation (Mitigate):**
1. Remove standing permission for manual (non-Terraform) changes to storage resources require all changes through pipeline with mandatory peer review.
2. Enable AWS GuardDuty and Macie for continuous sensitive-data and anomaly detection on storage buckets.
3. Run a quarterly cloud configuration review against the CIS AWS Foundations Benchmark.

**Owner:** Cloud Platform Lead · **Target date:** Q3 2026 · **Status:** Open

---

## CRM-R03 (Privileged insider misuse of production database access)

**Risk description:** If an engineer with standing production database access intentionally or accidentally exports, modifies, or deletes customer data outside of an authorised change process, customers could suffer data loss or a breach of confidentiality, and CloudReach could face contractual and reputational consequences.

**Threat / Vulnerability:** Malicious or careless insider with excessive standing privileges lack of query-level logging/alerting.

**Existing controls:** Production database access restricted to a named group of senior engineers access reviewed at time of hire only (not periodically) all access via bastion host with session recording no automated alerting on bulk data export queries.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 5 – Severe | **High (15)** |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ACSC Essential Eight: *Restrict Administrative Privileges* (ML1, no periodic recertification)
- ISO/IEC 27001:2022 Annex A: A.8.2 (Privileged access rights), A.5.18 (Access rights), A.8.15 (Logging), A.5.36 (Compliance with policies, rules and standards)

**Treatment recommendation (Mitigate):**
1. Introduce a quarterly access recertification process for all privileged production access, signed off by the Head of Engineering.
2. Implement automated alerting for bulk export/large result-set queries against the production database.
3. Move toward just-in-time, time-bound privileged access (e.g. via AWS SSO temporary elevation) rather than standing access.

**Owner:** Head of Engineering · **Target date:** Q4 2026 · **Status:** Open

---

## CRM-R04 (Customer account takeover due to weak or absent MFA)

**Risk description:** If a customer administrator's login credentials are compromised (via credential stuffing, phishing, or reuse from another breach) and MFA is not enforced on their account, an attacker could gain full access to that customer's CRM tenant, including exporting their entire customer database.

**Threat / Vulnerability:** Credential stuffing using breached password lists MFA currently optional rather than enforced at the platform level.

**Existing controls:** MFA available (TOTP) but opt-in for customer users password complexity policy enforced anomalous login detection (new device/location) sends an email alert but does not block the session.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 4 – Major | **Extreme (16)** |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ACSC Essential Eight: *Multi-Factor Authentication* (ML1, available but not enforced target ML2)
- ISO/IEC 27001:2022 Annex A: A.8.5 (Secure authentication), A.5.17 (Authentication information)

**Treatment recommendation (Mitigate):**
1. Make MFA mandatory for all customer administrator accounts by default, with a defined grace-period rollout and customer communication plan.
2. Move anomalous login detection from alert-only to step-up authentication or session block pending verification.
3. Publish an MFA enforcement roadmap to customers to support their own compliance obligations (many are regulated entities themselves).

**Owner:** Product Owner · **Target date:** Q3 2026 (in progress pilot with 20 customers underway) · **Status:** In Progress

---

## CRM-R05 (Unpatched application and OS vulnerabilities exploited)

**Risk description:** If known vulnerabilities in the application stack (frameworks, libraries) or underlying EC2/container OS images are not patched in a timely manner, an external attacker could exploit a publicly known CVE to gain unauthorised access to production systems.

**Threat / Vulnerability:** External attacker scanning for known CVEs internal patch cadence not formally tracked against a defined SLA.

**Existing controls:** Dependabot/Snyk scanning on application repositories base container images rebuilt monthly no formal patch SLA or exception process staging environment used before production deploys.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 5 – Severe | **High (15)** |
| **Residual** | 2 – Unlikely | 3 – Moderate | **Medium (6)** |

**Framework mapping:**
- ACSC Essential Eight: *Patch Applications* (ML2), *Patch Operating Systems* (ML2)
- ISO/IEC 27001:2022 Annex A: A.8.8 (Management of technical vulnerabilities), A.8.9 (Configuration management)

**Treatment recommendation (Mitigate):**
1. Define and publish a formal patch SLA (critical: 48 hours, high: 7 days, medium: 30 days) with monthly compliance reporting.
2. Introduce automated dependency-update PRs with mandatory CI test gates to reduce manual patching lag.
3. Run an external penetration test annually and after major architecture changes track findings to closure.

**Owner:** Cloud Platform Lead · **Target date:** Q3 2026 (SLA defined reporting build in progress) · **Status:** In Progress

---

## CRM-R06 (Multi-tenant data leakage between customer organisations)

**Risk description:** If a defect in tenant isolation logic (application-level row security, API authorisation checks) allows one customer's data to be visible to another customer, this constitutes a serious data breach affecting multiple customers simultaneously and would likely be catastrophic for customer trust.

**Threat / Vulnerability:** Application-layer logic error (broken object-level authorisation OWASP API Security Top 10, API1:2023) introduced through a code defect insufficient automated test coverage for cross-tenant scenarios.

**Existing controls:** Row-level security enforced at the database layer via tenant_id code review required for all PRs touching data access layers automated integration tests cover the primary tenant-isolation paths but not all API endpoints.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 5 – Severe | **High (15)** |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.8.25 (Secure development lifecycle), A.8.26 (Application security requirements), A.8.29 (Security testing in development and acceptance), A.8.4 (Access to source code)
- Referenced standard: OWASP API Security Top 10 (API1:2023 — Broken Object Level Authorisation)

**Treatment recommendation (Mitigate):**
1. Extend automated test coverage to include cross-tenant authorisation checks on every API endpoint (target 100% coverage), enforced as a CI gate.
2. Commission an annual application-focused penetration test explicitly scoped to test tenant isolation.
3. Add database-layer alerting for any query that does not include a tenant_id filter, as a defence-in-depth backstop.

**Owner:** Head of Engineering · **Target date:** Q4 2026 · **Status:** Open

---

## CRM-R07 (Third-party / API supply chain compromise)

**Risk description:** If a third-party integration (e.g. Stripe billing, transactional email provider, or an OAuth-connected customer integration) is compromised or suffers its own breach, customer or payment-adjacent data flowing through that integration could be exposed, and CloudReach's platform could be used as a pivot point.

**Threat / Vulnerability:** Supply chain compromise or breach at a third-party vendor over privileged API scopes granted to integrations no formal vendor security review process.

**Existing controls:** Payment processing outsourced to a PCI-DSS compliant provider (Stripe)  CloudReach does not store card data directly API keys for third parties stored in a secrets manager (not in code) no formal annual vendor security assessment process currently in place.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 3 – Moderate | **Medium (6)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.5.19 (Information security in supplier relationships), A.5.20 (Addressing security within supplier agreements), A.5.22 (Monitoring, review and change management of supplier services)

**Treatment recommendation (Mitigate):**
1. Establish a formal vendor risk assessment process for any third party with access to customer data, including annual re-assessment for critical vendors.
2. Review and minimise OAuth/API scopes granted to all integrations to least-privilege.
3. Add supplier security clauses (breach notification timeframes, right-to-audit) to new and renewed vendor contracts.

**Owner:** GRC Lead · **Target date:** Q4 2026 · **Status:** Open

---

## CRM-R08 (DDoS attack against customer-facing application)

**Risk description:** If CloudReach's application is targeted by a volumetric or application-layer DDoS attack, customers could experience service degradation or outage, affecting SLA commitments and customer trust.

**Threat / Vulnerability:** External threat actor (hacktivist, extortion attempt, or opportunistic attack) reliance on cloud-native scaling without a dedicated DDoS mitigation service.

**Existing controls:** AWS Shield Standard (included by default) CloudFront CDN in front of the application auto-scaling configured for the application tier.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 2 – Unlikely | 4 – Major | **Medium (8)** |
| **Residual** | 1 – Rare | 4 – Major | **Low (4)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.8.6 (Capacity management), A.5.29 (Information security during disruption)

**Treatment recommendation (Accept):**
Given AWS Shield Standard and CDN coverage already reduce residual likelihood to Rare, and the cost of AWS Shield Advanced is not currently justified by customer SLA commitments, this risk is **formally accepted** at its current residual rating. Recommend revisiting if the customer base grows to include higher-profile or higher-risk-profile organisations, or after any actual DDoS event.

**Owner:** Cloud Platform Lead · **Review date:** Annually, or upon material change · **Status:** Accepted (sign-off recorded, see governance log)

---

## CRM-R09 (Incomplete offboarding leaves former staff with system access)

**Risk description:** If an employee's access to CloudReach systems (source code, cloud console, CRM admin, Google Workspace) is not fully revoked at termination, a disgruntled or careless former employee could retain the ability to access or exfiltrate company or customer data.

**Threat / Vulnerability:** Manual, checklist-driven offboarding process with no single source of truth for "all systems an employee has access to" no automated deprovisioning tied to HRIS status change.

**Existing controls:** Offboarding checklist exists and is used by People & Culture in coordination with IT primary systems (Google Workspace, AWS SSO) are deprovisioned same-day secondary/individual tool access (e.g. personal API tokens, third-party SaaS logins) is inconsistently tracked.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 3 – Moderate | **Medium (6)** |

**Framework mapping:**
- ACSC Essential Eight: *Restrict Administrative Privileges* (supporting control)
- ISO/IEC 27001:2022 Annex A: A.6.5 (Responsibilities after termination or change of employment), A.5.18 (Access rights), A.8.9 (Configuration management)

**Treatment recommendation (Mitigate):**
1. Implement centralised identity management (e.g. AWS SSO / Google Workspace as the single identity provider for all SaaS tools where possible) to enable single-point deprovisioning.
2. Maintain a live systems-access inventory per employee, reviewed at onboarding and updated on any new tool access grant.
3. Add a 30-day post-termination access audit as a standing control to catch anything missed at time of exit.

**Owner:** People & Culture Lead (jointly with Cloud Platform Lead) · **Target date:** Q3 2026 · **Status:** Open

---

## CRM-R10 (Hardcoded API keys and secrets exposed in source repositories)

**Risk description:** If a developer accidentally commits an API key, database credential, or other secret into a source code repository, and that repository is later made public, forked, or accessed by an unauthorised party, those credentials could be used to access production systems or third-party services.

**Threat / Vulnerability:** Developer error absence of automated pre-commit secret scanning at the time of the incident this control gap was identified historical commits in repository history predating current controls.

**Existing controls:** GitHub secret scanning enabled on all repositories (detects known credential patterns) secrets manager used for new development no historical repository history scan has been completed to confirm no legacy exposure remains.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.8.24 (Use of cryptography), A.8.28 (Secure coding), A.8.4 (Access to source code)

**Treatment recommendation (Mitigate):**
1. Run a full historical git-history secret scan (e.g. TruffleHog/GitLeaks) across all repositories and rotate any credentials found, regardless of age.
2. Add pre-commit hook secret scanning in developer tooling to catch issues before they reach the remote repository.
3. Mandate that all new secrets are issued exclusively via the secrets manager, with periodic automated audits for hardcoded patterns.

**Owner:** Head of Engineering · **Target date:** Q3 2026 · **Status:** Open

---

## CRM-R11 (Business email compromise targeting Finance, invoice fraud)

**Risk description:** If a Finance team member receives a spoofed or compromised email impersonating a supplier, executive, or customer requesting a change to bank details or an urgent payment, CloudReach could suffer direct financial loss through fraudulent payment.

**Threat / Vulnerability:** Social engineering / business email compromise (BEC) this remains one of the most reported and highest-loss cybercrime categories for Australian businesses per the ACSC Annual Cyber Threat Report.

**Existing controls:** Dual-authorisation required for payments over $5,000 DMARC/DKIM/SPF configured on the corporate domain no verbal/callback verification requirement currently mandated for bank detail changes.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 4 – Major | **High (16)** *(rounds to High band)* |
| **Residual** | 2 – Unlikely | 4 – Major | **Medium (8)** |

**Framework mapping:**
- ACSC Essential Eight: *User Application Hardening*, *Restrict Microsoft Office Macro Settings* (supporting controls)
- ISO/IEC 27001:2022 Annex A: A.6.3 (Awareness, education and training), A.5.14 (Information transfer)

**Treatment recommendation (Mitigate):**
1. Mandate a verbal callback (to a known, independently sourced phone number never one provided in the email) for any request to change supplier bank details, regardless of apparent sender authority.
2. Run targeted phishing/BEC simulation exercises for the Finance team quarterly.
3. Consider cyber insurance coverage that explicitly includes social-engineering/funds-transfer fraud (many policies exclude it by default)  see also treatment overlap with Transfer options.

**Owner:** CFO · **Target date:** Q3 2026 · **Status:** Open

---

## CRM-R12 (Failure to meet Notifiable Data Breach obligations)

**Risk description:** If a data breach affecting customer PII occurs and CloudReach does not identify, assess, and (where required) notify the OAIC and affected individuals within the statutory timeframe, CloudReach could face regulatory penalties, in addition to the reputational damage of the breach itself.

**Threat / Vulnerability:** Absence of a tested, documented incident response and breach-assessment process aligned to the *Notifiable Data Breaches (NDB) scheme* under the *Privacy Act 1988 (Cth)*.

**Existing controls:** A basic incident response plan exists but has not been tested via a tabletop exercise in the last 12 months no formally documented NDB eligible-data-breach assessment procedure Privacy Officer role is assigned but not resourced as a dedicated function.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 3 – Moderate | **Medium (6)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.5.24 (Information security incident management planning and preparation), A.5.34 (Privacy and protection of PII), A.5.31 (Legal, statutory, regulatory and contractual requirements)
- Regulatory reference: *Privacy Act 1988 (Cth)*, Notifiable Data Breaches scheme (OAIC)

**Treatment recommendation (Mitigate):**
1. Document a formal eligible-data-breach assessment procedure mapped explicitly to the NDB scheme's 30-day assessment timeframe.
2. Run an annual tabletop incident response exercise involving Engineering, Legal, Executive, and Communications stakeholders, including a simulated NDB scenario.
3. Confirm cyber insurance coverage includes breach response costs (forensics, legal, notification, credit monitoring) and pre-register with a panel incident response firm.

**Owner:** GRC Lead · **Target date:** Q3 2026 · **Status:** Open

---

## CRM-R13 (Shadow IT / unsanctioned SaaS tools used by staff)

**Risk description:** If staff sign up for and use unapproved SaaS tools (e.g. AI coding assistants, file-sharing tools, note-taking apps) to handle company or customer data, that data falls outside CloudReach's security controls and visibility, increasing the risk of an undetected breach or data residency/compliance issue.

**Threat / Vulnerability:** Well-intentioned productivity-seeking behaviour by staff, enabled by an absence of a SaaS approval process or CASB-style visibility tooling.

**Existing controls:** Acceptable use policy exists and is signed at onboarding no technical control (CASB, DNS filtering) currently monitors or restricts SaaS sign-ups no defined process for staff to request new tool approval.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 4 – Likely | 2 – Minor | **Medium (8)** |
| **Residual** | 3 – Possible | 2 – Minor | **Medium (6)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.5.10 (Acceptable use of information and assets), A.5.9 (Inventory of information and other associated assets)

**Treatment recommendation (Mitigate):**
1. Stand up a lightweight SaaS tool approval process (a simple request form triaged by GRC/IT within 2 business days) to give staff a fast, sanctioned path rather than driving shadow adoption.
2. Introduce SSO-only access for any new SaaS tool where possible, to retain visibility and enable deprovisioning.
3. Periodically review Google Workspace/AWS marketplace and expense reports for evidence of unsanctioned tool spend.

**Owner:** GRC Lead · **Target date:** Q4 2026 · **Status:** Open

---

## CRM-R14 (Backup restoration failure during a real incident)

**Risk description:** If backups exist but have not been tested for successful restoration, CloudReach could discover during an actual ransomware or data-loss incident that backups are incomplete, corrupted, or too slow to restore within an acceptable Recovery Time Objective, extending the outage and potentially resulting in permanent data loss.

**Threat / Vulnerability:** "Backups exist" is frequently mistaken for "recovery works" untested backups are a common latent failure mode exposed only during a real incident.

**Existing controls:** Automated daily database backups with 30-day retention backups stored in a separate AWS account/region no documented, timed restoration test has been performed in the last 12 months.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 3 – Possible | 4 – Major | **High (12)** |
| **Residual** | 2 – Unlikely | 3 – Moderate | **Medium (6)** |

**Framework mapping:**
- ACSC Essential Eight: *Regular Backups* (ML1 backups exist and are isolated, but restoration is untested target ML2/ML3)
- ISO/IEC 27001:2022 Annex A: A.8.13 (Information backup), A.5.29 (Information security during disruption), A.5.30 (ICT readiness for business continuity)

**Treatment recommendation (Mitigate):**
1. Conduct a full, timed backup restoration test at least twice per year, documenting actual RTO/RPO achieved against target.
2. Define and formally approve target RTO/RPO values with the business (currently undocumented).
3. Store an immutable/air-gapped backup copy specifically to protect against ransomware that targets connected backup systems.

**Owner:** Cloud Platform Lead · **Target date:** Q3 2026 · **Status:** Open

---

## CRM-R15 (Cloud provider regional outage)

**Risk description:** If AWS experiences a significant outage in the ap-southeast-2 (Sydney) region, CloudReach's application could become unavailable to all customers simultaneously, regardless of CloudReach's own control maturity, since the platform is not currently deployed multi-region.

**Threat / Vulnerability:** Cloud provider infrastructure failure or regional disruption, a low-frequency but high-visibility event single-region architecture creates a hard dependency.

**Existing controls:** Multi-AZ deployment within the region (protects against single data-centre failure, not full regional outage) documented disaster recovery runbook exists no active multi-region failover capability.

| | Likelihood | Impact | Rating |
|---|---|---|---|
| **Inherent** | 2 – Unlikely | 4 – Major | **Medium (8)** |
| **Residual** | 1 – Rare | 4 – Major | **Low (4)** |

**Framework mapping:**
- ISO/IEC 27001:2022 Annex A: A.5.29 (Information security during disruption), A.5.30 (ICT readiness for business continuity)

**Treatment recommendation (Accept):**
Full multi-region active-active architecture is assessed as disproportionate to the current business impact and customer SLA commitments (99.9%, not 99.99%). Multi-AZ resilience already addresses the most probable failure scenarios. This risk is **formally accepted** at its current residual rating, with a commitment to re-assess if CloudReach signs an enterprise customer requiring a higher availability SLA.

**Owner:** Cloud Platform Lead · **Review date:** Annually, or upon material change to customer SLA commitments · **Status:** Accepted (sign-off recorded, see governance log)

---

*This register is a fictional portfolio exercise created to demonstrate GRC risk assessment methodology. Entity, staff numbers, and control detail are illustrative, not a real audit finding.*
