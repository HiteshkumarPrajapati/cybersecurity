# ACSC Essential 8 Gap Assessment — Meridian Consulting Group

## 1. Document control

| Field | Detail |
|---|---|
| **Client / Entity** | Meridian Consulting Group (fictional, ~80-staff management consulting and advisory firm) |
| **Assessment scope** | 3 of 8 Essential Eight strategies: Multi-Factor Authentication, Patch Applications, Regular Backups |
| **Assessment date** | July 2026 |
| **Assessed by** | GRC Analyst (portfolio exercise) |
| **Target maturity level** | Maturity Level 2 (ML2) across all in-scope strategies — see [`assessment-methodology.md`](assessment-methodology.md) §4 |
| **Assessment type** | Evidence and interview-based gap assessment (not a technical penetration test — see limitations) |
| **Next assessment recommended** | 12 months, or upon material change to identity provider, patch tooling, or backup architecture |

## 2. Executive summary

Meridian Consulting Group currently sits at **Maturity Level 1** for Multi-Factor Authentication, **Maturity Level 0** for Patch Applications, and **Maturity Level 1** for Regular Backups, against a target of Maturity Level 2 across all three. The single most urgent finding is that **Patch Applications does not yet meet even Maturity Level 1**, because the firm's internet-facing client deliverables portal (hosted on AWS) is not on a defined patch or vulnerability-scanning cadence at all — this is the one finding in this assessment that represents an active, exploitable gap on an asset directly exposed to the internet, and is recommended for immediate remediation ahead of the other two strategies. Multi-Factor Authentication is partially implemented (available and used by most staff) but not technically enforced for all users, and privileged/administrative accounts are not held to a stricter standard than standard users — both required to reach ML2. Regular Backups are occurring but have never been restoration-tested, and the on-premises file server's only backup copy sits on the same network as the data it protects, meaning a single ransomware event could plausibly destroy both the original data and its backup simultaneously. None of the three findings require a large capital investment to close to ML1/ML2 — the recommended roadmap in the accompanying document sequences a set of low-cost, high-impact actions achievable within the current financial year.

## 3. Maturity scorecard

| Strategy | Current Maturity | Target Maturity | Gap | Primary Blocker |
|---|---|---|---|---|
| **Multi-Factor Authentication** | ML1 | ML2 | 1 level | MFA not technically enforced tenant-wide; no distinction for privileged accounts |
| **Patch Applications** | ML0 | ML2 | 2 levels | No defined patch/vulnerability-scanning cadence for the internet-facing AWS application |
| **Regular Backups** | ML1 | ML2 | 1 level | No restoration testing performed; backup not isolated from the production network it protects |

## 4. Organisational context

Meridian operates a hybrid Microsoft 365 environment (Entra ID as the identity provider) for the majority of staff productivity and collaboration. A legacy on-premises Windows file server, retained for historical project archives predating the firm's 2019 migration to SharePoint, remains in use by a subset of long-tenured staff out of habit rather than necessity. A single client-facing web application — the "Meridian Client Portal," used by clients to receive and review deliverables — is hosted on AWS (ap-southeast-2) and managed day-to-day by a part-time outsourced DevOps contractor rather than an in-house engineer, as Meridian does not employ dedicated software engineering staff. IT operations more broadly are managed by a two-person internal IT team supplemented by an outsourced managed service provider (MSP) for after-hours support.

---

## 5. Multi-Factor Authentication — detailed assessment

### 5.1 ACSC criteria assessed against

| Level | Criterion | Met? |
|---|---|---|
| **ML1** | MFA is used to authenticate users to their organisation's internet-facing services that process, store or communicate their organisation's sensitive data. | Partially |
| **ML1** | MFA is enabled by default for non-organisational users (e.g. clients) accessing the organisation's internet-facing services, if supported. | Yes |
| **ML1** | Successful and unsuccessful MFA events are logged. | Yes |
| **ML2** | MFA is used to authenticate users to their organisation's internet-facing services. | Partially |
| **ML2** | MFA used for authentication uses either something a user has and something a user knows, or something a user has that is unlocked by something the user knows or is. | Yes, where MFA is used |
| **ML2** | MFA is used to authenticate privileged users of systems, and users of important data repositories. | No |
| **ML2** | MFA event logs are held centrally in a secure location and protected from unauthorised modification. | Partially |
| **ML3** | Phishing-resistant MFA is used to authenticate all users. | No |
| **ML3** | MFA is used for important data repositories regardless of whether it is internet-facing. | No |

### 5.2 Current state / evidence summary

MFA is technically available across Microsoft 365 (via Entra ID / Microsoft Authenticator) and is enabled by default for the small number of external client accounts able to log into the Client Portal. However, MFA enforcement for Meridian's own staff is currently configured as **user-optional rather than mandatory**: a Conditional Access policy exists but is set to "report-only" mode rather than enforced, meaning it logs whether MFA *would* have applied without actually blocking non-MFA sign-in. Approximately 61 of 80 staff (76%) have voluntarily registered for MFA; the remaining 24% have not. Critically, this includes at least two accounts confirmed during interview to hold Global Administrator privileges in the Microsoft 365 tenant — meaning the firm's most sensitive administrative access currently has no MFA requirement whatsoever. Sign-in logs are retained in Entra ID's default logging (30 days) but are not exported to a centralised, longer-retention log store, limiting both the audit trail available for an incident investigation and satisfaction of the ML2 centralised-logging criterion.

### 5.3 Gaps identified

- **G-MFA-01 (Critical):** Global Administrator and other privileged Microsoft 365 accounts do not have MFA enforced. This is the single highest-impact finding across the entire assessment — a compromised, non-MFA-protected Global Admin account would give an attacker effectively unrestricted control of Meridian's entire M365 environment, including email, SharePoint (which now holds the bulk of client data following the 2019 migration), and user account management.
- **G-MFA-02 (High):** MFA is not technically enforced for standard staff users; enforcement currently relies on voluntary registration, leaving 24% of staff accounts without MFA at all.
- **G-MFA-03 (Medium):** Sign-in and MFA event logs are not exported to a centralised, longer-retention log store, limiting incident investigation capability and falling short of the ML2 centralised-logging criterion.
- **G-MFA-04 (Medium):** No phishing-resistant MFA method (e.g. FIDO2 security key) is deployed for any user tier, which is not required to reach the ML2 target but represents the clearest, lowest-effort next step toward ML3 for privileged accounts specifically, given the disproportionate impact of a compromised admin account.

### 5.4 Maturity determined

**Maturity Level 1 (ML1) achieved.** ML2 is not achieved because two ML2 criteria are unmet: MFA is not enforced for all users of the internet-facing service (G-MFA-02), and MFA is specifically not enforced for privileged users (G-MFA-01) — per the strict maturity scoring logic described in the methodology document, either gap alone would be sufficient to cap the strategy below ML2, and both are present here.

---

## 6. Patch Applications — detailed assessment

### 6.1 ACSC criteria assessed against

| Level | Criterion | Met? |
|---|---|---|
| **ML1** | A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in internet-facing services. | No |
| **ML1** | A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in office productivity suites, web browsers and their extensions, email clients, PDF software, and security products. | Partially |
| **ML1** | Patches, updates or vendor mitigations for vulnerabilities in internet-facing services are applied within two weeks of release, or within 48 hours if an exploit exists. | No |
| **ML1** | Patches, updates or vendor mitigations for office productivity suites, browsers, email clients, PDF software and security products are applied within one month of release. | Partially |
| **ML1** | Internet-facing services, office productivity suites, browsers and extensions, email clients, PDF software, and security products that are no longer supported by vendors are removed. | Partially |
| **ML2** | A vulnerability scanner is used at least weekly to identify missing patches for internet-facing services, and fortnightly for other in-scope software. | No |
| **ML2** | Patches for internet-facing services are applied within 48 hours if an exploit exists, and within two weeks otherwise. | No |

### 6.2 Current state / evidence summary

Microsoft 365 applications (Office apps, browsers via Microsoft Edge managed updates) are patched automatically through Microsoft's standard update channel, which broadly satisfies the ML1 intent for that specific software category, though this is default vendor behaviour rather than a Meridian-managed process with defined SLAs or compliance reporting. The on-premises file server runs Windows Server with patches applied "when the IT team gets to it" per interview with the IT Manager — no defined patch SLA, no vulnerability scanner in use against it, and evidence of at least one patch (a Windows Server cumulative update addressing a publicly disclosed vulnerability) that remained unapplied for over four months after release.

The most significant finding sits with the **Meridian Client Portal on AWS**: there is currently **no vulnerability scanning of any kind** performed against this internet-facing application or its underlying infrastructure (EC2 instances, application dependencies), and no defined patch SLA. The outsourced DevOps contractor confirmed during interview that patching of the underlying OS and application dependencies is performed "reactively, generally when we're in there for something else" — meaning there is no proactive process at all, let alone one meeting the two-week (or 48-hour for actively exploited vulnerabilities) ML1 requirement for internet-facing services. Given this application is the one system in Meridian's environment directly exposed to the internet and reachable by unauthenticated external parties before login, this is assessed as the most urgent finding in this entire report.

### 6.3 Gaps identified

- **G-PATCH-01 (Critical):** No vulnerability scanning is performed against the internet-facing Client Portal (AWS-hosted) at any cadence, and no defined patch SLA exists for it. This directly fails the foundational ML1 criterion for internet-facing services and leaves Meridian unable to demonstrate — or in practice, know — whether a publicly disclosed and actively exploited vulnerability affecting the portal has gone unpatched.
- **G-PATCH-02 (High):** The on-premises file server has no vulnerability scanning and no defined patch SLA; evidence showed at least one patch outstanding for over four months past release.
- **G-PATCH-03 (Medium):** Microsoft 365 application patching relies entirely on default vendor auto-update behaviour with no Meridian-managed compliance reporting or defined internal SLA, meaning the firm has no way to demonstrate compliance with its own (currently unwritten) patch expectations if ever asked.
- **G-PATCH-04 (Low):** No formal process exists to confirm end-of-life/end-of-support software is identified and removed; this was assessed as partially met based on the IT Manager's general awareness of the firm's software estate, but with no documented inventory or review cadence to rely on.

### 6.4 Maturity determined

**Maturity Level 0 (ML0).** This strategy does not yet meet the intent of Maturity Level 1: the foundational ML1 requirement to scan for and patch vulnerabilities in internet-facing services within a defined timeframe is not met at all for the Client Portal (G-PATCH-01). This is the only strategy in this assessment that fails to clear ML1, and is flagged accordingly as the top priority in the remediation roadmap.

---

## 7. Regular Backups — detailed assessment

### 7.1 ACSC criteria assessed against

| Level | Criterion | Met? |
|---|---|---|
| **ML1** | Backups of important data, software and configuration settings are performed and retained in accordance with business continuity requirements. | Partially |
| **ML1** | Backups of important data, software and configuration settings are synchronised to enable restoration to a common point in time. | Yes |
| **ML1** | Restoration of systems, software and important data from backups is tested as part of disaster recovery exercises. | No |
| **ML1** | Unprivileged accounts are prevented from accessing backups belonging to other accounts, and from modifying or deleting backups. | Partially |
| **ML2** | Unprivileged accounts are prevented from accessing backups belonging to other accounts, and from modifying or deleting their own backups. | Partially |
| **ML2** | Privileged accounts (excluding backup administrator accounts) are prevented from accessing backups belonging to other accounts, and from modifying or deleting backups. | No |

### 7.2 Current state / evidence summary

Meridian's Microsoft 365 data (email, SharePoint, OneDrive) is protected by Microsoft's native retention and versioning capability, which provides a reasonable point-in-time recovery capability for that portion of the environment consistent with the ML1 intent, though this was not independently stress-tested as part of this assessment. The on-premises file server — which still holds a meaningful volume of historical project archive data not migrated to SharePoint — is backed up nightly to an attached network-attached storage (NAS) device located in the same server room, on the same local network. **No offsite or cloud copy of this backup exists.** This is functionally the same architectural weakness identified as a critical finding in the companion risk register portfolio's small-business case study, and represents a genuine single point of failure: a ransomware event, fire, or theft affecting the server room would plausibly destroy the primary data and its only backup simultaneously.

Separately, and independent of the offsite-copy gap, **no restoration test has ever been performed** on either the Microsoft 365 retention capability or the on-premises NAS backup, per confirmation from the IT Manager during interview. The firm has never had cause to actually restore from backup and has therefore never confirmed that a restoration would succeed within an acceptable timeframe, or at all. On access controls, the NAS device is managed through a shared administrative login used by the two-person IT team, with no differentiation between "IT staff generally" and "backup administrator" roles, and no evidence that non-IT privileged accounts (e.g. Global Administrators — see G-MFA-01) are specifically prevented from modifying or deleting the backup.

### 7.3 Gaps identified

- **G-BACKUP-01 (Critical):** No offsite or cloud copy of the on-premises file server backup exists; the only backup copy sits on the same local network as the production data it protects, creating a single point of failure against ransomware, fire, or theft affecting the server room.
- **G-BACKUP-02 (High):** No restoration test has ever been performed for either the Microsoft 365 retention capability or the on-premises NAS backup, meaning the firm cannot currently demonstrate its backups would actually restore successfully within an acceptable Recovery Time Objective — a foundational ML1 requirement.
- **G-BACKUP-03 (Medium):** No formal Recovery Time Objective (RTO) or Recovery Point Objective (RPO) has been defined and approved by Meridian's leadership, meaning "in accordance with business continuity requirements" (the ML1 wording) cannot currently be evaluated against any documented standard.
- **G-BACKUP-04 (Medium):** Backup administration is managed through a shared IT login with no distinct "backup administrator" role, and no confirmed technical control preventing a compromised privileged (e.g. Global Admin) account from deleting or modifying backups — directly relevant given the MFA gap on privileged accounts identified in G-MFA-01, since these two gaps compound each other's impact.

### 7.4 Maturity determined

**Maturity Level 1 (ML1) achieved**, on the basis that backups are occurring and are synchronised to a common restore point, satisfying the core ML1 intent — but this is a qualified ML1: the absence of any restoration testing (G-BACKUP-02) is itself an unmet ML1 criterion, and is flagged as a priority gap to close even within the current maturity level, not just as a blocker to ML2. ML2 is not achieved due to the unresolved access-control gap for privileged accounts (G-BACKUP-04).

---

## 8. Consolidated findings register

| Finding ID | Strategy | Severity | ACSC Level Affected | Summary | Owner |
|---|---|---|---|---|---|
| G-PATCH-01 | Patch Applications | **Critical** | ML1 | No vulnerability scanning or patch SLA for the internet-facing Client Portal | AWS DevOps Contractor / IT Manager |
| G-MFA-01 | Multi-Factor Authentication | **Critical** | ML2 | MFA not enforced on Global Administrator / privileged M365 accounts | IT Manager |
| G-BACKUP-01 | Regular Backups | **Critical** | ML1 | No offsite/cloud copy of on-premises file server backup | IT Manager |
| G-BACKUP-02 | Regular Backups | **High** | ML1 | No restoration test has ever been performed | IT Manager |
| G-PATCH-02 | Patch Applications | **High** | ML1 | No vulnerability scanning or patch SLA for the on-premises file server | IT Manager |
| G-MFA-02 | Multi-Factor Authentication | **High** | ML2 | MFA not technically enforced for standard staff (voluntary only) | IT Manager |
| G-BACKUP-04 | Regular Backups | **Medium** | ML2 | No distinct backup administrator role; privileged-account access to backups not restricted | IT Manager |
| G-BACKUP-03 | Regular Backups | **Medium** | ML1 | No defined/approved RTO or RPO | Practice Manager / IT Manager |
| G-PATCH-03 | Patch Applications | **Medium** | ML1 | M365 patching relies on default vendor behaviour with no internal compliance reporting | IT Manager |
| G-MFA-03 | Multi-Factor Authentication | **Medium** | ML2 | MFA/sign-in logs not centrally retained beyond 30 days | IT Manager |
| G-MFA-04 | Multi-Factor Authentication | **Medium** | ML3 (aspirational) | No phishing-resistant MFA deployed for privileged accounts | IT Manager |
| G-PATCH-04 | Patch Applications | **Low** | ML1 | No formal end-of-life software inventory/removal process | IT Manager |

**Sequencing note:** the three Critical findings (G-PATCH-01, G-MFA-01, G-BACKUP-01) are the recommended immediate priorities — each represents either an active exploitable exposure (G-PATCH-01), a single point of failure capable of taking down the firm's most privileged access with no compensating control (G-MFA-01), or a single point of failure capable of causing irrecoverable data loss (G-BACKUP-01). None of the three require significant capital expenditure to close. Full sequencing, ownership, and target dates are set out in [`remediation-roadmap.md`](remediation-roadmap.md).

## 9. Conclusion

Meridian Consulting Group has a reasonable operational foundation across all three assessed strategies — nothing in this assessment suggests a wholesale absence of security practice — but has clear, specific, and closeable gaps preventing it from reaching its target Maturity Level 2, and one gap (patch management on its sole internet-facing asset) that has not yet cleared even Maturity Level 1. The pattern across all three strategies is consistent: **the firm's foundational practices exist but are not consistently enforced, tested, or extended to its highest-risk assets** (privileged accounts, the internet-facing portal, and the offsite backup copy respectively). This is a common and encouraging pattern to find in a gap assessment, because it means the required uplift is largely about tightening and extending existing practice rather than building new capability from nothing — reflected in the low-cost, achievable-within-financial-year roadmap that follows.

---

*This assessment is a fictional portfolio exercise created to demonstrate ACSC Essential Eight gap assessment methodology. Meridian Consulting Group is a fictional entity; findings and evidence are illustrative of common real-world patterns, not an excerpt of a real organisation's environment.*
