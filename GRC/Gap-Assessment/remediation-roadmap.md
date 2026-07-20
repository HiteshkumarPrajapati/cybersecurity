# Remediation Roadmap — Essential 8 Gap Assessment (Meridian Consulting Group)

This roadmap sequences the findings from [`essential8-gap-assessment-report.md`](essential8-gap-assessment-report.md) into an achievable, prioritised plan. Sequencing logic: **Critical findings first regardless of strategy**, then remaining gaps ordered by a combination of risk reduction per dollar/effort and dependency (e.g. some backup fixes are more valuable once the privileged-access MFA gap is closed, since they compound). All target dates assume a decision to proceed is made within 2 weeks of this report being presented to Meridian's leadership.

---

## Prioritisation approach

| Priority tier | Definition |
|---|---|
| **P1 — Immediate (0–30 days)** | Critical findings; low-cost/low-effort actions with disproportionate risk reduction; anything that is a prerequisite for a later action |
| **P2 — Short term (1–3 months)** | High-severity findings; moderate-effort actions requiring some planning, budget approval, or vendor engagement |
| **P3 — Medium term (3–6 months)** | Medium-severity findings; process/governance uplift; items that mature an already-adequate baseline toward ML2/ML3 |
| **P4 — Longer term (6–12 months)** | Lower-severity findings and ML3-aspirational items appropriate to revisit once ML2 is consolidated |

---

## P1 — Immediate (0–30 days)

| Action | Addresses | Owner | Effort | Cost | Notes |
|---|---|---|---|---|---|
| Enforce MFA (switch Conditional Access policy from Report-only to On) for all standard staff accounts, with a 2-week staff communication runway | G-MFA-02 | IT Manager | Low | Nil (already licensed) | Single highest risk-reduction-per-effort action in this entire roadmap; no technical blocker identified |
| Enforce MFA specifically for all Global Administrator and other privileged Microsoft 365 accounts; confirm zero privileged accounts remain unregistered | G-MFA-01 | IT Manager | Low | Nil (already licensed) | Should be actioned even ahead of the tenant-wide rollout above if sequencing is needed — this is the single most disproportionate-impact finding in the report |
| Engage the AWS DevOps contractor to stand up baseline vulnerability scanning against the Client Portal (e.g. AWS Inspector, already natively available in the AWS environment) | G-PATCH-01 | AWS DevOps Contractor / IT Manager | Medium | Low (native AWS tooling, minimal incremental cost) | Recommend running an initial scan within the first week to establish a current-state vulnerability baseline, not just going-forward scanning |
| Apply the outstanding ~4-month overdue Windows Server cumulative update to the file server, following standard change control | G-PATCH-02 | IT Manager | Low | Nil | Immediate remediation of a specific, already-identified overdue patch; do not wait for the broader patch process uplift below |
| Configure a cloud-based or offsite backup destination for the on-premises file server (e.g. Azure Backup, AWS Backup, or a reputable SME-focused offsite backup product), in addition to — not replacing — the existing NAS backup during the transition period | G-BACKUP-01 | IT Manager | Medium | Low–Medium (ongoing cloud storage cost, budget-dependent on data volume) | Directly addresses the single point of failure identified as the most severe backup finding; should be prioritised even ahead of restoration testing, since an untested but geographically separated backup is still safer than a well-tested single-location one |

---

## P2 — Short term (1–3 months)

| Action | Addresses | Owner | Effort | Cost | Notes |
|---|---|---|---|---|---|
| Define and document a patch SLA for the Client Portal (e.g. critical/exploited: 48 hours; other internet-facing: 2 weeks), formalising the ML2 target cadence, and put a recurring scanning schedule (weekly minimum) on the calendar rather than relying on ad hoc engagement | G-PATCH-01 | AWS DevOps Contractor / IT Manager | Medium | Low | Converts the P1 baseline scanning action into an ongoing, accountable process |
| Define and document a patch SLA for the on-premises file server and deploy a vulnerability scanning tool against it (or accelerate the planned migration off the legacy server — see P3) | G-PATCH-02 | IT Manager | Medium | Low–Medium | If the file server retirement (P3 item) is brought forward, this action may become unnecessary — recommend a joint decision with leadership on which path to take |
| Perform a full, timed restoration test from both the new offsite backup and the Microsoft 365 retention capability, documenting actual RTO achieved | G-BACKUP-02 | IT Manager | Medium | Nil (internal effort) | Should be scheduled only once the offsite backup (P1) is in place, so the test validates the backup Meridian will actually rely on going forward |
| Formally define and seek leadership approval for a documented RTO and RPO, to give the backup and patch programs a concrete standard to be measured against | G-BACKUP-03 | Practice Manager / IT Manager | Low | Nil | A governance action, not a technical one — should involve a short discussion with Meridian's leadership team on acceptable downtime/data-loss tolerance |
| Restructure NAS/backup administration to use individually attributable accounts rather than a shared IT login, and confirm (or implement) a technical restriction preventing Global Administrator credentials from modifying/deleting backups | G-BACKUP-04 | IT Manager | Medium | Nil–Low | Directly compounds with the P1 privileged-account MFA fix — closing both together meaningfully reduces the blast radius of a single compromised admin credential |
| Export Entra ID sign-in and MFA event logs to a centralised, longer-retention log store (e.g. Microsoft Sentinel, or a lower-cost log export to Azure Storage if a full SIEM isn't yet justified) | G-MFA-03 | IT Manager | Medium | Low–Medium (licensing-dependent) | A lighter-weight log export/archival approach is a reasonable interim step if a full SIEM deployment isn't proportionate to Meridian's current size |

---

## P3 — Medium term (3–6 months)

| Action | Addresses | Owner | Effort | Cost | Notes |
|---|---|---|---|---|---|
| Formalise a Meridian-managed patch compliance reporting process for Microsoft 365 applications, rather than relying solely on default vendor auto-update behaviour | G-PATCH-03 | IT Manager | Low | Nil | Closes the gap between "patching is probably happening" and "patching compliance can be demonstrated" |
| Build and maintain a complete, regularly reviewed software asset inventory with end-of-life/support-status tracking | G-PATCH-04 | IT Manager | Medium | Nil–Low (tooling-dependent) | Consider a lightweight IT asset management tool if the manually maintained spreadsheet continues to prove unreliable |
| Evaluate a business case for retiring the legacy on-premises file server entirely, migrating remaining historical project archive data to SharePoint | G-PATCH-02, G-BACKUP-01 (long-term simplification) | IT Manager / Practice Manager | High | Medium (migration effort, staff change management) | Would eliminate an entire category of ongoing risk (patch and backup exposure on a single legacy asset) rather than continuing to manage it indefinitely — recommended as a strategic option for leadership consideration, not a mandatory action within this roadmap's timeframe |

---

## P4 — Longer term (6–12 months, ML3-aspirational)

| Action | Addresses | Owner | Effort | Cost | Notes |
|---|---|---|---|---|---|
| Deploy phishing-resistant MFA (FIDO2/security keys) for all Global Administrator and other privileged accounts | G-MFA-04 | IT Manager | Medium | Low–Medium (hardware key procurement) | Not required to reach the ML2 target, but the clearest, most cost-effective step toward ML3 given the disproportionate impact of privileged account compromise; recommended even if broader ML3 uplift isn't pursued firm-wide |

---

## Roadmap summary view

| Priority | Findings addressed | Estimated total effort | Estimated total incremental cost |
|---|---|---|---|
| P1 (0–30 days) | G-MFA-01, G-MFA-02, G-PATCH-01 (baseline), G-PATCH-02, G-BACKUP-01 | Low–Medium | Low |
| P2 (1–3 months) | G-PATCH-01 (process), G-PATCH-02 (process), G-BACKUP-02, G-BACKUP-03, G-BACKUP-04, G-MFA-03 | Medium | Low–Medium |
| P3 (3–6 months) | G-PATCH-03, G-PATCH-04, file server retirement (strategic option) | Medium–High | Nil–Medium (High if server retirement pursued) |
| P4 (6–12 months) | G-MFA-04 | Medium | Low–Medium |

**Expected maturity outcome if this roadmap is fully executed:** Multi-Factor Authentication and Regular Backups reach **ML2**; Patch Applications reaches **ML2** for the Client Portal specifically and at minimum **ML1** firm-wide, with a clear strategic path (file server retirement) to simplify the remaining exposure further. A follow-up assessment is recommended approximately 6 months after P1/P2 actions are completed to confirm maturity uplift and re-baseline against any environment changes in the interim.

---

*This roadmap is a fictional portfolio exercise created to demonstrate how a gap assessment's findings are translated into a sequenced, resourced remediation plan. Cost and effort estimates are illustrative and would be refined against real vendor quotes and internal capacity in an actual engagement.*
