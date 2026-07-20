# Evidence Register — Essential 8 Gap Assessment (Meridian Consulting Group)

This register logs the evidence gathered against each ACSC criterion referenced in [`essential8-gap-assessment-report.md`](essential8-gap-assessment-report.md). It is the working artefact underneath the report — every maturity determination in the main report should be traceable back to a row in this register. Where evidence was requested but not provided within the assessment window, this is recorded as **Not sighted**, not assumed either way.

**Legend:** Sighted = evidence directly reviewed and confirmed · Not sighted = requested but not provided/available · Partial = evidence provided but incomplete or inconclusive

---

## Multi-Factor Authentication

| Evidence ID | Criterion Reference | Evidence Requested | Evidence Provided | Status | Assessor Notes |
|---|---|---|---|---|---|
| EV-MFA-01 | ML1 — MFA on internet-facing services | Entra ID Conditional Access policy export | Policy export (PDF) | Sighted | Policy exists but is in "Report-only" enforcement mode, not "On" — confirmed via policy state field in export |
| EV-MFA-02 | ML1 — MFA for external/client users | Client Portal authentication configuration | AWS Cognito user pool MFA settings screenshot | Sighted | MFA enabled by default for external client accounts, confirmed |
| EV-MFA-03 | ML1 — MFA event logging | Entra ID sign-in logs sample (30 days) | Sign-in log export (CSV, 30-day window) | Sighted | Logging is occurring; retention limited to default 30 days (see EV-MFA-06) |
| EV-MFA-04 | ML2 — MFA registration coverage | MFA registration report (all users) | Entra ID MFA registration details export | Sighted | 61 of 80 users (76%) registered for MFA; 19 users (24%) not registered, including 2 Global Administrator accounts |
| EV-MFA-05 | ML2 — MFA for privileged users | List of Global Administrator role assignments + MFA registration status per account | Entra ID Privileged Identity Management role assignment export | Sighted | Confirms 2 of 4 Global Administrator accounts have no MFA method registered |
| EV-MFA-06 | ML2 — Centralised, protected log retention | Log Analytics / SIEM configuration for sign-in log export | Interview response only; no export provided | Not sighted | IT Manager confirmed no centralised log export/SIEM currently configured; logs remain in default Entra ID 30-day retention only |
| EV-MFA-07 | ML3 — Phishing-resistant MFA | FIDO2/security key deployment records | Interview response only | Not sighted | IT Manager confirmed no FIDO2/security key deployment; all MFA is via Microsoft Authenticator app (push/OTP) |
| EV-MFA-08 | ML3 — MFA for important data repositories regardless of internet-facing status | SharePoint/internal data repository access policy | Not requested — ML3 out of immediate scope; noted for future assessment | N/A | Recorded for completeness; not scored in this assessment cycle given ML2 target |

## Patch Applications

| Evidence ID | Criterion Reference | Evidence Requested | Evidence Provided | Status | Assessor Notes |
|---|---|---|---|---|---|
| EV-PATCH-01 | ML1 — Vulnerability scanning, internet-facing services | Vulnerability scan reports for Client Portal (last 6 months) | None available | Not sighted | AWS DevOps contractor confirmed no vulnerability scanning tool is deployed against the Client Portal or its AWS infrastructure |
| EV-PATCH-02 | ML1 — Patch SLA, internet-facing services | Documented patch SLA / change log for Client Portal | Ad hoc change log (partial, informal Slack history referenced but not exportable within assessment window) | Partial | No formal SLA document exists; informal evidence suggests patches applied "reactively," inconsistent with any defined timeframe |
| EV-PATCH-03 | ML1 — Vulnerability scanning, productivity software | Microsoft 365 update compliance report | Microsoft 365 Apps admin centre update channel report | Sighted | Confirms automatic update channel enabled; this is default Microsoft-managed behaviour, not an independently operated scan |
| EV-PATCH-04 | ML1 — Patch timeframe, productivity software | Patch deployment log, last 3 major M365 update cycles | Update history export from Microsoft 365 Apps admin centre | Sighted | Updates applied within Microsoft's standard rollout window; consistent with 1-month ML1 criterion for this software category |
| EV-PATCH-05 | ML1 — File server patch cadence | Windows Server Update Services (WSUS) or equivalent compliance report | WSUS console screenshot | Sighted | Confirms one cumulative security update (released February 2026, addressing a publicly disclosed vulnerability) remained unapplied as of the June 2026 screenshot — approximately 4 months outstanding |
| EV-PATCH-06 | ML1 — EOL software removal | Software asset inventory with support-status flags | Partial spreadsheet-based inventory (not comprehensive, manually maintained) | Partial | Inventory exists but IT Manager confirmed it is updated inconsistently and does not reliably flag EOL status |
| EV-PATCH-07 | ML2 — Weekly scanning, internet-facing services | (as EV-PATCH-01) | None available | Not sighted | Cannot be met given ML1 scanning requirement (EV-PATCH-01) is also unmet |

## Regular Backups

| Evidence ID | Criterion Reference | Evidence Requested | Evidence Provided | Status | Assessor Notes |
|---|---|---|---|---|---|
| EV-BACKUP-01 | ML1 — Backups performed per business continuity requirements | Backup job schedule/configuration for file server and M365 | NAS backup job configuration screenshot; Microsoft 365 retention policy export | Sighted | Nightly backup job confirmed running for file server; M365 retention policy confirmed configured (90-day retention on mailboxes and SharePoint) |
| EV-BACKUP-02 | ML1 — Common restore point | Backup job logs showing synchronised scheduling | NAS backup job logs (last 90 days) | Sighted | Backup jobs run nightly and consistently across all monitored file shares; common point-in-time restore is technically feasible based on job configuration |
| EV-BACKUP-03 | ML1 — Restoration testing | Disaster recovery test report / restoration test log | None available | Not sighted | IT Manager confirmed no restoration test has ever been performed on either the NAS backup or M365 retention capability |
| EV-BACKUP-04 | ML1/ML2 — Access restriction, unprivileged accounts | NAS access control list / permissions export | NAS share permissions export | Partial | Standard staff confirmed restricted from the backup share; however permissions export shows the two IT team accounts share a single administrative login rather than individually attributable accounts |
| EV-BACKUP-05 | ML2 — Access restriction, privileged accounts (excl. backup admin) | Evidence that Global Administrator/other privileged accounts cannot modify or delete NAS backups | Not provided | Not sighted | No technical control confirmed; IT Manager could not confirm whether Global Administrator credentials would grant modify/delete access to the NAS backup share |
| EV-BACKUP-06 | Business continuity requirement — RTO/RPO | Approved RTO/RPO documentation | None available | Not sighted | No RTO/RPO has been formally defined or approved by Meridian leadership; confirmed via Practice Manager interview |
| EV-BACKUP-07 | Offsite/geographic separation of backup copy | Backup architecture diagram or cloud backup configuration | NAS backup job configuration screenshot (as EV-BACKUP-01) | Sighted (confirms gap) | Configuration confirms the only backup destination is the on-premises NAS device, located in the same server room as the source file server — no offsite or cloud destination configured |

---

## Interview log

| Interview | Role | Date | Key inputs to this assessment |
|---|---|---|---|
| Interview 1 | IT Manager | July 2026 | Primary source for MFA configuration status, patch practices (file server and general), backup configuration and access control, RTO/RPO status |
| Interview 2 | Outsourced AWS DevOps Contractor | July 2026 | Primary source for Client Portal patch/vulnerability management practices and Client Portal authentication configuration |
| Interview 3 | Practice Manager | July 2026 | Confirmed no formally approved RTO/RPO exists; provided business context on the historical file server archive and its ongoing relevance to active client work |

---

*This evidence register is a fictional portfolio exercise created to demonstrate the evidence-gathering rigour behind an ACSC Essential Eight gap assessment. All evidence described is illustrative, not sourced from a real organisation.*
