# Finding 01 — MFA Not Enforced for Privileged Accounts

| | |
|---|---|
| **Audit** | Meridian Consulting Group — Internal Audit, Information Security Controls |
| **Control domain** | Access control / authentication |
| **Risk rating** | High |
| **Framework reference** | ISO/IEC 27001:2022 A.8.5 (Secure authentication), A.8.2 (Privileged access rights) · ACSC Essential Eight — Multi-Factor Authentication (ML2) · Privacy Act 1988 (Cth), Australian Privacy Principle 11 |
| **Date raised** | July 2026 |
| **Status** | Accepted by management — remediation in progress |

## Condition

During the walkthrough of Meridian's Microsoft 365 tenant, we reviewed the Entra ID Conditional Access configuration and the current MFA registration status for all accounts holding the Global Administrator role. Of the four accounts with Global Administrator access, two had no MFA method registered at all. The Conditional Access policy that would otherwise require MFA tenant-wide is configured in "Report-only" mode, meaning it logs what would have happened if enforced, but doesn't actually block a sign-in that skips MFA.

We asked the IT Manager directly whether this was a known gap or a surprise, and it was somewhere in between — he was aware MFA wasn't fully rolled out for standard users, but hadn't specifically checked whether it extended to the admin accounts, and was visibly uncomfortable once we pulled the registration report together in the meeting. That reaction is worth noting for the record, because it tells you this wasn't a documented, risk-accepted decision — it was simply a gap nobody had gone looking for.

## Criteria

ISO 27001 Annex A.8.5 requires secure authentication technologies and procedures to be implemented based on information access restrictions and the applicable policy. A.8.2 goes further for privileged access specifically, requiring the allocation and use of privileged access rights to be restricted and managed. The ACSC Essential Eight's Multi-Factor Authentication strategy, at Maturity Level 2, explicitly requires MFA for privileged users of systems, not just general staff. And under APP 11 of the Privacy Act, an organisation holding personal information is required to take reasonable steps to protect it from misuse, interference, loss, and unauthorised access — a standard that's difficult to credibly claim is met when the accounts with the broadest access to that information have no second authentication factor at all.

## Root cause

MFA was rolled out at Meridian on an opt-in basis when it was first introduced, and no one ever came back to make it mandatory. There's no single person who owns "MFA enforcement" as an accountability — it sits somewhere between the IT Manager's day-to-day admin work and a decision that, in practice, would need Practice Manager sign-off to enforce (since it affects all staff, not just IT). Nobody made that decision either way. It just never got escalated.

## Risk

A Global Administrator account is, functionally, the keys to everything — email, SharePoint (which holds the bulk of client financial and personal information following the 2019 migration off the old file server), and the ability to create, modify, or remove any other user account in the tenant. If either of the two unprotected admin accounts is compromised — and a plain password, with no MFA behind it, is compromised through phishing or credential stuffing more often than most people assume — an attacker doesn't need to find a second way in. They already have full administrative control.

This isn't a theoretical scenario dressed up to sound alarming. It's one of the most common patterns in real incident response engagements: a single compromised admin credential, no MFA in the way, and the rest of the incident is just how far the attacker chooses to go. Given the personal and financial information Meridian holds on behalf of its clients, this also puts the firm in a difficult position if it were ever asked to demonstrate it had taken "reasonable steps" under the Privacy Act — an auditor, or worse, the OAIC, would reasonably ask why the highest-privilege accounts in the environment were the least protected ones.

## Recommendation

Enforce MFA for all four Global Administrator accounts immediately — this doesn't require new licensing or budget, just switching the existing Conditional Access policy from report-only to enforced for this specific group of accounts, and it can realistically be done the same week this finding is raised. Separately, and on a slightly longer timeline, move the tenant-wide Conditional Access policy from report-only to enforced for all staff, with a short communication to the team beforehand so it doesn't land as a surprise. We'd also recommend Meridian consider a hardware security key (FIDO2) for the admin accounts specifically, given how disproportionate the impact of a compromised admin credential is compared to a standard user account — that's a slightly bigger step and doesn't need to happen this week, but it's worth having on the roadmap.

## Management response

**Accepted.** IT Manager confirmed MFA enforcement for the four Global Administrator accounts would be actioned within 5 business days of this finding being raised, ahead of the broader tenant-wide rollout. Practice Manager has been briefed and has approved moving the tenant-wide policy to enforced within 30 days, following staff communication.

| | |
|---|---|
| **Owner** | IT Manager |
| **Target date — privileged accounts** | Within 5 business days |
| **Target date — tenant-wide enforcement** | Within 30 days |
| **Follow-up** | To be verified at next audit cycle via a fresh MFA registration report, not taken on management's word alone |

---

*This finding is part of a fictional portfolio exercise demonstrating ISO 27001-referenced audit finding technique. Meridian Consulting Group is a fictional entity.*
