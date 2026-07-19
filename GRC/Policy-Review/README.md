# GRC Portfolio — Policy Review

## What this proves

This portfolio demonstrates the ability to **read, analyse, and evaluate security policy documents the way a GRC analyst does in a real Australian organisation** — not rewriting a policy from a blank page, but critically reviewing an existing one: identifying what's missing, what's ambiguous, what's outdated against current guidance, and what creates residual risk if left uncorrected.

Each review in this portfolio:

- Starts from a realistic **"as-written" policy** (fictional, but modelled on the kind of policy documents commonly found in Australian SMEs and mid-market organisations — including the specific weaknesses that show up again and again in real reviews)
- Applies a consistent, repeatable **review methodology**
- Produces a structured **findings register** with a risk rating, a framework reference, and a clear recommendation for each finding — written so a business stakeholder (not just an engineer) can understand what's wrong and why it matters
- Closes with **redlined/recommended replacement wording**, because a finding without proposed wording just creates work for someone else

The fictional entity under review — **CloudReach CRM**, the same B2B SaaS company used in the companion [Cyber Risk Register](../grc-risk-register) portfolio — is used again here so the two portfolios read as a consistent, connected body of work rather than disconnected exercises.

## Frameworks referenced

| Framework | Purpose in this portfolio |
|---|---|
| **NIST SP 800-63B — Digital Identity Guidelines (Authentication and Lifecycle Management)** | Current authoritative guidance on password/authenticator policy — used to challenge outdated practices like mandatory periodic rotation and complex composition rules, in favour of length, breach-screening, and MFA. |
| **ACSC Essential Eight (Maturity Level 2)** | Used as the Australian-context technical control baseline, particularly for Multi-Factor Authentication and Restrict Administrative Privileges, referenced throughout all three reviews. |
| **ISO/IEC 27001:2022 Annex A** (with 2013 Annex A.9 cross-references, as many Australian organisations' existing policies still cite the 2013 structure) | Used to map each finding to a recognised, auditable control reference — primarily the A.5 (Organisational) and A.8 (Technological) themes for access control, and A.6 (People) for acceptable use and remote working. |
| **Australian Privacy Principles (Privacy Act 1988)** and state-based workplace surveillance legislation (e.g. NSW *Workplace Surveillance Act 2005*, Vic *Surveillance Devices Act 1999*) | Referenced in the Acceptable Use review where monitoring, logging, and employee privacy intersect — a gap that generic (often US-authored) policy templates routinely miss in an Australian context. |

## Repository contents

```
grc-policy-review/
├── README.md                           ← This file
├── password-policy-review.md          ← Full policy review with gap findings
├── acceptable-use-policy-review.md    ← AUP review
├── remote-work-policy-review.md       ← Remote work / WFH policy review
└── review-template.md                 ← Blank review template
```

## Review methodology (applied consistently across all three reviews)

1. **Establish scope and review criteria** — confirm which policy is under review, its stated purpose, its audience, and which frameworks/legal obligations it should reasonably be assessed against.
2. **Read the policy as written** — no assumptions about intent; if a clause is ambiguous on the page, it is ambiguous in practice.
3. **Clause-by-clause gap analysis** — compare each substantive clause against current framework guidance and identify: missing content, outdated/contradicted guidance, ambiguous or unenforceable language, and misalignment with actual technical controls.
4. **Rate each finding** — Low / Medium / High / Critical, based on the compliance, security, and operational consequence of leaving the gap unaddressed (rating logic is consistent with the AS ISO 31000-based methodology used in the companion risk register portfolio).
5. **Recommend, don't just critique** — every finding includes proposed replacement or additional wording, not just a description of the problem.
6. **Summarise for two audiences** — a plain-English executive summary for business sign-off, and a detailed findings register for the policy owner/GRC function to action.

## How to read a review

Each review file follows the same structure:

1. **Document control** — what was reviewed, when, by whom, and against what version
2. **Executive summary** — 3–5 sentences a non-technical stakeholder (e.g. CFO, People & Culture Lead) can read and act on
3. **Policy as written** — the current clauses under review, quoted in full so findings are traceable
4. **Findings register** — table of all findings with severity and framework mapping
5. **Detailed findings** — the reasoning behind each finding
6. **Recommended replacement wording** — redlined/rewritten clauses ready to go back to the policy owner
7. **Review sign-off** — reviewer, date, and next review due date

Field definitions and a blank version of this structure are in [`review-template.md`](review-template.md).
