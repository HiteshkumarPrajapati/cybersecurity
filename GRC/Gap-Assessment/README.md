# GRC Portfolio — ACSC Essential 8 Gap Assessment

## What this proves

This portfolio demonstrates the ability to **assess an organisation's security posture against a structured maturity framework**, the way a GRC analyst does when scoping and delivering a real Essential Eight uplift engagement in Australia: gathering evidence against specific, published criteria (not vibes), scoring honestly against where the evidence actually lands (not where the organisation would like to be), and turning that into findings a business audience can prioritise and fund.

This assessment is deliberately scoped to **three of the eight Essential Eight strategies** — Multi-Factor Authentication, Patch Applications, and Regular Backups — rather than all eight. In a real engagement, scoping down to a defined subset is itself a defensible, common practice: it allows genuine depth (per-criterion evidence, not a checkbox tick) within a realistic assessment window, and these three strategies are consistently the ones with the highest real-world exploitation relevance for a small-to-mid-size professional services firm's actual threat profile (credential compromise, unpatched internet-facing services, and ransomware recovery).

## Fictional entity under assessment

**Meridian Consulting Group** — a fictional ~80-staff Australian management consulting and advisory firm operating a hybrid work model (in-office 2–3 days/week), built primarily on Microsoft 365, with a legacy on-premises file server retained for historical project archives, and a single client-facing web application (a client deliverables portal) hosted on AWS. This profile is intentionally realistic of the professional services segment most Essential Eight engagements in the Australian market are actually scoped for — large enough to have genuine IT complexity and a dedicated (if lean) IT function, but without the security maturity or budget of an enterprise.

## Framework

**ACSC Essential Eight Maturity Model**, as published by the Australian Cyber Security Centre (cyber.gov.au). The Essential Eight defines eight mitigation strategies and, for each, three maturity levels (Maturity Level 1 through Maturity Level 3, sitting above a baseline Maturity Level 0 of "not yet achieved") describing progressively more resilient implementation. This assessment applies the model's real scoring logic: **maturity is assessed per criterion, and an organisation's overall maturity for a strategy is the highest level at which *every* criterion at that level (and all levels below it) is met** — partial implementation of a higher level's criteria does not average out against a lower level; it caps the achieved maturity at the highest level *fully* satisfied.

The three strategies assessed here:

| Strategy | Why it's in scope |
|---|---|
| **Multi-Factor Authentication** | Directly mitigates the most common real-world initial access vector (credential compromise/phishing) reported in the ACSC Annual Cyber Threat Report, and is typically the single highest-leverage, lowest-cost control for an organisation at this maturity stage. |
| **Patch Applications** | Meridian's AWS-hosted client portal is internet-facing and processes client deliverables — unpatched application vulnerabilities on this asset carry a materially higher business impact than on an internal-only system. |
| **Regular Backups** | Meridian retains a legacy on-premises file server holding historical project archives with no confirmed offsite/immutable backup — a single ransomware event could result in irrecoverable loss of client work product. |

## Repository contents

```
grc-essential8-gap-assessment/
├── README.md                              ← This file
├── essential8-gap-assessment-report.md   ← Full assessment: current maturity, gaps, findings
├── assessment-methodology.md             ← How maturity was scored, evidence approach, limitations
├── evidence-register.md                  ← Evidence sighted/requested against each ML criterion
└── remediation-roadmap.md                ← Prioritised uplift roadmap with owners and timeframes
```

## How to read this portfolio piece

1. Start with **`essential8-gap-assessment-report.md`** — this is the primary deliverable, structured the way a real engagement report is: executive summary first, then a maturity scorecard, then the detailed per-strategy assessment against ACSC's published criteria, then a consolidated findings register.
2. **`assessment-methodology.md`** explains *how* the maturity levels were determined — useful for understanding the rigour behind the scoring, and honest about what this assessment does and doesn't cover (e.g. it is evidence-based, not a live penetration test).
3. **`evidence-register.md`** is the working artefact underneath the report — the criterion-by-criterion evidence log a real assessor keeps, showing exactly what was sighted, what was requested but not provided, and what that means for the score.
4. **`remediation-roadmap.md`** turns the findings into a sequenced, resourced plan — because a gap assessment that stops at "here are your gaps" without a realistic path to close them is only half the deliverable.
