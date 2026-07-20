# GRC Portfolio — Audit-Style Findings

## What this proves

Anyone can write "you should enable MFA." The harder skill — the one that actually gets budget approved and findings closed — is writing it up the way an auditor does: what did you actually observe, what should have been in place instead, why does the gap matter in terms someone outside IT will care about, and what specifically needs to happen next.

This project contains three findings written in that format, off the back of an ISO 27001-referenced internal audit conducted at **Meridian Consulting Group** — the same fictional ~80-staff advisory firm used in the companion [Essential 8 Gap Assessment](../grc-essential8-gap-assessment). One of the three findings here (MFA on privileged accounts) picks up directly from a gap that assessment already flagged; the other two — incident response and data classification — sit outside that earlier scope and were picked up separately during this audit. That overlap is intentional. Real organisations don't get assessed once and fixed forever; the same gap tends to show up again in the next piece of work if it wasn't actually closed, and a portfolio that shows that continuity is more honest than one where every project starts from a clean slate.

## Format used

Each finding follows the **Condition / Criteria / Risk / Recommendation** structure, which is standard across ISO 27001 internal/external audits and most Australian GRC consulting engagements. In practice a finding write-up also needs a root cause and a management response to actually close the loop, so those are included too — a finding without a cause tends to get "fixed" in a way that doesn't stop it recurring, and a finding without a documented management response just sits open indefinitely with no one accountable for it.

- **Condition** — what was actually observed during the audit, stated plainly, with evidence
- **Criteria** — what should have been in place, referencing the specific control clause or legal obligation
- **Root Cause** — why the gap exists, not just that it exists
- **Risk** — the real-world consequence if it's left as-is, written for a business audience
- **Recommendation** — the specific action needed to close it
- **Management Response** — whether the finding is accepted, by whom, and by when

## Frameworks referenced

- **ISO/IEC 27001:2022 Annex A** — the primary control reference throughout
- **ACSC Essential Eight** — referenced specifically for Finding 1, which overlaps directly with the MFA strategy
- **Privacy Act 1988 (Cth)**, including the Australian Privacy Principles and the Notifiable Data Breaches scheme — referenced wherever a finding has a genuine legal/regulatory dimension, not tacked on as decoration

## Repository contents

```
grc-audit-findings/
├── README.md                                           ← This file
├── findings-register-summary.md                       ← One-page tracker, all three findings
├── finding-01-mfa-not-enforced-privileged-accounts.md
├── finding-02-no-formal-incident-response-plan.md
└── finding-03-sensitive-client-data-not-classified.md
```

Start with the register if you just want the shape of the audit at a glance. Each individual finding file is the full write-up an audit committee or a client's risk and compliance lead would actually receive.
