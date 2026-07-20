# Assessment Methodology — Essential 8 Gap Assessment (Meridian Consulting Group)

## 1. Purpose

This document explains how maturity levels in the accompanying [`essential8-gap-assessment-report.md`](essential8-gap-assessment-report.md) were determined, so a reader can understand the rigour behind each score and where the assessment's limitations sit.

## 2. Assessment approach

This assessment followed a standard three-part evidence-gathering method, consistent with how Essential Eight assessments are typically conducted by Australian GRC practitioners and IRAP-style assessors:

1. **Documentation review** — policies, standards, and configuration standards relevant to each of the three in-scope strategies.
2. **Technical evidence review** — direct evidence of control configuration (e.g. Conditional Access policy exports, patch compliance dashboard screenshots, backup job logs and restoration test records), not just a policy stating the control exists.
3. **Stakeholder interviews** — structured interviews with the IT Manager, the outsourced AWS DevOps contractor, and the Practice Manager, to confirm actual operational practice matches both the documentation and the technical evidence, and to identify any gap between "what the policy says" and "what actually happens" (a gap this portfolio's companion [Policy Review](../grc-policy-review) project also specifically looks for).

Where evidence was requested but not able to be produced within the assessment window, this is recorded explicitly in the [evidence register](evidence-register.md) as **"Not sighted"** rather than assumed absent or assumed present — an honest assessment records what it could and couldn't verify, rather than guessing in either direction.

## 3. Maturity scoring logic

The ACSC Essential Eight Maturity Model defines four maturity levels for each strategy:

| Level | Description |
|---|---|
| **Maturity Level 0 (ML0)** | Weaknesses exist in an organisation's overall cyber security posture for this strategy. Not yet meeting the intent of Maturity Level 1. |
| **Maturity Level 1 (ML1)** | Partly aligned with the intent of the mitigation strategy. Provides a reasonable baseline against unsophisticated, opportunistic threats. |
| **Maturity Level 2 (ML2)** | Mostly aligned with the intent of the mitigation strategy. Addresses adversaries willing to invest more time and effort in a target, and to actively use stolen credentials or exploit weaknesses. |
| **Maturity Level 3 (ML3)** | Fully aligned with the intent of the mitigation strategy. Addresses adversaries who are more adaptive and less reliant on public tooling, and who may target specific individuals with tailored techniques. |

**Critically, this is not a percentage or an average.** Each maturity level is defined by a specific, published set of criteria. An organisation's achieved maturity for a given strategy is **the highest level at which every criterion at that level, and every criterion at every level below it, is fully met.** A single unmet ML1 criterion caps the strategy at ML0, even if every ML2 and ML3 criterion is otherwise satisfied elsewhere. This scoring logic is deliberately strict and mirrors how ACSC itself defines and assesses the model — it exists specifically to prevent organisations from claiming a headline maturity level based on their strongest controls while a foundational gap remains.

This assessment applies that same strict logic throughout: where the detailed report shows a strategy as "ML1 achieved, ML2 not yet achieved," it means at least one ML2 criterion (or an ML1 criterion normally bundled with it) is not met, even if most ML2 criteria are.

## 4. Target maturity level

Meridian Consulting Group's target maturity level for this assessment is **Maturity Level 2**, consistent with ACSC's general guidance that ML2 is an appropriate target for most small-to-mid-size organisations facing commodity and moderately targeted threats, rather than the nation-state-grade adversary profile ML3 is designed to address. This target should be formally confirmed with Meridian's leadership as part of a documented risk appetite decision, not assumed by the assessor — a recommendation carried into the main report.

## 5. Evidence types referenced

| Evidence type | Examples used in this assessment |
|---|---|
| **Policy/procedure documents** | Access control policy, patch management standard, backup and disaster recovery procedure |
| **Technical configuration exports** | Entra ID (Azure AD) Conditional Access policy list, MFA registration report, AWS Systems Manager Patch Manager compliance report |
| **Operational logs/records** | Patch deployment logs (last 6 months), backup job success/failure logs, most recent backup restoration test report |
| **Interview notes** | IT Manager, AWS DevOps contractor, Practice Manager |
| **Screenshots/dashboard exports** | Vulnerability scanner reports, MFA enforcement dashboard |

## 6. Limitations of this assessment

This assessment is **evidence-based and interview-based**, not a technical penetration test or live control validation. Where a control is described as "configured" based on a screenshot or policy export, this assessment did not independently verify the control cannot be bypassed in practice (e.g. it did not attempt to log in without MFA to confirm enforcement). A recommendation to validate key findings via a limited technical review (e.g. an external attack surface review of the AWS-hosted portal) is included in the [remediation roadmap](remediation-roadmap.md) for this reason.

This assessment is also a **point-in-time** assessment (July 2026). Maturity, particularly for Patch Applications, can shift week to week; the report's findings should be read as representative of the environment at the time evidence was gathered, not as a permanently current state.

Finally, this assessment covers **three of the eight** Essential Eight strategies by deliberate scope decision (see the portfolio [README](README.md)). It does not represent Meridian's overall Essential Eight maturity across all eight strategies, and should not be read or cited as such.

---

*This methodology document is part of a fictional portfolio exercise demonstrating GRC gap assessment technique. Meridian Consulting Group is a fictional entity.*
