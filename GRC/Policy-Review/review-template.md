# Policy Review Template

Use this template to run a new policy review. Field definitions are below each section. Rating logic is consistent with the methodology used in the companion [Cyber Risk Register](../grc-risk-register/notes/risk-rating-methodology.md) portfolio.

---

## 1. Document control

| Field | Detail |
|---|---|
| **Policy title** | |
| **Policy owner** | *(role, not GRC — GRC reviews and advises, the business owns the policy)* |
| **Version reviewed** | |
| **Date of last policy update (per document)** | |
| **Review date** | |
| **Reviewed by** | |
| **Review type** | Scheduled / Triggered *(e.g. incident, audit finding, regulatory change, new system)* |
| **Frameworks/obligations assessed against** | |
| **Next review due** | |

## 2. Scope and objective of this review

*State plainly what is and isn't in scope. A password policy review, for example, might explicitly exclude the technical enforcement mechanism (Azure AD Conditional Access config) and focus only on the written policy — note that as a limitation and a separate recommended review.*

## 3. Executive summary

*3–5 sentences, plain English, for a non-technical stakeholder. State: overall assessment (e.g. "the policy is broadly fit for purpose but has three gaps that should be closed within 90 days"), the single highest-priority finding, and the recommended decision being asked of the reader (approve updated wording / allocate budget / accept a documented risk).*

## 4. Policy as written

*Quote the current clauses in full, numbered, so every finding below can reference a specific clause. If reviewing a real document, this is copied verbatim; in this portfolio, a realistic fictional "as-written" policy is used to demonstrate the review technique.*

## 5. Findings register

| Finding ID | Clause Ref | Finding | Severity | Framework Reference | Recommendation Summary |
|---|---|---|---|---|---|
| e.g. F01 | | | Low / Medium / High / Critical | | |

**Severity definitions:**

| Severity | Definition |
|---|---|
| **Critical** | Policy gap creates an active, exploitable control failure or a clear breach of a legal/regulatory obligation. Requires action before the policy can be considered fit for purpose. |
| **High** | Policy gap materially weakens the control environment or creates ambiguity that would likely fail an audit or external assessment. Requires action within the current quarter. |
| **Medium** | Policy is workable but contains an outdated practice, an unclear responsibility, or a missing supporting process. Should be actioned at the next scheduled review or sooner if low-effort. |
| **Low** | Minor wording, formatting, or clarity improvement with limited risk consequence if left as-is until the next scheduled review. |

## 6. Detailed findings

*For each finding: what the policy says (or fails to say), why it matters (tie to a real-world consequence, not just "best practice says so"), and the specific framework clause or legal obligation it maps to.*

### [Finding ID] — [Short title]

**What the policy says:** …
**Why it matters:** …
**Framework/obligation reference:** …
**Recommendation:** …

## 7. Recommended replacement wording

*Provide actual redlined or rewritten clause text, not just a description of what should change. A recommendation the policy owner can copy-paste (and then tailor) gets actioned faster than a recommendation they have to translate themselves.*

## 8. Review sign-off

| Field | Detail |
|---|---|
| **Reviewed by** | |
| **Review date** | |
| **Findings accepted by policy owner** | Yes / Partially / Pending |
| **Target date for updated policy to be published** | |
| **Next scheduled review** | *(Recommend annually at minimum, or triggered by a material control/technology change)* |

## Tips for running a real policy review

1. **Read it as an outsider would, not as the author would.** If you already know what the policy "means," you'll unconsciously fill gaps a new employee or auditor wouldn't.
2. **Check the policy against what actually happens.** A policy that says MFA is mandatory when it isn't technically enforced is arguably worse than having no stated policy at all — it creates a false assurance.
3. **Don't cite a framework you haven't actually checked.** If you reference NIST SP 800-63B or an ISO clause, know the actual current wording — frameworks get updated (e.g. NIST's 2017 shift away from mandatory password rotation is still not reflected in many Australian organisations' policies).
4. **Separate "wrong" from "outdated."** Some findings are compliance gaps; others are simply stale practice that was reasonable when written. Say which is which — it changes the urgency.
5. **Always propose wording.** A finding that says "clause is too vague" without proposed replacement text usually sits in a backlog. A finding with ready-to-adopt wording gets actioned in the same meeting.
