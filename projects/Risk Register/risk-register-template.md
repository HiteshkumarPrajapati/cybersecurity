# Cyber Risk Register — Template

Use this template to run a new risk assessment. Field definitions are below the table. Rating scale and matrix are defined in [`notes/risk-rating-methodology.md`](notes/risk-rating-methodology.md).

---

## Register

| Risk ID | Risk Description | Threat / Vulnerability | Existing Controls | Inherent L | Inherent I | Inherent Rating | Residual L | Residual I | Residual Rating | Framework Mapping | Treatment Type | Treatment Recommendation | Risk Owner | Target Date | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| e.g. XXX-R01 | | | | | | | | | | | | | | | Open / In Progress / Closed |

---

## Field definitions

| Field | Definition |
|---|---|
| **Risk ID** | Unique identifier, format `[PROJECT PREFIX]-R[NN]` (e.g. `CRM-R01`). Prefix should reflect the entity/system being assessed. |
| **Risk Description** | Plain-English "if / then" statement: the event, its cause, and the business consequence. Written so a non-technical stakeholder understands what could go wrong and why it matters. Avoid pure technical jargon — translate it. |
| **Threat / Vulnerability** | The threat actor or event (e.g. external attacker, malicious insider, misconfiguration, third-party failure) paired with the specific weakness it could exploit. |
| **Existing Controls** | Controls that are demonstrably in place *today* — not planned, not aspirational. Should be specific enough to be auditable (e.g. "MFA enforced on all admin accounts via Azure AD Conditional Access" rather than "MFA in place"). |
| **Inherent L / I / Rating** | Likelihood (1–5) and Impact (1–5) assuming no controls exist, multiplied to give the inherent risk score and band (Low/Medium/High/Extreme). |
| **Residual L / I / Rating** | Likelihood and Impact after crediting existing controls. This is the rating that should drive prioritisation and reporting to management. |
| **Framework Mapping** | Relevant ISO/IEC 27001:2022 Annex A control reference(s) and/or ACSC Essential Eight strategy(ies), including Essential Eight Maturity Level where applicable. |
| **Treatment Type** | One of: **Mitigate** / **Transfer** / **Accept** / **Avoid** (see methodology notes for definitions). |
| **Treatment Recommendation** | The specific, actionable next step — should be concrete enough to assign and track (e.g. "Enable geo-blocking on VPN gateway for non-AU traffic by [date]"), not a vague aspiration. |
| **Risk Owner** | The accountable role (not necessarily the person who will do the work) — typically a business owner (e.g. Head of Engineering, Practice Manager), not the GRC/security function itself. GRC facilitates; the business owns the risk. |
| **Target Date** | Date by which the treatment action should be implemented and the residual rating re-tested. |
| **Status** | `Open` (not yet actioned), `In Progress` (treatment underway), `Closed` (treatment implemented and residual risk re-validated), or `Accepted` (formally accepted at current residual rating, with sign-off recorded). |

## Tips for running the assessment

1. **Identify before you rate.** Run a structured identification pass first (asset-based, threat-based, or scenario-based) before assigning any scores — rating too early anchors the discussion.
2. **Separate inherent from residual explicitly.** Stakeholders often only think in residual terms; showing both demonstrates the value of existing controls and justifies (or challenges) further spend.
3. **Validate impact with the business, not just IT.** A CFO or Practice Manager will usually have a more accurate view of financial and reputational consequence than a technical control owner.
4. **Don't let "Accept" become a default.** Every accepted risk above appetite should have a named approver and a review date, not silence.
5. **Re-test after treatment.** A treatment recommendation isn't "closed" until the residual rating has actually been re-assessed and evidenced.
