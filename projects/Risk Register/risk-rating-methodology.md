# Risk Rating Methodology

This note explains how likelihood, impact, and priority were scored across both risk registers in this portfolio. It follows the risk assessment process described in **AS ISO 31000:2018 — Risk Management Guidelines**, and is written the way a methodology section would appear in a real client-facing risk register or internal audit workpaper.

---

## 1. Risk management process (AS ISO 31000)

AS ISO 31000 describes risk management as an iterative process, not a one-off exercise:

1. **Establish the context** — understand the organisation's objectives, risk appetite, and the internal/external environment
2. **Risk identification** — find risks that could help or prevent the organisation achieving its objectives
3. **Risk analysis** — understand the nature of the risk, including likelihood and consequence
4. **Risk evaluation** — compare analysed risk against the organisation's risk criteria to decide if treatment is needed
5. **Risk treatment** — select and implement options to modify the risk
6. **Monitoring and review** — track risk and control effectiveness over time
7. **Recording and reporting** / **Communication and consultation** — run throughout all stages

Each risk register in this portfolio is the output of steps 2–5 for a point-in-time assessment. In a live environment, steps 6–7 would be operationalised through quarterly risk committee reviews, control testing, and incident-driven re-assessment.

---

## 2. Likelihood scale (1–5)

Likelihood reflects the probability of the risk event occurring within a **12-month** period, given the current threat environment and any existing controls credited in the *residual* rating.

| Rating | Descriptor | Definition |
|---|---|---|
| 1 | Rare | May occur only in exceptional circumstances (<5% chance in 12 months) |
| 2 | Unlikely | Could occur at some time (5–25% chance in 12 months) |
| 3 | Possible | Might occur at some time (25–50% chance in 12 months) |
| 4 | Likely | Will probably occur in most circumstances (50–75% chance in 12 months) |
| 5 | Almost Certain | Expected to occur in most circumstances (>75% chance in 12 months) |

Likelihood judgements were informed by:
- ACSC Annual Cyber Threat Report trends (e.g. business email compromise and ransomware remain top reported incident types for Australian SMEs)
- Sector-specific threat intelligence (e.g. professional services and accounting firms are frequently targeted for BEC due to access to trust accounts and client financial data)
- Maturity of existing controls (a risk with strong existing controls is rated lower on residual likelihood than inherent likelihood)

## 3. Impact / consequence scale (1–5)

Impact was assessed across four consequence lenses — **financial, operational, reputational, and regulatory/legal** — and the highest applicable consequence drives the overall rating (a "worst reasonable case" approach, not a "worst conceivable case" approach).

| Rating | Descriptor | Financial (indicative) | Operational | Regulatory / Legal | Reputational |
|---|---|---|---|---|---|
| 1 | Insignificant | <$10K | No disruption to service | No reporting obligation | No external visibility |
| 2 | Minor | $10K–$50K | Localised disruption, resolved within a day | Internal incident register only | Isolated client complaint |
| 3 | Moderate | $50K–$250K | Disruption to a business unit for 1–3 days | Possible OAIC notification considered | Local media / client trust impact |
| 4 | Major | $250K–$1M | Multi-day outage or data loss affecting many clients | Mandatory NDB notification likely (Privacy Act 1988) | National media, client attrition |
| 5 | Severe | >$1M | Extended outage; going-concern risk | Regulatory investigation / enforcement action | Sustained brand damage, loss of key contracts |

## 4. Risk matrix and rating bands

Inherent and residual risk are each calculated as **Likelihood × Impact**, plotted on a 5×5 matrix:

| Likelihood ↓ / Impact → | 1 Insignificant | 2 Minor | 3 Moderate | 4 Major | 5 Severe |
|---|---|---|---|---|---|
| **5 Almost Certain** | Medium (5) | High (10) | High (15) | Extreme (20) | Extreme (25) |
| **4 Likely** | Medium (4) | Medium (8) | High (12) | Extreme (16) | Extreme (20) |
| **3 Possible** | Low (3) | Medium (6) | High (9) | High (12) | Extreme (15) |
| **2 Unlikely** | Low (2) | Low (4) | Medium (6) | Medium (8) | High (10) |
| **1 Rare** | Low (1) | Low (2) | Low (3) | Medium (4) | High (5) |

**Rating bands and response expectations:**

| Band | Score range | Response |
|---|---|---|
| **Low** | 1–3 | Accept and monitor; no immediate action required |
| **Medium** | 4–8 | Manage through routine control activity; review at next scheduled cycle |
| **High** | 9–15 | Requires a documented treatment plan and named owner; report to management |
| **Extreme** | 16–25 | Immediate escalation to senior management/Board; treatment plan required before risk acceptance |

## 5. Inherent vs residual risk

- **Inherent risk** is rated assuming no controls are in place — it reflects the raw exposure.
- **Residual risk** is rated after crediting the controls that currently exist (not planned or aspirational controls).
- The gap between inherent and residual risk is the value delivered by existing controls, and is used to justify further investment (or to show a control is already doing its job).
- Where residual risk remains above the organisation's risk appetite (typically **Medium** for the fictional small business, and **Low–Medium** for the fictional SaaS provider given its B2B customer base), a treatment recommendation is mandatory, not optional.

## 6. Risk treatment options

Consistent with AS ISO 31000, each risk is assigned one of four treatment types:

- **Mitigate (reduce)** — implement or strengthen a control to reduce likelihood and/or impact. This is the default treatment for most risks in this portfolio.
- **Transfer (share)** — shift financial impact via cyber insurance, contractual indemnities, or outsourcing to a provider with stronger controls.
- **Accept** — a deliberate, documented decision to retain the risk because treatment cost exceeds benefit, or the risk is already within appetite. Acceptance must be signed off by the risk owner, not defaulted into.
- **Avoid** — stop the activity that creates the risk (e.g. decommission a legacy system rather than continue to patch it).

## 7. Control framework mapping

Each risk is mapped to:

- **ISO/IEC 27001:2022 Annex A** — using the four 2022 control themes (5 Organisational, 6 People, 7 Physical, 8 Technological controls), referenced by control number (e.g. A.8.24 — Use of Cryptography)
- **ACSC Essential Eight** — one or more of the eight mitigation strategies (application control, patch applications, configure Microsoft Office macro settings, user application hardening, restrict administrative privileges, patch operating systems, multi-factor authentication, regular backups), with reference to Maturity Level where relevant (ML0 = not implemented, ML1–ML3 = increasing rigour)

This dual mapping mirrors how Australian organisations typically operate: ISO 27001 for a certifiable/auditable ISMS, and Essential Eight as the technical baseline expected by government guidance and increasingly by cyber insurers.

## 8. Review cadence

- **Quarterly** — full register review by the risk/GRC function
- **Ad hoc** — triggered by a security incident, a significant change to systems/vendors, or a new regulatory obligation
- **Annually** — re-validation of likelihood assumptions against the latest ACSC Annual Cyber Threat Report and sector threat intelligence
