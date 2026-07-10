# GRC Portfolio — Cyber Risk Register

## What this proves

This portfolio demonstrates practical, end-to-end cyber risk assessment skills as they are applied in Australian GRC (Governance, Risk & Compliance) practice:

- Identifying realistic cyber risks across a business (technical, process, and people-related)
- Rating risks using a structured **likelihood × impact** methodology
- Mapping each risk to relevant controls and control frameworks
- Recommending treatment options (Mitigate / Transfer / Accept / Avoid) with residual risk in mind
- Communicating risk in language a non-technical business stakeholder (e.g. a CFO, Practice Manager, or Board member) can understand and act on

The register is not a compliance checklist — it is written to reflect how a risk register is actually built, used, and reviewed inside a real organisation: owned by named roles, reviewed on a cadence, and tied to a defined risk appetite.

## Frameworks used

| Framework | Purpose in this portfolio |
|---|---|
| **AS ISO 31000:2018 — Risk Management Guidelines** | Provides the overarching risk management process (establish context → identify → analyse → evaluate → treat → monitor & review → communicate & consult) and the likelihood/impact rating structure used throughout. |
| **ISO/IEC 27001:2022 (Annex A)** | Used to map each risk to a relevant information security control from the four Annex A themes: Organisational, People, Physical, Technological. |
| **ACSC Essential Eight** | Used as the primary technical control baseline for Australian organisations, including Maturity Level references (ML0–ML3), per the Australian Cyber Security Centre's Essential Eight Maturity Model. |
| **OAIC Notifiable Data Breaches (NDB) scheme / Privacy Act 1988** | Referenced where a risk could trigger a mandatory data breach notification obligation under Australian law. |

## Repository contents

```
grc-risk-register/
├── README.md                            ← This file
├── risk-register-saas-crm.md            ← Risk register: fictional SaaS CRM (my domain)
├── risk-register-small-business.md      ← Risk register: fictional accounting firm
├── risk-register-template.md            ← Blank template + field definitions
└── notes/
    └── risk-rating-methodology.md       ← How I scored likelihood, impact, and priority
```

## How to read the registers

Each risk register uses the same nine-field structure:

1. **Risk ID** — unique reference (e.g. `CRM-R01`)
2. **Risk Description** — plain-English statement of what could go wrong, and the business consequence
3. **Threat / Vulnerability** — what could exploit what
4. **Existing Controls** — what is already in place today
5. **Inherent Risk** — likelihood × impact *before* crediting existing controls
6. **Residual Risk** — likelihood × impact *after* crediting existing controls
7. **Framework Mapping** — the relevant ISO 27001 Annex A control and/or Essential Eight strategy
8. **Treatment Recommendation** — the recommended next action and treatment type (Mitigate/Transfer/Accept/Avoid)
9. **Risk Owner & Target Date** — who is accountable and by when

Full definitions of the rating scale, matrix, and prioritisation logic are in [`notes/risk-rating-methodology.md`](notes/risk-rating-methodology.md).

## Fictional scenarios

Two contrasting organisations were used deliberately, to show risk assessment isn't one-size-fits-all:

- **SaaS CRM provider** (`risk-register-saas-crm.md`) — a cloud-native, multi-tenant B2B software vendor. Risk profile is dominated by data segregation, API security, third-party/subprocessor risk, and availability.
- **Small accounting firm** (`risk-register-small-business.md`) — a 25-staff professional services firm handling TFNs and client financial data. Risk profile is dominated by business email compromise, ransomware, legacy on-prem systems, and reliance on an outsourced IT provider.

## Disclaimer

All organisation names, staff, and specific incidents referenced in this portfolio are fictional and created for demonstration purposes only. The methodology, control mappings, and treatment logic reflect genuine industry practice.
