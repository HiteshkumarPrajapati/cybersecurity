# Finding 02 — No Formal Incident Response Plan

| | |
|---|---|
| **Audit** | Meridian Consulting Group — Internal Audit, Information Security Controls |
| **Control domain** | Incident management |
| **Risk rating** | High |
| **Framework reference** | ISO/IEC 27001:2022 A.5.24 (Incident management planning and preparation), A.5.25 (Assessment and decision on information security events), A.5.26 (Response to information security incidents), A.5.28 (Collection of evidence) · Privacy Act 1988 (Cth) — Notifiable Data Breaches scheme |
| **Date raised** | July 2026 |
| **Status** | Accepted by management — remediation planned |

## Condition

We asked to see Meridian's incident response plan as part of the standard evidence request for this audit. There isn't one. What exists instead is an informal understanding — largely held in the IT Manager's head — that if something goes wrong, he calls the outsourced MSP, and if it's serious, someone eventually tells the Practice Manager. There's no written escalation path, no defined roles for who makes what decision during an incident, no pre-identified legal or forensic contact, and no record of a tabletop exercise or any kind of incident simulation ever having been run.

We tested this a bit further in the interview by asking a simple hypothetical: if a staff member reported clicking a suspicious link in an email this afternoon, what would actually happen? The answer took a while to land on anything specific. The IT Manager would probably hear about it via Teams message, would probably run a scan, and beyond that it wasn't clear who else would be told, or when, or what would trigger a broader response. That's not a criticism of the IT Manager personally — he was candid about it, and it's a fair reflection of the fact that nobody has ever sat down and actually built this out.

## Criteria

ISO 27001 Annex A.5.24 requires an organisation to plan and prepare for managing information security incidents, including defining roles and responsibilities. A.5.25 requires a documented process for assessing and deciding whether an event constitutes a security incident. A.5.26 requires incidents to be responded to in accordance with documented procedures. A.5.28 requires procedures for the identification, collection, acquisition, and preservation of evidence relevant to an incident — none of which is possible to do consistently without something written down in advance.

Separately, and arguably more pressingly for an Australian firm handling client personal information, the Notifiable Data Breaches scheme under the Privacy Act requires an organisation that suspects it may have experienced an eligible data breach to carry out a reasonable and expeditious assessment, and complete that assessment within 30 days. That's a genuinely tight timeframe to meet on an ad hoc, first-time basis in the middle of an actual incident, and it's the kind of thing that goes far more smoothly when the assessment process has been thought through and written down beforehand rather than improvised under pressure.

## Root cause

This one comes down to ownership more than resourcing. Meridian doesn't have a dedicated security or risk role — incident response has always been implicitly assumed to be "an IT thing," and IT, understandably, has focused its limited time on keeping systems running day to day rather than building out a plan for a scenario that, so far, hasn't happened. Nobody at leadership level has ever explicitly asked for one, and without that push, it's the kind of document that's easy to keep deprioritising indefinitely.

## Risk

The practical consequence of not having a plan isn't that Meridian would fail to respond to an incident at all — the IT Manager clearly would do something. The risk is in the gaps: a slower, less coordinated response than the situation calls for; decisions about containment or communication made inconsistently depending on who happens to be around that day; evidence not preserved properly because nobody thought to before restarting a system or wiping a device; and, most concretely, a real risk of missing the NDB scheme's 30-day assessment window simply because nobody had a defined process to start the clock against.

There's also a quieter cost worth naming. In the event of a genuine breach affecting client data, Meridian's ability to show it had a reasonable, prepared response capability matters — to the OAIC if it comes to that, to affected clients, and to any cyber insurer assessing a claim. Turning up to that conversation with "we called our IT provider and figured it out as we went" is a materially weaker position than being able to point to a documented plan that was actually followed.

## Recommendation

Build a plan that matches Meridian's actual size and resourcing rather than reaching for something enterprise-grade the firm doesn't have the headcount to run. Realistically, this means: a short, one-to-two page document naming who does what (who makes the call to escalate, who talks to clients, who talks to the insurer/legal, who's the technical lead), a pre-identified list of who to call — including confirming what Meridian's cyber insurance actually covers and whether it comes with a panel incident response firm — and a basic eligible data breach assessment checklist mapped to the NDB scheme's timeframe so that clock doesn't start from zero mid-incident. Once that exists, run a short tabletop walkthrough with the senior team — not a full simulation, just enough to surface anything the document missed and to make sure people have actually read it before they need it.

## Management response

**Accepted.** Practice Manager agreed this is overdue and has asked the IT Manager to draft an initial plan, to be reviewed and signed off by the leadership team. Given this touches insurance and legal exposure, Practice Manager will also confirm the firm's current cyber insurance coverage as part of the same piece of work, rather than treating it as a separate item.

| | |
|---|---|
| **Owner** | Practice Manager (drafting support from IT Manager) |
| **Target date** | Draft plan within 45 days; leadership sign-off and initial tabletop walkthrough within 60 days |
| **Follow-up** | Next audit to request the signed-off plan and evidence the tabletop walkthrough actually took place, not just that a document exists |

---

*This finding is part of a fictional portfolio exercise demonstrating ISO 27001-referenced audit finding technique. Meridian Consulting Group is a fictional entity.*
