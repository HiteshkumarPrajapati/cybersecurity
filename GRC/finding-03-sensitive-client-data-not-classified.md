# Finding 03 — Sensitive Client Data Not Classified or Labelled

| | |
|---|---|
| **Audit** | Meridian Consulting Group — Internal Audit, Information Security Controls |
| **Control domain** | Information classification and handling |
| **Risk rating** | Medium |
| **Framework reference** | ISO/IEC 27001:2022 A.5.12 (Classification of information), A.5.13 (Labelling of information) · Privacy Act 1988 (Cth), Australian Privacy Principle 11 |
| **Date raised** | July 2026 |
| **Status** | Accepted by management — remediation planned |

## Condition

We sampled a handful of SharePoint sites used for active client engagements — six in total, chosen to span a mix of older and newer clients — and looked at how the material inside was organised. Client deliverables, working papers, internal drafts, and in several cases scanned copies of client financial statements and identity documents were sitting in the same folder structure, distinguished only by the client's name and project phase. There is nothing in the folder names, metadata, or file properties that flags anything as more sensitive than anything else. A staff member's access to a client site is effectively all-or-nothing — once you're granted access to the engagement folder, you can see everything in it, from a meeting agenda to a client's tax file number.

We also checked whether Microsoft Purview sensitivity labels were configured anywhere in the tenant. They aren't. The capability exists in Meridian's current Microsoft 365 licensing — it simply hasn't been switched on or configured.

## Criteria

ISO 27001 Annex A.5.12 requires information to be classified according to the information security needs of the organisation, based on confidentiality, integrity, availability, and relevant legal or regulatory requirements. A.5.13 requires an appropriate set of procedures for labelling information, consistent with that classification scheme. Neither exists at Meridian in any form — there's no scheme to classify against, and consequently nothing to label.

Under APP 11 of the Privacy Act, an entity holding personal information must take reasonable steps to protect it against misuse, interference, loss, and unauthorised access. It's a genuinely difficult position to defend that standard when the organisation can't point to having identified which of its information actually needs that heightened protection in the first place — you can't apply "reasonable steps" in proportion to sensitivity if sensitivity was never assessed.

## Root cause

This traces back to the 2019 migration off the old on-premises file server onto SharePoint. That project was scoped and delivered as a straightforward lift-and-shift — get everything into one place, make it searchable, stop relying on a server nobody wanted to maintain — and classification was never part of the brief. It's a fairly common pattern: migrations tend to optimise for "get the data somewhere better" rather than "get the data somewhere better *and* organised by sensitivity," because the second part takes real thought and nobody's explicitly asked for it since. No one has owned this as a piece of work in the years since the migration completed.

## Risk

The immediate consequence is that Meridian has no mechanism to apply differentiated controls based on how sensitive something actually is. Everything gets the same treatment, which in practice tends to mean everything gets treated like it's less sensitive than the most sensitive thing in the folder, simply because nothing stands out. That makes oversharing more likely — a staff member added to a project for a narrow reason ends up with visibility into a client's full financial picture because access is granted at the folder level, not the document level. It also means Meridian can't currently apply automated controls like data loss prevention rules that key off a sensitivity label (for example, blocking a "Highly Confidential" file from being emailed to a personal address), because there's no label for those rules to act on.

There's a second-order risk worth flagging too: if Meridian ever did experience a breach or unauthorised disclosure, being able to say precisely what was exposed — and how sensitive it was — matters a great deal for the NDB assessment process referenced in Finding 02, and for communicating clearly and accurately with affected clients. Without classification, that assessment becomes slower and less precise exactly when speed and precision matter most.

## Recommendation

Start simple rather than trying to build an elaborate scheme nobody will actually use. A four-tier structure — Public, Internal, Confidential, Highly Confidential — covers the practical reality of what Meridian holds without requiring staff to make fine-grained judgement calls they won't have time for day to day. Once that's agreed, the mechanical part is straightforward given the existing licensing: configure Microsoft Purview sensitivity labels matching the tiers, apply them (at minimum) to the client engagement sites where personal and financial information is most likely to sit, and put basic DLP rules in place tied to the "Highly Confidential" label as a first step — this is where the risk is concentrated, so it's the sensible place to start rather than trying to label everything on day one. All of this needs a short round of staff guidance so people understand what each tier actually means in practice, otherwise the labels just become a formality nobody applies consistently.

## Management response

**Accepted.** Practice Manager agreed the classification scheme should be defined with input from a couple of senior client-facing staff, not just IT, since they're the ones who best understand what's genuinely sensitive across different engagement types. IT Manager to lead the Purview configuration once the scheme is agreed.

| | |
|---|---|
| **Owner** | Practice Manager (scheme definition) / IT Manager (technical implementation) |
| **Target date** | Classification scheme agreed within 30 days; Purview labelling configured and applied to priority client sites within 90 days |
| **Follow-up** | Next audit to sample a fresh set of client sites and confirm labels are actually present and being applied to new documents, not just configured and forgotten |

---

*This finding is part of a fictional portfolio exercise demonstrating ISO 27001-referenced audit finding technique. Meridian Consulting Group is a fictional entity.*
