# Policy Review — Remote Work / Work From Home Policy (CloudReach CRM)

## 1. Document control

| Field | Detail |
|---|---|
| **Policy title** | CloudReach CRM — Remote Work Policy |
| **Policy owner** | People & Culture Lead (jointly with Head of Engineering) |
| **Version reviewed** | v1.2 |
| **Date of last policy update (per document)** | August 2020 (written during the initial shift to remote work; not substantively updated since) |
| **Review date** | July 2026 |
| **Reviewed by** | GRC Analyst (portfolio exercise) |
| **Review type** | Scheduled (annual review cycle) — overdue; flagged as a finding in its own right (see F01) |
| **Frameworks/obligations assessed against** | ISO/IEC 27001:2022 Annex A (A.6.7, A.7.9, A.8.1); ACSC guidance for securing remote work arrangements; work health and safety obligations under the *Work Health and Safety Act 2011* as they intersect with home-based work |
| **Next review due** | July 2027, or sooner if the office footprint or hybrid work arrangement changes materially |

## 2. Scope and objective of this review

This review covers CloudReach's policy governing staff working remotely, including fully remote staff, hybrid staff, and occasional remote/travel-based work. CloudReach is a fully hybrid organisation (most staff work from home 2–3 days per week), meaning this policy is not a peripheral document — it governs the default working arrangement for the majority of the company, which raises the stakes of the gaps identified below. This review focuses on information security and data handling aspects of remote work; work health and safety (WHS) obligations for home-based work are noted where they intersect with security (e.g. physical security of screens/documents) but a full WHS review is out of scope and separately recommended.

## 3. Executive summary

This policy was written in 2020 during CloudReach's initial, largely reactive shift to remote work, and has not been substantively revised since — despite hybrid work now being the company's permanent default arrangement rather than a temporary measure. The most significant gap is the complete absence of any requirement around home network security (e.g. router firmware, default credentials, guest network separation), despite staff routinely accessing production systems from home networks the company has no visibility into or control over. The policy also does not address use of public Wi-Fi while travelling, screen privacy in shared living spaces, or what happens to company data on a personal device if that device is later sold, lost, or the employee's home is broken into. None of these gaps require a large budget to close — the recommended action is to approve the redlined wording in Section 7, which brings the policy in line with a genuinely hybrid, permanent working model rather than an emergency-era temporary arrangement.

## 4. Policy as written

> **CloudReach CRM — Remote Work Policy (v1.2, August 2020)**
>
> **1. Purpose**
> This policy provides guidance for employees working remotely during the current period of flexible working arrangements.
>
> **2. Eligibility**
> Remote work is available to employees whose role can be performed effectively outside the office, subject to manager approval.
>
> **3. Equipment**
> CloudReach will provide a company laptop for remote work. Employees are responsible for providing their own internet connection.
>
> **4. Security**
> Employees must use the company VPN when accessing company systems remotely. Company devices must not be left unattended in public places.
>
> **5. Working Hours**
> Employees are expected to be available during standard business hours (9am–5pm) unless otherwise agreed with their manager.
>
> **6. Confidentiality**
> Employees must take reasonable steps to protect confidential information while working remotely.

## 5. Findings register

| Finding ID | Clause Ref | Finding | Severity | Framework/Obligation Reference | Recommendation Summary |
|---|---|---|---|---|---|
| F01 | (document control) | Policy has not been substantively reviewed since 2020 despite hybrid work becoming the permanent default arrangement, not a temporary one | **Medium** | General policy governance best practice | Reframe policy as governing permanent hybrid work, not a temporary arrangement; establish overdue review cadence |
| F02 | (missing) | No requirement for home network security baseline (router firmware, default credentials, guest network separation) | **High** | ISO/IEC 27001:2022 A.8.1 (User endpoint devices); ACSC remote work guidance | Add a minimum home network security standard |
| F03 | §4 | VPN is required but the policy doesn't specify which systems require it, is silent on split-tunnelling, and doesn't address the (increasingly common) scenario of cloud services accessed directly without needing the VPN at all | **Medium** | ISO/IEC 27001:2022 A.8.20 (Networks security) | Clarify VPN scope and update for the company's actual current architecture (most SaaS tools use Conditional Access, not VPN, as the control) |
| F04 | (missing) | No guidance on use of public Wi-Fi (cafés, airports, co-working spaces) while working remotely | **Medium** | ACSC remote work guidance | Add explicit guidance: avoid unsecured public Wi-Fi for sensitive work, or mandate VPN/mobile hotspot use when unavoidable |
| F05 | (missing) | No guidance on physical/visual security of the work environment (e.g. screen visible to other household members or via video call background, printed documents) | **Medium** | ISO/IEC 27001:2022 A.7.9 (Security of assets off-premises), A.5.34 (Privacy and protection of PII) | Add practical guidance on screen privacy and physical document handling at home |
| F06 | §3 | No mention of personal device use for company work (BYOD) beyond the company laptop — in practice, staff sometimes check email or use collaboration tools from personal phones/tablets | **Medium** | ISO/IEC 27001:2022 A.8.1 | Cross-reference the BYOD clause recommended in the companion AUP review, rather than leaving this policy silent |
| F07 | (missing) | No guidance on what happens to company data/access if remote work is conducted from overseas (e.g. an extended trip, working from another country) | **High** | Privacy Act 1988 (Cth) — cross-border disclosure considerations (APP 8); potential data residency/contractual obligations to customers | Add a requirement to seek approval before working from overseas, referencing data residency and legal/tax considerations |
| F08 | (missing) | No incident-reporting or lost-device process specific to the remote context (e.g. what to do if a home is broken into, a device is lost while travelling) | **High** | ISO/IEC 27001:2022 A.6.8 (Information security event reporting) | Add explicit reporting expectation, cross-referencing the AUP's incident-reporting clause |
| F09 | §6 | "Reasonable steps to protect confidential information" is not defined with any practical examples specific to a home environment | **Low** | General policy governance best practice | Add concrete, illustrative examples appropriate to home-based work |
| F10 | (missing) | No mention of company equipment insurance/liability if a company laptop is damaged, lost, or stolen from a home or during travel | **Low** | General policy governance / practical operational clarity | Add a short clause clarifying process and expectations (report immediately; company handles replacement per asset policy) |

## 6. Detailed findings

### F01 — Policy framed as temporary despite permanent hybrid arrangement

**What the policy says:** The purpose statement frames the policy as guidance "during the current period of flexible working arrangements," language clearly written in 2020 in response to a temporary, externally-driven shift.
**Why it matters:** CloudReach now operates hybrid work as its permanent default arrangement for most staff, not an exceptional temporary measure — the policy's framing, tone, and lack of subsequent review all suggest it was written once under pressure and never revisited as circumstances stabilised. This isn't a security gap in itself, but it is a strong leading indicator that other, more substantive gaps (see F02–F08) have also gone unaddressed, which the rest of this review confirms.
**Framework/obligation reference:** General policy governance best practice — policies governing a permanent, majority working arrangement warrant at least the same review rigour as any other core company policy.
**Recommendation:** Reframe the purpose statement to describe hybrid work as CloudReach's standard operating model, and bring this policy into the same scheduled annual review cycle as the password and AUP policies reviewed alongside it.

### F02 — No home network security baseline

**What the policy says:** The policy is silent on home network security entirely.
**Why it matters:** Staff routinely connect to production systems and customer data from home networks that CloudReach has no visibility into and no control over. A home router with default admin credentials, outdated firmware, or no separation between the main network and IoT/guest devices represents a materially different (and generally weaker) security boundary than the office network, and this policy currently does nothing to raise that awareness or set any minimum expectation.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.8.1 (User endpoint devices); ACSC guidance for securing remote work arrangements specifically recommends organisations provide staff guidance on securing home networks.
**Recommendation:** Add a minimum home network security standard: change default router admin credentials, keep router firmware updated (or use an ISP-managed device that handles this automatically), and where feasible, keep work devices off the same network segment as smart home/IoT devices.

### F03 — VPN scope and architecture not clarified

**What the policy says:** "Employees must use the company VPN when accessing company systems remotely," without specifying which systems this applies to.
**Why it matters:** As written, this clause reads as though VPN is the universal access control for all company systems — but in CloudReach's actual current architecture, most SaaS tools (Google Workspace, GitHub, the CRM platform itself) are accessed directly over the internet with Conditional Access/IAM as the real control, not the VPN. The VPN is really only relevant for a narrower set of internal, non-SaaS resources. Leaving this vague risks staff either unnecessarily routing all traffic through VPN (creating performance friction and possibly encouraging staff to disable it out of frustration) or, conversely, assuming SaaS tools aren't covered by "company systems" at all.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.8.20 (Networks security).
**Recommendation:** Clarify explicitly which systems require VPN access (name them) and note that SaaS tools are separately protected via mandatory MFA and Conditional Access (cross-reference the password policy review), not the VPN.

### F04 — No guidance on public Wi-Fi use

**What the policy says:** The policy does not mention public Wi-Fi at all.
**Why it matters:** Staff working from cafés, airports, or co-working spaces while travelling is a normal and expected part of a flexible working arrangement, but connecting to unsecured public Wi-Fi networks carries a materially higher risk of traffic interception than a home network, particularly for any traffic not otherwise protected by VPN or HTTPS.
**Framework/obligation reference:** ACSC guidance on securing remote work commonly recommends explicit staff guidance on public Wi-Fi risk.
**Recommendation:** Add guidance recommending staff avoid unsecured public Wi-Fi for sensitive work where practical, and use a mobile hotspot or the company VPN if public Wi-Fi is unavoidable.

### F05 — No guidance on physical/visual security at home

**What the policy says:** The policy does not address the physical or visual security of a home working environment.
**Why it matters:** In a home environment, a screen may be visible to other household members, visitors, or (increasingly relevant) as a background element during video calls, and printed documents may not be stored as securely as they would be in a controlled office environment. This is a genuinely different risk profile from office-based work that the 2020-era policy simply doesn't address.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.7.9 (Security of assets off-premises), A.5.34 (Privacy and protection of PII).
**Recommendation:** Add brief, practical guidance: position screens away from direct view of visitors, use a privacy screen filter if working in a shared space, lock the screen when stepping away (even briefly, at home), and avoid printing client-identifiable documents at home where a portal or on-screen review is a practical alternative.

### F06 — No BYOD cross-reference

**What the policy says:** The policy only addresses the company-provided laptop, despite staff commonly checking email or using lightweight collaboration tools from personal phones while working remotely.
**Why it matters:** This is the same underlying gap identified as F09 in the companion AUP review — addressing it in one policy but not the other creates inconsistency and a missed opportunity to reinforce the same expectation across every document a staff member might read.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.8.1 (User endpoint devices).
**Recommendation:** Rather than duplicating detailed BYOD requirements in two places, add a short cross-reference to the AUP's BYOD clause, keeping the source of truth in one document.

### F07 — No guidance on working from overseas

**What the policy says:** The policy does not distinguish between remote work from home (within Australia) and remote work conducted from overseas.
**Why it matters:** An employee working from overseas for an extended period — even informally, e.g. combining remote work with an extended personal trip — can raise genuine data residency, cross-border disclosure, tax, and employment law considerations that a domestic remote work policy doesn't anticipate. For a SaaS company handling customer PII under Australian Privacy Principle obligations, and potentially subject to customer contractual data residency commitments, this is a real gap, not a theoretical one.
**Framework/obligation reference:** *Privacy Act 1988 (Cth)*, Australian Privacy Principle 8 (cross-border disclosure of personal information); potential customer contractual data residency clauses.
**Recommendation:** Add a requirement that working from overseas for any extended period requires advance manager and People & Culture approval, explicitly flagging that approval may need to consider data residency, tax, and legal implications on a case-by-case basis — this is a coordination/awareness clause, not something the policy itself needs to fully resolve.

### F08 — No remote-specific incident reporting or lost-device process

**What the policy says:** The policy does not address what a staff member should do if their home is broken into, a device is lost while travelling, or another remote-specific incident occurs.
**Why it matters:** A lost or stolen device while travelling, or a break-in at a staff member's home, is a foreseeable scenario for a hybrid workforce, and the policy currently gives no guidance on the expected immediate response, which risks delay in a scenario where speed (e.g. triggering a remote wipe) directly affects the impact of the incident.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.6.8 (Information security event reporting).
**Recommendation:** Add an explicit clause: report a lost or stolen device, or any suspected compromise of the home environment, immediately via the same incident-reporting channel defined in the AUP, so remote wipe/access revocation can be triggered without delay.

### F09 — "Reasonable steps" undefined for a home context

**What the policy says:** "Employees must take reasonable steps to protect confidential information while working remotely," with no home-specific examples.
**Why it matters:** This is a lower-severity clarity gap consistent with a similar finding in the companion AUP review — the standard itself is reasonable, but without concrete examples anchored to the home environment specifically, it's easy for staff to read this as already satisfied by simply having the company laptop, without considering the broader physical/network context this review has identified.
**Framework/obligation reference:** General policy governance best practice.
**Recommendation:** Add 2–3 concrete examples specific to home-based work (screen lock when stepping away, secure storage of any printed documents, not discussing confidential client matters within earshot of non-staff household members).

### F10 — No process for damaged/lost equipment

**What the policy says:** The policy does not address what happens if a company laptop is damaged, lost, or stolen from home or while travelling.
**Why it matters:** This is a low-severity operational clarity gap rather than a security risk on its own (the security response is covered by F08), but leaving it unaddressed means staff don't know what to expect procedurally, which can delay reporting if someone is unsure whether they'll be held financially responsible.
**Framework/obligation reference:** General operational/policy clarity.
**Recommendation:** Add a brief clause clarifying that staff should report loss/damage immediately (cross-referencing F08), and that replacement is handled per the company's asset management process, removing any ambiguity that might otherwise discourage prompt reporting.

## 7. Recommended replacement wording

> **CloudReach CRM — Hybrid and Remote Work Policy (v2.0 — proposed)**
>
> **1. Purpose and Scope**
> This policy sets out requirements for employees working remotely — including CloudReach's standard hybrid working model and any fully remote or travel-based work — to protect company and customer information outside the office environment.
>
> **2. Eligibility**
> Remote work is available to employees whose role can be performed effectively outside the office, subject to manager approval.
>
> **3. Equipment and Home Network**
> CloudReach provides a company laptop for remote work; employees are responsible for their own internet connection. Home networks used for work must have default router administrator credentials changed and router firmware kept up to date (or use an ISP-managed device that does this automatically). Where feasible, keep work devices on a separate network segment from smart home/IoT devices.
>
> **4. Remote Access**
> The company VPN is required for accessing [name specific internal systems]. Most company SaaS tools (email, CRM platform, source code repositories) are protected directly via mandatory multi-factor authentication and do not require the VPN. Avoid using unsecured public Wi-Fi for sensitive work; use a mobile hotspot or the company VPN if public Wi-Fi is unavoidable. Company devices must not be left unattended in public places.
>
> **5. Physical and Visual Security**
> Position your screen away from direct view of visitors where practical, lock your screen when stepping away even briefly, and avoid printing client-identifiable documents at home where reviewing on-screen or via a portal is a practical alternative.
>
> **6. Personal Devices (BYOD)**
> Personal device use for company email or systems is governed by the Acceptable Use Policy's BYOD clause.
>
> **7. Working Overseas**
> Working remotely from outside Australia for an extended period requires advance approval from your manager and People & Culture, who will consider data residency, tax, and legal implications as relevant.
>
> **8. Security Incidents and Lost/Damaged Equipment**
> Report a lost or stolen device, suspected compromise of your home environment, or any other suspected security incident immediately via [defined incident-reporting channel] so access can be revoked or the device remotely wiped without delay. Report damaged equipment through the same channel; replacement is handled per the company asset management process.
>
> **9. Working Hours**
> Employees are expected to be available during standard business hours (9am–5pm) unless otherwise agreed with their manager.
>
> **10. Confidentiality**
> Employees must take reasonable steps to protect confidential information while working remotely — for example, locking your screen when stepping away, storing any printed documents securely, and avoiding discussion of confidential client matters within earshot of non-staff household members.

## 8. Review sign-off

| Field | Detail |
|---|---|
| **Reviewed by** | GRC Analyst (portfolio exercise) |
| **Review date** | July 2026 |
| **Findings accepted by policy owner** | Pending — recommend prioritising F02 (home network baseline) and F08 (incident reporting) as the two findings with the most direct security consequence |
| **Target date for updated policy to be published** | Q3 2026 |
| **Next scheduled review** | July 2027, or sooner upon material change to the company's office footprint or hybrid work model |

---

*This review is a fictional portfolio exercise created to demonstrate GRC policy review methodology. The "as-written" policy is illustrative of common real-world weaknesses, not an excerpt of a real organisation's document, and nothing in this review constitutes legal or work health and safety advice.*
