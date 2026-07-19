# Policy Review — Acceptable Use Policy (CloudReach CRM)

## 1. Document control

| Field | Detail |
|---|---|
| **Policy title** | CloudReach CRM — Acceptable Use Policy (AUP) |
| **Policy owner** | People & Culture Lead (jointly with Head of Engineering) |
| **Version reviewed** | v1.4 |
| **Date of last policy update (per document)** | November 2021 |
| **Review date** | July 2026 |
| **Reviewed by** | GRC Analyst (portfolio exercise) |
| **Review type** | Scheduled (annual review cycle) |
| **Frameworks/obligations assessed against** | ISO/IEC 27001:2022 Annex A (A.5.10, A.5.9, A.6.3); Australian Privacy Principles (Privacy Act 1988 (Cth)); NSW Workplace Surveillance Act 2005 (as CloudReach's largest office is in Sydney); ACSC guidance on acceptable use and shadow IT |
| **Next review due** | July 2027, or sooner if monitoring tooling or company device policy changes materially |

## 2. Scope and objective of this review

This review covers CloudReach's Acceptable Use Policy as it applies to all staff use of company-provided IT assets (laptops, accounts, cloud services) and, where relevant, personal devices used to access company systems (BYOD). This review pays particular attention to two areas that are commonly under-addressed in Australian AUPs adapted from overseas (typically US) templates: (1) the legal requirements around **notifying staff of monitoring** under Australian workplace surveillance law, which differs meaningfully from US practice, and (2) the operational reality of **shadow IT**, which this review's companion risk register (CRM-R13) already identifies as an active gap.

## 3. Executive summary

The current AUP is reasonably comprehensive on the topics it does cover, but has three material gaps a non-technical reader should be aware of. First, the policy states that "all use of company systems may be monitored" without specifying what is actually monitored, how, or for what purpose — this is very likely insufficient to meet Australian workplace surveillance notification obligations, which are more prescriptive than many organisations assume, particularly in NSW where CloudReach's largest office sits. Second, the policy has no provision addressing unsanctioned SaaS tools (shadow IT), despite this being an active, identified risk in CloudReach's risk register. Third, the consequences section is vague enough that it would be difficult to enforce consistently or defensibly in a genuine misconduct case. None of these findings require significant cost to remediate — the recommended action is to approve the redlined wording in Section 7, and separately confirm with Legal/People & Culture that the monitoring notice meets current NSW and Commonwealth requirements before publishing.

## 4. Policy as written

> **CloudReach CRM — Acceptable Use Policy (v1.4, November 2021)**
>
> **1. Purpose**
> This policy sets out acceptable use of CloudReach company systems, including computers, email, internet access, and company accounts.
>
> **2. General Use**
> Company systems are provided for business purposes. Reasonable personal use is permitted provided it does not interfere with work duties, consume excessive resources, or bring the company into disrepute.
>
> **3. Prohibited Activities**
> Employees must not:
> - Access, download, or distribute illegal, offensive, or inappropriate content
> - Use company systems for personal commercial gain
> - Install unauthorised software
> - Attempt to bypass security controls
>
> **4. Monitoring**
> CloudReach reserves the right to monitor all use of company systems, including email and internet activity, at any time.
>
> **5. Social Media**
> Employees should exercise good judgement when posting on social media and must not disclose confidential company information.
>
> **6. Consequences**
> Failure to comply with this policy may result in disciplinary action.

## 5. Findings register

| Finding ID | Clause Ref | Finding | Severity | Framework/Obligation Reference | Recommendation Summary |
|---|---|---|---|---|---|
| F01 | §4 | Monitoring clause is too vague to satisfy Australian workplace surveillance notification requirements | **Critical** | NSW Workplace Surveillance Act 2005; Privacy Act 1988 (Cth), APP 1 & 5 | Specify what is monitored, how, why, and how staff can raise concerns; confirm compliance with Legal |
| F02 | (missing) | No provision addressing unsanctioned SaaS tools / shadow IT | **High** | ISO/IEC 27001:2022 A.5.9, A.5.10; linked to risk CRM-R13 | Add a shadow IT clause with a fast, sanctioned request path |
| F03 | §6 | Consequences section is too vague to be consistently or defensibly enforced | **Medium** | General policy governance / employment law best practice | Reference the disciplinary policy explicitly and describe a proportionate response scale |
| F04 | §3 | "Install unauthorised software" is not defined and is not technically enforced (no application allow-listing), creating a policy-practice gap | **Medium** | ACSC Essential Eight — Application Control (ML0 currently) | Clarify definition and cross-reference the Essential Eight uplift roadmap already underway elsewhere in the environment |
| F05 | (missing) | No explicit incident-reporting obligation — staff are not told what to do if they suspect a security incident, click a phishing link, or lose a device | **High** | ISO/IEC 27001:2022 A.6.8 (Information security event reporting) | Add a clear, low-friction reporting obligation and channel |
| F06 | §2 | "Reasonable personal use" and "excessive resources" are undefined, which is workable day-to-day but unenforceable if ever contested | **Low** | General policy governance best practice | Add illustrative (not exhaustive) examples to anchor the standard |
| F07 | §5 | Social media clause does not address staff identifying themselves as CloudReach employees or discussing work-related matters that could be misattributed as official company positions | **Low** | ISO/IEC 27001:2022 A.5.10 | Add guidance on personal disclosure statements when discussing work publicly |
| F08 | (missing) | No mention of acceptable use of AI tools (e.g. pasting customer data into public AI chat tools) — a materially different risk landscape from 2021 when the policy was last written | **High** | ISO/IEC 27001:2022 A.5.9 (Inventory of information assets), A.5.34 (Privacy and protection of PII) | Add an explicit AI tool use clause, distinguishing sanctioned/company-approved tools from public consumer tools |
| F09 | §2 | No reference to BYOD (personal devices used to access company email/systems), despite this being common practice at CloudReach | **Medium** | ISO/IEC 27001:2022 A.8.1 (User endpoint devices) | Add a BYOD clause or explicit cross-reference to a separate BYOD standard |

## 6. Detailed findings

### F01 — Monitoring clause too vague for Australian obligations

**What the policy says:** "CloudReach reserves the right to monitor all use of company systems, including email and internet activity, at any time."
**Why it matters:** This kind of broad, undefined monitoring clause is a very common pattern in AUPs adapted from US templates, where notification requirements are generally lighter. In Australia — and specifically in NSW, where surveillance of employees at work is directly regulated — employers are generally required to give employees clear, advance written notice of the kind of surveillance being conducted (e.g. computer/email/internet surveillance), how it will be carried out, when it will start, and whether it is continuous or intermittent. A generic "we may monitor everything" clause is unlikely to meet that bar, and separately, under the Australian Privacy Principles, the collection of personal information (which activity logs and email content constitute) should be fair, notified, and proportionate to a stated purpose. This is a genuine legal exposure, not just a best-practice gap.
**Framework/obligation reference:** *Workplace Surveillance Act 2005 (NSW)*; *Privacy Act 1988 (Cth)*, Australian Privacy Principle 1 (open and transparent management of personal information) and APP 5 (notification of collection).
**Recommendation:** Replace the clause with a specific description of what is monitored (e.g. email metadata and content for security/DLP purposes, endpoint activity via Defender for Endpoint, internet activity via DNS filtering logs), the purpose (security, legal/regulatory compliance, business continuity — not general performance surveillance), and a named contact for staff questions. **This clause should be reviewed by Legal or an employment law specialist before publishing** — this review identifies the gap but does not constitute legal advice on jurisdiction-specific compliance.

### F02 — No provision addressing shadow IT

**What the policy says:** The policy is silent on unsanctioned SaaS tool use.
**Why it matters:** This is a directly linked finding to risk CRM-R13 in the companion risk register: staff signing up for unapproved SaaS tools to solve a real productivity need is common, well-intentioned behaviour that the AUP currently does nothing to address — it neither prohibits it clearly nor offers a sanctioned alternative path, meaning staff have no clear expectation to follow either way.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.5.9 (Inventory of information and other associated assets), A.5.10 (Acceptable use of information and other associated assets).
**Recommendation:** Add a clause requiring new SaaS tools to be requested via a simple, fast-turnaround approval process (already recommended as the treatment for CRM-R13), rather than a blanket prohibition that's unlikely to be followed in practice without an alternative.

### F03 — Vague consequences section

**What the policy says:** "Failure to comply with this policy may result in disciplinary action."
**Why it matters:** This is not incorrect, but it is too thin to be useful in an actual misconduct scenario — it doesn't reference the company's formal disciplinary policy/process, and gives no indication of proportionality (a first-time minor infringement versus a deliberate, repeated, or malicious breach). In practice, this makes the clause harder to rely on consistently and defensibly if a disciplinary matter is ever contested.
**Framework/obligation reference:** General employment and policy governance best practice; consistency with any enterprise agreement or employment contract terms.
**Recommendation:** Cross-reference the formal Disciplinary Policy explicitly, and note that response is proportionate to severity and intent — from a documented conversation for a first minor breach, up to termination for deliberate or repeated serious breaches (e.g. deliberate data exfiltration).

### F04 — "Unauthorised software" undefined and not technically enforced

**What the policy says:** Staff must not "install unauthorised software," without defining what counts as authorised, and with no application allow-listing control actually in place to enforce it technically.
**Why it matters:** A policy statement that isn't backed by a technical control creates a false sense of assurance and relies entirely on individual staff judgement and compliance — this is the same "written policy vs actual practice" gap identified for MFA in the companion password policy review (Finding F04).
**Framework/obligation reference:** ACSC Essential Eight — Application Control strategy, currently at Maturity Level 0 in CloudReach's environment per the companion risk register.
**Recommendation:** In the short term, define "authorised" clearly (e.g. software installed via the company's managed software catalogue, or approved via IT request). In the medium term, cross-reference this clause to the Essential Eight uplift roadmap so the written policy and the technical control mature together rather than the policy overstating current enforcement.

### F05 — No incident-reporting obligation

**What the policy says:** The policy does not tell staff what to do if they suspect a security incident (e.g. clicking a phishing link, losing a device, noticing unusual account activity).
**Why it matters:** Every minute between a security event occurring and it being reported extends the window an attacker has to act, and directly affects CloudReach's ability to meet its Notifiable Data Breach assessment obligations (see risk CRM-R12). An AUP is a natural, high-visibility place to set this expectation, since every staff member reads it, but this policy currently misses the opportunity entirely.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.6.8 (Information security event reporting).
**Recommendation:** Add a short, clear clause: staff must report any suspected security incident immediately to [defined channel — e.g. a dedicated Slack channel or email alias monitored during business hours with an after-hours escalation path], with an explicit statement that reporting a mistake (e.g. clicking a phishing link) will not itself result in disciplinary action, to avoid discouraging timely reporting.

### F06 — "Reasonable personal use" undefined

**What the policy says:** Personal use of company systems is permitted if "reasonable" and not "excessive," without further definition.
**Why it matters:** In day-to-day practice this is workable and arguably appropriate to leave flexible — but if ever contested (e.g. a performance or disciplinary matter turns partly on this clause), the lack of any anchoring examples makes it hard to apply consistently across staff.
**Framework/obligation reference:** General policy governance best practice.
**Recommendation:** Add non-exhaustive illustrative examples (e.g. "checking personal email or messaging apps during a break is reasonable; streaming video or gaming during work hours is not"), explicitly noting the list is illustrative, not exhaustive, to preserve flexibility while giving staff a clearer reference point.

### F07 — Social media clause doesn't address personal/professional overlap

**What the policy says:** Staff should "exercise good judgement" and not disclose confidential information on social media.
**Why it matters:** This is reasonable as far as it goes, but doesn't address the more common real-world scenario at a company like CloudReach: staff discussing their work publicly (e.g. on LinkedIn) in ways that could be reasonably read as an official company position, without necessarily disclosing anything confidential.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.5.10 (Acceptable use of information and other associated assets).
**Recommendation:** Add brief guidance encouraging staff to note that views expressed are their own when discussing work-related topics publicly, without requiring a formal disclaimer on every post (which is generally impractical and rarely followed).

### F08 — No coverage of AI tool use

**What the policy says:** The policy is silent on the use of AI tools, unsurprising given it was last substantively updated in 2021.
**Why it matters:** This is one of the most materially changed risk areas since this policy was last written. Staff pasting customer data, source code, or internal documents into a public consumer AI chat tool to get help with a task is a realistic, easy-to-imagine scenario at a company like CloudReach, and could constitute an uncontrolled disclosure of customer PII with no visibility to CloudReach unless explicitly addressed.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.5.9 (Inventory of information and other associated assets), A.5.34 (Privacy and protection of PII).
**Recommendation:** Add an explicit clause distinguishing company-approved AI tools (with appropriate data-handling agreements in place) from public consumer AI tools, and explicitly prohibit pasting customer data, credentials, or proprietary source code into any non-approved tool.

### F09 — No BYOD coverage

**What the policy says:** The policy addresses company-provided systems only, with no reference to personal devices used to access company email or systems.
**Why it matters:** In practice, staff commonly check company email on personal phones — this is normal and low-risk if a minimum device standard applies (e.g. screen lock, remote wipe capability), but currently sits entirely outside any documented policy.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.8.1 (User endpoint devices).
**Recommendation:** Add a short BYOD clause requiring, at minimum, a device passcode/biometric lock and enrolment in mobile device management (conditional access) before a personal device can access company email or systems, or explicitly cross-reference a separate BYOD standard if a more detailed one is warranted.

## 7. Recommended replacement wording

> **CloudReach CRM — Acceptable Use Policy (v2.0 — proposed)**
>
> **1. Purpose and Scope**
> This policy sets out acceptable use of CloudReach company systems — including company-provided computers, email, internet access, cloud services, and company accounts — and the minimum standard for personal devices used to access company email or systems (BYOD).
>
> **2. General Use**
> Company systems are provided for business purposes. Reasonable personal use is permitted (for example, checking personal email or messages during a break) provided it does not interfere with work duties, consume excessive resources (for example, streaming video or gaming during work hours), or bring the company into disrepute. This list is illustrative, not exhaustive.
>
> **3. Prohibited Activities**
> Employees must not:
> - Access, download, or distribute illegal, offensive, or inappropriate content
> - Use company systems for personal commercial gain
> - Install software other than via the company's managed software catalogue or without IT approval
> - Attempt to bypass security controls
>
> **4. Shadow IT / New Tool Requests**
> If you need a tool that isn't already provided, submit a request via [defined channel]. Requests are triaged within 2 business days. Using unsanctioned SaaS tools to handle company or customer data without approval is not permitted, but we'd rather you ask than work around the rule.
>
> **5. Artificial Intelligence Tools**
> Company-approved AI tools may be used in line with any tool-specific guidance provided by IT. Customer data, credentials, source code, or confidential company information must **not** be entered into any AI tool that has not been explicitly approved by IT/GRC.
>
> **6. BYOD (Personal Devices)**
> Personal devices used to access company email or systems must have a passcode or biometric lock enabled and be enrolled in the company's mobile device management solution before access is granted.
>
> **7. Monitoring**
> CloudReach monitors use of company systems for security, legal/regulatory compliance, and business continuity purposes. This includes email metadata and content (via Microsoft/Google security tooling), endpoint activity (via endpoint protection software), and network/internet activity (via DNS filtering logs). Monitoring is not used for day-to-day performance management. Questions about monitoring can be directed to [People & Culture contact]. *[This clause requires confirmation against current NSW Workplace Surveillance Act and Privacy Act obligations by Legal/People & Culture before publishing.]*
>
> **8. Security Incident Reporting**
> If you suspect a security incident — including clicking a suspicious link, losing a company device, or noticing unusual account activity — report it immediately via [defined channel]. Reporting a genuine mistake promptly will not itself result in disciplinary action; failing to report a known incident may.
>
> **9. Social Media**
> Exercise good judgement when posting publicly. Do not disclose confidential company or customer information. When discussing work-related topics, note that views expressed are your own.
>
> **10. Consequences**
> Breach of this policy is addressed under the company Disciplinary Policy, proportionate to severity and intent — ranging from a documented conversation for a minor first breach, up to termination of employment for deliberate, repeated, or serious breaches.

## 8. Review sign-off

| Field | Detail |
|---|---|
| **Reviewed by** | GRC Analyst (portfolio exercise) |
| **Review date** | July 2026 |
| **Findings accepted by policy owner** | Pending — F01 (monitoring clause) recommended for urgent Legal review given genuine compliance exposure |
| **Target date for updated policy to be published** | Q3 2026, subject to Legal sign-off on §7 (Monitoring) |
| **Next scheduled review** | July 2027, or sooner upon material change to monitoring tooling, AI tool approvals, or company device policy |

---

*This review is a fictional portfolio exercise created to demonstrate GRC policy review methodology. The "as-written" policy is illustrative of common real-world weaknesses, not an excerpt of a real organisation's document, and nothing in this review constitutes legal advice.*
