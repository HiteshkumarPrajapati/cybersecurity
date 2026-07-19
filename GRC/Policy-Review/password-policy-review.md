# Policy Review — Password Policy (CloudReach CRM)

## 1. Document control

| Field | Detail |
|---|---|
| **Policy title** | CloudReach CRM — Password Policy |
| **Policy owner** | Head of Engineering |
| **Version reviewed** | v2.1 |
| **Date of last policy update (per document)** | March 2022 |
| **Review date** | July 2026 |
| **Reviewed by** | GRC Analyst (portfolio exercise) |
| **Review type** | Scheduled (annual review cycle) |
| **Frameworks/obligations assessed against** | NIST SP 800-63B (Digital Identity Guidelines), ACSC Essential Eight (Maturity Level 2), ISO/IEC 27001:2022 Annex A (A.5.17, A.8.5) / 2013 Annex A.9 |
| **Next review due** | July 2027, or sooner if authentication architecture changes materially |

## 2. Scope and objective of this review

This review covers the **written password policy** applicable to all CloudReach CRM staff accounts (Google Workspace, AWS, GitHub, internal tools) and, separately, notes where the written policy and the platform's *customer-facing* authentication settings diverge. It does not include a technical audit of Conditional Access/IAM configuration — that is recommended as a separate, follow-up technical control review, referenced in the recommendations below.

This review is written from the position that the policy has not been substantively updated since 2022, despite NIST's guidance in this space (SP 800-63B) having been stable in its current form since 2017 — meaning the policy was already out of step with best practice at the time it was last approved, not just today.

## 3. Executive summary

The current password policy is written in good faith but reflects password guidance that was outdated even at the time it was last approved in 2022. Two clauses — mandatory 90-day password rotation and a strict character-composition rule — are specifically identified by NIST SP 800-63B as practices that **degrade security** by pushing users toward predictable, weak password patterns, rather than improving it. More significantly, the policy references MFA as "recommended" rather than mandatory, which is inconsistent with the Essential Eight Maturity Level 2 target CloudReach has committed to elsewhere in its security documentation, and inconsistent with the treatment already agreed for risk CRM-R04 in the companion risk register. The recommended action is to approve the redlined wording in Section 7 of this review, which brings the policy in line with current NIST guidance and closes the gap against Essential Eight ML2 — this is a low-cost, high-value change with no licensing cost, as MFA capability already exists on all core platforms.

## 4. Policy as written

*The following is the current policy text, quoted in full for traceability of findings.*

> **CloudReach CRM — Password Policy (v2.1, March 2022)**
>
> **1. Purpose**
> This policy defines password requirements for all CloudReach CRM staff to protect company and customer systems from unauthorised access.
>
> **2. Password Requirements**
> All passwords must:
> - Be a minimum of 8 characters in length
> - Contain at least one uppercase letter, one lowercase letter, one number, and one special character
> - Not be the same as any of the user's previous 5 passwords
> - Be changed every 90 days
>
> **3. Password Handling**
> Employees must not write down their password or share it with any other person, including IT staff. Passwords must not be reused across multiple systems.
>
> **4. Multi-Factor Authentication**
> Multi-factor authentication (MFA) is recommended for all staff accounts where the underlying system supports it.
>
> **5. Account Lockout**
> Accounts will be locked after 5 failed login attempts and must be unlocked by an IT administrator.
>
> **6. Enforcement**
> Breach of this policy may result in disciplinary action up to and including termination of employment.

## 5. Findings register

| Finding ID | Clause Ref | Finding | Severity | Framework Reference | Recommendation Summary |
|---|---|---|---|---|---|
| F01 | §2, bullet 4 | Mandatory 90-day password rotation is contrary to current NIST guidance and drives weaker password choices | **High** | NIST SP 800-63B §5.1.1.2 | Remove mandatory periodic rotation; rotate only on evidence of compromise |
| F02 | §2, bullet 2 | Mandatory character-composition rule (upper/lower/number/symbol) is contrary to current NIST guidance and does not meaningfully increase entropy for the friction it creates | **Medium** | NIST SP 800-63B §5.1.1.2 | Replace composition rule with a minimum-length requirement and passphrase guidance |
| F03 | §2, bullet 1 | Minimum length of 8 characters is below current recommended minimums | **High** | NIST SP 800-63B §5.1.1.2 | Raise minimum to 12 characters (15+ for privileged accounts) |
| F04 | §4 | MFA is stated as "recommended," not mandatory, which is inconsistent with the Essential Eight ML2 target and with agreed treatment of risk CRM-R04 | **Critical** | ACSC Essential Eight (MFA, ML2); ISO/IEC 27001:2022 A.8.5 | Make MFA mandatory for all staff and privileged accounts, enforced technically, not just stated |
| F05 | §2 | No requirement to screen new passwords against known-breached/compromised password lists | **Medium** | NIST SP 800-63B §5.1.1.2 | Add requirement to check new passwords against a breached-password database at set time |
| F06 | (missing) | No distinction between standard user accounts and privileged/administrative accounts — same rules apply to both | **High** | ISO/IEC 27001:2022 A.8.2 (Privileged access rights) | Add a separate, stricter tier for privileged accounts (longer minimum length, mandatory hardware security key where feasible) |
| F07 | §5 | Account lockout threshold and manual unlock process is not scoped for how it interacts with MFA, and could itself become a denial-of-service/support burden vector | **Low** | ISO/IEC 27001:2022 A.8.5 | Clarify lockout duration/self-service unlock via MFA re-verification, reducing helpdesk load without weakening the control |
| F08 | (missing) | No mention of password manager use, despite being the single most effective practical control to enable long, unique passwords without user friction | **Medium** | NIST SP 800-63B (supporting guidance) | Add explicit endorsement and provisioning of an approved password manager |
| F09 | (missing) | No statement on service account / non-human credential handling, which typically carries higher risk than human accounts | **High** | ISO/IEC 27001:2022 A.8.24 (Use of cryptography), A.5.17 | Add a dedicated section for service accounts/API keys, cross-referencing the secrets management standard |
| F10 | §1 | Policy scope does not state whether it applies to customer-facing authentication settings (i.e. what CloudReach enforces or recommends for its own customers logging into the CRM product) | **Medium** | Internal consistency / customer trust | Clarify scope explicitly; cross-reference the product's customer-facing authentication settings documentation separately |

## 6. Detailed findings

### F01 — Mandatory 90-day rotation

**What the policy says:** Passwords must be changed every 90 days regardless of any indication of compromise.
**Why it matters:** This is one of the most well-documented examples of a security control that, in practice, reduces security. When users are forced to change a password on a fixed schedule with no other change in circumstance, the empirical and well-established pattern is that they make small, predictable modifications to their existing password (e.g. incrementing a trailing digit) — patterns that are well known to attackers and easily guessed once one historical password is known. NIST formally moved away from recommending mandatory periodic rotation in 2017 and this position has been maintained in subsequent revisions of SP 800-63B.
**Framework/obligation reference:** NIST SP 800-63B §5.1.1.2 explicitly states that verifiers **should not** require periodic password changes and should instead require a change only when there is evidence of compromise.
**Recommendation:** Remove the fixed 90-day rotation requirement. Retain the ability to force a reset on evidence of compromise (e.g. triggered by breach-list screening — see F05 — or a security incident).

### F02 — Mandatory character composition rules

**What the policy says:** Passwords must contain uppercase, lowercase, a number, and a special character.
**Why it matters:** Composition rules of this kind reliably produce predictable substitution patterns (e.g. "P@ssw0rd1!") that satisfy the rule without meaningfully increasing resistance to guessing or cracking, while adding friction that pushes some users toward writing passwords down or reusing slight variants across systems — the opposite of the policy's stated intent in §3.
**Framework/obligation reference:** NIST SP 800-63B §5.1.1.2 recommends against imposing composition rules and instead recommends length as the primary strength driver, alongside breach-list screening.
**Recommendation:** Remove the composition requirement. Replace with a minimum-length requirement (see F03) and explicit guidance encouraging passphrases (e.g. four or more random unrelated words), which are both easier for humans to generate and remember, and substantially harder to brute-force than a short complex string.

### F03 — Minimum length of 8 characters

**What the policy says:** Minimum password length is 8 characters.
**Why it matters:** An 8-character minimum is now well below what is considered adequate resistance to modern offline brute-force/credential-cracking capability, particularly if the composition rule is removed per F02 (length becomes the primary control once composition rules are relaxed).
**Framework/obligation reference:** NIST SP 800-63B recommends a minimum of 8 characters as an absolute floor but explicitly encourages verifiers to require significantly longer minimums; industry practice has converged on 12 as a reasonable minimum for standard accounts.
**Recommendation:** Raise the minimum to **12 characters** for standard accounts and **15 characters** for privileged/administrative accounts (see F06), paired with passphrase guidance so the higher minimum doesn't just reproduce the friction problem the composition-rule removal was meant to solve.

### F04 — MFA stated as recommended, not mandatory

**What the policy says:** "Multi-factor authentication (MFA) is recommended for all staff accounts where the underlying system supports it."
**Why it matters:** This is the most significant finding in this review. MFA is the single highest-leverage control against the most common real-world account compromise scenarios (credential stuffing, phishing, password reuse from an unrelated breach) — all of which remain top-reported incident types in the ACSC Annual Cyber Threat Report. Framing it as optional creates a policy-practice gap: CloudReach's own risk register (CRM-R04) already treats customer-facing MFA as a required control, and CloudReach cannot credibly hold customers to a higher standard than it holds its own staff. "Recommended" language in a policy also creates an audit and insurance problem — a cyber insurer or auditor reading this clause would reasonably conclude MFA enforcement is inconsistent across the organisation, which it is.
**Framework/obligation reference:** ACSC Essential Eight, Multi-Factor Authentication strategy, Maturity Level 2 requires MFA for all users authenticating to important data repositories and for all privileged users. ISO/IEC 27001:2022 A.8.5 (Secure authentication).
**Recommendation:** Change from "recommended" to **mandatory**, enforced technically (not left to individual compliance) via Conditional Access/IAM policy across Google Workspace, AWS, and GitHub, with no exceptions process other than a documented, time-bound, risk-accepted exception signed off by the Head of Engineering.

### F05 — No breach-list screening requirement

**What the policy says:** No mention of checking new passwords against known-compromised password databases.
**Why it matters:** A password can meet every length and complexity requirement in this policy and still be one of the billions of passwords already circulating in public breach dumps. Screening against a breach-list (e.g. via the Have I Been Pwned Pwned Passwords API or equivalent, integrated into the identity provider) closes this gap without adding any user friction at the point of password creation, since the check happens automatically.
**Framework/obligation reference:** NIST SP 800-63B §5.1.1.2 explicitly recommends verifiers compare prospective passwords against a list of values known to be commonly used, expected, or compromised.
**Recommendation:** Add a requirement that new passwords are automatically screened against a breach-list database at creation/reset time, with rejection and prompt to choose a different password if a match is found.

### F06 — No distinction between standard and privileged accounts

**What the policy says:** The same requirements apply uniformly to all accounts, with no reference to privileged or administrative access.
**Why it matters:** A compromised privileged account (e.g. AWS root/admin, production database access) carries materially higher impact than a compromised standard user account, and should be held to a correspondingly stricter standard — both in password strength and in authentication method (e.g. hardware security keys rather than app-based MFA where feasible).
**Framework/obligation reference:** ISO/IEC 27001:2022 A.8.2 (Privileged access rights) requires the allocation and use of privileged access rights to be restricted and managed, which reasonably extends to the authentication standard applied to those accounts.
**Recommendation:** Add a distinct privileged-account tier: 15-character minimum, mandatory hardware security key (e.g. FIDO2/WebAuthn) where the platform supports it, and quarterly access recertification (cross-reference risk CRM-R03 in the companion risk register, which already identifies this gap from a different angle).

### F07 — Account lockout and MFA interaction unclear

**What the policy says:** Accounts lock after 5 failed attempts and require IT administrator unlock.
**Why it matters:** This is a lower-severity clarity issue rather than a security gap, but as written it creates unnecessary helpdesk burden and a support bottleneck, and doesn't account for how lockout should interact with MFA (e.g. should a correct MFA challenge be able to self-unlock an account locked on password attempts alone?).
**Framework/obligation reference:** ISO/IEC 27001:2022 A.8.5 (Secure authentication).
**Recommendation:** Clarify that accounts may be self-unlocked via successful MFA re-verification, with administrator unlock reserved for accounts where MFA itself is unavailable (e.g. lost device), reducing support load while preserving the control's intent.

### F08 — No mention of password manager use

**What the policy says:** No guidance on password manager use.
**Why it matters:** Raising the minimum length (F03) and removing composition rules (F02) only actually improves security in practice if staff have a realistic way to generate and store long, unique passwords per system. Without an endorsed tool, the realistic outcome is password reuse across systems, which undermines every other control in this policy.
**Framework/obligation reference:** Supporting guidance consistent with NIST SP 800-63B's overall intent of reducing user-driven weak-password behaviour.
**Recommendation:** Add explicit endorsement of a company-provisioned password manager (e.g. 1Password Business or equivalent, already common in Australian SME/scale-up environments), including it in new-starter onboarding.

### F09 — No coverage of service accounts / API keys

**What the policy says:** The policy is silent on non-human credentials (service accounts, API keys, database credentials).
**Why it matters:** Service accounts and API keys are frequently higher-privilege and longer-lived than human accounts, and are a documented root cause in several real-world SaaS breaches (typically via a hardcoded or leaked key) — this is directly relevant to risk CRM-R10 in the companion risk register.
**Framework/obligation reference:** ISO/IEC 27001:2022 A.8.24 (Use of cryptography), A.5.17 (Authentication information).
**Recommendation:** Add a dedicated section requiring all service credentials to be issued and rotated via the company secrets manager, prohibiting hardcoded credentials in source code, and setting a maximum credential age even absent evidence of compromise (unlike human passwords, machine credentials are a reasonable case for scheduled rotation, since there's no user-behaviour downside).

### F10 — Unclear scope regarding customer-facing authentication

**What the policy says:** The policy title and purpose statement don't clarify whether it governs only internal staff accounts or also CloudReach's product-level authentication settings offered to customers.
**Why it matters:** This is a clarity/consistency issue rather than a security gap on its own, but an auditor or new staff member reading this policy in isolation could reasonably misread its scope, and it creates a risk that customer-facing authentication decisions are made without reference to any documented standard at all.
**Framework/obligation reference:** General policy governance practice; internal consistency.
**Recommendation:** Add an explicit scope statement clarifying this policy governs internal/staff authentication only, and cross-reference a (separately maintained) product authentication standard governing what CloudReach enforces for customer accounts.

## 7. Recommended replacement wording

> **CloudReach CRM — Password and Authentication Policy (v3.0 — proposed)**
>
> **1. Purpose and Scope**
> This policy defines password and authentication requirements for all CloudReach CRM staff accounts across company systems (Google Workspace, AWS, GitHub, and internal tools). It does not govern authentication settings offered to CloudReach customers within the CRM product — see the Product Authentication Standard for that scope.
>
> **2. Password Requirements — Standard Accounts**
> - Minimum length: **12 characters**. No mandatory character-composition rule; passphrases (e.g. four or more random, unrelated words) are encouraged.
> - New passwords are automatically checked against a known-breached-password database at creation and reset; matches are rejected.
> - Passwords are **not** required to be changed on a fixed schedule. A reset is required only where there is evidence or reasonable suspicion of compromise, or following a confirmed security incident.
> - Password reuse across the last 5 passwords, and reuse of the same password across multiple company or personal systems, remains prohibited.
>
> **3. Password Requirements — Privileged / Administrative Accounts**
> - Minimum length: **15 characters**.
> - A hardware security key (FIDO2/WebAuthn) must be used as the MFA method where the platform supports it, rather than SMS or authenticator app codes.
> - Privileged access is recertified quarterly by the Head of Engineering.
>
> **4. Multi-Factor Authentication**
> MFA is **mandatory** for all staff accounts on all systems that support it, enforced via technical control (Conditional Access/IAM policy), not left to individual compliance. Exceptions require documented, time-bound risk acceptance signed off by the Head of Engineering.
>
> **5. Password Managers**
> All staff are provisioned with an approved company password manager and are expected to use it to generate and store unique passwords for every system. IT will assist with setup as part of onboarding.
>
> **6. Service Accounts and API Keys**
> All non-human credentials (service accounts, API keys, database credentials) must be issued and stored via the company secrets manager. Hardcoded credentials in source code are prohibited. Service credentials are rotated at least every 12 months, or immediately upon suspected compromise or a relevant staff departure.
>
> **7. Account Lockout**
> Accounts lock after 5 failed password attempts. Accounts may be self-unlocked by successfully completing an MFA challenge. Administrator unlock is reserved for cases where MFA itself is unavailable to the user.
>
> **8. Enforcement**
> Breach of this policy may result in disciplinary action up to and including termination of employment, consistent with the Acceptable Use Policy.

## 8. Review sign-off

| Field | Detail |
|---|---|
| **Reviewed by** | GRC Analyst (portfolio exercise) |
| **Review date** | July 2026 |
| **Findings accepted by policy owner** | Pending — recommend presenting F04 (MFA) as a standalone, immediate change given no licensing cost and direct linkage to risk CRM-R04 |
| **Target date for updated policy to be published** | Q3 2026 |
| **Next scheduled review** | July 2027, or sooner upon material change to identity provider/architecture |

---

*This review is a fictional portfolio exercise created to demonstrate GRC policy review methodology. The "as-written" policy is illustrative of common real-world weaknesses, not an excerpt of a real organisation's document.*
