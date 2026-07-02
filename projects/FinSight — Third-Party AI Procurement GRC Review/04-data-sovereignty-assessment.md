# Data Sovereignty and Privacy Act Assessment — VeriGuard AI Arrangement

**Document ID:** FINSIGHT-AI-DSA-004
**Version:** 1.0
**Classification:** Internal — Restricted
**Owner:** Privacy Officer / GRC Analyst
**Framework references:** Privacy Act 1988 (AU) · Australian Privacy Principles (APPs 1–13) · OAIC APP Guidelines · Notifiable Data Breaches Scheme · GDPR (awareness — Ireland processing)

---

## Purpose

This assessment evaluates data sovereignty risks and Privacy Act 1988 obligations arising from FinSight Analytics' proposed engagement of VeriGuard AI — an offshore vendor whose platform processes Australian customer financial data in Singapore (primary) and Ireland (disaster recovery/backup).

The assessment addresses Australian Privacy Principle 8 (cross-border disclosure), identifies applicable privacy obligations across the full data lifecycle, evaluates the adequacy of data protection in the vendor's processing jurisdictions, and produces recommendations for contractual and operational controls required before the arrangement proceeds.

---

## Data Inventory — What Is Being Sent Offshore

| Data Type | Classification | Volume | Sensitivity | Privacy Act Category |
|-----------|---------------|--------|-------------|----------------------|
| Customer full name | Personal Information | Per transaction | Standard | Personal information |
| Customer account number | Personal Information | Per transaction | Standard | Personal information |
| Transaction amount | Financial Information | Per transaction | Medium | Personal information |
| Transaction timestamp | Metadata | Per transaction | Low | Personal information |
| Transaction counterparty details | Financial Information | Per transaction | Medium | Personal information |
| Transaction location / merchant | Behavioural Data | Per transaction | Medium | Personal information |
| Device fingerprint (device ID, OS, browser) | Technical Data | Per transaction | Medium | Personal information |
| IP address at time of transaction | Technical Data | Per transaction | Medium | Personal information |
| Historical transaction patterns (12 months) | Behavioural/Financial | Historical batch | High | Personal information |
| Account type and product holdings | Financial Information | Static/updated | Medium | Personal information |

**Privacy Act classification:** All data listed above constitutes personal information under Section 6 of the Privacy Act 1988. Financial information and behavioural patterns are treated as sensitive in the context of financial services, given the potential for serious harm from misuse.

**Volume estimate:** Approximately 2.3 million transactions per month. At full deployment, VeriGuard will process personal information of approximately 340,000 FinSight customers.

---

## Australian Privacy Principle 8 — Cross-Border Disclosure Assessment

### APP 8 Requirements

APP 8.1 requires that before an Australian entity discloses personal information to an overseas recipient, it must take reasonable steps to ensure that the overseas recipient does not breach the APPs in relation to that information.

APP 8.2 provides that an entity is accountable for any breach of the APPs by an overseas recipient as if the breach were an act of the entity itself.

**Practical implication:** FinSight is legally accountable for any Privacy Act breach committed by VeriGuard in Singapore or Ireland, including data breaches, unauthorised use of customer data, and failures to comply with APP obligations. This cannot be contracted away.

### Jurisdiction Assessment — Singapore

**Data protection regime:** Personal Data Protection Act 2012 (PDPA)
**Adequacy assessment:** Singapore PDPA is broadly comparable to the Australian Privacy Act for standard personal information. Key differences:

| Dimension | Australian Privacy Act 1988 | Singapore PDPA |
|-----------|----------------------------|----------------|
| Breach notification | Mandatory — NDB scheme (30-day assessment, individual notification) | Mandatory — from 1 February 2022 (3-day PDPC notification for significant breaches; 30 days for individual notification) |
| Consent requirements | APP 3 — collection with consent or reasonable expectation | Consent or legitimate purpose basis |
| Individual access rights | APP 12 — access right | Section 21 — access right |
| Data portability | Limited under Privacy Act | Data portability obligation introduced under PDPA |
| Enforcement | OAIC enforcement; civil penalties | PDPC enforcement; financial penalties up to SGD 1M or 10% of annual turnover |
| AI-specific obligations | No specific AI obligations in Privacy Act | No specific AI obligations in PDPA |

**APP 8 Adequacy Determination — Singapore:** Singapore PDPA provides broadly comparable protections to the Australian Privacy Act for standard personal information. However, FinSight cannot rely on jurisdictional adequacy alone — contractual protections equivalent to APPs are required.

**Additional risk factor:** Singapore is not on the OAIC's list of countries with substantially similar privacy protections for the purposes of APP 8.1(b). FinSight must therefore rely on the contractual mechanism (APP 8.1(a)) — taking reasonable steps through contractual obligations.

---

### Jurisdiction Assessment — Ireland (DR/Backup)

**Data protection regime:** EU General Data Protection Regulation (GDPR) — applies in Ireland as an EU member state. Enforced by the Data Protection Commission (DPC).

**Adequacy assessment:** Ireland is subject to GDPR, which provides a comparable or higher standard of protection than the Australian Privacy Act for most purposes.

| Dimension | Australian Privacy Act 1988 | EU GDPR (Ireland) |
|-----------|----------------------------|-------------------|
| Breach notification | 30-day NDB assessment; individual notification | 72-hour supervisory authority notification; individual notification without undue delay |
| Lawful basis for processing | APP 3 — collection for primary purpose | Article 6 — lawful basis required (contract, legitimate interest, consent) |
| Data subject rights | APP 12 (access), APP 13 (correction) | Articles 15–22 — broader rights including erasure, portability, restriction |
| Automated decision-making | Limited protections | Article 22 — right to explanation for solely automated decisions |
| Enforcement | OAIC; civil penalties | DPC; up to €20M or 4% of global turnover |

**APP 8 Adequacy Determination — Ireland (GDPR):** GDPR provides protections broadly equivalent to or exceeding the Australian Privacy Act. The European Commission has confirmed Australia is an adequate jurisdiction under GDPR (facilitating data flows in the other direction). Contractual protections for Australian APP compliance are still required.

**Additional risk factor:** GDPR Article 22 provides EU data subjects with specific rights regarding solely automated decisions. While FinSight's customers are Australian (not EU data subjects), VeriGuard's Ireland infrastructure may be subject to GDPR oversight — FinSight should confirm the scope of GDPR application to its customer data processed in Ireland.

---

## APP-by-APP Assessment

### APP 1 — Open and Transparent Management

**Requirement:** FinSight must have a clearly expressed privacy policy disclosing how personal information is collected, used, and disclosed — including to overseas recipients.

**Current state:** FinSight's privacy policy does not disclose:
- Use of an AI-based fraud detection system
- Transfer of customer financial data to an offshore vendor
- Processing of data in Singapore and Ireland

**Gap:** ❌ Non-compliant

**Required action:**
1. Update FinSight Privacy Policy — add section disclosing AI fraud detection processing, naming data processing jurisdictions, and explaining the purpose
2. Update customer-facing product disclosure statements (PDS) if financial product data is involved
3. Publish updated privacy policy before go-live

**Suggested disclosure language:**
> *"FinSight Analytics uses AI-powered fraud detection technology to protect your account and transactions. In delivering this service, certain transaction data — including transaction amount, counterparty details, device information, and historical patterns — may be processed by an authorised third-party technology provider in Singapore and Ireland. This processing occurs solely for fraud detection purposes. Your data is protected by contractual obligations requiring equivalent privacy standards to Australian law."*

---

### APP 3 — Collection of Solicited Personal Information

**Requirement:** FinSight must only collect personal information reasonably necessary for its functions. Data shared with VeriGuard for fraud detection must be the minimum necessary.

**Current state:** The data inventory identifies 10 data types to be shared. Not all may be strictly necessary for fraud detection.

**Gap:** ⚠️ Partial — data minimisation not confirmed

**Required action:**
1. Conduct data minimisation review with VeriGuard — for each data field, require vendor to confirm it is necessary for fraud detection and cannot be substituted with less sensitive data or a hash/pseudonym
2. Remove fields not confirmed as necessary before go-live
3. Document the data minimisation assessment outcome

---

### APP 5 — Notification of Collection

**Requirement:** At or before collection, FinSight must notify customers of offshore disclosure for fraud detection purposes.

**Current state:** Customer account opening forms and transaction disclosures do not reference AI fraud detection or offshore processing.

**Gap:** ❌ Non-compliant

**Required action:**
1. Update account opening disclosure and Terms and Conditions to include fraud detection processing disclosure
2. For existing customers — notify via email or in-app notification before go-live, with 30-day notice period
3. Update product disclosure documentation as required

---

### APP 6 — Use and Disclosure

**Requirement:** FinSight may only use or disclose personal information for the primary purpose of collection, or a directly related secondary purpose.

**Assessment:**
- ✅ Real-time fraud detection for FinSight customers — **permitted** (directly related to account management)
- ❌ VeriGuard model training using FinSight customer data — **not permitted** without consent
- ❌ VeriGuard sharing FinSight data patterns with other clients — **not permitted**
- ❌ FinSight or VeriGuard using fraud flag data for marketing purposes — **not permitted**

**Required action:** Vendor contract must explicitly prohibit all secondary uses of FinSight customer data beyond delivering the contracted fraud detection service. This must be a termination-for-cause clause.

---

### APP 8 — Cross-Border Disclosure

**Requirement:** Before disclosing personal information to VeriGuard in Singapore and Ireland, FinSight must take reasonable steps to ensure VeriGuard will not breach the APPs.

**Reasonable steps required:**
1. Execute a Data Processing Agreement (DPA) with VeriGuard that imposes APP-equivalent obligations — covering collection, use, disclosure, security, retention, deletion, access, and breach notification
2. Include audit right in DPA — FinSight can verify compliance
3. Obtain VeriGuard's current privacy policy and assess against APP requirements
4. Document the APP 8 assessment and retain for regulatory purposes

**Gap:** ❌ Non-compliant — no DPA executed; APP 8 assessment not conducted

**Required action:** DPA must be executed before any customer data is transmitted to VeriGuard. This is a pre-contract blocker.

---

### APP 11 — Security of Personal Information

**Requirement:** FinSight must take reasonable steps to protect personal information from misuse, interference, loss, unauthorised access, modification, or disclosure.

**Assessment:** The VeriGuard arrangement creates a new data flow that has not been security-assessed from a privacy perspective.

**Required controls (contractual):**
- TLS 1.3 encryption for all data in transit between FinSight and VeriGuard
- AES-256 encryption at rest for all FinSight customer data on VeriGuard infrastructure
- Role-based access controls — VeriGuard personnel access restricted to minimum necessary
- MFA required for all VeriGuard personnel with access to FinSight data
- Annual penetration testing of the data pathway and VeriGuard AI platform

---

### APP 12 — Access to Personal Information

**Requirement:** Customers have the right to access their personal information, including data processed by VeriGuard.

**Implication:** If a customer requests access to their fraud detection records, FinSight must be able to retrieve:
- What data was sent to VeriGuard for each transaction
- What fraud score or recommendation was generated
- Whether the customer's transaction was flagged, blocked, or cleared

**Required action:** Confirm with VeriGuard that customer-level AI input and output records are retrievable and retainable for 7 years. Define the data retrieval process in the DPA.

---

### Notifiable Data Breaches — Vendor Breach Scenarios

| Scenario | NDB Assessment | FinSight Action |
|----------|---------------|----------------|
| VeriGuard suffers data breach — FinSight customer transaction data accessed without authorisation | Likely eligible NDB — financial data of up to 340,000 customers | OAIC notification + individual notification; APRA 72-hour notification |
| VeriGuard employee exfiltrates FinSight customer data | Eligible NDB | As above |
| FinSight–VeriGuard API connection intercepted | Eligible NDB | As above; suspend API connection immediately |
| VeriGuard ransomware event — FinSight data encrypted | Eligible NDB — potential loss of personal information | As above; assess data recovery |

**Key finding:** VeriGuard must notify FinSight within 24 hours of any incident affecting FinSight data — to enable FinSight to conduct its 30-day NDB assessment and meet the APRA 72-hour notification obligation. This is a hard contractual requirement.

---

## Data Sovereignty Risk Summary

| Risk | Jurisdiction | Severity | Contractual Mitigation Required |
|------|-------------|:--------:|--------------------------------|
| Customer data processed in Singapore without APP 8 assessment | Singapore | 🔴 Critical | DPA with APP obligations; assessment documented |
| Customer data processed in Ireland — GDPR interaction | Ireland | 🟠 Medium | Confirm GDPR scope; DPA covers APP obligations |
| Data used for vendor model training | Singapore/Ireland | 🔴 High | Explicit contractual prohibition |
| Vendor breach notification delay prevents APRA compliance | Singapore | 🔴 Critical | 24-hour SLA contractual obligation |
| Data residency changes without FinSight consent | Any | 🔴 High | Written consent required for any location change |
| Customer access rights to offshore data | Singapore/Ireland | 🟠 Medium | Retrieval process defined in DPA |

---

## Pre-Contract Data Sovereignty Checklist

| Item | Status | Responsible |
|------|--------|-------------|
| APP 8 cross-border disclosure assessment documented | ❌ Not completed | Privacy Officer |
| Data Processing Agreement (DPA) executed | ❌ Not executed | Privacy Officer / Legal |
| Privacy Policy updated — offshore AI processing disclosed | ❌ Not updated | Privacy Officer |
| Customer notification for existing customers | ❌ Not sent | Privacy Officer / Marketing |
| Data minimisation review completed | ❌ Not completed | Privacy Officer / CCIO |
| Vendor privacy policy reviewed against APPs | ❌ Not reviewed | Privacy Officer |
| Data residency confirmed in writing | ❌ Not confirmed | GRC / Legal |
| Subprocessor list obtained and reviewed | ❌ Not obtained | GRC / Legal |
| Breach notification SLA in contract | ❌ Not included | Legal |
| Customer data access and retrieval process confirmed with vendor | ❌ Not confirmed | Privacy Officer |

**All items above must be completed before any customer data is transmitted to VeriGuard.**

---

## Tools Used

| Tool | Purpose |
|------|---------|
| OneTrust | Privacy impact assessment workflow and APP obligation tracking |
| OAIC APP Guidelines | APP 8 cross-border disclosure assessment methodology |
| Microsoft Purview | Data classification and customer data inventory |
| OAIC Privacy Register | NDB scheme obligation reference |
| IAPP Data Transfer Mechanism Tracker | Singapore PDPA and GDPR cross-reference |
| Confluence | Documentation and review workflow |

---

*This document is part of a sample GRC portfolio project. All organisations and scenarios are fictional.*
