# California Data Privacy Laws: CCPA & CPRA Compliance Guide

**Document Version:** 1.0
**Date:** February 2026
**Classification:** Reference / Compliance Guidance
**Audience:** Enterprise customers, application developers, compliance teams

---

> **Disclaimer:** This document is provided for informational purposes only and does not constitute legal advice. Organizations should consult qualified legal counsel to determine specific compliance obligations based on their circumstances.

---

## Table of Contents

1. [Overview and Legal Basis](#1-overview-and-legal-basis)
2. [Enforcement Authorities](#2-enforcement-authorities)
3. [Scope and Applicability Thresholds](#3-scope-and-applicability-thresholds)
4. [Key Definitions](#4-key-definitions)
5. [Consumer Rights](#5-consumer-rights)
6. [Business Obligations](#6-business-obligations)
7. [Service Provider and Contractor Requirements](#7-service-provider-and-contractor-requirements)
8. [Sensitive Personal Information](#8-sensitive-personal-information)
9. [Children's Data Protections](#9-childrens-data-protections)
10. [Penalties and Private Right of Action](#10-penalties-and-private-right-of-action)
11. [Application to Software and Applications](#11-application-to-software-and-applications)
12. [Considerations for Mendix and Low-Code Applications](#12-considerations-for-mendix-and-low-code-applications)
13. [Compliance Checklist for Application Developers](#13-compliance-checklist-for-application-developers)
14. [Comparison with GDPR and Colorado Privacy Act](#14-comparison-with-gdpr-and-colorado-privacy-act)
15. [Appendix: Key Resources](#15-appendix-key-resources)

---

## 1. Overview and Legal Basis

### 1.1 The California Consumer Privacy Act (CCPA)

The **California Consumer Privacy Act of 2018** (Cal. Civ. Code sections 1798.100-1798.199.100) was signed into law on June 28, 2018, and took effect on **January 1, 2020**. It was the first comprehensive consumer privacy law in the United States, granting California residents significant rights over their personal information and imposing obligations on businesses that collect, process, or sell that data.

The CCPA was enacted through **AB 375**, largely in response to growing public concern over data breaches (notably the Cambridge Analytica scandal) and the commodification of personal data. It was also motivated by a ballot initiative (the California Consumer Privacy Act of 2018 ballot measure) that would have imposed even stricter requirements; the legislature passed AB 375 as a compromise to allow future legislative amendments.

### 1.2 The California Privacy Rights Act (CPRA)

The **California Privacy Rights Act of 2020** (Proposition 24) was approved by California voters on November 3, 2020. The CPRA **amends and expands** the CCPA rather than replacing it. Key changes took effect on **January 1, 2023**, with enforcement beginning **July 1, 2023**.

The CPRA introduced several major enhancements:

- Created the **California Privacy Protection Agency (CPPA)**, a dedicated enforcement body
- Introduced the concept of **sensitive personal information** with additional protections
- Added new consumer rights: **right to correct** and **right to limit use of sensitive PI**
- Expanded the definition of **cross-context behavioral advertising** (sharing)
- Imposed **data minimization** requirements on businesses
- Introduced **contractor** as a distinct category alongside service providers
- Extended the statute to cover **business-to-business (B2B)** and **employee/HR** data (exemptions expired)
- Established **purpose limitation** principles
- Created an **audit** requirement framework for high-risk processing
- Introduced **cybersecurity audit** and **risk assessment** obligations (rulemaking ongoing)

### 1.3 Constitutional Basis

California's right to privacy is enshrined in **Article I, Section 1** of the California Constitution, which lists privacy as an inalienable right alongside life, liberty, and the pursuit of happiness. The CCPA/CPRA builds upon this constitutional foundation, as well as existing California privacy statutes including the California Online Privacy Protection Act (CalOPPA), the Shine the Light law (Cal. Civ. Code section 1798.83), and the California Invasion of Privacy Act.

### 1.4 Current Status

As of early 2026, the combined CCPA/CPRA framework is fully operative. The CPPA has completed its initial rulemaking and has published final regulations. Enforcement actions have been brought by both the California Attorney General and the CPPA. Additional rulemaking on automated decision-making technology (ADMT), cybersecurity audits, and risk assessments has been progressing through the regulatory process.

---

## 2. Enforcement Authorities

### 2.1 California Attorney General (AG)

The California Attorney General retains enforcement authority under the CCPA/CPRA:

- **Civil penalties:** The AG can bring enforcement actions seeking civil penalties of up to **$2,500 per violation** (unintentional) or **$7,500 per intentional violation**
- **Cure period:** Under the original CCPA, businesses had a 30-day cure period after receiving notice of an alleged violation. The CPRA **eliminated the mandatory 30-day cure period**, though the AG or CPPA may still provide an opportunity to cure at their discretion
- **Injunctive relief:** The AG can seek court orders requiring businesses to change practices
- The AG's office has published interpretive guidance and FAQs, though these are not binding regulations

### 2.2 California Privacy Protection Agency (CPPA)

The CPPA was created by the CPRA as the **first dedicated data protection authority in the United States**. Its powers include:

- **Administrative enforcement:** Authority to investigate possible violations, issue subpoenas, and hold administrative hearings
- **Administrative fines:** Can impose fines of up to **$2,500 per violation** or **$7,500 per intentional violation** (same amounts as AG civil penalties)
- **Enhanced penalties for children:** Violations involving the personal information of consumers the business knew or should have known were under 16 years of age are subject to fines of **$7,500 per violation** (tripled from the standard unintentional amount)
- **Rulemaking authority:** The CPPA is charged with promulgating regulations to implement the CCPA/CPRA, including rules on:
  - Opt-out preference signals (Global Privacy Control)
  - Risk assessments for high-risk processing
  - Cybersecurity audits
  - Automated decision-making technology
  - Access and deletion requirements for specific categories of personal information
- **Investigation and audit powers:** The CPPA can audit businesses for compliance, request documentation, and conduct inquiries
- **Guidance:** Issues advisory opinions and guidance documents

### 2.3 Practical Enforcement Landscape

- The AG and CPPA have **concurrent enforcement authority**; a business could face action from either or both
- The CPPA has signaled a focus on "sweeps" targeting specific industries or practices (e.g., data broker registration, opt-out mechanisms, children's data)
- Enforcement to date has addressed issues such as failure to honor opt-out requests, inadequate privacy notices, improper handling of consumer requests, and data broker non-registration

---

## 3. Scope and Applicability Thresholds

### 3.1 Who Must Comply

The CCPA/CPRA applies to a **for-profit entity** that does business in California and collects (or has collected on its behalf) the personal information of California consumers, **and** meets one or more of the following thresholds:

| Threshold | Original CCPA | CPRA Amendment |
|-----------|---------------|----------------|
| **Annual gross revenue** | Exceeds $25 million | Exceeds **$25 million** (unchanged) |
| **Consumer data volume** | Buys, sells, or shares PI of 50,000+ consumers, households, or devices | Buys or sells PI of **100,000+ consumers or households** (devices removed; threshold raised) |
| **Revenue from data** | Derives 50% or more of annual revenue from selling consumers' PI | Derives 50% or more of annual revenue from **selling or sharing** consumers' PI |

**Key changes under CPRA:**
- The data volume threshold was raised from 50,000 to **100,000**
- "Devices" were removed from the count (preventing businesses from reaching the threshold solely through cookie/device tracking)
- "Sharing" was added to the revenue threshold (capturing businesses that profit from cross-context behavioral advertising even without a traditional "sale")

### 3.2 Geographic Scope

- The law applies to businesses that "do business in California," which is broadly interpreted to include any for-profit entity that serves California residents, regardless of physical presence
- The law protects **California residents** (consumers), defined as natural persons who are in the State of California for other than a temporary or transitory purpose, or who are domiciled in California but temporarily outside the state
- Businesses outside California that meet the thresholds and collect PI of California consumers are subject to the law

### 3.3 Exemptions

The CCPA/CPRA includes several exemptions:

- **Non-profit organizations** (unless owned or controlled by a covered business)
- **Government agencies**
- **Information governed by certain federal laws**, to the extent those laws preempt or provide equivalent protections:
  - HIPAA/HITECH (protected health information)
  - Gramm-Leach-Bliley Act (GLBA) (financial information)
  - Fair Credit Reporting Act (FCRA) (consumer reports)
  - Driver's Privacy Protection Act (DPPA)
  - Farm Credit Act
  - Clinical trial data governed by federal policy (Common Rule)
- **Employee and B2B data:** Originally exempt, these exemptions **expired on January 1, 2023**, under the CPRA. Employee HR data and B2B contact information are now fully covered
- **Publicly available information** lawfully made available from government records
- **De-identified or aggregate consumer information** (if the business maintains technical safeguards and processes to prevent re-identification)

### 3.4 Extraterritorial Considerations

While the CCPA/CPRA is a California law, its practical reach extends nationally and even internationally for businesses that serve California consumers online. Any business with a website or application accessible to California residents should evaluate whether it meets the applicability thresholds.

---

## 4. Key Definitions

### 4.1 Personal Information

**Personal information** (Cal. Civ. Code section 1798.140(v)) means information that identifies, relates to, describes, is reasonably capable of being associated with, or could reasonably be linked, directly or indirectly, with a particular **consumer or household**.

This is an extremely broad definition and includes (but is not limited to):

- **Identifiers:** Real name, alias, postal address, unique personal identifier, online identifier, IP address, email address, account name, SSN, driver's license number, passport number
- **Commercial information:** Records of personal property, products or services purchased, obtained, or considered, purchasing or consuming histories or tendencies
- **Biometric information:** Physiological, biological, or behavioral characteristics that can establish identity (fingerprints, face, voice, iris, keystroke patterns, gait, sleep/health/exercise data)
- **Internet activity:** Browsing history, search history, information regarding a consumer's interaction with a website, application, or advertisement
- **Geolocation data:** Precise geolocation (latitude/longitude sufficient to identify street-level location)
- **Sensory data:** Audio, electronic, visual, thermal, olfactory, or similar information
- **Professional or employment information:** Current or past job history, performance evaluations
- **Education information:** Not publicly available personally identifiable information as defined in FERPA
- **Inferences:** Drawn from any of the above to create a profile about a consumer (preferences, characteristics, psychological trends, predispositions, behavior, attitudes, intelligence, abilities, aptitudes)

**What is NOT personal information:**
- Publicly available information lawfully made available from government records
- De-identified or aggregate consumer information
- Information excluded by sector-specific federal privacy laws (HIPAA, GLBA, FCRA, etc.)

### 4.2 Business

A **business** (section 1798.140(d)) is a for-profit legal entity that:
1. Collects consumers' personal information (or has it collected on its behalf)
2. Alone or jointly determines the purposes and means of processing consumers' PI
3. Does business in California
4. Meets one or more of the applicability thresholds (see Section 3)

A business also includes any entity that controls or is controlled by a business and shares common branding.

### 4.3 Service Provider

A **service provider** (section 1798.140(ag)) is a legal entity that:
- Processes personal information **on behalf of a business**
- Is bound by a written contract that prohibits the entity from retaining, using, or disclosing the PI for any purpose other than performing the contracted services
- Is prohibited from selling or sharing the PI
- Is prohibited from combining the PI with data obtained from other sources (except to detect security incidents or fraud)
- Must certify understanding of and compliance with these restrictions

### 4.4 Contractor

A **contractor** (section 1798.140(j)) is a category introduced by the CPRA, distinct from service providers:
- A person or entity to whom the business makes available consumers' PI for a **business purpose** pursuant to a written contract
- Must be bound by contractual obligations similar to service providers
- Unlike service providers, contractors **receive** data from businesses but may not necessarily process it "on behalf of" the business in the same manner
- The distinction matters for contractual flow-down obligations and data access rights

### 4.5 Consumer

A **consumer** (section 1798.140(i)) is a natural person who is a California resident, as defined by Section 17014 of Title 18 of the California Code of Regulations:
- A person in California for other than a temporary or transitory purpose, OR
- A person domiciled in California who is temporarily outside the state

Note: Unlike the GDPR's "data subject," the CCPA's "consumer" is limited to California residents. It does not cover visitors to California or non-resident users of California-based services.

### 4.6 Sale and Sharing

**Sale** (section 1798.140(ad)): Selling, renting, releasing, disclosing, disseminating, making available, transferring, or otherwise communicating a consumer's PI by the business to a **third party** for monetary or other valuable consideration.

**Sharing** (section 1798.140(ah), added by CPRA): Sharing, renting, releasing, disclosing, disseminating, making available, transferring, or otherwise communicating a consumer's PI to a third party for **cross-context behavioral advertising**, whether or not for monetary consideration.

The "sharing" concept closes a loophole where businesses exchanged data for targeted advertising without a traditional monetary "sale."

### 4.7 Third Party

A **third party** (section 1798.140(ai)) is a person or entity that is not:
- The business that collected the PI
- A service provider of that business
- A contractor of that business

---

## 5. Consumer Rights

The CCPA/CPRA grants California consumers the following rights:

### 5.1 Right to Know (sections 1798.100, 1798.110, 1798.115)

Consumers have the right to request that a business disclose:
- The **categories** of personal information collected
- The **specific pieces** of personal information collected
- The **categories of sources** from which PI is collected
- The **business or commercial purpose** for collecting, selling, or sharing PI
- The **categories of third parties** to whom PI is disclosed
- The categories of PI **sold or shared**, and the categories of third parties to whom it was sold or shared

Businesses must respond to verifiable consumer requests within **45 calendar days** (extendable by an additional 45 days with notice). Businesses must provide this information for the **12-month period preceding the request** (CPRA extended this to allow consumers to request data beyond the 12-month lookback, except where doing so would be impossible or involve a disproportionate effort).

### 5.2 Right to Delete (section 1798.105)

Consumers have the right to request deletion of their personal information collected by the business, subject to certain exceptions:
- Completing a transaction or providing a requested good/service
- Security incident detection, protection against fraud or illegal activity
- Debugging to identify and repair errors
- Exercising free speech or another right provided by law
- Compliance with the California Electronic Communications Privacy Act
- Research in the public interest (with consumer consent)
- Internal uses reasonably aligned with consumer expectations
- Complying with a legal obligation
- Otherwise using the PI internally in a lawful manner compatible with the context in which it was provided

When a business receives a deletion request, it must also **notify its service providers and contractors** to delete the data, and those entities must in turn notify their sub-processors.

### 5.3 Right to Opt-Out of Sale or Sharing (section 1798.120)

- Consumers have the right to direct a business that sells or shares their personal information to **stop selling or sharing** their PI
- Businesses must provide a clear and conspicuous link on their homepage titled **"Do Not Sell or Share My Personal Information"** (or equivalent)
- Businesses must honor **opt-out preference signals** (such as the Global Privacy Control / GPC browser signal) as valid opt-out requests
- Once opted out, a business must wait at least **12 months** before requesting that the consumer opt back in
- Businesses must not use **dark patterns** to obtain consent to opt back in

### 5.4 Right to Correct (section 1798.106, added by CPRA)

Consumers have the right to request that a business **correct inaccurate personal information** that it maintains about the consumer. The business must use commercially reasonable efforts to correct the information as directed by the consumer.

### 5.5 Right to Limit Use of Sensitive Personal Information (section 1798.121, added by CPRA)

Consumers have the right to direct a business to **limit its use of sensitive personal information** to only those purposes that are necessary to perform the services or provide the goods reasonably expected by an average consumer (i.e., operational purposes only). See Section 8 for details on sensitive PI categories.

Businesses that use sensitive PI beyond what is necessary must provide a **"Limit the Use of My Sensitive Personal Information"** link (or a combined link with the opt-out).

### 5.6 Right to Non-Discrimination (section 1798.125)

A business shall not discriminate against a consumer for exercising any of their CCPA/CPRA rights. Discrimination includes:
- Denying goods or services
- Charging different prices or rates (including through discounts, penalties, or surcharges)
- Providing a different level or quality of goods or services
- Suggesting the consumer will receive a different price, rate, or quality

**Exception:** A business **may** offer financial incentives (loyalty programs, discounts) for the collection, sale, or retention of PI, provided:
- The consumer gives **opt-in consent**
- The incentive is reasonably related to the value of the consumer's data
- The terms of the program are clearly described in the privacy notice

### 5.7 Right to Data Portability

Implicit within the right to know (specific pieces), a consumer can request their PI in a format that is **portable and, to the extent technically feasible, in a readily usable format** that allows the consumer to transmit the information to another entity without hindrance.

---

## 6. Business Obligations

### 6.1 Privacy Notices

Businesses must provide consumers with privacy notices that include:

**At or before the point of collection (section 1798.100(b)):**
- Categories of PI to be collected
- Purposes for which the PI will be used
- Whether the PI is sold or shared
- Length of time the business intends to retain each category of PI, or the criteria used to determine the retention period

**General privacy policy (section 1798.130):**
- Categories of PI collected in the preceding 12 months
- Categories of PI sold or shared in the preceding 12 months, and the categories of third parties involved
- Categories of PI disclosed for a business purpose, and the categories of recipients
- Description of each consumer right and how to exercise them
- Contact information for submitting requests (toll-free number, if applicable, and website address)
- Date the privacy policy was last updated
- Whether the business has actual knowledge that it sells or shares PI of consumers under 16

The privacy policy must be updated **at least once every 12 months**.

### 6.2 Honoring Consumer Requests

- Provide **at least two methods** for submitting requests (e.g., toll-free number, web form, email). Businesses operating exclusively online with a direct consumer relationship may provide only an email address
- **Verify the identity** of the consumer making the request using reasonable methods (higher verification standard for specific pieces vs. categories)
- Respond within **45 calendar days** (extendable by 45 more with notice)
- Provide information **free of charge** (up to twice in a 12-month period)
- Do not require consumers to create an account to submit a request
- Must designate methods to submit opt-out requests, including via an **opt-out preference signal**

### 6.3 Data Minimization (CPRA)

Under the CPRA, businesses are subject to the following data minimization principles:

- **Collection limitation:** A business shall not collect PI beyond what is **reasonably necessary and proportionate** to achieve the purposes for which the PI was collected or processed
- **Use limitation:** A business shall not process PI in a manner incompatible with the disclosed purposes
- **Retention limitation:** A business's retention of PI must be **reasonably necessary and proportionate** to the purpose for which the PI was collected. PI must not be retained for longer than is reasonably necessary for each disclosed purpose
- **Purpose limitation:** If a business intends to use PI for a purpose **materially different** from what was disclosed, it must provide the consumer with notice

### 6.4 Opt-Out Mechanisms

- Post a **"Do Not Sell or Share My Personal Information"** link on the homepage
- Post a **"Limit the Use of My Sensitive Personal Information"** link (if applicable), or combine both links into a single **"Your Privacy Choices"** or equivalent link with an associated icon
- Honor **Global Privacy Control (GPC)** signals as valid opt-out requests
- Do not use **dark patterns** in the opt-out flow
- Maintain records of opt-out requests and ensure downstream recipients comply

### 6.5 Contractual Obligations

Businesses must enter into written contracts with service providers, contractors, and third parties that include:
- Specification of the business purpose(s) for data processing
- Prohibition on selling or sharing the PI
- Requirements to comply with the CCPA/CPRA
- Grant the business the right to take reasonable steps to ensure the processor uses PI consistently with the business's obligations
- Require the processor to notify the business if it can no longer meet its obligations
- Grant the business the right to take reasonable and appropriate steps to stop and remediate unauthorized use of PI

### 6.6 Record-Keeping

Businesses that buy, receive for commercial purposes, sell, or share for commercial purposes the PI of **10 million or more consumers** in a calendar year must:
- Compile metrics on consumer requests (number received, complied with, denied, and median response time) by request type
- Disclose these metrics in the privacy policy or on a separate page linked from the privacy policy

### 6.7 Risk Assessments (CPRA)

The CPRA mandates that the CPPA issue regulations requiring businesses whose processing presents **significant risk to consumers' privacy or security** to:
- Submit regular **risk assessments** to the CPPA
- Perform **cybersecurity audits** on an annual basis

The CPPA has been developing these regulations, and businesses should monitor the rulemaking process for final requirements.

---

## 7. Service Provider and Contractor Requirements

### 7.1 Contractual Requirements

Both service providers and contractors must be bound by written contracts that include:

| Requirement | Service Provider | Contractor |
|-------------|-----------------|------------|
| Prohibit retaining, using, or disclosing PI beyond contracted services | Yes | Yes |
| Prohibit selling PI | Yes | Yes |
| Prohibit sharing PI | Yes | Yes |
| Prohibit combining PI with data from other sources (except for specified purposes) | Yes | Yes |
| Require compliance with CCPA/CPRA | Yes | Yes |
| Require notification if unable to meet obligations | Yes | Yes |
| Grant the business monitoring/audit rights | Yes | Yes |
| Require same obligations on sub-processors | Yes | Yes |
| Certify understanding of restrictions | Yes | Yes |

### 7.2 Obligations When Receiving Consumer Requests

- If a service provider or contractor receives a consumer request directly, it should either comply or inform the consumer that the request should be made to the business
- Service providers and contractors must cooperate with businesses in fulfilling consumer requests (e.g., deletion requests)
- Must delete PI upon notification by the business

### 7.3 Sub-Processing

- Service providers and contractors must enter into contracts with their own sub-processors (sub-service providers/sub-contractors) that impose the same level of privacy protection
- The flow-down of obligations must extend through the entire processing chain
- The business retains the right to audit downstream processors through its direct contractual partner

### 7.4 Distinguishing Service Providers from Contractors

The practical difference:
- **Service providers** process PI "on behalf of" the business (analogous to GDPR processors). Example: A cloud hosting provider, a payroll processor
- **Contractors** receive PI from the business but have somewhat more independent use, though still constrained by contract. Example: A consulting firm that receives employee data for an engagement

Both are distinguished from **third parties**, which receive PI without the same contractual restrictions and may use the PI for their own purposes.

---

## 8. Sensitive Personal Information

### 8.1 Categories

The CPRA introduced the concept of **sensitive personal information (SPI)** (section 1798.140(ae)), which includes:

1. **Government identifiers:** Social Security number, driver's license, state identification card, passport number
2. **Financial account information:** Account log-in, financial account, debit card, or credit card number in combination with any required security or access code, password, or credentials allowing access to the account
3. **Precise geolocation:** Derived from a device within a radius of **1,850 feet** (approximately 564 meters) that identifies a consumer's specific location
4. **Racial or ethnic origin**
5. **Religious or philosophical beliefs**
6. **Union membership**
7. **Contents of communications:** Mail, email, and text messages, unless the business is the intended recipient of the communication
8. **Genetic data**
9. **Biometric information** processed for the purpose of uniquely identifying a consumer
10. **Health information**
11. **Sex life or sexual orientation**

### 8.2 Consumer Right to Limit Use

When a business collects SPI, consumers have the right to limit its use to what is **necessary to perform the services or provide the goods reasonably expected by an average consumer** who requests those goods or services. Specifically, allowed uses include:

- Performing services or providing goods requested by the consumer
- Ensuring security and integrity
- Short-term, transient use (including non-personalized advertising)
- Performing services on behalf of the business (e.g., customer service, order fulfillment, billing)
- Quality and safety maintenance/verification
- Activities to verify or maintain the quality or safety of a product/service

### 8.3 Business Obligations for SPI

- If a business uses or discloses SPI for purposes beyond those listed above, it must:
  - Provide a **"Limit the Use of My Sensitive Personal Information"** link
  - Include the SPI categories collected, purposes of use, and whether it is sold or shared in the privacy notice
  - Limit use to the operational purposes upon consumer request
- Businesses should apply heightened security measures to SPI, including encryption at rest and in transit, access controls, and monitoring

---

## 9. Children's Data Protections

### 9.1 CCPA/CPRA Protections for Minors

The CCPA/CPRA provides enhanced protections for children's personal information:

**Children under 13:**
- A business shall **not sell or share** the PI of a consumer the business has actual knowledge is under 13 years of age, unless the child's **parent or guardian** has affirmatively authorized the sale or sharing (opt-in consent required)

**Children aged 13 to 15:**
- A business shall **not sell or share** the PI of a consumer the business has actual knowledge is at least 13 but under 16 years of age, unless the **consumer** (the minor themselves) has affirmatively authorized the sale or sharing (opt-in consent required)

**All consumers under 16:**
- Violations involving the PI of consumers known or reasonably should have been known to be under 16 are subject to penalties of **$7,500 per violation** (the same as intentional violations, regardless of intent)
- The "should have known" standard was added by CPRA, meaning businesses cannot simply avoid asking for age to avoid the obligation

### 9.2 Interaction with COPPA

The federal **Children's Online Privacy Protection Act (COPPA)** applies to:
- Websites and online services directed to children under 13
- General audience websites with actual knowledge they are collecting PI from children under 13

**Key interactions:**
- COPPA requires **verifiable parental consent** before collecting PI from children under 13
- CCPA/CPRA layers additional requirements on top of COPPA, particularly around the **sale and sharing** of children's data
- Compliance with COPPA does not automatically satisfy CCPA/CPRA requirements (and vice versa); businesses must comply with both independently
- CCPA/CPRA extends protections to ages **13-15** (an age range not covered by COPPA), requiring opt-in consent for sale/sharing
- The CCPA/CPRA does not preempt COPPA and is intended to complement federal protections

### 9.3 California Age-Appropriate Design Code Act (CAADCA)

While separate from the CCPA/CPRA, California's **Age-Appropriate Design Code Act** (AB 2273, effective July 1, 2024, though subject to legal challenges) imposes additional obligations on businesses likely to be accessed by children under 18, including:
- Data Protection Impact Assessments (DPIAs) for features likely accessed by children
- Default privacy settings set to "high" for child users
- Age estimation mechanisms

Businesses should consider these requirements alongside CCPA/CPRA compliance for products accessible to minors.

---

## 10. Penalties and Private Right of Action

### 10.1 Administrative/Civil Penalties

| Violation Type | Penalty Amount | Enforced By |
|---------------|---------------|-------------|
| Unintentional violation | Up to **$2,500 per violation** | AG or CPPA |
| Intentional violation | Up to **$7,500 per violation** | AG or CPPA |
| Violation involving children under 16 | Up to **$7,500 per violation** | AG or CPPA |

**Key points:**
- Penalties are assessed **per violation**, which courts may interpret as per-consumer, per-occurrence, or per-record, depending on the circumstances. This can result in very substantial aggregate penalties
- Under the CPRA, the mandatory 30-day cure period was eliminated; the AG or CPPA may, at their discretion, provide an opportunity to cure
- The CPPA can impose administrative fines through its own administrative proceedings (no court action required)
- Penalties go into the **Consumer Privacy Fund** to support enforcement

### 10.2 Private Right of Action (section 1798.150)

The CCPA provides consumers with a **limited private right of action** specifically for **data breaches** resulting from a business's failure to implement and maintain reasonable security procedures and practices. This is the only private right of action under the CCPA/CPRA.

**Requirements:**
- The consumer's **nonencrypted and nonredacted personal information** (as defined by Cal. Civ. Code section 1798.81.5(d)) was subject to unauthorized access, exfiltration, theft, or disclosure as a result of the business's failure to maintain reasonable security
- The categories of PI eligible for the private right of action are narrower than the general CCPA definition and include: name combined with SSN, driver's license number, financial account number with access codes, medical information, health insurance information, or biometric data
- Consumers must provide **30 days' written notice** to the business before filing suit, identifying the specific CCPA provisions violated
- If the business actually cures the violation within 30 days and provides an express written statement that the violations have been cured and no further violations will occur, no individual action for statutory damages may be maintained

**Damages:**
- **Statutory damages:** Not less than **$100** and not greater than **$750 per consumer per incident**, OR actual damages, whichever is greater
- **Injunctive or declaratory relief**
- **Any other relief the court deems proper**
- **Class actions** are permitted, making the aggregate exposure significant

### 10.3 Relationship to Other Laws

- The CCPA/CPRA's private right of action is narrower than many state data breach notification laws but provides a statutory damages floor that does not require proof of actual harm
- Businesses remain subject to other California laws (e.g., the California Confidentiality of Medical Information Act, Cal. Civ. Code section 1798.29 breach notification) and federal laws (e.g., HIPAA, GLBA)

---

## 11. Application to Software and Applications

### 11.1 Software as a Business

A software company or application developer may qualify as a "business" under the CCPA/CPRA if it:
- Meets any of the three thresholds (revenue, data volume, revenue from data sales/sharing)
- Collects personal information from California consumers through its software products
- Determines the purposes and means of processing (i.e., acts as a data controller, not merely a processor)

### 11.2 Software as a Service Provider

A software company may act as a **service provider** (or contractor) when it processes PI on behalf of its business customers. In this scenario:
- The software company's customer is the "business" under the CCPA/CPRA
- The software company must enter into a compliant service provider agreement
- The software company must not use customer data for its own purposes beyond the contracted services
- The software company must assist the business in fulfilling consumer requests

### 11.3 Key Application Design Considerations

**Data Collection:**
- Implement **privacy by design** and **privacy by default** principles
- Minimize data collection to what is reasonably necessary
- Clearly disclose all categories of PI collected and the purposes of collection
- Implement mechanisms to track the purpose for each data element collected

**Consent and Opt-Out:**
- Implement **opt-out mechanisms** for sale/sharing of PI
- Implement **opt-in mechanisms** for consumers under 16 (and parental consent for those under 13)
- Detect and honor **Global Privacy Control (GPC)** signals
- Implement **"Limit Use of Sensitive PI"** functionality where applicable
- Do not use **dark patterns** in consent flows

**Consumer Request Fulfillment:**
- Build infrastructure to **receive, verify, and respond** to consumer requests (know, delete, correct, opt-out, limit SPI use)
- Ensure the system can locate **all PI** associated with a consumer across all data stores
- Implement automated or semi-automated deletion workflows
- Maintain audit trails for consumer requests and responses
- Support data portability (export in machine-readable formats)

**Data Security:**
- Implement **reasonable security procedures and practices** appropriate to the nature of the PI (this is critical to avoid the private right of action for data breaches)
- Encrypt PI in transit and at rest
- Implement access controls, authentication, and audit logging
- Conduct regular security assessments and penetration testing

**Vendor Management:**
- When integrating third-party services (analytics, advertising, cloud services), ensure compliant contracts are in place
- Evaluate whether third-party integrations constitute a "sale" or "sharing" of PI
- Ensure contractual flow-down of obligations

### 11.4 Data Mapping and Inventories

Applications should maintain (or enable businesses to maintain):
- An inventory of all PI categories collected
- The sources of each PI category
- The purposes for collection and processing
- Categories of third parties with whom PI is shared
- Retention periods for each PI category
- The legal basis or business purpose for each processing activity

---

## 12. Considerations for Mendix and Low-Code Applications

### 12.1 Platform vs. Application Responsibility

In a Mendix (or similar low-code platform) environment, there is a **shared responsibility model** for CCPA/CPRA compliance:

| Aspect | Platform Provider (Siemens/Mendix) | Application Developer/Operator |
|--------|-----------------------------------|-------------------------------|
| Infrastructure security | Primary responsibility | Configuration responsibility |
| Data model design | Provides tools/framework | Designs compliant data models |
| Privacy notice content | N/A | Full responsibility |
| Consumer request fulfillment | Provides platform capabilities | Implements business logic |
| Data retention/deletion | Provides mechanisms | Configures and executes |
| Third-party integrations | Platform marketplace governance | Selection and configuration |
| Opt-out mechanisms | May provide widgets/modules | Must implement in app |
| GPC signal handling | May require custom implementation | Must ensure implementation |
| Data mapping | Provides domain model tools | Maps and documents PI flows |

### 12.2 Mendix-Specific Technical Considerations

**Domain Model Design:**
- Design entities with CCPA/CPRA compliance in mind: separate PI from non-PI, flag SPI categories
- Consider creating a **consent management** entity/module to track consumer preferences (opt-in, opt-out, limit SPI use)
- Implement **soft delete** capabilities to support deletion requests while maintaining legal hold obligations
- Use **enumeration attributes** or flags to classify data sensitivity levels
- Design for data minimization: only create attributes that are reasonably necessary

**Microflows and Nanoflows:**
- Build microflows to handle consumer request workflows (intake, verification, fulfillment, response)
- Implement automated data discovery microflows that can locate all PI associated with a consumer across the domain model
- Create export microflows for data portability (JSON/CSV export of consumer PI)
- Implement scheduled events for **data retention enforcement** (automatic deletion after retention period)

**User Interface:**
- Implement privacy preference centers where consumers can exercise their rights
- Add a **"Do Not Sell or Share My Personal Information"** page or link
- Add a **"Limit the Use of My Sensitive Personal Information"** option if applicable
- Implement cookie consent mechanisms if the app uses cookies for tracking
- Detect and honor GPC signals (requires custom JavaScript in the Mendix app or a dedicated module)

**Integration Considerations:**
- When using Mendix connectors to third-party services (CRM, analytics, marketing platforms), document and evaluate each integration for potential PI sale/sharing
- REST/OData/SOAP integrations that transmit PI must be covered by appropriate contracts
- Evaluate Mendix Marketplace modules for CCPA compliance (e.g., ensure analytics modules respect opt-out preferences)

**Mendix Cloud vs. On-Premises:**
- **Mendix Cloud:** Siemens acts as a service provider/processor. Verify that Mendix's Data Processing Agreement (DPA) includes CCPA-compliant terms
- **On-Premises/Private Cloud:** The application operator bears full responsibility for infrastructure security and data management
- Review Mendix's Trust Center documentation for their CCPA compliance posture

### 12.3 Common Low-Code Pitfalls

- **Over-collection:** Low-code platforms make it easy to add fields; discipline is needed to collect only what is necessary
- **Hard-coded integrations:** Marketplace modules may share data with third parties (analytics, error tracking) without clear disclosure
- **Lack of deletion capability:** If entities have deep associations, deleting a consumer's data may require cascading deletes across many related objects
- **Missing audit trails:** Ensure all consumer request actions are logged with timestamps
- **Default configurations:** Out-of-the-box Mendix apps do not include CCPA compliance features; these must be deliberately designed and built

---

## 13. Compliance Checklist for Application Developers

### 13.1 Data Inventory and Mapping

- [ ] Identify all categories of personal information collected by the application
- [ ] Document the source(s) of each PI category
- [ ] Document the business/commercial purpose for each PI category
- [ ] Identify which PI categories qualify as sensitive personal information
- [ ] Map all data flows: collection points, internal processing, storage locations, third-party transfers
- [ ] Document retention periods for each PI category
- [ ] Identify all third parties, service providers, and contractors that receive PI

### 13.2 Privacy Notices and Disclosures

- [ ] Implement a comprehensive privacy policy covering all CCPA/CPRA-required disclosures
- [ ] Provide a notice at or before the point of collection
- [ ] Include a "Do Not Sell or Share My Personal Information" link (if applicable)
- [ ] Include a "Limit the Use of My Sensitive Personal Information" link (if applicable)
- [ ] Disclose whether PI of consumers under 16 is sold or shared
- [ ] Update the privacy policy at least annually
- [ ] Include data retention periods in the privacy policy

### 13.3 Consumer Rights Infrastructure

- [ ] Implement at least two methods for consumers to submit requests (e.g., web form, email)
- [ ] Build identity verification workflows for consumer requests
- [ ] Implement Right to Know (categories and specific pieces)
- [ ] Implement Right to Delete (including notification to service providers/contractors)
- [ ] Implement Right to Correct
- [ ] Implement Right to Opt-Out of sale/sharing
- [ ] Implement Right to Limit Use of Sensitive PI
- [ ] Implement data portability (export PI in machine-readable format)
- [ ] Ensure non-discrimination: exercising rights does not degrade service
- [ ] Track and respond to requests within 45 days (with extension process)
- [ ] Maintain request logs for at least 24 months

### 13.4 Opt-Out Mechanisms

- [ ] Implement and honor Global Privacy Control (GPC) signals
- [ ] Implement a user-facing opt-out mechanism for sale/sharing
- [ ] Ensure downstream third parties respect opt-out preferences
- [ ] Do not use dark patterns in opt-out or consent flows
- [ ] Implement a 12-month wait period before requesting re-opt-in

### 13.5 Data Security

- [ ] Implement encryption for PI in transit (TLS 1.2+)
- [ ] Implement encryption for PI at rest
- [ ] Implement role-based access controls
- [ ] Implement multi-factor authentication for administrative access
- [ ] Conduct regular security assessments and penetration testing
- [ ] Implement intrusion detection/prevention systems
- [ ] Maintain an incident response plan
- [ ] Implement logging and monitoring of access to PI
- [ ] Apply the principle of least privilege

### 13.6 Vendor and Third-Party Management

- [ ] Maintain an inventory of all third parties, service providers, and contractors
- [ ] Execute CCPA-compliant contracts with all service providers and contractors
- [ ] Evaluate third-party integrations for potential PI sale/sharing
- [ ] Implement contractual flow-down requirements for sub-processors
- [ ] Conduct periodic assessments of vendor compliance

### 13.7 Data Minimization and Retention

- [ ] Review all data fields for necessity and proportionality
- [ ] Remove or stop collecting unnecessary PI
- [ ] Implement automated retention enforcement (scheduled deletion)
- [ ] Document and justify retention periods
- [ ] Implement data de-identification where possible

### 13.8 Children's Data

- [ ] Determine whether the application is likely to be accessed by minors
- [ ] Implement age-gating or age estimation if applicable
- [ ] Implement opt-in consent for sale/sharing of PI for consumers under 16
- [ ] Implement parental/guardian consent mechanisms for consumers under 13
- [ ] Apply heightened protections to children's data

### 13.9 Training and Governance

- [ ] Train personnel who handle consumer inquiries on CCPA/CPRA requirements
- [ ] Designate a privacy point of contact or Data Protection Officer
- [ ] Establish a process for monitoring regulatory updates
- [ ] Document compliance efforts for audit readiness
- [ ] Conduct periodic internal privacy audits

---

## 14. Comparison with GDPR and Colorado Privacy Act

### 14.1 CCPA/CPRA vs. GDPR

| Aspect | CCPA/CPRA | GDPR |
|--------|-----------|------|
| **Jurisdiction** | California, USA | European Union / EEA |
| **Effective Date** | CCPA: Jan 1, 2020; CPRA amendments: Jan 1, 2023 | May 25, 2018 |
| **Scope** | For-profit businesses meeting thresholds that collect CA consumer PI | Any entity processing personal data of EU/EEA residents, regardless of entity location or profit status |
| **Legal Basis for Processing** | No requirement to establish a legal basis; focuses on transparency and consumer rights | Requires one of six lawful bases (consent, contract, legal obligation, vital interests, public task, legitimate interest) |
| **Applicability Thresholds** | $25M revenue, 100K consumers, or 50% revenue from data sales/sharing | No thresholds; applies to all data processing of EU residents' data |
| **Non-Profits** | Generally exempt | Covered |
| **Consent Model** | Opt-out for sale/sharing; opt-in for minors and SPI limits | Opt-in consent required for many processing activities |
| **Sensitive Data** | SPI with right to limit use | Special categories with stricter lawful bases required (typically explicit consent) |
| **Right to Know/Access** | Yes | Yes (Right of Access, Art. 15) |
| **Right to Delete/Erasure** | Yes (with exceptions) | Yes (Right to Erasure, Art. 17, with exceptions) |
| **Right to Correct/Rectification** | Yes (CPRA) | Yes (Art. 16) |
| **Right to Portability** | Implicit in right to know (specific pieces) | Explicit right (Art. 20), machine-readable format |
| **Right to Opt-Out** | Yes (sale/sharing) | No direct equivalent; consent withdrawal and right to object serve similar functions |
| **Right to Restrict Processing** | Right to limit SPI use | Right to Restriction of Processing (Art. 18) |
| **Data Protection Officer** | No requirement (though recommended) | Required for certain entities (public bodies, large-scale processing, special categories) |
| **Data Protection Impact Assessment** | Risk assessments (CPRA, regulations pending) | DPIA required for high-risk processing (Art. 35) |
| **Breach Notification** | Private right of action for breaches; CA breach notification law (Cal. Civ. Code 1798.29) has its own requirements | 72-hour notification to supervisory authority (Art. 33); "without undue delay" to data subjects (Art. 34) |
| **Penalties** | $2,500-$7,500 per violation (AG/CPPA); $100-$750 per consumer per incident (private right of action) | Up to 4% of global annual turnover or EUR 20 million, whichever is greater |
| **Data Transfer Restrictions** | No CCPA-specific cross-border transfer restrictions | Strict rules on international data transfers (adequacy decisions, SCCs, BCRs) |
| **Cure Period** | Discretionary (was mandatory 30 days under original CCPA) | No cure period; supervisory authorities have discretion |
| **Private Right of Action** | Limited to data breaches | Broader right to compensation for damages (Art. 82) |
| **Data Minimization** | Yes (CPRA) | Yes (Art. 5(1)(c)), fundamental principle |
| **Purpose Limitation** | Yes (CPRA) | Yes (Art. 5(1)(b)), fundamental principle |

### 14.2 CCPA/CPRA vs. Colorado Privacy Act (CPA)

| Aspect | CCPA/CPRA | Colorado Privacy Act (CPA) |
|--------|-----------|---------------------------|
| **Effective Date** | CCPA: Jan 1, 2020; CPRA: Jan 1, 2023 | July 1, 2023 |
| **Scope** | For-profit businesses with CA thresholds | Entities conducting business in CO or targeting CO residents, and: (a) control/process PI of 100K+ consumers/year, OR (b) derive revenue from sale of PI and process/control PI of 25K+ consumers |
| **Revenue Threshold** | $25M or 50% from data sales/sharing | No revenue threshold |
| **Covered Entities** | For-profit only | For-profit and non-profit (no profit status limitation) |
| **Consent Model** | Opt-out for sale/sharing; opt-in for children, limit for SPI | Opt-out for sale, targeted advertising, profiling; opt-in for sensitive data |
| **Consumer Rights** | Know, delete, correct, opt-out, limit SPI use, non-discrimination | Access, correct, delete, data portability, opt-out of sale/targeted ads/profiling |
| **Sensitive Data** | SPI with right to limit use (opt-out model) | Requires **opt-in consent** for processing sensitive data |
| **Universal Opt-Out** | Must honor GPC / opt-out preference signals | Must honor **universal opt-out mechanisms** (effective July 1, 2024) |
| **Data Protection Assessments** | Required by CPRA regulations (pending finalization) | Required for processing that presents heightened risk (targeted advertising, sale, profiling, sensitive data, data involving minors) |
| **Enforcement** | AG and CPPA; private right of action for breaches | AG only; **no private right of action** |
| **Cure Period** | Discretionary | 60-day cure period (expired January 1, 2025) |
| **Penalties** | $2,500-$7,500 per violation | Up to $20,000 per violation under Colorado Consumer Protection Act |
| **Children's Protections** | Opt-in consent for sale/sharing under 16; parental consent under 13 | Sensitive data includes data from known children; opt-in consent required |
| **Data Minimization** | Yes (CPRA) | Yes (collection limited to what is adequate, relevant, and reasonably necessary) |
| **Processor/Controller Distinction** | Business/service provider/contractor | Controller/processor (closer to GDPR terminology) |

### 14.3 Key Takeaway for Multi-Jurisdictional Compliance

Organizations operating across California, the EU, Colorado, and other privacy-regulated jurisdictions should consider adopting a **highest-common-denominator approach**:

- Implement GDPR-level protections as a baseline (lawful basis, opt-in consent where required, DPIAs, DPO)
- Layer CCPA/CPRA-specific requirements on top (opt-out mechanisms, SPI limit mechanisms, GPC support, California-specific privacy policy disclosures)
- Address Colorado-specific requirements (opt-in for sensitive data, universal opt-out mechanisms, DPAs)
- Monitor emerging state privacy laws (Virginia CDPA, Connecticut CTDPA, Texas TDPSA, Oregon OCPA, and others) for additional obligations
- Design systems with configurability to adapt to varying jurisdictional requirements without re-architecture

---

## 15. Appendix: Key Resources

### Official Sources

- **CCPA/CPRA Statutory Text:** California Civil Code, Title 1.81.5, sections 1798.100-1798.199.100
  - Available at: https://leginfo.legislature.ca.gov/
- **California Attorney General CCPA Page:** https://oag.ca.gov/privacy/ccpa
- **California Privacy Protection Agency:** https://cppa.ca.gov/
- **CPPA Regulations:** https://cppa.ca.gov/regulations/
- **CPPA Enforcement Updates:** https://cppa.ca.gov/enforcement/

### Federal Resources

- **FTC COPPA Information:** https://www.ftc.gov/legal-library/browse/rules/childrens-online-privacy-protection-rule-coppa
- **GDPR Official Text:** https://gdpr.eu/

### Colorado Privacy Act

- **Colorado Privacy Act Text:** https://leg.colorado.gov/bills/sb21-190
- **Colorado AG CPA Resources:** https://coag.gov/resources/colorado-privacy-act/

### Industry Standards

- **NIST Privacy Framework:** https://www.nist.gov/privacy-framework
- **ISO 27701 (Privacy Information Management):** https://www.iso.org/standard/71670.html
- **OWASP Privacy Guidelines:** https://owasp.org/www-project-top-10-privacy-risks/

---

*This document was prepared as a compliance reference guide. It reflects the law as of February 2026. Privacy regulations evolve frequently; always verify current requirements with authoritative sources and qualified legal counsel before making compliance decisions.*
