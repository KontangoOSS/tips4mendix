# Colorado Privacy Act (CPA) Compliance Guide

## For Enterprise Software and Application Development

**Document Version:** 1.0
**Last Updated:** February 2026
**Applicable Statute:** C.R.S. Title 6, Article 1, Part 13 (SB 21-190)
**Effective Date:** July 1, 2023
**Universal Opt-Out Mechanism Compliance Date:** July 1, 2024

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [What Is the Colorado Privacy Act](#2-what-is-the-colorado-privacy-act)
3. [Enforcement Authority](#3-enforcement-authority)
4. [Scope and Applicability](#4-scope-and-applicability)
5. [Key Definitions](#5-key-definitions)
6. [Consumer Rights](#6-consumer-rights)
7. [Universal Opt-Out Mechanism](#7-universal-opt-out-mechanism)
8. [Controller Obligations](#8-controller-obligations)
9. [Processor Obligations](#9-processor-obligations)
10. [Data Protection Assessments](#10-data-protection-assessments)
11. [Sensitive Data Handling](#11-sensitive-data-handling)
12. [Penalties and Enforcement](#12-penalties-and-enforcement)
13. [Application to Software and Applications](#13-application-to-software-and-applications)
14. [Mendix and Low-Code Platform Considerations](#14-mendix-and-low-code-platform-considerations)
15. [Compliance Checklist for Application Developers](#15-compliance-checklist-for-application-developers)
16. [Comparison with CCPA and GDPR](#16-comparison-with-ccpa-and-gdpr)
17. [Additional Resources](#17-additional-resources)

---

## 1. Executive Summary

The Colorado Privacy Act (CPA) is a comprehensive consumer data privacy law that grants Colorado residents significant rights over their personal data and imposes obligations on businesses that collect, process, and store that data. Signed into law on July 7, 2021, the CPA took effect on **July 1, 2023**, making Colorado the third U.S. state (after California and Virginia) to enact a comprehensive privacy statute.

The CPA is codified at **C.R.S. Section 6-1-1301 et seq.** and is supplemented by formal rules adopted by the Colorado Attorney General, which provide detailed implementation guidance on topics including universal opt-out mechanisms, data protection assessments, and privacy notice requirements.

Organizations that develop, deploy, or operate software applications -- including those built on low-code platforms such as Mendix -- must understand their obligations under the CPA to ensure compliance and mitigate enforcement risk.

---

## 2. What Is the Colorado Privacy Act

### Legislative Background

The CPA was enacted through **Senate Bill 21-190**, signed by Governor Jared Polis on July 7, 2021. Colorado became the third state in the United States to pass a comprehensive consumer privacy law, following the California Consumer Privacy Act (CCPA) and the Virginia Consumer Data Protection Act (VCDPA).

### Effective Dates

| Milestone | Date |
|---|---|
| Signed into law | July 7, 2021 |
| General effective date | **July 1, 2023** |
| Universal opt-out mechanism compliance | **July 1, 2024** |
| AG final rulemaking adopted | March 15, 2023 (effective July 1, 2023) |

### Legislative Intent

The CPA was designed to:

- Provide Colorado consumers with meaningful control over their personal data
- Establish clear obligations for businesses that process personal data
- Create a framework for data protection that accounts for modern data processing practices
- Complement existing Colorado consumer protection statutes under the Colorado Consumer Protection Act (CCPA, C.R.S. Section 6-1-101 et seq.)

---

## 3. Enforcement Authority

### Colorado Attorney General

The CPA is enforced **exclusively** by the **Colorado Attorney General (AG)** and **Colorado District Attorneys**. This is a critical distinction from laws like the CCPA, which provides a limited private right of action.

**There is no private right of action under the CPA.** Consumers cannot bring individual or class-action lawsuits directly under the statute. Enforcement is pursued as a violation of the Colorado Consumer Protection Act.

### AG Rulemaking Authority

The CPA grants the Colorado AG formal rulemaking authority under C.R.S. Section 6-1-1313. The AG has exercised this authority to adopt detailed rules (4 CCR 904-3) covering:

- Universal opt-out mechanism technical specifications
- Data protection assessment requirements and procedures
- Privacy notice content and format requirements
- Consent mechanisms for sensitive data processing
- Clarification of key statutory terms

### Cure Period

The CPA originally included a **60-day cure period**, which allowed controllers to cure alleged violations before the AG could bring an enforcement action. This cure period **expired on January 1, 2025**. After that date, the AG has discretion (but no obligation) to provide an opportunity to cure before taking enforcement action.

---

## 4. Scope and Applicability

### Who Is Covered

The CPA applies to entities that:

1. Conduct business in Colorado **or** produce or deliver commercial products or services intentionally targeted to Colorado residents; **AND**
2. Meet **either** of the following thresholds:

| Threshold | Description |
|---|---|
| **Volume Threshold** | Control or process personal data of **100,000 or more Colorado consumers** per calendar year |
| **Revenue + Volume Threshold** | Control or process personal data of **25,000 or more Colorado consumers** per calendar year **AND** derive revenue or receive a discount on the price of goods or services from the sale of personal data |

**Important notes on thresholds:**

- "Consumer" means a Colorado resident acting in an individual or household context. It **excludes** individuals acting in a commercial or employment context.
- There is **no minimum revenue threshold** (unlike the CCPA, which has a $25 million gross revenue trigger).
- The thresholds are measured per **calendar year**.
- "Sale of personal data" means the exchange of personal data for monetary or other valuable consideration.

### Exemptions

The CPA provides exemptions at both the **entity level** and the **data level**:

**Entity-Level Exemptions:**

- Financial institutions and affiliates subject to the Gramm-Leach-Bliley Act (GLBA)
- Entities subject to the Health Insurance Portability and Accountability Act (HIPAA), including covered entities and business associates
- Institutions of higher education
- National securities associations registered under the Securities Exchange Act of 1934
- Air carriers

**Data-Level Exemptions (specific data types, not entire entities):**

- Data governed by HIPAA (Protected Health Information)
- Data governed by GLBA
- Data governed by the Fair Credit Reporting Act (FCRA)
- Data governed by the Driver's Privacy Protection Act (DPPA)
- Data governed by the Family Educational Rights and Privacy Act (FERPA)
- Data governed by the Children's Online Privacy Protection Act (COPPA)
- Data governed by the Farm Credit Act
- Employment data (personal data processed in an employment or B2B context)
- Publicly available information (data lawfully made available from government records or widely distributed media)
- De-identified data and pseudonymous data (if certain conditions are met)

---

## 5. Key Definitions

Understanding the CPA requires familiarity with its specific terminology, defined in C.R.S. Section 6-1-1303:

### Personal Data

**"Personal data"** means information that is linked or reasonably linkable to an identified or identifiable individual. It does **not** include de-identified data or publicly available information.

Key characteristics:
- Broad scope covering any data linked or reasonably linkable to a person
- Includes online identifiers, IP addresses, device identifiers, cookie data, and similar technical data when they can be linked to an individual
- Does not include data processed in a purely aggregate or de-identified form that cannot reasonably be re-identified

### Consumer

**"Consumer"** means an individual who is a Colorado resident acting only in an individual or household context. It **excludes** a person acting in a commercial or employment context.

This means:
- Employee data is generally outside scope (employment context exemption)
- B2B contact data is generally outside scope (commercial context exemption)
- The law protects individuals in their capacity as consumers, not as employees or business professionals

### Controller

**"Controller"** means a person that, alone or jointly with others, determines the purposes and means of processing personal data. This is the entity that decides **why** and **how** personal data is processed.

In the application context:
- The organization that deploys and operates a software application is typically the controller
- A SaaS provider may be a controller, processor, or both depending on the relationship
- If you decide what data to collect and why, you are likely a controller

### Processor

**"Processor"** means a person that processes personal data on behalf of a controller. This is the entity that processes data **as directed by** the controller.

In the application context:
- Cloud infrastructure providers (AWS, Azure, GCP) are typically processors
- Platform-as-a-service providers (such as Mendix Cloud) may be processors
- A contractor developing an application on behalf of a client may be a processor

### Sale of Personal Data

**"Sale of personal data"** means the exchange of personal data for monetary or other valuable consideration by a controller to a third party.

Exclusions from the definition of "sale":
- Disclosure to a processor acting on behalf of the controller
- Disclosure to a third party for purposes consistent with consumer expectations
- Disclosure to an affiliate of the controller
- Disclosure as part of a merger, acquisition, or similar transaction
- Disclosure the consumer intentionally made available to the general public

### Targeted Advertising

**"Targeted advertising"** means displaying an advertisement to a consumer where the advertisement is selected based on personal data obtained or inferred from the consumer's activities over time and across nonaffiliated websites, applications, or online services to predict consumer preferences or interests.

Exclusions:
- Advertisements based on activities within the controller's own websites or applications
- Advertisements based on the context of a consumer's current search query or visit
- Advertisements directed to a consumer in response to the consumer's request for information or feedback
- First-party advertising

### Profiling

**"Profiling"** means any form of automated processing of personal data to evaluate, analyze, or predict personal aspects concerning an identified or identifiable individual's economic situation, health, personal preferences, interests, reliability, behavior, location, or movements.

### Consent

**"Consent"** means a clear affirmative act signifying a consumer's freely given, specific, informed, and unambiguous agreement to process personal data. Consent may include a written statement, including by electronic means, or any other unambiguous affirmative action.

The following do **not** constitute consent:
- Acceptance of general or broad terms of use or similar documents
- Hovering over, muting, pausing, or closing a given piece of content
- Agreement obtained through the use of dark patterns

### Sensitive Data

**"Sensitive data"** means a category of personal data that includes:

- Personal data revealing racial or ethnic origin
- Personal data revealing religious beliefs
- Personal data concerning a consumer's mental or physical health condition or diagnosis
- Personal data revealing sex life or sexual orientation
- Personal data revealing citizenship or immigration status
- Genetic data that may be processed for the purpose of uniquely identifying an individual
- Biometric data processed for the purpose of uniquely identifying an individual
- Personal data of a known child (under 13 years of age)

---

## 6. Consumer Rights

The CPA grants Colorado consumers the following rights with respect to their personal data. Controllers must provide mechanisms for consumers to exercise these rights and must respond within **45 days** (extendable by an additional 45 days when reasonably necessary, with notice to the consumer).

### 6.1 Right to Access (Right to Know)

Consumers have the right to confirm whether a controller is processing their personal data and to access that data. The controller must provide the data in a portable and, to the extent technically feasible, readily usable format.

### 6.2 Right to Correction

Consumers have the right to correct inaccuracies in their personal data, taking into account the nature of the personal data and the purposes of processing.

### 6.3 Right to Deletion

Consumers have the right to delete personal data provided by or obtained about the consumer. Controllers must also direct processors to delete the data.

### 6.4 Right to Data Portability

Consumers have the right to obtain their personal data in a portable and, to the extent technically feasible, readily usable format that allows the consumer to transmit the data to another entity without hindrance.

### 6.5 Right to Opt Out

Consumers have the right to opt out of the processing of their personal data for purposes of:

1. **Targeted advertising**
2. **Sale of personal data**
3. **Profiling in furtherance of decisions that produce legal or similarly significant effects** concerning the consumer

### Appeals Process

If a controller declines to take action on a consumer's request, the controller must inform the consumer without undue delay, within 45 days of receiving the request, of the justification for declining and instructions on how to appeal. The controller must establish an internal appeals process.

If the appeal is denied, the controller must provide the consumer with an online mechanism (if available) or other method through which the consumer may contact the Colorado Attorney General to submit a complaint.

---

## 7. Universal Opt-Out Mechanism

### Overview

One of the CPA's most distinctive features is the **universal opt-out mechanism (UOOM)** requirement. As of **July 1, 2024**, controllers must recognize and honor opt-out signals sent through technology platforms (such as browser settings or extensions) that communicate a consumer's choice to opt out.

### AG Rules on Universal Opt-Out

The Colorado AG's rules (4 CCR 904-3, Rule 5) provide detailed specifications:

**Technical Requirements for a Universal Opt-Out Mechanism:**

- Must be a user-selected, platform-level setting or browser-based signal
- Must clearly represent the consumer's affirmative, freely given, and unambiguous choice to opt out of the processing of personal data for targeted advertising and/or the sale of personal data
- Must be designed so that it is not the default setting but rather requires the consumer to affirmatively make a choice
- Must be easy to use, functional, and provided at no cost to the consumer
- Must not unfairly disadvantage another controller
- Must not make use of a financial incentive for its adoption

**Controller Obligations When Receiving UOOM Signals:**

- Must treat a UOOM signal as a valid opt-out request for both targeted advertising and the sale of personal data
- Must process the opt-out request without requiring the consumer to take additional steps (no verification requirements for opt-out)
- Must not require consumers to verify their identity solely to process an opt-out request via UOOM
- May choose to apply the opt-out only to the specific browser or device from which the signal originates, OR to the consumer's account more broadly
- Must not interpret the absence of a UOOM signal as consent to targeted advertising or the sale of personal data

**Recognized Mechanisms:**

The AG has recognized the **Global Privacy Control (GPC)** signal (as defined at globalprivacycontrol.org) as a valid universal opt-out mechanism. Other mechanisms may also qualify if they meet the AG's technical specifications.

### Practical Implementation

For web applications:
- Detect the `Sec-GPC` HTTP header or `navigator.globalPrivacyControl` JavaScript property
- When the GPC signal is detected (value of `1` or `true`), treat this as an opt-out of targeted advertising and sale of personal data
- Do not load third-party advertising trackers or analytics that facilitate targeted advertising when the GPC signal is present
- Document your response to UOOM signals in your privacy notice

---

## 8. Controller Obligations

Controllers bear the primary compliance obligations under the CPA.

### 8.1 Privacy Notice

Controllers must provide consumers with a reasonably accessible, clear, and meaningful privacy notice that includes:

| Element | Description |
|---|---|
| Categories of personal data | The categories of personal data collected or processed |
| Purposes of processing | The purposes for which each category of personal data is processed |
| Consumer rights | How consumers may exercise their rights, including the right to appeal |
| Categories shared with third parties | The categories of personal data shared with third parties, if any |
| Categories of third parties | The categories of third parties with whom data is shared |
| Contact information | How consumers may contact the controller, including a method to submit requests |
| Sale and targeted advertising disclosure | Whether the controller sells personal data or processes it for targeted advertising, and how consumers may opt out |

### 8.2 Purpose Limitation

Controllers must:

- Specify the express purposes for which personal data is collected and processed
- Not process personal data for purposes that are not reasonably necessary to or compatible with the disclosed purposes, unless they obtain the consumer's consent
- Collect only personal data that is adequate, relevant, and limited to what is reasonably necessary for the disclosed purposes (**data minimization**)

### 8.3 Security

Controllers must establish, implement, and maintain reasonable administrative, technical, and physical data security practices to protect the confidentiality, integrity, and accessibility of personal data. These practices must be appropriate to the volume, scope, and nature of the data processed and the business.

### 8.4 Non-Discrimination

Controllers must not process personal data in violation of state or federal laws that prohibit unlawful discrimination against consumers. Controllers must not discriminate against a consumer for exercising any of their rights under the CPA.

### 8.5 Consent for Material Changes

If a controller wishes to process personal data for purposes that are not reasonably necessary to or compatible with the originally disclosed purposes, the controller must provide the consumer with notice and obtain consent before processing the data for the new purpose.

### 8.6 Avoiding Dark Patterns

The CPA and AG rules prohibit controllers from obtaining consent through the use of **dark patterns** -- user interfaces designed or manipulated to substantially subvert or impair user autonomy, decision-making, or choice. Any consent obtained through dark patterns is not valid consent under the CPA.

Specific dark pattern prohibitions include:
- Presenting choices in a way that impairs the ability to make a choice
- Using confusing language or design that steers consumers toward a particular option
- Making it substantially more difficult to exercise opt-out rights than to opt in
- Repeated prompting to override a consumer's opt-out choice

---

## 9. Processor Obligations

### 9.1 Contractual Requirements

A processor must adhere to a controller's instructions and must assist the controller in meeting its CPA obligations. The processing relationship must be governed by a **contract** (often called a Data Processing Agreement or DPA) that includes:

| Contract Element | Description |
|---|---|
| Clear instructions | Clear instructions for processing personal data, including the nature and purpose of processing, the type of data, and the duration |
| Duty of confidentiality | A duty of confidentiality on persons processing the data |
| Subprocessor requirements | Requirements that the processor engage subprocessors only with a written contract requiring compliance with the same obligations |
| Deletion or return | At the controller's direction, the processor must delete or return all personal data upon the end of the provision of services |
| Audit rights | Make available to the controller, on request, all information necessary to demonstrate compliance |
| Cooperation | Cooperate with reasonable assessments by the controller or the controller's designated assessor |

### 9.2 Data Security

Processors must implement appropriate technical and organizational measures to ensure a level of security appropriate to the risk of processing, including:

- Encryption of personal data where appropriate
- Access controls limiting who can process the data
- Incident response and breach notification procedures
- Regular testing and evaluation of security measures

### 9.3 Subprocessor Management

If a processor engages a subprocessor, the processor must:

- Enter into a written contract with the subprocessor requiring compliance with the same data protection obligations
- Remain liable to the controller for the subprocessor's performance of obligations
- Provide the controller with notice of any intended changes in subprocessors, giving the controller an opportunity to object

---

## 10. Data Protection Assessments

### When Required

Controllers must conduct and document **data protection assessments (DPAs)** for each of the following processing activities:

1. **Processing personal data for targeted advertising**
2. **Sale of personal data**
3. **Processing personal data for profiling** where profiling presents a reasonably foreseeable risk of:
   - Unfair or deceptive treatment of, or unlawful disparate impact on, consumers
   - Financial, physical, or reputational injury to consumers
   - Physical or other intrusion upon the solitude or seclusion of consumers
   - Other substantial injury to consumers
4. **Processing sensitive data**
5. **Any processing activity that presents a heightened risk of harm to consumers**

### Assessment Content

Each data protection assessment must include, at minimum:

| Element | Description |
|---|---|
| Description of processing | The types of personal data processed, the purposes, and the categories of recipients |
| Necessity and proportionality | An assessment of whether the processing is necessary and proportionate to the stated purposes |
| Benefits vs. risks | Identification of the benefits of the processing to the controller, the consumer, other stakeholders, and the public, weighed against the potential risks to the rights of the consumer |
| Safeguards | The safeguards employed by the controller to address the identified risks, including security measures, data minimization, and de-identification techniques |
| Consumer expectations | Whether the processing is consistent with consumer expectations |

### AG Access to Assessments

The Colorado Attorney General may request data protection assessments in the context of an investigation. The assessments are confidential and exempt from public inspection and copying under the Colorado Open Records Act (CORA). The disclosure of a DPA to the AG does not constitute a waiver of attorney-client privilege or work product protection.

### AG Rule Details

The AG rules further specify:

- Assessments must be conducted **before** initiating the relevant processing activity, or as soon as reasonably practicable for processing already underway as of the effective date
- Assessments must be updated when there is a material change in the processing activity
- Controllers should retain assessments for at least **three years** after the processing ends
- A single assessment may address a comparable set of processing activities that present similar risks

---

## 11. Sensitive Data Handling

### Consent Requirement

The CPA requires that controllers obtain **consent** before processing **sensitive data**. This is an opt-in requirement -- controllers cannot process sensitive data unless the consumer has affirmatively consented.

### Categories of Sensitive Data

As defined in Section 5 above, sensitive data includes:

- Racial or ethnic origin
- Religious beliefs
- Mental or physical health condition or diagnosis
- Sex life or sexual orientation
- Citizenship or immigration status
- Genetic data (processed to uniquely identify an individual)
- Biometric data (processed to uniquely identify an individual)
- Personal data of a known child (under 13)

### Consent Standards for Sensitive Data

Per the AG rules and statute:

- Consent must be **freely given, specific, informed, and unambiguous**
- The consent request must clearly describe the sensitive data categories to be processed and the purposes of processing
- Consent must be obtained through an affirmative act (opt-in) -- pre-checked boxes or silence do not constitute consent
- For children's data (under 13), consent must be obtained from the parent or legal guardian, consistent with COPPA requirements
- Controllers must provide an effective mechanism for consumers to revoke consent, and processing must cease within a reasonable period after revocation

### Application to Software

For application developers, sensitive data handling requires:

- Identifying all data fields that may qualify as sensitive data
- Implementing consent collection mechanisms before processing sensitive data
- Storing and auditing consent records
- Providing functionality to revoke consent
- Implementing technical controls to prevent processing of sensitive data without valid consent

---

## 12. Penalties and Enforcement

### Enforcement as a CCPA Violation

Violations of the CPA are enforced as violations of the **Colorado Consumer Protection Act (C.R.S. Section 6-1-101 et seq.)**. This means the AG has the full range of enforcement tools available under Colorado consumer protection law.

### Penalties

| Penalty Type | Amount |
|---|---|
| Civil penalty per violation | Up to **$20,000** per violation |
| CCPA deceptive trade practice penalty | Up to **$20,000** per violation (may stack) |
| Injunctive relief | Courts may order controllers/processors to cease violating conduct |
| Restitution | Courts may order restitution to affected consumers |
| Attorney's fees and costs | The AG may recover reasonable costs of investigation and prosecution |

**Note:** Because each affected consumer may constitute a separate violation, penalties can scale rapidly. Processing personal data of thousands of consumers without proper safeguards could result in penalties in the millions of dollars.

### No Private Right of Action

Consumers cannot bring private lawsuits under the CPA. Enforcement is limited to:

- The Colorado Attorney General
- Colorado District Attorneys

### Cure Period Status

| Period | Status |
|---|---|
| July 1, 2023 -- December 31, 2024 | 60-day cure period (mandatory for AG to provide notice and opportunity to cure before enforcement) |
| January 1, 2025 onward | Cure period expired; AG has **discretion** to provide an opportunity to cure but is not required to do so |

### Factors Likely to Influence Enforcement

While the AG has not published formal enforcement priorities, the following factors are commonly considered relevant:

- The number of consumers affected
- The nature and severity of the violation
- Whether the controller acted willfully or negligently
- The controller's history of compliance or violations
- Whether the controller cooperated with the AG's investigation
- The controller's efforts to cure the violation after discovery
- Whether the controller has a reasonable privacy program in place

---

## 13. Application to Software and Applications

### Software as a Data Processing Tool

Software applications are central to CPA compliance because they are typically the primary means through which personal data is collected, processed, stored, and shared. Application developers and operators must consider CPA requirements throughout the software development lifecycle.

### Key Technical Compliance Considerations

#### Data Collection and Minimization

- Applications must collect only personal data that is adequate, relevant, and limited to what is reasonably necessary for disclosed purposes
- Review all data input forms, API endpoints, and data collection mechanisms to ensure they align with stated purposes
- Avoid collecting data "just in case" -- each data field should map to a specific, disclosed purpose

#### Consent Management

- Implement consent collection mechanisms that meet the CPA's definition of consent (freely given, specific, informed, unambiguous, affirmative act)
- Provide granular consent options for sensitive data categories
- Store consent records with timestamps, version of privacy notice presented, and the specific consent choices made
- Implement functionality to revoke consent and cease processing upon revocation

#### Consumer Rights Fulfillment

- Build or integrate mechanisms to receive, verify, and respond to consumer rights requests (access, correction, deletion, portability, opt-out)
- Implement data export functionality that produces data in a portable, machine-readable format (e.g., JSON, CSV)
- Implement data deletion functionality that can remove a consumer's data from primary datastores and direct processors to do the same
- Implement data correction functionality that allows modification of consumer records
- Build an appeals process for denied requests

#### Universal Opt-Out Mechanism Detection

- Detect and honor Global Privacy Control (GPC) signals in web applications
- Implement server-side detection of the `Sec-GPC` HTTP header
- Implement client-side detection of the `navigator.globalPrivacyControl` property
- Suppress third-party tracking, targeted advertising, and data sale activities when opt-out signals are detected

#### Data Security

- Implement encryption at rest and in transit
- Implement role-based access controls
- Implement audit logging for access to personal data
- Implement secure authentication and session management
- Conduct regular security testing (penetration testing, vulnerability scanning)
- Implement incident response procedures

#### Third-Party Integrations

- Audit all third-party SDKs, APIs, and services for data processing practices
- Ensure third-party processors have appropriate DPAs in place
- Implement controls to prevent unauthorized data sharing with third parties
- Review analytics, advertising, and marketing integrations for compliance with opt-out requirements

---

## 14. Mendix and Low-Code Platform Considerations

### Shared Responsibility Model

When building applications on Mendix or other low-code platforms, CPA compliance responsibilities are shared between the platform provider and the application developer/operator:

| Responsibility | Platform Provider (e.g., Mendix/Siemens) | Application Developer/Operator |
|---|---|---|
| Infrastructure security | Primary | Oversight |
| Platform-level encryption | Primary | Configuration |
| Application data model design | Guidance | **Primary** |
| Data collection logic | Framework | **Primary** |
| Consent management | Optional marketplace modules | **Primary** |
| Privacy notice | N/A | **Primary** |
| Consumer rights request handling | Framework capabilities | **Primary** |
| Third-party integration compliance | Platform-level controls | **Primary** |
| Data protection assessments | Platform DPA available | **Primary** |
| UOOM detection/response | May provide modules | **Primary** |

### Mendix-Specific Implementation Guidance

#### Data Model Design

- Design entity models with privacy in mind: clearly identify which entities and attributes contain personal data
- Use Mendix's entity access rules to implement role-based access controls on personal data
- Consider creating a dedicated "Personal Data" module that centralizes personal data entities for easier management
- Implement data classification attributes (e.g., an enumeration for data sensitivity level)

#### Consent Management Implementation

- Build or adopt a consent management microflow/module that:
  - Presents clear consent requests before collecting sensitive data
  - Records consent with timestamp, purpose, and version
  - Provides a mechanism to withdraw consent
  - Prevents processing of sensitive data without valid consent
- Use Mendix's before-commit/after-commit event handlers to enforce consent checks

#### Consumer Rights Request Handling

- Implement a consumer rights request workflow using Mendix workflows or microflows:
  - **Access requests**: Build a microflow that retrieves all personal data associated with a consumer and exports it as JSON or CSV
  - **Deletion requests**: Build a microflow that identifies and deletes (or anonymizes) all personal data across related entities, respecting referential integrity
  - **Correction requests**: Build interfaces that allow authorized users to update consumer records
  - **Portability requests**: Leverage Mendix's export-to-Excel or REST API capabilities to provide data in machine-readable format
  - **Opt-out requests**: Build an opt-out preference store and integrate it with marketing/advertising logic

#### Audit and Logging

- Use Mendix's audit trail module or build custom audit logging for:
  - Access to personal data entities
  - Modifications to personal data
  - Consent changes
  - Consumer rights request processing
  - Data exports and deletions
- Retain audit logs for a period consistent with your data protection assessment documentation (minimum three years recommended)

#### Third-Party Marketplace Modules

- Audit all Mendix Marketplace modules used in your application for data processing behavior
- Ensure any module that processes personal data has appropriate documentation and DPA provisions
- Be cautious with modules that send data to external services (analytics, email, etc.)

#### Deployment Considerations

- If deploying on Mendix Cloud, review Siemens/Mendix's DPA and security documentation
- If deploying on private cloud or on-premises, ensure your infrastructure meets CPA security requirements
- Document the data processing chain: application -> platform -> infrastructure -> subprocessors
- Ensure data residency requirements are met if applicable

#### Mendix Security Best Practices for CPA

- Enable and enforce HTTPS/TLS for all application traffic
- Configure Mendix project security to Production level
- Implement proper user role definitions with least-privilege access to personal data
- Enable database encryption at rest (platform/infrastructure level)
- Use Mendix's built-in password hashing (bcrypt) for authentication
- Implement session timeout policies
- Regularly update the Mendix runtime to incorporate security patches

---

## 15. Compliance Checklist for Application Developers

Use this checklist to assess and track CPA compliance for your applications:

### Data Inventory and Mapping

- [ ] Conduct a comprehensive data inventory identifying all personal data collected, processed, and stored
- [ ] Map data flows from collection to storage, processing, sharing, and deletion
- [ ] Classify data by sensitivity level (personal data vs. sensitive data)
- [ ] Identify all third parties with whom personal data is shared
- [ ] Document the legal basis for each processing activity
- [ ] Determine if applicability thresholds are met (100K consumers or 25K + revenue from data sales)

### Privacy Notice

- [ ] Publish a clear, accessible privacy notice
- [ ] Disclose all categories of personal data collected
- [ ] Disclose all purposes of processing
- [ ] Disclose categories of third parties with whom data is shared
- [ ] Describe consumer rights and how to exercise them
- [ ] Disclose whether data is sold or used for targeted advertising
- [ ] Describe the appeals process for denied requests
- [ ] Include information about universal opt-out mechanisms recognized

### Consumer Rights

- [ ] Implement mechanism to receive consumer rights requests (web form, email, or other accessible method)
- [ ] Implement identity verification for rights requests (without creating excessive barriers)
- [ ] Implement data access/export functionality (portable, machine-readable format)
- [ ] Implement data correction functionality
- [ ] Implement data deletion functionality (including directing processors to delete)
- [ ] Implement opt-out mechanisms for targeted advertising, sale, and profiling
- [ ] Implement an appeals process with clear instructions
- [ ] Ensure response within 45-day timeline (with 45-day extension if needed with notice)
- [ ] Provide AG contact information when appeals are denied

### Universal Opt-Out Mechanism

- [ ] Detect and honor Global Privacy Control (GPC) signals
- [ ] Implement server-side `Sec-GPC` header detection
- [ ] Implement client-side `navigator.globalPrivacyControl` detection
- [ ] Suppress targeted advertising and data sale when UOOM signal detected
- [ ] Document UOOM recognition in privacy notice
- [ ] Do not require additional verification for UOOM-based opt-outs

### Consent Management

- [ ] Implement opt-in consent collection for sensitive data
- [ ] Ensure consent is freely given, specific, informed, and unambiguous
- [ ] Avoid dark patterns in consent interfaces
- [ ] Record consent with timestamps, purpose, and privacy notice version
- [ ] Implement consent revocation mechanism
- [ ] Cease processing upon consent revocation within reasonable timeframe

### Data Protection Assessments

- [ ] Identify processing activities requiring DPAs (targeted advertising, sale, profiling, sensitive data, high-risk processing)
- [ ] Conduct DPAs before initiating relevant processing activities
- [ ] Document necessity, proportionality, benefits, risks, and safeguards
- [ ] Update DPAs when processing activities materially change
- [ ] Retain DPAs for at least three years after processing ends

### Data Security

- [ ] Implement encryption at rest and in transit
- [ ] Implement role-based access controls
- [ ] Implement audit logging for personal data access and modifications
- [ ] Implement secure authentication and session management
- [ ] Conduct regular security assessments and penetration testing
- [ ] Establish and test incident response procedures
- [ ] Implement data breach notification processes

### Processor Management

- [ ] Execute DPAs with all processors handling personal data
- [ ] Ensure DPAs include all required contractual elements (instructions, confidentiality, subprocessor requirements, deletion/return, audit rights)
- [ ] Monitor processor compliance
- [ ] Maintain a register of all processors and subprocessors
- [ ] Review and update DPAs periodically

### Organizational Measures

- [ ] Train employees on CPA requirements and data handling procedures
- [ ] Designate a privacy point of contact
- [ ] Establish internal policies for data handling, retention, and disposal
- [ ] Implement a data retention schedule and delete data when no longer necessary
- [ ] Document compliance activities and decisions
- [ ] Conduct periodic compliance audits

---

## 16. Comparison with CCPA and GDPR

### Overview Comparison

| Feature | CPA (Colorado) | CCPA/CPRA (California) | GDPR (EU) |
|---|---|---|---|
| **Effective date** | July 1, 2023 | Jan 1, 2020 (CCPA) / Jan 1, 2023 (CPRA) | May 25, 2018 |
| **Scope** | Businesses in CO or targeting CO residents | Businesses meeting CA thresholds | Any entity processing EU residents' data |
| **Revenue threshold** | None | $25M gross annual revenue (one of three triggers) | None |
| **Consumer volume threshold** | 100K consumers OR 25K + data sale revenue | 100K consumers/households (one of three triggers) | No volume threshold |
| **Data sale volume threshold** | 25K consumers + revenue from sale | 50% of revenue from selling data (one of three triggers) | N/A (legitimate interest or consent) |
| **Private right of action** | No | Limited (data breaches only) | Yes (comprehensive) |
| **Enforcement** | AG and District Attorneys | AG, CPPA, limited private | Supervisory authorities, private actions |
| **Cure period** | 60 days (expired Jan 1, 2025) | 30 days (expired under CPRA) | None |
| **Sensitive data approach** | Opt-in consent required | Opt-out (right to limit use) under CPRA | Opt-in consent or other Art. 9 basis |
| **Universal opt-out mechanism** | Required (July 1, 2024) | Required (CPRA regulations) | Not specifically required (but consent withdrawal right) |
| **Data protection assessments** | Required | Required (CPRA risk assessments) | Required (DPIAs for high-risk processing) |
| **Right to access** | Yes | Yes | Yes |
| **Right to delete** | Yes | Yes | Yes (right to erasure) |
| **Right to correct** | Yes | Yes (CPRA) | Yes (right to rectification) |
| **Right to portability** | Yes | Yes | Yes |
| **Right to opt out of sale** | Yes | Yes | N/A (consent basis) |
| **Right to opt out of targeted ads** | Yes | Yes (CPRA) | Not explicit (consent/legitimate interest) |
| **Right to opt out of profiling** | Yes (legal/significant effects) | Yes (CPRA, automated decision-making) | Yes (Art. 22, automated decisions with legal effects) |
| **Right to appeal** | Yes (explicit requirement) | No explicit appeal (but AG complaint) | Right to lodge complaint with supervisory authority |
| **Penalties (per violation)** | Up to $20,000 | $2,500 / $7,500 (intentional) | Up to 4% global revenue or EUR 20M |
| **Dark patterns prohibition** | Explicit | Explicit (CPRA) | Implicit (consent requirements) |

### Key Differences to Note

**CPA vs. CCPA/CPRA:**

- The CPA has **no revenue threshold** -- smaller businesses may be covered if they meet the consumer volume thresholds
- The CPA requires **opt-in consent** for sensitive data, whereas the CCPA/CPRA uses an **opt-out** model for sensitive personal information
- The CPA has a more explicit **appeals process requirement**
- The CPA has **no private right of action** at all, whereas the CCPA allows private actions for data breaches
- The CPA's penalty structure can result in **higher per-violation fines** ($20,000 vs. $2,500/$7,500)
- Both require universal opt-out mechanism recognition

**CPA vs. GDPR:**

- The CPA is **narrower in scope** -- it applies only to Colorado consumers (residents in individual/household context), whereas the GDPR applies to all EU data subjects
- The GDPR has a **broader set of legal bases** for processing (consent, legitimate interest, contract, legal obligation, vital interest, public task), whereas the CPA primarily relies on consent and purpose limitation
- The GDPR's **penalty structure is significantly larger** (up to 4% of global annual revenue)
- The GDPR provides a **comprehensive private right of action**, whereas the CPA has none
- Both require opt-in consent for sensitive data
- Both require data protection assessments for high-risk processing

### Multi-Jurisdiction Compliance Strategy

For organizations that must comply with multiple privacy laws, consider implementing a unified privacy framework that meets the highest standard across all applicable jurisdictions:

1. **Default to opt-in consent** for sensitive data (meets CPA, GDPR, and most other frameworks)
2. **Implement universal opt-out mechanism detection** (meets CPA and CPRA)
3. **Conduct data protection assessments** for all high-risk processing (meets all three)
4. **Provide all consumer rights** across the board (access, correction, deletion, portability, opt-out)
5. **Implement a comprehensive privacy notice** that addresses all jurisdictional requirements
6. **Use the shortest response timelines** -- 30 days (GDPR) rather than 45 days (CPA)
7. **Execute robust DPAs** with all processors that satisfy all applicable requirements

---

## 17. Additional Resources

### Official Sources

- **Colorado Privacy Act Statute**: C.R.S. Title 6, Article 1, Part 13 (SB 21-190)
- **Colorado AG CPA Rules**: 4 CCR 904-3 (Rules Regarding the Colorado Privacy Act)
- **Colorado Attorney General's Office**: [coag.gov/resources/colorado-privacy-act](https://coag.gov/resources/colorado-privacy-act/)
- **Global Privacy Control Specification**: [globalprivacycontrol.org](https://globalprivacycontrol.org/)

### Industry Guidance

- **IAPP (International Association of Privacy Professionals)**: Comparison charts and analysis of U.S. state privacy laws
- **NIST Privacy Framework**: Voluntary framework for managing privacy risk
- **OWASP Privacy Guidelines**: Technical guidance for privacy in application development

### Mendix-Specific Resources

- **Mendix Security Documentation**: Platform security features and configuration guidance
- **Siemens/Mendix DPA**: Data Processing Agreement for Mendix Cloud deployments
- **Mendix Marketplace**: Privacy and consent management modules

---

## Disclaimer

This document is provided for informational purposes only and does not constitute legal advice. Organizations should consult with qualified legal counsel to determine the specific applicability of the Colorado Privacy Act to their operations and to develop a compliance strategy tailored to their circumstances. Privacy laws are subject to amendment, rulemaking, and interpretive guidance that may affect the information presented herein. Always refer to the current statutory text and AG rules for the most authoritative and up-to-date requirements.

---

*Prepared for enterprise customers and application development teams. This document should be reviewed and updated periodically as the regulatory landscape evolves.*
