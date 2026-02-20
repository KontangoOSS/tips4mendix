# Export Administration Regulations (EAR) Compliance Guide

## Purpose

This document provides a comprehensive overview of the U.S. Export Administration Regulations (EAR) as they apply to software development, cloud-hosted applications, and low-code/no-code platforms such as Mendix. It is intended for engineering teams, compliance officers, and enterprise stakeholders who need to understand their obligations under U.S. export control law.

This is not legal advice. Organizations should consult qualified export control counsel for compliance decisions specific to their products and operations.

---

## Table of Contents

1. [What EAR Is and Its Legal Basis](#1-what-ear-is-and-its-legal-basis)
2. [Who Enforces EAR](#2-who-enforces-ear)
3. [What EAR Covers](#3-what-ear-covers)
4. [ECCN Classification System](#4-eccn-classification-system)
5. [Who Must Comply](#5-who-must-comply)
6. [Key Compliance Requirements](#6-key-compliance-requirements)
7. [Restricted Party Screening](#7-restricted-party-screening)
8. [Penalties for Non-Compliance](#8-penalties-for-non-compliance)
9. [Software and Technology-Specific Controls](#9-software-and-technology-specific-controls)
10. [Mendix and Low-Code Platform Considerations](#10-mendix-and-low-code-platform-considerations)
11. [Compliance Checklist for Application Developers](#11-compliance-checklist-for-application-developers)
12. [EAR vs. ITAR: Key Differences](#12-ear-vs-itar-key-differences)
13. [References and Resources](#13-references-and-resources)

---

## 1. What EAR Is and Its Legal Basis

The **Export Administration Regulations (EAR)** are a set of U.S. federal regulations found in **Title 15 of the Code of Federal Regulations (CFR), Parts 730-774**. They govern the export, re-export, and in-country transfer of commercial and dual-use items, technology, and software from the United States.

### Legal Foundation

The EAR derives its authority from several statutes:

| Statute | Role |
|---|---|
| **Export Control Reform Act of 2018 (ECRA)** | The primary legal authority. Part of the John S. McCain National Defense Authorization Act for Fiscal Year 2019. ECRA made permanent the export control authorities that had previously relied on temporary extensions under the International Emergency Economic Powers Act (IEEPA). It codified the Bureau of Industry and Security's mandate and established the framework for controlling "emerging and foundational technologies." |
| **International Emergency Economic Powers Act (IEEPA)** | Provides the President with authority to regulate commerce during national emergencies. Historically served as the legal basis for EAR before ECRA was enacted. Still relevant for certain sanctions-related controls. |
| **Export Administration Act of 1979 (EAA)** | The original statute authorizing export controls on dual-use goods. Lapsed multiple times and was ultimately superseded by ECRA, but its regulatory framework (the EAR itself) was preserved. |

### Core Policy Objectives

The EAR exists to advance three national security and foreign policy objectives:

1. **National security** -- Preventing adversaries from acquiring technologies that would provide a military or intelligence advantage.
2. **Foreign policy** -- Supporting U.S. foreign policy goals, including human rights, anti-terrorism, and regional stability.
3. **Short supply** -- Preventing the export of commodities in short domestic supply (rarely invoked in practice).

---

## 2. Who Enforces EAR

### Bureau of Industry and Security (BIS)

The **Bureau of Industry and Security (BIS)**, a division of the **U.S. Department of Commerce**, is the primary agency responsible for administering and enforcing the EAR. BIS has two key operational components:

| Division | Function |
|---|---|
| **Export Administration (EA)** | Processes license applications, issues advisory opinions, develops and maintains the Commerce Control List (CCL), and publishes regulatory guidance. |
| **Export Enforcement (EE)** | Investigates violations, conducts end-use checks (pre-license checks and post-shipment verifications), and coordinates enforcement actions. Includes the Office of Export Enforcement (OEE) and the Office of Antiboycott Compliance. |

### Other Agencies Involved

While BIS is the primary authority for EAR, other agencies participate in export control:

| Agency | Role |
|---|---|
| **Department of State / DDTC** | Administers ITAR (International Traffic in Arms Regulations) for defense articles. Jurisdiction overlaps with EAR in some areas. |
| **Department of the Treasury / OFAC** | Administers economic sanctions and embargoes. OFAC's Specially Designated Nationals (SDN) list intersects with EAR restricted party lists. |
| **Department of Energy** | Controls nuclear-related technology and materials. |
| **Nuclear Regulatory Commission** | Controls certain nuclear equipment and materials. |
| **Department of Defense** | Reviews license applications for items with military applications. |

### Interagency Review

License applications for controlled items frequently undergo interagency review. BIS chairs this process, but the Departments of State, Defense, and Energy may have review authority depending on the item and destination.

---

## 3. What EAR Covers

### Scope of Control

The EAR applies to a broad range of items, including:

- **Commodities** -- Physical goods, hardware, equipment, and materials.
- **Software** -- Executable code, source code, and object code, regardless of delivery medium.
- **Technology** -- Technical data, know-how, technical assistance, and information necessary for the development, production, or use of a commodity or software.

### The Commerce Control List (CCL)

The **Commerce Control List (CCL)** is found in **Supplement No. 1 to Part 774 of the EAR**. It organizes controlled items into ten categories:

| Category | Description |
|---|---|
| **0** | Nuclear Materials, Facilities, and Equipment (and Miscellaneous Items) |
| **1** | Special Materials and Related Equipment, Chemicals, Microorganisms, and Toxins |
| **2** | Materials Processing |
| **3** | Electronics |
| **4** | Computers |
| **5 (Part 1)** | Telecommunications |
| **5 (Part 2)** | Information Security (encryption) |
| **6** | Sensors and Lasers |
| **7** | Navigation and Avionics |
| **8** | Marine |
| **9** | Aerospace and Propulsion |

Each category contains five product groups:

| Group | Code | Description |
|---|---|---|
| Equipment, Assemblies, and Components | A | Physical hardware |
| Test, Inspection, and Production Equipment | B | Manufacturing and test equipment |
| Materials | C | Raw and processed materials |
| Software | D | Software specifically designed or modified for items in the category |
| Technology | E | Technical data and know-how related to items in the category |

### EAR99

Items that are **subject to the EAR** but **not listed on the CCL** fall under the designation **EAR99**. This is the classification for the vast majority of commercial products. EAR99 items generally do not require an export license, except when:

- The destination is a comprehensively embargoed or sanctioned country (e.g., Cuba, Iran, North Korea, Syria, the Crimea/Donetsk/Luhansk regions of Ukraine).
- The end-user appears on a restricted party list.
- The exporter knows or has reason to know the item will be used in a prohibited end-use (e.g., weapons of mass destruction).

### Items NOT Subject to the EAR

Certain items fall outside EAR jurisdiction entirely:

- Items controlled by another U.S. government agency (e.g., ITAR-controlled defense articles, NRC-controlled nuclear materials).
- Published information and publicly available software and technology (with specific criteria defined in EAR Part 734.7-734.11).
- Fundamental research performed at accredited institutions (as defined in EAR Part 734.8).

---

## 4. ECCN Classification System

### What is an ECCN?

An **Export Control Classification Number (ECCN)** is a five-character alphanumeric code that identifies items on the Commerce Control List and specifies the reasons for control, licensing requirements, and applicable license exceptions.

### ECCN Format

An ECCN follows this structure: **[Category][Product Group][Serial Number]**

Example: **5D002**

| Component | Value | Meaning |
|---|---|---|
| Category | 5 | Telecommunications and Information Security |
| Product Group | D | Software |
| Serial Number | 002 | Specific control entry (in this case: encryption software) |

### Reasons for Control

Each ECCN entry specifies one or more **Reasons for Control** that determine when a license is required. Common reasons include:

| Code | Reason for Control |
|---|---|
| **NS** | National Security |
| **MT** | Missile Technology |
| **NP** | Nuclear Nonproliferation |
| **CB** | Chemical and Biological Weapons |
| **CC** | Crime Control |
| **RS** | Regional Stability |
| **AT** | Anti-Terrorism |
| **UN** | United Nations Sanctions |
| **SI** | Significant Items |
| **SL** | Surreptitious Listening |
| **EI** | Encrypted Items |

### How Classification Works

There are three ways to determine an item's ECCN:

1. **Self-classification** -- The exporter reviews the CCL and determines the correct ECCN based on the technical parameters of the item. This is the most common method and is the exporter's responsibility.

2. **Commodity Classification Request (CLASSING)** -- The exporter submits a formal request to BIS for an official classification. BIS responds with a **Commodity Classification Automated Tracking System (CCATS)** number. This is binding and can be relied upon for compliance.

3. **Manufacturer or developer classification** -- The original manufacturer may provide an ECCN, but the exporter remains responsible for verifying its accuracy.

### The Commerce Country Chart

**Supplement No. 1 to Part 738** contains the **Commerce Country Chart**, which cross-references the Reason for Control with the destination country to determine whether a license is required. If the intersection of the Reason for Control and destination country contains an "X," a license is required (unless a license exception applies).

---

## 5. Who Must Comply

### U.S. Persons

Any **U.S. person** involved in an export, re-export, or in-country transfer of items subject to the EAR must comply. "U.S. person" includes:

- U.S. citizens and permanent residents, regardless of where they are located.
- Entities organized under U.S. law, including their foreign branches.
- Any person physically present in the United States.

### Non-U.S. Persons

Non-U.S. persons must comply with the EAR when:

- They re-export U.S.-origin items from one foreign country to another.
- They export foreign-made items that incorporate more than a *de minimis* amount of controlled U.S.-origin content (generally 25%, or 10% for items destined to embargoed countries).
- They export foreign-made items that are the **direct product** of certain U.S.-origin technology or software.
- They are involved in activities that trigger the EAR's end-use and end-user controls (Part 744).

### Specific Entities That Must Comply

| Entity Type | How EAR Applies |
|---|---|
| **U.S.-based software companies** | All exports of software and technology, including downloads, cloud access, and technical support provided to foreign persons. |
| **Cloud service providers** | Providing access to controlled technology via cloud infrastructure may constitute an export or a deemed export. |
| **Employers of foreign nationals** | Releasing controlled technology to a foreign national employee in the U.S. is a "deemed export" to that person's home country. |
| **Universities and research institutions** | Fundamental research exclusion applies, but sponsored/proprietary research and controlled equipment are still subject to the EAR. |
| **Foreign subsidiaries of U.S. companies** | Must comply with re-export controls. Items received from the U.S. parent retain their EAR classification. |
| **Distributors and resellers** | Responsible for ensuring compliance when they export or re-export EAR-controlled items. |

---

## 6. Key Compliance Requirements

### 6.1 Export Licensing

When the Commerce Country Chart indicates a license is required for a particular ECCN/destination combination, and no license exception applies, the exporter must apply to BIS for a license before the export, re-export, or transfer can take place.

**License application process:**

1. Determine the item's ECCN (or confirm it is EAR99).
2. Check the Commerce Country Chart for license requirements based on the Reason for Control and destination.
3. Evaluate whether any **license exception** applies (see Part 740 of the EAR).
4. If no exception applies, submit a license application through BIS's **Simplified Network Application Process Redesign (SNAP-R)** system.
5. BIS review typically takes 30-60 days but can be longer for interagency review items.

**License review policies:**

| Policy | Meaning |
|---|---|
| **Case-by-case** | BIS reviews the specific facts of the transaction. |
| **Presumption of approval** | License is likely to be granted absent adverse factors. |
| **Presumption of denial** | License is unlikely to be granted. Applied to embargoed destinations and certain end-users. |

### 6.2 License Exceptions

The EAR provides several **license exceptions** (Part 740) that permit exports without a specific license, provided all conditions of the exception are met. Key license exceptions for software companies include:

| Exception | Code | Description |
|---|---|---|
| **Technology and Software Unrestricted (TSU)** | TSU | Permits export of publicly available technology and software (e.g., published source code, mass-market software). |
| **Encryption Commodities, Software, and Technology (ENC)** | ENC | Permits export of specified encryption items, subject to classification reporting and semi-annual self-classification reports. |
| **Temporary Imports, Exports, Re-exports, and Transfers (TMP)** | TMP | Covers items taken abroad temporarily (e.g., laptops). |
| **Governments and International Organizations (GOV)** | GOV | Exports to U.S. government agencies and personnel for official use. |
| **Additional Permissive Re-exports (APR)** | APR | Permits certain re-exports from Country Group A:1 countries. |

### 6.3 Restricted Party Screening

Before any export, re-export, or transfer, the exporter must screen all parties to the transaction against U.S. government restricted party lists. This is covered in detail in [Section 7](#7-restricted-party-screening).

### 6.4 Record-Keeping

**EAR Part 762** imposes record-keeping requirements:

- Exporters must retain records of all export transactions for **five years** from the date of export, re-export, or transfer (or from the date of the last license-related shipment, whichever is later).
- Records include: export documents, license applications and determinations, end-use certificates, technology control plans, screening results, and internal correspondence related to export decisions.
- Records must be produced within a reasonable time if requested by BIS for inspection.
- Destruction or alteration of records to prevent disclosure is a separate violation.

### 6.5 End-Use and End-User Controls

Even when an item is classified as EAR99 or otherwise does not require a license, the exporter has an obligation to evaluate the end-use and end-user. Under **Part 744**, a license may be required regardless of ECCN if the exporter **knows or has reason to know** that the item:

- Will be used in the design, development, production, or use of **nuclear, chemical, or biological weapons**.
- Will be used in the design, development, production, or use of **missiles** capable of delivering such weapons.
- Will be diverted to a **military end-use** or **military end-user** in certain countries (currently China, Russia, Venezuela, Burma/Myanmar, and others under EAR 744.21).
- Is destined for an end-user on a restricted party list.

This is commonly referred to as the **"know your customer"** obligation. Red flags that should trigger additional due diligence are described in **Supplement No. 3 to Part 732** ("Know Your Customer" Guidance and Red Flags).

### 6.6 Red Flags

BIS publishes specific indicators that should raise concern. Examples include:

- The customer is reluctant to provide information about the end-use or end-user.
- The product's capabilities do not match the buyer's line of business.
- The customer declines normal installation, training, or maintenance.
- Delivery dates or routes are inconsistent with the buyer's location.
- A freight forwarder is listed as the final destination.
- The customer is willing to pay cash for an expensive item that would normally be financed.
- The customer has little or no business background or reputation.
- The order is for quantities inconsistent with the customer's needs.

When red flags are present, the exporter must resolve them through due diligence or refrain from the transaction.

---

## 7. Restricted Party Screening

### Overview

The U.S. government maintains multiple lists of individuals, entities, and organizations that are subject to restrictions under U.S. export control and sanctions laws. Exporters must screen all parties to a transaction -- including end-users, consignees, intermediaries, and any other parties involved -- against these lists.

### Key Restricted Party Lists

| List | Administering Agency | What It Means |
|---|---|---|
| **Denied Persons List (DPL)** | BIS | Individuals and entities that have been denied export privileges. No items subject to the EAR may be exported, re-exported, or transferred to any party on this list without specific BIS authorization. |
| **Entity List** | BIS (Supplement No. 4 to Part 744) | Entities determined to be acting contrary to the national security or foreign policy interests of the United States. Specific license requirements and review policies are listed per entity. Some entries impose a "presumption of denial." |
| **Unverified List (UVL)** | BIS (Supplement No. 6 to Part 744) | Entities for which BIS has been unable to verify the bona fides (legitimacy and reliability) as an end-user in prior transactions. A UVL listing requires the exporter to obtain a **UVL statement** from the listed party before proceeding with certain transactions. |
| **Specially Designated Nationals (SDN) List** | OFAC (Treasury) | Individuals, entities, vessels, and aircraft owned or controlled by, or acting for or on behalf of, sanctioned countries, terrorist organizations, and narcotics traffickers. Assets are frozen, and U.S. persons are generally prohibited from dealing with SDN-listed parties. |
| **Military End User (MEU) List** | BIS (Supplement No. 7 to Part 744) | Entities in China, Russia, Venezuela, Burma/Myanmar, and other countries determined to be military end users. License required for items listed in Supplement No. 2 to Part 744. |
| **Sectoral Sanctions Identifications (SSI) List** | OFAC | Entities operating in sectors of certain countries' economies subject to sanctions. Specific types of transactions are prohibited. |
| **Non-SDN Chinese Military-Industrial Complex Companies List (NS-CMIC)** | OFAC | Chinese military-industrial complex companies subject to investment restrictions. |
| **Foreign Sanctions Evaders (FSE) List** | OFAC | Foreign individuals and entities determined to have violated or attempted to evade U.S. sanctions. |

### Consolidated Screening List

The **Consolidated Screening List (CSL)**, maintained by the International Trade Administration (trade.gov), aggregates multiple restricted party lists into a single searchable database. This is available at **https://www.trade.gov/consolidated-screening-list**.

The CSL includes lists from Commerce (BIS), Treasury (OFAC), and State (DDTC) and is a practical starting point for screening, though it should not be the only resource -- always cross-check against the primary lists maintained by each agency.

### Screening Best Practices

- Screen **all parties** to a transaction: end-user, consignee, intermediate consignee, purchaser, and any other involved party.
- Screen at **multiple points** in the transaction lifecycle: at order intake, before shipment/provisioning, and periodically for ongoing service relationships.
- Use **fuzzy matching** to account for transliteration variations, aliases, and alternate spellings.
- **Document all screening results**, including negative results (no matches), and retain records for five years.
- Re-screen existing customers whenever restricted party lists are updated (BIS publishes updates in the Federal Register).

---

## 8. Penalties for Non-Compliance

### Criminal Penalties

| Violation Type | Maximum Penalty |
|---|---|
| **Willful violation** | Up to **$1,000,000 per violation** and/or **up to 20 years imprisonment** per violation. |
| **Conspiracy** | Same penalties as the underlying violation. |

### Administrative (Civil) Penalties

| Violation Type | Maximum Penalty |
|---|---|
| **Per violation** | The greater of **$364,992** (adjusted for inflation annually) or **twice the value of the transaction**. |
| **Denial of export privileges** | BIS can deny an individual or entity the right to participate in any export transaction for a specified period, effectively barring them from international trade. |
| **Exclusion from practice** | Individuals can be barred from appearing before BIS. |

### Other Consequences

- **Seizure and forfeiture** of goods involved in violations.
- **Adverse publicity** -- BIS publishes enforcement actions, including settlements.
- **Debarment** from U.S. government contracts.
- **Loss of license exceptions** -- BIS can revoke an entity's eligibility to use license exceptions.
- **Reputational damage** -- Public enforcement actions and inclusion on the Denied Persons List can severely impact business relationships.

### Voluntary Self-Disclosure (VSD)

BIS strongly encourages **Voluntary Self-Disclosure** of violations. Under **Part 764.5**, entities that voluntarily disclose violations, cooperate with investigations, and implement corrective actions generally receive significantly reduced penalties. BIS has stated that VSD is a "mitigating factor of great weight." Failure to disclose a known violation is considered an aggravating factor.

---

## 9. Software and Technology-Specific Controls

### 9.1 Encryption Controls

Encryption is one of the most significant areas of EAR control for software companies. Encryption items are primarily controlled under **Category 5, Part 2** of the CCL.

#### Key ECCNs for Encryption

| ECCN | Description |
|---|---|
| **5A002** | Encryption hardware (systems, equipment, and components) |
| **5B002** | Equipment for the development or production of encryption items |
| **5D002** | Encryption software |
| **5E002** | Technology for the development, production, or use of encryption items |

#### What Triggers Encryption Controls

Software is controlled under 5D002 if it:

- Employs cryptography for data confidentiality with a key length exceeding 56 bits for symmetric algorithms or equivalent strength for asymmetric algorithms.
- Has been specifically designed or modified to use cryptography for data confidentiality.
- Contains cryptographic functionality that goes beyond authentication, digital signature, data integrity, or access control.

#### Mass Market Encryption Exception

Software that qualifies as **"mass market"** encryption under **Note 3 to Category 5, Part 2** is classified as **5D992** (rather than 5D002) and is generally eligible for export under **License Exception ENC** with minimal restrictions. To qualify:

- The software must be generally available to the public via retail or download.
- The cryptographic functionality must not be easily modified by the user.
- The software must not have been designed for government, military, or intelligence end-uses.

#### ENC License Exception and Reporting

**License Exception ENC** (Part 740.17) allows export of many encryption items without a license, but imposes specific obligations:

1. **Classification request or self-classification report** -- Before relying on ENC, the exporter must either submit a classification request to BIS or file a self-classification report.
2. **Semi-annual reporting** -- Exporters using ENC must file semi-annual reports (by February 1 and August 1) identifying the encryption items exported and the destinations.
3. **Restrictions** -- ENC does not authorize exports to embargoed destinations (Cuba, Iran, North Korea, Syria) or to restricted end-users.

#### Publicly Available Encryption Source Code

Encryption source code that is **publicly available** (e.g., published open-source code) is generally not subject to the EAR under **Section 742.15(b)**, provided:

- The source code is publicly available (e.g., posted on a public repository).
- The exporter has sent an email notification to BIS (crypt@bis.gov) and the ENC Encryption Request Coordinator (enc@nsa.gov) with the URL or a copy of the source code.

This notification is a one-time requirement. Compiled binaries derived from publicly available source code, however, may still be subject to EAR controls.

### 9.2 Deemed Exports

A **deemed export** occurs when controlled technology or source code is released to a foreign national within the United States. "Release" includes:

- Visual inspection (e.g., allowing a foreign national to observe controlled equipment or read controlled technical data).
- Oral exchanges (e.g., discussing controlled technical information).
- Application of personal knowledge or technical experience acquired abroad.
- Providing access to controlled software or technology through electronic means.

The deemed export is treated as an export **to the foreign national's home country** (or most recent country of citizenship or permanent residence). If a license would be required for a physical export of that technology to that country, a license is also required for the deemed export.

**Implications for employers:**

- Companies employing foreign nationals must evaluate whether those employees will have access to EAR-controlled technology.
- A **Technology Control Plan (TCP)** may be necessary to restrict foreign national access to controlled information.
- Deemed export licenses specify the individual foreign national and the technology they are authorized to access.

**Exceptions to deemed export controls:**

- Fundamental research at accredited institutions is excluded.
- Information available to the public is excluded.
- Patent applications and certain published patent information are excluded.

### 9.3 Cloud Computing and SaaS Considerations

Cloud computing and SaaS delivery models introduce specific EAR compliance considerations:

#### When Cloud Access Constitutes an Export

Providing a foreign person or entity with access to controlled technology or software via cloud infrastructure may constitute an export or a deemed export. Relevant factors include:

- **Where the user is located** -- Providing cloud access to a user in a controlled destination triggers export control considerations.
- **What data or functionality is being accessed** -- If the cloud service provides access to controlled source code, technical data, or controlled computing capabilities, it may be a controlled export.
- **Where the data is stored and processed** -- If controlled data is stored on servers in a foreign country, the transfer of data to that server location may itself be an export or re-export.

#### BIS Guidance on Cloud Computing

BIS has issued guidance and rules clarifying that:

- Storing encrypted data on a server outside the United States is **not** an export of the underlying data, provided:
  - The data is **encrypted end-to-end**.
  - The encryption meets the standards specified in the EAR (FIPS 140-2 or equivalent).
  - The decryption keys are **not stored** on the foreign server and are not accessible to foreign persons.
  - The cloud provider does not have access to the unencrypted data.

- If these conditions are not met, the transfer of data to the foreign server is treated as an export to the country where the server is located.

#### Infrastructure Location

- Running workloads on cloud infrastructure in a foreign country (e.g., AWS regions, Azure regions) may constitute an export of the technology being processed.
- Organizations should evaluate whether their cloud architecture results in controlled technology being exported to or through countries that would require a license.

### 9.4 Software Updates and Technical Support

- Providing software updates to foreign end-users constitutes an export and must be evaluated under the same controls as the initial export.
- Technical support (troubleshooting, configuration assistance) provided to foreign persons may constitute a release of controlled technology if it involves providing access to controlled technical data or know-how.

---

## 10. Mendix and Low-Code Platform Considerations

### Platform vs. Application Distinction

When evaluating EAR compliance for Mendix applications, it is important to distinguish between:

1. **The Mendix platform itself** -- Mendix (a Siemens subsidiary) is responsible for the EAR classification and compliance of the platform software. Siemens publishes export control information for its products, and the Mendix platform generally falls under EAR99 or has applicable license exceptions.

2. **Applications built on Mendix** -- The applications you build using Mendix are **your** products. You are responsible for their classification and compliance. The EAR classification of an application depends on its functionality, not solely on the platform used to build it.

3. **Third-party components and modules** -- Java actions, custom widgets, and Mendix Marketplace modules may introduce controlled functionality (especially encryption) into your application. Each component must be evaluated.

### When a Mendix Application May Be Controlled

A Mendix application would likely be classified beyond EAR99 if it:

- **Implements encryption for data confidentiality** beyond what the platform provides natively (e.g., custom encryption modules, integration with encryption services).
- **Processes, stores, or transmits controlled technical data** -- If the application is designed to handle ECCN-controlled information, the application itself may be subject to controls.
- **Provides capabilities described on the CCL** -- For example, an application designed for industrial process control (Category 2), telecommunications management (Category 5), or sensor data processing (Category 6) may fall under the relevant ECCN.
- **Is specifically designed for a controlled end-use** -- Applications designed for military, intelligence, or weapons-related applications.

### Encryption in Mendix Applications

Most Mendix applications rely on the platform's built-in encryption capabilities:

| Component | Encryption Type | EAR Relevance |
|---|---|---|
| **HTTPS/TLS** | Transport encryption | Generally covered by Mendix/Siemens platform classification. Standard TLS for web applications typically qualifies for mass market treatment. |
| **Database encryption at rest** | Storage encryption | Provided by the underlying database or cloud provider. Classification responsibility typically lies with the database/cloud vendor. |
| **Mendix Encryption module** | Application-level encryption | Uses AES-128/256 encryption. If you add this module, evaluate whether it changes your application's ECCN. |
| **Custom Java actions using JCE/Bouncy Castle** | Custom encryption | You are responsible for classifying any custom encryption functionality you add. |
| **Third-party API integrations** | Varies | If your application calls external encryption services, evaluate the combined functionality. |

### Deployment Considerations

| Deployment Model | EAR Considerations |
|---|---|
| **Mendix Cloud (public)** | Mendix Cloud operates in multiple regions. Deploying to a non-U.S. region with controlled data may constitute an export. Evaluate data residency requirements. |
| **Mendix Cloud Dedicated** | Provides more control over data location but still requires evaluation of data flows and access patterns. |
| **Private Cloud (customer-managed)** | You control the infrastructure and data location. EAR compliance for the deployment environment is your responsibility. |
| **On-premises** | If deployed on-premises in a foreign country, the deployment constitutes an export. |

### Mendix Marketplace Modules

When incorporating Marketplace modules:

- Evaluate each module for controlled functionality, especially encryption.
- Open-source modules may qualify for the publicly available source code exclusion, but compiled/deployed versions may not.
- Community-developed modules may not have undergone export control classification. The integrating developer is responsible for the final product's classification.

---

## 11. Compliance Checklist for Application Developers

### Pre-Development

- [ ] **Identify the application's purpose and functionality.** Document what the application does, what data it processes, and who the intended users are.
- [ ] **Determine if the application implements or incorporates encryption.** If yes, identify the specific algorithms, key lengths, and purposes (confidentiality, authentication, integrity).
- [ ] **Classify the application under the EAR.** Determine whether it is EAR99 or falls under a specific ECCN. If unsure, consider filing a Commodity Classification Request with BIS.
- [ ] **Identify all third-party components** (libraries, modules, APIs) and determine their EAR classifications.
- [ ] **Determine target markets and deployment locations.** Identify all countries where the application will be deployed or accessed.

### Design and Development

- [ ] **Implement access controls** to prevent unauthorized access to controlled functionality or data by foreign persons in restricted destinations.
- [ ] **Design for data residency compliance.** Ensure controlled data can be isolated to approved geographic locations.
- [ ] **Document all encryption functionality** in the application, including inherited/platform-provided encryption.
- [ ] **Evaluate deemed export implications** if foreign national developers will have access to controlled source code or technology.
- [ ] **Implement audit logging** to support record-keeping requirements (who accessed what, when, and from where).

### Pre-Deployment

- [ ] **Screen all customers and end-users** against consolidated restricted party lists before provisioning access.
- [ ] **Verify end-use.** Confirm the application will not be used for prohibited end-uses (WMD, missile technology, military end-use in restricted countries).
- [ ] **Determine license requirements** based on the application's ECCN, destination country, and end-user. Consult the Commerce Country Chart.
- [ ] **Apply for necessary licenses** or confirm applicable license exceptions.
- [ ] **File encryption classification reports** if relying on License Exception ENC (semi-annual reporting to BIS).
- [ ] **Implement geo-blocking or IP-based access controls** for embargoed destinations if the application is publicly accessible.

### Ongoing Operations

- [ ] **Re-screen customers periodically** and when restricted party lists are updated.
- [ ] **Monitor for red flags** in customer behavior, requested configurations, and access patterns.
- [ ] **Maintain export records for five years.** This includes: license determinations, screening results, end-user certifications, and transaction records.
- [ ] **Report updates to BIS** if the application's encryption functionality changes materially.
- [ ] **File semi-annual encryption reports** (February 1 and August 1) if using License Exception ENC.
- [ ] **Train relevant personnel** on EAR compliance obligations, including developers, sales teams, and support staff.
- [ ] **Conduct periodic compliance audits** to verify that procedures are being followed.
- [ ] **Voluntarily self-disclose** any identified violations to BIS promptly.

### Incident Response

- [ ] **If a potential violation is identified**, halt the transaction and escalate to your compliance officer and legal counsel immediately.
- [ ] **Preserve all records** related to the potential violation.
- [ ] **Evaluate whether Voluntary Self-Disclosure (VSD) is appropriate** and file with BIS if so.
- [ ] **Implement corrective actions** to prevent recurrence.

---

## 12. EAR vs. ITAR: Key Differences

The **International Traffic in Arms Regulations (ITAR)**, administered by the **Department of State's Directorate of Defense Trade Controls (DDTC)**, governs the export of defense articles, defense services, and related technical data. EAR and ITAR are distinct regulatory frameworks, and understanding the differences is critical for compliance.

| Dimension | EAR | ITAR |
|---|---|---|
| **Administering Agency** | Bureau of Industry and Security (BIS), Department of Commerce | Directorate of Defense Trade Controls (DDTC), Department of State |
| **Legal Authority** | Export Control Reform Act (ECRA) | Arms Export Control Act (AECA) |
| **Scope** | Commercial and dual-use items, software, and technology | Defense articles, defense services, and related technical data |
| **Control List** | Commerce Control List (CCL), Part 774 | U.S. Munitions List (USML), 22 CFR 121 |
| **Classification System** | ECCN (alphanumeric, e.g., 5D002) | USML Category (Roman numerals, e.g., Category XI) |
| **Default Classification** | EAR99 (no specific controls for most commercial items) | No equivalent. If on the USML, it is controlled. |
| **License Policy** | Varies by ECCN, destination, and end-use. Many transactions require no license. | License or other authorization required for virtually all exports and re-exports. Presumption of denial for many destinations. |
| **License Exceptions** | Multiple exceptions available (TSU, ENC, TMP, GOV, etc.) | Very limited exemptions. |
| **Deemed Exports** | Yes, controlled release of technology to foreign nationals in the U.S. | Yes, and **more restrictive**. Release of ITAR-controlled technical data to any foreign person (regardless of location) requires authorization. No fundamental research exemption for ITAR technical data. |
| **Foreign Person Restrictions** | Varies by ECCN, destination country, and end-use. | **Broad restrictions.** ITAR-controlled technical data generally cannot be shared with any foreign person without authorization, regardless of their nationality (with limited Canadian exemptions). |
| **Registration** | No registration requirement. | Manufacturers, exporters, and brokers of defense articles must **register with DDTC** and pay annual registration fees. |
| **Re-export Controls** | De minimis rules apply (25% or 10% U.S.-content thresholds). | **No de minimis exception.** Any defense article with any U.S.-origin ITAR-controlled content remains ITAR-controlled regardless of the amount of foreign content. |
| **Cloud/SaaS** | Specific guidance for cloud storage of encrypted data. | More restrictive. Storing ITAR-controlled data on foreign servers generally requires authorization. DDTC has issued guidance on cloud computing, generally requiring that ITAR data remain within the United States or be accessible only by U.S. persons. |
| **Penalties (Criminal)** | Up to $1,000,000 and/or 20 years per violation | Up to $1,000,000 and/or 20 years per violation |
| **Penalties (Civil)** | Up to ~$365,000 or twice the transaction value per violation | Up to approximately $1,280,000 per violation (adjusted annually) |
| **Compliance Culture** | Flexible compliance programs tailored to risk. | Strict compliance expected. DDTC expects formal compliance programs and often requires them as part of consent agreements. |

### Jurisdiction Determination

If an item could potentially fall under either EAR or ITAR jurisdiction, the process for determining which applies is:

1. **Check the USML first.** If the item is specifically enumerated on the USML, it is ITAR-controlled regardless of whether it also appears to fit a CCL entry.
2. **ECR Reform "bright lines."** The Export Control Reform (ECR) initiative established clearer boundaries between the USML and CCL. Items that are "specially designed" for military applications tend to remain on the USML, while items with predominantly commercial applications were moved to the CCL.
3. **Commodity Jurisdiction (CJ) request.** If jurisdiction is unclear, submit a CJ request to DDTC. DDTC will determine whether the item is ITAR or EAR controlled. This determination is binding.

### Why This Matters for Software Developers

Most commercial software, including Mendix applications, falls under EAR jurisdiction. However, software becomes ITAR-relevant if:

- It is specifically designed, developed, or modified for a defense article on the USML.
- It constitutes technical data related to a defense article (e.g., design specifications, manufacturing instructions).
- It provides a military-specific capability that is enumerated on the USML.

If your application processes, stores, or transmits ITAR-controlled technical data, the application itself and its hosting environment may need to comply with ITAR requirements, even if the application software is otherwise EAR99. This is a jurisdiction-by-content situation that requires careful legal analysis.

---

## 13. References and Resources

### Primary Regulatory Sources

| Resource | Location |
|---|---|
| EAR Full Text (15 CFR 730-774) | https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C |
| Commerce Control List (Supplement No. 1 to Part 774) | https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-774/supplement-No.-1-to-part-774 |
| Commerce Country Chart (Supplement No. 1 to Part 738) | https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-738/supplement-No.-1-to-part-738 |

### BIS Resources

| Resource | Location |
|---|---|
| BIS Website | https://www.bis.gov |
| SNAP-R (License Application System) | https://snapr.bis.gov |
| Denied Persons List | https://www.bis.gov/denied-persons-list |
| Entity List | https://www.bis.gov/entity-list |
| Unverified List | https://www.bis.gov/unverified-list |
| BIS Encryption Controls | https://www.bis.gov/encryption |
| Semi-Annual Encryption Reports | https://www.bis.gov/ear/title-15/part-740 |

### Screening Resources

| Resource | Location |
|---|---|
| Consolidated Screening List (CSL) | https://www.trade.gov/consolidated-screening-list |
| OFAC SDN List | https://www.treasury.gov/ofac/downloads/sdnlist.txt |
| OFAC Sanctions Search | https://sanctionssearch.ofac.treas.gov |

### Guidance Documents

| Resource | Description |
|---|---|
| "Know Your Customer" Guidance | Supplement No. 3 to Part 732 -- Red flags and due diligence guidance |
| Deemed Export FAQ | BIS guidance on deemed exports and Technology Control Plans |
| Cloud Computing Advisory | BIS guidance on cloud storage and export control implications |
| Voluntary Self-Disclosure Guidelines | Part 764.5 -- Procedures for disclosing potential violations |

### Industry Resources

| Resource | Description |
|---|---|
| Siemens Export Control Information | Siemens publishes ECCN and export control information for its products, including Mendix. Check Siemens compliance portal for current classifications. |
| BIS Online Training | BIS offers free online seminars and training materials on export compliance. |
| Update Conferences | BIS hosts annual Update Conferences on Export Controls and Policy. Materials are published on the BIS website. |

---

*This document was prepared for informational purposes and reflects U.S. Export Administration Regulations as of early 2025. Export control regulations are subject to frequent amendment. Organizations should monitor the Federal Register for updates and consult qualified export control counsel for compliance decisions specific to their products, services, and operations.*
