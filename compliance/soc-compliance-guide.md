# SOC Compliance: Comprehensive Guide for Service Organizations and Software Providers

**Version:** 1.0
**Last Updated:** February 2026
**Classification:** Internal / Customer-Facing

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [What Is SOC?](#2-what-is-soc)
3. [SOC Report Types: SOC 1, SOC 2, and SOC 3](#3-soc-report-types-soc-1-soc-2-and-soc-3)
4. [Type I vs. Type II Reports](#4-type-i-vs-type-ii-reports)
5. [The Five Trust Services Criteria](#5-the-five-trust-services-criteria)
6. [Who Needs SOC Compliance?](#6-who-needs-soc-compliance)
7. [The SOC Audit Process](#7-the-soc-audit-process)
8. [Common Controls and Requirements](#8-common-controls-and-requirements)
9. [SOC 2 in Detail: Criteria for Software Organizations](#9-soc-2-in-detail-criteria-for-software-organizations)
10. [How SOC Applies to Software and Applications](#10-how-soc-applies-to-software-and-applications)
11. [Specific Considerations for Mendix and Low-Code Platforms](#11-specific-considerations-for-mendix-and-low-code-platforms)
12. [Key Compliance Checklist for Application Developers](#12-key-compliance-checklist-for-application-developers)
13. [Cost and Timeline Expectations](#13-cost-and-timeline-expectations)
14. [Continuous Compliance vs. Point-in-Time](#14-continuous-compliance-vs-point-in-time)
15. [Frequently Asked Questions](#15-frequently-asked-questions)
16. [Glossary](#16-glossary)

---

## 1. Executive Summary

System and Organization Controls (SOC) reports are the gold standard for demonstrating that a service organization has implemented effective controls over its systems and data. Originally developed by the American Institute of Certified Public Accountants (AICPA), SOC reports provide independent, third-party assurance to customers, regulators, and stakeholders that an organization manages data with the highest standards of security and operational excellence.

For software providers, SaaS companies, and organizations building applications on platforms such as Mendix, SOC 2 compliance is increasingly a prerequisite for doing business with enterprise customers. This guide provides a comprehensive overview of SOC compliance, with particular attention to its application in software development and low-code/no-code environments.

---

## 2. What Is SOC?

### 2.1 Definition

**SOC (System and Organization Controls)** is a suite of audit reports produced by independent Certified Public Accountants (CPAs) that examine the controls a service organization has in place. These reports provide assurance about the effectiveness of controls relevant to security, availability, processing integrity, confidentiality, and privacy.

> **Note:** SOC was formerly known as "Service Organization Controls" and, prior to that, "SAS 70" (Statement on Auditing Standards No. 70). The AICPA retired SAS 70 in 2011 and replaced it with the current SOC framework.

### 2.2 Who Created SOC?

The **American Institute of Certified Public Accountants (AICPA)** developed and maintains the SOC framework. The AICPA is the national professional organization for CPAs in the United States, founded in 1887. Key points:

- The AICPA established the **Trust Services Criteria (TSC)** that form the foundation of SOC 2 and SOC 3 reports.
- The AICPA's **Assurance Services Executive Committee (ASEC)** is responsible for maintaining and updating the criteria.
- The most recent significant update to the Trust Services Criteria was issued in **2017**, with a revision effective as of **December 15, 2018**. Subsequent updates and points of focus have been issued to address evolving risks including cloud computing, AI, and supply chain security.
- SOC examinations must be performed by an independent CPA or CPA firm in accordance with AICPA professional standards (AT-C Section 105, AT-C Section 205, and AT-C Section 320).

### 2.3 Governing Standards

| Standard | Applies To | Description |
|----------|-----------|-------------|
| SSAE 18 (AT-C 320) | SOC 1 | Reporting on controls at a service organization relevant to user entities' internal control over financial reporting |
| AT-C 205 | SOC 2, SOC 3 | Examination engagements based on Trust Services Criteria |
| ISAE 3402 | International SOC 1 equivalent | International Standard on Assurance Engagements |
| ISAE 3000 | International SOC 2 equivalent | Assurance engagements other than audits or reviews |

---

## 3. SOC Report Types: SOC 1, SOC 2, and SOC 3

### 3.1 Overview Comparison

| Aspect | SOC 1 | SOC 2 | SOC 3 |
|--------|-------|-------|-------|
| **Focus** | Financial reporting controls | Operational and security controls | Same as SOC 2 (summary) |
| **Standard** | SSAE 18 (AT-C 320) | AT-C 205 | AT-C 205 |
| **Criteria** | Control objectives defined by service org | Trust Services Criteria | Trust Services Criteria |
| **Audience** | User entity auditors, management | Management, regulators, specified parties | General public |
| **Distribution** | Restricted (NDA required) | Restricted (NDA required) | Publicly distributable |
| **Detail Level** | High (detailed control descriptions and tests) | High (detailed control descriptions and tests) | Low (summary opinion only) |
| **Typical Use** | Payroll processors, financial SaaS, loan servicers | SaaS providers, data centers, cloud services | Marketing, website trust seal |

### 3.2 SOC 1 (Financial Reporting Controls)

**Purpose:** Evaluates controls at a service organization that are relevant to user entities' internal control over financial reporting (ICFR).

**When to use SOC 1:**
- Your service directly impacts your customers' financial statements.
- Your customers' auditors require assurance about your controls as part of their financial statement audit.
- You process financial transactions on behalf of clients (payroll, billing, claims processing, loan servicing).

**Example scenarios:**
- A payroll processing company that calculates and distributes employee wages
- A payment gateway that processes credit card transactions
- An accounting SaaS platform that hosts general ledger data

### 3.3 SOC 2 (Security and Operational Controls)

**Purpose:** Evaluates controls relevant to one or more of the five Trust Services Criteria: Security (required), Availability, Processing Integrity, Confidentiality, and Privacy.

**When to use SOC 2:**
- You store, process, or transmit customer data.
- Enterprise customers require proof of security and operational controls.
- You operate a SaaS platform, cloud service, data center, or managed service.
- You need to demonstrate compliance with security best practices.

**Key characteristics:**
- **Security (Common Criteria) is always required** and forms the baseline for every SOC 2 report.
- Additional criteria (Availability, Processing Integrity, Confidentiality, Privacy) are selected based on the nature of the service and customer expectations.
- The report includes a detailed description of the system, the controls in place, and the auditor's tests and results.

**SOC 2 is the most relevant report type for software companies, SaaS providers, and application developers.**

### 3.4 SOC 3 (General Use Report)

**Purpose:** Provides the same assurance as SOC 2 but in a shortened, general-use format suitable for public distribution.

**When to use SOC 3:**
- You want to publicly demonstrate your commitment to security.
- You need a trust seal for your website or marketing materials.
- Prospects need assurance before signing an NDA to receive the full SOC 2 report.

**Key characteristics:**
- Contains the auditor's opinion but not the detailed description of controls, tests, or results.
- Can be freely distributed without an NDA.
- Often used alongside a SOC 2 report (SOC 3 for marketing, SOC 2 for due diligence).

---

## 4. Type I vs. Type II Reports

### 4.1 Overview

| Aspect | Type I | Type II |
|--------|--------|---------|
| **What it evaluates** | Design of controls at a specific point in time | Design AND operating effectiveness of controls over a period of time |
| **Time scope** | Single date (snapshot) | Minimum 3 months, typically 6-12 months |
| **Auditor opinion** | Controls are suitably designed | Controls are suitably designed AND operating effectively |
| **Evidence required** | Control descriptions and design documentation | Control descriptions, design documentation, AND evidence of consistent operation |
| **Typical duration** | 4-8 weeks | 3-12 months (observation period) + 4-8 weeks (reporting) |
| **Cost** | Lower | Higher |
| **Customer acceptance** | Acceptable for initial compliance, new organizations | Preferred by enterprise customers and regulators |

### 4.2 Type I Report

A Type I report (sometimes written "Type 1") evaluates whether controls are **suitably designed and implemented** as of a **specific date**.

**When to pursue Type I:**
- You are pursuing SOC compliance for the first time.
- You need to demonstrate compliance quickly to close a deal.
- You plan to follow up with a Type II report within 6-12 months.
- Your controls are new and have not been in operation long enough for a Type II audit.

**Limitations:**
- Does not verify that controls actually operate effectively over time.
- Some enterprise customers and regulated industries will not accept Type I reports.
- Considered a stepping stone, not a final destination.

### 4.3 Type II Report

A Type II report (sometimes written "Type 2") evaluates whether controls are **suitably designed AND operating effectively** over a **defined period of time** (the "audit window" or "observation period").

**When to pursue Type II:**
- Enterprise customers require it (this is the standard expectation).
- You have had controls in place for at least 3-6 months.
- You want to demonstrate sustained operational discipline.
- Regulatory or contractual requirements demand it.

**Key considerations:**
- The observation period is typically 6-12 months (12 months is the gold standard).
- Auditors will sample evidence throughout the period, not just at the end.
- Any control failures during the observation period will be reported as exceptions.
- Exceptions do not necessarily result in a qualified opinion if they are isolated and compensating controls exist.

### 4.4 Recommended Path

```
Year 1: Readiness Assessment → Remediation → Type I Report
Year 1-2: Begin Type II observation period (6-12 months)
Year 2: Type II Report issued
Year 2+: Annual Type II renewal
```

---

## 5. The Five Trust Services Criteria

The Trust Services Criteria (TSC), developed by the AICPA, define the control objectives used in SOC 2 and SOC 3 examinations. **Security is mandatory** for every SOC 2 engagement. The remaining four criteria are optional and selected based on the nature of the service.

### 5.1 Security (Common Criteria) -- REQUIRED

**Definition:** Information and systems are protected against unauthorized access, unauthorized disclosure of information, and damage to systems that could compromise the availability, integrity, confidentiality, and privacy of information or systems.

**Why it is always required:** Security underpins all other criteria. You cannot have availability, integrity, confidentiality, or privacy without a secure foundation.

**Key areas:**
- Logical and physical access controls
- System operations and monitoring
- Change management
- Risk assessment and management
- Communication and information
- Monitoring of controls
- Vendor and third-party management

**Common Criteria (CC) Series:**
| Series | Domain |
|--------|--------|
| CC1 | Control Environment |
| CC2 | Communication and Information |
| CC3 | Risk Assessment |
| CC4 | Monitoring Activities |
| CC5 | Control Activities |
| CC6 | Logical and Physical Access Controls |
| CC7 | System Operations |
| CC8 | Change Management |
| CC9 | Risk Mitigation |

### 5.2 Availability

**Definition:** Information and systems are available for operation and use to meet the entity's objectives.

**When to include:**
- You provide services with SLA commitments (uptime guarantees).
- Your customers depend on your system being continuously available.
- Downtime would have material business impact on your customers.

**Key areas:**
- Performance monitoring and capacity planning
- Disaster recovery and business continuity
- Backup and restoration procedures
- Incident management for availability events
- SLA monitoring and reporting
- Redundancy and failover mechanisms

**Relevant criteria:** A1.1 through A1.3

### 5.3 Processing Integrity

**Definition:** System processing is complete, valid, accurate, timely, and authorized to meet the entity's objectives.

**When to include:**
- Your system performs critical data processing or calculations.
- Accuracy of output is essential (financial calculations, reporting, data transformations).
- Customers rely on the correctness of your system's outputs.

**Key areas:**
- Input validation and data quality controls
- Processing accuracy verification
- Output reconciliation and review
- Error detection and correction procedures
- Data lineage and audit trails

**Relevant criteria:** PI1.1 through PI1.5

### 5.4 Confidentiality

**Definition:** Information designated as confidential is protected to meet the entity's objectives.

**When to include:**
- You handle data that is classified as confidential (trade secrets, intellectual property, business plans, pre-release financial data).
- Contractual or regulatory requirements mandate confidentiality protections.
- Your customers share sensitive business information with you.

**Key areas:**
- Data classification and labeling
- Encryption (at rest and in transit)
- Access restrictions based on data classification
- Confidential data disposal and destruction
- Non-disclosure and confidentiality agreements

**Note:** Confidentiality applies to business-sensitive information. For personal information (PII), see Privacy.

**Relevant criteria:** C1.1 through C1.2

### 5.5 Privacy

**Definition:** Personal information is collected, used, retained, disclosed, and disposed of in conformity with the commitments in the entity's privacy notice and with criteria set forth in generally accepted privacy principles (GAPP).

**When to include:**
- You collect, store, or process personal information (PII) directly from data subjects.
- You act as a data controller (not just a data processor).
- Your privacy practices are a key concern for customers or regulators.
- You need to demonstrate alignment with privacy regulations (GDPR, CCPA, etc.).

**Key areas:**
- Notice and communication of privacy practices
- Choice and consent mechanisms
- Collection limitation and data minimization
- Use, retention, and disposal policies
- Access, correction, and deletion rights
- Disclosure to third parties
- Security for personal information
- Quality and accuracy of personal information
- Monitoring and enforcement

**Relevant criteria:** P1.0 through P8.1

> **Important distinction:** Privacy is about *personal information* and the rights of individuals. Confidentiality is about *business-sensitive information* designated as confidential. A SOC 2 report can include one, both, or neither (but Security is always required).

### 5.6 Criteria Selection Guide

| You should include... | If your service... |
|----------------------|-------------------|
| Security (required) | Handles any customer data or systems |
| + Availability | Has SLA commitments or uptime is critical |
| + Processing Integrity | Performs calculations, reporting, or data transformations |
| + Confidentiality | Handles trade secrets, IP, or classified business data |
| + Privacy | Collects or processes personal information (PII) from individuals |

**Typical selections for software/SaaS companies:**
- **Minimum:** Security
- **Standard:** Security + Availability + Confidentiality
- **Comprehensive:** Security + Availability + Processing Integrity + Confidentiality
- **Full scope:** All five (when handling PII directly)

---

## 6. Who Needs SOC Compliance?

### 6.1 Primary Audiences

**Service Organizations** -- any organization that provides services to other entities where those services affect the user entity's operations, information, or controls:

| Organization Type | SOC Report(s) | Rationale |
|------------------|---------------|-----------|
| SaaS providers | SOC 2 (+ SOC 3) | Store/process customer data in the cloud |
| Cloud infrastructure providers (IaaS/PaaS) | SOC 2 | Host customer workloads and data |
| Managed service providers (MSPs) | SOC 1 and/or SOC 2 | Manage customer IT infrastructure |
| Data centers and colocation facilities | SOC 2 | Physical and environmental controls for customer equipment |
| Payment processors | SOC 1 + SOC 2 | Financial transaction processing + data security |
| Payroll and HR service providers | SOC 1 | Impact on financial reporting |
| Healthcare IT providers | SOC 2 (+ HITRUST) | Protected health information handling |
| Financial technology (FinTech) | SOC 1 + SOC 2 | Financial reporting impact + operational security |
| Low-code/no-code platform providers | SOC 2 | Application hosting and data processing |
| Consulting and outsourcing firms | SOC 2 | Access to customer systems and data |

### 6.2 Why Enterprise Customers Require SOC Reports

1. **Due diligence:** Enterprise procurement and security teams use SOC reports to evaluate vendor risk.
2. **Regulatory compliance:** SOC reports support compliance with regulations such as SOX, HIPAA, GLBA, and GDPR.
3. **Audit support:** User entity auditors rely on SOC 1 reports when auditing financial statements.
4. **Contractual requirements:** Master service agreements (MSAs) and data processing agreements (DPAs) increasingly require SOC 2 compliance.
5. **Insurance:** Cyber insurance underwriters may require or provide premium discounts for SOC 2 compliance.
6. **Competitive advantage:** SOC compliance differentiates service providers in crowded markets.

### 6.3 When SOC Compliance Becomes Necessary

SOC compliance is not legally mandated by a single regulation, but it becomes effectively required when:

- Enterprise customers include it in their vendor security questionnaires.
- Prospects will not sign contracts without a current SOC 2 Type II report.
- Your organization is subject to regulatory oversight that expects third-party assurance (SOX, FFIEC, HIPAA).
- You are pursuing government contracts (FedRAMP includes SOC 2 concepts).
- You are scaling beyond small/mid-market customers into enterprise segments.

---

## 7. The SOC Audit Process

### 7.1 Process Overview

The SOC compliance journey consists of five major phases:

```
Phase 1          Phase 2         Phase 3          Phase 4          Phase 5
Readiness   -->  Gap        -->  Remediation  -->  Formal      -->  Report &
Assessment       Analysis        & Implementation  Audit            Maintenance
(2-4 weeks)      (2-4 weeks)     (2-6 months)      (Type I: 4-8w)   (Ongoing)
                                                    (Type II: 3-12m)
```

### 7.2 Phase 1: Readiness Assessment (2-4 weeks)

**Objective:** Understand the current state of controls and identify the scope of the SOC examination.

**Activities:**
- Define the system boundaries (which systems, applications, infrastructure, and data are in scope).
- Select the applicable Trust Services Criteria.
- Inventory existing controls, policies, and procedures.
- Interview key personnel (IT, security, engineering, HR, management).
- Review existing documentation (policies, procedures, architecture diagrams).
- Identify subservice organizations (hosting providers, third-party tools).

**Deliverable:** Readiness assessment report with current state findings and recommendations.

### 7.3 Phase 2: Gap Analysis (2-4 weeks)

**Objective:** Identify gaps between current controls and SOC requirements.

**Activities:**
- Map existing controls to Trust Services Criteria point by point.
- Identify missing controls, insufficient controls, and undocumented controls.
- Assess the maturity of existing controls (ad hoc, repeatable, defined, managed, optimized).
- Prioritize gaps based on risk and remediation effort.
- Develop a remediation roadmap with timelines and owners.

**Deliverable:** Gap analysis report with prioritized remediation plan.

### 7.4 Phase 3: Remediation and Implementation (2-6 months)

**Objective:** Close identified gaps and establish a control environment suitable for audit.

**Activities:**
- Develop or update policies and procedures:
  - Information Security Policy
  - Access Control Policy
  - Change Management Policy
  - Incident Response Plan
  - Business Continuity and Disaster Recovery Plan
  - Data Classification and Handling Policy
  - Vendor Management Policy
  - Acceptable Use Policy
  - Risk Assessment Policy
  - Privacy Policy (if Privacy criteria selected)
- Implement technical controls:
  - Multi-factor authentication (MFA)
  - Encryption at rest and in transit
  - Logging and monitoring (SIEM)
  - Vulnerability scanning and penetration testing
  - Endpoint protection
  - Network segmentation and firewalls
  - Backup and disaster recovery systems
- Implement operational controls:
  - Background checks for employees
  - Security awareness training
  - Onboarding and offboarding procedures
  - Vendor risk assessments
  - Periodic access reviews
  - Change advisory board (CAB) processes
- Begin collecting evidence of control operation.

**Deliverable:** Implemented controls with evidence of design and initial operation.

### 7.5 Phase 4: Formal Audit (Type I: 4-8 weeks; Type II: 3-12 months)

**Objective:** Independent CPA examination of controls.

**Activities:**

**For Type I:**
- Auditor reviews system description.
- Auditor evaluates control design as of the specified date.
- Auditor issues opinion on suitability of design.

**For Type II:**
- Auditor reviews system description.
- Auditor evaluates control design.
- Auditor tests operating effectiveness throughout the observation period.
- Testing methods include:
  - **Inquiry:** Interviews with control owners.
  - **Observation:** Watching controls in operation.
  - **Inspection:** Reviewing documentation and evidence.
  - **Re-performance:** Independently executing the control to verify results.
- Auditor documents any exceptions (control failures).
- Auditor issues opinion on design suitability and operating effectiveness.

**Deliverable:** SOC report including:
1. Independent auditor's report (opinion)
2. Management's assertion
3. System description
4. Description of controls, tests performed, and results (Type II only includes test results)
5. Other information provided by management (optional)

### 7.6 Phase 5: Report and Continuous Maintenance (Ongoing)

**Objective:** Distribute the report and maintain compliance for annual renewal.

**Activities:**
- Distribute the report to customers (under NDA for SOC 2).
- Address any exceptions identified during the audit.
- Maintain continuous operation of all controls.
- Collect evidence throughout the year for the next audit cycle.
- Conduct annual risk assessments.
- Update policies and procedures as needed.
- Manage organizational and system changes that could impact controls.

**Deliverable:** Annual SOC report renewal; continuous compliance program.

### 7.7 Selecting an Auditor

**Requirements:**
- Must be a licensed CPA firm.
- Must have experience with SOC examinations.
- Must be independent of the service organization.

**Selection criteria:**
- Industry experience (e.g., SaaS, healthcare, financial services).
- Reputation and references.
- Use of automation and compliance platforms (reduces evidence collection burden).
- Communication style and responsiveness.
- Pricing transparency.
- Willingness to provide guidance during readiness and remediation phases (within independence constraints).

---

## 8. Common Controls and Requirements

### 8.1 Control Categories

SOC 2 controls typically fall into three categories:

| Category | Description | Examples |
|----------|-------------|----------|
| **Administrative** | Policies, procedures, and governance | Security policy, risk assessment, training programs |
| **Technical** | Technology-based controls | Encryption, MFA, firewalls, SIEM, DLP |
| **Physical** | Controls over the physical environment | Badge access, surveillance, environmental controls |

### 8.2 Essential Policies and Procedures

The following policies are expected in virtually every SOC 2 examination:

1. **Information Security Policy** -- Overarching security governance framework
2. **Access Control Policy** -- User provisioning, de-provisioning, least privilege, role-based access
3. **Change Management Policy** -- How changes to systems are requested, approved, tested, and deployed
4. **Incident Response Plan** -- Detection, triage, containment, eradication, recovery, post-mortem
5. **Business Continuity and Disaster Recovery Plan** -- RPO, RTO, failover procedures, testing schedule
6. **Risk Assessment Policy** -- Annual risk assessment process, risk register, treatment plans
7. **Vendor Management Policy** -- Third-party risk assessment, contractual requirements, ongoing monitoring
8. **Data Classification Policy** -- Classification levels, handling requirements, labeling
9. **Acceptable Use Policy** -- Employee responsibilities for using organizational systems
10. **Encryption Policy** -- Standards for encryption at rest and in transit
11. **Logging and Monitoring Policy** -- What is logged, retention periods, review procedures
12. **Human Resources Security Policy** -- Background checks, onboarding, offboarding, training

### 8.3 Common Technical Controls

| Control Area | Common Implementations |
|-------------|----------------------|
| **Identity and Access Management** | SSO, MFA, RBAC, least privilege, quarterly access reviews, automated provisioning/de-provisioning |
| **Network Security** | Firewalls, network segmentation, VPN, intrusion detection/prevention (IDS/IPS), WAF |
| **Data Protection** | TLS 1.2+ in transit, AES-256 at rest, key management, DLP, secure data disposal |
| **Endpoint Security** | EDR/antivirus, disk encryption, MDM, patch management, hardened configurations |
| **Logging and Monitoring** | Centralized logging (SIEM), alerting, log integrity, 90-day+ retention, regular review |
| **Vulnerability Management** | Regular vulnerability scanning, annual penetration testing, patch management SLAs |
| **Change Management** | Version control, code review, separation of duties, CAB approval, rollback procedures |
| **Backup and Recovery** | Automated backups, offsite/cross-region replication, regular restoration testing |
| **Incident Response** | Defined runbooks, 24/7 on-call, post-incident reviews, customer notification procedures |
| **Physical Security** | Badge access, visitor logs, CCTV, environmental controls (HVAC, fire suppression) |

### 8.4 Organizational Controls

| Control Area | Requirements |
|-------------|-------------|
| **Governance** | Board/management oversight, security committee, CISO or security leadership role |
| **Risk Management** | Annual risk assessment, risk register, risk treatment plans, risk acceptance process |
| **Human Resources** | Background checks, security training (onboarding + annual), confidentiality agreements |
| **Vendor Management** | Due diligence before engagement, contractual security requirements, annual reassessment |
| **Communication** | Security policies communicated to employees, customer security commitments documented |

---

## 9. SOC 2 in Detail: Criteria for Software Organizations

This section provides a detailed breakdown of each Trust Services Criteria area as it applies to software organizations.

### 9.1 Security: Common Criteria (CC Series)

Security is the foundation of every SOC 2 report. The Common Criteria are organized into nine series:

#### CC1: Control Environment

**Purpose:** Establishes the tone at the top and the organizational commitment to integrity and security.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC1.1 | The entity demonstrates a commitment to integrity and ethical values | Code of conduct, ethics training, whistleblower policy |
| CC1.2 | The board of directors demonstrates independence from management and exercises oversight | Board/committee oversight of security, regular reporting |
| CC1.3 | Management establishes structures, reporting lines, and appropriate authorities | Organizational chart, CISO role, security team structure |
| CC1.4 | The entity demonstrates a commitment to attract, develop, and retain competent individuals | Job descriptions with security responsibilities, training, performance evaluations |
| CC1.5 | The entity holds individuals accountable for internal control responsibilities | Documented roles, performance accountability, disciplinary procedures |

#### CC2: Communication and Information

**Purpose:** Ensures relevant information is identified, captured, and communicated.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC2.1 | The entity obtains or generates and uses relevant, quality information | Asset inventory, data flow diagrams, system documentation |
| CC2.2 | The entity internally communicates information necessary to support the functioning of internal control | Security policies distributed to all employees, intranet, training |
| CC2.3 | The entity communicates with external parties regarding matters affecting the functioning of internal control | Customer security documentation, breach notification procedures, status pages |

#### CC3: Risk Assessment

**Purpose:** Identifies and assesses risks that could prevent the achievement of objectives.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC3.1 | The entity specifies objectives with sufficient clarity | Documented security objectives, system description |
| CC3.2 | The entity identifies risks to the achievement of its objectives | Annual risk assessment, threat modeling, risk register |
| CC3.3 | The entity considers the potential for fraud | Fraud risk assessment, segregation of duties, whistleblower mechanisms |
| CC3.4 | The entity identifies and assesses changes that could significantly impact internal control | Change management process, M&A integration, regulatory change tracking |

#### CC4: Monitoring Activities

**Purpose:** Evaluates whether controls are present and functioning over time.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC4.1 | The entity selects, develops, and performs ongoing and/or separate evaluations | Continuous monitoring, internal audits, management reviews |
| CC4.2 | The entity evaluates and communicates internal control deficiencies in a timely manner | Exception tracking, remediation plans, management reporting |

#### CC5: Control Activities

**Purpose:** Contributes to the mitigation of risks to the achievement of objectives.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC5.1 | The entity selects and develops control activities that contribute to mitigation of risks | Controls mapped to identified risks, defense in depth |
| CC5.2 | The entity also selects and develops general control activities over technology | IT general controls, automated controls, technology governance |
| CC5.3 | The entity deploys control activities through policies and procedures | Written policies, documented procedures, evidence of execution |

#### CC6: Logical and Physical Access Controls

**Purpose:** Restricts logical and physical access to authorized individuals.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC6.1 | The entity implements logical access security software, infrastructure, and architectures | SSO, directory services, network architecture, firewalls |
| CC6.2 | Prior to issuing system credentials, the entity registers and authorizes new users | Onboarding process, access request and approval workflow |
| CC6.3 | The entity authorizes, modifies, or removes access based on authorization | RBAC, least privilege, access modification process |
| CC6.4 | The entity restricts physical access to facilities and protected information assets | Badge access, visitor management, data center controls |
| CC6.5 | The entity discontinues logical and physical protections over physical assets only after transferring them | Secure asset disposal, media sanitization, NIST 800-88 compliance |
| CC6.6 | The entity implements logical access security measures to protect against threats from sources outside its system boundaries | Firewalls, WAF, DDoS protection, email security, endpoint protection |
| CC6.7 | The entity restricts the transmission, movement, and removal of information | Encryption in transit, DLP, removable media controls, secure file transfer |
| CC6.8 | The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software | Antivirus/EDR, application whitelisting, software restriction policies |

#### CC7: System Operations

**Purpose:** Detects and mitigates processing deviations and security events.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC7.1 | To meet its objectives, the entity uses detection and monitoring procedures | SIEM, IDS/IPS, log monitoring, anomaly detection, alerting |
| CC7.2 | The entity monitors system components and the operation of those components for anomalies | Infrastructure monitoring, application performance monitoring, threshold alerts |
| CC7.3 | The entity evaluates security events to determine whether they could or have resulted in a failure | Event triage, incident classification, threat intelligence |
| CC7.4 | The entity responds to identified security incidents | Incident response plan, runbooks, escalation procedures, communication plans |
| CC7.5 | The entity identifies, develops, and implements activities to recover from identified security incidents | Recovery procedures, post-incident review, lessons learned, root cause analysis |

#### CC8: Change Management

**Purpose:** Controls changes to infrastructure, data, software, and procedures.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC8.1 | The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes | Change management process, SDLC, code review, testing, approval gates, deployment procedures |

#### CC9: Risk Mitigation

**Purpose:** Identifies and mitigates risks from business disruptions and vendor relationships.

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| CC9.1 | The entity identifies, selects, and develops risk mitigation activities | Risk treatment plans, compensating controls, insurance |
| CC9.2 | The entity assesses and manages risks associated with vendors and business partners | Vendor risk assessment, due diligence, contractual requirements, SOC report review |

### 9.2 Availability Criteria

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| A1.1 | The entity maintains, monitors, and evaluates current processing capacity and use | Capacity planning, auto-scaling, performance monitoring, load testing |
| A1.2 | The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup, and recovery infrastructure | DR plan, backup systems, redundant infrastructure, failover, UPS/generators |
| A1.3 | The entity tests recovery plan procedures supporting system recovery | Annual DR testing, tabletop exercises, documented test results, remediation of findings |

### 9.3 Processing Integrity Criteria

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| PI1.1 | The entity obtains or generates, uses, and communicates relevant, quality information regarding the objectives related to processing | Data quality standards, input validation rules, processing specifications |
| PI1.2 | The entity implements policies and procedures over system inputs | Input validation, data type checking, boundary checks, duplicate detection |
| PI1.3 | The entity implements policies and procedures over system processing | Processing controls, reconciliation, audit trails, error handling |
| PI1.4 | The entity implements policies and procedures to make available or deliver output completely, accurately, and timely | Output validation, delivery confirmation, completeness checks |
| PI1.5 | The entity implements policies and procedures to store inputs, items in processing, and outputs completely, accurately, and timely | Data retention, integrity verification, storage controls, archival procedures |

### 9.4 Confidentiality Criteria

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| C1.1 | The entity identifies and maintains confidential information | Data classification policy, labeling, inventory of confidential data |
| C1.2 | The entity disposes of confidential information | Secure disposal procedures, certificate of destruction, automated retention enforcement |

### 9.5 Privacy Criteria

| Criteria | Description | Typical Controls |
|----------|-------------|-----------------|
| P1.1 | Notice | Privacy policy/notice, cookie banners, consent mechanisms |
| P2.1 | Choice and Consent | Opt-in/opt-out mechanisms, granular consent, consent records |
| P3.1 | Collection | Collection limitation, data minimization, purpose specification |
| P3.2 | Collection | Implicit/explicit consent for collection aligned with stated purposes |
| P4.1 | Use, Retention, and Disposal | Use limitation, retention schedules, automated purging |
| P4.2 | Use, Retention, and Disposal | Retention policies aligned with legal/contractual requirements |
| P4.3 | Use, Retention, and Disposal | Secure disposal of personal information |
| P5.1 | Access | Data subject access rights (view, export) |
| P5.2 | Access | Correction and amendment procedures |
| P6.1 | Disclosure and Notification | Third-party disclosure policies, data processing agreements |
| P6.2 | Disclosure and Notification | Breach notification procedures, regulatory notification |
| P6.3 | Disclosure and Notification | Data subject notification of material changes |
| P6.4 | Disclosure and Notification | Authorization required for disclosure |
| P6.5 | Disclosure and Notification | Third-party compliance verification |
| P6.6 | Disclosure and Notification | Notification of breaches and incidents |
| P6.7 | Disclosure and Notification | Provision of privacy notice |
| P7.1 | Quality | Data accuracy and completeness procedures |
| P8.1 | Monitoring and Enforcement | Privacy compliance monitoring, complaint handling, enforcement procedures |

---

## 10. How SOC Applies to Software and Applications

### 10.1 Access Controls

**Application-level access controls** are a primary focus area for software providers:

| Control | Description | Implementation |
|---------|-------------|----------------|
| Authentication | Verify user identity | SSO integration (SAML, OIDC), MFA enforcement, password complexity, account lockout |
| Authorization | Control what users can do | RBAC, ABAC, least privilege, permission inheritance, API authorization |
| Session Management | Secure user sessions | Session timeout, secure cookies, token expiration, concurrent session limits |
| User Lifecycle | Manage user access over time | Automated provisioning (SCIM), just-in-time provisioning, periodic access reviews, prompt de-provisioning |
| Privileged Access | Control administrative access | Separate admin accounts, just-in-time elevation, privileged access workstations, session recording |
| API Security | Secure programmatic access | API key management, OAuth 2.0, rate limiting, API gateway, scope-based permissions |

### 10.2 Change Management

**Software development lifecycle (SDLC)** controls are critical for SOC 2:

| Control | Description | Implementation |
|---------|-------------|----------------|
| Version Control | Track all code changes | Git-based repositories, branch protection, commit signing |
| Code Review | Peer review before merge | Pull/merge request approvals, minimum reviewer requirements, automated checks |
| Separation of Duties | Developers cannot deploy their own code to production | Distinct roles for development, review, and deployment; automated CI/CD gates |
| Testing | Validate changes before deployment | Unit tests, integration tests, security testing (SAST/DAST), regression testing |
| Approval Gates | Authorize changes before production | CAB approval, release manager sign-off, automated policy checks |
| Deployment | Controlled release process | CI/CD pipelines, blue-green/canary deployments, rollback capability, deployment logs |
| Emergency Changes | Handle urgent production fixes | Defined emergency change process, retrospective review, post-deployment approval |
| Documentation | Record what changed and why | Release notes, change records, deployment logs, rollback plans |

### 10.3 Monitoring and Logging

**Comprehensive monitoring and logging** demonstrates operational awareness:

| Control | Description | Implementation |
|---------|-------------|----------------|
| Application Logging | Record application events | Structured logging, audit trails, user action logging, error logging |
| Infrastructure Monitoring | Monitor system health | CPU, memory, disk, network monitoring; auto-scaling triggers; capacity alerts |
| Security Monitoring | Detect security events | SIEM integration, anomaly detection, failed login monitoring, privilege escalation alerts |
| Availability Monitoring | Track uptime and performance | Synthetic monitoring, real user monitoring, status page, SLA tracking |
| Log Management | Centralize and protect logs | Centralized log aggregation, tamper protection, retention (90+ days), access controls on logs |
| Alerting | Notify on-call personnel | Defined alert thresholds, escalation paths, on-call rotation, alert fatigue management |

### 10.4 Incident Response

**A mature incident response capability** is expected:

| Phase | Activities | Evidence |
|-------|-----------|----------|
| **Preparation** | Incident response plan, runbooks, team training, communication templates | Documented IRP, training records, tabletop exercises |
| **Detection** | Monitoring alerts, user reports, threat intelligence, automated detection | Alert logs, detection rules, monitoring dashboards |
| **Triage** | Severity classification, initial assessment, scope determination | Triage procedures, severity matrix, initial response records |
| **Containment** | Isolate affected systems, preserve evidence, limit blast radius | Containment actions documented, forensic preservation |
| **Eradication** | Remove threat, patch vulnerabilities, harden systems | Root cause analysis, remediation actions |
| **Recovery** | Restore services, verify integrity, monitor for recurrence | Recovery procedures, verification testing, enhanced monitoring |
| **Post-Incident** | Lessons learned, process improvements, stakeholder communication | Post-mortem reports, action items, customer notifications |

### 10.5 Data Protection

| Control | Description | Implementation |
|---------|-------------|----------------|
| Encryption in Transit | Protect data during transmission | TLS 1.2+, certificate management, HSTS, certificate pinning for mobile |
| Encryption at Rest | Protect stored data | AES-256 for databases and file storage, transparent data encryption, encrypted backups |
| Key Management | Securely manage encryption keys | HSM or cloud KMS, key rotation, separation of key management from data access |
| Data Backup | Protect against data loss | Automated backups, cross-region replication, point-in-time recovery, backup encryption |
| Data Disposal | Securely remove data | Cryptographic erasure, media sanitization (NIST 800-88), automated retention enforcement |
| Data Segregation | Isolate customer data | Tenant isolation (logical or physical), database-per-tenant or schema-per-tenant, network isolation |

### 10.6 Vulnerability Management

| Control | Description | Implementation |
|---------|-------------|----------------|
| Vulnerability Scanning | Identify known vulnerabilities | Regular automated scanning (at least quarterly), authenticated scans, scan all environments |
| Penetration Testing | Simulate real attacks | Annual third-party penetration test, web application testing, API testing, remediation tracking |
| Dependency Management | Manage third-party libraries | Software composition analysis (SCA), automated dependency updates, license compliance |
| Patch Management | Apply security patches | Defined patch SLAs (critical: 24-72 hours, high: 7-14 days), automated patching where possible |
| Security Code Review | Find vulnerabilities in code | Static analysis (SAST), dynamic analysis (DAST), manual security code review for critical components |

---

## 11. Specific Considerations for Mendix and Low-Code Platforms

### 11.1 Shared Responsibility Model

When building applications on Mendix or similar low-code platforms, compliance follows a **shared responsibility model**:

```
+------------------------------------------+
|        Customer Responsibilities          |
|  (Application developer / your org)       |
|  - Application logic and security         |
|  - Data handling within the application   |
|  - User access management                 |
|  - Custom code security                   |
|  - Business process compliance            |
|  - Application-level monitoring           |
+------------------------------------------+
|        Platform Responsibilities          |
|  (Mendix / Siemens)                       |
|  - Platform infrastructure security       |
|  - Runtime environment                    |
|  - Platform-level encryption              |
|  - Platform availability (SLA)            |
|  - Physical and network security          |
|  - Platform SOC 2 compliance              |
+------------------------------------------+
|     Infrastructure Responsibilities       |
|  (Cloud Provider: AWS, Azure, etc.)       |
|  - Physical data center security          |
|  - Network infrastructure                 |
|  - Hypervisor and hardware security       |
|  - Cloud provider SOC 2 compliance        |
+------------------------------------------+
```

> **Key point:** Mendix (as part of Siemens) maintains its own SOC 2 compliance for the platform. However, organizations building applications on Mendix are responsible for the controls within their applications and organizational practices. You cannot simply rely on Mendix's SOC 2 report -- you must have your own controls for the application layer.

### 11.2 Mendix-Specific Controls

#### Access Control in Mendix Applications

| Control Area | Mendix Implementation | SOC 2 Relevance |
|-------------|----------------------|-----------------|
| **User Roles** | Define module roles and user roles in the Mendix Security model | CC6.1, CC6.3 -- Logical access security, authorization |
| **Entity Access** | Configure entity access rules per role | CC6.1 -- Restrict access to data |
| **Page Access** | Set page and microflow access per role | CC6.1 -- Restrict access to functionality |
| **SSO Integration** | SAML 2.0 / OIDC module for enterprise SSO | CC6.1, CC6.2 -- Centralized authentication |
| **MFA** | Integrate with identity provider MFA (e.g., Azure AD, Okta) | CC6.1 -- Multi-factor authentication |
| **Password Policies** | Configure password complexity, expiration, lockout in Mendix | CC6.1 -- Credential management |
| **SCIM Provisioning** | Automate user lifecycle via SCIM integration | CC6.2, CC6.3 -- User provisioning/de-provisioning |
| **API Security** | Published REST/OData service authentication and authorization | CC6.6 -- Protect against external threats |

#### Change Management in Mendix

| Control Area | Mendix Implementation | SOC 2 Relevance |
|-------------|----------------------|-----------------|
| **Version Control** | Mendix built-in Team Server (SVN/Git) | CC8.1 -- Track and manage changes |
| **Branch Management** | Feature branches, main line development | CC8.1 -- Controlled change process |
| **Code Review** | Mendix peer review before merge to main | CC8.1 -- Approval of changes |
| **Environments** | Separate Development, Acceptance, Production environments | CC8.1 -- Testing before production |
| **Deployment** | Mendix Cloud deployment pipeline with approval gates | CC8.1 -- Authorized deployment |
| **Rollback** | Mendix Cloud supports rollback to previous versions | CC8.1 -- Recovery from failed changes |
| **Custom Java/JavaScript** | Security review of custom code (not generated by the platform) | CC8.1, CC6.8 -- Secure development |

#### Data Protection in Mendix

| Control Area | Mendix Implementation | SOC 2 Relevance |
|-------------|----------------------|-----------------|
| **Encryption in Transit** | HTTPS enforced (TLS 1.2+) by Mendix Cloud | CC6.7 -- Protect data in transmission |
| **Encryption at Rest** | Mendix Cloud database encryption | CC6.1 -- Protect stored data |
| **Data Segregation** | Separate database per application in Mendix Cloud | CC6.1 -- Tenant isolation |
| **Backups** | Mendix Cloud automated backups with configurable retention | A1.2 -- Backup infrastructure |
| **File Storage** | Mendix Cloud encrypted file storage (S3-backed) | CC6.1 -- Protect file data |
| **Data Export** | Control export capabilities through microflow security | C1.1 -- Protect confidential information |
| **Data Retention** | Implement scheduled events for data cleanup per retention policy | P4.1, P4.2 -- Retention and disposal |

#### Monitoring and Logging in Mendix

| Control Area | Mendix Implementation | SOC 2 Relevance |
|-------------|----------------------|-----------------|
| **Application Logs** | Mendix runtime logging, custom log nodes | CC7.1, CC7.2 -- Detection and monitoring |
| **Audit Trails** | Mendix Audit Trail module for entity change tracking | CC7.1 -- Monitoring user actions |
| **Metrics** | Mendix Cloud monitoring (Datadog integration available) | CC7.2, A1.1 -- System monitoring |
| **Alerts** | Configure alerts for application health and errors | CC7.2 -- Anomaly detection |
| **APM** | Application Performance Monitor in Mendix Cloud | A1.1 -- Performance monitoring |
| **Custom Logging** | Java action logging for security-relevant events | CC7.1 -- Security event logging |

### 11.3 Low-Code Specific Challenges

| Challenge | Description | Mitigation |
|-----------|-------------|------------|
| **Generated Code Review** | Auditors may question how platform-generated code is secured | Reference Mendix platform SOC 2 report; document custom code review processes |
| **Custom Widget Security** | Custom JavaScript widgets may introduce vulnerabilities | Security review of all custom widgets, dependency scanning, content security policy |
| **Marketplace Module Risk** | Marketplace modules are third-party code | Vet marketplace modules, review source when available, maintain an approved module list |
| **Platform Dependency** | Heavy reliance on platform vendor's security | Document shared responsibility model, review Mendix SOC 2 report, contractual security requirements |
| **Limited Infrastructure Control** | Less control over underlying infrastructure in Mendix Cloud | Leverage Mendix Cloud security features, document what Mendix handles vs. what you handle |
| **Citizen Developer Risk** | Non-professional developers may introduce security issues | Security training for all developers, mandatory security review process, security guardrails |
| **Complex Integrations** | Mendix apps often integrate with many external systems | Secure integration patterns, API gateway, certificate management, credential vaulting |

### 11.4 Mendix Cloud vs. Private Cloud Considerations

| Aspect | Mendix Cloud | Private Cloud (Kubernetes) |
|--------|-------------|--------------------------|
| **Infrastructure controls** | Mendix responsibility | Your responsibility |
| **Platform patching** | Mendix responsibility | Shared (Mendix runtime + your infrastructure) |
| **Network security** | Mendix manages, you configure | Full responsibility |
| **Database management** | Mendix manages | Your responsibility |
| **Backup management** | Mendix automated | Your responsibility |
| **SOC 2 scope** | Smaller (application-layer focus) | Larger (includes infrastructure) |
| **Compliance effort** | Lower | Higher |

---

## 12. Key Compliance Checklist for Application Developers

### 12.1 Pre-Audit Checklist

#### Governance and Documentation

- [ ] Information Security Policy documented and approved by management
- [ ] Risk assessment completed within the last 12 months
- [ ] Risk register maintained with treatment plans for identified risks
- [ ] Roles and responsibilities for security documented (RACI matrix)
- [ ] Security awareness training completed by all employees (annually)
- [ ] Board or executive management oversight of security program documented
- [ ] Code of conduct / ethics policy signed by all employees

#### Access Controls

- [ ] Multi-factor authentication (MFA) enforced for all production access
- [ ] Single Sign-On (SSO) implemented for enterprise applications
- [ ] Role-based access control (RBAC) implemented in the application
- [ ] Least privilege principle enforced across all systems
- [ ] Quarterly access reviews performed and documented
- [ ] Automated user provisioning and de-provisioning (SCIM preferred)
- [ ] Offboarding process includes timely access revocation (same-day)
- [ ] Privileged access managed with just-in-time elevation or PAM solution
- [ ] Service account access reviewed and rotated regularly
- [ ] Default accounts disabled or removed from all systems

#### Change Management and SDLC

- [ ] All code changes tracked in version control (Git)
- [ ] Branch protection rules enforced (no direct commits to main/production branches)
- [ ] Code review required before merge (minimum one reviewer)
- [ ] Separation of duties: developers cannot approve their own changes
- [ ] Automated CI/CD pipeline with security gates
- [ ] Static Application Security Testing (SAST) integrated into pipeline
- [ ] Dependency scanning (SCA) automated in build process
- [ ] Test environments separate from production with no production data
- [ ] Change approval documented (CAB or equivalent for significant changes)
- [ ] Rollback procedures documented and tested
- [ ] Emergency change process defined with retrospective review

#### Monitoring and Logging

- [ ] Centralized log aggregation in place (SIEM or equivalent)
- [ ] Security-relevant events logged (authentication, authorization, admin actions, data access)
- [ ] Log retention meets minimum requirements (90 days online, 1 year archived)
- [ ] Logs protected against tampering (immutable storage or integrity verification)
- [ ] Alerting configured for critical security events
- [ ] On-call rotation established with documented escalation procedures
- [ ] Application performance and availability monitoring active
- [ ] Regular log review process documented and performed

#### Data Protection

- [ ] Encryption in transit enforced (TLS 1.2+ minimum, TLS 1.3 preferred)
- [ ] Encryption at rest implemented for all data stores (databases, file storage, backups)
- [ ] Encryption key management documented (rotation, access controls, backup)
- [ ] Data classification policy defined and applied to all data assets
- [ ] Data retention and disposal schedules defined and automated
- [ ] Customer data segregation verified (logical or physical tenant isolation)
- [ ] No production data in non-production environments (or anonymized/masked)
- [ ] Secure data transfer mechanisms for sensitive data exchange

#### Vulnerability Management

- [ ] Vulnerability scanning performed at least quarterly (infrastructure and application)
- [ ] Annual penetration test conducted by independent third party
- [ ] Patch management process defined with SLAs by severity
- [ ] Dependency vulnerabilities tracked and remediated (Dependabot, Snyk, etc.)
- [ ] Vulnerability remediation tracked to closure with evidence

#### Incident Response

- [ ] Incident response plan documented, approved, and distributed
- [ ] Incident severity classification matrix defined
- [ ] Communication templates prepared (internal, customer, regulatory)
- [ ] Tabletop exercise or simulation conducted within last 12 months
- [ ] Post-incident review process defined (blameless post-mortem)
- [ ] Customer notification procedures align with contractual and regulatory requirements

#### Business Continuity and Disaster Recovery

- [ ] Business continuity plan (BCP) documented
- [ ] Disaster recovery plan (DRP) documented with RPO and RTO targets
- [ ] Backup procedures automated and monitored
- [ ] Backup restoration tested at least annually
- [ ] Failover procedures documented and tested
- [ ] DR test results documented with remediation of findings

#### Vendor Management

- [ ] Inventory of all third-party vendors and subservice organizations maintained
- [ ] Vendor risk assessments performed before engagement and annually thereafter
- [ ] SOC 2 reports or equivalent attestations collected from critical vendors
- [ ] Data processing agreements (DPAs) in place with vendors handling customer data
- [ ] Vendor access limited to minimum necessary and reviewed periodically

#### Human Resources

- [ ] Background checks performed for all employees (pre-hire)
- [ ] Confidentiality/NDA agreements signed by all employees and contractors
- [ ] Security awareness training completed at onboarding and annually
- [ ] Onboarding process includes security briefing and policy acknowledgment
- [ ] Offboarding process includes exit interview, access revocation, asset return

### 12.2 Application-Specific Checklist

- [ ] Application security model reviewed and documented
- [ ] All API endpoints authenticated and authorized
- [ ] Input validation implemented for all user inputs
- [ ] Output encoding implemented to prevent XSS
- [ ] SQL injection protection verified (parameterized queries, ORM)
- [ ] CSRF protection implemented for state-changing operations
- [ ] Rate limiting implemented on authentication and sensitive endpoints
- [ ] Session management configured securely (timeout, secure cookies, token rotation)
- [ ] Error handling does not expose sensitive information (stack traces, internal paths)
- [ ] File upload validation and restrictions in place
- [ ] Audit trail captures user actions on sensitive data and administrative operations
- [ ] Application health check endpoints configured for monitoring
- [ ] Graceful degradation and error handling for downstream service failures

---

## 13. Cost and Timeline Expectations

### 13.1 Cost Breakdown

| Cost Category | SOC 2 Type I | SOC 2 Type II | Notes |
|--------------|-------------|--------------|-------|
| **Readiness assessment** | $10,000 - $30,000 | $10,000 - $30,000 | Can be performed by consulting firm or auditor (within independence rules) |
| **Gap remediation** | $20,000 - $100,000+ | $20,000 - $100,000+ | Varies dramatically based on current maturity; includes tools, personnel, and process changes |
| **Compliance automation platform** | $10,000 - $50,000/year | $10,000 - $50,000/year | Vanta, Drata, Secureframe, Thoropass, Sprinto, etc. Significantly reduces evidence collection effort |
| **Audit fees** | $20,000 - $60,000 | $30,000 - $100,000 | Varies by auditor, scope (number of criteria), organization size, and complexity |
| **Internal personnel time** | Significant | Significant | Security champion, engineering time for control implementation, evidence collection |
| **Penetration testing** | $10,000 - $50,000 | $10,000 - $50,000 | Annual requirement; scope-dependent |
| **Total (first year)** | **$70,000 - $290,000+** | **$80,000 - $330,000+** | Wide range based on starting maturity and organization size |
| **Annual renewal** | N/A | $40,000 - $150,000 | Typically lower in subsequent years as processes mature |

> **Note:** These figures represent typical ranges for small-to-mid-size software companies (10-200 employees). Larger organizations or those with complex infrastructure may see higher costs. Startups leveraging compliance automation platforms often achieve SOC 2 at the lower end of these ranges.

### 13.2 Timeline Expectations

#### First-Time SOC 2 (Type I Path)

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Readiness assessment | 2-4 weeks | Month 1 |
| Gap analysis | 2-4 weeks | Month 1-2 |
| Remediation and implementation | 2-4 months | Month 2-6 |
| Type I audit fieldwork | 4-6 weeks | Month 6-8 |
| Report issuance | 2-4 weeks | Month 8-9 |
| **Total to Type I report** | **6-9 months** | |

#### First-Time SOC 2 (Type II Path)

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Readiness assessment | 2-4 weeks | Month 1 |
| Gap analysis | 2-4 weeks | Month 1-2 |
| Remediation and implementation | 2-4 months | Month 2-6 |
| Observation period (controls operating) | 6-12 months | Month 6-18 |
| Type II audit fieldwork | 6-10 weeks | Month 18-20 |
| Report issuance | 2-4 weeks | Month 20-21 |
| **Total to Type II report** | **12-21 months** | |

#### Accelerated Path (with compliance automation)

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Platform setup and integration | 2-4 weeks | Month 1 |
| Gap analysis (platform-assisted) | 1-2 weeks | Month 1 |
| Remediation (platform-guided) | 1-3 months | Month 2-4 |
| Type I audit | 3-4 weeks | Month 4-5 |
| **Type I report** | **3-5 months** | |
| Observation period for Type II | 3-6 months | Month 5-11 |
| **Type II report** | **8-12 months** | |

### 13.3 Factors Affecting Cost and Timeline

**Factors that increase cost and timeline:**
- Low starting maturity (few existing policies, controls, or documentation)
- Large number of systems in scope
- Complex architecture (multi-cloud, hybrid)
- Multiple Trust Services Criteria selected
- Large number of employees
- Regulated industry overlays (HIPAA, PCI, FedRAMP)
- Many subservice organizations to evaluate

**Factors that decrease cost and timeline:**
- Existing security program and documentation
- Compliance automation platform adoption
- Small team and simple architecture
- Cloud-native infrastructure with built-in controls
- Prior SOC 1 or ISO 27001 certification
- Experienced internal security team

---

## 14. Continuous Compliance vs. Point-in-Time

### 14.1 The Problem with Point-in-Time

A SOC 2 Type II report covers a specific observation period (typically 12 months). Some organizations make the mistake of treating compliance as a periodic event:

```
Compliant -----> Audit Period -----> Report -----> Compliance Drift -----> Scramble -----> Audit Period
     ^                                                                         |
     |_________________________________________________________________________|
                              The "Compliance Sprint" Anti-Pattern
```

**Problems with this approach:**
- Controls degrade between audit periods ("compliance drift").
- Evidence gaps emerge that are difficult to fill retroactively.
- Staff turnover leads to knowledge loss about control requirements.
- Audit preparation becomes a stressful, resource-intensive project.
- Exceptions are more likely when controls are not consistently operated.
- Customer confidence erodes if they detect inconsistent practices.

### 14.2 Continuous Compliance Model

**Continuous compliance** means operating controls consistently throughout the year, with real-time monitoring and evidence collection:

```
Compliant -----> Continuous Monitoring -----> Continuous Evidence -----> Audit = Validation
     ^                    |                          |                         |
     |                    v                          v                         |
     |            Real-time alerts           Automated collection              |
     |_________________________________________________________________________|
                              The Continuous Compliance Model
```

### 14.3 Implementing Continuous Compliance

#### Compliance Automation Platforms

Modern compliance platforms continuously monitor your controls and collect evidence:

| Platform | Key Features |
|----------|-------------|
| Vanta | Automated evidence collection, continuous monitoring, 200+ integrations, audit management |
| Drata | Continuous monitoring, automated evidence, risk management, trust center |
| Secureframe | Automated compliance, personnel management, vendor risk, training |
| Thoropass (formerly Laika) | Compliance management, audit facilitation, framework mapping |
| Sprinto | Automated compliance, risk management, continuous monitoring |

#### Key Practices

1. **Automated evidence collection:** Integrate compliance tools with your systems (cloud providers, identity providers, code repositories, HR systems) to continuously collect evidence.

2. **Continuous monitoring:** Deploy monitoring for control effectiveness:
   - MFA enforcement status
   - Access review completion
   - Encryption configuration
   - Vulnerability scan results
   - Training completion rates
   - Policy acknowledgment status

3. **Real-time alerting:** Configure alerts for control deviations:
   - MFA disabled for a user
   - Unencrypted data store detected
   - Missing code review approval
   - Failed background check
   - Overdue access review

4. **Regular cadence activities:**

   | Activity | Frequency |
   |----------|-----------|
   | Access reviews | Quarterly |
   | Risk assessment | Annually (with quarterly updates for significant changes) |
   | Penetration testing | Annually |
   | Vulnerability scanning | At least quarterly (monthly or continuous preferred) |
   | Security awareness training | Annually (with periodic phishing simulations) |
   | Business continuity/DR testing | Annually |
   | Policy review and update | Annually |
   | Vendor risk reassessment | Annually |
   | Incident response tabletop | Annually |
   | Backup restoration test | Annually |

5. **Compliance reviews:** Monthly or quarterly internal review of compliance posture:
   - Review monitoring dashboard
   - Address any open findings or exceptions
   - Verify evidence completeness
   - Track remediation of identified issues
   - Prepare for upcoming scheduled activities

### 14.4 Benefits of Continuous Compliance

| Benefit | Description |
|---------|-------------|
| **Reduced audit burden** | Evidence is already collected; audit becomes validation rather than evidence gathering |
| **Fewer exceptions** | Continuous monitoring catches issues before they become audit findings |
| **Faster audits** | Auditors can access a well-organized evidence repository, reducing fieldwork time |
| **Lower risk** | Consistent control operation means actual security posture matches the report |
| **Customer confidence** | Demonstrable continuous compliance builds deeper trust than annual snapshots |
| **Multi-framework leverage** | Continuous compliance data maps to multiple frameworks (ISO 27001, HIPAA, PCI DSS) |
| **Cost reduction over time** | Initial investment in automation pays for itself through reduced annual audit effort |

---

## 15. Frequently Asked Questions

**Q: Is SOC 2 legally required?**
A: SOC 2 is not a legal requirement per se. However, it is often contractually required by enterprise customers and effectively necessary for selling to regulated industries. Some regulations (SOX, HIPAA) expect third-party assurance that SOC reports help satisfy.

**Q: How long is a SOC 2 report valid?**
A: A SOC 2 report does not have an explicit expiration date, but it covers a specific point in time (Type I) or period (Type II). Industry practice considers reports current for 12 months from the end of the observation period. Customers typically require a report less than 12 months old.

**Q: Can we share our SOC 2 report with anyone?**
A: SOC 2 reports are restricted-use reports and should only be shared under NDA with specified parties (customers, prospects, regulators). Use a SOC 3 report for public distribution. Many organizations use a "trust center" or "security portal" where prospects can request access after signing an NDA.

**Q: What happens if we get exceptions in our SOC 2 report?**
A: Exceptions are documented in the report and do not necessarily result in a qualified opinion. The auditor evaluates whether exceptions are isolated, whether compensating controls exist, and whether they materially affect the overall control environment. Some exceptions are common and acceptable if properly addressed.

**Q: Do we need SOC 2 if our cloud provider (AWS/Azure/GCP) has SOC 2?**
A: Yes. Your cloud provider's SOC 2 covers their infrastructure responsibilities. You are responsible for the controls within your application, your organizational practices, and your use of the cloud platform. This is the shared responsibility model.

**Q: Can we use Mendix's SOC 2 report instead of getting our own?**
A: No. Mendix's SOC 2 report covers the platform. You need your own SOC 2 report covering your application controls, organizational practices, and the controls you implement on top of the platform. However, you can reference Mendix as a "subservice organization" and cite their SOC 2 report for the controls they manage.

**Q: How does SOC 2 relate to ISO 27001?**
A: ISO 27001 is an international standard for information security management systems (ISMS) that results in a certification. SOC 2 is an attestation by a CPA firm. They share many control requirements (approximately 80% overlap). Organizations often pursue both -- ISO 27001 for international markets and SOC 2 for North American enterprise customers. Compliance automation platforms can help manage both simultaneously.

**Q: What is the difference between SOC 2 and SOC for Cybersecurity?**
A: SOC for Cybersecurity is a newer framework from the AICPA designed for organization-wide cybersecurity risk management reporting. It uses the AICPA's Cybersecurity Risk Management Framework rather than the Trust Services Criteria. It is less common than SOC 2 and has a broader organizational scope.

**Q: Can a startup achieve SOC 2?**
A: Yes. Startups regularly achieve SOC 2, often within 3-6 months using compliance automation platforms. The key is starting with good security foundations (cloud-native, SSO/MFA from day one, version control, infrastructure-as-code). Many VCs and enterprise customers expect SOC 2 from even early-stage startups.

---

## 16. Glossary

| Term | Definition |
|------|-----------|
| **AICPA** | American Institute of Certified Public Accountants; the organization that developed and maintains the SOC framework |
| **Attestation** | A formal assertion by a CPA firm about the subject matter (controls) based on their examination |
| **Audit Window / Observation Period** | The time period covered by a Type II report (typically 6-12 months) |
| **CAB** | Change Advisory Board; a group that reviews and approves significant changes to production systems |
| **CCPA** | California Consumer Privacy Act; state privacy law relevant to Privacy criteria |
| **Common Criteria (CC)** | The nine control series (CC1-CC9) that make up the Security Trust Services Criteria |
| **Complementary User Entity Controls (CUECs)** | Controls that the service organization assumes its customers have in place |
| **Complementary Subservice Organization Controls (CSOCs)** | Controls that the service organization assumes its subservice organizations (vendors) have in place |
| **CPA** | Certified Public Accountant; the only professionals authorized to issue SOC reports |
| **DPA** | Data Processing Agreement; a contractual document governing how a processor handles personal data |
| **Exception** | An instance where a control did not operate as designed during the audit period |
| **GDPR** | General Data Protection Regulation; EU privacy regulation relevant to Privacy criteria |
| **ISAE 3402** | International Standard on Assurance Engagements; the international equivalent of SOC 1 |
| **ISAE 3000** | International Standard on Assurance Engagements for non-financial subject matter; international equivalent of SOC 2 |
| **Management Assertion** | A written statement by management about the fairness of the system description and the suitability of controls |
| **PAM** | Privileged Access Management; tools and processes for managing administrative access |
| **Qualified Opinion** | An auditor opinion indicating material issues with controls (vs. unqualified/clean opinion) |
| **RBAC** | Role-Based Access Control; access model where permissions are assigned to roles rather than individuals |
| **RPO** | Recovery Point Objective; maximum acceptable data loss measured in time |
| **RTO** | Recovery Time Objective; maximum acceptable downtime before services must be restored |
| **SCIM** | System for Cross-domain Identity Management; protocol for automated user provisioning |
| **SDLC** | Software Development Life Cycle; the process for planning, developing, testing, and deploying software |
| **SIEM** | Security Information and Event Management; centralized security monitoring platform |
| **SOC** | System and Organization Controls; the framework for examining controls at a service organization |
| **SOX** | Sarbanes-Oxley Act; U.S. law requiring internal controls over financial reporting |
| **SSAE 18** | Statement on Standards for Attestation Engagements No. 18; the standard governing SOC 1 examinations |
| **Subservice Organization** | A third-party vendor used by the service organization that is part of the system (e.g., AWS, Mendix Cloud) |
| **System Description** | The written description of the service organization's system, including infrastructure, software, people, procedures, and data |
| **Trust Services Criteria (TSC)** | The five categories of criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy) used in SOC 2 and SOC 3 |
| **Type I Report** | An examination of the design of controls at a specific point in time |
| **Type II Report** | An examination of the design and operating effectiveness of controls over a period of time |
| **User Entity** | The customer of the service organization whose operations depend on the service |

---

*This document is intended for informational purposes and should not be construed as legal or audit advice. Organizations should consult with a qualified CPA firm and legal counsel when pursuing SOC compliance.*
