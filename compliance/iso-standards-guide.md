# ISO Compliance Standards for Software & Information Security

## A Comprehensive Guide for Enterprise Application Development

**Version:** 1.0
**Date:** February 2026
**Classification:** Public

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [ISO 27001 -- Information Security Management System](#2-iso-27001----information-security-management-system)
3. [ISO 27002 -- Code of Practice for Information Security Controls](#3-iso-27002----code-of-practice-for-information-security-controls)
4. [ISO 27017 -- Cloud Security](#4-iso-27017----cloud-security)
5. [ISO 27018 -- PII Protection in Public Clouds](#5-iso-27018----pii-protection-in-public-clouds)
6. [ISO 27701 -- Privacy Information Management](#6-iso-27701----privacy-information-management)
7. [ISO 9001 -- Quality Management System](#7-iso-9001----quality-management-system)
8. [Applying ISO Standards to Software Applications](#8-applying-iso-standards-to-software-applications)
9. [Considerations for Mendix and Low-Code Platforms](#9-considerations-for-mendix-and-low-code-platforms)
10. [Compliance Checklist for Application Developers](#10-compliance-checklist-for-application-developers)
11. [Certification vs. Compliance](#11-certification-vs-compliance)
12. [Cost and Timeline Expectations](#12-cost-and-timeline-expectations)
13. [ISO and SOC 2 -- How They Relate](#13-iso-and-soc-2----how-they-relate)
14. [Appendix A -- Glossary](#appendix-a----glossary)
15. [Appendix B -- Cross-Reference Matrix](#appendix-b----cross-reference-matrix)

---

## 1. Executive Summary

ISO (International Organization for Standardization) publishes internationally recognized standards that provide frameworks for managing information security, privacy, quality, and cloud-specific risks. For organizations developing and operating software -- whether using traditional development or low-code platforms -- ISO standards offer a structured, auditable approach to demonstrating security maturity and regulatory compliance to enterprise customers, partners, and regulators.

This document covers the following standards in detail:

| Standard | Full Title | Current Version | Focus |
|----------|-----------|----------------|-------|
| ISO/IEC 27001 | Information Security Management Systems -- Requirements | 2022 | ISMS framework and certification |
| ISO/IEC 27002 | Information Security Controls | 2022 | Control implementation guidance |
| ISO/IEC 27017 | Code of Practice for Cloud Services | 2015 | Cloud-specific security controls |
| ISO/IEC 27018 | Protection of PII in Public Clouds | 2019 | Cloud privacy for PII processors |
| ISO/IEC 27701 | Privacy Information Management | 2019 | PIMS extension to 27001/27002 |
| ISO 9001 | Quality Management Systems | 2015 | Quality management framework |

**Key takeaway:** ISO 27001 is the foundational standard. All other ISO 27000-family standards extend or supplement it. An organization typically starts with ISO 27001 certification and then layers additional standards as business requirements demand.

---

## 2. ISO 27001 -- Information Security Management System

### 2.1 What It Is and Its Purpose

ISO/IEC 27001:2022 is the world's most widely adopted international standard for information security management. It specifies the requirements for establishing, implementing, maintaining, and continually improving an **Information Security Management System (ISMS)** within the context of an organization.

**Purpose:**

- Provide a systematic approach to managing sensitive company and customer information
- Ensure the confidentiality, integrity, and availability (CIA triad) of information assets
- Establish a risk-based approach to information security rather than prescriptive technical controls
- Demonstrate to customers, regulators, and stakeholders that information security is managed to an internationally recognized standard
- Enable third-party certification by accredited certification bodies

**Key characteristics:**

- It is a **management system standard**, not a technical checklist -- it requires governance, leadership commitment, risk management processes, and continuous improvement
- It is **risk-based** -- organizations identify their own risks and select controls appropriate to their context
- It is **certifiable** -- independent auditors can verify conformance and issue formal certificates
- The 2022 revision restructured Annex A controls from 14 domains (2013 version) to 4 themes with 93 controls

### 2.2 The ISMS Framework

The ISMS is the overarching management framework that governs how an organization protects its information assets. It operates on the **Plan-Do-Check-Act (PDCA)** cycle:

```
    +-----------+
    |   PLAN    |  Establish ISMS policy, objectives, processes,
    |           |  and procedures relevant to managing risk
    +-----+-----+
          |
          v
    +-----+-----+
    |    DO     |  Implement and operate the ISMS policy,
    |           |  controls, processes, and procedures
    +-----+-----+
          |
          v
    +-----+-----+
    |   CHECK   |  Assess and measure process performance
    |           |  against policy, objectives, and practical
    |           |  experience; report results to management
    +-----+-----+
          |
          v
    +-----+-----+
    |    ACT    |  Take corrective and preventive actions,
    |           |  based on results of internal audit and
    |           |  management review, to achieve continual
    |           |  improvement of the ISMS
    +-----------+
```

**The ISMS encompasses:**

- **Scope definition** -- which parts of the organization, which information assets, which locations
- **Information security policy** -- top-level statement of intent and direction
- **Risk assessment methodology** -- how risks are identified, analyzed, and evaluated
- **Risk treatment plan** -- how identified risks are addressed (mitigate, accept, transfer, avoid)
- **Statement of Applicability (SoA)** -- which Annex A controls are selected and why, and which are excluded with justification
- **Internal audit program** -- systematic review of ISMS effectiveness
- **Management review** -- top management evaluation of ISMS performance
- **Continual improvement process** -- addressing nonconformities and optimizing the ISMS

### 2.3 Mandatory Clauses (4--10)

The normative body of ISO 27001:2022 consists of Clauses 4 through 10. All requirements in these clauses are mandatory for certification. They follow the **Annex SL high-level structure** shared across all ISO management system standards.

#### Clause 4 -- Context of the Organization

| Subclause | Requirement |
|-----------|-------------|
| 4.1 Understanding the organization and its context | Determine external and internal issues relevant to the ISMS purpose and objectives |
| 4.2 Understanding the needs and expectations of interested parties | Identify stakeholders (customers, regulators, employees, partners) and their information security requirements |
| 4.3 Determining the scope of the ISMS | Define boundaries and applicability; document the scope |
| 4.4 Information security management system | Establish, implement, maintain, and continually improve the ISMS |

**Practical implication:** You must formally document who your stakeholders are, what they expect regarding security, and precisely which systems, processes, locations, and assets fall within the ISMS boundary.

#### Clause 5 -- Leadership

| Subclause | Requirement |
|-----------|-------------|
| 5.1 Leadership and commitment | Top management must demonstrate leadership by ensuring ISMS policy and objectives are established, resources are available, and the ISMS achieves its intended outcomes |
| 5.2 Policy | Establish an information security policy appropriate to the organization's purpose, providing a framework for setting objectives |
| 5.3 Organizational roles, responsibilities and authorities | Assign and communicate responsibilities for ISMS roles |

**Practical implication:** Information security cannot be delegated solely to IT. Executive leadership must be visibly engaged, allocate budget, and formally assign ISMS responsibilities.

#### Clause 6 -- Planning

| Subclause | Requirement |
|-----------|-------------|
| 6.1 Actions to address risks and opportunities | Define and apply a risk assessment process; determine risk treatment options; produce a Statement of Applicability |
| 6.1.2 Information security risk assessment | Establish criteria for risk acceptance, identify risks to CIA, analyze likelihood and impact, evaluate against acceptance criteria |
| 6.1.3 Information security risk treatment | Select appropriate controls (referencing Annex A), produce a risk treatment plan, obtain risk owner approval for residual risks |
| 6.2 Information security objectives and planning | Set measurable security objectives at relevant functions and levels; plan how to achieve them |
| 6.3 Planning of changes | When changes to the ISMS are needed, carry them out in a planned manner |

**Practical implication:** This is the core of the risk-based approach. Organizations must maintain a living risk register, conduct periodic risk assessments, and map selected controls back to identified risks.

#### Clause 7 -- Support

| Subclause | Requirement |
|-----------|-------------|
| 7.1 Resources | Determine and provide resources needed for the ISMS |
| 7.2 Competence | Ensure persons performing ISMS work are competent through education, training, or experience |
| 7.3 Awareness | Persons working under the organization's control must be aware of the security policy, their contribution, and implications of nonconformance |
| 7.4 Communication | Determine internal and external communication needs (what, when, with whom, who communicates, how) |
| 7.5 Documented information | Create, update, and control documented information required by the ISMS |

**Practical implication:** Security awareness training programs, documented procedures, competency records, and communication plans are all required artifacts.

#### Clause 8 -- Operation

| Subclause | Requirement |
|-----------|-------------|
| 8.1 Operational planning and control | Plan, implement, and control processes needed to meet ISMS requirements |
| 8.2 Information security risk assessment | Perform risk assessments at planned intervals or when significant changes occur |
| 8.3 Information security risk treatment | Implement the risk treatment plan |

**Practical implication:** This is the "Do" phase -- actually executing the controls, running the risk assessments, and operating the ISMS day-to-day.

#### Clause 9 -- Performance Evaluation

| Subclause | Requirement |
|-----------|-------------|
| 9.1 Monitoring, measurement, analysis and evaluation | Determine what needs to be monitored and measured, methods, timing, and who analyzes results |
| 9.2 Internal audit | Conduct internal audits at planned intervals to confirm the ISMS conforms to requirements and is effectively implemented |
| 9.3 Management review | Top management must review the ISMS at planned intervals to ensure continuing suitability, adequacy, and effectiveness |

**Practical implication:** You need defined KPIs/metrics, an internal audit program with qualified auditors, and scheduled management review meetings with documented minutes and action items.

#### Clause 10 -- Improvement

| Subclause | Requirement |
|-----------|-------------|
| 10.1 Continual improvement | Continually improve the suitability, adequacy, and effectiveness of the ISMS |
| 10.2 Nonconformity and corrective action | React to nonconformities, evaluate the need for corrective action, implement corrections, and review their effectiveness |

**Practical implication:** Maintain a nonconformity register, track corrective actions to closure, and demonstrate year-over-year improvement in security posture.

### 2.4 Annex A Controls (ISO 27001:2022)

The 2022 revision of ISO 27001 restructured the Annex A controls from 14 domains with 114 controls (2013 version) into **4 themes with 93 controls**. Eleven new controls were introduced.

#### 2.4.1 Organizational Controls (A.5) -- 37 Controls

These controls address security governance, policies, and organizational measures.

| Control ID | Control Name | Description |
|-----------|-------------|-------------|
| A.5.1 | Policies for information security | Define, approve, publish, and communicate a set of information security policies |
| A.5.2 | Information security roles and responsibilities | Define and allocate information security roles and responsibilities |
| A.5.3 | Segregation of duties | Conflicting duties and responsibilities shall be segregated |
| A.5.4 | Management responsibilities | Management shall require personnel to apply information security in accordance with policies |
| A.5.5 | Contact with authorities | Maintain appropriate contacts with relevant authorities |
| A.5.6 | Contact with special interest groups | Maintain contacts with specialist security groups and professional associations |
| A.5.7 | Threat intelligence | **(New in 2022)** Collect and analyze information about information security threats |
| A.5.8 | Information security in project management | Integrate information security into project management |
| A.5.9 | Inventory of information and associated assets | Develop and maintain an inventory of information and associated assets |
| A.5.10 | Acceptable use of information and associated assets | Rules for acceptable use and handling of information and assets |
| A.5.11 | Return of assets | Personnel and other interested parties shall return organizational assets on change or termination |
| A.5.12 | Classification of information | Classify information according to needs, considering CIA requirements |
| A.5.13 | Labelling of information | Develop and implement procedures for information labelling |
| A.5.14 | Information transfer | Transfer rules, agreements, or procedures for all types of transfer facilities |
| A.5.15 | Access control | Rules to control logical and physical access to information and assets |
| A.5.16 | Identity management | Full lifecycle of identity management |
| A.5.17 | Authentication information | Control allocation and management of authentication information |
| A.5.18 | Access rights | Provision, review, modify, and remove access rights to information and assets |
| A.5.19 | Information security in supplier relationships | Define and implement processes to manage security risks with supplier use |
| A.5.20 | Addressing information security within supplier agreements | Establish and agree upon relevant security requirements with each supplier |
| A.5.21 | Managing information security in the ICT supply chain | Define and implement processes to manage security risks in the ICT supply chain |
| A.5.22 | Monitoring, review and change management of supplier services | Monitor, review, evaluate, and manage changes in supplier security practices |
| A.5.23 | Information security for use of cloud services | **(New in 2022)** Establish processes for acquisition, use, management, and exit of cloud services |
| A.5.24 | Information security incident management planning and preparation | Plan and prepare for incident management |
| A.5.25 | Assessment and decision on information security events | Assess security events and decide if they are incidents |
| A.5.26 | Response to information security incidents | Respond to incidents in accordance with documented procedures |
| A.5.27 | Learning from information security incidents | Use knowledge gained from incidents to strengthen controls |
| A.5.28 | Collection of evidence | Establish procedures for identification, collection, acquisition, and preservation of evidence |
| A.5.29 | Information security during disruption | Plan how to maintain security during disruption |
| A.5.30 | ICT readiness for business continuity | **(New in 2022)** Plan, implement, maintain, and test ICT readiness for business continuity |
| A.5.31 | Legal, statutory, regulatory and contractual requirements | Identify and document compliance requirements |
| A.5.32 | Intellectual property rights | Implement procedures to protect intellectual property rights |
| A.5.33 | Protection of records | Protect records from loss, destruction, falsification, and unauthorized access |
| A.5.34 | Privacy and protection of PII | Identify and meet requirements regarding PII protection under applicable legislation |
| A.5.35 | Independent review of information security | Review the ISMS at planned intervals or when significant changes occur |
| A.5.36 | Compliance with policies, rules and standards | Regularly review compliance with information security policies and standards |
| A.5.37 | Documented operating procedures | Document operating procedures for information processing facilities |

#### 2.4.2 People Controls (A.6) -- 8 Controls

These controls address human resource security.

| Control ID | Control Name | Description |
|-----------|-------------|-------------|
| A.6.1 | Screening | Background verification checks on candidates prior to employment |
| A.6.2 | Terms and conditions of employment | Employment contracts shall state information security responsibilities |
| A.6.3 | Information security awareness, education and training | All personnel shall receive appropriate security awareness training |
| A.6.4 | Disciplinary process | A formal disciplinary process for personnel who commit a security breach |
| A.6.5 | Responsibilities after termination or change of employment | Information security responsibilities that remain valid after termination |
| A.6.6 | Confidentiality or non-disclosure agreements | Personnel and external parties shall sign confidentiality agreements |
| A.6.7 | Remote working | Implement security measures for remote working |
| A.6.8 | Information security event reporting | Provide a mechanism for personnel to report security events |

#### 2.4.3 Physical Controls (A.7) -- 14 Controls

These controls address physical and environmental security.

| Control ID | Control Name | Description |
|-----------|-------------|-------------|
| A.7.1 | Physical security perimeters | Define security perimeters to protect areas containing information |
| A.7.2 | Physical entry | Secure areas shall be protected by appropriate entry controls |
| A.7.3 | Securing offices, rooms and facilities | Design and apply physical security for offices, rooms, and facilities |
| A.7.4 | Physical security monitoring | **(New in 2022)** Continuously monitor premises for unauthorized physical access |
| A.7.5 | Protecting against physical and environmental threats | Design and apply protection against physical and environmental threats |
| A.7.6 | Working in secure areas | Design and apply security measures for working in secure areas |
| A.7.7 | Clear desk and clear screen | Define clear desk rules for papers and removable storage; clear screen rules for processing facilities |
| A.7.8 | Equipment siting and protection | Reduce risks from environmental threats and unauthorized access |
| A.7.9 | Security of assets off-premises | Protect off-premises assets |
| A.7.10 | Storage media | Manage storage media through their lifecycle |
| A.7.11 | Supporting utilities | Protect from power failures and disruptions |
| A.7.12 | Cabling security | Protect power and telecommunications cabling |
| A.7.13 | Equipment maintenance | Maintain equipment correctly to ensure availability and integrity |
| A.7.14 | Secure disposal or re-use of equipment | Securely erase or destroy data before equipment disposal |

#### 2.4.4 Technological Controls (A.8) -- 34 Controls

These controls address technical security measures.

| Control ID | Control Name | Description |
|-----------|-------------|-------------|
| A.8.1 | User endpoint devices | Protect information stored on, processed by, or accessible via user endpoint devices |
| A.8.2 | Privileged access rights | Restrict and manage allocation of privileged access rights |
| A.8.3 | Information access restriction | Restrict access to information in accordance with access control policy |
| A.8.4 | Access to source code | Manage access to source code, development tools, and software libraries |
| A.8.5 | Secure authentication | Implement secure authentication technologies and procedures |
| A.8.6 | Capacity management | Monitor and adjust resource use; project future capacity requirements |
| A.8.7 | Protection against malware | Implement protection against malware |
| A.8.8 | Management of technical vulnerabilities | Obtain information about technical vulnerabilities; evaluate and take appropriate measures |
| A.8.9 | Configuration management | **(New in 2022)** Establish, document, implement, monitor, and review configurations |
| A.8.10 | Information deletion | **(New in 2022)** Delete information when no longer required |
| A.8.11 | Data masking | **(New in 2022)** Use data masking in accordance with access control and business requirements |
| A.8.12 | Data leakage prevention | **(New in 2022)** Apply data leakage prevention measures to systems, networks, and devices |
| A.8.13 | Information backup | Maintain and regularly test backup copies of information, software, and systems |
| A.8.14 | Redundancy of information processing facilities | Implement sufficient redundancy to meet availability requirements |
| A.8.15 | Logging | Produce, store, protect, and analyze logs recording activities, exceptions, faults, and events |
| A.8.16 | Monitoring activities | **(New in 2022)** Monitor networks, systems, and applications for anomalous behavior |
| A.8.17 | Clock synchronization | Synchronize clocks of information processing systems to approved time sources |
| A.8.18 | Use of privileged utility programs | Restrict and tightly control use of utility programs that can override system controls |
| A.8.19 | Installation of software on operational systems | Implement procedures for controlling software installation |
| A.8.20 | Networks security | Secure, manage, and control networks to protect information in systems and applications |
| A.8.21 | Security of network services | Identify, implement, and monitor security mechanisms and service levels for network services |
| A.8.22 | Segregation of networks | Segregate groups of information services, users, and systems |
| A.8.23 | Web filtering | **(New in 2022)** Manage access to external websites to reduce exposure to malicious content |
| A.8.24 | Use of cryptography | Define and implement rules for effective use of cryptography |
| A.8.25 | Secure development life cycle | Establish and apply rules for secure development of software and systems |
| A.8.26 | Application security requirements | Identify, specify, and approve information security requirements for developing or acquiring applications |
| A.8.27 | Secure system architecture and engineering principles | Establish, document, maintain, and apply principles for engineering secure systems |
| A.8.28 | Secure coding | Apply secure coding principles to software development |
| A.8.29 | Security testing in development and acceptance | Define and implement security testing processes in the development life cycle |
| A.8.30 | Outsourced development | Direct, monitor, and review activities related to outsourced system development |
| A.8.31 | Separation of development, test and production environments | Separate and secure development, testing, and production environments |
| A.8.32 | Change management | Subject changes to information processing facilities and systems to change management procedures |
| A.8.33 | Test information | Appropriately select, protect, and manage test information |
| A.8.34 | Protection of information systems during audit testing | Plan and agree upon audit tests to minimize disruption to business processes |

### 2.5 Risk Assessment and Treatment

Risk management is the core engine of the ISMS. ISO 27001 does not prescribe a specific risk methodology but requires a systematic, repeatable approach.

#### Risk Assessment Process

```
Step 1: Establish Context
    |
    v
Step 2: Identify Risks
    - What assets exist? (information, systems, processes)
    - What threats apply? (hackers, malware, natural disasters, insider threats)
    - What vulnerabilities exist? (unpatched systems, weak passwords, misconfiguration)
    - What is the potential impact on CIA?
    |
    v
Step 3: Analyze Risks
    - Determine likelihood of each risk materializing
    - Determine impact/consequence if it does
    - Calculate risk level (typically Likelihood x Impact)
    |
    v
Step 4: Evaluate Risks
    - Compare against risk acceptance criteria
    - Prioritize risks requiring treatment
    |
    v
Step 5: Treat Risks
    - Modify (apply controls to reduce risk)
    - Retain/Accept (acknowledge and accept residual risk)
    - Avoid (eliminate the activity creating risk)
    - Share/Transfer (outsource or insure)
    |
    v
Step 6: Document and Monitor
    - Risk register
    - Statement of Applicability
    - Risk treatment plan
    - Ongoing monitoring and review
```

#### Statement of Applicability (SoA)

The SoA is one of the most critical documents in the ISMS. It must:

- List all 93 Annex A controls
- State whether each control is applicable or not
- Provide justification for inclusion or exclusion
- Reference the implementation status
- Map controls to the risks they address

#### Risk Acceptance

The organization must define risk acceptance criteria, and risk owners must formally approve:

- The risk treatment plan
- Any residual risk that remains after treatment

### 2.6 Certification Process

#### Stages of Certification

| Stage | Activity | Duration | Output |
|-------|----------|----------|--------|
| Preparation | Implement ISMS, conduct risk assessment, develop policies, deploy controls | 6--18 months | Operational ISMS |
| Stage 1 Audit | Certification body reviews ISMS documentation, confirms readiness for Stage 2 | 1--3 days on-site | Stage 1 audit report identifying gaps |
| Gap Remediation | Address any major findings from Stage 1 | 1--3 months | Updated documentation and controls |
| Stage 2 Audit | Certification body audits ISMS effectiveness, tests controls, interviews personnel | 3--10 days on-site (depending on scope) | Certification decision |
| Certificate Issuance | Certification body issues certificate (valid 3 years) | 2--4 weeks after Stage 2 | ISO 27001 certificate |
| Surveillance Audits | Annual audits (Years 1 and 2) to verify continued conformance | 1--3 days on-site per year | Surveillance audit report |
| Recertification | Full recertification audit in Year 3 | 3--8 days on-site | Renewed certificate |

#### Accredited Certification Bodies

Certification must be performed by an accredited certification body. Major accredited bodies include:

- BSI (British Standards Institution)
- Bureau Veritas
- DNV (Det Norske Veritas)
- TUV (Technischer Uberwachungsverein)
- SGS
- Schellman
- A-LIGN
- Coalfire

The accreditation body varies by country (e.g., UKAS in the UK, ANAB in the US, DAkkS in Germany, RvA in the Netherlands).

---

## 3. ISO 27002 -- Code of Practice for Information Security Controls

### 3.1 Relationship to ISO 27001

ISO/IEC 27002:2022 is the companion standard to ISO 27001. While ISO 27001 defines **what** must be done (the management system requirements and the list of controls in Annex A), ISO 27002 provides **how** to implement those controls through detailed implementation guidance.

**Key distinctions:**

| Aspect | ISO 27001 | ISO 27002 |
|--------|-----------|-----------|
| Nature | Requirements standard | Guidance standard |
| Certifiable | Yes | No (not independently certifiable) |
| Controls listed | 93 controls in Annex A (brief descriptions) | Same 93 controls with detailed guidance |
| Purpose | Define WHAT to implement | Explain HOW to implement |
| Mandatory | All clauses are mandatory for certification | Controls are selected based on risk assessment |
| Audience | Management, auditors, certification bodies | Security practitioners, implementers |

**The relationship works as follows:**

1. ISO 27001 Clause 6.1.3 requires organizations to select controls from Annex A
2. Annex A provides a one-paragraph description of each control
3. ISO 27002 provides multi-page guidance on implementing each of those same controls
4. Additional controls beyond Annex A may be drawn from ISO 27002 or other sources

### 3.2 Control Categories and Implementation Guidance

ISO 27002:2022 organizes the 93 controls into the same four themes as ISO 27001 Annex A. For each control, ISO 27002 provides:

- **Control statement** -- what the control achieves
- **Purpose** -- why the control is needed
- **Guidance** -- detailed implementation advice
- **Other information** -- additional context, cross-references

#### New in 2022: Control Attributes

ISO 27002:2022 introduced a taxonomy of **attributes** that can be assigned to each control for filtering and sorting:

| Attribute | Values |
|-----------|--------|
| Control type | Preventive, Detective, Corrective |
| Information security properties | Confidentiality, Integrity, Availability |
| Cybersecurity concepts | Identify, Protect, Detect, Respond, Recover |
| Operational capabilities | Governance, Asset Management, Information Protection, Human Resource Security, Physical Security, System and Network Security, Application Security, Secure Configuration, Identity and Access Management, Threat and Vulnerability Management, Continuity, Supplier Relationships Security, Legal and Compliance, Information Security Event Management, Information Security Assurance |
| Security domains | Governance and Ecosystem, Protection, Defence, Resilience |

These attributes enable organizations to create custom views of controls -- for example, viewing all "Preventive" controls that address "Confidentiality" in the "Application Security" operational capability.

#### Implementation Guidance Examples

**A.8.25 Secure Development Life Cycle** -- ISO 27002 guidance includes:

- Establish and communicate secure development policies to all development staff
- Address security in all phases of the SDLC methodology (requirements, design, implementation, testing, deployment, maintenance)
- Use security requirements checklists or design patterns
- Identify mandatory and optional security checkpoints in project milestones
- Perform security reviews at defined stages
- Use secure repositories and version control for source code
- Require security knowledge in development teams (training records)
- Address ability of developers to identify, report, and correct vulnerabilities
- Apply secure coding practices specific to the programming language or low-code platform in use

**A.8.28 Secure Coding** -- ISO 27002 guidance includes:

- Establish organization-specific secure coding practices
- Prevent use of insecure design patterns (e.g., hard-coded credentials)
- Use static and dynamic application security testing tools
- Review code for adherence to secure coding requirements
- Use vetted and managed libraries and frameworks
- Document, manage, and control any exceptions to secure coding practices
- Protect against common web application attacks (OWASP Top 10-style coverage)

---

## 4. ISO 27017 -- Cloud Security

### 4.1 Overview

ISO/IEC 27017:2015 provides guidelines for information security controls applicable to the provision and use of cloud services. It is structured as a supplementary code of practice based on ISO 27002, with additional cloud-specific implementation guidance and seven entirely new controls not found in ISO 27002.

**Scope:** Applicable to both **cloud service providers (CSPs)** and **cloud service customers (CSCs)**. The standard explicitly differentiates guidance for each role.

**Note:** ISO 27017 is not independently certifiable. Organizations typically certify to ISO 27001 and reference ISO 27017 as an extended control set within their Statement of Applicability.

### 4.2 Cloud-Specific Controls

ISO 27017 adds seven extended controls beyond those in ISO 27002:

| Control ID | Control Name | Description | Applies To |
|-----------|-------------|-------------|-----------|
| CLD.6.3 | Relationship between cloud service customer and cloud service provider | Establish clear roles and responsibilities documented in service agreement | CSP and CSC |
| CLD.8.1 | Shared roles and responsibilities within a cloud computing environment | Clearly define and document shared responsibilities for security controls | CSP and CSC |
| CLD.9.5 | Segregation in virtual computing environments | Ensure virtual machine environments are securely isolated | CSP |
| CLD.12.1 | Operational security -- Monitoring of cloud services | Provide customers with monitoring capabilities for their cloud resources | CSP |
| CLD.12.4 | Clock synchronization across cloud environments | Ensure consistent time sources across distributed cloud environments | CSP |
| CLD.13.1 | Security of virtual networks | Apply security controls to virtual networks equivalent to physical networks | CSP and CSC |
| CLD.13.8 | Removal of cloud service customer assets | Ensure timely and complete removal of customer assets upon termination | CSP |

### 4.3 Shared Responsibility Model

One of the most critical concepts in ISO 27017 is the **shared responsibility model**. The standard requires explicit documentation of which security controls are the responsibility of the CSP, which are the responsibility of the CSC, and which are shared.

```
+-------------------------------------------------------------------+
|                    SHARED RESPONSIBILITY MODEL                     |
+-------------------------------------------------------------------+
|                                                                    |
|  CUSTOMER RESPONSIBILITY (varies by service model)                 |
|  +--------------------------------------------------------------+ |
|  | SaaS: Data classification, user access, business continuity   | |
|  | PaaS: + Application security, development practices           | |
|  | IaaS: + OS patching, network config, middleware, runtime       | |
|  +--------------------------------------------------------------+ |
|                                                                    |
|  SHARED RESPONSIBILITY                                             |
|  +--------------------------------------------------------------+ |
|  | Identity & access management configuration                    | |
|  | Encryption key management                                     | |
|  | Incident response coordination                                | |
|  | Compliance monitoring and reporting                            | |
|  | Data backup and recovery testing                               | |
|  +--------------------------------------------------------------+ |
|                                                                    |
|  PROVIDER RESPONSIBILITY                                           |
|  +--------------------------------------------------------------+ |
|  | Physical data center security                                  | |
|  | Hypervisor / infrastructure layer security                     | |
|  | Network infrastructure and DDoS protection                     | |
|  | Hardware lifecycle management                                   | |
|  | Platform availability and redundancy                            | |
|  +--------------------------------------------------------------+ |
|                                                                    |
+-------------------------------------------------------------------+
```

**Key requirements for the shared responsibility model:**

- Responsibility allocation must be clearly documented in service agreements
- Both parties must understand their obligations before the service commences
- Regular reviews of the responsibility allocation must occur
- Changes to service offerings must trigger a review of the responsibility split
- Evidence of control effectiveness must be available from both parties

### 4.4 Additional Cloud Guidance Areas

ISO 27017 provides cloud-specific implementation guidance for many existing ISO 27002 controls, including:

- **Asset management:** Cloud service customer assets must be identifiable and retrievable; exit strategies must be documented
- **Access control:** Multi-tenancy considerations; administrative access segregation between CSP and CSC environments
- **Cryptography:** Guidance on who manages encryption keys in cloud environments; CSC's ability to use own encryption
- **Operations security:** Monitoring, logging, and clock synchronization across cloud boundaries
- **Communications security:** Virtual network isolation; data-in-transit protection between CSC and CSP
- **Supplier relationships:** Sub-processor transparency; cascade of security requirements to cloud sub-services
- **Compliance:** Consideration of data residency requirements; cross-border data transfer implications

---

## 5. ISO 27018 -- PII Protection in Public Clouds

### 5.1 Overview

ISO/IEC 27018:2019 establishes commonly accepted control objectives, controls, and guidelines for protecting **Personally Identifiable Information (PII)** in public cloud computing environments. It applies specifically to **PII processors** (cloud service providers) that process PII on behalf of **PII principals** (individuals) and **PII controllers** (cloud customers).

**Scope:** Public cloud PII processors acting under the instructions of the PII controller.

**Key purpose:** Provide cloud customers with confidence that their provider handles personal data in compliance with applicable data protection obligations.

### 5.2 Privacy Controls for Cloud Providers

#### Core Principles

ISO 27018 is built upon the following privacy principles for cloud PII processors:

1. **Consent and choice** -- PII must only be processed for the purposes defined by the customer (PII controller); marketing or advertising use of PII is prohibited unless explicitly consented
2. **Purpose legitimacy and specification** -- PII processed in the cloud must not be used for purposes beyond what is specified in the contract
3. **Collection limitation** -- Temporary files and documents that could contain PII must be securely deleted in a timely manner
4. **Data minimization** -- Only process PII that is adequate, relevant, and not excessive for the stated purposes
5. **Use, retention, and disclosure limitation** -- Return, transfer, and securely dispose of PII when the processing contract ends
6. **Accuracy and quality** -- Do not alter PII without instruction from the controller
7. **Openness, transparency and notice** -- Disclose sub-processors and the countries where PII is processed
8. **Individual participation and access** -- Assist the PII controller in fulfilling data subject access requests
9. **Accountability** -- Notify the customer promptly in case of a data breach involving PII

#### Specific Controls

| Requirement | Description |
|-------------|-------------|
| Sub-processor disclosure | Disclose the use of any sub-processors to the cloud customer before they are engaged |
| Data location transparency | Inform the cloud customer of the countries where their PII may be stored or processed |
| Data return and deletion | Provide the ability to return PII to the customer and securely delete it upon contract termination |
| Breach notification | Notify the cloud customer without undue delay upon discovering a PII breach |
| Government access | Notify cloud customers of any legally binding government access requests, unless prohibited by law |
| Audit support | Provide mechanisms for cloud customers (or their designated auditors) to verify compliance |
| Encryption | Encrypt PII in transit and at rest; manage encryption keys separately from data |
| Portable media | If PII is stored on portable media, apply encryption and physical protection |
| PII restoration | Ensure PII can be restored in a timely manner from backups |
| Marketing prohibition | Do not use PII processed on behalf of a customer for marketing or advertising purposes |
| Employee access | Restrict and log employee access to PII; implement confidentiality obligations |

### 5.3 Relationship to GDPR

ISO 27018 aligns well with GDPR requirements for data processors (Article 28), but it is not a GDPR certification. However, demonstrating ISO 27018 compliance supports GDPR compliance by addressing:

- Data processing agreements (Article 28)
- Sub-processor requirements (Article 28(2))
- Data breach notification (Article 33)
- Data subject rights assistance (Articles 15--22)
- Data transfer safeguards (Chapter V)
- Data deletion upon termination (Article 28(3)(g))

---

## 6. ISO 27701 -- Privacy Information Management

### 6.1 Overview

ISO/IEC 27701:2019 specifies requirements and provides guidance for establishing, implementing, maintaining, and continually improving a **Privacy Information Management System (PIMS)**. It is an extension to ISO 27001 and ISO 27002, adding privacy-specific requirements and guidance.

**Key characteristic:** ISO 27701 is designed to be implemented **on top of** an existing ISO 27001 ISMS. It cannot stand alone -- it extends the ISMS into a PIMS.

**Structure:**

- Clauses 5--8: PIMS-specific requirements extending ISO 27001 clauses
- Annex A: PIMS-specific reference controls for PII controllers
- Annex B: PIMS-specific reference controls for PII processors
- Annex D: Mapping to GDPR
- Annex F: How to apply ISO 27701 in conjunction with ISO 27001 and ISO 27002

### 6.2 GDPR Alignment

ISO 27701 was explicitly designed with GDPR alignment as a primary objective. Annex D of the standard provides a detailed mapping between ISO 27701 controls and GDPR articles:

| GDPR Article | ISO 27701 Mapping |
|-------------|-------------------|
| Art. 5 -- Principles relating to processing of personal data | Clause 6.2 (conditions for collection and processing) |
| Art. 6 -- Lawfulness of processing | Clause 7.2.2 (identify lawful basis) |
| Art. 7 -- Conditions for consent | Clause 7.2.3 (determine when and how consent is to be obtained) |
| Art. 12--23 -- Data subject rights | Clauses 7.3.1--7.3.10 (obligations to PII principals) |
| Art. 24 -- Responsibility of the controller | Clause 7.2.1 (purpose identification and documentation) |
| Art. 25 -- Data protection by design and by default | Clause 7.4 (privacy by design and by default) |
| Art. 28 -- Processor | Clauses 8.2--8.5 (PII processor obligations) |
| Art. 30 -- Records of processing activities | Clause 7.2.8 (records related to processing PII) |
| Art. 32 -- Security of processing | Clause 6.9 (operations security aligned with ISO 27002) |
| Art. 33 -- Breach notification to authority | Clause 6.13.1 (management of information security incidents) |
| Art. 35 -- Data protection impact assessment | Clause 7.2.5 (privacy impact assessment) |
| Art. 44--49 -- International transfers | Clause 7.5 (PII sharing, transfer, and disclosure) |

### 6.3 PII Controller Requirements (Annex A)

Organizations acting as PII controllers must implement additional controls covering:

| Area | Key Requirements |
|------|-----------------|
| Conditions for collection and processing | Identify and document the specific purpose for PII processing; identify the lawful basis; define and document when and how consent is obtained; obtain and record consent; perform privacy impact assessments; maintain contracts with PII processors |
| Obligations to PII principals | Determine and document obligations to PII principals (transparency, access, correction, deletion, data portability, objection); implement mechanisms to support these rights; inform third parties of modifications |
| Privacy by design and by default | Limit collection to what is necessary; limit processing to what is identified; default settings should be privacy-protective; implement temporary file and data retention policies |
| PII sharing, transfer, and disclosure | Identify and document the basis for PII transfers between jurisdictions; identify and record countries where PII may be stored; record PII disclosure to third parties |

### 6.4 PII Processor Requirements (Annex B)

Organizations acting as PII processors must implement additional controls covering:

| Area | Key Requirements |
|------|-----------------|
| Conditions for collection and processing | Establish a customer agreement addressing processing purpose, data types, security measures, sub-processor use, and return/deletion; only process PII as instructed by the customer; document basis for international transfers |
| Obligations to PII principals | Provide the means for customers to comply with PII principal access, correction, and deletion rights; inform customers of any request received directly from PII principals |
| Privacy by design and by default | Apply data minimization to temporary files; implement data return, transfer, and disposal procedures; maintain data transmission confidentiality |
| Sub-contractors | Disclose the use of sub-contractors to customers before engagement; contractually require sub-contractors to implement equivalent controls; inform customers of sub-contractor changes |
| Breach notification | Provide timely notification to affected customers in the event of a PII breach |

### 6.5 Certification

ISO 27701 is a certifiable extension. However, because it extends ISO 27001:

- An organization **must** already hold (or concurrently achieve) ISO 27001 certification
- The ISO 27701 certificate states whether the organization is certified as a **PII controller**, a **PII processor**, or **both**
- The scope of the PIMS must align with the scope of the underlying ISMS

---

## 7. ISO 9001 -- Quality Management System

### 7.1 Overview

ISO 9001:2015 specifies requirements for a **Quality Management System (QMS)** that demonstrates an organization's ability to consistently provide products and services that meet customer and regulatory requirements. It is the world's most widely adopted management system standard, with over one million certificates issued globally.

**Key principles:**

1. Customer focus
2. Leadership
3. Engagement of people
4. Process approach
5. Improvement
6. Evidence-based decision making
7. Relationship management

### 7.2 Relevance to Software Development

While ISO 9001 is not specific to software, it is highly relevant to software development organizations:

| QMS Requirement | Software Development Application |
|----------------|----------------------------------|
| Customer requirements (Clause 8.2) | Requirements gathering, user story definition, acceptance criteria |
| Design and development (Clause 8.3) | Software architecture, design reviews, prototyping, design verification |
| Control of externally provided processes (Clause 8.4) | Third-party library management, open-source governance, SaaS dependencies |
| Production and service provision (Clause 8.5) | Software build, deployment, CI/CD pipelines, release management |
| Release of products and services (Clause 8.6) | Quality gates, testing (unit, integration, UAT), go/no-go decisions |
| Control of nonconforming outputs (Clause 8.7) | Bug tracking, defect management, hotfix processes |
| Monitoring and measurement (Clause 9.1) | Code quality metrics, defect density, deployment frequency, MTTR |
| Internal audit (Clause 9.2) | Process audits of development practices, code reviews as quality assurance |
| Continual improvement (Clause 10) | Retrospectives, process optimization, technology upgrades |

**Combined certification:** Many software organizations pursue dual ISO 27001 + ISO 9001 certification, which demonstrates both security and quality management. The Annex SL structure shared by both standards makes integration straightforward -- common processes for document control, internal audit, management review, corrective action, and continual improvement can serve both management systems.

### 7.3 ISO 9001 and Agile Development

ISO 9001 is process-agnostic -- it does not mandate waterfall or any specific methodology. Agile and DevOps practices can satisfy ISO 9001 requirements when properly documented:

- **Sprint planning** satisfies planning requirements
- **Definition of Done** satisfies acceptance criteria requirements
- **Sprint retrospectives** satisfy continual improvement requirements
- **Automated testing in CI/CD** satisfies verification and validation requirements
- **Backlog management** satisfies change control requirements
- **Code reviews** satisfy design review requirements

---

## 8. Applying ISO Standards to Software Applications

### 8.1 Software Development Life Cycle (SDLC) Controls

ISO 27001/27002 include specific controls for secure software development. Application developers and their organizations should address:

#### Secure Development Policy (A.8.25)

- Define and document the secure development life cycle methodology
- Apply security at every phase: requirements, design, implementation, testing, deployment, maintenance
- Define mandatory security checkpoints in the development process
- Require security training for all developers

#### Application Security Requirements (A.8.26)

- Conduct threat modeling during application design
- Define security requirements alongside functional requirements
- Address authentication, authorization, input validation, output encoding, session management, error handling, logging, and cryptography requirements
- Consider OWASP Application Security Verification Standard (ASVS) as a requirements framework

#### Secure Architecture and Engineering (A.8.27)

- Apply defense-in-depth principles
- Implement the principle of least privilege
- Validate all input; encode all output
- Fail securely (deny by default)
- Separate concerns (authentication, authorization, business logic, data access)
- Design for auditability (comprehensive logging)

#### Secure Coding (A.8.28)

- Apply secure coding standards (OWASP, CERT, language-specific guidelines)
- Use parameterized queries (prevent SQL injection)
- Implement proper error handling (no information leakage)
- Manage dependencies and third-party libraries (SCA -- Software Composition Analysis)
- Conduct code reviews with a security focus
- Use SAST (Static Application Security Testing) and DAST (Dynamic Application Security Testing) tools

#### Security Testing (A.8.29)

- Integrate security testing into CI/CD pipelines
- Perform penetration testing at defined intervals
- Conduct vulnerability assessments
- Execute security regression testing after changes
- Test for OWASP Top 10 vulnerabilities

#### Environment Separation (A.8.31)

- Maintain separate development, testing, staging, and production environments
- Use different credentials and configurations per environment
- Never use production data in development/test (or apply anonymization/data masking per A.8.11)
- Control promotion processes between environments

### 8.2 Operational Security for Applications

| Area | Controls |
|------|----------|
| Access management | Role-based access control, MFA for privileged access, regular access reviews, API key management |
| Logging and monitoring | Centralized log collection, anomaly detection, alerting on security events, log integrity protection, retention policies |
| Vulnerability management | Regular scanning, patch management process, zero-day response procedures, CVE monitoring |
| Change management | Formal change request process, impact assessment, approval workflows, rollback procedures |
| Backup and recovery | Automated backups, tested restoration procedures, defined RPO/RTO, off-site storage |
| Incident response | Documented incident response plan, defined severity levels, communication procedures, post-incident review |

### 8.3 Supply Chain and Third-Party Management

Modern applications depend heavily on external components. ISO controls address:

- **Third-party library management** (A.5.19--A.5.22, A.8.30): Maintain a Software Bill of Materials (SBOM), monitor for vulnerabilities in dependencies, assess supplier security practices
- **Cloud service security** (A.5.23): Evaluate cloud provider security certifications, implement controls based on the shared responsibility model, plan for cloud exit scenarios
- **API security**: Secure API endpoints, implement rate limiting, validate input/output, use appropriate authentication (OAuth 2.0, API keys), document API security requirements

---

## 9. Considerations for Mendix and Low-Code Platforms

### 9.1 Unique Aspects of Low-Code Security

Low-code platforms like Mendix introduce specific considerations for ISO compliance:

| Aspect | Consideration |
|--------|--------------|
| Platform responsibility | Security controls are split between the platform vendor (Mendix/Siemens) and the application developer. Understanding this boundary is critical |
| Abstraction layers | Low-code abstractions may obscure underlying security implementations. Developers must understand what happens "under the hood" |
| Custom code | When custom code (Java actions, JavaScript widgets) is introduced, all standard secure coding controls apply |
| Marketplace components | Third-party modules from the Mendix Marketplace require security evaluation equivalent to any third-party library |
| Platform certifications | Mendix (Siemens) maintains its own ISO certifications for the platform -- application builders should leverage this but not assume it covers application-level controls |

### 9.2 Mendix Platform Security Features Relevant to ISO

| ISO Control | Mendix Feature |
|-------------|---------------|
| A.5.15 Access control | Mendix role-based security model (project security, module security, entity access, page access, microflow access) |
| A.5.17 Authentication | Mendix supports SSO (SAML, OIDC), MFA integration, password policies |
| A.8.3 Information access restriction | Entity-level access rules with XPath constraints; page and microflow access based on user roles |
| A.8.4 Access to source code | Mendix Team Server (Git-based) with role-based access; branch management |
| A.8.5 Secure authentication | Mendix BCrypt password hashing; session management; CSRF protection built-in |
| A.8.15 Logging | Mendix runtime logging; custom logging through microflow activities; log node configuration |
| A.8.20 Network security | Mendix Cloud provides network isolation, TLS by default, custom domain certificates |
| A.8.24 Use of cryptography | Mendix encrypts data at rest and in transit in Mendix Cloud; Encryption module for application-level encryption |
| A.8.25 Secure development life cycle | Mendix Development Portal includes project management, version control, CI/CD support |
| A.8.31 Environment separation | Mendix Cloud provides separate Free, Test, Acceptance, and Production environments |

### 9.3 Application Developer Responsibilities in Mendix

Even with the platform providing foundational security, application developers remain responsible for:

1. **Domain model security** -- Configuring entity access rules correctly; never leaving entities without access rules in production
2. **Microflow security** -- Setting appropriate access on microflows; never exposing sensitive operations without authorization checks
3. **Page security** -- Restricting page access based on user roles; hiding sensitive widgets is not a substitute for access rules
4. **Input validation** -- Implementing validation rules on entities and microflows; never trusting client-side validation alone
5. **Custom code review** -- Applying secure coding practices to Java actions and JavaScript widgets
6. **Marketplace module assessment** -- Evaluating security of third-party marketplace modules before use
7. **Data classification** -- Identifying PII and sensitive data; applying appropriate access controls and encryption
8. **API security** -- Securing published REST/OData/SOAP services with authentication and authorization
9. **Logging and auditing** -- Implementing application-level audit trails for sensitive operations
10. **Security testing** -- Performing penetration testing on the deployed application

### 9.4 Mendix Cloud Certifications

Mendix Cloud (operated by Siemens) maintains the following certifications relevant to enterprise customers:

- **ISO 27001** -- Information Security Management System
- **ISO 27017** -- Cloud Security Controls
- **ISO 27018** -- PII Protection in Public Clouds
- **SOC 2 Type II** -- Trust Services Criteria
- **CSA STAR** -- Cloud Security Alliance STAR certification
- **ISAE 3402** -- Assurance Reports on Controls at a Service Organization

**Important:** These certifications cover the Mendix platform and cloud infrastructure. Applications built on the platform require their own security controls and may need independent assessment depending on the regulatory context.

---

## 10. Compliance Checklist for Application Developers

### 10.1 Security Governance

- [ ] Information security policy documented and approved by management
- [ ] Security roles and responsibilities defined (security champion, data owner, risk owner)
- [ ] Security requirements included in project initiation and planning
- [ ] Risk assessment conducted for the application and its data
- [ ] Statement of Applicability maintained (if pursuing certification)
- [ ] Security awareness training completed by all team members
- [ ] Incident response plan documented and tested

### 10.2 Secure Development

- [ ] Secure development life cycle defined and followed
- [ ] Threat modeling conducted during design phase
- [ ] Secure coding standards adopted and enforced
- [ ] Code reviews include security review criteria
- [ ] SAST (Static Application Security Testing) integrated into CI/CD
- [ ] DAST (Dynamic Application Security Testing) performed on deployed applications
- [ ] SCA (Software Composition Analysis) for dependency vulnerability monitoring
- [ ] Software Bill of Materials (SBOM) maintained

### 10.3 Access Control

- [ ] Role-based access control implemented at all layers
- [ ] Principle of least privilege applied
- [ ] Strong authentication implemented (MFA for privileged access)
- [ ] Session management configured securely (timeouts, invalidation)
- [ ] API authentication and authorization enforced
- [ ] Regular access reviews conducted

### 10.4 Data Protection

- [ ] Data classification scheme implemented
- [ ] PII identified and inventoried
- [ ] Encryption applied to data at rest and in transit
- [ ] Data masking/anonymization used for non-production environments
- [ ] Data retention and deletion policies implemented
- [ ] Backup procedures documented and tested
- [ ] Data transfer controls implemented (especially cross-border)

### 10.5 Operational Security

- [ ] Logging implemented for security-relevant events
- [ ] Log centralization and monitoring in place
- [ ] Vulnerability scanning performed regularly
- [ ] Patch management process defined and followed
- [ ] Change management process documented
- [ ] Separate environments for development, testing, and production
- [ ] Business continuity plan documented and tested

### 10.6 Compliance and Audit

- [ ] Regulatory requirements identified (GDPR, CCPA, industry-specific)
- [ ] Privacy impact assessment conducted where PII is processed
- [ ] Third-party/supplier security assessed
- [ ] Internal audits scheduled and conducted
- [ ] Nonconformities tracked and corrective actions implemented
- [ ] Evidence of control effectiveness maintained

---

## 11. Certification vs. Compliance

Understanding the distinction between certification and compliance is critical for organizations communicating their security posture:

### 11.1 Definitions

| Term | Definition |
|------|-----------|
| **Compliance** | Conforming to the requirements of a standard through implemented controls and processes. Self-assessed or informally verified. No external certificate issued |
| **Certification** | Formal verification by an accredited, independent third-party certification body that an organization's management system conforms to the standard's requirements. Results in an official certificate |

### 11.2 Comparison

| Aspect | Compliance (Self-Assessed) | Certification (Third-Party Audited) |
|--------|---------------------------|-------------------------------------|
| Cost | Lower (internal effort only) | Higher (audit fees + internal effort) |
| Credibility | Moderate -- depends on trust relationship | High -- independently verified |
| Ongoing obligation | Self-determined review cycle | Mandatory annual surveillance audits |
| Certificate issued | No | Yes (valid for 3 years, subject to annual surveillance) |
| Customer acceptance | May require additional due diligence | Widely accepted by enterprise customers |
| Regulatory recognition | Varies -- some regulators require formal certification | Recognized by most regulators as demonstration of due diligence |
| Marketing value | Limited -- cannot claim "certified" | Significant -- can display certification mark |

### 11.3 When Each Approach Is Appropriate

**Compliance (without certification) is appropriate when:**

- The organization is building toward certification but is not yet ready
- Customers and regulators do not require formal certification
- Budget constraints prevent certification investment
- The organization wants to adopt best practices without the overhead of formal audit

**Certification is appropriate when:**

- Enterprise customers contractually require ISO certification
- Regulatory frameworks reference ISO certification
- The organization operates in high-trust sectors (finance, healthcare, government)
- Competitive differentiation is needed
- The organization processes sensitive data on behalf of customers

### 11.4 Statement of Conformity vs. Certificate

Organizations that are compliant but not certified should use careful language:

- **Acceptable:** "Our processes are aligned with ISO 27001 requirements" or "We have implemented controls based on the ISO 27001 framework"
- **Not acceptable:** "We are ISO 27001 certified" (unless formally certified by an accredited body)

---

## 12. Cost and Timeline Expectations

### 12.1 ISO 27001 Certification

#### Typical Timeline

| Phase | Duration | Activities |
|-------|----------|-----------|
| Gap assessment | 2--4 weeks | Assess current state against ISO 27001 requirements |
| ISMS design and planning | 1--3 months | Define scope, establish risk methodology, draft policies |
| Control implementation | 3--9 months | Deploy controls, configure technology, train staff, create procedures |
| Internal audit | 2--4 weeks | Conduct internal audit; identify nonconformities |
| Remediation | 1--3 months | Address internal audit findings |
| Stage 1 audit | 1--3 days | Documentation review by certification body |
| Stage 1 remediation | 1--2 months | Address any Stage 1 findings |
| Stage 2 audit | 3--10 days | Full certification audit |
| Certificate issuance | 2--4 weeks | Certificate issued after successful Stage 2 |
| **Total** | **9--18 months** | From project initiation to certificate |

#### Typical Cost Ranges

| Cost Category | Small Organization (10--50 people) | Mid-Size Organization (50--250 people) | Large Organization (250+ people) |
|--------------|------------------------------------|-----------------------------------------|----------------------------------|
| Consulting (gap assessment, implementation support) | $15,000--$40,000 | $30,000--$80,000 | $60,000--$200,000+ |
| Tooling (GRC platform, SIEM, vulnerability scanning) | $5,000--$20,000/year | $15,000--$60,000/year | $40,000--$150,000+/year |
| Certification body audit fees (initial) | $8,000--$20,000 | $15,000--$40,000 | $30,000--$80,000+ |
| Annual surveillance audit fees | $5,000--$12,000 | $10,000--$25,000 | $20,000--$50,000+ |
| Internal effort (staff time) | 500--1,500 hours | 1,500--4,000 hours | 3,000--10,000+ hours |
| Training and awareness | $2,000--$8,000 | $5,000--$20,000 | $10,000--$50,000+ |
| **Total initial investment (Year 1)** | **$30,000--$90,000** | **$75,000--$200,000** | **$160,000--$500,000+** |
| **Annual maintenance** | **$15,000--$40,000** | **$35,000--$100,000** | **$80,000--$250,000+** |

*Note: Ranges vary significantly based on organizational complexity, existing security maturity, scope size, certification body, and geographic location. Consulting fees vary by region.*

### 12.2 Additional ISO Standards

| Standard | Incremental Cost (on top of 27001) | Incremental Timeline |
|----------|-----------------------------------|--------------------|
| ISO 27017 | 15--25% additional | 1--3 months additional |
| ISO 27018 | 15--25% additional | 1--3 months additional |
| ISO 27701 | 25--40% additional | 2--4 months additional |
| ISO 9001 | 30--50% of 27001 cost (significant overlap) | 3--6 months additional |

**Cost efficiencies:**

- Pursuing multiple ISO standards simultaneously reduces total cost by 20--40% compared to sequential implementation, due to shared management system elements (document control, internal audit, management review, corrective action)
- Organizations already holding ISO 27001 can add 27017, 27018, and 27701 as extensions with significantly reduced effort
- Integrated audits (multiple standards in a single audit) reduce certification body fees

---

## 13. ISO and SOC 2 -- How They Relate

### 13.1 Overview of SOC 2

SOC 2 (System and Organization Controls 2) is an auditing standard developed by the **American Institute of Certified Public Accountants (AICPA)**. It evaluates an organization's controls relevant to the **Trust Services Criteria (TSC)**:

1. **Security** (Common Criteria -- mandatory)
2. **Availability** (optional)
3. **Processing Integrity** (optional)
4. **Confidentiality** (optional)
5. **Privacy** (optional)

SOC 2 reports come in two types:

- **Type I:** Evaluates the design of controls at a specific point in time
- **Type II:** Evaluates the design and operating effectiveness of controls over a period (typically 6--12 months)

### 13.2 Comparison: ISO 27001 vs. SOC 2

| Aspect | ISO 27001 | SOC 2 |
|--------|-----------|-------|
| **Origin** | International (ISO/IEC) | United States (AICPA) |
| **Output** | Certificate (pass/fail) | Audit report with opinion (may include exceptions) |
| **Global recognition** | Strong globally, especially in Europe, Asia, Middle East | Strong in North America; growing globally |
| **Scope** | Organization-wide ISMS | Specific system or service |
| **Framework** | Management system + Annex A controls | Trust Services Criteria |
| **Risk approach** | Mandatory risk assessment methodology | Risk assessment implied but less prescriptive |
| **Validity** | 3 years (with annual surveillance) | Typically 12 months (then new report needed) |
| **Auditor** | Accredited certification body (ISO 17021) | Licensed CPA firm |
| **Public disclosure** | Certificate is public; audit details are private | Report is private; shared under NDA (SOC 3 is public) |
| **Cost** | See Section 12 | Type II: $30,000--$150,000+ depending on scope |
| **Timeline** | See Section 12 | 3--12 months readiness + 6--12 month observation period |

### 13.3 Control Mapping

There is significant overlap between ISO 27001 Annex A controls and SOC 2 Trust Services Criteria:

| SOC 2 Trust Services Criteria | Related ISO 27001 Controls |
|------------------------------|---------------------------|
| CC1: Control Environment | Clause 5 (Leadership), A.5.1--A.5.4 |
| CC2: Communication and Information | Clause 7 (Support), A.5.14, A.5.37 |
| CC3: Risk Assessment | Clause 6.1 (Planning), A.5.7 |
| CC4: Monitoring Activities | Clause 9 (Performance Evaluation), A.8.15, A.8.16 |
| CC5: Control Activities | A.5.10, A.8.1--A.8.34 (various technological controls) |
| CC6: Logical and Physical Access Controls | A.5.15--A.5.18, A.7.1--A.7.4, A.8.2--A.8.5 |
| CC7: System Operations | A.5.24--A.5.28, A.8.6--A.8.8, A.8.15--A.8.16, A.8.32 |
| CC8: Change Management | A.8.32, A.8.9, A.8.19, A.8.25 |
| CC9: Risk Mitigation | A.5.19--A.5.23 (supplier controls), Clause 6.1.3 |
| Availability | A.5.29--A.5.30, A.8.6, A.8.13--A.8.14 |
| Processing Integrity | A.8.25--A.8.29, A.8.33 |
| Confidentiality | A.5.12--A.5.14, A.8.3, A.8.11--A.8.12, A.8.24 |
| Privacy | A.5.34, ISO 27701 extensions |

### 13.4 Choosing Between ISO 27001 and SOC 2

| Scenario | Recommendation |
|----------|---------------|
| Primarily serve US enterprise customers | SOC 2 Type II (often expected by US organizations) |
| Primarily serve European/international customers | ISO 27001 (internationally recognized) |
| Serve both US and international markets | Both (many organizations pursue both) |
| Need to demonstrate GDPR compliance | ISO 27001 + ISO 27701 |
| Cloud service provider | ISO 27001 + ISO 27017 + ISO 27018 + SOC 2 |
| Startup with limited budget (choose one first) | SOC 2 Type II if US-focused; ISO 27001 if international |
| Regulated industry (finance, healthcare) | Both, plus industry-specific requirements |

### 13.5 Leveraging One for the Other

Organizations that hold ISO 27001 certification can significantly accelerate SOC 2 readiness, and vice versa:

- **ISO 27001 to SOC 2:** ~60--70% of SOC 2 Common Criteria controls are addressed by an ISO 27001-conformant ISMS. Gap areas typically include: detailed monitoring/alerting evidence, change management evidence for specific systems, and additional documentation of control operating effectiveness over time
- **SOC 2 to ISO 27001:** ~50--60% of ISO 27001 requirements are addressed by SOC 2 Common Criteria. Gap areas typically include: formal ISMS governance structure, risk assessment methodology documentation, Statement of Applicability, internal audit program, and management review process

---

## Appendix A -- Glossary

| Term | Definition |
|------|-----------|
| **Annex A** | The normative appendix to ISO 27001 listing 93 reference controls |
| **Annex SL** | The harmonized high-level structure used by all ISO management system standards |
| **CIA Triad** | Confidentiality, Integrity, and Availability -- the three core information security objectives |
| **Corrective Action** | Action to eliminate the cause of a detected nonconformity |
| **CSC** | Cloud Service Customer -- organization using cloud services |
| **CSP** | Cloud Service Provider -- organization providing cloud services |
| **DAST** | Dynamic Application Security Testing -- testing a running application for vulnerabilities |
| **GRC** | Governance, Risk, and Compliance -- the integrated approach to managing these disciplines |
| **ISMS** | Information Security Management System -- the management system established under ISO 27001 |
| **Management Review** | Periodic evaluation of the ISMS by top management |
| **Nonconformity** | Non-fulfilment of a requirement |
| **PDCA** | Plan-Do-Check-Act -- the continual improvement cycle |
| **PII** | Personally Identifiable Information -- any information relating to an identified or identifiable natural person |
| **PII Controller** | Organization that determines the purposes and means of PII processing |
| **PII Processor** | Organization that processes PII on behalf of a PII controller |
| **PIMS** | Privacy Information Management System -- the management system established under ISO 27701 |
| **QMS** | Quality Management System -- the management system established under ISO 9001 |
| **Risk Owner** | Person or entity with accountability and authority to manage a specific risk |
| **SAST** | Static Application Security Testing -- analyzing source code for security vulnerabilities |
| **SCA** | Software Composition Analysis -- identifying vulnerabilities in third-party dependencies |
| **SBOM** | Software Bill of Materials -- a formal, machine-readable inventory of software components and dependencies |
| **SoA** | Statement of Applicability -- the document listing all Annex A controls with inclusion/exclusion justification |
| **Surveillance Audit** | Annual interim audit to verify continued conformance between recertification cycles |

---

## Appendix B -- Cross-Reference Matrix

### ISO Standard Applicability by Organization Role

| Standard | Software Vendor | Cloud Provider | Enterprise Customer (Cloud User) | Low-Code App Developer |
|----------|----------------|----------------|----------------------------------|----------------------|
| ISO 27001 | Essential | Essential | Recommended | Recommended for org; platform vendor provides foundation |
| ISO 27002 | Implementation guide | Implementation guide | Implementation guide | Implementation guide |
| ISO 27017 | If hosting in cloud | Essential | Recommended | Leverage platform vendor's certification |
| ISO 27018 | If processing PII in cloud | Essential if processing PII | Verify provider holds this | Leverage platform vendor's certification |
| ISO 27701 | If processing PII | If processing PII | If controlling PII | If application processes PII |
| ISO 9001 | Recommended | Optional | Optional | Recommended for professional development shops |

### ISO 27001 Annex A to SOC 2 TSC Quick Reference

| Annex A Theme | Controls | Primary SOC 2 TSC Mapping |
|---------------|----------|--------------------------|
| Organizational (A.5) | 37 controls | CC1, CC2, CC3, CC5, CC9 |
| People (A.6) | 8 controls | CC1, CC5 |
| Physical (A.7) | 14 controls | CC6 |
| Technological (A.8) | 34 controls | CC5, CC6, CC7, CC8, Availability, Processing Integrity, Confidentiality |

---

*This document is intended for informational purposes. For definitive requirements, always refer to the official ISO standards available from the International Organization for Standardization (iso.org) or your national standards body. ISO standards are copyrighted and their full text must be purchased from ISO or authorized distributors.*

*Organizations pursuing certification should engage qualified consultants and accredited certification bodies for authoritative guidance specific to their context.*
