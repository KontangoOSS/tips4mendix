# ITAR Compliance Guide for Application Developers

## Purpose of this document

This guide provides a comprehensive overview of the International Traffic in Arms Regulations (ITAR), with a specific focus on how ITAR requirements affect software applications, cloud-hosted platforms, and low-code development environments such as Mendix. It is intended for application developers, solution architects, IT compliance officers, and anyone responsible for building or operating systems that handle ITAR-controlled data.

This is a practical reference, not legal advice. Engage qualified ITAR counsel before making compliance decisions.

---

## Table of Contents

1. [What ITAR Is and Its Legal Basis](#1-what-itar-is-and-its-legal-basis)
2. [Who Enforces ITAR](#2-who-enforces-itar)
3. [What ITAR Covers](#3-what-itar-covers)
4. [Who Must Comply](#4-who-must-comply)
5. [Key Compliance Requirements](#5-key-compliance-requirements)
6. [Penalties for Non-Compliance](#6-penalties-for-non-compliance)
7. [How ITAR Applies to Software and Applications](#7-how-itar-applies-to-software-and-applications)
8. [Specific Considerations for Mendix and Low-Code Applications](#8-specific-considerations-for-mendix-and-low-code-applications)
9. [Compliance Checklist for Application Developers](#9-compliance-checklist-for-application-developers)
10. [Common Pitfalls and Mistakes](#10-common-pitfalls-and-mistakes)
11. [Appendix A: Key Regulatory References](#appendix-a-key-regulatory-references)
12. [Appendix B: Key Terminology Quick Reference](#appendix-b-key-terminology-quick-reference)
13. [Appendix C: ITAR Compliance Decision Tree](#appendix-c-itar-compliance-decision-tree-for-application-projects)

---

## 1. What ITAR is and its legal basis

The International Traffic in Arms Regulations (ITAR) are a set of United States federal regulations, codified at **22 CFR Parts 120 through 130**, that control the export and import of defense-related articles, services, and technical data. ITAR exists to advance U.S. national security and foreign policy objectives by restricting who can access American defense technology.

### Legal foundation

ITAR derives its authority from the **Arms Export Control Act (AECA)**, 22 U.S.C. 2778. The AECA gives the President the authority to control the import and export of defense articles and defense services. The President has delegated this authority to the **Secretary of State**, who administers it through the Directorate of Defense Trade Controls (DDTC).

Key statutes and regulations:

| Source | What it does |
|---|---|
| **Arms Export Control Act (AECA)**, 22 U.S.C. 2751-2799 | The enabling statute. Grants the executive branch authority to control defense trade |
| **22 CFR Parts 120-130 (ITAR)** | The implementing regulations. Contains the detailed rules, definitions, and procedures |
| **Executive Order 13637** | Delegates AECA authorities from the President to the Secretary of State and Secretary of Defense |
| **United States Munitions List (USML)** | 22 CFR Part 121. The list of defense articles, services, and technical data subject to ITAR control |

ITAR is distinct from the Export Administration Regulations (EAR), which are administered by the Bureau of Industry and Security (BIS) at the Department of Commerce and cover dual-use items. An item is controlled under either ITAR or EAR, not both. The determination of which regime applies is called **commodity jurisdiction** — and getting it wrong is one of the more consequential mistakes an organization can make.

---

## 2. Who enforces ITAR

### Directorate of Defense Trade Controls (DDTC)

The **DDTC**, within the U.S. Department of State's Bureau of Political-Military Affairs, is the primary regulatory body for ITAR. DDTC is responsible for:

- Maintaining the United States Munitions List (USML)
- Processing and adjudicating export license applications
- Managing the registration of manufacturers, exporters, and brokers of defense articles
- Issuing commodity jurisdiction (CJ) determinations
- Conducting compliance audits and investigations
- Administering consent agreements and civil penalties

### Other agencies involved

| Agency | Role |
|---|---|
| **Department of Justice (DOJ)** | Criminal prosecution of ITAR violations |
| **U.S. Customs and Border Protection (CBP)** | Border enforcement, seizure of unauthorized defense article exports |
| **Department of Defense (DoD)** | Technical assessments, end-use monitoring, foreign disclosure decisions |
| **FBI** | Criminal investigations related to illegal arms trafficking and espionage |
| **Department of the Treasury / OFAC** | Sanctions enforcement that may overlap with ITAR controls |
| **Defense Counterintelligence and Security Agency (DCSA)** | Oversight of cleared contractor facilities |

### Voluntary self-disclosure

DDTC strongly encourages — and practically speaking, expects — companies to voluntarily self-disclose ITAR violations. Voluntary disclosures under ITAR Part 127.12 are treated as a significant mitigating factor in enforcement actions. Failing to self-disclose when a violation is later discovered tends to make the penalty substantially worse.

---

## 3. What ITAR covers

ITAR controls three categories of items, all defined in 22 CFR Part 120:

### Defense articles (22 CFR 120.31)

Any item or technical data designated on the United States Munitions List. This includes:
- Physical hardware (weapons, vehicles, aircraft, vessels, satellites)
- Components and parts specifically designed for defense articles
- Technical data (see below)
- Software specifically designed for defense articles or defense services
- Classified articles

### Defense services (22 CFR 120.32)

The furnishing of assistance (including training) to foreign persons in the design, development, engineering, manufacture, production, assembly, testing, repair, maintenance, modification, operation, demilitarization, destruction, processing, or use of defense articles.

This is where application developers frequently get caught. If a foreign person can access a system that contains ITAR technical data, you may be furnishing a defense service — even if nobody intended to.

### Technical data (22 CFR 120.33)

Information required for the design, development, production, manufacture, assembly, operation, repair, testing, maintenance, or modification of defense articles. This includes:

- Blueprints, drawings, plans, instructions, specifications
- Engineering analysis, design methodology
- Software source code (when related to defense articles)
- Manufacturing know-how and processes
- Test data and results
- Operational and maintenance documentation

**What technical data is NOT**: General scientific, mathematical, or engineering principles taught in schools and available to the public. This is the "fundamental research" and "public domain" exclusion (22 CFR 120.34). But be very careful with this — the exclusion is narrow and heavily litigated.

### The United States Munitions List (USML) — 22 CFR Part 121

The USML is organized into 21 categories:

| Category | Description |
|---|---|
| I | Firearms, Close Assault Weapons and Combat Shotguns |
| II | Guns and Armament |
| III | Ammunition and Ordnance |
| IV | Launch Vehicles, Guided Missiles, Ballistic Missiles, Rockets, Torpedoes, Bombs, and Mines |
| V | Explosives and Energetic Materials, Propellants, Incendiary Agents, and Their Constituents |
| VI | Surface Vessels of War and Special Naval Equipment |
| VII | Ground Vehicles |
| VIII | Aircraft and Related Articles |
| IX | Military Training Equipment and Training |
| X | Personal Protective Equipment |
| XI | Military Electronics |
| XII | Fire Control, Laser, Imaging, and Guidance Equipment |
| XIII | Materials and Miscellaneous Articles |
| XIV | Toxicological Agents, Including Chemical Agents, Biological Agents, and Associated Equipment |
| XV | Spacecraft and Related Articles |
| XVI | Nuclear Weapons Related Articles |
| XVII | Classified Articles, Technical Data, and Defense Services Not Otherwise Enumerated |
| XVIII | Directed Energy Weapons |
| XIX | Gas Turbine Engines and Associated Equipment |
| XX | Submersible Vessels and Related Articles |
| XXI | Articles, Technical Data, and Defense Services Not Otherwise Enumerated |

Each category contains specific entries. Items are listed with varying levels of specificity — some entries are very targeted (a specific missile system), while others are broad (software "specifically designed" for items in the category). The "specifically designed" language is key and has been the subject of extensive DDTC guidance.

**Important**: The USML has undergone significant reform since 2013 under the Export Control Reform (ECR) initiative. Many items that were previously on the USML have been moved to the Commerce Control List (CCL) under EAR jurisdiction. Always check whether your item is still on the current USML.

---

## 4. Who must comply

### Entities that must register with DDTC

Under 22 CFR Part 122, the following must register with DDTC:

- **Manufacturers** of defense articles
- **Exporters** of defense articles
- **Brokers** of defense articles (22 CFR Part 129)
- **Providers of defense services**

Registration is mandatory before you can apply for any export license. It is also mandatory even if you do not intend to export — if you manufacture defense articles, you must register. Registration is annual and currently costs a minimum of $2,936 per year (the fee schedule has increased substantially in recent years, check DDTC for current rates).

### The "deemed export" rule

This is the one that catches most software companies. Under ITAR, a "deemed export" occurs when ITAR-controlled technical data is disclosed to a **foreign person** (a person who is not a U.S. citizen, U.S. lawful permanent resident, or protected person under 8 U.S.C. 1324b(a)(3)). This applies regardless of where the disclosure occurs.

That means:
- A foreign national employee sitting at a desk in your Virginia office looking at ITAR data on their screen is a deemed export
- A foreign national developer with access to a code repository containing ITAR-related source code is a deemed export
- A foreign national contractor with admin access to a cloud environment hosting ITAR data is a deemed export
- A foreign national Mendix developer who can open a module containing ITAR-controlled logic is a deemed export

Unless you have an applicable license or exemption, every one of those scenarios is an ITAR violation.

### Who is a "U.S. Person"

Under ITAR, a "U.S. person" means:

- A U.S. citizen (by birth or naturalization)
- A lawful permanent resident (green card holder)
- A protected individual under 8 U.S.C. 1324b(a)(3) (refugees, asylees)
- An organization incorporated in the U.S. (but foreign-owned subsidiaries require additional analysis)

Dual citizens, visa holders (H-1B, L-1, F-1, etc.), and foreign nationals on assignment in the U.S. are **not** U.S. persons for ITAR purposes unless they also hold permanent residency.

---

## 5. Key compliance requirements

### DDTC Registration (22 CFR Part 122)

- File Form DS-2032 (Statement of Registration) with DDTC
- List all defense articles you manufacture, export, or broker
- Renewal is required annually
- Registration does not grant any export authority — it is a prerequisite for applying for licenses
- DDTC registration is also a prerequisite for participation in most DoD contracts involving defense articles

### Export licenses (22 CFR Part 123-125)

When you need to export (or deemed-export) a defense article, defense service, or technical data, you typically need one of:

| Mechanism | When to use it |
|---|---|
| **DSP-5 (Permanent export license)** | One-time or recurring export of defense articles to a specific end user |
| **DSP-73 (Temporary export license)** | Temporary export of defense articles for demos, testing, exhibitions |
| **DSP-85 (Temporary import license)** | Temporary import of unclassified defense articles |
| **TAA (Technical Assistance Agreement)** | Ongoing provision of defense services or disclosure of technical data to foreign persons |
| **MLA (Manufacturing License Agreement)** | Authorizing a foreign person to manufacture defense articles |
| **Exemption** | Specific regulatory exemptions in 22 CFR 125 and 126 that may apply (e.g., 126.1 for NATO + certain allies, various exemptions for specific circumstances) |

License processing times vary. Simple DSP-5s may be processed in 30-60 days. TAAs can take 3-6 months or longer, particularly if the End-Use Monitoring (EUM) division or Congressional Notification is involved.

### Technology Control Plans (TCP)

A Technology Control Plan is an internal document (and operational framework) that describes how an organization will prevent unauthorized access to ITAR-controlled technical data. While not always legally mandated as a standalone document, TCPs are:

- Required by many DoD contracts (DFARS 252.225-7048 and related clauses)
- Expected by DDTC during compliance reviews
- Essential for any organization employing foreign persons who work near ITAR programs
- The primary mechanism for demonstrating how you implement "deemed export" controls

A TCP should address:

1. **Physical security** — restricted areas, badge access, visitor controls
2. **IT security** — network segmentation, access controls, encryption, monitoring
3. **Personnel controls** — citizenship verification, NDA/non-disclosure requirements, training
4. **Marking and handling** — how ITAR data is identified, labeled, stored, transmitted, and destroyed
5. **Incident response** — what happens when a potential unauthorized disclosure occurs
6. **Subcontractor management** — how you flow ITAR requirements to subcontractors and vendors

### Record-keeping (22 CFR 122.5)

ITAR requires retention of all records related to defense trade activities for a minimum of **5 years**. This includes:

- Export license applications and approvals
- Shipping and delivery documentation
- Technical data transmittals
- End-user certificates and statements
- Compliance training records
- Incident reports and voluntary disclosures

---

## 6. Penalties for non-compliance

ITAR violations are taken seriously. Penalties have increased over the years, and enforcement has expanded to include both traditional defense contractors and technology companies.

### Criminal penalties (22 U.S.C. 2778(c))

- Up to **$1,000,000 per violation** in fines
- Up to **20 years imprisonment** per violation
- Criminal forfeiture of articles involved

Criminal prosecution is handled by the Department of Justice and typically involves intentional or willful violations — unauthorized exports with knowledge, arms trafficking, or repeated/systemic disregard for ITAR requirements.

### Civil penalties (22 CFR 127.10)

- Up to **$1,282,564 per violation** (this figure is adjusted periodically for inflation; check the current Federal Register notice for the latest amount)
- Debarment from defense trade (the practical death penalty for a defense contractor)
- Consent agreements requiring implementation of extensive compliance programs, appointment of external monitors, and sometimes structural changes to the organization
- Mandatory disclosure and notification to affected parties

### Administrative actions

- Suspension or revocation of DDTC registration
- Denial of pending and future export license applications
- Debarment from eligibility for defense contracts
- Referral to DOJ for criminal investigation

### Notable enforcement examples

DDTC has imposed substantial penalties across a range of violations:

- Companies have been fined tens of millions of dollars for unauthorized exports of technical data
- Cloud service providers and IT contractors have faced enforcement actions for failing to restrict foreign person access to ITAR data
- "Inadvertent" violations — where companies did not intend to violate ITAR but failed to implement adequate controls — still result in significant civil penalties
- Even small companies and individual engineers have faced personal liability

The trend is clear: DDTC expects proactive compliance. "We didn't know" or "it was an accident" is not a defense, though voluntary self-disclosure and demonstrated good-faith compliance efforts are strong mitigating factors.

---

## 7. How ITAR applies to software and applications

This is where things get concrete for application developers. ITAR's reach into the software world is broad and often underestimated.

### Software as a defense article

Software that is specifically designed, developed, configured, adapted, or modified for a defense article listed on the USML is itself a defense article. This includes:

- Firmware for weapons systems
- Flight control software for military aircraft
- Encryption software specifically designed for defense communications systems
- Test and simulation software for USML-listed items
- Logistics and maintenance software specifically designed for defense articles

### Software as technical data

Even if the software itself is not a defense article, the following can constitute ITAR-controlled technical data:

- Source code that reveals design methodology for defense articles
- Configuration files, parameters, or settings that embody controlled technical data
- Database schemas that reflect the design or operational characteristics of defense articles
- API specifications that reveal defense-related functionality
- Build scripts, deployment configurations, and DevOps pipelines that are specifically designed for defense programs

### The cloud hosting problem

This is one of the most significant operational challenges for ITAR compliance in modern software. When you host an application in the cloud:

1. **Physical location matters**. ITAR data must be stored on servers physically located in the United States. This is non-negotiable. Data replication to non-U.S. regions, CDN edge caching in foreign locations, or automatic geo-failover to international data centers are all potential ITAR violations.

2. **Administrator access matters**. Every person who has administrative access to the infrastructure (cloud engineers, SREs, DBAs, support staff) that stores, processes, or can access ITAR data must be a U.S. person. This includes the cloud provider's staff. Standard commercial cloud offerings (AWS commercial, Azure commercial, GCP) do not guarantee this.

3. **Approved cloud environments**:

   | Provider | ITAR-suitable offering | Notes |
   |---|---|---|
   | **AWS** | AWS GovCloud (US) | U.S.-only regions, U.S. person staff, FedRAMP High |
   | **Microsoft** | Azure Government (specifically GCC-High or DoD regions) | Azure Government alone may not be sufficient; GCC-High adds ITAR-specific controls |
   | **Google** | Assured Workloads (IL4/IL5) | Available but less mature for ITAR specifically |
   | **Oracle** | Oracle Cloud Infrastructure Government Cloud | FedRAMP High authorized |

4. **Shared responsibility model**. The cloud provider handles physical security and infrastructure. You handle everything above that — application-level access controls, data classification, user identity management, logging, and more. Being on GovCloud does not make you ITAR-compliant by itself. It gives you an infrastructure foundation that is capable of supporting ITAR compliance.

### Access control requirements

For any application handling ITAR data:

- **Authentication** must positively identify every user before granting access
- **Authorization** must be role-based, with ITAR data restricted to verified U.S. persons
- **Multi-factor authentication (MFA)** is a practical requirement (expected by DDTC and often mandated by contract)
- **Session management** must enforce timeouts and re-authentication
- **Audit logging** must capture who accessed what data, when, from where, and what they did with it
- All audit logs must be retained for at least 5 years and protected from tampering
- **Encryption in transit** — TLS 1.2+ minimum, FIPS 140-2 validated modules preferred
- **Encryption at rest** — AES-256 or equivalent, with key management under U.S. person control
- **Network segmentation** — ITAR workloads must be isolated from non-ITAR workloads at the network level

### Data handling in transit

- Email is generally not acceptable for transmitting ITAR technical data unless the email system is end-to-end encrypted and both endpoints are ITAR-compliant
- File sharing services (Dropbox, Google Drive, OneDrive commercial) are not ITAR-compliant
- SFTP, SCP, and encrypted file transfer within controlled environments are acceptable
- API data transfers must use TLS and should be authenticated and logged

---

## 8. Specific considerations for Mendix and low-code applications

Low-code platforms like Mendix introduce unique ITAR compliance challenges because of their architecture — multi-tenant cloud hosting, abstracted infrastructure, collaborative development environments, and platform-managed services.

### Platform hosting and data residency

**The fundamental question**: Where does the Mendix application run, and who has access to the underlying infrastructure?

- **Mendix Cloud (standard)**: The standard Mendix Cloud offering is a multi-tenant, globally distributed platform. It does not meet ITAR requirements because:
  - Data residency cannot be guaranteed to U.S.-only servers
  - Platform support staff may include non-U.S. persons
  - Infrastructure management (Mendix's responsibility) is not restricted to U.S. persons
  - Multi-tenant architecture means isolation guarantees are at the application level, not the infrastructure level

- **Mendix for Private Cloud / Mendix on Kubernetes**: Mendix applications can be deployed on customer-managed Kubernetes clusters. This is the path to ITAR compliance because:
  - You control the infrastructure (run it on AWS GovCloud, Azure GCC-High, or on-premises)
  - You control who has admin access to the infrastructure
  - You control network segmentation and data residency
  - You control encryption keys and certificate management

- **On-premises deployment**: Mendix apps can be deployed on-premises on your own hardware. This gives you full physical and logical control, which is the most straightforward path to ITAR compliance from an infrastructure perspective.

### Development environment controls

This is where low-code introduces complications that traditional code development does not have:

1. **Mendix Studio / Studio Pro access**: Developers using Studio Pro (the desktop IDE) or Mendix Studio (the web-based IDE) have access to the full application model — domain models, microflows, pages, integrations, and potentially any ITAR-controlled logic or data structures embedded in the application. Every developer with access to the project must be a verified U.S. person.

2. **Mendix Team Server (version control)**: The default Team Server is hosted by Mendix in their cloud. If your application model constitutes ITAR technical data (which it likely does if the application handles ITAR data), then the Team Server repository itself contains controlled technical data. Options:
   - Use a self-hosted Git repository on ITAR-compliant infrastructure instead of the Mendix-managed Team Server
   - Ensure that the Mendix Team Server instance used is in a U.S.-only, U.S.-person-administered environment (discuss with Mendix/Siemens about private cloud options)

3. **Mendix Marketplace modules**: Be careful about what Marketplace modules you include. While the modules themselves are generally public domain, any customization you make to them for ITAR purposes could constitute controlled technical data.

4. **Mendix App Services and integrations**: If your application calls external services or is called by external services, every integration point is a potential export control boundary. Map all data flows and ensure that ITAR data does not leave the controlled environment through any integration.

### Runtime considerations

| Concern | What to do |
|---|---|
| **Database** | Host on ITAR-compliant infrastructure. Encrypt at rest. Restrict DBA access to U.S. persons. Use FIPS-validated encryption modules |
| **File storage** | Use S3-compatible storage in GovCloud or on-premises MinIO/equivalent. Do not use Mendix's default file storage if it is not on controlled infrastructure |
| **Logging** | Application logs may contain ITAR data (error messages with technical details, user activity with controlled data). Route all logs to an ITAR-compliant logging infrastructure |
| **Backups** | Backups contain the full database and file storage. Backup storage must meet the same ITAR requirements as production. Backup encryption keys must be under U.S. person control |
| **CI/CD pipelines** | Build servers, deployment pipelines, and artifact repositories all process the application model and code. They must be on ITAR-compliant infrastructure with U.S.-person-only access |
| **Monitoring and APM** | Tools like Datadog, New Relic, or Dynatrace receive telemetry from your application. If that telemetry could include ITAR data, the monitoring platform must be ITAR-compliant. Most commercial SaaS APM tools are not |

### Mendix-specific architecture recommendations

1. **Separate ITAR and non-ITAR applications**. Do not mix ITAR and non-ITAR data in the same Mendix application if you can avoid it. Maintaining two separate compliance postures within a single app is operationally painful and audit-risky.

2. **Use Mendix for Private Cloud on GovCloud infrastructure**. Deploy your ITAR Mendix application to a customer-managed Kubernetes cluster running in AWS GovCloud or Azure GCC-High.

3. **Implement application-level access controls**. Even with infrastructure-level controls, your Mendix application must enforce its own access controls:
   - User role-based access to pages, microflows, entities, and attributes
   - Entity access rules that restrict ITAR-classified entities to authorized roles
   - Microflow security constraints
   - API endpoint authentication and authorization

4. **Version control on controlled infrastructure**. Use a self-hosted Git server (Gitea, GitLab, etc.) on ITAR-compliant infrastructure rather than the default Mendix Team Server.

5. **Audit trail module**. Implement comprehensive audit logging within the Mendix application using a custom or Marketplace audit trail module. Log all CRUD operations on ITAR-controlled entities, all user authentication events, and all data exports.

---

## 9. Compliance checklist for application developers

This checklist is organized by domain. Not every item applies to every application — but if you are building or operating an application that handles ITAR data, you should be able to answer each one.

### Infrastructure and hosting

- [ ] Application is hosted on ITAR-compliant infrastructure (GovCloud, GCC-High, on-premises, or equivalent)
- [ ] All servers storing, processing, or transmitting ITAR data are physically located in the United States
- [ ] No data replication, caching, or failover to non-U.S. locations
- [ ] All infrastructure administrators (cloud engineers, SREs, DBAs) are verified U.S. persons
- [ ] Network segmentation isolates ITAR workloads from non-ITAR workloads
- [ ] Encryption in transit: TLS 1.2+ with FIPS 140-2 validated modules
- [ ] Encryption at rest: AES-256 or equivalent with FIPS 140-2 validated modules
- [ ] Encryption keys are managed by U.S. persons and stored on compliant infrastructure

### Access control

- [ ] All users are authenticated before accessing any ITAR data
- [ ] Multi-factor authentication is enforced for all users with access to ITAR data
- [ ] Role-based access control restricts ITAR data to verified U.S. persons
- [ ] Citizenship/immigration status verification process is documented and followed before granting access
- [ ] Session timeouts and re-authentication are configured
- [ ] Privileged access (admin, DBA, root) is restricted, logged, and reviewed
- [ ] Service accounts and API keys are inventoried and controlled
- [ ] Access reviews are conducted periodically (quarterly at minimum)

### Development environment

- [ ] All developers with access to ITAR-related source code, application models, or technical data are verified U.S. persons
- [ ] Version control repositories containing ITAR-controlled data are on compliant infrastructure
- [ ] CI/CD pipelines run on compliant infrastructure with U.S.-person-only access
- [ ] Development, staging, and test environments meet the same access control requirements as production (if they contain real or representative ITAR data)
- [ ] Code reviews and pull requests are restricted to authorized persons
- [ ] Third-party libraries and dependencies have been reviewed for export control implications
- [ ] No ITAR technical data is stored in public or externally-hosted repositories

### Data handling

- [ ] ITAR-controlled data is classified and marked (at minimum, in system documentation and data dictionaries)
- [ ] Data flow diagrams document all paths that ITAR data takes through the system, including integrations
- [ ] Data export functionality (CSV exports, API endpoints, reporting) is restricted and logged
- [ ] Print and download controls are in place where appropriate
- [ ] Data destruction procedures are documented and followed
- [ ] Backup and disaster recovery storage meets ITAR requirements
- [ ] No ITAR data is transmitted via non-compliant channels (commercial email, consumer file sharing, etc.)

### Logging and monitoring

- [ ] Comprehensive audit logs capture: user identity, action performed, data accessed, timestamp, source IP
- [ ] Audit logs are tamper-resistant (write-once storage, integrity verification)
- [ ] Audit logs are retained for a minimum of 5 years
- [ ] Logging infrastructure is ITAR-compliant (if logs may contain controlled data)
- [ ] Security monitoring is in place for anomalous access patterns
- [ ] Incident response procedures are documented and tested

### Personnel and training

- [ ] All personnel with access to ITAR data have been verified as U.S. persons
- [ ] Verification documentation (citizenship proof, I-9 records, etc.) is maintained
- [ ] ITAR awareness training is provided to all personnel with access to controlled data
- [ ] Training records are maintained for at least 5 years
- [ ] Non-disclosure agreements are in place
- [ ] Procedures exist for access revocation upon personnel departure or role change

### Vendor and subcontractor management

- [ ] All third-party vendors with access to ITAR data are DDTC-registered (if applicable)
- [ ] Vendor contracts include ITAR compliance flow-down clauses
- [ ] Cloud service providers have been verified as ITAR-capable for the specific services used
- [ ] SaaS tools used in development or operations have been assessed for ITAR compatibility
- [ ] Third-party support and maintenance personnel are verified U.S. persons (or appropriate licenses are in place)

### Documentation and governance

- [ ] Technology Control Plan is documented, approved, and current
- [ ] ITAR compliance policies and procedures are documented
- [ ] Commodity jurisdiction determinations or self-classifications are on file
- [ ] DDTC registration is current (if applicable)
- [ ] Export licenses and agreements are current and not exceeded
- [ ] Record-keeping procedures comply with the 5-year retention requirement
- [ ] Voluntary self-disclosure procedures are in place for reporting potential violations
- [ ] Regular compliance audits are conducted (internal and/or external)

---

## 10. Common pitfalls and mistakes

These are the mistakes we see repeatedly. Some are technical, some are procedural, and some are organizational. All of them have resulted in real enforcement actions.

### "We're just building the app, we're not exporting anything"

**Wrong**. If your application model, source code, or configuration embodies ITAR technical data, then every person who accesses it is a potential export recipient. The "deemed export" rule does not require anything to cross a border. A foreign national developer on your team opening the Mendix project file is a deemed export if the project contains controlled technical data.

### Using commercial cloud for ITAR workloads

Standard AWS, Azure, and GCP commercial regions are not ITAR-compliant. It does not matter if you pick the `us-east-1` region. Commercial cloud operations staff are globally distributed and may include non-U.S. persons with administrative access to infrastructure. You need GovCloud, GCC-High, or equivalent.

### Assuming the platform vendor handles compliance

If you deploy on Mendix Cloud, AWS, or Azure, the cloud provider is responsible for physical security and certain infrastructure controls (the "cloud of" responsibilities). Everything else — application access control, data classification, user verification, audit logging, export control compliance — is your responsibility. The shared responsibility model means exactly what it says. The cloud provider will hand you a FedRAMP authorization package, but that does not make your application ITAR-compliant.

### Not controlling development environments

Production is locked down, but the development environment is wide open. Developers use personal laptops, push code to GitHub.com, pull dependencies from public npm registries, and debug against copies of production data on their local machines. If any of that data or code is ITAR-controlled, every one of those actions is a potential violation.

### Ignoring the CI/CD pipeline

Your Jenkins server, GitHub Actions runners, Docker registries, and artifact repositories all process your application code. If that code is ITAR-controlled, these systems must be on compliant infrastructure with U.S.-person-only access. A GitHub Actions runner executing a build of your ITAR application on a Microsoft-managed server with globally-distributed staff is a problem.

### Failing to verify citizenship

"We asked them on the onboarding form and they said they were a citizen" is not verification. ITAR compliance requires actual verification of U.S. person status. This typically means reviewing original documentation (U.S. passport, birth certificate, permanent resident card). Document the verification. Keep the records. Many organizations integrate this with their I-9 employment verification process, but ITAR verification may need to go further than what I-9 requires.

### Mixing ITAR and non-ITAR data

Putting ITAR and non-ITAR data in the same database, the same application, or the same infrastructure environment means the entire environment must be treated as ITAR-controlled. This dramatically increases compliance scope and cost. Architect for separation from the beginning.

### Not having a Technology Control Plan

If you have foreign national employees anywhere in your organization — even if they do not work on ITAR programs — you need a TCP that documents how you prevent them from accessing ITAR data. "They don't have access" is a conclusion, not a plan. The TCP documents the controls that ensure they do not have access.

### Overlooking support and maintenance access

Your application goes to production and everything is locked down. Then a support ticket comes in and someone gives the vendor's support engineer remote access to debug an issue. If that support engineer is not a verified U.S. person and they can see ITAR data (or even ITAR-controlled configuration and code), that is an unauthorized disclosure. Build ITAR-compatible support procedures from the start.

### Failing to account for AI and LLM tools

This is an emerging and critical concern. If developers use AI coding assistants (Copilot, ChatGPT, Claude, or others) and submit ITAR-controlled code as prompts, that is potentially an unauthorized export of technical data to a system operated by an entity with non-U.S.-person staff. Enterprise agreements with AI vendors that include ITAR-specific terms, or air-gapped/on-premises AI tools, may be required.

Similarly, if an application handling ITAR data integrates with AI/ML services for features like classification, search, or summarization, the AI service must be on ITAR-compliant infrastructure with appropriate access controls.

### Not conducting regular audits

ITAR compliance is not a one-time setup. People change roles, infrastructure changes, new integrations are added, new developers join the team. Without regular audits (at minimum annually, quarterly is better), drift is inevitable. When an auditor or DDTC finds the drift, the fact that you were compliant two years ago does not help.

### Underestimating the scope of "technical data"

Engineers tend to think of "technical data" as blueprints and specifications. Under ITAR, it also includes:
- Meeting notes from design reviews
- Emails discussing technical approaches
- Whiteboard photos from architecture sessions
- Jira/Ticketarr tickets with technical details
- Slack messages with code snippets
- Test results and bug reports that reveal system behavior
- Performance metrics that reveal design characteristics

If any of these relate to a defense article, they are potentially ITAR-controlled technical data. Your collaboration tools, project management systems, and communication platforms are all in scope.

---

## Appendix A: Key regulatory references

| Reference | Description |
|---|---|
| 22 U.S.C. 2751-2799 | Arms Export Control Act |
| 22 CFR Part 120 | General provisions and definitions |
| 22 CFR Part 121 | United States Munitions List |
| 22 CFR Part 122 | Registration of manufacturers and exporters |
| 22 CFR Part 123 | Licenses for export and temporary import of defense articles |
| 22 CFR Part 124 | Agreements, off-shore procurement, and other defense services |
| 22 CFR Part 125 | Licenses for export of technical data and classified defense articles |
| 22 CFR Part 126 | General policies and provisions (country policies, exemptions) |
| 22 CFR Part 127 | Violations and penalties |
| 22 CFR Part 128 | Administrative procedures |
| 22 CFR Part 129 | Registration and licensing of brokers |
| 22 CFR Part 130 | Political contributions, fees, and commissions |
| DFARS 252.204-7012 | Safeguarding Covered Defense Information (CDI) and Cyber Incident Reporting |
| DFARS 252.225-7048 | Export-Controlled Items |
| NIST SP 800-171 | Protecting Controlled Unclassified Information (CUI) — often applied alongside ITAR |

## Appendix B: Key terminology quick reference

| Term | Definition |
|---|---|
| **AECA** | Arms Export Control Act — the enabling statute for ITAR |
| **CJ Determination** | Commodity Jurisdiction determination — the formal process to determine if an item is ITAR (USML) or EAR (CCL) controlled |
| **DDTC** | Directorate of Defense Trade Controls — the State Department office that administers ITAR |
| **Deemed export** | Disclosure of ITAR-controlled technical data to a foreign person, regardless of location |
| **Defense article** | Any item or technical data on the USML |
| **Defense service** | Assistance to foreign persons in the design, development, production, etc. of defense articles |
| **DSP-5** | Application/License for Permanent Export of Unclassified Defense Articles and Related Data |
| **EAR** | Export Administration Regulations — Commerce Department controls for dual-use items (separate from ITAR) |
| **FIPS 140-2** | Federal Information Processing Standard for cryptographic modules |
| **Foreign person** | Any person who is not a U.S. person (includes foreign governments and organizations) |
| **MLA** | Manufacturing License Agreement |
| **TAA** | Technical Assistance Agreement |
| **TCP** | Technology Control Plan |
| **Technical data** | Information required for the design, development, production, etc. of defense articles |
| **USML** | United States Munitions List — the list of controlled defense articles |
| **U.S. person** | U.S. citizen, lawful permanent resident, or protected individual under 8 U.S.C. 1324b(a)(3) |
| **VSD** | Voluntary Self-Disclosure — reporting a potential violation to DDTC |

---

## Appendix C: ITAR compliance decision tree for application projects

```
START: Does your application store, process, transmit, or display data
       related to items on the United States Munitions List (USML)?
       |
       +-- NO --> ITAR likely does not apply to your application.
       |          (Consider EAR/CUI requirements separately.)
       |
       +-- YES (or UNSURE)
           |
           Has a Commodity Jurisdiction determination been completed?
           |
           +-- NO --> Get one. Do not proceed with assumptions.
           |
           +-- YES, item is ITAR-controlled
               |
               Is your organization registered with DDTC?
               |
               +-- NO --> Register before proceeding.
               |
               +-- YES
                   |
                   Is the application hosted on ITAR-compliant infrastructure?
                   (GovCloud, GCC-High, on-premises, or equivalent)
                   |
                   +-- NO --> Migrate or re-architect before handling ITAR data.
                   |
                   +-- YES
                       |
                       Are ALL persons with access to the application, its code,
                       its infrastructure, and its data verified U.S. persons?
                       |
                       +-- NO --> Obtain appropriate export licenses (TAA/DSP-5)
                       |          OR restrict access to U.S. persons only.
                       |
                       +-- YES
                           |
                           Are access controls, audit logging, encryption,
                           and a Technology Control Plan in place?
                           |
                           +-- NO --> Implement them before going live.
                           |
                           +-- YES --> You have a foundation for ITAR compliance.
                                       Maintain it through regular audits,
                                       training, and continuous monitoring.
```

---

*This document is a general compliance guide and does not constitute legal advice. ITAR regulations are complex and subject to change. Organizations handling ITAR-controlled data should engage qualified export control counsel and consider working with DDTC directly on jurisdictional and licensing questions. Regulatory citations are current as of the authoring date and should be verified against the latest edition of the Code of Federal Regulations (eCFR) and DDTC guidance.*
