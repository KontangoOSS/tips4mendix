<div align="center">

# Tips for Mendix

**A practical, open-source knowledge base for building, deploying, and securing Mendix applications.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)
[![Mendix](https://img.shields.io/badge/Mendix-10+-0595DB.svg)](https://www.mendix.com/)

Built by engineers who ship Mendix to production — not just tutorials, but the stuff you actually need when things get real.

</div>

---

## What's Inside

Every guide is written with production use in mind. You'll find concrete examples, configuration snippets, decision matrices, and troubleshooting steps — not just theory.

### Development

| Guide | What You'll Learn |
|-------|-------------------|
| [Microflows](./microflows/) | Server-side logic, error handling, performance patterns, batch processing, debugging |
| [Nanoflows](./nanoflows/) | Client-side execution, offline-first design, JavaScript actions, when to use nanoflows vs microflows |
| [Entities](./entities/) | Domain modeling, associations, access rules, indexes, data migration strategies |
| [Pages & UI](./pages-and-ui/) | Layouts, widgets, Atlas UI styling, accessibility, responsive patterns |
| [Integrations](./integrations/) | REST, OData, SOAP, Kafka, retry patterns, circuit breakers, OAuth 2.0 |

### Architecture & Operations

| Guide | What You'll Learn |
|-------|-------------------|
| [Modules](./modules/) | Module structure, inter-module dependencies, security boundaries, refactoring |
| [Marketplace](./marketplace/) | Evaluating third-party modules, customization patterns, building your own |
| [Infrastructure](./infrastructure/) | Runtime architecture, JVM tuning, caching, clustering, reverse proxy configs |
| [Deployment](./deployment/) | Docker, Kubernetes, Mendix Cloud, blue/green releases, secrets management |
| [CI/CD](./ci-cd/) | Build automation, testing pipelines, quality gates, GitHub Actions & GitLab CI examples |

### Security & Compliance

| Guide | What You'll Learn |
|-------|-------------------|
| [Security](./security/) | Authentication, RBAC, API security, encryption, XSS prevention, hardening checklist |
| [SSO](./sso/) | SAML payload validation, load balancer troubleshooting, IdP configuration |
| [Compliance](./compliance/) | GDPR, CCPA/CPRA, ITAR, EAR, SOC, ISO, and Colorado Privacy Act — with Mendix-specific guidance |

## Quick Start

**New to Mendix?** Start with [Entities](./entities/) to understand the domain model, then move to [Microflows](./microflows/) for server-side logic.

**Setting up a new project?** Read [Modules](./modules/) for project structure, then [Security](./security/) before you ship anything.

**Going to production?** Work through [Deployment](./deployment/), [Infrastructure](./infrastructure/), and [CI/CD](./ci-cd/) in that order.

**Dealing with compliance requirements?** The [Compliance](./compliance/) section has regulation-specific guides with Mendix implementation details for each.

## Contributing

Contributions are welcome. If you've solved a tricky Mendix problem and want to share the knowledge, open a PR.

A few guidelines:

- **Be practical.** Real configurations and code over abstract advice.
- **Be specific.** Include version numbers, known limitations, and gotchas.
- **Be direct.** Write like you're explaining something to a teammate, not writing a textbook.

## License

This project is licensed under the [Apache License 2.0](./LICENSE).
