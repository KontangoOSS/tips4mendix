[Home](../README.md) > **Security**

---

# Mendix Security Best Practices

## A Comprehensive Guide for Mendix Developers

**Version:** 1.0
**Date:** February 2026
**Classification:** Public

---

## Table of Contents

1. [Mendix Security Model Overview](#1-mendix-security-model-overview)
   - [The Layered Security Model](#the-layered-security-model)
   - [Project Security](#project-security)
   - [Module Security](#module-security)
   - [Entity Access](#entity-access)
   - [Page Access](#page-access)
   - [Microflow Access](#microflow-access)
   - [How the Layers Work Together](#how-the-layers-work-together)
2. [Authentication](#2-authentication)
   - [Built-in Authentication](#built-in-authentication)
   - [SSO Integration with SAML](#sso-integration-with-saml)
   - [SSO Integration with OIDC](#sso-integration-with-oidc)
   - [Multi-Factor Authentication](#multi-factor-authentication)
   - [Custom Authentication Microflows](#custom-authentication-microflows)
   - [Password Policies](#password-policies)
   - [Session Management](#session-management)
3. [Authorization](#3-authorization)
   - [Role-Based Access Control (RBAC)](#role-based-access-control-rbac)
   - [Entity Access Rules with XPath Constraints](#entity-access-rules-with-xpath-constraints)
   - [Parameterized Security](#parameterized-security)
   - [Negative vs. Positive Security Models](#negative-vs-positive-security-models)
   - [Common Authorization Pitfalls](#common-authorization-pitfalls)
4. [API Security](#4-api-security)
   - [Published REST Service Security](#published-rest-service-security)
   - [Published OData Security](#published-odata-security)
   - [Published Web Service (SOAP) Security](#published-web-service-soap-security)
   - [API Keys and Token Management](#api-keys-and-token-management)
   - [Rate Limiting](#rate-limiting)
   - [Consumed Service Security](#consumed-service-security)
5. [Data Encryption](#5-data-encryption)
   - [The Encryption Module](#the-encryption-module)
   - [At-Rest Encryption](#at-rest-encryption)
   - [In-Transit Encryption](#in-transit-encryption)
   - [Key Management](#key-management)
   - [Hashing vs. Encryption](#hashing-vs-encryption)
6. [Input Validation and XSS Prevention](#6-input-validation-and-xss-prevention)
   - [Server-Side Validation in Microflows](#server-side-validation-in-microflows)
   - [Validation Rules on Entities](#validation-rules-on-entities)
   - [HTML Sanitization](#html-sanitization)
   - [Preventing Injection Through Dynamic Content](#preventing-injection-through-dynamic-content)
   - [OQL and XPath Injection](#oql-and-xpath-injection)
   - [File Upload Validation](#file-upload-validation)
7. [CSRF Protection](#7-csrf-protection)
   - [How Mendix Handles CSRF](#how-mendix-handles-csrf)
   - [Built-in CSRF Tokens](#built-in-csrf-tokens)
   - [Custom API Endpoint Considerations](#custom-api-endpoint-considerations)
   - [SameSite Cookie Configuration](#samesite-cookie-configuration)
8. [Logging and Auditing](#8-logging-and-auditing)
   - [The Audit Trail Module](#the-audit-trail-module)
   - [Security-Relevant Logging](#security-relevant-logging)
   - [Log Node Configuration](#log-node-configuration)
   - [Tamper-Proof Logging](#tamper-proof-logging)
   - [Compliance-Oriented Logging](#compliance-oriented-logging)
9. [Dependency Security](#9-dependency-security)
   - [Reviewing Marketplace Modules](#reviewing-marketplace-modules)
   - [Java Dependency Scanning](#java-dependency-scanning)
   - [Keeping Dependencies Updated](#keeping-dependencies-updated)
   - [Custom Java Actions](#custom-java-actions)
   - [JavaScript Widget Security](#javascript-widget-security)
10. [Penetration Testing](#10-penetration-testing)
    - [Preparing a Mendix App for Pen Testing](#preparing-a-mendix-app-for-pen-testing)
    - [Common Findings in Mendix Apps](#common-findings-in-mendix-apps)
    - [Remediation Patterns](#remediation-patterns)
    - [Automated Security Scanning](#automated-security-scanning)
    - [Testing Checklists](#testing-checklists)
11. [Security Headers](#11-security-headers)
    - [Content Security Policy (CSP)](#content-security-policy-csp)
    - [X-Frame-Options](#x-frame-options)
    - [HTTP Strict Transport Security (HSTS)](#http-strict-transport-security-hsts)
    - [Additional Headers](#additional-headers)
    - [Configuring Headers via Reverse Proxy](#configuring-headers-via-reverse-proxy)
    - [Mendix Cloud Header Configuration](#mendix-cloud-header-configuration)
12. [Hardening Checklist](#12-hardening-checklist)
    - [Pre-Production Checklist](#pre-production-checklist)
    - [Runtime Configuration Hardening](#runtime-configuration-hardening)
    - [Infrastructure Hardening](#infrastructure-hardening)
    - [Ongoing Security Operations](#ongoing-security-operations)

---

## 1. Mendix Security Model Overview

Mendix uses a layered, declarative security model. Unlike traditional frameworks where security is bolted on through middleware or annotations scattered across code, Mendix treats security as a first-class configuration concern built directly into the platform. Understanding these layers -- and how they interact -- is the foundation for building secure applications.

### The Layered Security Model

Mendix security operates across five distinct layers, each enforced by the Mendix Runtime:

```
+-----------------------------------------------+
|            Project Security (Global)           |
|  Security level, demo users, anonymous access  |
+-----------------------------------------------+
         |
         v
+-----------------------------------------------+
|           Module Security (Per Module)         |
|    Module roles, role mapping to user roles    |
+-----------------------------------------------+
         |
         v
+-----------------------------------------------+
|          Entity Access (Data Layer)            |
| Access rules per entity, XPath constraints,   |
| attribute-level read/write control             |
+-----------------------------------------------+
         |
         v
+-----------------------------------------------+
|           Page Access (UI Layer)               |
|   Which roles can open which pages             |
+-----------------------------------------------+
         |
         v
+-----------------------------------------------+
|        Microflow/Nanoflow Access (Logic)       |
|   Which roles can execute which flows          |
+-----------------------------------------------+
```

Every request passes through all applicable layers. A user cannot access data unless every layer grants permission. This is a deny-by-default system: if you do not explicitly grant access, it is denied.

### Project Security

Project security is the top-level switch. It has three levels:

| Level | Behavior | Use Case |
|-------|----------|----------|
| **Off** | No security enforcement whatsoever. All data and logic are accessible to everyone. | Early prototyping only. Never deploy with this setting. |
| **Prototype / demo** | Security is enforced, but the runtime shows warnings instead of hard errors for missing access rules. Demo users are available on the login screen. | Internal demos, design reviews. |
| **Production** | Full enforcement. Missing access rules cause hard errors. No demo user shortcuts. | All deployments that face real users or real data. |

**Key settings within Project Security:**

- **User roles**: Define the application-wide roles (e.g., Administrator, Manager, User, Anonymous). These are the roles assigned to user accounts.
- **Demo users**: Predefined accounts for each role, available only when security level is Prototype/demo. Disable these for production.
- **Anonymous access**: Whether unauthenticated users can access any part of the application. When enabled, you must assign an anonymous user role that controls what anonymous users can see and do.
- **Password policy**: Minimum length, complexity requirements (digits, mixed case, symbols), and password expiration intervals.

**Best practices for Project Security:**

- Always set security to **Production** before deploying to any environment outside of development.
- Treat the "Prototype/demo" setting as a development convenience, never as a deployment option.
- If your app does not need anonymous access, turn it off. Every anonymous endpoint is an attack surface.
- Define the minimum number of user roles necessary. Each role adds complexity to your access rule matrix.

### Module Security

Each module in a Mendix app has its own security configuration. Module security defines **module roles** -- these are more granular than project-level user roles and control access within the scope of that module.

**Module roles vs. user roles:**

- A **user role** (project level) represents a business persona: "HRManager", "Employee", "ExternalAuditor".
- A **module role** (module level) represents a permission level within a specific module: "Administrator", "User", "ReadOnly".
- User roles are **mapped** to module roles. A single user role can be mapped to different module roles in different modules.

Example mapping:

| User Role | HR Module Role | Finance Module Role | Reporting Module Role |
|-----------|---------------|--------------------|-----------------------|
| HRManager | Administrator | ReadOnly | User |
| Employee | User | (none) | User |
| FinanceAdmin | ReadOnly | Administrator | Administrator |

**Best practices for Module Security:**

- Keep module roles generic and reusable: "Administrator", "User", "ReadOnly" work well for most modules.
- Map user roles to module roles deliberately. If a user role should not access a module at all, do not map it to any module role in that module.
- Review module role mappings when adding new user roles. It is easy to forget to add (or deliberately omit) mappings.
- When importing a Marketplace module, review its module roles and map only what is necessary. Many Marketplace modules ship with an "Administrator" module role that should only be mapped to your app's admin user role.

### Entity Access

Entity access is where Mendix security gets powerful -- and where most security mistakes happen. Entity access rules define, for each combination of entity and module role:

- **Whether the role can create, read, update, or delete objects** of that entity.
- **Which attributes** the role can read or write.
- **An XPath constraint** that limits which objects the role can see or modify.

An entity access rule looks like this (conceptually):

```
Entity: Order
Module Role: User
  Create: Yes
  Read:   Yes, constrained by [Order_Customer/Customer/Id = '[%CurrentUser%]']
  Update: Yes, constrained by [Order_Customer/Customer/Id = '[%CurrentUser%]' and Status != 'Shipped']
  Delete: No
  Readable attributes: OrderNumber, OrderDate, TotalAmount, Status
  Writable attributes: ShippingAddress, Notes
```

This rule says: a User can create orders, can read and update only their own orders (and cannot update shipped orders), cannot delete orders, can read most fields, and can only write to ShippingAddress and Notes.

**Critical points about entity access:**

1. **Entity access is enforced by the Runtime, not the UI.** Even if a page does not display certain data, a technically skilled user could craft API calls to retrieve it. Entity access rules are your actual security boundary.
2. **XPath constraints filter the dataset.** If a User queries for all orders, the Runtime silently applies the XPath constraint, returning only that user's orders. There is no error -- the other orders simply do not exist from that user's perspective.
3. **Attribute-level control is real.** If an attribute is not marked as readable for a role, the Runtime strips it from responses. The attribute returns as `null` / empty regardless of what the database contains.
4. **No rule means no access.** If you do not define an entity access rule for a module role on an entity, that role has zero access to that entity. This is the correct default behavior.

**Best practices for Entity Access:**

- Write XPath constraints that are as restrictive as possible. Start with maximum restriction and relax only when business requirements demand it.
- Always constrain read access. An unrestricted read rule means that role can see every record in the entity. Ask yourself: does this role really need to see all 500,000 customer records?
- Be explicit about writable attributes. Do not mark status fields, audit fields, or system fields as writable unless a role genuinely needs to modify them through the UI.
- Test entity access rules by signing in as each role and attempting to access data outside the expected scope. Use the Mendix Runtime API (or browser developer tools) to confirm that data is not leaking.
- Document your XPath constraints. Complex constraints are hard to read -- add comments explaining the business logic.

### Page Access

Page access controls which roles can navigate to which pages. When a user's role does not have access to a page, the page does not appear in navigation menus, and direct URL access returns an error.

**Important nuance:** Page access is a UI-level control. It prevents users from seeing pages, but it does not prevent data access. If an entity's access rules allow a role to read data, that data is accessible through the API regardless of page access settings. Page access is a usability and navigation concern, not a security boundary.

**Best practices for Page Access:**

- Configure page access for every page. Studio Pro will warn you about pages without access rules when security is set to Production.
- Use page access to enforce least-privilege navigation: roles should only see pages relevant to their work.
- Do not rely on page access as your only security measure. Always back it up with entity access rules.
- For admin pages, restrict access to a dedicated Administrator role.

### Microflow Access

Microflow access controls which roles can execute which microflows. This is critical because microflows contain business logic, including logic that modifies data, sends emails, triggers integrations, or performs administrative operations.

**When microflow access matters most:**

- Microflows that are exposed as REST/SOAP endpoints
- Microflows used as data sources for pages or widgets
- Microflows triggered by buttons or events on pages
- Scheduled events (these run as a system context, not as a user)

**Best practices for Microflow Access:**

- Grant microflow access only to roles that need to execute that logic.
- For microflows that perform destructive or sensitive operations (delete all records, export all data, reset passwords), restrict access to the minimum necessary roles.
- Be aware that nanoflows execute on the client and are visible in the browser. Do not put sensitive logic or secrets in nanoflows.
- Scheduled events bypass user-level security because they run in a system context. Audit scheduled events carefully -- they have unrestricted data access.

### How the Layers Work Together

Consider a scenario where an Employee clicks a button that triggers a microflow to display a list of salary records:

1. **Project Security**: Is security on? Yes (Production). Proceed.
2. **Module Security**: Is the Employee's user role mapped to a module role in the HR module? If not, access is denied at this level -- the employee cannot interact with anything in the HR module.
3. **Microflow Access**: Does the Employee's module role have execute access to this microflow? If not, the button click is rejected.
4. **Entity Access**: The microflow retrieves salary records. The Runtime applies XPath constraints: employees can only see their own salary records. The microflow receives a filtered dataset.
5. **Page Access**: The microflow tries to open a page showing the results. Does the Employee's role have access to that page? If not, the page does not render.

At every layer, the system enforces restrictions. The result is defense-in-depth: even if one layer is misconfigured, the other layers still limit exposure.

---

## 2. Authentication

Authentication is the process of verifying that a user is who they claim to be. Mendix provides several authentication mechanisms, from simple username/password to enterprise SSO integrations.

### Built-in Authentication

Mendix includes a built-in authentication system based on the `System.User` entity. Out of the box:

- Users authenticate with a username and password.
- Passwords are hashed using **bcrypt** (configurable rounds; default is 10).
- The Runtime manages sessions using cookies (`XASSESSIONID`).
- Failed login attempts can trigger account lockout (configurable).

**Built-in authentication configuration:**

| Setting | Recommendation | Why |
|---------|---------------|-----|
| Hash algorithm | BCrypt (default) | Industry standard, resistant to brute-force |
| BCrypt rounds | 10-12 | Higher = slower hashing = harder to brute-force, but impacts login performance |
| Session timeout | 10-30 minutes for sensitive apps | Limits exposure from unattended sessions |
| Max failed logins | 5 attempts, then lock for 15-30 minutes | Prevents credential stuffing |
| Password policy | Min 12 chars, require mixed case + digits + symbols | Aligns with current NIST guidance |

**Runtime settings for authentication:**

```
# In Mendix Runtime configuration (e.g., m2ee.yaml or environment variables)
EnableKeepAlive: true
SessionTimeout: 600000           # 10 minutes in milliseconds
ClusterManagerActionInterval: 5000
```

**Best practices:**

- Change default admin credentials immediately after initial deployment. The default admin account (`MxAdmin`) is a well-known target.
- Disable the default admin account if you have other administrator accounts configured.
- Set `EnableKeepAlive` appropriately. In high-security environments, shorter sessions with forced re-authentication are preferred over long-lived sessions.
- Configure account lockout policies. Without lockout, attackers can attempt unlimited passwords.

### SSO Integration with SAML

SAML (Security Assertion Markup Language) 2.0 is the most common SSO protocol for enterprise Mendix apps. The **SAML** module from the Mendix Marketplace handles the integration.

**How SAML works in Mendix:**

1. User navigates to the Mendix app.
2. The app redirects the user to the Identity Provider (IdP) -- e.g., Azure AD, Okta, ADFS.
3. The user authenticates at the IdP.
4. The IdP sends a signed SAML assertion back to the Mendix app.
5. The SAML module validates the assertion (signature, timestamps, audience) and creates or updates a local user account.
6. The user is logged in.

**SAML module configuration checklist:**

- **Assertion Consumer Service (ACS) URL**: Must match exactly between the Mendix app and the IdP configuration. Typically `https://your-app.mendixcloud.com/SSO/`.
- **Entity ID**: A unique identifier for your app. Use the app URL.
- **Certificate**: Import the IdP's signing certificate. The SAML module uses this to verify assertion signatures.
- **Attribute mapping**: Map IdP attributes (email, name, groups) to Mendix user attributes. Configure which attribute determines the username.
- **User provisioning**: Decide whether to auto-create users (Just-In-Time provisioning) or require pre-existing accounts.
- **Role mapping**: Map IdP groups or attributes to Mendix user roles.

**Security considerations for SAML:**

- **Always validate the assertion signature.** The SAML module does this by default -- never disable it.
- **Enforce HTTPS** for the ACS endpoint. SAML assertions contain sensitive identity data.
- **Set appropriate clock skew tolerance.** The default is typically 5 minutes. Tighter values reduce the window for replay attacks but can cause legitimate failures if server clocks drift.
- **Use encrypted assertions** if your IdP supports them. This protects assertion content even if TLS is somehow compromised.
- **Review the SAML module's "after startup" microflow.** This is where you configure the SAML module programmatically. Ensure it runs with the correct settings.
- **Validate the `InResponseTo` attribute** to prevent assertion replay attacks. The SAML module handles this, but verify it is enabled.

**Common SAML pitfalls:**

- Forgetting to update the IdP configuration when the app URL changes (e.g., moving from acceptance to production).
- Not mapping IdP roles to Mendix roles, resulting in users who can log in but cannot access anything.
- Using HTTP instead of HTTPS for the ACS URL, which exposes assertions to man-in-the-middle attacks.
- Not testing with multiple IdP users to verify attribute mapping works across different user profiles.

### SSO Integration with OIDC

OpenID Connect (OIDC) is a modern authentication layer built on OAuth 2.0. It is simpler to implement than SAML and is increasingly preferred for new integrations, especially with cloud-native identity providers.

The **OIDC SSO** module from the Mendix Marketplace supports OIDC integration.

**OIDC flow in Mendix:**

1. User navigates to the Mendix app.
2. The app redirects the user to the OIDC provider (e.g., Azure AD, Auth0, Keycloak).
3. The user authenticates.
4. The provider redirects back with an authorization code.
5. The Mendix app exchanges the code for tokens (ID token, access token, optionally refresh token).
6. The OIDC module validates the ID token and establishes a session.

**OIDC security considerations:**

- Use the **Authorization Code flow with PKCE** (Proof Key for Code Exchange). This prevents authorization code interception attacks. The OIDC module supports this.
- **Validate the ID token** completely: signature (using the provider's JWKS endpoint), issuer (`iss`), audience (`aud`), and expiration (`exp`).
- **Do not use the Implicit flow.** It exposes tokens in browser URLs and is deprecated by OAuth 2.1.
- Store **client secrets securely** -- use environment variables or the Mendix secrets store, not hardcoded values.
- Configure appropriate **scopes**: request only `openid`, `profile`, `email`, and any custom scopes you actually need.

### Multi-Factor Authentication

MFA adds a second layer of authentication beyond the password. In Mendix, MFA is typically implemented in one of these ways:

**1. IdP-level MFA (recommended):**
If you use SAML or OIDC, configure MFA at the identity provider (Azure AD Conditional Access, Okta MFA policies, etc.). This is the simplest and most secure approach because:
- The MFA logic is managed by a dedicated identity platform.
- You get access to hardware key support (FIDO2/WebAuthn), push notifications, and other strong MFA methods.
- The Mendix app does not need to handle MFA complexity.

**2. App-level MFA with the Google Authenticator module:**
The Mendix Marketplace includes a module that integrates TOTP (Time-based One-Time Password) support:
- Users scan a QR code with Google Authenticator, Authy, or any TOTP app.
- On login, they enter a 6-digit code in addition to their password.
- The module stores the shared secret in the Mendix database (encrypt this value).

**3. Custom MFA microflows:**
For specialized requirements, you can build custom MFA:
- Send a one-time code via email or SMS (use a reliable delivery service -- SMS is vulnerable to SIM swapping).
- Implement a challenge-response mechanism.
- Integrate with a dedicated MFA API (Duo, Twilio Verify).

**MFA best practices:**

- Prefer IdP-level MFA over app-level MFA when using SSO.
- If implementing app-level MFA, use TOTP over SMS. SMS is vulnerable to SIM swapping and SS7 interception.
- Provide MFA recovery mechanisms: backup codes, admin reset, or secondary verification methods.
- Enforce MFA for administrator and privileged accounts at minimum. Ideally, enforce it for all accounts.
- Log MFA events: enrollment, successful verification, failed verification, and recovery code usage.

### Custom Authentication Microflows

Mendix allows you to replace or extend the default authentication mechanism with custom microflows. This is useful for:

- Integrating with external user directories (LDAP, custom databases).
- Implementing custom login flows (multi-step, conditional).
- Adding pre-login or post-login logic (terms of service acceptance, license checks).

**Implementing a custom authentication microflow:**

1. Create a microflow that accepts `UserName` (String) and `Password` (String) parameters.
2. The microflow should validate credentials against your authentication source.
3. If authentication succeeds, retrieve or create the corresponding `System.User` object.
4. Return the `System.User` object from the microflow (return `empty` for failed authentication).
5. Configure the microflow as the custom authentication microflow in Project Security.

**Security considerations for custom authentication:**

- **Never log passwords.** Even at trace level, password values should never appear in logs.
- **Use constant-time comparison** for credential validation to prevent timing attacks. The Mendix built-in `System.VerifyPassword` action handles this correctly.
- **Implement rate limiting** in your custom microflow. Without it, attackers can attempt unlimited logins per second.
- **Handle errors consistently.** Return the same error message for "user not found" and "wrong password" to prevent username enumeration.
- **Audit failed login attempts.** Log the username (not the password), timestamp, and source IP if available.

### Password Policies

Mendix allows you to configure password policies in Project Security. A strong policy reduces the risk of credential-based attacks.

**Recommended password policy settings:**

| Setting | Recommended Value | Notes |
|---------|------------------|-------|
| Minimum length | 12 characters | NIST SP 800-63B recommends at least 8; 12+ is better |
| Require digit | Yes | |
| Require mixed case | Yes | |
| Require symbol | Yes | |
| Maximum age | 0 (no expiration) | NIST now recommends against forced rotation unless a breach is suspected |
| Minimum age | 1 day | Prevents users from cycling through passwords to reuse an old one |

**Additional password guidance:**

- Consider integrating with a breached-password database (Have I Been Pwned API) to reject known compromised passwords.
- Do not truncate or limit maximum password length unreasonably. Allow at least 64 characters.
- Display clear password requirements to users during registration and password changes.

### Session Management

Once authenticated, users are assigned a session. Session management has its own security considerations:

- **Session timeout**: Configure `SessionTimeout` in the Runtime settings. For sensitive applications, use 10-15 minutes. For general business apps, 30 minutes is common.
- **Session fixation**: Mendix regenerates the session ID after successful authentication, preventing session fixation attacks.
- **Cookie security flags**: The `XASSESSIONID` cookie should have `Secure` (HTTPS only), `HttpOnly` (not accessible to JavaScript), and `SameSite=Strict` or `SameSite=Lax` flags set. Mendix sets `HttpOnly` by default. Configure `Secure` and `SameSite` through Runtime settings or your reverse proxy.
- **Concurrent sessions**: Decide whether to allow multiple simultaneous sessions per user. For high-security apps, limit to one active session and invalidate previous sessions on new login.

**Runtime settings for session security:**

```
# Recommended session-related runtime settings
SessionTimeout: 900000                    # 15 minutes
EnableKeepAlive: false                    # For high-security apps
SessionKeepAliveUpdatesInterval: 100000   # Keep-alive ping interval
```

---

## 3. Authorization

Authorization determines what an authenticated user is allowed to do. Mendix uses a Role-Based Access Control (RBAC) model, extended with XPath constraints for fine-grained data-level authorization.

### Role-Based Access Control (RBAC)

Mendix RBAC operates at two levels:

**User roles** (project level) represent business personas:

```
User Roles:
  - Administrator    (full system access)
  - Manager          (read/write to team data)
  - Employee         (read/write to own data)
  - ExternalAuditor  (read-only to specific data)
  - Anonymous        (public-facing content only)
```

**Module roles** (module level) represent permission levels within a module:

```
HR Module:
  Module Roles:
    - Administrator  (manage all HR records)
    - Manager        (manage team records)
    - User           (view own records)
    - ReadOnly       (view assigned records)
```

**Mapping user roles to module roles:**

In Studio Pro, open the module's security settings and configure which user roles map to which module roles. This mapping is the bridge between the global role model and the per-module access rules.

**RBAC design principles:**

1. **Least privilege**: Each role should have the minimum permissions needed to perform its function. Start with no access and add permissions as requirements dictate.
2. **Separation of duties**: No single role should be able to both initiate and approve a sensitive operation (e.g., creating and approving a payment).
3. **Role hierarchy**: If your roles form a natural hierarchy (Admin > Manager > User), consider whether higher roles should inherit all lower-role permissions or whether each role's permissions should be independent.
4. **Minimize role count**: Each additional role multiplies the number of entity access rules you need to configure and maintain. Use the minimum number of roles that accurately represents your authorization model.

### Entity Access Rules with XPath Constraints

XPath constraints are the most powerful authorization mechanism in Mendix. They filter data at the Runtime level, ensuring that users can only see and modify objects they are authorized to access.

**Basic XPath constraint patterns:**

**User can only access their own data:**
```xpath
[Module.Entity_Account/System.Account/System.User = '[%CurrentUser%]']
```

**Manager can access their team's data:**
```xpath
[Module.Entity_Team/Module.Team/Module.Team_Manager/System.Account/System.User = '[%CurrentUser%]']
```

**User can access data in their department:**
```xpath
[Module.Entity_Department/Module.Department = '[%CurrentUser%]'/Module.Account_Department/Module.Department]
```

**Data filtered by status (e.g., only published content is public):**
```xpath
[Status = 'Published']
```

**Combined constraints (user's own data OR data shared with their team):**
```xpath
[Module.Entity_Owner/System.Account/System.User = '[%CurrentUser%]'
  or Module.Entity_Team/Module.Team/Module.Team_Members/System.Account/System.User = '[%CurrentUser%]']
```

**Advanced XPath constraint patterns:**

**Time-based access (records less than 30 days old):**
```xpath
[CreatedDate > '[%BeginOfCurrentDay%]' - 30]
```

**Multi-level association traversal:**
```xpath
[Module.Order_Customer/Module.Customer/Module.Customer_Region/Module.Region/Module.Region_Manager = '[%CurrentUser%]']
```

**Best practices for XPath constraints:**

- **Test constraints with realistic data.** An XPath that works with 10 records might behave unexpectedly with 100,000 records (e.g., if the association path returns unexpected results).
- **Prefer direct associations** over deeply nested paths. Each level of traversal adds complexity and potential for error.
- **Index the attributes and associations** used in XPath constraints. Without indexes, every entity access check requires a full table scan, degrading performance.
- **Be aware of OR constraints.** An OR in an XPath constraint can be less restrictive than you intend. Verify that the combined effect matches your authorization requirements.
- **Document complex constraints.** Future developers (including yourself) will need to understand why a constraint exists and what business rule it enforces.

### Parameterized Security

Parameterized security allows you to implement dynamic, data-driven access control that goes beyond static role assignments. Instead of hardcoding access rules per role, you store access decisions in data.

**Example: Feature flags controlling access.**

Create a `FeatureAccess` entity:

```
Entity: FeatureAccess
  - Feature (String)
  - UserRole (String)
  - IsEnabled (Boolean)
```

In microflows, check whether a feature is enabled for the current user's role before executing logic:

```
// Pseudocode for a microflow
Retrieve FeatureAccess where Feature = 'ExportData' and UserRole = $currentUserRole
If FeatureAccess/IsEnabled = true:
    Execute export logic
Else:
    Show error "You do not have access to this feature"
```

**Example: Organization-scoped access.**

For multi-tenant applications, associate users with organizations and constrain all data access:

```xpath
[Module.Entity_Organization/Module.Organization = '[%CurrentUser%]'/Module.Account_Organization/Module.Organization]
```

This ensures that users in Organization A never see Organization B's data, even if they share the same role.

**Dynamic role assignment:**

For complex scenarios, you can assign user roles dynamically based on data:

- A project-based system where a user is a "Manager" for Project A but a "Viewer" for Project B.
- A workflow system where the current step determines who can edit the record.
- A delegation system where users can temporarily grant their permissions to a substitute.

Implement these patterns using associations (e.g., `Project_Manager`, `Task_Assignee`) and XPath constraints rather than by changing user roles at runtime.

### Negative vs. Positive Security Models

**Positive security model (recommended):** Start with no access and explicitly grant permissions. Mendix uses this model -- if no entity access rule exists for a role, that role has no access.

**Negative security model (dangerous):** Start with full access and explicitly deny permissions. This model is error-prone because any oversight grants too much access.

Always work with the positive model: define exactly what each role can do, not what it cannot do.

### Common Authorization Pitfalls

**1. The "Administrator sees everything" trap:**
Do not give the Administrator role unrestricted access to all entities without XPath constraints just because they are an admin. Even administrators should not see data they do not need (e.g., raw password hashes in System.User).

**2. Missing entity access rules on associated entities:**
If you restrict access to `Order` but not to `OrderLine`, a user might not be able to see orders but could potentially retrieve order lines through the API.

**3. Overly broad write permissions:**
Allowing a role to write all attributes when they only need to modify two specific fields. This lets users modify status flags, audit timestamps, or association references they should not touch.

**4. Forgetting about created/deleted access:**
Read and write access are configured separately from create and delete access. A role might need to read and update records but should not be able to create new ones or delete existing ones.

**5. XPath constraints on write but not on read:**
If a user can read all records but only write to their own, they can still see all data. Ensure that read constraints are at least as restrictive as write constraints.

**6. Ignoring non-persistable entities:**
Non-persistable entities are not stored in the database, but they can still contain sensitive data in memory. Apply access rules to non-persistable entities when they hold sensitive information.

---

## 4. API Security

Mendix applications commonly expose APIs through published REST services, OData services, and SOAP web services. Each requires deliberate security configuration.

### Published REST Service Security

When you create a published REST service in Mendix, you need to configure authentication and authorization for each operation.

**Authentication methods for REST services:**

| Method | Mendix Support | Use Case |
|--------|---------------|----------|
| **Session-based (cookies)** | Built-in | Browser-based clients that have already authenticated through the Mendix login page |
| **Username/password (Basic Auth)** | Built-in | Service-to-service integrations with shared credentials |
| **Custom authentication** | Via microflow | Token-based auth (JWT, API keys), OAuth 2.0, certificate-based auth |
| **No authentication** | Built-in | Public endpoints (use sparingly) |

**Implementing custom authentication for REST:**

1. Create an authentication microflow that accepts an `HttpRequest` parameter.
2. Extract the authentication credential (e.g., `Authorization` header with a Bearer token).
3. Validate the credential (verify JWT signature, look up API key in database, call an OAuth introspection endpoint).
4. If valid, return a `System.User` object representing the authenticated principal.
5. If invalid, return `empty` -- Mendix will return a 401 response.

```
// Custom REST authentication microflow (pseudocode)
Input: HttpRequest

Extract 'Authorization' header from HttpRequest
If header starts with 'Bearer ':
    Extract token value
    Validate JWT (verify signature, check expiration, check issuer)
    If valid:
        Retrieve User by JWT subject claim
        Return User
    Else:
        Return empty
Else:
    Return empty
```

**Authorization for REST operations:**

- Each REST operation can be restricted to specific user roles (module roles).
- The user returned by the authentication microflow determines which roles are active.
- Entity access rules apply to data retrieved or modified by REST operation microflows, just as they do for UI-triggered microflows.

**REST security best practices:**

- **Always require authentication** unless the endpoint serves genuinely public data.
- **Use HTTPS exclusively.** Never expose REST endpoints over HTTP in production.
- **Validate all input parameters.** REST operation microflows receive raw input -- validate types, ranges, and formats before processing.
- **Return appropriate HTTP status codes.** Return 401 for unauthenticated requests, 403 for unauthorized requests, 404 for resources the user cannot access (not 403, to avoid revealing that the resource exists).
- **Paginate list responses.** Unbounded queries can be used for denial-of-service attacks.
- **Set response content type headers** correctly to prevent content-type confusion attacks.
- **Log API access** for auditing purposes: who accessed what endpoint, when, and from where.

### Published OData Security

OData services in Mendix follow similar patterns to REST services, with some additional considerations:

- **Entity access rules apply.** The OData service exposes entities, and the Runtime enforces the same entity access rules that apply to pages and microflows. This is a major advantage -- your security model is consistent across all access channels.
- **Countable queries.** OData supports `$count` queries. Ensure that entity access rules prevent users from counting records they should not know about.
- **Filter expressions.** OData `$filter` expressions are translated to database queries with entity access constraints applied. However, complex filters can be computationally expensive. Consider limiting supported filter operators.
- **Expand expressions.** OData `$expand` follows associations. Ensure that entity access rules on associated entities are correct, or users could expand into data they should not see.

**OData security best practices:**

- Limit exposed attributes to those that external consumers actually need.
- Configure read-only access unless the consumer needs to create, update, or delete data.
- Use a dedicated module role for OData consumers that grants only the necessary access.
- Monitor OData query patterns for unusual behavior (excessive `$expand`, broad `$filter` queries).

### Published Web Service (SOAP) Security

SOAP web services in Mendix use a similar security model:

- Authentication can be session-based, Basic Auth, or custom (via a header authentication microflow).
- Each published operation can be restricted to specific module roles.
- Entity access rules apply to data handled by the operation microflows.

**Additional SOAP security considerations:**

- **WS-Security headers**: For enterprise integrations, you may need to support WS-Security (UsernameToken, X.509 certificates). Implement this through a custom header validation microflow.
- **WSDL exposure**: By default, the WSDL is publicly accessible. If the service structure itself is sensitive, consider restricting WSDL access.
- **XML External Entity (XXE) attacks**: Mendix Runtime protects against XXE by default by disabling external entity processing in its XML parser. Do not override this behavior in custom Java actions.

### API Keys and Token Management

For service-to-service integrations, API keys and tokens need careful management:

**API key storage:**
- Store API keys as encrypted attributes (use the Encryption module).
- Never hardcode API keys in microflows, constants, or code.
- Use environment variables or the Mendix secrets store for API keys.

**API key lifecycle:**
- Generate cryptographically random keys (at least 32 characters).
- Implement key rotation: provide a mechanism to issue new keys and revoke old ones without downtime.
- Set expiration dates on keys.
- Log key usage for auditing.

**Token best practices:**
- Use short-lived tokens (15-60 minutes) for authentication.
- Use refresh tokens (longer-lived) to obtain new access tokens without re-authentication.
- Store refresh tokens securely (encrypted, in the database, never in browser local storage).
- Implement token revocation for logout and security events.

### Rate Limiting

Mendix does not provide built-in rate limiting for published services. Implement rate limiting at the infrastructure layer:

**Reverse proxy rate limiting (recommended):**

```nginx
# NGINX example
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

server {
    location /rest/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://mendix-app:8080;
    }
}
```

**Application-level rate limiting (custom):**

Create a `RateLimitEntry` entity that tracks request counts per client per time window. In your authentication microflow, check whether the client has exceeded its limit before processing the request.

```
// Rate limiting pseudocode
Retrieve RateLimitEntry for current client IP / API key in current time window
If count >= limit:
    Return HTTP 429 "Too Many Requests"
Else:
    Increment count
    Proceed with request
```

### Consumed Service Security

When your Mendix app consumes external APIs, security is also your concern:

- **Store credentials securely.** Use constants backed by environment variables, not hardcoded values.
- **Validate SSL certificates.** Do not disable certificate validation even in development. Use trusted certificates or import the CA certificate into the JVM trust store.
- **Handle sensitive data in responses carefully.** If an external API returns sensitive data (PII, financial data), apply the same encryption and access controls to it as you would to internally generated data.
- **Implement circuit breakers** for external calls. A compromised or unavailable external service should not cause your application to hang or crash.
- **Log consumed service calls** (without logging sensitive request/response bodies) for debugging and security auditing.

---

## 5. Data Encryption

Protecting data at rest and in transit is fundamental to application security. Mendix provides tools for encryption, but you must configure and use them deliberately.

### The Encryption Module

The **Encryption** module from the Mendix Marketplace provides AES-256 encryption and decryption capabilities for attribute values.

**How it works:**

1. Import the Encryption module from the Marketplace.
2. Set the `EncryptionKey` constant to a 32-character (256-bit) key. Store this key as an environment variable, not in the model.
3. Call the `Encrypt` action to encrypt a string value before storing it.
4. Call the `Decrypt` action to decrypt a value when you need to use it.

**What to encrypt:**

| Data Type | Encrypt? | Reason |
|-----------|----------|--------|
| Passwords | Hash, do not encrypt | Passwords should be one-way hashed (bcrypt), not reversibly encrypted |
| API keys/secrets | Yes | Must be recoverable for use, but should not be stored in plaintext |
| PII (SSN, national ID) | Yes | Regulatory requirement in most jurisdictions |
| Payment card data | Yes (or better, do not store) | PCI DSS requirement |
| Health records | Yes | HIPAA, GDPR requirement |
| Session tokens | Depends | If stored in the database, encrypt them |

**Using the Encryption module effectively:**

```
// Storing encrypted data (microflow pseudocode)
$EncryptedSSN = Encryption.Encrypt($PlaintextSSN)
$Person/SSN_Encrypted = $EncryptedSSN
Commit $Person

// Retrieving and decrypting (microflow pseudocode)
$PlaintextSSN = Encryption.Decrypt($Person/SSN_Encrypted)
// Use $PlaintextSSN, then discard -- do not store the decrypted value
```

**Important limitations:**

- Encrypted attributes cannot be searched or sorted at the database level. You cannot write XPath constraints against encrypted values.
- If you need to search encrypted data, consider storing a hash of the search value alongside the encrypted value, or use a blind index.
- The encryption key is a single point of failure. If lost, all encrypted data is irrecoverable.

### At-Rest Encryption

At-rest encryption protects data stored in the database and file storage.

**Database-level encryption:**

- **Mendix Cloud**: Databases in Mendix Cloud are encrypted at rest using the cloud provider's encryption (AES-256). This is transparent to the application.
- **On-premises / self-hosted**: Configure database encryption at the database level:
  - **PostgreSQL**: Use `pgcrypto` extension or Transparent Data Encryption (TDE) if available.
  - **SQL Server**: Enable Transparent Data Encryption (TDE).
  - **Oracle**: Use Transparent Data Encryption (TDE) with Oracle Advanced Security.

**File storage encryption:**

- **Mendix Cloud**: File storage (S3) is encrypted at rest by default.
- **On-premises**: Configure encryption on your file storage:
  - **S3-compatible storage**: Enable server-side encryption (SSE-S3 or SSE-KMS).
  - **Local file system**: Use encrypted volumes (LUKS on Linux, BitLocker on Windows).

**Application-level encryption (Encryption module):**

- Use when database-level encryption is insufficient (e.g., DBAs should not see sensitive data).
- Use when specific fields need stronger protection than the general database encryption.
- Use when you need to demonstrate field-level encryption to auditors.

### In-Transit Encryption

All data moving between components must be encrypted.

**Browser to application:**

- **Always use HTTPS (TLS 1.2 or 1.3).** Configure TLS at the load balancer or reverse proxy.
- **Redirect HTTP to HTTPS.** Users who type `http://` should be redirected, not served insecure content.
- **Use strong cipher suites.** Disable outdated ciphers (RC4, DES, 3DES, export ciphers).

**Application to database:**

- **Enable SSL/TLS for database connections.** Configure the JDBC connection string to require SSL:
  ```
  jdbc:postgresql://dbhost:5432/mydb?ssl=true&sslmode=verify-full
  ```
- **Verify the database server certificate** to prevent man-in-the-middle attacks.

**Application to external services:**

- Always use HTTPS when calling external APIs.
- Validate SSL certificates (do not set `verify=false`).
- Use certificate pinning for highly sensitive integrations (though this adds operational complexity).

**Internal service communication:**

- Even within a private network, use TLS between services. Zero-trust networking principles apply.
- Use mutual TLS (mTLS) for service-to-service authentication in high-security environments.

### Key Management

Key management is the hardest part of encryption. A strong algorithm with poor key management provides false security.

**Key management principles:**

1. **Separate keys from data.** Never store encryption keys in the same database or file system as the encrypted data.
2. **Use environment variables** for the Encryption module key. In Mendix Cloud, use the environment configuration. On-premises, use your platform's secrets management (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
3. **Rotate keys periodically.** Define a key rotation schedule (e.g., annually). When rotating:
   - Decrypt all data with the old key.
   - Re-encrypt with the new key.
   - Securely destroy the old key after confirming all data has been re-encrypted.
4. **Back up keys securely.** Use offline, encrypted backups stored in a physically separate location.
5. **Limit key access.** Only the application runtime should have access to the encryption key. Developers, DBAs, and operators should not have routine access.
6. **Audit key access.** Log every use of the encryption key (or at minimum, every configuration change).

**Key rotation microflow pattern:**

```
// Key rotation (pseudocode)
$OldKey = GetOldEncryptionKey()
$NewKey = GetNewEncryptionKey()

Retrieve all encrypted records (batched for performance)
For each record:
    $Plaintext = Decrypt(record/EncryptedValue, $OldKey)
    $NewCiphertext = Encrypt($Plaintext, $NewKey)
    record/EncryptedValue = $NewCiphertext
    Commit record

Update EncryptionKey constant to $NewKey
Securely delete $OldKey
```

### Hashing vs. Encryption

Understand when to use each:

| Scenario | Use | Why |
|----------|-----|-----|
| Storing passwords | Hash (bcrypt) | You never need to recover the original password; you only need to verify it |
| Storing API keys your app needs to send | Encrypt (AES-256) | You need to recover the original value to use it |
| Storing PII that users can view | Encrypt (AES-256) | You need to display the original value |
| Verifying data integrity | Hash (SHA-256) | You need to detect changes, not recover the original |
| Storing PII that only needs to be matched | Hash (SHA-256) + salt | You can verify a match without recovering the original |

---

## 6. Input Validation and XSS Prevention

Input validation prevents attackers from injecting malicious data into your application. Cross-site scripting (XSS) is one of the most common web vulnerabilities, and Mendix has both built-in protections and areas where you need to be vigilant.

### Server-Side Validation in Microflows

Client-side validation (in pages and nanoflows) provides a good user experience but is not a security control. Attackers can bypass the Mendix client entirely and send requests directly to the Runtime. Server-side validation in microflows is your actual security boundary.

**Validation pattern for microflows:**

```
// Microflow: ValidateAndSaveOrder (pseudocode)
Input: $Order (Order object)

// Validate required fields
If $Order/CustomerName = empty:
    Add validation feedback: "Customer name is required"

// Validate data types and ranges
If $Order/Quantity < 1 or $Order/Quantity > 10000:
    Add validation feedback: "Quantity must be between 1 and 10,000"

// Validate string lengths
If length($Order/Description) > 5000:
    Add validation feedback: "Description cannot exceed 5,000 characters"

// Validate formats
If not matches($Order/Email, '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'):
    Add validation feedback: "Invalid email format"

// Validate business rules
If $Order/ShipDate < [%CurrentDateTime%]:
    Add validation feedback: "Ship date cannot be in the past"

// If any validation feedback was added, abort
If hasValidationFeedback($Order):
    Return false

// Proceed with save
Commit $Order
Return true
```

**Best practices for server-side validation:**

- Validate **every** input parameter in microflows that create or modify data.
- Validate in the microflow that processes the data, not just in the page that collects it.
- Use validation feedback (not error messages) for user-facing validation -- this provides a better experience and does not leak internal details.
- Validate associations and references: ensure that the referenced object exists and that the current user has access to it (prevent IDOR -- Insecure Direct Object Reference).

### Validation Rules on Entities

Mendix supports validation rules directly on entity attributes:

- **Required**: The attribute must have a value.
- **Unique**: The attribute value must be unique across all objects of this entity.
- **Maximum length**: Limits the string length.
- **Regular expression**: The value must match a regex pattern.
- **Range**: Numeric values must fall within a specified range.

**Entity validation rule examples:**

| Attribute | Rule | Configuration |
|-----------|------|---------------|
| Email | Regex | `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` |
| PhoneNumber | Regex | `^\+?[1-9]\d{1,14}$` (E.164 format) |
| Age | Range | 0 to 150 |
| Username | Max length | 100 characters |
| TaxID | Regex | Country-specific pattern |

**Important**: Entity validation rules are enforced by the Runtime when objects are committed. They are not enforced when values are set in microflows -- only when the commit action runs. Design your microflows to handle validation failures gracefully.

### HTML Sanitization

Mendix renders text content safely by default -- attribute values displayed in text widgets are HTML-encoded, preventing XSS. However, there are scenarios where raw HTML is rendered:

**Dangerous: HTML/Content widgets:**
If you use a widget that renders HTML content (e.g., an HTML viewer, a rich text editor's output, or a custom widget), the content is rendered as raw HTML. If this content comes from user input, it can contain malicious scripts.

**Mitigation: Sanitize HTML before storage.**

Create a microflow that sanitizes HTML content before committing it:

```
// HTML sanitization microflow (pseudocode)
Input: $RawHTML (String)

// Option 1: Strip all HTML tags
$CleanText = replaceAll($RawHTML, '<[^>]*>', '')

// Option 2: Allow safe tags only (requires a Java action with a library like OWASP Java HTML Sanitizer)
$SanitizedHTML = JavaAction_SanitizeHTML($RawHTML)
// Allows: <p>, <b>, <i>, <ul>, <ol>, <li>, <a href="...">
// Removes: <script>, <iframe>, <object>, <embed>, event handlers (onclick, onerror, etc.)

Return $SanitizedHTML
```

**Using OWASP Java HTML Sanitizer in a custom Java action:**

```java
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

public class SanitizeHTML extends CustomJavaAction<String> {
    private String rawHTML;

    @Override
    public String executeAction() throws Exception {
        PolicyFactory policy = new HtmlPolicyBuilder()
            .allowElements("p", "b", "i", "u", "em", "strong", "br",
                           "ul", "ol", "li", "a", "h1", "h2", "h3")
            .allowAttributes("href").onElements("a")
            .allowUrlProtocols("https")
            .toFactory();

        return policy.sanitize(rawHTML);
    }
}
```

**Best practices for HTML sanitization:**

- Sanitize on input (before storage), not on output. This ensures that malicious content never enters your database.
- Use an allowlist approach: define what HTML is permitted, and strip everything else.
- Never trust user-supplied HTML, even from authenticated users.
- Be cautious with rich text editors. They produce HTML that is stored and later rendered -- this is a classic XSS vector.

### Preventing Injection Through Dynamic Content

Several Mendix features can introduce injection vulnerabilities if misused:

**1. Dynamic text in email templates:**
If you compose emails using string concatenation with user input, you risk HTML injection in the email body. Use template variables with proper encoding rather than raw concatenation.

**2. Custom widgets using `innerHTML`:**
Custom (pluggable) widgets that set `innerHTML` from Mendix attribute values are vulnerable. Use `textContent` or a sanitization library instead.

**3. URL parameters and deep links:**
If your app reads URL parameters and displays them on a page (e.g., a search query), ensure the value is not rendered as HTML.

**4. OQL queries built with string concatenation:**

```
// DANGEROUS - OQL injection
$Query = 'SELECT * FROM Module.Entity WHERE Name = '' + $UserInput + '''

// SAFE - Parameterized OQL
$Query = 'SELECT * FROM Module.Entity WHERE Name = $ParamName'
// Pass $UserInput as the $ParamName parameter
```

### OQL and XPath Injection

Mendix's XPath queries are generally safe from injection because they are constructed using the modeler's visual query builder, not through string concatenation. However, there are edge cases:

**OQL in datasets and custom queries:**
If you build OQL strings dynamically using string concatenation with user input, you are vulnerable to OQL injection. Always use parameterized queries.

**XPath in custom Java actions:**
If you construct XPath strings in Java actions using string concatenation, sanitize user input or use parameterized queries.

**XPath in the Mendix Client API:**
The Mendix client-side API allows JavaScript to execute XPath queries. If custom widgets pass unsanitized user input into these queries, injection is possible.

**Best practices:**

- Use the visual query builder whenever possible.
- When you must build queries dynamically, use parameterized queries.
- Never concatenate user input directly into query strings.
- If you must use string concatenation (rare), escape single quotes and validate input format.

### File Upload Validation

File uploads are a common attack vector. Validate uploaded files thoroughly:

**Validation checklist for file uploads:**

| Check | Implementation |
|-------|---------------|
| **File extension** | Maintain an allowlist of permitted extensions (e.g., `.pdf`, `.jpg`, `.png`, `.docx`). Reject all others. |
| **MIME type** | Verify the Content-Type header matches the expected file type. Note: MIME types can be spoofed. |
| **File content (magic bytes)** | For critical applications, validate the file's magic bytes (first few bytes that identify the file format) using a Java action. |
| **File size** | Set maximum file size limits. Mendix allows you to configure this per file upload widget. |
| **Filename** | Sanitize filenames: remove path separators, special characters, and excessively long names. |
| **Antivirus scanning** | For high-security applications, scan uploaded files with ClamAV or a cloud-based scanning service before storing them. |

**File upload security microflow:**

```
// File validation pseudocode
Input: $FileDocument

// Check extension
$Extension = toLowerCase(getFileExtension($FileDocument/Name))
If $Extension not in ['pdf', 'jpg', 'jpeg', 'png', 'docx', 'xlsx']:
    Delete $FileDocument
    Show error "File type not allowed"
    Return false

// Check size (e.g., max 10MB)
If $FileDocument/Size > 10485760:
    Delete $FileDocument
    Show error "File exceeds maximum size of 10MB"
    Return false

// Sanitize filename
$FileDocument/Name = sanitizeFilename($FileDocument/Name)

Commit $FileDocument
Return true
```

---

## 7. CSRF Protection

Cross-Site Request Forgery (CSRF) attacks trick authenticated users into performing unintended actions. A malicious website can submit requests to your Mendix app using the victim's authenticated session.

### How Mendix Handles CSRF

Mendix includes built-in CSRF protection for its standard request handling:

1. **CSRF tokens**: The Mendix Runtime generates a unique CSRF token for each user session. This token is included in every form submission and AJAX request made by the Mendix client.
2. **Token validation**: The Runtime validates the CSRF token on every state-changing request (POST, PUT, DELETE). If the token is missing or invalid, the request is rejected.
3. **Automatic inclusion**: The Mendix client (the JavaScript framework that runs in the browser) automatically includes the CSRF token in requests. You do not need to manually add it.

### Built-in CSRF Tokens

**How the token flow works:**

```
1. User logs in
2. Server generates CSRF token and sends it to the client
3. Client stores the token (in a meta tag or JavaScript variable)
4. For every subsequent request:
   a. Client includes the CSRF token as a request header (X-Csrf-Token)
   b. Server validates the token against the session
   c. If valid, process the request
   d. If invalid, reject with 403 Forbidden
```

**What Mendix protects automatically:**

- All requests made through the Mendix client (page interactions, microflow calls, data commits).
- Mendix REST service calls made through the Mendix client.
- Form submissions within Mendix pages.

**What Mendix does NOT automatically protect:**

- Custom REST endpoints that you expose for third-party consumers (external systems sending requests directly).
- Custom HTML/JavaScript that bypasses the Mendix client framework.
- Endpoints accessed by non-browser clients (mobile apps, CLI tools) -- these typically do not need CSRF protection because CSRF is a browser-specific attack.

### Custom API Endpoint Considerations

When you publish REST services intended for external (non-browser) consumers, CSRF protection may conflict with your integration pattern:

**Scenario 1: REST service consumed by another server (no CSRF needed):**

Server-to-server calls do not originate from a browser with an existing session. These calls use their own authentication (API key, Basic Auth, Bearer token) and are not vulnerable to CSRF because there is no browser session to hijack.

Configure your REST service to use custom authentication (not session-based) for external consumers:

```
Published REST Service: OrderAPI
  Authentication: Custom (microflow-based)
  -> Validates API key or JWT
  -> No browser session, no CSRF risk
```

**Scenario 2: REST service consumed by custom JavaScript in the same app (CSRF needed):**

If your custom widget or JavaScript snippet calls a REST endpoint within the same application, you must include the CSRF token:

```javascript
// Include the CSRF token in custom JavaScript calls
const csrfToken = mx.session.getConfig("csrftoken");

fetch("/rest/myservice/v1/data", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "X-Csrf-Token": csrfToken
    },
    body: JSON.stringify(data),
    credentials: "same-origin"  // Include session cookies
});
```

**Scenario 3: REST service consumed by a separate frontend (CSRF mitigation needed):**

If a separate frontend application (React, Angular) authenticates with your Mendix backend using session cookies, CSRF protection is relevant. Options:

- Use token-based authentication (JWT) instead of session cookies. Tokens are not automatically included by the browser, so CSRF is not a concern.
- If you must use cookies, implement the double-submit cookie pattern: send the CSRF token as both a cookie and a request header, and validate that they match.

### SameSite Cookie Configuration

The `SameSite` cookie attribute is a defense-in-depth measure against CSRF:

| Value | Behavior | CSRF Protection |
|-------|----------|----------------|
| `Strict` | Cookie is never sent in cross-site requests | Strong, but breaks legitimate cross-site navigation |
| `Lax` | Cookie is sent with top-level navigation (GET) but not with cross-site POST/PUT/DELETE | Good balance for most apps |
| `None` | Cookie is always sent (requires `Secure` flag) | No CSRF protection from this mechanism |

**Recommended configuration:**

```
# Set via reverse proxy or Mendix Runtime configuration
SameSite: Lax
```

Use `Lax` as the default. Use `Strict` if your application is never accessed via cross-site links (e.g., internal enterprise apps). Use `None` only if you have a legitimate need for cross-site cookie sharing (e.g., embedding your app in an iframe on another domain).

Configure `SameSite` at the reverse proxy level:

```nginx
# NGINX example
proxy_cookie_flags ~ secure samesite=lax httponly;
```

```
# Caddy example
header Set-Cookie "SameSite=Lax; Secure; HttpOnly" {
    # Applied to all Set-Cookie headers
}
```

---

## 8. Logging and Auditing

Comprehensive logging is essential for security monitoring, incident response, and compliance. Mendix provides several logging mechanisms, but you need to configure them thoughtfully.

### The Audit Trail Module

The **Audit Trail** module from the Mendix Marketplace automatically tracks changes to entities.

**How it works:**

1. Import the Audit Trail module.
2. Configure which entities to audit by adding the `AuditTrail.AudittrailSuperClass` generalization (inheritance) to your entities.
3. The module automatically records:
   - Who changed the object (user)
   - When the change occurred (timestamp)
   - What changed (old value, new value, attribute name)
   - What type of change (create, update, delete)

**Audit Trail entity structure:**

```
AuditTrail.Log
  - DateTime (DateTime)
  - LogObject (String) -- entity name
  - LogAction (Enum) -- Create, Change, Delete
  - LogNode (String) -- object ID
  - AuditTrail.Log_User (Association to System.User)

AuditTrail.LogLine
  - Attribute (String) -- attribute name
  - OldValue (String) -- previous value
  - NewValue (String) -- current value
  - AuditTrail.LogLine_Log (Association to Log)
```

**Configuration considerations:**

- **Selective auditing**: Do not audit every entity. Focus on entities containing sensitive data, financial records, user accounts, and security-relevant configuration.
- **Performance impact**: Audit logging adds overhead to every commit operation on audited entities. In high-throughput scenarios, consider asynchronous audit logging.
- **Storage growth**: Audit logs grow indefinitely. Implement a retention policy (e.g., archive logs older than 2 years, delete logs older than 7 years) based on your compliance requirements.
- **Encrypted fields**: If you audit encrypted attributes, the audit trail stores the encrypted values (ciphertext), not the plaintext. This is usually the correct behavior -- you do not want decrypted sensitive data in audit logs.

**Best practices for the Audit Trail module:**

- Audit all entities that contain PII, financial data, or security-relevant configuration.
- Audit changes to user accounts, roles, and permissions.
- Protect audit log entities with strict access rules: most roles should have read-only access (or no access) to audit data.
- Do not allow any role to delete audit records through the application. Implement a background process for retention management.
- Include audit data in your backup strategy.

### Security-Relevant Logging

Beyond data change auditing, log security events explicitly in your microflows:

**Events to log:**

| Event | Log Level | Details to Include |
|-------|-----------|-------------------|
| Successful login | Info | Username, timestamp, source IP (if available) |
| Failed login | Warning | Username attempted, timestamp, source IP, failure reason |
| Account lockout | Warning | Username, number of failed attempts, lockout duration |
| Password change | Info | Username, timestamp (not the password) |
| Role change | Warning | Username, old role, new role, who made the change |
| Access denied | Warning | Username, resource attempted, timestamp |
| Data export | Info | Username, entity exported, record count, timestamp |
| API key created/revoked | Warning | Key identifier (not the key value), who created/revoked, timestamp |
| Configuration change | Warning | Setting name, old value, new value, who changed it |
| Encryption key rotation | Critical | Timestamp, who initiated, number of records re-encrypted |

**Implementing security logging in microflows:**

```
// Security logging microflow (pseudocode)
$LogMessage = '[SECURITY] Failed login attempt for user: ' + $Username +
              ' at ' + formatDateTime([%CurrentDateTime%], 'yyyy-MM-dd HH:mm:ss') +
              ' from IP: ' + $SourceIP

Log message: $LogMessage
Log node: 'Security'
Log level: Warning
```

### Log Node Configuration

Mendix uses **log nodes** to categorize log output. Configure log levels per node:

| Log Node | Recommended Level | Purpose |
|----------|------------------|---------|
| `ConnectionBus` | Warning | Database queries. Set to Trace only for debugging (reveals query structure). |
| `Security` | Info | Authentication and authorization events |
| `WebServices` | Info | API call logging |
| `Core` | Warning | Mendix Runtime core operations |
| `ActionManager` | Warning | Scheduled event execution |
| `Custom.Security` | Info | Your custom security log node |

**Creating a custom log node:**

In your microflows, use a consistent log node name for all security-related logging:

```
Log Node: "Security.Authentication"
Log Node: "Security.Authorization"
Log Node: "Security.DataAccess"
Log Node: "Security.Configuration"
```

This allows you to:
- Set log levels independently for each security concern.
- Filter log output by category in log management tools.
- Route security logs to a dedicated log stream for SIEM integration.

**Important runtime log settings:**

- **Do not set `ConnectionBus` to Trace in production.** This logs every SQL query, including potentially sensitive data values.
- **Do not set `Core` to Trace in production.** This generates enormous log volumes that can fill disk space.
- **Set custom log nodes to at least Info** for security events. You want these in your logs even when general logging is at Warning level.

### Tamper-Proof Logging

Standard application logs can be modified by anyone with server access. For security-critical logging, implement tamper-proof mechanisms:

**1. Forward logs to an external system in real time:**

Send logs to a centralized logging service (Splunk, ELK Stack, Datadog, AWS CloudWatch) where application administrators cannot modify or delete them.

Configure log forwarding in the Mendix Runtime:

```
# Forward logs to an external syslog server
LogFileName: /var/log/mendix/application.log

# Use a syslog forwarder (e.g., rsyslog, Fluentd, Filebeat) to ship logs
# to a central logging system in real time
```

**2. Hash-chain logs:**

For compliance-critical audit trails, implement a hash chain:

```
// Hash chain pseudocode
$PreviousHash = GetLastAuditLogHash()
$CurrentEntry = $Timestamp + $User + $Action + $Details
$CurrentHash = SHA256($PreviousHash + $CurrentEntry)
Store $CurrentEntry with $CurrentHash

// To verify integrity: recalculate hashes from the first entry
// Any tampering breaks the chain
```

**3. Write-once storage:**

Store audit logs in write-once storage (S3 with Object Lock, WORM-compliant storage). This prevents deletion or modification even by administrators.

**4. Digital signatures:**

Sign log entries with a private key. Anyone with the corresponding public key can verify that log entries have not been altered.

### Compliance-Oriented Logging

Different regulations have specific logging requirements:

**GDPR:**
- Log all access to personal data (who accessed what, when).
- Log data subject requests (access, deletion, correction).
- Retain logs for as long as needed to demonstrate compliance, but not longer than necessary.

**HIPAA:**
- Log all access to Protected Health Information (PHI).
- Retain audit logs for at least 6 years.
- Include user identification, date/time, and type of action in all log entries.

**SOC 2:**
- Log all authentication events.
- Log authorization failures.
- Monitor and alert on anomalous access patterns.
- Retain logs for at least 1 year.

**PCI DSS:**
- Log all access to cardholder data.
- Log all administrative actions.
- Retain logs for at least 1 year, with 3 months immediately available.
- Implement automated log monitoring and alerting.

---

## 9. Dependency Security

Mendix applications depend on Marketplace modules, Java libraries, and custom widgets. Each dependency is a potential attack vector.

### Reviewing Marketplace Modules

Before importing a Marketplace module into your application:

**Evaluation checklist:**

| Criterion | What to Check |
|-----------|---------------|
| **Publisher** | Is it published by Mendix or a Mendix Partner? These are generally more reliable than community contributions. |
| **Ratings and reviews** | Read reviews for security-related concerns. Low ratings may indicate quality or security issues. |
| **Update frequency** | When was the module last updated? Modules not updated for 2+ years may have unpatched vulnerabilities. |
| **Version compatibility** | Is the module compatible with your Mendix Studio Pro version? Incompatible modules may behave unpredictably. |
| **Source code access** | Can you review the module's microflows, Java actions, and configurations? Obfuscated modules are harder to audit. |
| **Dependencies** | Does the module bring in additional Java libraries or other modules? Each dependency is an additional attack surface. |
| **Permissions** | What module roles does it define? Does it need access to system entities? |
| **Data model** | Does it create new entities? Does it modify existing ones? What data does it store? |

**After importing a Marketplace module:**

1. Review the module's security settings. Ensure module roles are mapped only to appropriate user roles.
2. Review entity access rules. Some modules grant broad access by default -- tighten access to match your requirements.
3. Review any microflows that run "after startup" or as scheduled events. These run with elevated privileges.
4. Review Java actions for suspicious behavior (network calls, file system access, command execution).
5. Test the module's functionality in a non-production environment before deploying to production.

**Red flags in Marketplace modules:**

- Java actions that make network calls to unknown endpoints.
- Modules that request access to `System.User` or `System.Session` without a clear reason.
- Modules that store sensitive data in plaintext.
- Modules with no documentation about their security model.
- Modules that use `executeWithoutContext` or `sudo` calls in Java, bypassing security.

### Java Dependency Scanning

Mendix applications run on the JVM and can include Java libraries (JAR files) in the `userlib` folder. These libraries may contain known vulnerabilities.

**Scanning tools:**

| Tool | Type | Integration |
|------|------|-------------|
| **OWASP Dependency-Check** | Open source | CLI, Maven/Gradle plugin, CI/CD integration |
| **Snyk** | Commercial (free tier) | CLI, GitHub integration, CI/CD |
| **JFrog Xray** | Commercial | Artifactory integration |
| **GitHub Dependabot** | Free (GitHub repos) | Automatic PR creation for updates |
| **Trivy** | Open source | Container and filesystem scanning |

**Running OWASP Dependency-Check on a Mendix project:**

```bash
# Install dependency-check CLI
# Then scan the userlib folder

dependency-check \
    --project "MyMendixApp" \
    --scan ./userlib/ \
    --format HTML \
    --out ./dependency-check-report/

# Review the generated HTML report for vulnerabilities
```

**Integrating dependency scanning into CI/CD:**

```yaml
# Example: GitHub Actions workflow
name: Dependency Security Scan
on: [push, pull_request]

jobs:
  dependency-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run OWASP Dependency-Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'MyMendixApp'
          path: './userlib'
          format: 'HTML'
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: dependency-check-report
          path: './reports'
```

**Best practices for Java dependencies:**

- Scan dependencies before every release to production.
- Maintain a software bill of materials (SBOM) listing all Java libraries and their versions.
- Subscribe to security advisories for critical libraries (e.g., Apache Commons, Jackson, Log4j).
- Remove unused JAR files from `userlib`. Every unused library is unnecessary attack surface.
- When a vulnerability is found, update the library promptly. If the vulnerable library is part of a Marketplace module, contact the module publisher or find an alternative.

### Keeping Dependencies Updated

**Mendix Runtime updates:**

- Mendix releases monthly updates that include security patches for the Runtime, bundled libraries, and the Mendix client.
- Review the release notes for security fixes before updating.
- Test updates in a non-production environment before deploying to production.
- Do not skip major version updates indefinitely. Older versions eventually lose support and stop receiving security patches.

**Marketplace module updates:**

- Check for updates to imported Marketplace modules regularly (at least monthly).
- Review changelogs for security-related fixes.
- Test module updates in a non-production environment -- module updates can change behavior.
- If a module is no longer maintained, consider finding an alternative or forking it (if the license allows).

**Java library updates:**

- Use dependency scanning results to identify outdated libraries with known CVEs.
- Update libraries that have critical or high-severity CVEs immediately.
- For medium/low-severity CVEs, plan updates within your regular release cycle.
- Verify that updated libraries are compatible with your Mendix version and other libraries.

### Custom Java Actions

Custom Java actions in Mendix have access to the full JVM runtime, which means they can:

- Access the file system.
- Make network connections.
- Execute system commands.
- Access the database directly (bypassing Mendix entity access rules).

**Security guidelines for custom Java actions:**

1. **Minimize custom Java code.** Prefer Mendix-native functionality over Java actions. Every line of Java is code you need to maintain and audit.
2. **Review Java actions during code reviews.** Pay attention to:
   - Input validation (are parameters sanitized?).
   - Error handling (do exceptions leak internal details?).
   - Resource cleanup (are connections, streams, and files properly closed?).
   - Privilege escalation (does the code bypass Mendix security?).
3. **Do not use `Core.execute()` with user-supplied strings.** This is command injection.
4. **Do not use `Runtime.executeWithoutContext()` unless absolutely necessary.** This bypasses all Mendix security.
5. **Sanitize file paths** to prevent path traversal attacks (e.g., `../../etc/passwd`).
6. **Use parameterized queries** if accessing the database directly.
7. **Log security-relevant actions** performed by Java actions.

### JavaScript Widget Security

Custom (pluggable) widgets run in the browser and have access to the DOM, network requests, and local storage.

**Widget security checklist:**

| Concern | Mitigation |
|---------|------------|
| **XSS** | Never use `innerHTML` with user-supplied data. Use `textContent` or a sanitization library. |
| **Sensitive data exposure** | Do not store secrets in widget configuration or local storage. |
| **Third-party libraries** | Scan widget dependencies (`npm audit`). Keep them updated. |
| **Network requests** | Widgets should only communicate with the Mendix backend, not with arbitrary external endpoints. |
| **CSP compliance** | Ensure widgets do not use `eval()` or inline `<script>` tags that violate Content Security Policy. |

**Auditing a custom widget:**

```bash
# In the widget project directory
npm audit                     # Check for known vulnerabilities
npm audit fix                 # Auto-fix where possible
npx eslint --ext .tsx,.ts .   # Lint for common issues
```

---

## 10. Penetration Testing

Penetration testing (pen testing) validates your security controls by simulating real attacks. Mendix applications have a specific architecture that influences how pen tests are conducted and what findings are typical.

### Preparing a Mendix App for Pen Testing

**Before the test:**

1. **Define scope**: Clearly specify which environments, endpoints, and functionalities are in scope. Include:
   - The Mendix application URL(s).
   - Published REST/OData/SOAP services.
   - Custom API endpoints.
   - Authentication mechanisms (login page, SSO, API authentication).
   - File upload/download functionality.

2. **Provide documentation to testers**:
   - Application architecture overview (Mendix Runtime, database, file storage, integrations).
   - User roles and their intended access levels.
   - Published API documentation (Swagger/OpenAPI specs, WSDL).
   - Known technology stack (Mendix version, Java version, database type).

3. **Create test accounts** for each user role. Testers need to test authorization from different perspectives.

4. **Set up a dedicated test environment** that mirrors production configuration but uses test data. Never pen test against production with real data.

5. **Ensure logging is enabled** at appropriate levels during the test so you can correlate tester activity with log entries.

6. **Notify stakeholders**: Inform your Mendix Cloud team (if applicable) or infrastructure team that a pen test will occur, to prevent false positive security alerts.

**Mendix-specific considerations for testers:**

- Mendix uses a client-server architecture where the client is a JavaScript SPA. Testers should intercept and modify requests at the HTTP level (using Burp Suite, OWASP ZAP) rather than testing only through the UI.
- The Mendix Runtime API (`/xas/`) handles data operations. Testers should focus on this endpoint for authorization testing.
- Entity access rules are enforced server-side. Testers should verify that the rules work correctly by attempting to access data outside their authorized scope through direct API calls.
- Mendix generates client-side JavaScript. Testers should review this code for information disclosure (entity names, attribute names, service endpoints).

### Common Findings in Mendix Apps

Based on real-world penetration tests of Mendix applications, these are the most common findings:

**1. Missing or overly permissive entity access rules (High severity)**

**Finding**: A role can access data that it should not be able to see, either because no entity access rule exists or because the XPath constraint is too broad.

**Example**: An Employee role can retrieve all salary records by crafting an API call to `/xas/`, bypassing the page that normally filters data.

**Remediation**: Add or tighten XPath constraints on entity access rules. Test by making direct API calls (not just through the UI) to verify that data filtering works at the Runtime level.

**2. Insecure Direct Object Reference (IDOR) (High severity)**

**Finding**: A user can access or modify objects belonging to other users by manipulating object IDs in API requests.

**Example**: Changing the ID in a REST endpoint URL (`/rest/orders/v1/order/12345` to `/rest/orders/v1/order/12346`) returns another user's order.

**Remediation**: Use XPath constraints in entity access rules to restrict access to the current user's objects. In REST operation microflows, validate that the requested object belongs to the current user before returning it.

**3. Information disclosure through error messages (Medium severity)**

**Finding**: Error responses reveal internal details such as database table names, stack traces, or Mendix entity names.

**Example**: An invalid API request returns a stack trace showing the Mendix microflow name and entity structure.

**Remediation**: Configure the Runtime to suppress detailed error messages in production:
```
# Runtime configuration
com.mendix.core.ShouldStackTraceBeIncluded: false
```

In custom error handling, return generic error messages without internal details.

**4. Missing security headers (Medium severity)**

**Finding**: The application does not set security headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options).

**Remediation**: Configure headers at the reverse proxy level (covered in Section 11).

**5. Session timeout too long (Low-Medium severity)**

**Finding**: User sessions persist for hours without re-authentication.

**Remediation**: Set `SessionTimeout` to an appropriate value (10-30 minutes for sensitive applications).

**6. Verbose client-side code (Low severity)**

**Finding**: The Mendix client-side JavaScript reveals entity names, attribute names, microflow names, and association paths. This is not a vulnerability itself but provides reconnaissance information.

**Remediation**: This is inherent to the Mendix architecture and cannot be fully eliminated. Ensure that server-side security (entity access rules, microflow access) is robust enough that knowledge of entity names does not help an attacker.

**7. Missing rate limiting on authentication endpoints (Medium severity)**

**Finding**: The login endpoint accepts unlimited authentication attempts, allowing brute-force attacks.

**Remediation**: Implement account lockout (built-in Mendix feature) and rate limiting at the reverse proxy level.

**8. Privilege escalation through microflow manipulation (High severity)**

**Finding**: A user can trigger a microflow that they should not have access to by modifying client-side requests.

**Remediation**: Configure microflow access rules correctly. Never rely on client-side checks (hiding a button) as your only access control.

### Remediation Patterns

**Pattern 1: Fixing overly permissive entity access.**

Before:
```
Entity: Customer
Role: User
Read: Yes (no XPath constraint -- user can read ALL customers)
```

After:
```
Entity: Customer
Role: User
Read: Yes, constrained by [Module.Customer_Account = '[%CurrentUser%]']
```

**Pattern 2: Preventing IDOR in REST services.**

Before:
```
// REST operation microflow
Input: $OrderID (Long)
Retrieve Order where Id = $OrderID
Return Order
```

After:
```
// REST operation microflow
Input: $OrderID (Long)
Retrieve Order where Id = $OrderID
  AND Module.Order_Customer/Module.Customer/Module.Customer_Account = '[%CurrentUser%]'
If Order = empty:
    Return HTTP 404  // Not 403, to prevent information leakage
Return Order
```

**Pattern 3: Sanitizing error responses.**

Before:
```
// Error handler
Return HTTP 500 with body: $Exception/Message + $Exception/StackTrace
```

After:
```
// Error handler
Log $Exception/Message + $Exception/StackTrace at Error level
Return HTTP 500 with body: "An internal error occurred. Reference ID: " + $ReferenceID
```

### Automated Security Scanning

Complement manual pen testing with automated scanning:

**OWASP ZAP (free, open source):**

```bash
# Run ZAP against a Mendix application
docker run -t owasp/zap2docker-stable zap-full-scan.py \
    -t https://your-app.mendixcloud.com \
    -r zap-report.html

# For authenticated scanning, provide ZAP with valid session cookies
# or configure the authentication context in ZAP
```

**Burp Suite (commercial, free community edition):**

- Use the scanner module for automated vulnerability detection.
- Use the intruder module for testing entity access rules (fuzz object IDs).
- Use the repeater module for manual testing of individual requests.

**Integration into CI/CD:**

```yaml
# Example: Run OWASP ZAP in CI/CD pipeline
security-scan:
  stage: test
  script:
    - docker run --rm -v $(pwd):/zap/wrk owasp/zap2docker-stable \
        zap-api-scan.py -t https://test-app.example.com/rest/api/v1/ \
        -f openapi -r zap-api-report.html
  artifacts:
    paths:
      - zap-api-report.html
```

### Testing Checklists

**Authentication testing:**

- [ ] Verify that failed login attempts trigger account lockout.
- [ ] Confirm that passwords are hashed, not stored in plaintext.
- [ ] Test session timeout behavior.
- [ ] Verify that session cookies have Secure, HttpOnly, and SameSite flags.
- [ ] Test that session IDs are regenerated after login.
- [ ] Attempt to reuse invalidated session tokens.
- [ ] Test concurrent session behavior.

**Authorization testing:**

- [ ] For each user role, attempt to access data belonging to other users (IDOR).
- [ ] For each user role, attempt to execute microflows restricted to other roles.
- [ ] For each user role, attempt to access pages restricted to other roles.
- [ ] Verify that XPath constraints are applied at the API level, not just the UI level.
- [ ] Test attribute-level access (can restricted attributes be read through the API?).
- [ ] Test create/delete permissions separately from read/update.

**API testing:**

- [ ] Test all published REST endpoints with no authentication.
- [ ] Test all published REST endpoints with invalid authentication.
- [ ] Test all published REST endpoints with valid authentication but insufficient authorization.
- [ ] Fuzz input parameters for injection vulnerabilities.
- [ ] Test file upload endpoints with malicious files.
- [ ] Verify that API responses do not include excessive data.

---

## 11. Security Headers

HTTP security headers instruct browsers to enable (or disable) specific security features. Mendix applications should be deployed behind a reverse proxy that sets these headers.

### Content Security Policy (CSP)

CSP tells the browser which content sources are trusted, preventing XSS attacks by blocking unauthorized scripts, styles, and other resources.

**Recommended CSP for a Mendix application:**

```
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'unsafe-inline' 'unsafe-eval';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data: https:;
    font-src 'self' data:;
    connect-src 'self' https://sprintr.home.mendix.com wss:;
    frame-ancestors 'self';
    base-uri 'self';
    form-action 'self';
```

**Explanation of each directive:**

| Directive | Value | Reason |
|-----------|-------|--------|
| `default-src` | `'self'` | Only load resources from the app's own origin by default |
| `script-src` | `'self' 'unsafe-inline' 'unsafe-eval'` | Mendix client requires inline scripts and eval. This is a known limitation. |
| `style-src` | `'self' 'unsafe-inline'` | Mendix client uses inline styles |
| `img-src` | `'self' data: https:` | Allow images from the app, data URIs (used by some widgets), and HTTPS sources |
| `font-src` | `'self' data:` | Allow fonts from the app and base64-encoded fonts |
| `connect-src` | `'self' wss:` | Allow XHR/WebSocket connections to the app. Add external API origins if consumed from the client. |
| `frame-ancestors` | `'self'` | Prevent the app from being embedded in iframes on other domains (clickjacking protection) |
| `base-uri` | `'self'` | Prevent `<base>` tag injection |
| `form-action` | `'self'` | Prevent form submissions to other domains |

**Tightening CSP:**

The `'unsafe-inline'` and `'unsafe-eval'` directives weaken CSP significantly. Unfortunately, the Mendix client framework requires them. If you are using Mendix 10+ and custom widgets that do not require `eval`, you may be able to remove `'unsafe-eval'`. Test thoroughly.

For custom pages or widgets:
- Use nonces or hashes instead of `'unsafe-inline'` where possible.
- Avoid `eval()` and `Function()` in custom JavaScript code.

**CSP reporting:**

Use the `report-uri` or `report-to` directive to receive violation reports without blocking content:

```
Content-Security-Policy-Report-Only:
    default-src 'self';
    script-src 'self';
    report-uri /api/csp-report;
```

This sends violation reports to your endpoint without blocking any content, allowing you to test a stricter policy before enforcing it.

### X-Frame-Options

Prevents your application from being embedded in iframes on other domains, protecting against clickjacking attacks.

```
X-Frame-Options: DENY
```

| Value | Behavior |
|-------|----------|
| `DENY` | The page cannot be displayed in an iframe at all |
| `SAMEORIGIN` | The page can only be displayed in an iframe on the same origin |
| `ALLOW-FROM uri` | The page can be displayed in an iframe on the specified origin (deprecated; use CSP `frame-ancestors` instead) |

**Recommendation**: Use `DENY` unless your application is legitimately embedded in iframes. If it is, use `SAMEORIGIN` or the CSP `frame-ancestors` directive for more granular control.

**Note**: `frame-ancestors` in CSP supersedes `X-Frame-Options`. Set both for backward compatibility with older browsers.

### HTTP Strict Transport Security (HSTS)

HSTS tells browsers to only access the application over HTTPS, preventing protocol downgrade attacks and cookie hijacking.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `max-age` | `31536000` | Browser remembers to use HTTPS for 1 year |
| `includeSubDomains` | (flag) | Applies to all subdomains |
| `preload` | (flag) | Allows submission to browser HSTS preload lists |

**Important considerations:**

- **Do not enable HSTS until you are confident that HTTPS works correctly** on your domain and all subdomains. Once a browser receives an HSTS header, it will refuse to connect over HTTP for the specified duration.
- Start with a short `max-age` (e.g., 300 seconds / 5 minutes) and increase it gradually after verifying correct behavior.
- If you use `includeSubDomains`, ensure that all subdomains support HTTPS. A subdomain that only serves HTTP will become inaccessible.
- The `preload` flag is a commitment: once your domain is in browser preload lists, removing it takes months. Only add it for domains where HTTPS is permanent.

### Additional Headers

**X-Content-Type-Options:**

Prevents browsers from MIME-type sniffing, which can turn a harmless file into an executable script.

```
X-Content-Type-Options: nosniff
```

Always set this header. There is no reason to allow MIME sniffing.

**Referrer-Policy:**

Controls how much referrer information is included when navigating away from your application.

```
Referrer-Policy: strict-origin-when-cross-origin
```

| Value | Behavior |
|-------|----------|
| `no-referrer` | Never send referrer |
| `strict-origin-when-cross-origin` | Send full URL for same-origin, only origin for cross-origin, nothing for downgrade |
| `same-origin` | Send referrer only for same-origin requests |

**Recommendation**: Use `strict-origin-when-cross-origin` as a balanced default. Use `no-referrer` for applications handling highly sensitive URLs.

**Permissions-Policy (formerly Feature-Policy):**

Controls which browser features (camera, microphone, geolocation, etc.) the application can use.

```
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

This disables camera, microphone, geolocation, and payment APIs. Enable only the features your application actually uses:

```
# If your app uses geolocation
Permissions-Policy: camera=(), microphone=(), geolocation=(self), payment=()
```

**X-XSS-Protection:**

This header was used to enable browser XSS filters. Modern browsers have deprecated it in favor of CSP. However, it can still be set for older browser compatibility:

```
X-XSS-Protection: 0
```

Setting it to `0` is now recommended because the legacy XSS filter could itself be exploited in some browsers. Rely on CSP instead.

**Cache-Control for sensitive pages:**

Prevent browsers and proxies from caching sensitive responses:

```
Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate
Pragma: no-cache
Expires: 0
```

Apply this to responses containing sensitive data (personal information, financial data) to prevent data leakage through browser caches.

### Configuring Headers via Reverse Proxy

Mendix applications are typically deployed behind a reverse proxy (NGINX, Caddy, Apache, AWS ALB, Azure Application Gateway). Configure security headers at the proxy level.

**NGINX configuration:**

```nginx
server {
    listen 443 ssl http2;
    server_name myapp.example.com;

    # SSL configuration
    ssl_certificate /etc/ssl/certs/myapp.crt;
    ssl_certificate_key /etc/ssl/private/myapp.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header X-XSS-Protection "0" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'self'; base-uri 'self'; form-action 'self';" always;

    # Proxy to Mendix Runtime
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Caddy configuration:**

```
myapp.example.com {
    reverse_proxy localhost:8080

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
        X-XSS-Protection "0"
        Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'self'; base-uri 'self'; form-action 'self';"
    }
}
```

**Apache configuration:**

```apache
<VirtualHost *:443>
    ServerName myapp.example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/myapp.crt
    SSLCertificateKeyFile /etc/ssl/private/myapp.key
    SSLProtocol -all +TLSv1.2 +TLSv1.3

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set X-XSS-Protection "0"
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'self'; base-uri 'self'; form-action 'self';"

    ProxyPass / http://localhost:8080/
    ProxyPassReverse / http://localhost:8080/
    ProxyPreserveHost On
</VirtualHost>
```

### Mendix Cloud Header Configuration

If you deploy on Mendix Cloud, some security headers can be configured through the Mendix Developer Portal:

1. Go to your app's environment in the Developer Portal.
2. Navigate to **Network** > **Custom Headers**.
3. Add the security headers listed above.

**Mendix Cloud defaults:**

- HSTS is enabled by default on Mendix Cloud.
- X-Frame-Options is set to `SAMEORIGIN` by default. Override to `DENY` if iframe embedding is not needed.
- Other security headers must be configured explicitly.

**Validating your headers:**

Use online tools to verify that headers are correctly configured:

```bash
# Check headers with curl
curl -I https://myapp.example.com

# Or use securityheaders.com for a comprehensive analysis
```

---

## 12. Hardening Checklist

This checklist covers every layer of a Mendix application deployment. Work through it before every production release.

### Pre-Production Checklist

**Project Security:**

- [ ] Security level is set to **Production** (not Off or Prototype/demo).
- [ ] Demo users are disabled or removed.
- [ ] Default admin password (`MxAdmin`) has been changed to a strong, unique password.
- [ ] Anonymous access is disabled unless explicitly required. If enabled, the anonymous role has minimal permissions.
- [ ] Password policy enforces minimum 12 characters with complexity requirements.
- [ ] Account lockout is configured (5 failed attempts, 15-30 minute lockout).

**User Roles and Authorization:**

- [ ] Each user role follows least-privilege: minimum permissions necessary for its function.
- [ ] User roles are mapped to module roles deliberately (not just "map everything").
- [ ] No user role has unrestricted access to sensitive entities without XPath constraints.
- [ ] Entity access rules include XPath constraints for row-level security on all entities containing user-specific or organization-specific data.
- [ ] Attribute-level access is configured: roles cannot write to status fields, audit fields, or system fields unless necessary.
- [ ] Create and delete permissions are configured separately from read/update.
- [ ] Non-persistable entities containing sensitive data have access rules.

**Pages and Navigation:**

- [ ] Every page has page access configured for appropriate roles.
- [ ] Admin pages are restricted to administrator roles only.
- [ ] Navigation items are consistent with page access (no orphaned menu items).
- [ ] Deep link pages validate user authorization before displaying content.

**Microflows and Logic:**

- [ ] Every microflow exposed through pages, REST services, or widgets has access rules.
- [ ] Microflows that perform destructive operations (bulk delete, data export, password reset) are restricted to appropriate roles.
- [ ] Scheduled events are reviewed for correct behavior and appropriate data access.
- [ ] No sensitive data (passwords, keys, secrets) is hardcoded in microflows.
- [ ] Server-side validation exists for all data creation and modification operations.
- [ ] Error handling does not expose internal details (entity names, stack traces, SQL errors).

**Nanoflows:**

- [ ] Nanoflows do not contain sensitive logic or data processing that should be server-side.
- [ ] Nanoflows do not contain hardcoded secrets, API keys, or tokens.
- [ ] Nanoflow access is restricted to appropriate roles.

**API Security:**

- [ ] All published REST services require authentication.
- [ ] REST service authentication uses custom microflows with token validation (not just Basic Auth) for external consumers.
- [ ] Published OData services expose only necessary entities and attributes.
- [ ] API input parameters are validated in operation microflows.
- [ ] API error responses do not leak internal details.
- [ ] Rate limiting is configured at the reverse proxy level for API endpoints.
- [ ] API documentation (Swagger/WSDL) is not publicly accessible unless intended.

**Data Security:**

- [ ] Sensitive attributes (PII, financial data, health data) are encrypted using the Encryption module.
- [ ] The encryption key is stored as an environment variable, not in the model.
- [ ] Database connections use SSL/TLS.
- [ ] File storage is encrypted at rest.
- [ ] Backups are encrypted.
- [ ] Data retention policies are implemented for entities with personal data.

**Authentication:**

- [ ] SSO integration (SAML/OIDC) is configured correctly with certificate validation.
- [ ] MFA is enabled for administrator accounts (at minimum).
- [ ] Session timeout is set to an appropriate value (10-30 minutes for sensitive apps).
- [ ] Session cookies have Secure, HttpOnly, and SameSite flags.
- [ ] Login/logout events are logged.

### Runtime Configuration Hardening

**Critical Runtime settings:**

```
# Suppress stack traces in error responses
com.mendix.core.ShouldStackTraceBeIncluded: false

# Session timeout (milliseconds) -- 15 minutes
SessionTimeout: 900000

# Disable client-side logging in production
ClientLogLevel: NONE

# Restrict file upload types (if applicable)
com.mendix.storage.AllowedMimeTypes: application/pdf,image/jpeg,image/png

# Database connection pool settings
ConnectionPoolingMaxActive: 50
ConnectionPoolingMaxIdle: 10
ConnectionPoolingMinIdle: 5

# Enable strict mode for model validation
StrictMode: true
```

**Environment variables to set:**

| Variable | Purpose | Example |
|----------|---------|---------|
| `ADMIN_PASSWORD` | Override default admin password | (strong random password) |
| `DATABASE_URL` | Database connection with SSL | `jdbc:postgresql://host:5432/db?ssl=true&sslmode=verify-full` |
| `MX_ENCRYPTION_KEY` | Encryption module key | (32-character random string) |
| `SAML_ENCRYPTION_KEY` | SAML module encryption key | (random string, stored securely) |
| `JAVA_OPTS` | JVM security settings | `-Djava.security.egd=file:/dev/urandom` |

**Log level configuration for production:**

```
# Minimal logging -- increase temporarily for debugging
ConnectionBus: WARNING
Core: WARNING
ActionManager: WARNING
Microflows: WARNING
Security: INFO
WebServices: INFO
REST: INFO
```

### Infrastructure Hardening

**Network security:**

- [ ] The Mendix application is behind a reverse proxy / load balancer. The Runtime is not directly exposed to the internet.
- [ ] Only ports 80 (HTTP redirect) and 443 (HTTPS) are open to the public. The Runtime port (8080) is internal only.
- [ ] Database port (5432 for PostgreSQL) is not accessible from the public network.
- [ ] File storage (S3, MinIO) is not directly accessible from the public network.
- [ ] Network segmentation separates the web tier, application tier, and database tier.
- [ ] Firewall rules follow least-privilege: only necessary connections are allowed.

**TLS configuration:**

- [ ] TLS 1.2 or 1.3 only (TLS 1.0 and 1.1 are disabled).
- [ ] Strong cipher suites are configured (ECDHE + AES-GCM preferred).
- [ ] SSL certificates are valid and not expired.
- [ ] Certificate auto-renewal is configured (e.g., Let's Encrypt with auto-renewal).
- [ ] HSTS is enabled with an appropriate `max-age`.

**Security headers:**

- [ ] Content-Security-Policy is configured.
- [ ] X-Frame-Options is set to DENY (or SAMEORIGIN if embedding is needed).
- [ ] X-Content-Type-Options is set to nosniff.
- [ ] Referrer-Policy is set to strict-origin-when-cross-origin.
- [ ] Permissions-Policy restricts unused browser features.
- [ ] Strict-Transport-Security is set with a long max-age.

**Container / VM hardening (for self-hosted deployments):**

- [ ] The Mendix Runtime runs as a non-root user.
- [ ] The file system is read-only except for directories that need write access (temporary files, logs).
- [ ] Unnecessary packages and services are removed from the base image.
- [ ] Security patches are applied to the OS and all system packages.
- [ ] Container images are scanned for vulnerabilities before deployment.
- [ ] Resource limits (CPU, memory) are configured to prevent denial-of-service.

**Database hardening:**

- [ ] Database user credentials are strong and unique per environment.
- [ ] The application database user has minimum necessary privileges (no `SUPERUSER`, no `CREATE DATABASE`).
- [ ] Database backups are automated, encrypted, and stored in a separate location.
- [ ] Database access is logged.
- [ ] Point-in-time recovery is configured for critical databases.

**Secrets management:**

- [ ] No secrets (passwords, API keys, encryption keys) are stored in the application model, source control, or plaintext configuration files.
- [ ] All secrets are managed through environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
- [ ] Secrets are rotated on a defined schedule.
- [ ] Access to secrets is logged and audited.

### Ongoing Security Operations

**Regular activities:**

| Activity | Frequency | Owner |
|----------|-----------|-------|
| Review entity access rules | Every sprint / release | Development team |
| Run dependency scan (OWASP Dependency-Check) | Every release, at minimum monthly | DevOps / Security |
| Update Mendix Runtime version | Monthly (review release notes) | Development team |
| Update Marketplace modules | Monthly | Development team |
| Review audit logs for anomalies | Weekly | Security / Operations |
| Rotate encryption keys | Annually | Security |
| Rotate API keys and service credentials | Quarterly | Operations |
| Full penetration test | Annually | External security firm |
| Automated security scan (ZAP/Burp) | Monthly or per release | DevOps |
| Review and update security headers | Quarterly | DevOps |
| Review user accounts and roles | Quarterly | Application owner |
| Test backup and recovery procedures | Quarterly | Operations |
| Security awareness training for developers | Annually | Management |

**Incident response preparation:**

- [ ] An incident response plan exists and is documented.
- [ ] Contact information for the security team, Mendix support, and infrastructure providers is readily available.
- [ ] Log aggregation and alerting are configured to detect security events (failed logins, access denied, unusual API usage).
- [ ] A process exists for emergency patching (when a critical CVE is published).
- [ ] Regular tabletop exercises are conducted to practice incident response.

**Monitoring and alerting:**

Set up alerts for:

- More than 10 failed login attempts from a single IP in 5 minutes.
- Access denied errors exceeding normal baseline.
- Application errors exceeding normal baseline.
- SSL certificate expiration (alert 30 days before expiry).
- Unusual data export volumes (e.g., a user downloading 10,000 records when the normal pattern is 50).
- Runtime restarts outside of deployment windows.
- Database connection pool exhaustion.
- Disk space approaching capacity (logs, database, file storage).

---

## Quick Reference: Security Configuration Locations

| Security Concern | Where to Configure |
|-----------------|-------------------|
| Security level (Off/Prototype/Production) | Project Security in Studio Pro |
| User roles | Project Security > User Roles |
| Module roles and mapping | Module Security in Studio Pro |
| Entity access rules and XPath | Entity properties > Access Rules |
| Page access | Page properties > Visible For |
| Microflow access | Microflow properties > Allowed Roles |
| Password policy | Project Security > Password Policy |
| Session timeout | Runtime configuration (`SessionTimeout`) |
| Encryption key | Environment variable (`EncryptionKey` constant) |
| Security headers | Reverse proxy configuration |
| TLS certificates | Reverse proxy / load balancer |
| Database encryption | Database server configuration |
| Log levels | Runtime configuration (log nodes) |
| SAML/OIDC configuration | SAML/OIDC module administration pages |
| Rate limiting | Reverse proxy configuration |

---

## References

- [Mendix Security Documentation](https://docs.mendix.com/howto/security/)
- [Mendix Runtime Security Best Practices](https://docs.mendix.com/refguide/security/)
- [OWASP Top 10 Web Application Security Risks](https://owasp.org/www-project-top-ten/)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-63B Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Mendix Marketplace: Encryption Module](https://marketplace.mendix.com/link/component/1011)
- [Mendix Marketplace: SAML Module](https://marketplace.mendix.com/link/component/1174)
- [Mendix Marketplace: OIDC SSO Module](https://marketplace.mendix.com/link/component/120371)
- [Mendix Marketplace: Audit Trail Module](https://marketplace.mendix.com/link/component/138)
- [OWASP Java HTML Sanitizer](https://owasp.org/www-project-java-html-sanitizer/)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Mozilla Observatory](https://observatory.mozilla.org/) -- Online tool for evaluating security headers
- [SecurityHeaders.com](https://securityheaders.com/) -- Quick header analysis

---

<div align="center">

**[Back to Home](../README.md)**

</div>
