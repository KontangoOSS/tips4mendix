# Mendix Marketplace Modules Guide

A practical guide to finding, evaluating, installing, customizing, and publishing Mendix Marketplace modules. This covers everything from picking the right module to maintaining it in production.

---

## Table of Contents

- [1. What is the Mendix Marketplace](#1-what-is-the-mendix-marketplace)
  - [Module Types](#module-types)
  - [How Licensing Works](#how-licensing-works)
  - [Marketplace vs. Building It Yourself](#marketplace-vs-building-it-yourself)
- [2. Evaluating Marketplace Modules](#2-evaluating-marketplace-modules)
  - [Quality Indicators](#quality-indicators)
  - [Mendix-Supported vs. Community](#mendix-supported-vs-community)
  - [Version Compatibility](#version-compatibility)
  - [Evaluation Checklist](#evaluation-checklist)
- [3. Installing and Configuring](#3-installing-and-configuring)
  - [Installation Through Studio Pro](#installation-through-studio-pro)
  - [Manual Import](#manual-import)
  - [Resolving Import Conflicts](#resolving-import-conflicts)
  - [Post-Install Configuration](#post-install-configuration)
  - [Module Dependencies](#module-dependencies)
- [4. Commonly Used Modules](#4-commonly-used-modules)
  - [Community Commons](#community-commons)
  - [Nanoflow Commons](#nanoflow-commons)
  - [Atlas UI Resources](#atlas-ui-resources)
  - [SAML (SSO)](#saml-sso)
  - [Email Module (with Templates)](#email-module-with-templates)
  - [Encryption](#encryption)
  - [Deep Link](#deep-link)
  - [REST and SOAP Helpers](#rest-and-soap-helpers)
  - [Excel Import and Export](#excel-import-and-export)
  - [PDF Document Generation](#pdf-document-generation)
  - [Other Notable Modules](#other-notable-modules)
- [5. Security Considerations](#5-security-considerations)
  - [Why This Matters](#why-this-matters)
  - [Reviewing Third-Party Code](#reviewing-third-party-code)
  - [Access Rules and Entity Access](#access-rules-and-entity-access)
  - [Security Review Checklist](#security-review-checklist)
  - [Compliance Environments](#compliance-environments)
- [6. Customizing Marketplace Modules](#6-customizing-marketplace-modules)
  - [The Golden Rule](#the-golden-rule)
  - [Safe Customization Patterns](#safe-customization-patterns)
  - [When to Fork vs. Extend](#when-to-fork-vs-extend)
  - [Protecting Your Changes From Updates](#protecting-your-changes-from-updates)
  - [Documentation of Customizations](#documentation-of-customizations)
- [7. Updating Marketplace Modules](#7-updating-marketplace-modules)
  - [Version Management Strategy](#version-management-strategy)
  - [Update Process](#update-process)
  - [Testing After Updates](#testing-after-updates)
  - [Rollback Strategy](#rollback-strategy)
  - [Reading Changelogs](#reading-changelogs)
- [8. Building and Publishing](#8-building-and-publishing)
  - [When to Publish](#when-to-publish)
  - [Module Architecture for Publishing](#module-architecture-for-publishing)
  - [Packaging Your Module](#packaging-your-module)
  - [Documentation Requirements](#documentation-requirements)
  - [The Publishing Process](#the-publishing-process)
  - [Maintaining a Published Module](#maintaining-a-published-module)
- [9. Troubleshooting](#9-troubleshooting)
  - [Common Import Errors](#common-import-errors)
  - [Version Conflicts](#version-conflicts)
  - [Dependency Issues](#dependency-issues)
  - [Runtime Errors From Marketplace Modules](#runtime-errors-from-marketplace-modules)
  - [Performance Problems](#performance-problems)
  - [Getting Help](#getting-help)

---

## 1. What is the Mendix Marketplace

The Mendix Marketplace is the central repository for reusable components that extend what you can do with the Mendix platform. It lives at [marketplace.mendix.com](https://marketplace.mendix.com/) and is integrated directly into Studio Pro.

Think of it as npm or Maven but for Mendix. Instead of writing everything from scratch, you pull in modules that other developers (or Mendix itself) have already built and tested. Some of these are polished, production-ready components maintained by Mendix. Others are community contributions that range from excellent to "use at your own risk."

The Marketplace has been around since the early days of the platform, but it has evolved significantly. Early on, it was mostly a dumping ground for app store widgets. Now it includes full solution templates, connectors to external services, utility libraries, and complete application modules with their own domain models and microflows.

### Module Types

There are several categories of content on the Marketplace. Understanding what each one is helps you know what you are getting into before you download something.

**Modules**

These are the most common type. A module is a self-contained package that includes some combination of domain models, microflows, nanoflows, pages, Java actions, and constants. When you import a module, it shows up as its own module in your project's module list.

Examples: Community Commons, SAML, Email Module, Encryption.

Modules can range from simple utility collections (a handful of Java actions) to complex subsystems with their own entities, pages, and scheduled events. The bigger the module, the more care you need to take during installation and updates.

**Widgets**

Widgets are front-end components that you can drop onto pages. They are built with JavaScript/TypeScript (usually React for modern widgets, Dojo for legacy ones) and packaged as `.mpk` files. They show up in your widget toolbox in Studio Pro.

Examples: Charts widget, Rich Text editor, Data Grid 2, Gallery.

Widgets are generally lower-risk than modules because they don't modify your domain model or add microflows. They do run client-side code though, so security review still matters.

**Connectors**

Connectors are modules specifically designed to integrate with external services. They wrap API calls, handle authentication, and provide Mendix-native interfaces (microflow actions, domain models) for talking to things like AWS, Azure, SAP, Salesforce, and so on.

Examples: AWS S3 Connector, MS Graph Connector, SAP OData Connector, Slack Connector.

Connectors usually come with their own configuration pages and constants that you need to fill in with API keys, endpoints, and credentials. They also tend to have dependencies on other modules like Community Commons or the Encryption module.

**Solutions**

Solutions are complete, pre-built applications or large functional blocks that you can use as a starting point or integrate wholesale. These are typically built and maintained by Mendix partners or Mendix itself.

Examples: Workflow Commons, Data Widgets, Atlas Core.

Solutions are the most opinionated type of Marketplace content. They come with their own design decisions, patterns, and sometimes even their own navigation structure. You are buying into their approach when you use them.

**Starter Apps / Templates**

These are project templates that you can use when creating a new Mendix app. Instead of starting from a blank project, you start from a pre-built application with some functionality already in place.

Examples: Blank Web App, Blank Native Mobile App, various industry-specific starters.

You only use these at project creation time. They are not imported into existing projects.

### How Licensing Works

Most Marketplace content is free to use. The license is usually Apache 2.0 or MIT for community modules, and Mendix's own license for their supported modules.

Some modules and solutions are commercial and require a separate license or subscription. These are clearly marked on the Marketplace listing. Common examples include premium connectors and partner-built solutions.

Always check the license before importing a module into a commercial project. The license information is on the Marketplace listing page under the "License" section.

### Marketplace vs. Building It Yourself

The decision to use a Marketplace module vs. building your own comes down to a few factors:

| Factor | Use Marketplace | Build Your Own |
|---|---|---|
| Functionality is generic (email, encryption, Excel) | Yes | No |
| You need it quickly | Yes | No |
| You need deep customization | Maybe not | Yes |
| It is a core differentiator for your app | No | Yes |
| The module is Mendix-supported | Strong yes | - |
| The module has not been updated in 2+ years | Be cautious | Consider it |
| You have compliance requirements (ITAR, FedRAMP) | Review carefully | Maybe |

The sweet spot for Marketplace modules is generic, horizontal functionality that every app needs but that is not worth building from scratch. Email sending, PDF generation, encryption, SSO. Those are the modules that save you the most time.

---

## 2. Evaluating Marketplace Modules

Not all Marketplace modules are created equal. Before you add a dependency to your project, you need to evaluate whether the module is worth the trade-off. Every module you import is code you are responsible for, even if you did not write it.

### Quality Indicators

**Download Count**

High download counts (10,000+) generally indicate that a module has been battle-tested across many projects. It does not guarantee quality, but it does mean a lot of people have used it and presumably found it useful. Low download counts (under 100) should make you more cautious, not necessarily avoidant.

**Star Ratings**

The star rating on the Marketplace is a rough signal. Look at the actual reviews, not just the aggregate number. A module with 4.2 stars and 50 reviews is more trustworthy than one with 5.0 stars and 3 reviews.

Pay attention to negative reviews specifically. They often describe real pain points: upgrade issues, missing documentation, breaking changes, performance problems. Those are the things that will bite you in production.

**Last Updated Date**

This is one of the most important indicators. A module that has not been updated in over a year might be:

- Abandoned by its maintainer
- Incompatible with newer versions of Studio Pro
- Missing security patches

That said, some modules are genuinely "done" and do not need frequent updates. A simple utility function module might go years without changes because it just works. Use judgment.

**Studio Pro Version Compatibility**

Check which versions of Studio Pro the module supports. The listing page shows this. If the module says it supports Studio Pro 9.x and you are on 10.x, you might run into issues. Sometimes it works anyway, sometimes it does not.

**Documentation Quality**

Good modules have good documentation. If the Marketplace listing is three sentences and a screenshot, that is a red flag. Look for:

- Clear setup instructions
- Configuration steps
- Known limitations
- Example usage
- Troubleshooting guidance

**Source Code Availability**

Some modules include their source code (Java actions, JavaScript widget code). Being able to read the source is valuable for security review and debugging. Modules that are entirely opaque (compiled Java JARs with no source) should be treated with more caution.

### Mendix-Supported vs. Community

This distinction matters a lot.

**Mendix-Supported Modules** (marked with a blue "Mendix" badge or "Platform Supported" label):

- Built and maintained by Mendix
- Tested against new Studio Pro releases before they ship
- Get security patches
- Have official support through Mendix Support tickets
- Follow Mendix's own development standards
- Examples: SAML, Atlas UI, Workflow Commons, Data Widgets

**Community Modules** (marked with a "Community" badge):

- Built by individual developers, partners, or companies
- Maintained on a best-effort basis
- May or may not be updated for new Studio Pro releases
- Support comes from the community forums, not Mendix Support
- Quality varies enormously
- Examples: Many utility modules, niche connectors, specialized widgets

**Mendix Labs / Experimental**:

- Prototypes or experimental features from Mendix
- Not production-ready
- May be discontinued
- Useful for evaluation and prototyping, not for production apps

**Siemens / Partner Modules**:

- Built by Mendix partners
- Usually well-maintained but support goes through the partner, not Mendix
- Quality is generally good but varies by partner

For production applications, prefer Mendix-supported modules when they exist. If a community module is your only option, spend extra time on evaluation.

### Version Compatibility

Mendix versioning matters. Here is how to think about it:

**Major versions** (e.g., Studio Pro 9 vs. 10) often introduce breaking changes. Modules built for 9.x may not work in 10.x without modification. Check the module's listed compatibility before importing.

**Minor versions** (e.g., 10.6 vs. 10.12) are usually backward-compatible, but not always. Some modules use APIs or features introduced in specific minor versions. The module listing should state the minimum required version.

**LTS (Long Term Support) versions** are your safest bet for module compatibility. Most module authors test against LTS releases. If you are on an LTS version, you are more likely to find compatible modules.

Check the module's release notes to see which Studio Pro versions each release was built for. If the module's latest release targets Studio Pro 10.6 and you are on 10.18, it will probably work, but test it.

### Evaluation Checklist

Before you commit to using a Marketplace module, run through this checklist:

```
[ ] Module is compatible with your Studio Pro version
[ ] Module has been updated within the last 12 months (or is stable/complete)
[ ] Module has meaningful download count and ratings
[ ] Documentation is adequate for your use case
[ ] You understand what the module does to your domain model
[ ] You understand what security roles and access rules the module adds
[ ] License is compatible with your project
[ ] You have checked the module's dependencies
[ ] If community module: you have reviewed the source code
[ ] If for a regulated environment: you have cleared it with your security team
[ ] You have a plan for what happens if the module is abandoned
```

---

## 3. Installing and Configuring

### Installation Through Studio Pro

The easiest way to install a Marketplace module is directly from Studio Pro. Here is the process:

1. Open your project in Studio Pro.
2. Go to the Marketplace section. You can access it through the top menu bar or the right-hand panel.
3. Search for the module you want.
4. Click on the module to see its details. Check the version, compatibility, and dependencies.
5. Click "Download" (or "Import" depending on your Studio Pro version).
6. Studio Pro will download the `.mpk` file and begin the import process.
7. You will see a dialog showing what will be imported. Review it.
8. Confirm the import.

The module will appear in your Project Explorer under the modules section.

**Before you import anything**, make sure you have committed (or at least backed up) your current project state. If the import goes sideways, you want to be able to get back to where you were.

### Manual Import

Sometimes you need to import a module manually. Maybe you downloaded the `.mpk` file from the website, or someone sent it to you, or you are importing from a private repository.

1. Download the `.mpk` file to your local machine.
2. In Studio Pro, go to **App** > **Import Module Package** (or **File** > **Import Module Package** in older versions).
3. Browse to the `.mpk` file and select it.
4. Studio Pro will analyze the package and show you what it contains.
5. You will be asked whether to **Add as a new module** or **Replace an existing module**. Choose carefully:
   - **Add as a new module**: Use this for first-time installations.
   - **Replace existing module**: Use this when updating an existing module. This replaces the entire module with the new version.
6. Review and confirm.

If you are replacing an existing module, Studio Pro will warn you about what will be overwritten. Pay attention to this dialog. If you have made any changes to the module (more on this in section 6), those changes will be lost.

### Resolving Import Conflicts

Import conflicts happen when the module you are importing contains elements that clash with what is already in your project. Here are the common conflict types and how to handle them:

**Entity name conflicts**

If the module defines an entity with the same name as one already in your project (in a different module), you will get a conflict. This is rare if you follow good naming conventions, but it happens.

Resolution: Rename your entity before importing, or import the module and then rename the conflicting entity. Mendix's refactoring tools will update references.

**Microflow name conflicts**

Same idea as entity conflicts. Two microflows with the same name in different modules will not conflict (they are namespaced to their module), but if you are replacing a module and your microflows reference the old module's microflows, those references will break.

Resolution: After import, use the Errors pane to find and fix broken references.

**Java action conflicts**

If two modules ship Java actions with the same fully qualified class name, you have a problem. This usually happens when two modules bundle the same dependency (like a specific version of Apache Commons).

Resolution: Check the `userlib` folder for duplicate JARs. Remove the older version. If both modules need different versions of the same library, you have a real compatibility problem and may need to choose one module over the other.

**Widget conflicts**

If you import a module that includes widgets that are already in your project (possibly from another module), Studio Pro will ask how to handle it. Generally, keep the newer version unless you have a specific reason not to.

Resolution: Let Studio Pro handle it during import. If you get client-side errors after import, check that you do not have multiple versions of the same widget in your `widgets` folder.

**Constant conflicts**

Modules often define constants for configuration. If a constant name conflicts with an existing one, the import will flag it.

Resolution: Usually you want the module's constant to win. Merge your custom values into the module's constant after import.

### Post-Install Configuration

Most modules need some configuration after installation. Here is a general checklist:

**1. Set Constants**

Almost every non-trivial module has constants that need to be set. These are things like API keys, URLs, feature flags, and encryption keys. Find them in the module's folder in the Project Explorer, usually under a "Configuration" or "Constants" subfolder.

For each constant:
- Read the description (hover over it or check the module documentation).
- Set the value appropriately for your environment.
- Remember that constants can have different values per environment (development, acceptance, production). Configure this in your deployment settings.

**2. Configure Security**

Marketplace modules add their own module roles. You need to map these module roles to your application's user roles.

Go to **App** > **Security** (or **Project** > **Security** in older versions), then look at the **Module roles** tab for the imported module. You will see roles like `Administrator`, `User`, `Anonymous`, etc. Map them to your project's user roles.

Get this wrong and you will either lock users out of functionality they need, or give them access to things they should not see. Take the time to understand what each module role grants access to.

**3. Add Navigation Items**

If the module includes pages (admin screens, configuration pages, etc.), you may want to add them to your app's navigation. Some modules come with snippets or layouts that expect to be placed in specific locations.

**4. Configure Scheduled Events**

Some modules include scheduled events (background jobs). These are disabled by default after import. Review each scheduled event and decide whether to enable it. Check the interval and make sure it makes sense for your use case.

Common examples: the Email module has a scheduled event for sending queued emails, some modules have cleanup jobs that purge old data.

**5. Set Up After-Startup Microflows**

Some modules require an after-startup microflow to run when the application starts. Check the module's documentation for this. If the module includes a microflow called something like `ASU_ModuleName` or `AfterStartup`, you need to call it from your main after-startup microflow.

**6. Review the userlib Folder**

After importing a module with Java actions, check the `userlib` folder in your project directory. This is where Java dependencies (JAR files) live. Make sure there are no duplicate or conflicting JARs. Studio Pro sometimes warns about this, sometimes it does not.

**7. Run the App and Check for Errors**

After all configuration, run the app locally and check:
- The console for errors or warnings.
- The module's functionality. Does it actually work?
- The Errors pane in Studio Pro. Fix any remaining issues.

### Module Dependencies

Many modules depend on other modules. For example, the Email module depends on Community Commons and the Encryption module. If you import a module without its dependencies, things will break.

The module's Marketplace listing should list its dependencies. Some modules bundle their dependencies in the `.mpk` file, but many do not. You need to import the dependencies separately.

Here is a common dependency tree for frequently used modules:

```
Email Module
  |-- Community Commons
  |-- Encryption
  |-- MxModel Reflection (for template rendering)

SAML Module
  |-- Community Commons
  |-- Encryption

Excel Import/Export
  |-- Community Commons
  |-- MxModel Reflection

Deep Link Module
  |-- Community Commons
```

Import dependencies before the module that needs them. If you import them in the wrong order, Studio Pro will show errors, but they should resolve once all dependencies are in place.

---

## 4. Commonly Used Modules

This section covers the modules you will encounter in most Mendix projects. These are the workhorses.

### Community Commons

**What it is**: A utility library maintained by Mendix. It provides a large collection of Java actions and microflows for common operations that are not built into the platform natively.

**Why you need it**: Half the other modules on this list depend on it. Even if you do not use it directly, you will end up importing it because something else requires it.

**Key functionality**:

- **String operations**: `StringUtils.isBlank()`, `StringUtils.trim()`, regex matching, string splitting, substring operations, HTML escaping, URL encoding/decoding.
- **Date/time operations**: `DateUtils.addDays()`, `DateUtils.daysBetween()`, date formatting, timezone conversions.
- **File operations**: `FileUtils.getFileSize()`, Base64 encoding/decoding, file copying, MIME type detection.
- **Logging**: `LogMessage()` microflow action with severity levels.
- **Object operations**: Deep clone, object comparison, type checking.
- **HTTP operations**: HTTP GET/POST with headers, useful for simple integrations.
- **Math operations**: Rounding, random number generation, hashing (MD5, SHA-256).
- **Miscellaneous**: GUID generation, environment info, system text retrieval.

**Configuration**: Minimal. Import it and start using the actions. Some Java actions may need constants set, but most work out of the box.

**Common gotcha**: Community Commons is large. You probably will not use 80% of what is in it. That is fine. Do not try to trim it down since that breaks updates.

**Example usage**: When you need to generate a UUID in a microflow, call the `CommunityCommons.GenerateUUID` Java action. When you need to check if a string is empty or null, use `CommunityCommons.StringUtils.isBlank()` instead of building your own conditional logic.

```
// In a microflow, use the Java action:
$UUID = CommunityCommons.GenerateUUID()

// In an expression:
if CommunityCommons.StringUtils.isNotBlank($Account/Email) then ...
```

### Nanoflow Commons

**What it is**: The client-side equivalent of Community Commons. Provides JavaScript actions for use in nanoflows (which run in the browser or on the mobile device, not on the server).

**Why you need it**: Nanoflows cannot call Java actions. If you need utility functions in nanoflows, this is where you get them.

**Key functionality**:

- **Clipboard**: Copy text to clipboard.
- **Local storage**: Read and write to browser local storage (useful for caching preferences).
- **Navigation**: Open URLs, get current page URL, navigate with parameters.
- **Notifications**: Show local notifications on mobile devices.
- **Network**: Check if the device is online or offline.
- **Platform detection**: Determine if running on web, iOS, or Android.
- **Camera and media**: Access device camera and media library.
- **Date/time**: Client-side date formatting and manipulation.
- **Animation**: Basic animation utilities.

**Configuration**: Import and use. No constants to set.

**Common gotcha**: Some actions only work on native mobile, not on web. Check the documentation for each action to see which platforms it supports. If you call a native-only action in a web app, it will fail silently or throw an error.

### Atlas UI Resources

**What it is**: The design system and UI framework for Mendix applications. Atlas provides layouts, page templates, building blocks, and a design language.

**Why you need it**: Every Mendix app uses Atlas in some form. New projects start with Atlas already included. You generally do not "install" Atlas; it is there from the start.

**Key components**:

- **Layouts**: Responsive layouts for different page types (full-width, sidebar, pop-up, etc.).
- **Page templates**: Pre-built page designs for common patterns (list pages, detail pages, dashboards).
- **Building blocks**: Reusable UI compositions (cards, headers, lists, forms).
- **Design properties**: Styling options you can apply through the Studio Pro properties panel.
- **Design tokens**: CSS variables that control colors, spacing, typography.

**Customization**: You can customize Atlas by modifying the theme files in your project's `theme` folder. The `main.scss` (or `main.css` depending on your Atlas version) file is where you override default styles. Do not modify Atlas module files directly since they will be overwritten on update.

**Version note**: Atlas has gone through several major versions (Atlas 2, Atlas 3, Atlas Core). Make sure the module documentation and any tutorials you follow match the version of Atlas in your project.

### SAML (SSO)

**What it is**: The SAML module enables Single Sign-On using the SAML 2.0 protocol. It turns your Mendix app into a SAML Service Provider that can authenticate users against an Identity Provider like Azure AD, Okta, ADFS, or Ping.

**Why you need it**: If your organization uses SSO (and most enterprise organizations do), you need this module.

**Dependencies**: Community Commons, Encryption.

**Key configuration steps**:

1. **Import the module** and its dependencies.
2. **Configure the Encryption key** constant. This must be a 16-character string and must be the same across all environments of your app.
3. **Set up the after-startup microflow**. The SAML module needs its startup microflow called from your main startup microflow.
4. **Configure your IdP** in the SAML admin page. You need the IdP metadata URL or XML. The SAML module's admin page (usually at `/SSO/`) lets you configure this.
5. **Map SAML attributes** to your user entity. At minimum, map the NameID to your username attribute.
6. **Configure the ACS (Assertion Consumer Service) URL**. This is the URL the IdP will POST the SAML response to. It is typically `https://yourdomain.com/SSO/`.
7. **Test it**. Use the SAML module's test page to verify the configuration.

**Common gotchas**:

- The EntityID must match exactly between what your app sends and what the IdP expects. Even a trailing slash difference will cause authentication failures.
- Clock skew between your server and the IdP will cause "response not valid" errors. The SAML module has a clock skew tolerance constant; set it to 120 seconds or more if you see timing-related errors.
- If you are behind a load balancer or reverse proxy, the ACS URL that the IdP sees might be different from the URL your app thinks it is on. Configure the `SP EntityID` and `ACS Location` constants to match the external URL, not the internal one.
- Certificate management is critical. When the IdP rotates certificates, you need to update the SAML module's configuration.

**Security note**: The SAML module handles authentication, which is the most security-sensitive part of your application. Always use the Mendix-supported version, keep it updated, and follow Mendix's security guidelines for configuration.

### Email Module (with Templates)

**What it is**: Provides email sending and receiving capabilities with support for email templates, attachments, and SMTP configuration.

**Why you need it**: Almost every business application sends email at some point. Notifications, reports, confirmations, password resets, etc.

**Dependencies**: Community Commons, Encryption, MxModel Reflection (for template token replacement).

**Key functionality**:

- **Send email**: Plain text and HTML emails with attachments.
- **Email templates**: Define reusable templates with placeholder tokens that get replaced at send time.
- **SMTP configuration**: Connect to any SMTP server (Gmail, Office 365, SendGrid, Amazon SES, etc.).
- **Email queue**: Emails are queued and sent by a scheduled event, not sent synchronously from your microflow. This is better for performance and reliability.
- **Logging**: All sent emails are logged with status and error messages.

**Configuration**:

1. Set the SMTP constants: host, port, username, password, from address, encryption type (TLS, SSL, or none).
2. Enable the `SE_SendQueuedEmails` scheduled event. Set an appropriate interval (every 30 seconds is a common starting point).
3. Synchronize the MxModel Reflection module so it knows about your entities. This is needed for template token replacement.
4. Create email templates through the admin pages included in the module.

**Common gotchas**:

- If emails are not being sent, check: (a) the scheduled event is enabled, (b) the SMTP credentials are correct, (c) the SMTP server allows connections from your app's IP address, (d) the port is not blocked by a firewall.
- Email templates use token syntax like `[%TokenName%]`. Tokens must be mapped to entity attributes through MxModel Reflection. If tokens are not being replaced, re-sync MxModel Reflection.
- For Office 365, you may need to use OAuth2 instead of basic SMTP authentication. Microsoft has been deprecating basic auth. Check whether the Email module version you are using supports OAuth2 or if you need a separate connector.
- Sending large volumes of email through a shared SMTP server will get you rate-limited or blocked. Use a dedicated email service (SendGrid, SES) for production workloads.

### Encryption

**What it is**: Provides AES encryption and decryption functionality so you can store sensitive data encrypted in the database.

**Why you need it**: If you store anything sensitive (API keys, personal data, tokens, passwords), you should encrypt it at rest. The Encryption module is also a dependency for SAML and other modules.

**Dependencies**: Community Commons.

**Configuration**:

1. Set the `EncryptionKey` constant to a 16-character string. This is your AES-128 encryption key.
2. **This key must be the same across all environments** if encrypted data needs to be portable (e.g., if you migrate data from acceptance to production).
3. **Keep this key secret and safe**. If you lose it, you cannot decrypt your data. Store it in your environment configuration, not in source control.
4. Call the `Encryption.DecryptString` and `Encryption.EncryptString` Java actions in your microflows.

**Common gotchas**:

- The encryption key must be exactly 16 characters for AES-128, or 32 characters for AES-256 (depending on the module version). An incorrect length will throw runtime errors.
- Do not change the encryption key after you have encrypted data with it. You will not be able to decrypt the old data.
- The Encryption module encrypts strings. If you need to encrypt files or binary data, you will need additional logic to convert them to Base64 strings first.

**Security note**: AES-128 is considered secure for most purposes. If your compliance requirements mandate AES-256, check which version of the Encryption module you need and make sure your key length matches.

### Deep Link

**What it is**: Enables custom URL routing in your Mendix application. It lets you define friendly URLs that map to specific pages or microflows with parameters.

**Why you need it**: Any time you want URLs like `yourdomain.com/invoice/12345` instead of `yourdomain.com/p/invoice-detail?InvoiceID=12345`. Also essential for email links that take users directly to a specific page or object.

**Dependencies**: Community Commons.

**Configuration**:

1. Import the module.
2. Add the Deep Link startup microflow to your after-startup microflow.
3. Configure deep links in the admin page. Each deep link has:
   - A name (this becomes part of the URL path).
   - A target microflow (this is called when the URL is hit).
   - Parameters (these are passed to the microflow from the URL).
4. Optionally configure a login behavior: what happens if an unauthenticated user hits a deep link.

**Example**:

You configure a deep link named `invoice` that calls `DeepLink_Invoice(InvoiceNumber : String)`. When a user visits `yourdomain.com/link/invoice/INV-2024-001`, the Deep Link module calls your microflow with `InvoiceNumber = "INV-2024-001"`.

**Common gotchas**:

- Deep links run their target microflow as the currently logged-in user (or the anonymous user if not authenticated). Make sure your target microflow handles the case where the user is not logged in, typically by redirecting to the login page and then back to the original URL.
- If you are using the SAML module for SSO, deep links and SAML can have routing conflicts. The Deep Link module's `IndexPage` constant and the SAML module's landing page URL need to be coordinated. Check both modules' documentation for how to make them work together.
- URL encoding matters. If your deep link parameters contain special characters (spaces, slashes, ampersands), they need to be URL-encoded. The Deep Link module handles some of this, but test with edge cases.

### REST and SOAP Helpers

**What it is**: Mendix has built-in support for consuming and publishing REST and SOAP services. The Marketplace offers additional modules that provide helpers, utilities, and connectors.

**Built-in REST (no module needed)**:

Mendix Studio Pro 8+ has robust built-in REST support:
- **Published REST services**: Define REST endpoints directly in Studio Pro. Map them to microflows for handling.
- **Consumed REST services**: Call external REST APIs from microflows using the Call REST action. Handle JSON/XML import/export mappings.

You often do not need a Marketplace module for basic REST integration. The built-in tooling covers most use cases.

**When you might want a Marketplace module**:

- **REST module (by Mendix)**: Provides additional utilities for REST operations, including OAuth token management, retry logic, and request/response logging.
- **JSON Structure**: Helps you create import/export mappings from JSON examples.
- **OData Connector**: If you are integrating with OData APIs (common with SAP, Microsoft Dynamics).
- **GraphQL Connector**: If you need to consume GraphQL APIs.
- **SOAP utilities**: For complex WS-Security scenarios, custom SOAP headers, or MTOM attachment handling.

**Common gotchas**:

- For REST calls, Mendix's built-in Call REST action works well for simple cases. You only need a module when you have complex authentication flows (OAuth2 with refresh tokens), need retry logic, or want standardized error handling across many integrations.
- SOAP support in Mendix uses a WSDL file to generate proxy entities and microflows. If the WSDL changes, you need to re-import it, which can break things. Marketplace modules for SOAP mostly help with non-standard SOAP configurations.

### Excel Import and Export

**What it is**: Enables importing data from Excel spreadsheets into your Mendix app and exporting data from your app to Excel files.

**Why you need it**: Business users live in Excel. They want to bulk upload data from spreadsheets and download reports as Excel files. This module handles both directions.

**Dependencies**: Community Commons, MxModel Reflection.

**Key functionality**:

- **Import**: Upload an Excel file (`.xlsx` or `.xls`), map columns to entity attributes, validate data, and create/update objects.
- **Export**: Define export templates that map entity data to Excel columns, including formatting, headers, and multiple sheets.
- **Templates**: Both import and export configurations can be saved as reusable templates.
- **MxModel Reflection integration**: The module uses MxModel Reflection to discover your entities and attributes at runtime, which is how the column mapping works.

**Configuration**:

1. Import the module and its dependencies.
2. Sync MxModel Reflection to make your entities discoverable.
3. Create import/export templates through the module's admin pages.
4. Add the import/export pages or snippets to your application navigation.

**Common gotchas**:

- Large Excel files (10,000+ rows) can cause memory issues, especially if each row creates multiple objects with associations. Consider batch processing or increasing your app's memory allocation.
- Date formatting is a common source of import errors. Excel stores dates as serial numbers internally, and the interpretation depends on the locale. Test with real data from your users, not just your own test files.
- The import process runs in a single transaction by default. If it fails halfway through, everything rolls back. For large imports, consider implementing batch processing with commit points.
- After updating MxModel Reflection, re-sync it before using Excel Import/Export. Otherwise, new entities and attributes will not appear in the mapping interface.

### PDF Document Generation

**What it is**: Multiple approaches exist for generating PDF documents in Mendix. The Marketplace has several modules for this, including template-based generators and code-based options.

**Common approaches**:

**1. Document Templates (Built-in)**

Mendix has a built-in document template feature. You design a template visually in Studio Pro (similar to designing a page), and a microflow action generates a PDF from it. No Marketplace module needed for basic PDF generation.

The built-in approach handles:
- Headers and footers
- Data tables
- Dynamic data from your domain model
- Images
- Page numbers
- Basic formatting

Limitation: the visual template designer is not the most flexible tool. Complex layouts, precise positioning, and advanced formatting can be difficult or impossible.

**2. HTML-to-PDF Modules**

Several Marketplace modules convert HTML to PDF. You build an HTML template (with CSS), merge in your data, and the module converts it to a PDF. This gives you much more control over the output.

Examples:
- **wkhtmltopdf**: Uses the wkhtmltopdf engine. Good output quality but requires the wkhtmltopdf binary on the server.
- **Puppeteer/Chromium-based**: Uses a headless Chrome instance. Best output quality and CSS support, but heavier on resources.

**3. iText/OpenPDF-based Modules**

Modules that use the iText or OpenPDF Java library to generate PDFs programmatically. You define the document structure in Java code or through configuration.

**Which to use**:

| Approach | Pros | Cons |
|---|---|---|
| Built-in templates | No dependencies, visual designer, easy to start | Limited formatting, hard to achieve pixel-perfect output |
| HTML-to-PDF | Full CSS support, flexible layouts, familiar technology | Requires external binary or service, more setup |
| iText/OpenPDF | Programmatic control, no external dependencies | Steeper learning curve, more Java code |

**Configuration depends on the module**, but generally:
1. Import the module.
2. Set up any required external services (for HTML-to-PDF approaches).
3. Create your templates.
4. Call the generation microflow/Java action from your code, passing in data and the template.

**Common gotchas**:

- Server-side font availability. If your PDF uses a specific font and that font is not installed on the server, the PDF will fall back to a default font. Package the fonts with your application.
- Image paths in PDF templates need to be absolute URLs that the server can resolve. Relative paths and client-side-only URLs will not work.
- Memory usage. Generating large PDFs (100+ pages, many images) consumes significant memory. Monitor your app's memory usage and consider generating large PDFs asynchronously.

### Other Notable Modules

Here are additional modules worth knowing about:

**MxModel Reflection**: Used by many other modules (Email, Excel Import/Export) to introspect your domain model at runtime. You almost never use it directly; it is a dependency of other modules. Remember to sync it after domain model changes.

**Object Handling**: Provides advanced object manipulation: deep clone, object comparison, batch commit, advanced retrieval. Useful for complex data operations.

**Audittrail**: Automatically logs changes to entities. Useful for compliance and debugging. Configure which entities to audit and how long to retain audit data.

**Push Notifications**: Enables push notifications to native mobile apps. Requires Firebase (Android) and APNs (iOS) configuration.

**Database Connector**: Allows direct SQL queries to external databases. Useful when you need to integrate with legacy databases that do not have APIs. Use with caution since direct SQL bypasses Mendix's ORM and security layer.

**OData Connector for SAP**: Essential if you are integrating with SAP. Handles SAP-specific OData quirks and authentication.

**Unit Testing**: Provides a framework for writing and running unit tests within Mendix. Not as mature as JUnit or Jest, but better than no tests.

**Web Actions**: JavaScript actions for web applications. Things like downloading files, printing pages, and other browser-specific actions.

---

## 5. Security Considerations

### Why This Matters

Every module you import is code running in your application. It has access to your database, your user sessions, your API keys, and your users' data. A poorly written or malicious module can:

- Exfiltrate data through external HTTP calls.
- Create backdoor admin accounts.
- Modify security rules to grant unintended access.
- Log sensitive data to places it should not be logged.
- Introduce SQL injection or XSS vulnerabilities.

This is not hypothetical. Community modules are not audited by Mendix. They are uploaded by anyone with a Marketplace account. Treat third-party modules with the same caution you would treat any third-party code dependency.

### Reviewing Third-Party Code

When you import a module, review the following:

**Java Actions**

Java actions are compiled into `.jar` files in the `userlib` folder, and the source is (usually) in the `javasource` folder. Read the Java source code. Look for:

- Network calls (`HttpURLConnection`, `HttpClient`, `URL`, `Socket`). Does the module make external HTTP calls? To where? Why?
- File system access (`File`, `FileInputStream`, `FileOutputStream`). Does it read or write files outside the expected scope?
- Reflection and dynamic code execution (`Class.forName`, `Method.invoke`). These can be used for legitimate purposes, but they can also be used to bypass security.
- Hardcoded credentials, API keys, or URLs. These are red flags.
- Database access outside of Mendix's ORM (`DriverManager`, `Connection`, `Statement`). This bypasses Mendix's security model.

**Microflows and Nanoflows**

Open each microflow in the module and review it. Look for:

- Calls to external web services or REST endpoints. Why is the module calling out? Is it a telemetry/analytics call? Is it actually needed for functionality?
- Changes to system entities (`System.User`, `System.Session`). The module should not be modifying system entities unless it is specifically an authentication module.
- Excessive logging of potentially sensitive data.
- Broad retrieval queries (retrieve all objects without constraints). This could indicate a performance issue or data leakage risk.

**Widgets (JavaScript/TypeScript)**

Widget source is in the `widgets` folder or in the module's `src` folder. For `.mpk` widget packages, you may need to extract them. Look for:

- External script loading (`createElement('script')`, dynamic imports from external URLs).
- Data exfiltration (`fetch`, `XMLHttpRequest`, `navigator.sendBeacon` to non-application URLs).
- Cookie manipulation.
- DOM manipulation that bypasses Mendix's client framework.

### Access Rules and Entity Access

This is the most practically important security review you can do. When a module is imported, it may add:

**Entity Access Rules**

The module's entities will have access rules defined. Check:

- Which module roles can create, read, update, and delete each entity?
- Are there overly permissive access rules (e.g., all users can read all data)?
- Does the module grant access to its entities through XPath constraints, or is it wide open?

**Module Roles**

Every module defines its own roles. When you map these to your app's user roles, you are granting access. Understand what each role can do before mapping it.

Common pattern:
- `Administrator` role: full access to all module functionality, including configuration.
- `User` role: access to use the module's features but not to configure them.
- `Anonymous` role: limited access for unauthenticated users.

Map these conservatively. If you are not sure whether a user role needs a module role, do not assign it. You can always add it later.

**Microflow Access**

Modules may expose microflows that can be called from pages or as REST endpoints. Check which microflows are accessible to which roles. An unprotected microflow that modifies data could be called by anyone who can craft the right HTTP request.

**Page Access**

Similarly, check which pages in the module are accessible to which roles. An admin configuration page that is accessible to regular users is a security issue.

### Security Review Checklist

Use this checklist for every Marketplace module you import into a production application:

```
## Pre-Import
[ ] Read the module's Marketplace listing completely
[ ] Check the module author's reputation and other contributions
[ ] Verify the module's license is compatible with your project
[ ] Check for known security advisories or issues in reviews/comments

## Code Review
[ ] Review Java action source code for external network calls
[ ] Review Java action source code for file system access
[ ] Review Java actions for hardcoded secrets or credentials
[ ] Review microflows for calls to external services
[ ] Review microflows for data access patterns (over-retrieval, missing constraints)
[ ] If widget: review JavaScript/TypeScript for external communications
[ ] Check for dependencies and review those separately

## Security Configuration
[ ] Map module roles to application user roles (conservative approach)
[ ] Review entity access rules on all module entities
[ ] Review XPath constraints on entity access
[ ] Check which microflows are exposed and to which roles
[ ] Review page access configuration
[ ] Check for any REST/web service endpoints the module publishes
[ ] Verify scheduled events do not expose or log sensitive data

## Post-Import
[ ] Test with different user roles to verify access is correct
[ ] Monitor network traffic during testing (check for unexpected external calls)
[ ] Verify that the module does not create or modify user accounts unexpectedly
[ ] Document the module version, review date, and reviewer
```

### Compliance Environments

If you are building applications in regulated environments (ITAR, FedRAMP, SOC2, HIPAA, GDPR), you need to be especially careful with Marketplace modules:

**Data residency**: Does the module send data to external servers? If so, where are those servers located? This matters for GDPR, ITAR, and data sovereignty requirements.

**Data handling**: Does the module store sensitive data? If so, is it encrypted? Does it follow your data classification policies?

**Audit trail**: Does the module log what it does? For compliance environments, you may need to demonstrate auditability of all data processing.

**Approved software lists**: Some compliance frameworks require all software components to be on an approved list. A community Marketplace module may not be on that list. Check with your compliance team before importing.

**Code review requirements**: Some compliance frameworks require formal code reviews of all third-party components. The security review checklist above is a starting point, but your compliance requirements may mandate additional reviews.

For ITAR and FedRAMP environments specifically: be extremely cautious about modules that make external network calls. Any data leaving your application boundary could be a compliance violation. Even telemetry or analytics calls can be problematic.

---

## 6. Customizing Marketplace Modules

### The Golden Rule

**Never modify Marketplace module files directly if you can avoid it.**

When you update a Marketplace module, the entire module is replaced. Any changes you made inside the module will be lost. This is the single most common mistake developers make with Marketplace modules.

Instead, extend the module from outside. Call its microflows from your own microflows. Build your pages that use its data. Create your own entities that specialize or wrap the module's entities. Keep your code in your own modules.

### Safe Customization Patterns

**Pattern 1: Wrapper Microflows**

Instead of modifying a module's microflow, create your own microflow that calls the module's microflow and adds your custom logic before or after.

Example: The Email module sends an email using its `IVK_SendEmail` microflow. You want to add custom logging. Do not modify `IVK_SendEmail`. Instead, create `MyModule.SendEmailWithLogging` that:
1. Runs your custom logging logic.
2. Calls `Email.IVK_SendEmail`.
3. Runs any post-send logic you need.

Then use `MyModule.SendEmailWithLogging` everywhere in your app.

**Pattern 2: Entity Specialization**

If you need to add attributes to a module's entity, use entity specialization (inheritance). Create a new entity in your own module that specializes (extends) the module's entity. Add your attributes to the specialization.

Example: The module has a `EmailMessage` entity. You need a `Priority` attribute. Create `MyModule.ExtendedEmailMessage` that specializes `Email.EmailMessage` and add the `Priority` attribute to your specialized entity.

Note: This does not always work cleanly. Specialization has limitations in Mendix (you cannot always use specialized entities in the module's own microflows). Test it. If specialization does not work, the next pattern might.

**Pattern 3: Associated Entities**

If entity specialization is not practical, create a separate entity in your own module that has an association to the module's entity. Store your custom attributes on your entity.

Example: Create `MyModule.EmailMetadata` with an association to `Email.EmailMessage`. Add your `Priority`, `Category`, and `CustomTrackingId` attributes to `EmailMetadata`. Retrieve them together when you need them.

This is more work than specialization, but it always works and survives module updates.

**Pattern 4: Event Handlers**

If you need to run custom logic when a module's entity is created, changed, or deleted, use event handlers. You can add before-commit and after-commit microflows to any entity, including entities from imported modules.

Wait, no. That is a modification inside the module. Instead, if the module provides hooks or callback microflows, use those. Many well-designed modules include extension points.

If the module does not provide hooks, you need to handle this at a higher level. For example, instead of hooking into the module's entity commit, add your logic to the microflows in your own module that interact with the module's functionality.

**Pattern 5: CSS and Theme Overrides**

For UI modules (Atlas UI, widgets), customize appearance through your project's theme files. Override CSS classes and design tokens in your `main.scss` or `main.css`. The theme folder is yours; it does not get replaced when you update a module.

Example: Instead of modifying Atlas UI's built-in card styling, add an override in your theme:

```css
/* theme/web/custom-styles.scss */
.card-custom-header {
    background-color: var(--brand-primary);
    color: white;
    padding: 12px 16px;
}
```

**Pattern 6: Constants and Configuration**

If the module uses constants for configuration, set those constants to the values you need. This is the intended customization mechanism for most modules. Constants are project-level settings; they are not part of the module itself.

### When to Fork vs. Extend

**Extend** (use the patterns above) when:
- You need to add functionality around the module.
- Your changes are in addition to what the module does.
- You want to keep receiving updates from the Marketplace.
- Your changes are relatively small.

**Fork** (copy the module and make it your own) when:
- You need to change the module's core behavior.
- The module is abandoned and will never be updated.
- You need to fix a bug in the module and cannot wait for the maintainer.
- Your changes are so extensive that the module is effectively a different product.
- You have accepted that you will never update this module from the Marketplace again.

**How to fork**:

1. Import the module normally.
2. Rename it to something like `MyEmail` (instead of `Email`). This prevents Studio Pro from treating it as the same module during future imports.
3. Make your changes.
4. Document that this is a fork, what the original module was, what version you forked from, and what changes you made.
5. Accept that you are now the maintainer. Security patches, compatibility updates, bug fixes: all on you.

Forking is a last resort. Every fork is a maintenance burden that grows over time.

### Protecting Your Changes From Updates

If you must make changes inside a module (and sometimes you do, despite the golden rule), protect yourself:

**1. Document every change**

Keep a document (in your project or in your wiki) that lists every modification you made to every Marketplace module. Include:
- Which module and version.
- Which file/microflow/entity you changed.
- What you changed and why.
- The date of the change.

When you update the module, re-apply your changes from this document.

**2. Use version control**

Always commit your project to version control before and after modifying a Marketplace module. When you update the module later, you can diff the changes and see what was lost.

**3. Use Studio Pro's "Mark as Used" feature**

In Studio Pro, you can mark modules as "not updateable" to prevent accidental updates. This does not protect your changes, but it prevents you from accidentally overwriting them.

**4. Create automated tests**

Write test microflows that verify your customizations work correctly. After updating a module and re-applying your changes, run these tests to catch regressions.

### Documentation of Customizations

Seriously, document your customizations. Six months from now, you will not remember why you changed that microflow. A new developer joining the project definitely will not know.

At minimum, keep a `MARKETPLACE_CUSTOMIZATIONS.md` file (or equivalent) in your project that tracks:

```markdown
## Module: Email Module v4.0.2
### Changes:
1. Modified IVK_SendEmail to add BCC support
   - File: EmailModule/IVK_SendEmail microflow
   - Reason: Business requirement for audit team BCC on all outgoing emails
   - Date: 2024-03-15
   - Risk on update: HIGH - this change will be lost on module update

## Module: Community Commons v9.0.1
### Changes: None (using as-is)
```

---

## 7. Updating Marketplace Modules

### Version Management Strategy

Marketplace modules should be treated like any other software dependency. You need a strategy for when and how to update them.

**Do not update in production emergencies.** Module updates should be planned, tested, and deployed through your normal release process. The exception is a critical security patch, and even then, test it in a non-production environment first.

**Do not update everything at once.** If you have 10 Marketplace modules and all of them have updates available, do not update them all in a single commit. Update one at a time, test, commit, then move on to the next. This way, if something breaks, you know which update caused it.

**Do update regularly.** Letting modules get multiple major versions behind makes the eventual update much harder. Quarterly review of your Marketplace modules is a good cadence. Check for updates, review changelogs, and plan updates for the next sprint.

**LTS alignment.** Try to update your Marketplace modules when you update your Studio Pro version, especially when moving to a new LTS. Module authors often release compatible versions when a new LTS comes out.

### Update Process

Here is a step-by-step process for updating a Marketplace module:

**1. Check the changelog**

Before downloading anything, read the changelog on the Marketplace listing. What changed? Are there breaking changes? New dependencies? Removed features? Do this before you spend time on the actual update.

**2. Check compatibility**

Verify that the new module version is compatible with your Studio Pro version and with the versions of other modules you have installed (especially dependencies).

**3. Back up your project**

Commit your current state to version control. Create a branch if your workflow supports it. You want a clean rollback point.

**4. Document your current customizations**

If you have made any changes to the module (you should not have, but often people do), document them now. You will need to re-apply them after the update.

**5. Import the new version**

In Studio Pro, import the new module version. Choose "Replace existing module" when prompted. Studio Pro will overwrite the entire module.

**6. Resolve errors**

After the import, check the Errors pane. Common issues:
- Missing dependencies (the new version may require a new module you do not have).
- Changed microflow signatures (parameters added, removed, or renamed).
- Removed entities or attributes.
- Changed module roles.

Fix these errors. This may require updating your own code that references the module.

**7. Re-apply customizations**

If you had customized the module, re-apply your changes from your documentation. (This is why documentation matters.)

**8. Update module role mappings**

Check if the module has added or changed its module roles. Update the role mappings in your project security settings.

**9. Update constants**

Check if the module has added new constants or changed default values. Set them appropriately.

**10. Test**

Test the module's functionality thoroughly. See the next section for what to test.

### Testing After Updates

After updating a module, test the following at minimum:

**Functional testing**:
- All features of the module that you actively use. Does it still work the way you expect?
- Any microflows in your code that call the module's microflows. Are the interfaces still the same?
- Any pages that display the module's entities. Are the attributes still there and populated correctly?

**Regression testing**:
- Features that worked before the update should still work. If you have automated tests (unit tests, Selenium tests), run them all.
- If the module changed its domain model, check that existing data is handled correctly. Entity attribute renames or type changes can corrupt data.

**Security testing**:
- Verify module role mappings are still correct.
- Test with different user roles to confirm access is appropriate.
- If the module publishes REST endpoints or web services, verify they are still secured.

**Performance testing**:
- If the module changed its data access patterns (new queries, changed retrieval logic), monitor performance.
- Check for new scheduled events that might impact system resources.

**Integration testing**:
- If the module integrates with external services, verify those integrations still work. API endpoints, authentication methods, or data formats may have changed.

### Rollback Strategy

If an update breaks things and you cannot fix it quickly:

**Option 1: Version control rollback**

If you committed before the update (you should have), revert to the previous commit. This is the cleanest rollback.

```
# In your Mendix project's version control
# Use Studio Pro's version control features or your Git client
# Revert to the commit before the module update
```

**Option 2: Re-import the old version**

If you still have the old `.mpk` file (or can download the old version from the Marketplace), import it to replace the new version. The Marketplace sometimes keeps older versions available.

**Option 3: Manual fix-forward**

Sometimes rolling back is not practical (maybe you have already made other changes you do not want to lose). In that case, fix the issues caused by the update. This is why updating one module at a time matters: the scope of issues is contained.

**Database rollback consideration**:

If the module update modified the database schema (added tables, changed columns, migrated data), rolling back the code does not roll back the database. You may need to:
- Restore a database backup (if you took one before the update, which you should for major updates).
- Manually revert schema changes (risky and not recommended unless you know exactly what changed).
- Fix forward (adjust your code to work with the new schema, even with the old module version).

This is why testing in a non-production environment first is critical. Catch schema issues before they affect production data.

### Reading Changelogs

Marketplace changelogs vary in quality. Here is how to read them effectively:

**Look for "Breaking Changes" sections.** These are the things that will break your app. Renamed microflows, changed parameters, removed entities, changed access rules. These need immediate attention.

**Look for "New Features" sections.** New features might introduce new constants to configure, new scheduled events, or new dependencies. Even if you do not use the new features, they might affect your app.

**Look for "Bug Fixes" sections.** If you have been working around a bug, the fix might mean you can remove your workaround. But test it; "fixed" does not always mean "fixed the way you need it."

**Look for "Dependencies" changes.** If the module now requires a newer version of Community Commons or a new module you do not have, you need to handle that before (or during) the update.

**If there is no changelog**, that is a yellow flag. It means the maintainer did not document what changed. You can try diffing the old and new module files in version control after import, but this is tedious. Consider whether you trust the module enough to update it blind.

---

## 8. Building and Publishing

### When to Publish

Not everything should be a Marketplace module. Publish when:

- You have solved a problem that many Mendix developers face.
- Your solution is generic enough to work in different projects without modification.
- You are willing to maintain it (respond to issues, release updates, fix bugs).
- Your employer is okay with it (check your employment agreement and intellectual property policies).

Do not publish when:
- The module is highly specific to your project.
- It contains proprietary business logic.
- You will not maintain it after publishing.
- It duplicates existing Marketplace functionality without adding value.

### Module Architecture for Publishing

A well-architected Marketplace module follows these principles:

**Self-contained**: The module should work independently. It can have dependencies on other Marketplace modules, but keep them minimal. Every dependency is a potential compatibility issue for consumers.

**Well-named**: Use a clear, descriptive module name. Prefix your entities, microflows, and constants with the module name to avoid collisions. For example, if your module is called `PDFMerge`, name your entities `PDFMerge.MergeJob`, `PDFMerge.MergeConfig`, etc.

**Minimal footprint**: Include only what is necessary. Do not bundle example pages, test data, or debug microflows in the published version. These add clutter and confusion for consumers.

**Clear interfaces**: Define a clear public API for your module. Which microflows should consumers call? Which entities should they interact with? Which constants should they set? Everything else should be treated as internal implementation.

**Configuration through constants**: Use constants for all configuration values. Do not hardcode URLs, credentials, or feature flags. Consumers need to be able to configure your module for their environment.

**Documentation in the module**: Include a documentation page or snippet within the module itself. Not everyone reads the Marketplace listing.

**Version awareness**: Include a constant with your module version number. This makes it easier for consumers to know which version they have installed and for you to provide support.

Here is a recommended folder structure for a publishable module:

```
MyModule/
  _Documentation/           # Internal documentation pages
  _Configuration/           # Admin/setup pages
  _UseMe/                   # Microflows consumers should call
      IVK_DoTheThing        # Public interface microflow
      IVK_ConfigureModule   # Public configuration microflow
  _Private/                 # Internal implementation
      SUB_HelperLogic       # Private microflows
      DS_GetConfig          # Private data sources
  Domain Model              # Entities
  Constants                 # Configuration constants
```

The underscore-prefix convention makes folders sort to the top and signals their purpose. The `_UseMe` folder pattern is well-established in the Mendix community for indicating public API microflows.

### Packaging Your Module

To create an `.mpk` file for publishing:

1. **Clean up your module**: Remove test data, debug microflows, personal notes, TODO comments, and anything that is not part of the module's functionality.

2. **Verify dependencies**: Make sure your module's dependencies are clearly documented. Do not bundle dependencies inside your module unless absolutely necessary (and there is no Marketplace version of them).

3. **Test in a clean project**: Import your module into a fresh Mendix project (one that has never had your module in it) to verify it works. This catches issues with missing dependencies, hardcoded paths, and assumptions about project structure.

4. **Export the module**: In Studio Pro, right-click on your module in the Project Explorer and select "Export Module Package". This creates an `.mpk` file.

5. **Choose what to include**: Studio Pro will ask which files to include (Java source, widgets, etc.). Include everything that consumers need to use and potentially debug your module.

6. **Naming**: Name the `.mpk` file with the module name and version: `MyModule_v1.0.0.mpk`.

### Documentation Requirements

Your Marketplace listing needs to include:

**Description**: What does the module do? Be specific and practical. "This module provides PDF merging capabilities" is better than "A comprehensive document management solution."

**Screenshots**: Show the module in action. If it has UI, show the UI. If it is a utility library, show the microflow actions in the toolbox.

**Setup instructions**: Step-by-step guide to get the module working. Include:
1. Prerequisites (Studio Pro version, dependencies).
2. Import steps.
3. Configuration (constants, module roles, after-startup microflows).
4. Verification (how to confirm it is working).

**Usage examples**: Show common use cases with examples. Include example microflows if possible.

**Known limitations**: Be honest about what the module does not do. This saves everyone time.

**Changelog**: Document changes for every version. What is new, what is fixed, what is breaking.

**Compatibility**: Which Studio Pro versions does it support? Which dependency versions are required?

**License**: State the license clearly. Apache 2.0 and MIT are the most common for open-source modules.

**Contact/Support**: How should consumers report issues or ask questions? GitHub issues? Mendix Forum? Email?

### The Publishing Process

Here is the actual process for publishing to the Mendix Marketplace:

1. **Create a Marketplace listing**: Go to [marketplace.mendix.com](https://marketplace.mendix.com/) and create a new listing. You need a Mendix account.

2. **Fill in the metadata**: Name, description, category, tags, screenshots, documentation.

3. **Upload the `.mpk` file**: Upload your module package.

4. **Set compatibility**: Indicate which Studio Pro versions your module supports.

5. **Set the license**: Choose the appropriate license.

6. **Submit for review**: Mendix reviews new Marketplace submissions before they go live. The review checks for:
   - Basic quality (does it import cleanly?).
   - Documentation completeness.
   - Naming conventions.
   - No malicious code (basic review, not a full security audit).

7. **Wait for approval**: The review process can take a few days to a couple of weeks.

8. **Publish**: Once approved, your module goes live on the Marketplace.

For updates to an existing listing, the process is similar but faster. You upload a new `.mpk` file and update the changelog and documentation.

**Community profile**: Your Marketplace contributions are tied to your Mendix community profile. Publishing quality modules builds your reputation in the community.

### Maintaining a Published Module

Publishing is not the end; it is the beginning of a maintenance commitment:

**Respond to issues**: When users report bugs or ask questions, respond promptly. Even if you cannot fix something immediately, acknowledge the report.

**Test against new Studio Pro releases**: When a new LTS comes out, test your module against it and update if needed. Users will be upgrading and they will expect your module to work.

**Maintain backward compatibility**: Avoid breaking changes unless absolutely necessary. If you must make breaking changes, document them clearly, bump the major version, and keep the old version available.

**Security patches**: If a vulnerability is discovered in your module or its dependencies, release a patch promptly.

**Deprecation**: If you can no longer maintain the module, clearly mark it as deprecated on the Marketplace listing. Suggest alternatives if they exist.

---

## 9. Troubleshooting

### Common Import Errors

**"Could not find required module 'X'"**

The module you are importing depends on another module (`X`) that is not in your project.

Fix: Import the dependency module first, then retry importing the original module. Check the module's Marketplace listing for its dependency list.

**"JAR file conflict in userlib"**

Two modules are shipping the same Java library (JAR file) but in different versions.

Fix:
1. Open your project's `userlib` folder in a file explorer.
2. Look for duplicate JAR files (same library, different versions). For example, `commons-lang3-3.8.jar` and `commons-lang3-3.12.jar`.
3. Keep the newer version and delete the older one. (Usually. If one module specifically requires the older version, you have a deeper compatibility problem.)
4. Restart Studio Pro or do a clean deployment.

**"Consistency error: Entity 'X.Y' no longer exists"**

You updated or replaced a module and it removed or renamed an entity that your project references.

Fix: Find all references to the missing entity (use Find Usages or the Errors pane) and update them to point to the new entity name or a replacement.

**"Widget 'X' could not be loaded"**

The module included a widget that cannot be loaded, usually because it is incompatible with your Studio Pro version or because it has a JavaScript error.

Fix:
1. Check if a newer version of the widget is available on the Marketplace.
2. Check the widget's compatibility with your Studio Pro version.
3. Try removing the widget's `.mpk` file from the `widgets` folder and re-importing it.
4. Check the browser console for JavaScript errors when loading a page that uses the widget.

**"The module package was created with a newer version of Studio Pro"**

The module was built with a newer version of Studio Pro than yours.

Fix: Update Studio Pro to the version specified, or find an older version of the module that is compatible with your Studio Pro version.

**"Access rule on entity 'X.Y' refers to a role that does not exist"**

The module defines access rules that reference module roles, but something went wrong during import and the roles are not properly set up.

Fix: Open the module's security settings and verify all module roles exist. If they do not, re-import the module. If they do exist but the access rules are wrong, manually fix the access rules.

**"An error occurred while importing the module: 'out of memory'"**

Large modules (especially those with many pages, images, or widgets) can exceed Studio Pro's default memory allocation.

Fix: Increase Studio Pro's memory allocation. Edit the `studio-pro.exe.config` file (or equivalent) and increase the `MaxHeapSize` value. Restart Studio Pro and retry the import.

### Version Conflicts

**Module X requires Community Commons v9+ but you have v8**

When a module requires a newer version of a dependency than what you have.

Fix: Update the dependency first, then import/update the module that requires it. Be aware that updating the dependency may break other modules that depend on the older version (this is rare but possible).

**Module X requires Studio Pro 10.6+ but you are on 9.24 LTS**

The module uses features or APIs that were introduced in a Studio Pro version newer than yours.

Fix: Either update Studio Pro or find an older version of the module that supports your version. The Marketplace listing should show which versions support which Studio Pro versions.

**Two modules require different versions of the same JAR**

This is the classic "dependency hell" problem. Module A needs `library-1.x` and Module B needs `library-2.x`, and the two versions are not compatible.

Fix: There is no easy fix. Options:
1. Check if newer versions of either module resolve the conflict.
2. Contact the module authors and ask if they can update their dependency.
3. Fork one of the modules and update its dependency yourself.
4. Choose one module over the other.
5. In extreme cases, use a Java class loader trick to isolate the conflicting libraries, but this is advanced and fragile.

**The module was built for Mendix 10 but your project is Mendix 9**

Major version mismatches are usually not resolvable. Mendix 9 and 10 have significant platform differences.

Fix: Find a version of the module that was built for your Mendix major version, or upgrade your project.

### Dependency Issues

**Circular dependencies**

Module A depends on Module B, and Module B depends on Module A. This should not happen with well-designed modules, but it does occasionally.

Fix: Check if one of the dependencies is actually optional or if there is a version of one module that does not have the circular dependency. If the modules genuinely require each other, import them in a specific order (usually the one with fewer dependencies first) and resolve errors after both are imported.

**Transitive dependencies**

Module A depends on Module B, which depends on Module C. You imported A and B but forgot C.

Fix: Check Module B's dependencies and import Module C. Some modules document their full dependency tree; many only document direct dependencies.

**MxModel Reflection sync issues**

Many modules depend on MxModel Reflection being synced (so it knows about your current domain model). If you add entities or attributes after syncing, the modules that depend on reflection will not see the new elements.

Fix: Re-sync MxModel Reflection. Go to its admin page (usually at `/MxModelReflection/`) and click "Sync." Do this any time you change your domain model and are using modules that depend on reflection.

**After-startup microflow ordering**

Some modules require their startup microflow to run before others. For example, the Encryption module should initialize before the SAML module because SAML uses encryption.

Fix: In your main after-startup microflow, call the module startup microflows in the correct order:
1. Encryption.ASU_Encryption
2. Community Commons startup (if any)
3. SAML.ASU_SAML
4. Other module startups
5. Your own startup logic

If you get errors during startup, check the order of these calls.

### Runtime Errors From Marketplace Modules

**"Encryption key not set"**

You are using a module that depends on the Encryption module, but you have not set the encryption key constant.

Fix: Set the `Encryption.EncryptionKey` constant to a 16-character string (or 32 for AES-256). Set it in your project settings for each environment.

**"SMTP connection refused" or "Mail sending failed"**

The Email module cannot connect to your SMTP server.

Fix: Check:
1. The SMTP host, port, username, and password constants are correct.
2. The SMTP server allows connections from your app's IP address.
3. The port is not blocked by a firewall.
4. The encryption type (TLS/SSL/None) matches what the SMTP server expects.
5. If using Gmail or Office 365, check if "less secure apps" or app passwords are required.

**"SAMLResponse validation failed"**

The SAML module received a SAML response that did not pass validation.

Fix: This is a broad error with many possible causes:
1. Clock skew between your server and the IdP. Increase the `ClockSkewAllowance` constant.
2. Incorrect Entity ID. The Entity ID in your SAML configuration must match what the IdP expects, exactly.
3. Certificate mismatch. The IdP's signing certificate may have changed. Update it in your SAML configuration.
4. ACS URL mismatch. The URL the IdP sends the response to must match the URL configured in the SAML module.

For detailed SAML troubleshooting, see the SAML/SSO payload validation guide in this repository.

**"MxModel Reflection: Object 'X' not found"**

A module is trying to use MxModel Reflection to find an entity or attribute that does not exist (anymore).

Fix: Re-sync MxModel Reflection. If the entity was intentionally removed, update the module's configuration to point to the correct entity.

**NullPointerException in a Java action**

A Java action in a Marketplace module threw a NullPointerException.

Fix: Check the stack trace in the Studio Pro console. It will tell you which Java action and which line. Common causes:
1. A required parameter was not passed to the microflow that calls the Java action.
2. A configuration constant is not set.
3. An expected object is null (not found in the database, not passed correctly).
4. The Java action has a bug. Check if a newer version of the module fixes it, or file an issue with the module author.

**Widget rendering errors**

A widget from a Marketplace module is not rendering correctly or is throwing JavaScript errors.

Fix:
1. Open the browser developer tools (F12) and check the Console tab for errors.
2. Check if the widget version is compatible with your Mendix client version.
3. Clear your browser cache and try again.
4. Check if the widget has required properties that you did not set in Studio Pro.
5. Try the widget on a simple test page with minimal complexity to isolate the issue.

### Performance Problems

**Module is slow at startup**

Some modules do significant work during their after-startup microflow (loading configuration, syncing data, warming caches).

Fix: Check how long each after-startup microflow takes. If a module is slow to start, check its documentation for options to defer initialization or reduce startup work.

**Module creates too many database queries**

Some modules are not optimized for performance, especially community modules. They may use multiple retrieves where a single OQL query would suffice, or retrieve entire tables when they only need a few records.

Fix: Use Mendix's performance monitoring tools (Runtime Statistics, Application Performance Monitor) to identify slow queries. If the problem is in the module's code and you cannot change it, consider:
1. Adding indexes to the module's entities (you can do this without modifying the module itself in Mendix 9+).
2. Contacting the module author.
3. Forking the module and optimizing the queries yourself.

**Scheduled event consuming too many resources**

A module's scheduled event is running too frequently or processing too much data.

Fix: Adjust the scheduled event's interval. Many modules default to running every minute or every 30 seconds, which may be more frequent than you need. Change it to an appropriate interval for your use case.

**Memory leaks from widgets**

Some client-side widgets do not properly clean up when they are destroyed (page navigation). This can cause memory leaks in the browser.

Fix: If you notice the browser tab consuming more and more memory over time, check each widget by removing them one at a time to identify the culprit. Report the issue to the widget author. In the meantime, advise users to refresh the browser periodically.

### Getting Help

When you are stuck with a Marketplace module issue:

**1. Check the Marketplace listing's documentation and FAQ**. Your question may already be answered.

**2. Check the Mendix Forum**. Search for your specific error message or module name. Chances are someone else has encountered the same issue. The Mendix Forum is at [forum.mendix.com](https://forum.mendix.com/).

**3. Check GitHub**. Many Marketplace modules have their source on GitHub (often under the `mendix` organization or the author's profile). Check the Issues tab for known issues and solutions.

**4. File a support ticket (Mendix-supported modules only)**. If the module is Mendix-supported (has the blue badge), you can file a support ticket through the Mendix Support portal. Include:
   - Module name and version.
   - Studio Pro version.
   - Exact error message and stack trace.
   - Steps to reproduce.
   - What you have already tried.

**5. Ask in the Mendix Community Slack**. The Mendix community has an active Slack workspace where you can ask questions and get help from other developers.

**6. Contact the module author directly**. For community modules, the author's profile is linked from the Marketplace listing. Some authors are responsive to direct messages or questions.

**7. Post on the Mendix Forum with details**. If you cannot find an existing answer, create a new Forum post. Include all the details listed in point 4 above. Tag it with the module name.

---

## Summary

The Mendix Marketplace is a powerful resource that can save you significant development time. But it is not a grab-bag you can pull from without thinking. Every module you import is a dependency you need to manage, a piece of code you need to secure, and a potential maintenance burden.

The key principles:

1. **Evaluate before importing.** Not all modules are worth the trade-off.
2. **Prefer Mendix-supported modules.** They are maintained, tested, and supported.
3. **Review security.** Especially for community modules and regulated environments.
4. **Do not modify module internals.** Extend from outside to preserve updatability.
5. **Update regularly.** Stale dependencies are a liability.
6. **Test after every update.** Changelogs do not catch everything.
7. **Document everything.** Your future self and your teammates will thank you.
8. **When publishing, commit to maintaining.** An abandoned module helps nobody.

Follow these principles and the Marketplace will be one of the most valuable tools in your Mendix development workflow.
