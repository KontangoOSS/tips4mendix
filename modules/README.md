# Mendix Modules Guide

## A Practical Reference for Mendix Developers

**Version:** 1.0
**Date:** February 2026

---

## Table of Contents

1. [What Is a Module](#1-what-is-a-module)
2. [Module Types](#2-module-types)
3. [Module Structure](#3-module-structure)
4. [Creating and Organizing Modules](#4-creating-and-organizing-modules)
5. [Module Security](#5-module-security)
6. [Module Settings](#6-module-settings)
7. [Inter-Module Dependencies](#7-inter-module-dependencies)
8. [Refactoring](#8-refactoring)
9. [Versioning and Updates](#9-versioning-and-updates)
10. [Common Patterns](#10-common-patterns)
11. [Naming Conventions](#11-naming-conventions)

---

## 1. What Is a Module

### Definition

A module in Mendix is the primary unit of organization within a project. It is a self-contained package of functionality that groups together related domain models, pages, microflows, nanoflows, constants, enumerations, Java actions, and security rules. Every piece of logic, every entity, every page you build in Mendix lives inside a module.

Think of a module as a folder with rules. It is not just a directory for organizing files -- it carries its own security configuration, its own domain model, and its own lifecycle. When you export a module, everything it contains travels with it. When you delete a module, everything inside it goes away.

### Logical Separation

Modules exist to give you logical separation. Without them, a Mendix project would be a flat collection of hundreds or thousands of artifacts with no boundaries. Modules let you draw lines between different concerns in your application.

A well-structured project uses modules to answer the question: "Where does this piece of functionality belong?" When a new developer joins the team and needs to find the logic for invoice processing, they should be able to look at the module list and immediately know where to go.

The separation modules provide is more than cosmetic. Module boundaries affect:

- **Security**: Each module defines its own roles and access rules. An entity's access is configured at the module level.
- **Dependencies**: You can see which modules reference which other modules. This visibility helps you manage coupling.
- **Deployment**: Marketplace modules can be updated independently. Your own modules can be exported and imported into other projects.
- **Team ownership**: In larger teams, modules map naturally to team responsibilities. The team that owns the "OrderManagement" module owns everything inside it.

### Module vs. Project Structure

A Mendix project (also called an "app" in modern Mendix terminology) is the top-level container. It contains:

- **Project-level settings**: Security mode, runtime settings, theme, navigation, system texts.
- **Modules**: One or more modules that hold all the actual functionality.
- **Project-level security**: User roles that span the entire application.

The relationship is straightforward:

```
Project (App)
  |-- Project Settings
  |-- Project Security (User Roles)
  |-- Navigation
  |-- Module A
  |     |-- Domain Model
  |     |-- Pages
  |     |-- Microflows
  |     |-- Security (Module Roles)
  |     |-- ...
  |-- Module B
  |     |-- Domain Model
  |     |-- Pages
  |     |-- Microflows
  |     |-- Security (Module Roles)
  |     |-- ...
  |-- Module C (from Marketplace)
  |     |-- ...
```

Every new Mendix project starts with a single module, typically named after the project itself. This default module is an app module -- you own it, you control it. From there, you add more modules as your application grows.

A common mistake is to leave everything in that single default module. This works fine for prototypes and small apps, but it becomes unmanageable once you have more than a few dozen microflows and a handful of entities. The guideline is simple: if you find yourself creating deeply nested folders within a single module to keep things organized, it is time to split into multiple modules.

### What a Module Is Not

A module is not a microservice. It does not run in isolation. All modules in a Mendix project share the same runtime, the same database, and the same deployment unit. Modules are a compile-time organizational tool, not a runtime isolation boundary.

A module is also not a package in the traditional programming sense. You cannot version individual app modules independently within the same project. They all move together when you commit to version control. Marketplace modules are the exception -- they carry version metadata and can be updated through the Marketplace.

---

## 2. Module Types

Mendix distinguishes between several types of modules. Understanding these types matters because they have different rules about what you can modify, how they are updated, and how they interact with your project.

### App Modules

App modules are the modules you create yourself. They contain your application's business logic, domain model, and user interface. You have full control over every aspect of an app module -- its entities, microflows, pages, security, and structure.

Key characteristics of app modules:

- **Full edit access**: You can modify anything inside them.
- **No external versioning**: They are versioned with your project through your version control system (Git or SVN).
- **No automatic updates**: Changes are entirely manual and under your control.
- **Exportable**: You can export an app module as an `.mpk` file and import it into another project.

Most projects have between 3 and 15 app modules, depending on complexity. A simple departmental app might have 3. An enterprise application might have 10 or more.

### Marketplace Modules

Marketplace modules are third-party modules downloaded from the Mendix Marketplace (formerly the App Store). They provide pre-built functionality that you incorporate into your project.

Common examples include:

| Module | Purpose |
|--------|---------|
| Community Commons | Utility microflows and Java actions for string manipulation, date handling, and more |
| Encryption | AES encryption and decryption of string values |
| Email Connector | Sending emails via SMTP or Exchange |
| SAML | Single sign-on using SAML 2.0 |
| MendixSSO | Single sign-on through the Mendix platform |
| Atlas UI Resources | UI framework components and building blocks |
| Nanoflow Commons | Client-side utility actions for nanoflows |
| Database Replication | Importing data from external databases |
| Excel Importer | Importing data from Excel spreadsheets |
| REST Services | Consuming and publishing REST APIs |
| Deep Link | Handling deep links into your application |
| Audittrail | Tracking changes to entities |
| Scheduled Event Admin | Managing scheduled events at runtime |

Key characteristics of Marketplace modules:

- **Limited edit access**: You can modify them, but updates from the Marketplace will overwrite your changes unless you take precautions (covered in section 9).
- **Versioned externally**: The Marketplace tracks versions. You can see when a new version is available and review changelogs.
- **Update notifications**: Studio Pro notifies you when a newer version is available.
- **Dependencies**: Some Marketplace modules depend on other Marketplace modules. Studio Pro will prompt you to download dependencies.

When you download a Marketplace module, Studio Pro adds it to your project just like any other module. The difference is that it carries metadata linking it to the Marketplace listing, which enables the update mechanism.

### Add-On Modules

Add-on modules are a special category introduced for the Mendix Solutions ecosystem. They are modules that a solution vendor builds and distributes as part of a solution. The key difference from regular Marketplace modules is the level of protection.

Add-on modules can have their internals hidden. The consumer of the solution cannot see or modify the microflows, domain model details, or Java actions inside a protected add-on module. They can only interact with the module through its public API -- the entities, microflows, and other artifacts that the vendor has explicitly marked as public.

Key characteristics:

- **Protected internals**: The vendor controls what is visible and what is hidden.
- **Public API surface**: Only artifacts marked as "usable" or "public" in the module's API are accessible to consumers.
- **Vendor-managed updates**: The solution vendor pushes updates. Consumers receive them through the Solutions mechanism.
- **IP protection**: Vendors can distribute functionality without exposing implementation details.

Most Mendix developers will not need to create add-on modules unless they are building a solution for distribution. However, you will encounter them when using certain Mendix-built solutions and partner solutions.

### Solution Modules

Solution modules take the add-on concept further. A Mendix Solution is a complete, configurable application built on Mendix that is distributed to multiple customers. Solution modules are the building blocks of these solutions.

The key distinction is the configurability model:

- **Non-adaptable elements**: Core logic that the solution vendor maintains. Consumers cannot modify these.
- **Adaptable elements**: Parts of the module that consumers are expected to customize for their specific needs, such as certain pages, microflows, or configuration entities.
- **Extension points**: Explicit hooks where consumers can add their own logic, such as "after-processing" microflows that the solution calls if they exist.

The solution module concept is relevant primarily to ISVs (Independent Software Vendors) and partners building distributable Mendix applications. If you are building a custom application for a single organization, you will work exclusively with app modules and Marketplace modules.

### Choosing the Right Module Type

For most development work, the decision is straightforward:

| Scenario | Module Type |
|----------|-------------|
| Building your application's business logic | App module |
| Need common utility functions | Marketplace module (e.g., Community Commons) |
| Need authentication/SSO | Marketplace module (e.g., SAML, MendixSSO) |
| Building a distributable solution | Add-on module or solution module |
| Need to protect intellectual property in a shared module | Add-on module |

---

## 3. Module Structure

Every module, regardless of type, has the same internal structure. Understanding this structure is essential for organizing your work effectively.

### Domain Model

The domain model is the heart of any module. It defines the entities (data tables), their attributes (columns), associations (relationships), and access rules.

Each module has exactly one domain model. You cannot have multiple domain models within a single module -- this is by design. The domain model is what gives the module its identity. When people talk about the "OrderManagement module," they are primarily referring to the entities and relationships defined in its domain model.

#### Entities

An entity maps to a database table. Each entity has:

- **Attributes**: The data fields. Each attribute has a type (String, Integer, Decimal, Boolean, DateTime, Enumeration, etc.) and optional validation rules.
- **Associations**: Relationships to other entities, either within the same module or in other modules. Associations can be one-to-one, one-to-many, or many-to-many (using a reference set).
- **Access rules**: Who can create, read, update, and delete instances of this entity, and which attributes they can access. Access rules are tied to module roles.
- **Event handlers**: Microflows that run before or after commit, before or after delete.
- **Indexes**: Database indexes for improving query performance on specific attributes or combinations of attributes.
- **Validation rules**: Rules that the runtime enforces when committing an object.

#### Persistable vs. Non-Persistable Entities

Entities can be either persistable (stored in the database) or non-persistable (existing only in memory during a session or microflow execution).

Non-persistable entities (NPEs) are used for:

- View models that shape data for a specific page but do not need to be stored.
- Request/response wrappers for service calls.
- Temporary calculation results.
- Search or filter criteria objects.

A common pattern is to place NPEs in the same module as the pages or microflows that use them. If an NPE is used across multiple modules, consider whether it belongs in a shared module.

#### Generalization (Inheritance)

Entities can inherit from other entities. The specialized entity gets all attributes and associations of its generalization (parent) entity, plus any additional attributes you define. This maps to table-per-hierarchy inheritance in the database.

Generalization works across module boundaries. An entity in Module A can inherit from an entity in Module B. This creates a dependency from A to B.

Common uses:

- Specializing `System.Image` or `System.FileDocument` for custom file storage.
- Creating a base `Address` entity and specializing it into `ShippingAddress`, `BillingAddress`, etc.
- Specializing `Administration.Account` for custom user types.

#### Associations

Associations define relationships between entities. Key design points:

- **Owner**: Every association has an owner -- the entity on the "many" side of a one-to-many relationship, or either side of a one-to-one. The owner stores the foreign key.
- **Delete behavior**: You can set delete behavior to "delete {associated object} as well" or "delete {associated object} only if not associated with other objects." The default is to do nothing, which can leave orphaned records.
- **Cross-module associations**: An entity in one module can associate with an entity in another module. This is normal and expected, but each such association creates a dependency between the modules.

### Pages

Pages define the user interface. Within a module, pages are organized into folders. Each page is associated with a layout (which typically comes from your UI module or Atlas UI).

Pages reference entities from the domain model, call microflows and nanoflows, and use widgets from the widget library. A page in Module A can reference entities from Module B, but this creates a cross-module dependency.

Types of pages you will find in a module:

- **Overview pages**: List views or data grids showing multiple objects.
- **Detail pages**: Forms for viewing and editing a single object.
- **Select pages**: Pop-up pages for selecting associated objects.
- **Dashboard pages**: Summary views combining data from multiple entities.
- **Snippets**: Reusable page fragments that can be embedded in multiple pages.

### Microflows

Microflows are the server-side visual programming constructs in Mendix. They run on the Mendix Runtime (server side) and can access the database, call external services, manipulate data, and perform business logic.

Within a module, microflows are organized into folders. Naming and folder conventions are covered in section 11.

Key microflow concepts within a module:

- **Entity event handlers**: Microflows triggered by entity lifecycle events (before/after commit, before/after delete). These are configured on the entity in the domain model.
- **Page-triggered microflows**: Microflows called from buttons, data views, or other page elements.
- **Scheduled event microflows**: Microflows executed on a timer (configured in the module's scheduled events).
- **Sub-microflows**: Microflows called from other microflows. These are your reusable building blocks.
- **Exposed microflows**: Microflows that you make available as web service operations or REST endpoints.

Microflows can reference entities, other microflows, constants, and enumerations from any module in the project. Each such reference creates a dependency.

### Nanoflows

Nanoflows are the client-side counterpart to microflows. They run in the user's browser (for web apps) or on the device (for native mobile apps). Nanoflows cannot access the database directly -- they work with objects that are already on the client.

Use nanoflows for:

- Client-side validation before submitting data.
- Conditional visibility logic.
- Navigation actions.
- Calling client-side APIs (JavaScript actions).
- Offline logic in native mobile apps.

Nanoflows live inside modules just like microflows, organized into folders. The same dependency rules apply -- a nanoflow in Module A can call a nanoflow in Module B, creating a cross-module dependency.

### Constants

Constants are named values that you define at design time and can override at deployment time. They are scoped to a module.

Common uses for constants:

- API endpoint URLs.
- Feature flags.
- Configuration values (timeouts, retry counts, batch sizes).
- External system credentials (though for secrets, consider using environment variables or a secrets manager instead).

Constants have a default value set in Studio Pro and can be overridden per environment in the Mendix Developer Portal or through the runtime configuration. This makes them ideal for values that differ between development, test, and production environments.

A constant is referenced by its full name: `ModuleName.ConstantName`. Any module can read any constant from any other module, as long as it is not protected.

### Enumerations

Enumerations define a fixed set of named values. They are used as attribute types in the domain model and in microflow logic.

Examples:

- `OrderStatus`: Open, Processing, Shipped, Delivered, Cancelled
- `Priority`: Low, Medium, High, Critical
- `PaymentMethod`: CreditCard, BankTransfer, PayPal, Invoice

Each enumeration value has:

- **Name**: The internal identifier (used in microflow logic and database storage). Keep this stable -- changing it affects stored data.
- **Caption**: The display text shown to users. This can be localized through the system's internationalization features.
- **Image** (optional): An icon associated with the value.

Enumerations can be used across modules. An entity in Module A can have an attribute of an enumeration type defined in Module B.

### Java Actions

Java actions bridge the gap between Mendix's visual development and custom Java code. They are defined in a module and can be called from microflows just like any other action.

Each Java action has:

- **Parameters**: Input values passed from the microflow.
- **Return type**: The value returned to the microflow.
- **Java implementation**: The actual Java code, located in the `javasource` directory of your project.

The Java source files follow the module structure:

```
javasource/
  modulename/
    actions/
      MyJavaAction.java
    proxies/
      EntityName.java
```

The `proxies` directory contains auto-generated Java proxy classes for each entity in the module's domain model. These proxies give your Java code type-safe access to entity attributes and associations.

When you rename or move a Java action between modules, the Java source files need to move as well. Studio Pro handles this automatically in most cases, but you should verify the file system reflects the change, especially if you are using an external IDE for Java development.

### Module Security

Every module has a security document that defines:

- **Module roles**: The roles specific to this module (e.g., "User," "Manager," "Administrator").
- **Entity access rules**: For each entity, which module roles can create, read, write, and delete objects, and which attributes they can access.
- **Microflow access**: Which module roles can execute which microflows (relevant for microflows called from pages or exposed as services).
- **Nanoflow access**: Which module roles can execute which nanoflows.
- **Page access**: Which module roles can view which pages.
- **OData access**: Which module roles can access which published OData resources.
- **REST access**: Which module roles can access which published REST operations.

Module security is covered in depth in section 5.

### Scheduled Events

Scheduled events are timers that execute a microflow on a defined schedule. They are configured within a module and reference a microflow in that same module.

Each scheduled event has:

- **Schedule**: Interval-based (every N minutes/hours/days) or cron-based.
- **Enabled/Disabled**: Can be toggled in Studio Pro and overridden at runtime (if using the Scheduled Event Admin module).
- **Microflow**: The microflow to execute. Must be in the same module as the scheduled event.

### Published and Consumed Services

Modules can contain service definitions:

- **Published web services (SOAP)**: Expose microflows as SOAP operations.
- **Published REST services**: Expose microflows as REST endpoints with defined paths, methods, and authentication.
- **Published OData services**: Expose entities as OData resources for external consumption.
- **Consumed web services (SOAP)**: Import a WSDL and generate proxy microflows for calling external SOAP services.
- **Consumed REST services**: Define external REST endpoints and map their request/response structures.

These service definitions live within a module and naturally group related integration logic together. An "IntegrationERP" module might contain all consumed services for your ERP system, along with the mapping microflows and any staging entities needed for data transformation.

---

## 4. Creating and Organizing Modules

Good module organization is the difference between a maintainable application and a tangled mess. This section covers practical strategies for structuring your modules.

### Single-Responsibility Principle

Each module should have one clear reason to exist. If you cannot describe a module's purpose in a single sentence, it is probably doing too much.

Good examples:

- "The OrderManagement module handles order creation, processing, and fulfillment."
- "The CustomerPortal module provides the self-service UI for external customers."
- "The ERPIntegration module manages all communication with the SAP ERP system."

Bad examples:

- "The Main module contains everything that does not fit elsewhere." (This is a dumping ground, not a module.)
- "The Utilities module handles email sending, PDF generation, user management, and reporting." (This is at least four modules.)

The single-responsibility principle does not mean each module should be tiny. A module that handles order management might contain entities for Order, OrderLine, OrderStatus, Shipment, and Return, along with dozens of microflows, several pages, and a handful of scheduled events. That is fine -- all of those artifacts serve the same responsibility.

### Feature Modules vs. Layer Modules

There are two fundamental approaches to organizing modules, and most projects use a combination of both.

#### Feature Modules (Vertical Slices)

Feature modules group everything related to a specific business capability. Each feature module contains its own entities, pages, microflows, and security configuration.

```
Project
  |-- OrderManagement (entities, pages, microflows for orders)
  |-- CustomerManagement (entities, pages, microflows for customers)
  |-- ProductCatalog (entities, pages, microflows for products)
  |-- Invoicing (entities, pages, microflows for invoices)
  |-- Reporting (entities, pages, microflows for reports)
```

Advantages:

- Aligns with business domains and team ownership.
- Changes to one feature are contained within one module.
- Easy to understand what each module does.
- Supports parallel development -- different team members can work in different modules with less conflict.

Disadvantages:

- Cross-cutting concerns (logging, notifications, auditing) do not fit neatly into a single feature.
- Some entities are shared across features (e.g., Customer is used by both OrderManagement and Invoicing).

#### Layer Modules (Horizontal Slices)

Layer modules separate concerns by technical layer. This mirrors traditional architecture patterns like MVC.

```
Project
  |-- DomainModel (all entities)
  |-- BusinessLogic (all microflows)
  |-- UserInterface (all pages)
  |-- Integration (all service definitions)
```

Advantages:

- Clear separation of technical concerns.
- Easy to enforce architectural rules (e.g., "pages never access the database directly").

Disadvantages:

- A single feature change requires modifying multiple modules.
- Dependencies between layers create tight coupling across the module boundary.
- Does not align with team ownership of business capabilities.
- In practice, becomes unwieldy as the application grows.

#### The Practical Approach: Feature-First with Shared Modules

The recommended approach is feature-first with a small number of shared modules for cross-cutting concerns:

```
Project
  |-- Core (shared entities, enumerations, and base microflows)
  |-- OrderManagement
  |-- CustomerManagement
  |-- ProductCatalog
  |-- Invoicing
  |-- Notification (cross-cutting: email, SMS, push notifications)
  |-- Integration_SAP (all SAP-related integration logic)
  |-- Administration (app configuration, admin-only pages)
  |-- System (Mendix system module, not editable)
  |-- CommunityCommons (Marketplace)
  |-- Encryption (Marketplace)
```

The `Core` or `Shared` module holds entities and microflows that genuinely belong to multiple features. The key word is "genuinely" -- resist the temptation to put things in Core just because you are not sure where they belong. If an entity is used by only one feature, it belongs in that feature's module, even if you think it might be used elsewhere someday.

### Shared and Common Modules

A shared module (often called `Core`, `Common`, `Shared`, or `Foundation`) contains elements that are used across multiple feature modules. Typical contents include:

- **Base entities**: Entities that multiple modules reference, such as `Country`, `Currency`, or `UnitOfMeasure`.
- **Utility microflows**: Generic helper microflows for string formatting, date calculations, or data validation that are not specific to any feature.
- **Common enumerations**: Enumerations used across multiple modules.
- **Shared snippets**: Page snippets that appear in multiple feature modules.
- **Application-wide constants**: Constants that multiple modules need, such as the application name or base URL.

Rules of thumb for the shared module:

1. **Keep it small**. If your shared module is the largest module in the project, something has gone wrong. Shared code should be the exception, not the norm.
2. **No business logic**. The shared module should not contain feature-specific business rules. If a microflow implements an order processing rule, it belongs in OrderManagement, not Shared.
3. **Stable interfaces**. Because many modules depend on the shared module, changes to it have a wide blast radius. Treat its entities and microflows as a stable API.
4. **No circular dependencies**. The shared module should not depend on any feature module. Dependencies flow in one direction: feature modules depend on the shared module, never the reverse.

### When to Create a New Module

Create a new module when:

- You are building a distinct business capability (order management, invoicing, customer self-service).
- You are integrating with an external system and the integration involves multiple entities, microflows, and possibly scheduled events.
- You have cross-cutting functionality (notifications, auditing, reporting) that serves multiple feature modules.
- Your current module has grown past 50-100 microflows and multiple developers are experiencing merge conflicts.
- You want to reuse functionality across multiple Mendix projects.

Do not create a new module when:

- You just want to organize a few related microflows (use folders within the existing module instead).
- The new module would contain only one or two entities and a handful of microflows (unless it is a genuine, isolated concern).
- You are creating it solely to match an organizational chart rather than a logical grouping of functionality.

### Module Creation Checklist

When creating a new module, go through this checklist:

1. **Name it clearly** (see section 11 for naming conventions).
2. **Define its module roles** -- at minimum, decide what roles interact with this module's functionality.
3. **Set up the domain model** -- even if it starts with a single entity.
4. **Create the folder structure** within the module for microflows, pages, etc.
5. **Configure security** -- do not leave this until the end. Set access rules on entities as you create them.
6. **Document the module's purpose** -- add a brief description in the module settings or a README microflow.
7. **Map module roles to project user roles** in the project security settings.

---

## 5. Module Security

Security in Mendix is a layered system. Project security defines the overall security mode and user roles. Module security defines what each module role can access within that module. The mapping between project user roles and module roles is what ties it all together.

### Module Roles

A module role is a role defined within a specific module. It represents a level of access to that module's resources. A module can have any number of module roles.

Typical module roles:

| Module | Module Roles |
|--------|-------------|
| OrderManagement | OrderUser, OrderManager, OrderAdmin |
| CustomerManagement | CustomerViewer, CustomerEditor, CustomerAdmin |
| Reporting | ReportViewer, ReportCreator |
| Administration | AdminUser |

Module roles are internal to the module. They do not directly correspond to user accounts. Instead, they are mapped to project-level user roles.

### Mapping Module Roles to Project User Roles

Project security defines user roles at the application level (e.g., Employee, Manager, Administrator). Module roles are connected to user roles through a mapping in the project security settings.

The mapping works like this:

```
Project User Role: Manager
  |-- OrderManagement.OrderManager
  |-- CustomerManagement.CustomerEditor
  |-- Reporting.ReportViewer
  |-- Administration (no role -- Manager has no access to admin functions)

Project User Role: Administrator
  |-- OrderManagement.OrderAdmin
  |-- CustomerManagement.CustomerAdmin
  |-- Reporting.ReportCreator
  |-- Administration.AdminUser
```

A single project user role can be mapped to at most one module role per module. If a user has the "Manager" project user role, they get the `OrderManager` module role in the OrderManagement module and the `CustomerEditor` role in the CustomerManagement module.

A single module role can be mapped to multiple project user roles. Both "Manager" and "Administrator" might be mapped to `OrderManagement.OrderManager`.

### Entity Access Rules

Entity access rules are the core of module security. For each entity, you define what each module role can do:

- **Create**: Can this role create new objects of this entity?
- **Delete**: Can this role delete objects of this entity?
- **Read**: Which attributes can this role read? You can grant read access per attribute.
- **Write**: Which attributes can this role write? You can grant write access per attribute.
- **XPath constraint**: An optional constraint that limits which objects are visible to this role. For example, `[OrderManagement.Order_CreatedBy = '[%CurrentUser%]']` restricts users to seeing only their own orders.

Best practices for entity access rules:

1. **Start restrictive, then open up**. By default, no role has access to anything. Add access explicitly for each role that needs it.
2. **Use XPath constraints for row-level security**. Do not rely on microflow logic alone to restrict data access. XPath constraints are enforced at the database level and cannot be bypassed.
3. **Separate read and write access**. Just because a role can see an attribute does not mean it should be able to change it. Grant write access only where needed.
4. **Be specific with attributes**. Do not grant access to all attributes if a role only needs a subset. A `CustomerViewer` role might need to see a customer's name and email but not their internal credit score.

### Default Rights Strategy

When defining entity access, you need a consistent strategy across your application. There are two common approaches:

#### Deny-by-Default (Recommended)

Start with no access and explicitly add rules for each role that needs them. This is the safest approach because a missing rule means no access, not accidental access.

Steps:
1. Create the entity with no access rules.
2. For each module role, add an access rule granting only the specific access needed.
3. If a role does not need access to the entity, do not add a rule for it.

#### Grant-Then-Restrict

Start with broad access and restrict where needed. This is faster for simple applications but dangerous for complex ones because a forgotten restriction means unintended access.

The deny-by-default approach is strongly recommended for any application that handles sensitive data, has multiple user roles, or will be used in a production environment.

### Microflow, Nanoflow, and Page Access

Beyond entity access, module security also controls:

- **Microflow access**: Which module roles can execute a microflow. This is checked when a microflow is called from a page button or menu item. It is not checked when a microflow is called from another microflow (sub-microflow calls bypass this check).
- **Nanoflow access**: Same as microflow access but for nanoflows.
- **Page access**: Which module roles can open a page. This controls navigation menu visibility and direct page access.

A common mistake is to set page access but forget to set microflow access (or vice versa). If a page has a button that calls a microflow, both the page and the microflow need to be accessible to the user's module role. Otherwise, the user can see the page but gets an error when clicking the button.

### Security and Marketplace Modules

Marketplace modules come with their own module roles. When you add a Marketplace module to your project, you need to map its module roles to your project user roles.

For example, the SAML module defines roles like `Administrator`. You need to map this role to whichever project user role should be able to configure SAML settings (typically your application's Administrator role).

Some Marketplace modules require specific role mappings to function correctly. Always read the module's documentation for security setup instructions.

### Practical Security Patterns

#### Admin-Only Entities

For configuration entities that only administrators should access:

1. Create an `Admin` module role in your module.
2. Grant full CRUD access on the configuration entity only to the `Admin` role.
3. Map the `Admin` module role to the project's `Administrator` user role.
4. Create admin pages in a separate folder, accessible only to the `Admin` role.

#### Multi-Tenant Data Isolation

For applications serving multiple organizations:

1. Create a `Tenant` entity with associations to data entities.
2. On each data entity, add an XPath constraint that filters by the current user's tenant: `[Module.Entity_Tenant/Module.Tenant/Module.Tenant_Account = '[%CurrentUser%]']`.
3. Apply this constraint to every module role except the system administrator.

#### Audit-Friendly Access

For entities that need change tracking:

1. Add `CreatedBy`, `CreatedDate`, `ChangedBy`, `ChangedDate` attributes (or use the `System.changedBy` and `System.changedDate` system members).
2. Make audit attributes read-only for all roles (grant read access but not write access).
3. Set them automatically using event handlers or system members.

---

## 6. Module Settings

Each module has settings that control its behavior at startup and shutdown, as well as configuration values through constants.

### After-Startup Microflow

A module can designate a microflow to run when the application starts. This microflow executes after the Mendix Runtime has fully initialized, including database synchronization.

Common uses for after-startup microflows:

- **Initializing configuration data**: Creating default records if they do not exist (e.g., a singleton configuration entity).
- **Registering custom request handlers**: Setting up custom URL handlers using the Core.addRequestHandler Java API.
- **Validating configuration**: Checking that required constants are set and logging warnings if they are not.
- **Warming caches**: Pre-loading frequently accessed data into memory.
- **Starting background processes**: Initiating long-running processes that operate alongside the application.

Important considerations:

1. **Execution order**: If multiple modules have after-startup microflows, the execution order is not guaranteed. Do not rely on one module's startup microflow running before another's.
2. **Error handling**: If an after-startup microflow throws an unhandled error, the application will still start, but the error will be logged. Consider wrapping your startup logic in error handling to fail gracefully.
3. **Performance**: Keep startup microflows fast. Long-running initialization delays application availability. If you need to load large amounts of data, consider using an asynchronous pattern (start a background process and return immediately).
4. **Idempotency**: Startup microflows should be idempotent -- running them multiple times should produce the same result as running them once. The application may restart at any time.

Example pattern for a startup microflow:

```
ACT_Module_AfterStartup
  |-- Retrieve singleton config entity
  |-- If not found: Create with default values, Commit
  |-- Log "Module initialized successfully"
```

### Before-Shutdown Microflow

A module can designate a microflow to run when the application is shutting down. This microflow executes before the Mendix Runtime shuts down but while the database is still available.

Common uses:

- **Cleanup**: Removing temporary data or session-specific records.
- **Logging**: Recording the shutdown event for audit purposes.
- **Graceful disconnection**: Closing connections to external systems that do not handle abrupt disconnections well.
- **Saving state**: Persisting in-memory state to the database so it can be restored on the next startup.

Important considerations:

1. **Time limit**: The shutdown microflow has a limited time to execute. If it takes too long, the runtime will proceed with shutdown regardless.
2. **Not guaranteed**: In cases of crashes, infrastructure failures, or forced termination, the shutdown microflow will not execute. Do not rely on it for critical data integrity -- use transactional patterns instead.
3. **No user context**: The shutdown microflow runs in a system context without a current user.

### Module Constants

Constants are configured per module. Each constant has:

- **Name**: The identifier used to reference the constant from microflows.
- **Type**: String, Integer, Long, Decimal, Boolean, or DateTime.
- **Default value**: The value used in the development environment and as a fallback if no override is set.
- **Description**: Documentation of the constant's purpose and expected values.

Constants are set in three ways, in order of precedence (highest first):

1. **Environment variable**: Set in the deployment environment using the format `MX_ModuleName_ConstantName` (for Mendix Cloud) or in the runtime configuration.
2. **Mendix Developer Portal**: Set per environment in the portal's environment details.
3. **Default value**: The value defined in Studio Pro.

This precedence order means you can set sensible defaults in Studio Pro for development and override them per environment for test and production.

#### Constant Organization Patterns

For modules with many constants, organize them logically:

```
Module: ERPIntegration
  Constants:
    |-- ERP_BaseUrl (String, default: "https://erp-dev.example.com/api")
    |-- ERP_ApiKey (String, default: "dev-key-not-for-production")
    |-- ERP_TimeoutSeconds (Integer, default: 30)
    |-- ERP_RetryCount (Integer, default: 3)
    |-- ERP_BatchSize (Integer, default: 100)
    |-- ERP_EnableDebugLogging (Boolean, default: false)
```

Best practices for constants:

1. **Prefix with the module or integration name** for clarity when referenced from other modules.
2. **Set meaningful defaults** that work in the development environment without requiring manual configuration.
3. **Never put production secrets in default values**. Use a placeholder like "CONFIGURE-IN-PORTAL" to make it obvious that the value must be set per environment.
4. **Document expected format and valid ranges** in the constant's description field.
5. **Use Boolean constants for feature flags**. This lets you toggle functionality per environment without code changes.

---

## 7. Inter-Module Dependencies

Modules in a Mendix project are not isolated. They reference each other's entities, call each other's microflows, and use each other's enumerations. Managing these dependencies is critical for maintainability.

### How Cross-Module References Work

When a microflow in Module A retrieves an entity from Module B, or when a page in Module A displays an attribute from Module B's entity, Mendix creates a dependency from Module A to Module B. These dependencies are tracked automatically and visible in Studio Pro.

Types of cross-module references:

- **Entity references**: Using another module's entity in a retrieve, change, or create action.
- **Association references**: Creating an association from an entity in Module A to an entity in Module B.
- **Microflow calls**: Calling a microflow defined in another module.
- **Nanoflow calls**: Calling a nanoflow defined in another module.
- **Constant references**: Reading a constant from another module.
- **Enumeration references**: Using an enumeration from another module as an attribute type or in a conditional expression.
- **Page references**: Opening a page from another module or using a snippet from another module.
- **Java action calls**: Calling a Java action defined in another module.

### Dependency Direction

Dependencies should flow in one direction. Establish a clear hierarchy:

```
Layer 0: System, Marketplace Modules (no custom dependencies)
Layer 1: Core/Shared Module (depends only on Layer 0)
Layer 2: Feature Modules (depend on Layer 0 and Layer 1)
Layer 3: Integration Modules (depend on Layer 0, 1, and relevant Layer 2 modules)
Layer 4: UI/Portal Modules (depend on all layers as needed)
```

The cardinal rule: **avoid circular dependencies**. If Module A depends on Module B, Module B should not depend on Module A. Circular dependencies make it impossible to change one module without considering the other, effectively merging them into a single coupled unit.

When you detect a circular dependency, resolve it by:

1. **Moving the shared element to a third module** that both modules depend on (often the Core/Shared module).
2. **Using an event-based pattern** where one module publishes an event (commits an entity) and the other reacts to it through an event handler.
3. **Rethinking the module boundaries** -- if two modules are tightly coupled, perhaps they should be one module.

### Managing Coupling

Tight coupling between modules defeats the purpose of having modules in the first place. Here are strategies for keeping coupling manageable:

#### Use Module APIs

Define a clear "public interface" for each module -- the entities, microflows, and other artifacts that other modules are expected to use. Everything else is an internal implementation detail.

While Mendix does not enforce this distinction for app modules (unlike add-on modules), you can use naming conventions and folder structure to make it clear:

```
Module: OrderManagement
  |-- _API (folder)
  |     |-- Microflows that other modules should call
  |     |-- SUB_Order_GetByCustomer
  |     |-- SUB_Order_CalculateTotal
  |     |-- SUB_Order_Submit
  |-- _Internal (folder)
  |     |-- Microflows that are implementation details
  |     |-- _ProcessOrderLine
  |     |-- _ValidateStockLevels
  |     |-- _SendOrderConfirmation
```

Prefixing internal microflows with an underscore (`_`) or placing them in an `_Internal` folder signals to other developers: "Do not call these from outside this module."

#### Minimize Cross-Module Entity Access

The most common source of tight coupling is direct access to another module's entities. Instead of retrieving and manipulating entities from another module directly, consider:

1. **Exposing microflows as APIs**: Instead of having Module B retrieve and process Module A's entities directly, have Module A expose a microflow that does the work and returns the result.
2. **Using associations sparingly**: Each cross-module association is a dependency. Ask whether the association is truly necessary or if you can pass data through microflow parameters instead.
3. **Favoring reads over writes**: If Module B needs to read data from Module A, that is generally acceptable. If Module B needs to create or modify Module A's entities, that is a stronger coupling that warrants scrutiny.

#### Dependency Rules to Enforce

Establish these rules for your project:

| Rule | Description |
|------|-------------|
| No circular dependencies | If A depends on B, B must not depend on A |
| Feature modules do not depend on each other | OrderManagement should not depend on Invoicing; use a shared module or event pattern |
| Shared modules do not depend on feature modules | The Core module must not reference OrderManagement |
| Marketplace modules are treated as read-only dependencies | Do not modify them; wrap their functionality in your own microflows |
| Integration modules are isolated | Each external system integration should be in its own module with its own entities |

### Practical Example: Breaking a Circular Dependency

Suppose OrderManagement needs to send a notification when an order is placed, and the Notification module needs to read order details to compose the email.

**Circular dependency (bad):**
```
OrderManagement --> Notification (to send notification)
Notification --> OrderManagement (to read order details)
```

**Solution 1: Pass data through parameters**
```
OrderManagement calls Notification.SendEmail(To, Subject, Body)
-- OrderManagement composes the email content itself
-- Notification has no dependency on OrderManagement
```

**Solution 2: Use a shared entity**
```
Core module defines a NotificationRequest entity
OrderManagement creates a NotificationRequest and commits it
Notification has an after-commit handler on NotificationRequest that sends the email
-- Both modules depend on Core, not on each other
```

**Solution 3: Use a callback pattern**
```
OrderManagement calls Notification.SendOrderConfirmation(OrderId, CustomerEmail)
Notification stores the OrderId and calls back to OrderManagement.GetOrderSummary(OrderId)
-- Wait, this is still circular. Use Solution 1 or 2 instead.
```

Solution 1 is the simplest and usually the best choice. Module A gathers the data it needs and passes it to Module B's microflow as parameters. Module B does not need to know where the data came from.

---

## 8. Refactoring

As your application evolves, you will need to move elements between modules, rename things, and restructure your module hierarchy. Mendix refactoring is different from traditional code refactoring because of the visual model and the database implications.

### Moving Entities Between Modules

Moving an entity from one module to another is one of the most impactful refactoring operations. It affects:

- **Database table name**: Mendix names database tables based on the module and entity name. Moving an entity changes its table name, which means the runtime will create a new table and the old one remains (with data in it).
- **Associations**: Any associations to or from the entity will break if the referenced module changes.
- **Microflow references**: Every microflow that retrieves, creates, changes, or deletes the entity will need updating.
- **Page references**: Every page that displays the entity will need updating.
- **Security rules**: Access rules reference module roles, and those change when the entity moves.

#### Safe Process for Moving Entities

1. **Assess the impact**: Before moving anything, find all references to the entity. In Studio Pro, right-click the entity and select "Find usages." Note every microflow, page, and association that references it.

2. **Plan the data migration**: If the entity has data in a production database, you need a migration strategy. Options:
   - Use a Java action to copy data from the old table to the new table.
   - Use a startup microflow that checks if data needs to be migrated and performs the copy.
   - Use database-level scripts to rename the table (advanced, not officially supported).

3. **Move the entity**: In Studio Pro, cut and paste the entity from one domain model to another. Studio Pro will update some references automatically, but not all.

4. **Fix broken references**: Go through the list from step 1 and fix every broken reference. Studio Pro will show errors for anything it could not automatically resolve.

5. **Handle the association foreign keys**: If the entity had associations owned by other entities, the foreign key column names will change. The runtime will create new columns and the old ones will remain with data. You may need a migration step to copy foreign key values.

6. **Test thoroughly**: After moving, test every page and microflow that references the entity. Pay special attention to:
   - Retrieve actions with XPath constraints.
   - Security rules (especially XPath constraints in access rules).
   - Event handlers (before/after commit/delete).
   - Calculated attributes.

7. **Deploy carefully**: The first deployment after an entity move will create new database tables/columns. Plan for data migration in the deployment process.

### Moving Microflows Between Modules

Moving microflows is less risky than moving entities because microflows do not have database-side effects. However, they can still cause problems:

- **Calling microflows by name**: If any external system calls your microflows by their fully qualified name (e.g., through a published web service), the name change will break the call.
- **Scheduled events**: If a scheduled event references the microflow, you need to update the scheduled event.
- **Page references**: Buttons, data views, and other page elements that call the microflow will need updating.
- **Java actions**: If Java code calls the microflow by name (using Core.microflowCall), the Java code needs updating.

Studio Pro handles most internal references automatically when you move a microflow by dragging it to another module. However, always verify by checking for errors after the move.

### Handling Broken References

When refactoring causes broken references, Studio Pro will show them as errors in the Errors pane. Common types:

| Error Type | Cause | Fix |
|------------|-------|-----|
| CE0001: Entity not found | Entity was moved or deleted | Update the reference to point to the new location |
| CE0002: Association not found | Association was moved or deleted | Recreate the association or update references |
| CE0003: Microflow not found | Microflow was moved or deleted | Update the caller to reference the new location |
| CE0080: Enumeration not found | Enumeration was moved or deleted | Update attribute types and expressions |
| CE0568: Module role not found | Module role was deleted or renamed | Update security rules and role mappings |

Strategy for fixing broken references:

1. **Sort errors by module**: Focus on one module at a time.
2. **Fix domain model errors first**: These cascade into microflow and page errors.
3. **Fix microflow errors next**: Fix the logic before fixing the UI.
4. **Fix page errors last**: Pages depend on both domain model and microflows.
5. **Re-run the consistency checker** after fixing all errors to catch any you missed.

### Renaming Strategies

Renaming modules, entities, attributes, and microflows has different implications depending on what you are renaming.

#### Renaming a Module

Renaming a module changes the fully qualified name of everything inside it. The database implications are significant:

- All tables for the module's entities get new names.
- All association columns get new names.
- The runtime creates new tables and columns on the next deployment.
- Old tables and columns remain in the database with their data.

If the module contains persistable entities with data, you need a data migration plan. For non-persistable entities only, renaming is safe.

#### Renaming an Entity

Renaming an entity within the same module changes the database table name. The same migration considerations apply as with moving entities. Studio Pro will update most references automatically, but verify manually.

#### Renaming an Attribute

Renaming an attribute changes the database column name. A new column is created with the new name, and the old column (with data) remains. The runtime does not migrate data between columns automatically.

For production systems with data, the safe approach is:

1. Add a new attribute with the desired name.
2. Create a migration microflow that copies data from the old attribute to the new attribute.
3. Run the migration microflow after deployment (or as a startup microflow).
4. Remove the old attribute once you have confirmed the migration was successful.
5. Clean up the database to drop the orphaned column (optional, but recommended for hygiene).

#### Renaming a Microflow

Renaming a microflow has no database impact and is generally safe. Studio Pro updates internal references automatically. The only risks are:

- External callers that reference the microflow by name (web services, Java code).
- Documentation or runbooks that reference the old name.

### Bulk Refactoring Tips

1. **Work in a branch**: Always do significant refactoring in a dedicated branch. If things go wrong, you can abandon the branch without affecting the main line.
2. **Refactor in small steps**: Move one entity at a time, fix all errors, test, then move the next. Do not try to restructure your entire module hierarchy in one sitting.
3. **Keep a migration log**: Document what was moved, from where to where, and what migration steps are needed. This log is invaluable during deployment.
4. **Coordinate with the team**: If other developers are working in the modules you are refactoring, coordinate to avoid merge conflicts.
5. **Clean up the database after deployment**: After the new structure is deployed and verified, consider removing orphaned tables and columns from the database. This is not strictly necessary (the runtime ignores them) but reduces confusion.

---

## 9. Versioning and Updates

### How Module Versioning Works

App modules do not have independent version numbers. They are versioned together with the project through your version control system (Git or Mendix Team Server, which is SVN or Git). When you commit a revision, the entire project -- including all app modules -- gets a new revision number.

Marketplace modules, however, have their own version numbers. When you download a module from the Marketplace, Studio Pro records the version. When a new version is available, Studio Pro shows an update notification.

### Updating Marketplace Modules

Updating a Marketplace module is a common operation, but it carries risk if you have customized the module. Here is the process:

1. **Check the changelog**: Before updating, read the module's release notes in the Marketplace. Look for breaking changes, new dependencies, and required migration steps.

2. **Back up your current version**: Commit your current project to version control before updating. This gives you a rollback point.

3. **Download the update**: In Studio Pro, go to the Marketplace pane and download the new version. Studio Pro will replace the module's contents.

4. **Fix compilation errors**: The update may introduce errors if the module's API has changed (renamed entities, removed microflows, changed parameter types).

5. **Reconfigure security**: The update may add new module roles or change existing ones. Check the module's security and update the role mappings.

6. **Test thoroughly**: Test all functionality that interacts with the updated module.

### Protecting Customizations

A key challenge with Marketplace modules is that updating them overwrites your changes. There are several strategies to protect your customizations:

#### Strategy 1: Never Modify Marketplace Modules (Recommended)

The safest approach is to treat Marketplace modules as read-only. Instead of modifying a Marketplace module's microflow, create a wrapper microflow in your own module that calls the Marketplace microflow and adds your custom logic.

```
Your Module:
  ACT_SendCustomEmail
    |-- Validate input (your custom logic)
    |-- Call EmailConnector.SendEmail (Marketplace microflow)
    |-- Log the result (your custom logic)
    |-- Create audit record (your custom logic)
```

This way, when the Email Connector module is updated, your wrapper microflow continues to work as long as the Marketplace microflow's signature has not changed.

#### Strategy 2: Fork and Own

If you need to make significant modifications to a Marketplace module, you can "fork" it:

1. Download the module from the Marketplace.
2. Rename it (e.g., `EmailConnector_Custom`).
3. Make your modifications.
4. Never update it from the Marketplace again -- you now own this module.

The downside is that you lose access to bug fixes and improvements from the Marketplace. You are responsible for maintaining the forked module.

#### Strategy 3: Selective Customization with Documentation

If you must modify a Marketplace module and still want to receive updates:

1. Document every change you make to the module in a separate document or in a dedicated microflow called `_Documentation_Customizations`.
2. When updating the module, re-apply your documented changes after the update.
3. Use a diff tool (Mendix Studio Pro has built-in diff for microflows) to verify your changes are correctly reapplied.

This approach is labor-intensive and error-prone. Use it only when Strategy 1 is not feasible.

### Upgrade Strategies for Major Version Changes

Sometimes a Marketplace module releases a major version with breaking changes. Here is a structured approach to handling major upgrades:

1. **Read the migration guide**: Major versions usually come with a migration guide. Read it completely before starting.

2. **Create a branch**: Never upgrade a critical module on the main development line. Create a branch for the upgrade.

3. **Assess the impact**: Before downloading the new version, identify all places in your project that use the module. Use "Find usages" on the module's entities and microflows.

4. **Download and fix**: Download the new version and systematically fix all errors.

5. **Migrate data**: If the module's domain model has changed, you may need migration microflows. Common scenarios:
   - Entity renamed: Data in the old table needs to be copied to the new table.
   - Attribute type changed: Data needs to be converted.
   - Association restructured: Foreign keys need to be updated.

6. **Test in a test environment**: Deploy the upgraded version to a test environment with a copy of production data. Verify all functionality.

7. **Plan the production deployment**: Schedule the deployment, prepare rollback procedures, and ensure migration microflows will run correctly against production data.

### Handling Module Dependencies During Updates

Some Marketplace modules depend on other modules. For example, many modules depend on Community Commons. When updating a module that has dependencies:

1. Check if the dependencies also need updating.
2. Update dependencies first (bottom-up order).
3. Test after each update before proceeding to the next.

The dependency chain can be:
```
Your Module --> EmailConnector (v3.0) --> Encryption (v2.5) --> Community Commons (v8.4)
```

If you update EmailConnector to v4.0 and it requires Encryption v3.0 and Community Commons v9.0, update in this order:
1. Community Commons to v9.0
2. Encryption to v3.0
3. EmailConnector to v4.0

### Version Compatibility Matrix

Maintain a compatibility matrix for your project. This is especially useful for projects with many Marketplace modules:

| Module | Current Version | Min Studio Pro Version | Dependencies | Last Updated |
|--------|----------------|----------------------|--------------|-------------|
| Community Commons | 9.2.0 | 9.24.0 | None | 2025-11-15 |
| Encryption | 3.1.0 | 9.24.0 | Community Commons >= 9.0 | 2025-10-20 |
| SAML | 4.2.0 | 9.24.0 | Encryption >= 3.0 | 2025-12-01 |
| Email Connector | 5.0.0 | 10.0.0 | Community Commons >= 9.0 | 2026-01-10 |
| Deep Link | 6.0.1 | 9.24.0 | Community Commons >= 8.0 | 2025-09-15 |

This matrix helps you plan updates and understand the impact of upgrading one module on others.

---

## 10. Common Patterns

Over years of Mendix development, certain module patterns have proven themselves repeatedly. These patterns are not mandatory, but they solve common problems effectively.

### Utility Module

**Purpose**: Provide reusable, generic helper functionality that does not belong to any specific business domain.

**Typical contents**:

- String manipulation microflows (truncate, pad, format).
- Date utility microflows (business day calculations, date range checks).
- Number formatting microflows (currency formatting, percentage formatting).
- List utility microflows (deduplication, sorting, filtering).
- Validation microflows (email format, phone format, URL format).
- File utility microflows (file size formatting, MIME type detection).

**Design rules**:

1. No business logic. The utility module knows nothing about orders, customers, or invoices.
2. No persistable entities. Utilities should be stateless functions. If they need temporary data structures, use non-persistable entities.
3. No dependencies on other app modules. The utility module should depend only on System and Marketplace modules.
4. Every microflow should be self-documenting. The name should describe what it does: `StringUtils_TruncateWithEllipsis`, `DateUtils_GetNextBusinessDay`.

**Example structure**:

```
UtilityModule
  |-- Domain Model (NPEs only, if any)
  |-- Microflows
  |     |-- StringUtils
  |     |     |-- StringUtils_TruncateWithEllipsis
  |     |     |-- StringUtils_PadLeft
  |     |     |-- StringUtils_RemoveSpecialCharacters
  |     |     |-- StringUtils_ToTitleCase
  |     |-- DateUtils
  |     |     |-- DateUtils_GetNextBusinessDay
  |     |     |-- DateUtils_IsWeekend
  |     |     |-- DateUtils_GetDateRangeOverlap
  |     |-- NumberUtils
  |     |     |-- NumberUtils_FormatCurrency
  |     |     |-- NumberUtils_RoundToDecimalPlaces
  |     |-- ValidationUtils
  |           |-- ValidationUtils_IsValidEmail
  |           |-- ValidationUtils_IsValidPhoneNumber
  |           |-- ValidationUtils_IsValidURL
  |-- Security
        |-- Module Role: User (all authenticated users)
```

Note: If you are using the Community Commons module from the Marketplace, many of these utilities are already available. Check Community Commons before building your own. Only build a custom utility when Community Commons does not have what you need or when you need behavior that differs from what it provides.

### Integration Module

**Purpose**: Encapsulate all communication with a specific external system.

**Why one module per integration**: Each external system has its own data model, authentication, error patterns, and lifecycle. Keeping them separate means you can change one integration without affecting others.

**Typical contents**:

- Consumed service definitions (REST or SOAP).
- Mapping entities (import mappings, export mappings, and the intermediate entities they use).
- Staging entities (temporary storage for data received from or sent to the external system).
- Integration-specific constants (base URL, API key, timeout).
- Integration microflows (call the service, handle the response, map to your domain model).
- Error handling microflows (retry logic, dead letter queue, alerting).
- Scheduled events (for polling-based integrations).

**Design rules**:

1. **Isolate external data models**. Do not let external system entity structures leak into your domain model. Create dedicated entities in the integration module that mirror the external structure, and map between those and your domain entities.
2. **Single point of entry**. Other modules should call the integration module through a small set of well-defined microflows (the module's API). They should never directly access the integration module's staging entities or consumed services.
3. **Handle errors inside the module**. The integration module should handle retries, timeouts, and error logging internally. It should return clean results (or meaningful error information) to the caller.
4. **Log everything**. Integration issues are the number one source of production incidents. Log every call, response, and error with enough detail to diagnose problems without reproducing them.

**Example structure**:

```
Integration_SAP
  |-- Domain Model
  |     |-- SAPOrder (staging entity for incoming order data)
  |     |-- SAPProduct (staging entity for product master data)
  |     |-- SAPSyncLog (entity for tracking sync operations)
  |     |-- SAPError (entity for storing failed operations)
  |-- Consumed REST Services
  |     |-- SAP_OrderService
  |     |-- SAP_ProductService
  |-- Microflows
  |     |-- _API
  |     |     |-- SAP_SyncOrders (called by OrderManagement module)
  |     |     |-- SAP_GetProductPrice (called by ProductCatalog module)
  |     |     |-- SAP_SubmitInvoice (called by Invoicing module)
  |     |-- _Internal
  |     |     |-- _SAP_CallOrderEndpoint
  |     |     |-- _SAP_MapOrderToSAPOrder
  |     |     |-- _SAP_HandleError
  |     |     |-- _SAP_RetryFailedOperations
  |     |-- _Scheduled
  |           |-- SE_SAP_SyncProducts (runs daily)
  |           |-- SE_SAP_RetryFailedOperations (runs hourly)
  |-- Constants
  |     |-- SAP_BaseUrl
  |     |-- SAP_ApiKey
  |     |-- SAP_TimeoutSeconds
  |     |-- SAP_MaxRetries
  |-- Security
        |-- Module Role: IntegrationAdmin (for viewing sync logs)
        |-- Module Role: IntegrationUser (for triggering manual syncs)
```

### Notification Module

**Purpose**: Centralize all notification logic -- email, SMS, push notifications, in-app messages -- in a single module.

**Why centralize notifications**: Notification logic tends to be scattered across feature modules. The order module sends order confirmations. The customer module sends welcome emails. The invoice module sends payment reminders. Centralizing this logic gives you:

- A single place to manage notification templates.
- Consistent formatting and branding across all notifications.
- A unified log of all notifications sent.
- Easy switching of notification providers (e.g., changing email providers).

**Typical contents**:

- Notification template entities (subject, body, channel).
- Notification log entity (who was notified, when, what channel, status).
- Notification queue entity (for asynchronous processing).
- Email sending microflows.
- SMS sending microflows (if applicable).
- Push notification microflows (if applicable).
- Template rendering microflows (merging data into templates).

**Design rules**:

1. **Callers provide data, not logic**. The calling module should pass all necessary data (recipient, subject, body or template variables) to the notification module. The notification module should not reach back into the calling module to fetch additional data.
2. **Asynchronous by default**. Sending notifications should not block the user's action. Use a queue pattern: the calling microflow creates a notification request and returns immediately. A scheduled event picks up queued notifications and sends them.
3. **Template-based**. Use templates with placeholders rather than building notification content in microflows. This makes it easy to update messaging without code changes.
4. **Provide status tracking**. Record whether each notification was sent successfully, failed, or is pending. This is essential for debugging and for customer service inquiries ("Did the customer receive the confirmation email?").

**Example structure**:

```
Notification
  |-- Domain Model
  |     |-- NotificationTemplate
  |     |     |-- Name (String)
  |     |     |-- Channel (Enum: Email, SMS, Push, InApp)
  |     |     |-- SubjectTemplate (String)
  |     |     |-- BodyTemplate (String, unlimited)
  |     |-- NotificationRequest
  |     |     |-- Recipient (String)
  |     |     |-- Subject (String)
  |     |     |-- Body (String, unlimited)
  |     |     |-- Status (Enum: Queued, Sending, Sent, Failed)
  |     |     |-- Channel (Enum: Email, SMS, Push, InApp)
  |     |     |-- SentAt (DateTime)
  |     |     |-- ErrorMessage (String)
  |     |-- NotificationLog (historical record)
  |-- Microflows
  |     |-- _API
  |     |     |-- Notification_SendEmail(To, Subject, Body)
  |     |     |-- Notification_QueueFromTemplate(TemplateName, Recipient, Parameters)
  |     |-- _Internal
  |     |     |-- _ProcessQueue
  |     |     |-- _SendViaEmail
  |     |     |-- _SendViaSMS
  |     |     |-- _RenderTemplate
  |     |-- _Scheduled
  |           |-- SE_ProcessNotificationQueue (every 1 minute)
  |           |-- SE_CleanOldNotifications (daily)
  |-- Pages
  |     |-- Admin
  |           |-- NotificationTemplate_Overview
  |           |-- NotificationLog_Overview
  |-- Security
        |-- Module Role: NotificationAdmin
        |-- Module Role: NotificationUser
```

### Administration and Configuration Module

**Purpose**: Centralize application-wide configuration and administrative functions.

**Typical contents**:

- Application configuration entity (singleton -- only one instance).
- System parameters (feature flags, maintenance mode toggle, global settings).
- Admin dashboard pages.
- User management pages (if not using the standard Administration module).
- System health check microflows.
- Data cleanup and maintenance microflows.
- Audit log viewer pages.

**Design rules**:

1. **Singleton pattern for configuration**. Create a single configuration entity. Use an after-startup microflow to ensure exactly one instance exists. Retrieve it by selecting "First" without XPath constraint.
2. **Admin-only access**. All pages and microflows in this module should be restricted to administrator roles.
3. **Do not put business logic here**. The admin module is for system configuration, not for order processing or customer management. If an admin page shows business data (like "all orders from the last 24 hours"), the data retrieval should live in the OrderManagement module, and the admin module should call that microflow.

**Example singleton pattern**:

```
Entity: AppConfiguration
  |-- MaintenanceMode (Boolean, default: false)
  |-- MaintenanceMessage (String)
  |-- MaxFileUploadSizeMB (Integer, default: 10)
  |-- DefaultLanguage (String, default: "en_US")
  |-- EnableDebugLogging (Boolean, default: false)

After-Startup Microflow: ACT_AppConfiguration_Initialize
  |-- Retrieve first AppConfiguration from database
  |-- If empty:
  |     |-- Create new AppConfiguration with defaults
  |     |-- Commit
  |-- Log "Application configuration loaded"
```

### Error Handling Module

**Purpose**: Provide a consistent approach to error handling and logging across the application.

**Typical contents**:

- Error log entity (stores errors with stack traces, timestamps, and context).
- Error handling microflows (standardized try-catch patterns).
- Error dashboard pages (for monitoring and investigating errors).
- Alert microflows (send notifications when critical errors occur).
- Error cleanup scheduled events.

**Design rules**:

1. **Standardized error logging**. Every module should use the same error logging pattern. The error handling module provides the microflows; feature modules call them.
2. **Context is everything**. When logging an error, include enough context to diagnose it: the microflow name, the input parameters (sanitized of sensitive data), the user, and the timestamp.
3. **Distinguish error severity**. Not every error is critical. Use severity levels (Info, Warning, Error, Critical) and alert only on high-severity errors.

**Example error logging microflow**:

```
ErrorHandling_LogError(ErrorMessage, Severity, SourceModule, SourceMicroflow, AdditionalContext)
  |-- Create ErrorLog entity
  |     |-- ErrorMessage = $ErrorMessage
  |     |-- Severity = $Severity
  |     |-- SourceModule = $SourceModule
  |     |-- SourceMicroflow = $SourceMicroflow
  |     |-- Context = $AdditionalContext
  |     |-- OccurredAt = [%CurrentDateTime%]
  |     |-- UserName = [%CurrentUser/Name%] (or "System" if no user context)
  |-- Commit
  |-- If Severity = Critical:
  |     |-- Call Notification_SendEmail(AdminEmail, "Critical Error", ErrorDetails)
```

### Scheduled Tasks Module

**Purpose**: Centralize the management of background processes and scheduled jobs.

This pattern is useful when your application has many scheduled events across different modules. Instead of scattering scheduled events throughout your modules, you create a central module that coordinates them.

**Typical contents**:

- A `ScheduledTask` entity that tracks execution history.
- Wrapper microflows that call the actual logic in feature modules but add logging and error handling.
- An admin page showing scheduled task status, last run time, and any errors.
- Feature flags to enable/disable individual tasks per environment.

**Design rules**:

1. **The scheduled task module orchestrates; it does not contain business logic**. The actual work should be in the feature module. The scheduled task module wraps it with logging, error handling, and execution tracking.
2. **Idempotent tasks**. Every scheduled task should be safe to run multiple times. If a task is interrupted halfway, running it again should pick up where it left off or start fresh without causing data corruption.
3. **Stagger schedules**. Do not schedule all tasks to run at the same time. Stagger them to spread the load.

### Audit Module

**Purpose**: Track changes to important entities for compliance, debugging, or business analysis.

**Typical contents**:

- Audit trail entity (stores who changed what, when, and what the old and new values were).
- Event handler microflows that run on after-commit and after-delete events.
- Audit log viewer pages.
- Data retention microflows (purging old audit records).

**Implementation approaches**:

1. **Marketplace module**: The Mendix Marketplace has an `Audittrail` module that provides this functionality out of the box. It uses event handlers to automatically track changes to entities you configure.
2. **Custom implementation**: If the Marketplace module does not meet your needs (e.g., you need custom formatting, selective field tracking, or integration with an external audit system), build your own.
3. **System members**: For simple change tracking, enable the `createdDate`, `changedDate`, `owner`, and `changedBy` system members on your entities. This provides basic "who created/changed this and when" without a full audit trail.

### Authentication Module

**Purpose**: Handle user authentication and session management.

For most Mendix applications, authentication is handled by the built-in Mendix authentication or by Marketplace modules like SAML, MendixSSO, or OIDC SSO. However, if you have custom authentication requirements, a dedicated module keeps this logic separate from your business modules.

**Typical contents**:

- Custom login page.
- Authentication microflows (credential validation, token management).
- Session management microflows.
- Password policy configuration.
- Multi-factor authentication logic.
- Integration with external identity providers.

**Design rule**: Authentication logic should never be mixed with business logic. A microflow that processes orders should not contain authentication checks -- those are handled by the security layer and the authentication module.

---

## 11. Naming Conventions

Consistent naming is one of the simplest things you can do to make a Mendix project maintainable. When every developer follows the same conventions, the codebase becomes navigable and predictable.

### Module Names

Module names should be:

- **PascalCase**: `OrderManagement`, not `order_management` or `orderManagement`.
- **Descriptive**: The name should convey the module's purpose without needing further explanation.
- **Concise**: Keep names short enough to be readable but long enough to be clear. `OrderMgmt` is acceptable; `OM` is not.
- **Without spaces**: Spaces in module names cause issues with Java package names and database table names.

**Recommended naming patterns**:

| Pattern | Example | When to Use |
|---------|---------|-------------|
| BusinessDomain | `OrderManagement`, `CustomerPortal` | Feature modules |
| Integration_SystemName | `Integration_SAP`, `Integration_Salesforce` | Integration modules |
| Common or Core | `Common`, `Core`, `Foundation` | Shared utility modules |
| Administration | `Administration`, `AdminPortal` | Admin and configuration modules |
| MarketplaceName (as-is) | `CommunityCommons`, `Encryption` | Marketplace modules (keep their original names) |

**Names to avoid**:

- `Main`, `Default`, `App` -- too generic, will become a dumping ground.
- `Misc`, `Other`, `Temp` -- these names indicate a lack of design.
- `V2`, `New`, `Old` -- version information does not belong in module names.
- Abbreviations that are not universally understood by your team.

### Folder Structure Within Modules

A well-organized folder structure makes it easy to find any artifact in the module. Here is a recommended structure:

```
Module: OrderManagement
  |-- Domain Model
  |-- Microflows
  |     |-- _API (microflows callable from other modules)
  |     |-- ACT (microflows triggered by page actions)
  |     |-- DS (data source microflows for pages)
  |     |-- SUB (sub-microflows -- reusable building blocks)
  |     |-- VAL (validation microflows)
  |     |-- SE (scheduled event microflows)
  |     |-- BCO (before-commit event handlers)
  |     |-- ACO (after-commit event handlers)
  |     |-- BDE (before-delete event handlers)
  |     |-- ADE (after-delete event handlers)
  |-- Nanoflows
  |     |-- ACT (client-side action nanoflows)
  |     |-- DS (data source nanoflows)
  |     |-- VAL (validation nanoflows)
  |     |-- NAV (navigation nanoflows)
  |-- Pages
  |     |-- Overview (list pages)
  |     |-- Detail (detail/edit pages)
  |     |-- Select (selection pop-ups)
  |     |-- Admin (admin-only pages)
  |     |-- Snippets (reusable page fragments)
  |-- Enumerations
  |-- Constants
  |-- Rules
  |-- Scheduled Events
  |-- Published Services
  |-- Consumed Services
```

This structure is a recommendation, not a mandate. Adapt it to your project's needs. The important thing is consistency: whatever structure you choose, apply it uniformly across all modules.

### Microflow Naming

Microflow names should follow a convention that communicates the microflow's purpose and type at a glance.

**Recommended format**: `Prefix_EntityName_ActionDescription`

| Prefix | Meaning | Example |
|--------|---------|---------|
| ACT | Action -- triggered by a page button or menu item | `ACT_Order_Submit` |
| DS | Data Source -- provides data for a page widget | `DS_Order_GetRecentOrders` |
| SUB | Sub-microflow -- called from other microflows, not from pages | `SUB_Order_CalculateTotal` |
| VAL | Validation -- validates data before processing | `VAL_Order_ValidateBeforeSubmit` |
| SE | Scheduled Event -- executed by a scheduled event timer | `SE_Order_ProcessPendingOrders` |
| BCO | Before Commit -- entity event handler | `BCO_Order_SetDefaults` |
| ACO | After Commit -- entity event handler | `ACO_Order_NotifyCustomer` |
| BDE | Before Delete -- entity event handler | `BDE_Order_CheckCanDelete` |
| ADE | After Delete -- entity event handler | `ADE_Order_CleanupRelatedData` |
| IVK | Invoke -- a general-purpose callable microflow (some teams use this as a catch-all) | `IVK_Order_RecalculateShipping` |

**Additional conventions**:

- Use PascalCase for the entity name and action description: `ACT_Order_Submit`, not `ACT_order_submit`.
- For microflows that operate on a list, include "List" in the name: `SUB_OrderLine_CalculateListTotal`.
- For microflows that return a Boolean, start the action with "Is" or "Has": `SUB_Order_IsEditable`, `SUB_Order_HasPendingPayment`.
- For microflows that create objects, use "Create": `SUB_Order_CreateFromTemplate`.
- For microflows that delete objects, use "Delete": `ACT_Order_DeleteDraft`.

### Nanoflow Naming

Nanoflows follow the same convention as microflows but with an `NF_` prefix or within a Nanoflows folder that makes the type clear:

| Prefix | Meaning | Example |
|--------|---------|---------|
| NF_ACT | Client action | `NF_ACT_Order_ValidateAndSubmit` |
| NF_DS | Data source | `NF_DS_Order_FilterByStatus` |
| NF_NAV | Navigation | `NF_NAV_Order_GoToDetail` |
| NF_VAL | Validation | `NF_VAL_Order_CheckRequiredFields` |
| NF_ON | Event handler (on-change, on-enter, etc.) | `NF_ON_OrderStatus_Change` |

Some teams omit the `NF_` prefix and rely on the folder structure to distinguish nanoflows from microflows. Either approach works as long as it is consistent.

### Entity Naming

Entity names should be:

- **PascalCase**: `OrderLine`, not `order_line` or `orderline`.
- **Singular**: `Order`, not `Orders`. The entity represents a single instance; Mendix handles pluralization where needed.
- **Descriptive**: `InvoiceLine`, not `IL`. Abbreviations are acceptable only for universally understood terms within your domain.
- **Without module prefix**: The entity is already scoped to its module. An entity named `Order` in the `OrderManagement` module has the fully qualified name `OrderManagement.Order`. Do not name it `OM_Order`.

**Association naming**: Associations in Mendix are automatically named `ModuleName.Entity1_Entity2`. You can rename them for clarity. Useful when an entity has multiple associations to the same target:

- `Order_Customer` (the customer who placed the order)
- `Order_Customer_Approver` (the customer who approved the order)

### Attribute Naming

Attribute names should be:

- **PascalCase**: `FirstName`, `OrderDate`, `TotalAmount`.
- **Descriptive**: `CustomerEmail`, not `Email` (unless the entity context makes it unambiguous).
- **Without type suffixes for common types**: `OrderDate` (not `OrderDateTime`), `IsActive` (not `IsActiveBool`). The type is visible in the domain model.
- **With unit suffixes where ambiguous**: `WeightKg`, `DistanceKm`, `DurationMinutes`. This prevents confusion about units.

**Boolean attributes**: Start with `Is`, `Has`, `Can`, or `Should`:

- `IsActive`, `IsArchived`, `IsDeleted`
- `HasAttachments`, `HasBeenReviewed`
- `CanEdit`, `CanDelete`
- `ShouldNotify`, `ShouldSync`

**Date attributes**: End with `Date`, `DateTime`, or `At`:

- `CreatedAt`, `ModifiedAt`, `SubmittedAt`
- `OrderDate`, `DeliveryDate`
- `ValidFrom`, `ValidUntil`

### Enumeration Naming

Enumeration names should be:

- **PascalCase**: `OrderStatus`, `PaymentMethod`.
- **Singular**: `Priority`, not `Priorities`.
- **Descriptive of the concept**: `ApprovalState`, not `State` (too generic).

Enumeration values should be:

- **PascalCase or UPPER_CASE**: `InProgress` or `IN_PROGRESS`. Pick one convention and stick with it. PascalCase is more common in Mendix.
- **Stable**: Once deployed to production, do not rename enumeration values. The internal name is stored in the database. Renaming it does not update stored data, leading to orphaned values. Instead, add new values and deprecate old ones.
- **Clear**: `Processing`, not `Status3`. The value name should be understandable without context.

### Constant Naming

Constants should follow the pattern: `ModuleAbbreviation_ConstantName`

- `SAP_BaseUrl`, `SAP_ApiKey`, `SAP_TimeoutSeconds`
- `App_MaintenanceMode`, `App_DefaultLanguage`
- `Email_SmtpHost`, `Email_SmtpPort`, `Email_FromAddress`

This pattern makes it easy to identify which module a constant belongs to when viewing the list of all constants in the runtime configuration.

### Page Naming

Page names should follow the pattern: `EntityName_Action` or `Purpose_Description`

| Pattern | Example | When to Use |
|---------|---------|-------------|
| Entity_Overview | `Order_Overview` | List/grid pages |
| Entity_Detail | `Order_Detail` | Detail view and edit pages |
| Entity_New | `Order_New` | Create pages |
| Entity_Select | `Customer_Select` | Selection pop-up pages |
| Entity_Dashboard | `Order_Dashboard` | Summary/dashboard pages |
| Purpose_Description | `Login_Page`, `Home_Dashboard` | Non-entity-specific pages |

For snippets:
- `Snippet_EntityName_Purpose`: `Snippet_Order_StatusBadge`, `Snippet_Customer_ContactInfo`

### Naming Anti-Patterns

Avoid these common naming mistakes:

| Anti-Pattern | Why It Is Bad | Better Alternative |
|-------------|---------------|-------------------|
| `Microflow_1`, `Microflow_2` | No indication of purpose | `ACT_Order_Submit` |
| `Copy_of_ACT_Order_Submit` | Indicates unfinished refactoring | Delete the copy or give it a proper name |
| `Test_DoNotDelete` | Test code should not be in production | Remove or move to a dedicated test module |
| `ACT_Order_Submit_v2` | Version numbers in names indicate fear of changing the original | Update the original or create a meaningful name for the new version |
| `temp_FixBug123` | Temporary names become permanent | Name it for what it does, not why it was created |
| `MyModule.MyModule_MyEntity` | Redundant module name in entity name | `MyModule.MyEntity` |
| `ACT_HandleButton1Click` | Named after the UI element, not the business action | `ACT_Order_Submit` |

---

## Quick Reference Card

### Module Checklist

Use this checklist when creating or reviewing a module:

- [ ] Module has a clear, descriptive PascalCase name
- [ ] Module has a single, well-defined responsibility
- [ ] Domain model contains only entities relevant to the module's responsibility
- [ ] Module roles are defined and mapped to project user roles
- [ ] Entity access rules follow deny-by-default strategy
- [ ] Microflow access and page access are configured for all module roles
- [ ] Folder structure is consistent with project conventions
- [ ] Microflow naming follows the agreed-upon prefix convention
- [ ] No circular dependencies with other modules
- [ ] Cross-module references are minimized and go through defined API microflows
- [ ] Constants have meaningful defaults and descriptions
- [ ] Scheduled events are documented and have reasonable intervals
- [ ] After-startup microflow (if any) is idempotent and fast
- [ ] Security is tested -- verified that each role can only access what it should

### Module Type Decision Matrix

| Question | If Yes | If No |
|----------|--------|-------|
| Am I building new business functionality? | App module | Continue below |
| Does a Marketplace module provide what I need? | Marketplace module | Continue below |
| Am I distributing this for others to use? | Add-on or solution module | App module |
| Do I need to protect my implementation? | Add-on module | App module |

### Dependency Direction Rules

```
System / Marketplace Modules (Layer 0)
         ^
         |  depends on
Core / Shared Module (Layer 1)
         ^
         |  depends on
Feature Modules (Layer 2)
         ^
         |  depends on
Integration Modules (Layer 3)
         ^
         |  depends on
UI / Portal Modules (Layer 4)
```

Dependencies flow upward: higher layers depend on lower layers, never the reverse. Modules within the same layer should not depend on each other.

---

## Further Reading

- [Mendix Documentation: Modules](https://docs.mendix.com/refguide/modules/)
- [Mendix Documentation: Module Security](https://docs.mendix.com/refguide/module-security/)
- [Mendix Documentation: Module Settings](https://docs.mendix.com/refguide/module-settings/)
- [Mendix Documentation: Published REST Services](https://docs.mendix.com/refguide/published-rest-services/)
- [Mendix Documentation: Consumed REST Services](https://docs.mendix.com/refguide/consumed-rest-services/)
- [Mendix Documentation: Domain Model](https://docs.mendix.com/refguide/domain-model/)
- [Mendix Marketplace](https://marketplace.mendix.com/)
- [Mendix Best Practices: Architecture](https://docs.mendix.com/refguide/dev-best-practices/)
