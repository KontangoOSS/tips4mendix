[Home](../README.md) > **Entities & Domain Modeling**

---

# Mendix Entities and Domain Modeling Guide

## A Practical Reference for Mendix Developers

**Version:** 1.0
**Date:** February 2026
**Classification:** Public

---

## Table of Contents

1. [What Is an Entity](#1-what-is-an-entity)
2. [Attributes](#2-attributes)
3. [Associations](#3-associations)
4. [Generalization (Inheritance)](#4-generalization-inheritance)
5. [Non-Persistable Entities](#5-non-persistable-entities)
6. [Indexes](#6-indexes)
7. [Access Rules](#7-access-rules)
8. [Validation Rules](#8-validation-rules)
9. [Event Handlers](#9-event-handlers)
10. [Domain Model Patterns](#10-domain-model-patterns)
11. [Data Migration](#11-data-migration)
12. [Performance Considerations](#12-performance-considerations)
13. [Naming Conventions](#13-naming-conventions)

---

## 1. What Is an Entity

### Overview

An entity is the fundamental building block of any Mendix application's data layer. It represents a real-world concept -- a customer, an order, an invoice, a device -- and defines the structure that instances of that concept will follow. If you have built applications with relational databases, think of an entity as the Mendix equivalent of a database table definition. Each entity describes a set of attributes (columns), associations (foreign keys or join tables), and rules that govern how data is created, read, updated, and deleted.

When you model your domain in Mendix Studio Pro, every rectangle you drag onto the domain model canvas creates an entity. Each row of data stored against that entity is called an **object** -- one entity, many objects.

### How Entities Map to Database Tables

Mendix uses a relational database under the hood (PostgreSQL on the Mendix Cloud, though SQL Server, Oracle, and others are supported for on-premises deployments). When you deploy your application, the runtime translates your domain model into physical database structures:

| Domain Model Concept | Database Equivalent |
|---|---|
| Entity | Table |
| Attribute | Column |
| Object | Row |
| Association (one-to-many) | Foreign key column on the child table |
| Association (many-to-many) | Junction/join table |
| Generalization | Single-table or joined-table inheritance (see Section 4) |
| AutoNumber attribute | Sequence-backed integer column |

The Mendix runtime manages all DDL (CREATE TABLE, ALTER TABLE) operations automatically during deployment. You never write SQL to change the schema. When you add an attribute, rename an entity, or change an association, the runtime generates the appropriate migration statements and applies them at startup.

### Persistable Entities

A **persistable entity** is one whose objects are stored in the database. This is the default when you create a new entity. Persistable entities:

- Survive application restarts. Data written to them persists across deployments, crashes, and server reboots.
- Are queryable via XPath and OQL. You can retrieve objects from the database using XPath expressions in microflows, nanoflows (indirectly), pages, and data grids.
- Participate in transactions. Commit and rollback semantics apply. An object only reaches the database when it is explicitly committed (or auto-committed at the end of a successful microflow).
- Consume database storage. Every committed object occupies space in the underlying RDBMS.
- Can have indexes, access rules, validation rules, and event handlers.

When to use persistable entities:

- The data must survive beyond a single user session.
- Multiple users need to read or write the same data.
- You need to query, sort, filter, or aggregate the data at the database level.
- Audit, compliance, or regulatory requirements demand durable storage.

### Non-Persistable Entities

A **non-persistable entity** (NPE) exists only in memory. It is never written to the database. Non-persistable entities are covered in depth in [Section 5](#5-non-persistable-entities), but the key distinctions are:

- Objects live in the runtime's memory for the duration of a user session or microflow execution.
- They cannot be retrieved via XPath from the database (because they are not in the database).
- They are garbage-collected when no longer referenced.
- They are ideal for transient data: search forms, view models, API request/response wrappers, and intermediate calculation results.

### System Entities

Mendix provides several built-in entities in the **System** module that every application inherits:

| Entity | Purpose |
|---|---|
| `System.User` | Base entity for all user accounts. Your `Administration.Account` entity generalizes from this. |
| `System.Session` | Represents an active user session. |
| `System.FileDocument` | Base entity for file storage. Any entity that needs to store binary files should generalize from this. |
| `System.Image` | Specialization of `System.FileDocument` for image files with thumbnail support. |
| `System.Language` | Represents a language/locale available in the application. |
| `System.TimeZone` | Represents a time zone. |
| `System.ScheduledEventInformation` | Metadata about scheduled events. |

You cannot modify or delete system entities, but you can (and should) create specializations of `System.FileDocument` and `System.Image` whenever you need file or image storage. Never use `System.FileDocument` directly -- always create a specialized entity so you can add your own attributes, associations, and access rules.

### Entity Properties Summary

When you double-click an entity in Studio Pro, you see these key properties:

| Property | Description | Default |
|---|---|---|
| Name | The entity name. Must be unique within the module. | -- |
| Persistable | Whether objects are stored in the database. | Yes |
| Generalization | The parent entity this entity inherits from (if any). | None |
| Documentation | Free-text description of the entity's purpose. | Empty |
| Image | An icon displayed on the domain model canvas. | Default entity icon |
| Stored in | The database table name (auto-generated, can be overridden). | Module name + entity name |

---

## 2. Attributes

### Overview

Attributes define the individual data fields of an entity. Every attribute has a name, a type, and optional configuration for default values, validation, and storage. Attributes map directly to columns in the underlying database table.

### Data Types

Mendix supports the following attribute types:

| Type | Description | Database Type (PostgreSQL) | Range / Limits |
|---|---|---|---|
| **String** | Variable-length text. You set the maximum length (default: 200 characters). | `varchar(n)` or `text` | 1 to unlimited characters. Strings over 8,192 characters are stored as `text`. |
| **Integer** | 32-bit signed whole number. | `integer` | -2,147,483,648 to 2,147,483,647 |
| **Long** | 64-bit signed whole number. | `bigint` | -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807 |
| **Decimal** | Arbitrary-precision decimal number. Use for financial or scientific data. | `numeric` | Up to 20 digits of precision by default. Configurable. |
| **Boolean** | True or false. | `boolean` | `true` or `false` |
| **DateTime** | Date and time with timezone awareness. | `timestamp with time zone` | Stored in UTC internally. Displayed in the user's timezone. |
| **Enumeration** | A fixed set of named values defined elsewhere in the model. | `integer` (stores the ordinal index) | Limited to the values defined in the enumeration. |
| **AutoNumber** | Auto-incrementing integer assigned on first commit. | `bigint` with a sequence | Starts at 1 by default. Never reuses values. |
| **Binary** | Raw binary data (files, images). Only available on entities that generalize from `System.FileDocument`. | Stored in external blob storage, not inline. | Limited by storage backend configuration. |

### Choosing Between Integer, Long, and Decimal

This is a common source of confusion. Here is a practical decision table:

| Scenario | Recommended Type | Why |
|---|---|---|
| Counting items (quantity, stock level) | Integer | Values comfortably fit in 32 bits. Efficient storage and comparison. |
| Database IDs from external systems | Long | External systems often use 64-bit identifiers. |
| Currency / financial amounts | Decimal | Floating-point rounding errors are unacceptable for money. Decimal gives exact arithmetic. |
| Percentages | Decimal | Avoids rounding issues when multiplying (e.g., tax rate * amount). |
| Timestamps as epoch milliseconds | Long | Epoch millis exceed the 32-bit integer range. |
| Simple flags or counters under 2 billion | Integer | Smaller storage footprint. |

### String Length Considerations

When you create a String attribute, you specify a maximum length. Consider:

- **Short strings (1-200)**: Names, codes, identifiers. The default length of 200 is fine for most cases.
- **Medium strings (200-8,192)**: Descriptions, addresses, short notes. These are still stored as `varchar` and are indexed efficiently.
- **Long strings (over 8,192)**: Rich text content, JSON payloads, log entries. These are stored as `text` in PostgreSQL. Avoid indexing these columns -- full-text search or dedicated search modules (e.g., the Mendix Search module backed by Elasticsearch) are better approaches.
- **Unlimited**: Setting the length to "unlimited" removes the cap entirely. Use sparingly. You lose the ability to put a database-level constraint on column width, and XPath `contains()` queries on very long text are expensive.

### Default Values

Every attribute type supports a default value. Defaults are applied when a new object is created (before commit):

| Type | Default Value Options | Example |
|---|---|---|
| String | Any literal string, or empty. | `"Draft"` |
| Integer | Any integer literal. | `0` |
| Long | Any long literal. | `0` |
| Decimal | Any decimal literal. | `0.00` |
| Boolean | `true` or `false`. | `false` |
| DateTime | `[%CurrentDateTime%]` token or empty. The token resolves at object creation time. | `[%CurrentDateTime%]` |
| Enumeration | Any value from the enumeration, or empty. | `Status.Draft` |
| AutoNumber | Not user-configurable. The runtime assigns the next sequence value on first commit. | -- |

Best practices for defaults:

- Always set a default for Boolean attributes. A `null` Boolean creates three-state logic (true/false/null) that complicates page expressions and microflow decisions.
- Use `[%CurrentDateTime%]` for "created date" attributes so they are automatically populated.
- For Enumeration attributes that represent a workflow state, set the default to the initial state (e.g., `Draft` or `New`).
- Do not rely on defaults for critical business logic. Defaults are a convenience -- use validation rules and microflows to enforce required values.

### Calculated Attributes

Mendix supports **calculated attributes** whose values are derived from a microflow rather than stored in the database. Key characteristics:

- The value is computed every time the attribute is read.
- It is not stored in a database column.
- You cannot sort, filter, or search by a calculated attribute in a data grid or XPath expression (because there is no database column to query).
- Use calculated attributes for display-only values like "Full Name" (concatenation of first and last name) or "Age" (derived from birth date).
- If you need to filter or sort by the value, store it as a regular attribute and update it via event handlers or microflows.

### Attribute Properties Reference

| Property | Description |
|---|---|
| Name | Unique within the entity. Follow naming conventions (see Section 13). |
| Type | One of the types in the table above. |
| Default value | Value assigned to new objects. |
| Length | For String attributes only. Maximum character count. |
| Enumeration | For Enumeration attributes only. The enumeration definition to use. |

---

## 3. Associations

### Overview

Associations define relationships between entities. They are the Mendix equivalent of foreign keys and join tables in a relational database. Understanding association types, ownership, and delete behavior is critical to building a correct and performant domain model.

### Association Types

Mendix supports three relationship cardinalities through two association mechanisms:

| Cardinality | Mendix Mechanism | Database Implementation | Example |
|---|---|---|---|
| One-to-one | Reference (1-1) | Foreign key column on the owner's table with a unique constraint. | `Employee` -- `ParkingSpot` (each employee has at most one assigned spot) |
| One-to-many | Reference (1-*) or (*-1) | Foreign key column on the "many" side's table. | `Customer` -- `Order` (one customer has many orders) |
| Many-to-many | Reference set (*-*) | Junction table with two foreign key columns. | `Student` -- `Course` (students enroll in many courses; courses have many students) |

### Reference vs. Reference Set

The distinction is straightforward:

- A **reference** (single association) means "this object points to exactly one (or zero) other object." In the UI, this is a drop-down selector, reference selector, or input reference set selector showing a single value.
- A **reference set** means "this object points to zero or more other objects." In the UI, this is typically a list, checkbox group, or reference set selector.

When you draw an association line between two entities in Studio Pro, the default is a reference (one-to-many). You change it to a reference set by setting the type to "Reference set" in the association properties.

### Association Ownership

Ownership determines which entity "holds" the foreign key. This matters for both database structure and behavior:

| Ownership | Meaning | Database Effect |
|---|---|---|
| **Default** (child owns) | The entity on the "many" side (or the entity you draw from) stores the foreign key. | FK column added to the owner's table. |
| **Both** | Both entities store references to each other. Only applicable to reference sets. | A junction table is created. Both sides can navigate the association. |
| **One side only** | Only the designated owner stores the reference. | FK column or junction table on the owner's side only. |

Practical implications of ownership:

- **Retrieving associated objects**: You can always navigate from owner to owned. Navigating from the non-owner side requires a database query (retrieve by association over the owner's table).
- **Changing the association**: Only the owner can change the reference. If `Order` owns the association to `Customer`, you set `$Order/Order_Customer` to a `Customer` object. You cannot set it from the `Customer` side directly -- you would need to retrieve the `Order` and modify it.
- **Performance**: Navigating from the non-owner side is more expensive because the runtime must query the owner's table. If you frequently need to find all orders for a customer, the `Order` should own the association to `Customer` -- and it does by default in a one-to-many relationship.

### Defining Associations Step by Step

1. Open the domain model in Studio Pro.
2. Select the association tool from the toolbar (the line with a diamond).
3. Click on the first entity (the owner) and drag to the second entity.
4. Double-click the association line to configure:
   - **Name**: Follow the naming convention `EntityA_EntityB` (see Section 13).
   - **Type**: Reference or Reference set.
   - **Owner**: Default, or specify explicitly.
   - **Delete behavior**: What happens to associated objects on delete (see below).
   - **Navigability**: Both directions or one direction only.

### Delete Behavior

Delete behavior controls what happens to associated objects when the owner object is deleted. This is one of the most important configuration decisions you will make:

| Delete Behavior | Effect | When to Use |
|---|---|---|
| **Delete {associated entity} objects** | When the owner is deleted, all associated objects are also deleted. Cascading delete. | Parent-child relationships where children have no meaning without the parent. Example: deleting an `Order` also deletes its `OrderLine` objects. |
| **Keep {associated entity} objects** | When the owner is deleted, associated objects remain but the association is cleared (set to null). | When the associated objects are independent entities that should survive. Example: deleting a `Department` should not delete the `Employee` objects -- they should become unassigned. |
| **Prevent delete of {owner entity} if {associated entity} objects exist** | The owner cannot be deleted if any associated objects exist. The delete operation throws an error. | Referential integrity enforcement. Example: a `Customer` cannot be deleted if they have `Order` objects. The orders must be handled first. |

Delete behavior configuration per association type:

| Association Type | Available Delete Behaviors |
|---|---|
| Reference (1-1, 1-*) | Delete, Keep, Prevent |
| Reference set (*-*) | Keep only. Mendix does not support cascading delete on reference sets -- you must handle cleanup manually in a microflow. |

Common delete behavior mistakes:

- **Cascading deletes on the wrong side**: Setting "Delete Order objects" on the `Customer` side means deleting a customer wipes out their order history. This is rarely what you want. Usually you want "Prevent" here.
- **Not considering orphaned objects**: Using "Keep" means associated objects lose their parent reference. If your application logic assumes every `OrderLine` has an `Order`, you will get null reference errors. Add validation or cleanup logic.
- **Forgetting reference sets**: Reference sets only support "Keep." If you need cascading behavior, write a before-delete event handler that manually deletes the associated objects.

### Association Navigation in Microflows

Associations are navigated using the "Retrieve" activity or XPath expressions:

**Retrieve by association (from owner to associated):**
```
// In a microflow, given $Order:
// Retrieve the Customer for this Order
$Order/Order_Customer
```

**Retrieve over association (from non-owner to owner):**
```
// In a microflow, given $Customer:
// Retrieve all Orders for this Customer
[Module.Order_Customer = $Customer]
```

**XPath constraint using association:**
```
// Find all Orders for a specific Customer
//Module.Order[Module.Order_Customer/Module.Customer/Name = 'Acme Corp']
```

### Cross-Module Associations

You can create associations between entities in different modules. Considerations:

- The association is defined in one module but references an entity in another.
- Both modules must be part of the same project.
- Access rules on both entities apply when the association is navigated.
- Circular dependencies between modules (Module A references Module B, Module B references Module A) are allowed but should be avoided because they make modules harder to maintain and reuse independently.
- If you need to reference a Marketplace module's entity, create the association from your module's entity to the Marketplace entity. Never modify Marketplace module entities directly.

---

## 4. Generalization (Inheritance)

### Overview

Generalization is Mendix's implementation of entity inheritance. A **generalization** entity (parent) defines shared attributes and associations. **Specialization** entities (children) inherit everything from the parent and add their own attributes, associations, and rules.

This maps to the object-oriented concept of inheritance: a `Dog` is a specialization of `Animal`. Every `Dog` has all the attributes of `Animal` (name, weight) plus its own attributes (breed, barkVolume).

### How It Works

When you set the generalization of entity B to entity A:

- Entity B inherits all attributes of entity A.
- Entity B inherits all associations of entity A.
- Entity B inherits all access rules of entity A (but can override them).
- Entity B inherits all validation rules of entity A.
- Entity B inherits all event handlers of entity A.
- Objects of entity B can be used anywhere entity A is expected (polymorphism).

### Database Mapping

Mendix uses **single-table inheritance** for generalization hierarchies. All entities in the hierarchy share a single database table:

| Concept | Database Implementation |
|---|---|
| Parent entity `Vehicle` | Table `module$vehicle` with columns for `Vehicle` attributes |
| Child entity `Car` (specialization of `Vehicle`) | Same table `module$vehicle`, with additional columns for `Car`-specific attributes. A discriminator column identifies the entity type. |
| Child entity `Truck` (specialization of `Vehicle`) | Same table `module$vehicle`, with additional columns for `Truck`-specific attributes. |

This means:

- All specializations share one table. The table has columns for every attribute across the entire hierarchy.
- Rows for `Car` objects will have null values in `Truck`-specific columns (and vice versa).
- A discriminator column (`submetaobjectname` internally) stores the actual entity type.
- Queries on the parent entity return objects of all specialization types.

### When to Use Generalization

**Good use cases:**

| Scenario | Parent Entity | Specializations |
|---|---|---|
| Different types of users | `System.User` | `Employee`, `ExternalContractor`, `Customer` |
| Different document types | `System.FileDocument` | `Invoice`, `Receipt`, `Contract` |
| Different product types | `Product` | `PhysicalProduct`, `DigitalProduct`, `Subscription` |
| Polymorphic relationships | `Notification` | `EmailNotification`, `SMSNotification`, `PushNotification` |

**When not to use generalization:**

- When the entities share only a few attributes. Use associations instead.
- When the specializations have vastly different attribute sets. Single-table inheritance creates very wide tables with many null columns.
- When you have more than 3-4 levels of inheritance depth. Deep hierarchies are hard to reason about and debug.
- When performance is critical and you query the parent frequently. The database must scan a single large table that contains rows for all specializations.

### Querying Across Generalizations

When you retrieve objects of a parent entity, the result includes objects of all specialization types:

```
// Retrieves all Vehicles -- including Cars, Trucks, and Motorcycles
//Module.Vehicle[Year > 2020]
```

You can filter to a specific specialization:

```
// Retrieves only Car objects
//Module.Car[Year > 2020]
```

In microflows, you can use the "Cast object" activity to safely convert a parent reference to a specific specialization:

1. Retrieve a `Vehicle` object.
2. Use an "Inheritance split" activity to branch based on the actual type (Car, Truck, etc.).
3. In each branch, use "Cast object" to convert the `Vehicle` to the specific type.
4. Access specialization-specific attributes on the cast object.

### Generalization and Access Rules

Access rules are inherited but can be overridden:

- If `Vehicle` grants read access to the `Year` attribute for the `User` role, then `Car` objects also grant that access.
- A specialization can add additional rules but cannot remove inherited ones.
- If you need different access patterns for different specializations, define rules at the specialization level and keep the parent rules minimal.

### Generalization Depth and System Entities

The `System` module provides key entities for generalization:

- **`System.FileDocument`**: The base for all file storage. Provides `Name`, `Size`, `Contents` (binary), and file management infrastructure. Always generalize from this for file-related entities.
- **`System.Image`**: A specialization of `System.FileDocument` with thumbnail generation. Use for image-specific entities.
- **`System.User`**: The base for all user account entities. The `Administration.Account` entity generalizes from this.

Best practice: keep your generalization hierarchies shallow. One or two levels deep is ideal. Three levels is acceptable. Beyond that, reconsider your design.

### Example: Document Management Hierarchy

```
System.FileDocument
  |
  +-- Document (adds: DocumentType, Version, Status, UploadedBy)
        |
        +-- Invoice (adds: InvoiceNumber, Amount, DueDate)
        +-- Contract (adds: ContractNumber, StartDate, EndDate, SignedBy)
        +-- Report (adds: ReportPeriod, GeneratedBy)
```

Each specialization inherits `Name`, `Size`, and `Contents` from `System.FileDocument`, plus `DocumentType`, `Version`, `Status`, and `UploadedBy` from `Document`. The specializations add their own domain-specific attributes.

---

## 5. Non-Persistable Entities

### Overview

Non-persistable entities (NPEs) are entities whose objects exist only in the application server's memory. They are never written to the database. When you set an entity's "Persistable" property to "No," it becomes non-persistable.

NPEs are one of the most underutilized features in Mendix. Many developers default to persistable entities for everything, which leads to unnecessary database tables, orphaned records, and cleanup complexity. Understanding when and how to use NPEs will make your applications cleaner and faster.

### Key Characteristics

| Characteristic | Persistable Entity | Non-Persistable Entity |
|---|---|---|
| Stored in database | Yes | No |
| Survives app restart | Yes | No |
| Retrievable via XPath | Yes | No (must be passed by reference) |
| Queryable in data grids | Yes | Only if the data source is a microflow/nanoflow |
| Supports indexes | Yes | No |
| Supports access rules | Yes | Yes (but only attribute-level; XPath constraints are not applicable) |
| Supports event handlers | Yes | No |
| Supports validation rules | Yes | Yes |
| Can associate with persistable entities | Yes | Yes (with caveats) |
| Memory footprint | Minimal (data in DB) | Objects consume runtime memory |

### Use Cases

**1. Search / Filter Forms**

The most common use case. Create a non-persistable `SearchCriteria` entity with attributes matching the fields the user can search by. Pass it to a page, let the user fill in the fields, then use the values in a microflow to construct an XPath query or OQL statement against the actual persistable entities.

```
NPE: OrderSearchCriteria
  - CustomerName : String
  - MinAmount : Decimal
  - MaxAmount : Decimal
  - Status : Enumeration (OrderStatus)
  - DateFrom : DateTime
  - DateTo : DateTime
```

Why not use a persistable entity? Because search criteria are transient. You do not need to store them in the database. Using a persistable entity means you must clean up old search criteria objects, or the table grows indefinitely.

**2. View Models / DTOs**

When a page needs to display data from multiple entities combined, or data that does not map 1:1 to your domain model, create a non-persistable "view model" entity:

```
NPE: DashboardSummary
  - TotalOrders : Integer
  - TotalRevenue : Decimal
  - PendingApprovals : Integer
  - OverdueInvoices : Integer
  - TopCustomerName : String
```

A microflow populates this NPE by querying multiple persistable entities and assembling the results.

**3. API Request / Response Wrappers**

When integrating with external REST APIs, NPEs are the natural choice for modeling request and response structures:

```
NPE: WeatherAPIResponse
  - Temperature : Decimal
  - Humidity : Integer
  - Description : String
  - WindSpeed : Decimal
  - City : String
```

The import mapping maps the JSON/XML response to this NPE. Your microflow processes the data and either displays it or stores relevant parts in persistable entities.

**4. Wizard / Multi-Step Form State**

When building a multi-step wizard, store the in-progress data in an NPE until the user completes all steps. Only commit to persistable entities at the final step:

```
NPE: RegistrationWizard
  - Step : Integer (default: 1)
  - FirstName : String
  - LastName : String
  - Email : String
  - CompanyName : String
  - Plan : Enumeration (SubscriptionPlan)
  - AcceptedTerms : Boolean
```

This avoids creating incomplete records in the database when users abandon the wizard partway through.

**5. Intermediate Calculation Results**

When a microflow performs complex calculations (e.g., pricing, scoring, risk assessment), use NPEs to hold intermediate results:

```
NPE: PricingCalculation
  - BasePrice : Decimal
  - DiscountPercentage : Decimal
  - DiscountAmount : Decimal
  - TaxRate : Decimal
  - TaxAmount : Decimal
  - ShippingCost : Decimal
  - TotalPrice : Decimal
```

### Lifecycle and Garbage Collection

Non-persistable objects are managed by the Mendix runtime's memory system:

1. **Creation**: An NPE object is created in memory when a "Create object" activity executes.
2. **Scope**: The object is available within the microflow that created it, and in any microflow or page that receives it as a parameter.
3. **Client state**: When an NPE object is sent to a page (as a page parameter or data source), the Mendix Client holds a reference to it. The object remains alive as long as the page is open.
4. **Garbage collection**: When no microflow variable, page widget, or client state references the NPE object, it becomes eligible for garbage collection. The Mendix runtime periodically cleans up unreferenced NPE objects.
5. **Session end**: All NPE objects associated with a user session are cleaned up when the session ends (user logs out or session times out).

Memory considerations:

- NPE objects consume runtime (JVM) memory. If you create thousands of NPE objects in a loop, you can cause memory pressure or out-of-memory errors.
- Always limit the number of NPE objects in memory. If you need to process large datasets, use persistable entities or process in batches.
- Do not store large binary data in NPE attributes. Use persistable `FileDocument` specializations instead.

### Associations Between Persistable and Non-Persistable Entities

You can associate NPEs with persistable entities, but there are rules:

| Association Direction | Allowed? | Notes |
|---|---|---|
| NPE to Persistable | Yes | The NPE holds a reference to a committed persistable object. Common for search forms that reference a specific customer or category. |
| Persistable to NPE | No | A persistable entity cannot have a foreign key to something that does not exist in the database. The runtime prevents this. |
| NPE to NPE | Yes | Both entities are in memory. This is fine and common for complex view models. |

### Best Practices for Non-Persistable Entities

1. **Default to NPE for transient data.** If the data does not need to survive a page close or session end, make it non-persistable.
2. **Use a dedicated module.** Group NPEs in a module like `ViewModels` or `TransientData` to keep your domain model clean.
3. **Document the lifecycle.** Add documentation to each NPE explaining what creates it, what pages use it, and when it is discarded.
4. **Watch memory usage.** In production, monitor JVM heap usage. If NPE creation is unbounded (e.g., in a scheduled event or loop), you have a memory leak.
5. **Do not overuse NPEs for data that should be persistent.** If users expect to see their data after logging out and back in, it must be persistable.

---

## 6. Indexes

### Overview

Indexes are database structures that speed up data retrieval at the cost of additional storage and slower write operations. In Mendix, you create indexes on entity attributes to improve the performance of XPath queries, data grid sorts, and association lookups.

Without indexes, the database must perform a full table scan -- reading every row -- to find matching objects. With an appropriate index, the database can jump directly to the relevant rows.

### When to Create Indexes

Create an index when:

| Scenario | Example | Index On |
|---|---|---|
| A data grid frequently filters by an attribute | Order list filtered by Status | `Order.Status` |
| A microflow retrieves objects with an XPath constraint | `//Order[Status = 'Open' and CreatedDate > $CutoffDate]` | `Order.Status` + `Order.CreatedDate` (compound) |
| A data grid is sorted by an attribute by default | Customer list sorted by LastName | `Customer.LastName` |
| A unique constraint must be enforced | Employee badge number must be unique | `Employee.BadgeNumber` (unique index) |
| Large tables are queried with range conditions | Logs filtered by timestamp range | `AuditLog.Timestamp` |
| An attribute is used in association-like lookups | External system ID used for matching | `Order.ExternalOrderId` |

Do not create indexes when:

- The table has very few rows (under a few thousand). The overhead of maintaining the index exceeds the benefit.
- The attribute has very low cardinality (e.g., a Boolean column with only `true`/`false` values on a large table). The index does not help the database narrow down results significantly.
- The attribute is rarely used in queries or sorts.
- Write performance is critical and reads are infrequent. Every insert, update, and delete on an indexed column must also update the index.

### Creating Indexes in Studio Pro

1. Open the entity's properties.
2. Go to the "Indexes" tab.
3. Click "New" to create an index.
4. Add one or more attributes to the index.
5. Optionally set the index to unique (if you need to enforce uniqueness).

### Single-Attribute Indexes

A single-attribute index covers queries that filter or sort by one attribute:

```
Entity: Customer
Index: idx_Customer_Email
  - Email (ascending)
```

This index speeds up:
- `//Customer[Email = 'john@example.com']`
- Data grids sorted by Email

### Compound (Multi-Attribute) Indexes

A compound index covers queries that filter or sort by multiple attributes. The order of attributes in the index matters:

```
Entity: Order
Index: idx_Order_Status_CreatedDate
  - Status (ascending)
  - CreatedDate (descending)
```

This index speeds up:
- `//Order[Status = 'Open']` (uses the first column of the index)
- `//Order[Status = 'Open' and CreatedDate > $CutoffDate]` (uses both columns)
- `//Order[Status = 'Open']` sorted by CreatedDate descending

This index does **not** help:
- `//Order[CreatedDate > $CutoffDate]` without a Status filter (the first column of the index is not used, so the database cannot efficiently traverse the index)

The "leftmost prefix" rule: a compound index can be used for queries that filter on the first N columns of the index (from left to right), but not for queries that skip the first column.

### Compound Index Column Order Guidelines

| Query Pattern | Optimal Index Column Order |
|---|---|
| Equality on A, then range on B | A first, B second |
| Equality on A, sort by B | A first, B second |
| Equality on A, equality on B | Either order works (put the more selective one first for marginal benefit) |
| Range on A, equality on B | B first, A second (equality filters narrow results more than range filters) |

### Unique Constraints

Setting an index to "Unique" enforces that no two objects can have the same value(s) for the indexed attribute(s):

```
Entity: Employee
Unique Index: idx_Employee_BadgeNumber
  - BadgeNumber
```

If a microflow tries to commit an `Employee` with a `BadgeNumber` that already exists, the commit fails with a database constraint violation. Handle this gracefully with error handling in your microflows.

Compound unique indexes enforce uniqueness across the combination:

```
Entity: Enrollment
Unique Index: idx_Enrollment_Student_Course
  - Student (association)
  - Course (association)
```

This prevents a student from enrolling in the same course twice.

### Indexes and Associations

Mendix automatically creates indexes on foreign key columns (association columns). You do not need to manually index associations. However, if you frequently query by a combination of an association and an attribute, a compound index can help:

```
Entity: OrderLine
Index: idx_OrderLine_Order_Product
  - Order_OrderLine (association - auto-indexed)
  - Product (attribute - add to compound index if queried together)
```

### Index Impact on Performance

| Operation | Effect of Adding an Index |
|---|---|
| SELECT (read) with matching filter | Faster. Can be orders of magnitude faster on large tables. |
| INSERT (create + commit) | Slightly slower. The database must update the index. |
| UPDATE (change + commit) on indexed column | Slightly slower. The old index entry is removed and a new one is added. |
| DELETE | Slightly slower. The index entry must be removed. |
| Storage | Increased. Each index consumes disk space proportional to the number of rows and the size of the indexed columns. |

Rule of thumb: the read performance gain almost always outweighs the write performance cost, unless your application is write-heavy with very few reads on the indexed columns.

### Monitoring Index Usage

In production environments:

- Use the Mendix Application Performance Monitor (APM) or database monitoring tools to identify slow queries.
- Check the PostgreSQL `pg_stat_user_indexes` view to see which indexes are actually being used.
- Remove unused indexes to reclaim storage and reduce write overhead.
- Use `EXPLAIN ANALYZE` on slow queries (via direct database access, if permitted) to see whether indexes are being used.

---

## 7. Access Rules

### Overview

Access rules are Mendix's built-in mechanism for row-level and attribute-level security. They define which user roles can create, read, update, and delete objects of an entity, and under what conditions. Access rules are evaluated at the database level (via XPath constraints appended to queries) and at the runtime level (via attribute-level checks).

Access rules are not optional. In production, Mendix enforces security strictly. If an entity has no access rules for a given role, that role cannot interact with the entity at all.

### How Access Rules Work

When a user with role `Manager` tries to retrieve `Order` objects, the Mendix runtime:

1. Checks if there is an access rule for `Manager` on the `Order` entity.
2. If no rule exists, the retrieval returns nothing (empty list). The user is denied access silently.
3. If a rule exists, the runtime appends the XPath constraint from the rule to the database query.
4. The database returns only the rows matching the constraint.
5. The runtime checks attribute-level permissions and strips out attributes the role cannot read.

### Configuring Access Rules

Each access rule specifies:

| Property | Description |
|---|---|
| **Role(s)** | One or more module roles this rule applies to. |
| **XPath constraint** | An XPath expression that limits which objects the role can access. Leave empty for unrestricted access to all objects. |
| **Allow create** | Whether the role can create new objects of this entity. |
| **Allow delete** | Whether the role can delete objects of this entity. |
| **Attribute access** | For each attribute: None, Read, or Read/Write. |
| **Default rights for new attributes** | What access new attributes get by default (None, Read, or Read/Write). |

### XPath-Based Row-Level Security

The XPath constraint is the most powerful feature of access rules. It filters objects at the database level, ensuring users only see data they are authorized to see.

**Example 1: Users see only their own orders**

```
[Module.Order_Customer/Module.Customer/Module.Customer_Account = '[%CurrentUser%]']
```

This constraint navigates from `Order` to `Customer` to `Account` and checks if the account matches the current user. Only orders belonging to the current user's customer record are returned.

**Example 2: Managers see orders in their department**

```
[Module.Order_Department = '[%CurrentObject%]/../Module.Employee_Department]
```

**Example 3: Users see published articles only**

```
[Status = 'Published' or Module.Article_Author = '[%CurrentUser%]']
```

This allows users to see all published articles, plus their own drafts.

**Example 4: Time-based access**

```
[ExpirationDate > '[%CurrentDateTime%]' or ExpirationDate = empty]
```

This shows only non-expired objects (or objects with no expiration date).

### Common XPath Constraint Tokens

| Token | Resolves To |
|---|---|
| `[%CurrentUser%]` | The `System.User` object of the currently logged-in user. |
| `[%CurrentDateTime%]` | The current date and time (server time). |
| `[%BeginOfCurrentDay%]` | Midnight (00:00:00) of the current day. |
| `[%EndOfCurrentDay%]` | End of the current day (23:59:59). |
| `[%BeginOfCurrentWeek%]` | Start of the current week (Monday 00:00:00 in most locales). |
| `[%BeginOfCurrentMonth%]` | First day of the current month at 00:00:00. |

### Attribute-Level Access

For each access rule, you configure per-attribute access:

| Access Level | Meaning |
|---|---|
| **None** | The attribute is invisible to this role. It is not included in API responses or page data. |
| **Read** | The role can see the attribute value but cannot change it. Input fields for this attribute are read-only. |
| **Read/Write** | The role can see and modify the attribute value. |

Best practices for attribute-level access:

- Start with "None" for all attributes and grant access explicitly. This follows the principle of least privilege.
- Sensitive attributes (SSN, salary, internal notes) should be "None" or "Read" for most roles.
- Audit attributes (CreatedBy, CreatedDate, ChangedDate) should be "Read" for all roles, "Read/Write" for none. Let event handlers or the system manage these.

### Access Rules and Security Levels

Mendix has three security levels:

| Level | Access Rule Enforcement | Recommended For |
|---|---|---|
| **Off** | No enforcement. All data is accessible to everyone. | Local development only. Never use in production. |
| **Prototype / demo** | Partial enforcement. Warnings but no hard blocks. | Demos and prototypes. |
| **Production** | Full enforcement. Missing access rules mean zero access. | All deployed environments. |

Always develop with security set to "Production" level. If you develop with security off and add it later, you will spend days debugging access issues.

### Multiple Access Rules Per Entity

An entity can have multiple access rules for different roles. The rules are evaluated independently:

```
Entity: Order

Rule 1 (Customer role):
  XPath: [Module.Order_Customer/Module.Customer_Account = '[%CurrentUser%]']
  Create: Yes
  Delete: No
  Attributes: OrderNumber (Read), Status (Read), TotalAmount (Read)

Rule 2 (Manager role):
  XPath: [Module.Order_Department/Module.Department_Manager = '[%CurrentUser%]']
  Create: No
  Delete: Yes
  Attributes: OrderNumber (Read), Status (Read/Write), TotalAmount (Read), InternalNotes (Read/Write)

Rule 3 (Administrator role):
  XPath: (none - unrestricted)
  Create: Yes
  Delete: Yes
  Attributes: All (Read/Write)
```

If a user has multiple roles, the rules are combined with OR logic. The user gets the union of all permissions from all their roles.

### Common Access Rule Mistakes

| Mistake | Consequence | Fix |
|---|---|---|
| No access rules defined | The role has zero access to the entity. Pages show empty grids. | Always define at least one access rule per entity per role that needs access. |
| XPath constraint too broad | Users see data they should not see. Security vulnerability. | Test with multiple user accounts. Use the Mendix security checker. |
| XPath constraint too narrow | Users cannot see data they need. Support tickets and confusion. | Verify constraints with actual data. Log in as each role during testing. |
| Forgetting to update rules when adding attributes | New attributes default to "None" access. Users see blank columns. | Set "Default rights for new attributes" to "Read" for roles that need general access. Or review attribute access when adding new attributes. |
| Using `[%CurrentUser%]` on entities not associated with users | The constraint always fails. No objects are returned. | Ensure the entity has an association path back to `System.User`. |

---

## 8. Validation Rules

### Overview

Validation rules ensure data integrity by checking attribute values before an object is committed to the database. Mendix supports both built-in (declarative) validation rules on entities and custom validation logic in microflows.

### Built-In Validation Rules

You configure validation rules in the entity properties, on the "Validation Rules" tab. Each rule specifies:

| Property | Description |
|---|---|
| **Attribute** | The attribute to validate. |
| **Rule type** | The type of check (see table below). |
| **Error message** | The message shown to the user if validation fails. Supports template parameters. |
| **Module roles** | Which roles the rule applies to (leave empty for all roles). |

### Rule Types

| Rule Type | Applicable To | Description | Example |
|---|---|---|---|
| **Required** | All types | The attribute must have a non-empty value. For strings, it must be non-empty and non-whitespace. For associations, the reference must be set. | Email address is required. |
| **Unique** | String, Integer, Long, AutoNumber | The attribute value must be unique across all objects of this entity. Enforced via a database check. | Employee badge number must be unique. |
| **Maximum length** | String | The string length must not exceed the specified maximum. | Description must be 500 characters or fewer. |
| **Maximum value** | Integer, Long, Decimal | The numeric value must not exceed the specified maximum. | Quantity must be 10,000 or fewer. |
| **Minimum value** | Integer, Long, Decimal | The numeric value must not be below the specified minimum. | Price must be 0 or greater. |
| **Range** | Integer, Long, Decimal, DateTime | The value must fall within a specified range. | Date must be between January 1, 2020, and December 31, 2030. |
| **Regular expression** | String | The string must match the specified regular expression pattern. | Email format: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` |
| **Equalities** | All comparable types | The value must equal (or not equal) a specific value. | Status must not be "Cancelled." |

### Validation Rule Error Messages

Error messages support parameters that reference the object being validated:

```
"The email address '{Email}' is not valid. Please enter a valid email."
"Quantity must be between {MinQuantity} and {MaxQuantity}."
"A customer with badge number '{BadgeNumber}' already exists."
```

Best practices for error messages:

- Be specific. "Invalid input" tells the user nothing. "Email must contain an @ symbol" is actionable.
- Use the attribute name in the message so the user knows which field is problematic.
- Keep messages under one sentence. Long messages are ignored.
- Translate messages if your application supports multiple languages.

### Custom Validation Microflows

For complex validation that cannot be expressed with built-in rules, use a **validation microflow** triggered by a before-commit event handler (see Section 9) or called explicitly from a save microflow.

Common custom validation scenarios:

| Scenario | Why Built-In Rules Are Insufficient |
|---|---|
| Cross-attribute validation (end date must be after start date) | Built-in rules operate on a single attribute. |
| Conditional required fields (address required only if shipping method is "Physical") | Built-in rules cannot express conditional logic. |
| Cross-entity validation (order total must not exceed customer credit limit) | Built-in rules cannot query other entities. |
| Business rule validation (cannot approve your own expense report) | Requires checking the current user against object associations. |
| Uniqueness across multiple attributes (no two employees in the same department with the same badge number) | Built-in uniqueness applies to a single attribute only. |

### Implementing Custom Validation

Pattern for a custom validation microflow:

1. Accept the object to validate as a parameter.
2. Perform your checks. For each failed check, add an error message using the "Validation feedback" activity.
3. Return a Boolean indicating whether validation passed.
4. In the calling microflow, check the return value. If `false`, do not commit the object.

```
Microflow: ValidateOrder($Order)
  1. If $Order/EndDate < $Order/StartDate:
       Validation feedback: "End date must be after start date." (on EndDate attribute)
       Set $IsValid = false
  2. If $Order/TotalAmount > $Order/Order_Customer/CreditLimit:
       Validation feedback: "Order total exceeds customer credit limit." (on TotalAmount attribute)
       Set $IsValid = false
  3. Return $IsValid
```

### Client-Side vs. Server-Side Validation

| Aspect | Client-Side (Page) | Server-Side (Microflow / Commit) |
|---|---|---|
| When it runs | Before the save action reaches the server. | During the microflow or commit operation on the server. |
| Speed | Instant feedback to the user. | Requires a round-trip to the server. |
| Security | Can be bypassed by API calls or page manipulation. | Cannot be bypassed. Always runs. |
| Capabilities | Limited to widget-level checks (required, regex, range). | Full access to the domain model, other entities, and business logic. |
| Recommendation | Use for immediate UX feedback. | Always implement as the authoritative check. |

Always implement validation on the server side. Client-side validation is a UX convenience, not a security mechanism.

### Validation and Error Handling

When a validation rule fails:

- **Built-in rules**: The Mendix runtime automatically generates a validation error and sends it to the client. The client highlights the offending field and shows the error message.
- **Custom validation with "Validation feedback" activity**: The activity attaches an error message to a specific attribute. The client highlights that attribute's widget.
- **Custom validation with "Show message" activity**: A generic message is shown, but no specific field is highlighted. Use "Validation feedback" instead when possible.
- **Database-level constraint violations (unique index)**: The commit fails with a runtime error. Handle this with error handling in your microflow and show a user-friendly message.

---

## 9. Event Handlers

### Overview

Event handlers are microflows that execute automatically when specific operations occur on entity objects. They allow you to inject custom logic into the object lifecycle without modifying every microflow that creates, changes, or deletes objects.

### Event Handler Types

| Event | Trigger | Can Prevent Operation? | Common Uses |
|---|---|---|---|
| **Before Create** | Fires when a new object is instantiated (before any attributes are set). | No. The object is always created. | Setting default values that cannot be expressed as attribute defaults (e.g., referencing the current user). |
| **Before Commit** | Fires before the object is written to the database. | Yes. Throwing an error or returning false prevents the commit. | Validation, computed fields, audit trail population, business rule enforcement. |
| **After Commit** | Fires after the object is successfully written to the database. | No. The commit has already happened. | Sending notifications, triggering downstream processes, cache invalidation. |
| **Before Delete** | Fires before the object is removed from the database. | Yes. Throwing an error prevents the deletion. | Referential integrity checks, archiving (copy to history table before delete), cascading cleanup. |
| **After Delete** | Fires after the object is removed from the database. | No. The deletion has already happened. | Cleanup of related external systems, logging, notification. |

### Configuring Event Handlers

1. Open the entity properties.
2. Go to the "Event handlers" tab.
3. Click "New."
4. Select the event type (Before Create, Before Commit, After Commit, Before Delete, After Delete).
5. Select or create the microflow to execute.
6. Optionally, choose whether the handler runs for all changes or only for specific attributes (Before Commit and After Commit support "Raise event on change of" specific attributes).

### Before Commit -- The Workhorse

Before Commit is the most commonly used event handler. It fires every time an object is committed, regardless of which microflow performs the commit. This makes it the right place for logic that must always run.

Common before-commit patterns:

**Audit trail population:**
```
Microflow: BCo_Order_BeforeCommit($Order)
  1. Set $Order/ChangedDate = [%CurrentDateTime%]
  2. Set $Order/ChangedBy = [%CurrentUser%]
  3. If $Order is new (check changedDate = empty or use $Order/CreatedDate = empty):
       Set $Order/CreatedDate = [%CurrentDateTime%]
       Set $Order/CreatedBy = [%CurrentUser%]
```

**Computed field update:**
```
Microflow: BCo_OrderLine_BeforeCommit($OrderLine)
  1. Set $OrderLine/LineTotal = $OrderLine/Quantity * $OrderLine/UnitPrice
  2. Retrieve $Order via association
  3. Calculate new order total (sum of all line totals)
  4. Set $Order/TotalAmount = calculated total
  5. Commit $Order (careful: this triggers Order's before-commit handler -- avoid infinite loops)
```

**Validation:**
```
Microflow: BCo_Expense_BeforeCommit($Expense)
  1. If $Expense/Amount > 10000 and $Expense/Expense_Approver = empty:
       Validation feedback: "Expenses over $10,000 require an approver."
       // The commit is prevented because validation feedback was generated.
```

### After Commit -- Side Effects

After Commit fires after the database write succeeds. Use it for side effects that should not prevent the commit:

**Sending notifications:**
```
Microflow: ACo_Order_AfterCommit($Order)
  1. If $Order/Status = 'Approved':
       Retrieve $Customer via association
       Send email to $Customer/Email with order confirmation
```

**Triggering integrations:**
```
Microflow: ACo_Invoice_AfterCommit($Invoice)
  1. If $Invoice/Status changed to 'Finalized':
       Call REST service to send invoice to accounting system
```

### Before Delete -- Guarding Data

Before Delete fires before an object is removed. Use it to prevent deletions or to archive data:

**Preventing deletion of referenced objects:**
```
Microflow: BDe_Customer_BeforeDelete($Customer)
  1. Retrieve list of Orders associated with $Customer
  2. If list is not empty:
       Show validation message: "Cannot delete customer with existing orders."
       // Throwing an error prevents the deletion
```

**Archiving before delete:**
```
Microflow: BDe_Order_BeforeDelete($Order)
  1. Create new ArchivedOrder object
  2. Copy all attributes from $Order to $ArchivedOrder
  3. Commit $ArchivedOrder
  // Deletion of $Order proceeds after this microflow completes
```

### Performance Implications

Event handlers have significant performance implications. Every handler adds latency to the corresponding operation:

| Concern | Impact | Mitigation |
|---|---|---|
| Before Commit on bulk operations | If you commit 1,000 objects in a loop, the before-commit handler fires 1,000 times. | Use "Commit without events" when bulk-loading data (available in Java actions). Or batch commits and minimize handler logic. |
| After Commit calling external services | External service calls add latency and can fail. Failures in after-commit handlers do not roll back the commit but can cause errors. | Use asynchronous processing (task queues, scheduled events) for unreliable external calls. |
| Recursive commits | A before-commit handler that commits another object of the same entity triggers itself recursively. | Add guard clauses. Use a flag attribute (e.g., `IsProcessing`) to prevent re-entry. Or restructure to avoid committing the same entity type from within its own handler. |
| Database queries in handlers | Retrieving data in a handler that fires on every commit adds queries to the transaction. | Minimize retrievals. Cache frequently needed data. Use associations instead of XPath queries when possible. |
| Cascading handlers | Committing entity A's handler commits entity B, which triggers entity B's handler, which commits entity C. The chain can grow unexpectedly. | Map out your handler chains. Document them. Keep them short. |

### Event Handler Execution Context

| Property | Value |
|---|---|
| Transaction | Handlers run within the same database transaction as the triggering operation. If a before-commit handler fails, the entire transaction rolls back. |
| Current user | The user who triggered the operation. `[%CurrentUser%]` works as expected. |
| Object state | In before-commit, the object has its new (uncommitted) values. In after-commit, the object is committed. |
| Error handling | Errors in before-commit/before-delete handlers prevent the operation. Errors in after-commit/after-delete handlers are logged but do not roll back the operation (the commit/delete has already succeeded). |

### Best Practices

1. **Keep handlers lean.** A before-commit handler should execute in milliseconds, not seconds. Move heavy work to after-commit or to asynchronous processes.
2. **Guard against recursion.** If handler A commits entity B, and entity B's handler commits entity A, you have infinite recursion. Use flags or restructure the logic.
3. **Do not rely on handlers for security.** Access rules are the right mechanism for security. Handlers are for business logic.
4. **Document all handlers.** Future developers need to know that committing an `Order` triggers a chain of side effects. Put a comment at the top of each handler microflow explaining why it exists.
5. **Test handlers in isolation.** Create unit test microflows that commit objects and verify the handler's effects.
6. **Consider "Commit without events."** When importing data or performing bulk operations, use Java actions to commit without triggering event handlers. This avoids performance problems and unintended side effects during data loads.

---

## 10. Domain Model Patterns

### Overview

This section covers proven domain model patterns that solve recurring design problems in Mendix applications. These patterns are not Mendix-specific -- they come from decades of relational database and enterprise application design -- but they have Mendix-specific considerations.

### Pattern 1: Master-Detail

**Problem:** You have a parent entity with multiple child records that must be managed together. Examples: Order with OrderLines, Invoice with InvoiceItems, Survey with Questions.

**Structure:**

```
Order (master)
  |-- OrderNumber : AutoNumber
  |-- OrderDate : DateTime
  |-- Status : Enumeration
  |-- TotalAmount : Decimal
  |
  +--- OrderLine (detail) [1-to-many association, Order owns]
         |-- LineNumber : Integer
         |-- Quantity : Integer
         |-- UnitPrice : Decimal
         |-- LineTotal : Decimal (computed in before-commit)
         |-- Description : String
```

**Key decisions:**

| Decision | Recommendation |
|---|---|
| Delete behavior | Delete OrderLines when Order is deleted. Lines have no meaning without their parent. |
| Ownership | Order owns the association. OrderLine stores the FK. |
| Computed totals | Calculate `Order.TotalAmount` as the sum of `OrderLine.LineTotal` in a before-commit handler on `OrderLine`. |
| Validation | Require at least one OrderLine before allowing the Order to transition to "Submitted" status. |
| Access rules | Apply the same XPath constraint to both Order and OrderLine. If users can only see their own Orders, they should only see those Orders' lines. |

**Mendix implementation tips:**

- Use a data view for the master, with a nested data grid or list view for the detail.
- Allow inline editing of detail records for a smooth UX.
- Commit the master and detail objects together in a save microflow to maintain consistency.

### Pattern 2: Polymorphic References

**Problem:** An entity needs to reference one of several different entity types. Example: a `Comment` can belong to a `Task`, a `Project`, or a `Customer`.

**Approach A: Generalization**

Create a common parent entity and have `Comment` reference the parent:

```
Commentable (generalization)
  |
  +-- Task (specialization)
  +-- Project (specialization)
  +-- Customer (specialization)

Comment --> Commentable (association)
```

Pros: Clean model. Single association. Easy to query all comments for any commentable entity.

Cons: Forces Task, Project, and Customer into a single inheritance hierarchy. If they already have different generalizations, this does not work.

**Approach B: Multiple associations**

```
Comment
  |-- Comment_Task : Task (optional)
  |-- Comment_Project : Project (optional)
  |-- Comment_Customer : Customer (optional)
```

Validation rule: exactly one of the three associations must be set.

Pros: No inheritance constraint. Each entity remains independent.

Cons: Null associations. Validation complexity. Adding a new commentable type requires modifying the Comment entity.

**Approach C: String-based reference (least recommended)**

```
Comment
  |-- TargetEntityType : String ("Task", "Project", "Customer")
  |-- TargetObjectId : Long
```

Pros: Completely flexible. No model changes when adding new types.

Cons: No referential integrity. No cascade behavior. No association navigation in the domain model. Requires Java actions or complex microflows to resolve references. Avoid this pattern unless you have a strong reason.

**Recommendation:** Use Approach A (generalization) when possible. Use Approach B when generalization is not feasible. Avoid Approach C.

### Pattern 3: Soft Delete

**Problem:** You need to "delete" objects without actually removing them from the database. Regulatory, audit, or undo requirements demand that data is never truly destroyed.

**Structure:**

```
Entity: Order
  |-- IsDeleted : Boolean (default: false, indexed)
  |-- DeletedDate : DateTime
  |-- DeletedBy : Association to System.User
  |-- ... other attributes ...
```

**Implementation:**

| Component | Details |
|---|---|
| Marking as deleted | A microflow sets `IsDeleted = true`, `DeletedDate = now()`, `DeletedBy = current user`, then commits. |
| Access rules XPath | Add `[IsDeleted = false]` to all access rule XPath constraints. Users never see soft-deleted objects in normal use. |
| Admin view | A separate page with its own data source that shows objects where `IsDeleted = true`. Only accessible to administrators. |
| Restore | A microflow sets `IsDeleted = false`, clears `DeletedDate` and `DeletedBy`, commits. |
| Hard delete | A scheduled event permanently deletes objects where `IsDeleted = true` and `DeletedDate` is older than the retention period (e.g., 90 days). |
| Index | Create an index on `IsDeleted` (or a compound index with other frequently filtered attributes) because every query now includes this filter. |

**Caveats:**

- Every XPath query and access rule must include the `IsDeleted` filter. Miss one, and deleted data leaks through.
- Soft-deleted objects still consume storage, indexes, and query time.
- Associations to soft-deleted objects may cause issues. If `Order` is soft-deleted but `OrderLine` objects are not, the lines reference a "deleted" parent. Handle this with cascading soft delete.

### Pattern 4: Audit Trail

**Problem:** You need to track who changed what, when, and what the previous value was.

**Approach A: Simple audit attributes**

Add to every auditable entity:

```
  |-- CreatedDate : DateTime (set in before-commit)
  |-- CreatedBy : Association to System.User (set in before-commit)
  |-- ChangedDate : DateTime (set in before-commit)
  |-- ChangedBy : Association to System.User (set in before-commit)
```

Pros: Simple. Answers "who last changed it?" and "when was it created?" Covers 80% of audit needs.

Cons: Does not capture what changed or the previous value. Only tracks the last change.

**Approach B: Audit log entity**

Create a dedicated audit entity:

```
AuditTrailEntry
  |-- EntityName : String
  |-- ObjectId : Long
  |-- AttributeName : String
  |-- OldValue : String (unlimited)
  |-- NewValue : String (unlimited)
  |-- ChangedDate : DateTime
  |-- ChangedBy : Association to System.User
  |-- ChangeType : Enumeration (Create, Update, Delete)
```

A before-commit event handler on each audited entity compares old and new values, and creates `AuditTrailEntry` objects for each changed attribute.

Pros: Full change history. Can answer "what was the value of attribute X on date Y?"

Cons: Significant storage growth. Performance impact (every commit creates multiple audit log entries). Complex to implement consistently.

**Approach C: Use the Community Commons or Audit Trail Marketplace module**

The Mendix Marketplace provides an Audit Trail module that automates Approach B. Consider this before building your own.

| Feature | Community Module | Custom Implementation |
|---|---|---|
| Effort | Low (install and configure) | High (build and maintain) |
| Flexibility | Limited to module capabilities | Fully customizable |
| Performance tuning | Limited | Full control |
| Support | Community-supported | Your team maintains it |

### Pattern 5: Temporal Data (Effective Dating)

**Problem:** You need to track how data changes over time, not just the current state. Examples: employee salary history, insurance policy versions, product pricing over time.

**Structure:**

```
EmployeeSalary
  |-- Employee : Association to Employee
  |-- Amount : Decimal
  |-- EffectiveFrom : DateTime (indexed)
  |-- EffectiveTo : DateTime (indexed, nullable -- null means "current")
  |-- ApprovedBy : Association to System.User
  |-- ApprovedDate : DateTime
```

**Key rules:**

| Rule | Implementation |
|---|---|
| No overlapping periods | Before-commit validation: check that no other `EmployeeSalary` for the same employee has an overlapping date range. |
| Current record | Query: `[Employee = $Employee and EffectiveTo = empty]` returns the current salary. |
| Historical record | Query: `[Employee = $Employee and EffectiveFrom <= $AsOfDate and (EffectiveTo >= $AsOfDate or EffectiveTo = empty)]` returns the salary effective on a given date. |
| New salary | Set the current record's `EffectiveTo` to the new record's `EffectiveFrom` minus one day. Create the new record with `EffectiveTo = empty`. |

**Indexes:**

Create a compound index on (`Employee` association, `EffectiveFrom`, `EffectiveTo`) to optimize temporal queries.

### Pattern 6: State Machine

**Problem:** An entity transitions through a series of states with defined rules about which transitions are allowed.

**Structure:**

```
Entity: Ticket
  |-- Status : Enumeration (New, InProgress, OnHold, Resolved, Closed)
  |-- ... other attributes ...
```

**Transition matrix:**

| From \ To | New | InProgress | OnHold | Resolved | Closed |
|---|---|---|---|---|---|
| New | -- | Yes | No | No | Yes |
| InProgress | No | -- | Yes | Yes | No |
| OnHold | No | Yes | -- | No | Yes |
| Resolved | No | Yes | No | -- | Yes |
| Closed | No | No | No | No | -- |

**Implementation:**

Create a microflow `ChangeTicketStatus($Ticket, $NewStatus)` that:

1. Checks the transition matrix. If the transition from `$Ticket/Status` to `$NewStatus` is not allowed, show a validation error.
2. Performs any transition-specific logic (e.g., setting `ResolvedDate` when moving to "Resolved").
3. Sets the new status and commits.

Implement the transition matrix as:

- A series of if/then checks in the microflow.
- A separate `StatusTransition` entity that defines allowed from/to pairs (more flexible, data-driven).
- A Java action that evaluates the transition (most performant for complex matrices).

### Pattern 7: Configuration / Settings Entity

**Problem:** Your application needs configurable settings (email sender address, API endpoint URLs, feature flags) that administrators can change without redeployment.

**Structure:**

```
Entity: AppConfiguration (singleton)
  |-- SmtpServer : String
  |-- SmtpPort : Integer (default: 587)
  |-- SenderEmail : String
  |-- MaxUploadSizeMB : Integer (default: 10)
  |-- FeatureBetaEnabled : Boolean (default: false)
  |-- MaintenanceMode : Boolean (default: false)
```

**Singleton enforcement:**

- On application startup (After Startup microflow), check if an `AppConfiguration` object exists. If not, create one with defaults.
- Remove "Create" permission for all roles. Only the startup microflow creates the object.
- The admin page retrieves the single object and displays it in a data view.

**Caching:**

Retrieve the configuration object once per microflow chain and pass it as a parameter rather than retrieving it repeatedly. For high-frequency access, consider caching the values in a non-persistable entity or Java static fields.

---

## 11. Data Migration

### Overview

As your Mendix application evolves, the domain model changes. Attributes are added, removed, or renamed. Entities are restructured. Associations change. The Mendix runtime handles schema migration automatically at deployment, but data migration -- ensuring existing data remains correct and complete after model changes -- is your responsibility.

### How Mendix Handles Schema Changes

When you deploy a new version of your application, the Mendix runtime compares the new domain model to the existing database schema and generates DDL statements:

| Model Change | Runtime Action | Data Impact |
|---|---|---|
| New entity | `CREATE TABLE` | No existing data affected. |
| New attribute | `ALTER TABLE ADD COLUMN` | Existing rows get `NULL` (or the default value if specified). |
| Removed entity | Table is **not** dropped (by default). | Data remains in the orphaned table. Can be cleaned up manually. |
| Removed attribute | Column is **not** dropped (by default). | Data remains in the orphaned column. Mendix ignores it. |
| Renamed entity | Old table is kept. New table is created. | Data is **not** migrated automatically. You must handle this. |
| Renamed attribute | Old column is kept. New column is added. | Data is **not** migrated automatically. You must handle this. |
| Changed attribute type | Depends on compatibility. Compatible changes (e.g., Integer to Long) are handled. Incompatible changes may fail. | Test type changes in a non-production environment first. |
| New association | `ALTER TABLE ADD COLUMN` (FK) or `CREATE TABLE` (junction). | Existing rows have NULL for the new FK. |
| Removed association | FK column or junction table is **not** dropped. | Data remains. Mendix ignores it. |
| Changed association cardinality | Complex. May require a new column or table. | Existing data is not migrated. Handle manually. |

### Default Values for New Attributes

When you add a new attribute to an existing entity with data:

- **With a default value**: New rows get the default. Existing rows remain `NULL` unless you run a migration.
- **Without a default value**: All existing rows have `NULL` for the new column.
- **With a required validation rule**: Existing rows will fail validation if retrieved and committed without setting the new attribute. This can break microflows that commit these objects.

**Migration strategy for new required attributes:**

1. Add the attribute with a default value but without the required validation rule.
2. Deploy.
3. Run a data migration microflow that sets the attribute on all existing objects.
4. Add the required validation rule.
5. Deploy again.

Or combine steps by running the migration in an After Startup microflow.

### Data Migration Microflows

A data migration microflow runs once (or idempotently) to update existing data after a model change. Patterns:

**After Startup migration:**

```
Microflow: ASu_MigrateData
  1. Check if migration is needed (e.g., query for objects where NewAttribute = empty)
  2. If needed, retrieve objects in batches (e.g., 1,000 at a time)
  3. For each batch:
       a. Update the new attribute with the correct value
       b. Commit without events (to avoid triggering event handlers)
  4. Log the migration result (number of objects updated)
```

**Migration tracking entity:**

```
Entity: MigrationRecord
  |-- Name : String (unique)
  |-- ExecutedDate : DateTime
  |-- Success : Boolean
  |-- Notes : String (unlimited)
```

Before running a migration, check if a `MigrationRecord` with the migration's name exists. If it does, skip it. This makes migrations idempotent and prevents them from running on every restart.

### Handling Entity Renames

Mendix does not automatically migrate data when you rename an entity. The old table remains with the old name, and a new empty table is created with the new name.

**Migration procedure:**

1. Before renaming, create a migration microflow that reads from the old entity and writes to the new entity.
2. Rename the entity in the domain model.
3. Create a temporary "old" entity in the model that maps to the original table name (set the "Stored in" property to the old table name).
4. Deploy. Run the migration microflow.
5. Verify data integrity.
6. Remove the temporary "old" entity.
7. Deploy again.

Alternatively, use direct SQL (via a Java action or database admin tool) to rename the table:

```sql
ALTER TABLE module$oldentityname RENAME TO module$newentityname;
```

This is faster and avoids the temporary entity approach, but requires database access and is not part of the Mendix model. Document it thoroughly.

### Handling Attribute Renames

Similar to entity renames, attribute renames create a new column and leave the old one:

1. Add the new attribute.
2. Create a migration microflow that copies values from the old attribute to the new attribute.
3. Deploy. Run the migration.
4. Remove the old attribute.
5. Deploy again.

Or use SQL:

```sql
UPDATE module$entityname SET newcolumnname = oldcolumnname;
ALTER TABLE module$entityname DROP COLUMN oldcolumnname;
```

### Batch Processing in Migrations

Large datasets require batch processing to avoid memory and timeout issues:

| Batch Size | Memory Usage | Commit Frequency | Recommended For |
|---|---|---|---|
| 100-500 | Low | Every batch | Small to medium datasets (under 100K objects) |
| 500-1,000 | Moderate | Every batch | Medium datasets (100K-1M objects) |
| 1,000-5,000 | Higher | Every batch | Large datasets (over 1M objects) with sufficient memory |

**Batch processing pattern:**

```
Microflow: Migrate_SetDefaultRegion
  Variables: $Offset = 0, $BatchSize = 1000, $TotalMigrated = 0
  Loop:
    1. Retrieve $BatchSize objects where Region = empty, sorted by ID, offset $Offset
    2. If list is empty, exit loop
    3. For each object in batch:
         Set Region = 'US' (or derive from other attributes)
    4. Commit batch without events
    5. $TotalMigrated = $TotalMigrated + size of batch
    6. Continue loop
  Log: "Migration complete. Updated " + $TotalMigrated + " objects."
```

### Migration Pitfalls

| Pitfall | Consequence | Prevention |
|---|---|---|
| Running migrations with event handlers enabled | Before-commit handlers fire on every object, causing performance issues and unintended side effects. | Use "Commit without events" in migration microflows. |
| Not making migrations idempotent | Re-running the migration (e.g., after a restart) corrupts data or creates duplicates. | Use a MigrationRecord entity to track completed migrations. |
| Migrating in a single transaction | Committing millions of objects in one transaction can exhaust database resources and timeout. | Process in batches. Commit each batch separately. |
| Forgetting to migrate before adding validation | Existing objects fail validation when committed, breaking the application. | Always migrate data before adding stricter rules. |
| Not testing with production-sized data | Migration works on a test database with 100 rows but takes hours on production with 10 million rows. | Test with a copy of production data. |

---

## 12. Performance Considerations

### Overview

Domain model design has a direct and significant impact on application performance. Decisions you make during modeling -- how many attributes per entity, how entities relate, how data is stored and retrieved -- determine whether your application scales gracefully or bogs down under load.

### Wide Entities vs. Normalized Models

**Wide entities** have many attributes (50+). They are simple to understand but have performance costs:

| Aspect | Wide Entity (50+ attributes) | Normalized Model (multiple entities, 10-20 attributes each) |
|---|---|---|
| Query performance | Every query retrieves all columns, even if only a few are needed. | Queries retrieve only the columns in the queried entity. |
| Memory usage | Each object in memory consumes more RAM. | Smaller per-object footprint. |
| Network transfer | More data sent between database, server, and client. | Less data per request. |
| Index efficiency | Wider rows mean fewer rows per index page, reducing index performance. | Narrower rows are more index-friendly. |
| Development simplicity | Everything in one place. Easy to find attributes. | More entities to navigate. More associations to manage. |
| Commit performance | Every commit writes the entire row (all columns). | Commits only affect the relevant entity's table. |

**Guideline:** Keep entities under 40 attributes. If an entity grows beyond this, consider:

- Splitting rarely-used attributes into a separate entity with a 1-1 association (vertical partitioning).
- Grouping logically related attributes into their own entity (normalization).
- Moving computed or derived values to non-persistable entities or calculated attributes.

### Attribute Count Impact

Empirical guidelines based on Mendix performance testing:

| Attribute Count | Impact |
|---|---|
| 1-20 | Optimal. No performance concerns. |
| 20-40 | Good. Minor overhead. Acceptable for most use cases. |
| 40-60 | Moderate impact. Consider vertical partitioning for rarely used attribute groups. |
| 60-100 | Significant impact on commit and retrieve times. Split the entity. |
| 100+ | Severe performance degradation. Refactoring is required. |

### Lazy Loading vs. Eager Loading

Mendix uses **lazy loading** for associations by default. When you retrieve an `Order`, the associated `Customer` is not loaded until you explicitly navigate the association.

| Loading Strategy | Behavior | Performance Impact |
|---|---|---|
| Lazy (default) | Associated objects are loaded on demand when the association is navigated. | Efficient when you do not always need the associated data. Can cause N+1 query problems if you navigate associations in a loop. |
| Eager (data grid with associated columns) | The runtime joins associated data in a single query when a data grid displays columns from associated entities. | Efficient for display. The runtime optimizes the SQL query. |
| Manual batch retrieval | In a microflow, retrieve associated objects explicitly for a list of parent objects. | Most control. You decide when and how much to load. |

**N+1 query problem:**

```
// BAD: N+1 pattern
Retrieve list of 100 Orders
For each $Order:
    Retrieve $Customer via $Order/Order_Customer   // This fires 100 separate queries!
    Log $Customer/Name
```

```
// GOOD: Batch pattern
Retrieve list of 100 Orders
Retrieve list of Customers where [Module.Order_Customer = $OrderList]   // Single query
For each $Order:
    Find matching Customer in the Customer list
```

### Large Binary Attributes

Binary data (files, images) is stored outside the main database table (in blob storage on Mendix Cloud, or in a configured file system). However, entities that generalize from `System.FileDocument` still have metadata in the database.

Performance considerations for binary data:

| Consideration | Recommendation |
|---|---|
| Do not retrieve FileDocument objects in bulk unless needed | Only retrieve the file contents when the user explicitly downloads or views the file. |
| Use thumbnails for images | The `System.Image` generalization generates thumbnails. Display thumbnails in list views, full images only in detail views. |
| Set maximum file sizes | Use validation rules or microflow checks to reject files above your size threshold. |
| Clean up orphaned files | Deleting the entity object removes the database row. The runtime also cleans up the associated blob. Ensure your delete logic actually deletes the object (not just soft-deletes it). |
| Avoid associations to FileDocument in hot paths | If an entity is retrieved frequently, and it has an association to a FileDocument, the FileDocument metadata is loaded. Keep binary-heavy entities separate from frequently queried entities. |

### Query Optimization

| Technique | Description | Benefit |
|---|---|---|
| Use indexed attributes in XPath constraints | Ensure attributes used in `[Attribute = value]` are indexed. | Avoids full table scans. |
| Limit result sets | Use `first` parameter in retrieve activities. Use paging in data grids. | Reduces memory and transfer overhead. |
| Avoid `contains()` on large text fields | XPath `contains()` translates to SQL `LIKE '%value%'`, which cannot use indexes. | Prevents slow full-text scans. |
| Use sorting on indexed columns | Sorting on non-indexed columns requires the database to sort the entire result set in memory. | Indexed sorts are fast. |
| Prefer equality over range | `[Status = 'Open']` is faster than `[Status != 'Closed']` because the database can seek directly to matching index entries. | Better index utilization. |
| Avoid deeply nested association traversals in XPath | `[A/B/C/D/E/Attribute = value]` generates multiple JOINs. | Fewer JOINs means faster queries. |
| Use OQL for complex aggregations | OQL (Mendix's SQL-like query language) is better than XPath for GROUP BY, HAVING, and complex joins. | Purpose-built for analytics queries. |

### Denormalization

Sometimes, violating normalization principles improves performance:

| Scenario | Denormalization Approach | Trade-off |
|---|---|---|
| Displaying the customer name on every order row | Store `CustomerName` on `Order` (copied from `Customer.Name`). | Avoids joining the Customer table for every order list query. Must keep the copy in sync via event handlers. |
| Counting child objects | Store `LineCount` on `Order` (count of OrderLines). | Avoids `COUNT(*)` subquery. Must update on OrderLine create/delete. |
| Aggregating totals | Store `TotalAmount` on `Order` (sum of OrderLine.LineTotal). | Avoids `SUM()` subquery. Must update on OrderLine changes. |

Denormalization rules:

1. Only denormalize when you have measured a performance problem. Do not optimize prematurely.
2. Always maintain consistency via event handlers. If the source data changes, the denormalized copy must update.
3. Document the denormalization. Future developers need to know that `Order.CustomerName` is a copy that must be kept in sync.

### Scheduled Event and Data Volume

Scheduled events that process large volumes of data can degrade application performance:

| Practice | Description |
|---|---|
| Process in batches | Retrieve and process 500-1,000 objects at a time. Commit each batch. |
| Run during off-peak hours | Schedule heavy processing for nighttime or weekends. |
| Use "Commit without events" for bulk updates | Avoids triggering event handlers on every object. |
| Monitor runtime memory | Large retrievals can exhaust JVM heap. Use the Mendix Runtime Statistics page or APM tools. |
| Use separate database queries for counting | Before processing, use an OQL `COUNT(*)` to know the total. Do not retrieve all objects just to count them. |

### Association Performance

| Association Type | Retrieval Cost | Notes |
|---|---|---|
| Reference (owner navigates to associated) | Low. Single FK lookup. | The most efficient direction. |
| Reference (non-owner navigates) | Moderate. Requires query on the owner's table. | Add an index on the FK column if this direction is frequent. (Mendix auto-indexes FKs.) |
| Reference set | Higher. Requires a junction table query. | Junction tables can grow large in many-to-many relationships. Index them. |
| Deep association chains | Increases with depth. Each level adds a JOIN. | Denormalize if you frequently traverse 3+ levels. |

---

## 13. Naming Conventions

### Overview

Consistent naming conventions make your domain model readable, maintainable, and navigable. When a team of developers works on the same project, conventions eliminate ambiguity and reduce the time spent understanding someone else's model.

### Entity Naming

| Rule | Example | Anti-Pattern |
|---|---|---|
| Use PascalCase (UpperCamelCase). | `CustomerOrder` | `customer_order`, `customerorder` |
| Use singular nouns. An entity represents a single object type. | `Order` | `Orders` (the table may hold many, but the entity is the definition of one) |
| Be specific. Avoid generic names. | `InvoiceLine` | `Item` (item of what?) |
| Prefix module-specific entities if the module may be reused. | `CRM_Customer` (in a reusable CRM module) | `Customer` (may collide with other modules) |
| Do not include the module name in the entity name. The module provides the namespace. | `Customer` (in CRM module, accessed as `CRM.Customer`) | `CRMCustomer` (redundant) |
| Use the business domain term, not a technical term. | `Employee` | `EmployeeRecord`, `EmployeeRow`, `TblEmployee` |

### Entity Naming for Specific Patterns

| Pattern | Naming Convention | Example |
|---|---|---|
| Non-persistable entity (view model) | Suffix with the purpose or `Helper`. | `OrderSearchCriteria`, `DashboardSummary`, `RegistrationHelper` |
| Non-persistable entity (API wrapper) | Match the API resource name. | `WeatherResponse`, `PaymentRequest` |
| Audit/history entity | Suffix with `History` or `Log`. | `OrderHistory`, `AuditLog` |
| Configuration/settings (singleton) | Suffix with `Configuration` or `Settings`. | `AppConfiguration`, `EmailSettings` |
| Junction entity (for many-to-many with attributes) | Combine both entity names. | `StudentCourseEnrollment` |
| Specialization entity | Use a descriptive subtype name, not a prefix. | `DigitalProduct` (not `Product_Digital`) |

### Attribute Naming

| Rule | Example | Anti-Pattern |
|---|---|---|
| Use PascalCase. | `FirstName` | `firstName`, `first_name`, `FIRSTNAME` |
| Be descriptive. A reader should understand the attribute without seeing the entity. | `OrderDate` | `Date` (date of what?) |
| Boolean attributes: use `Is`, `Has`, `Can`, or `Should` prefix. | `IsActive`, `HasDiscount`, `CanEdit` | `Active` (is it active? can it be activated?) |
| DateTime attributes: suffix with `Date`, `Time`, or `DateTime`. | `CreatedDate`, `StartDateTime` | `Created` (is this a date? a flag? a user?) |
| Amount/currency attributes: be explicit about what is measured. | `TotalAmount`, `DiscountPercentage`, `TaxRate` | `Amount` (amount of what?) |
| Avoid abbreviations unless universally understood. | `Description` | `Desc` |
| Enumeration attributes: name the attribute after the concept, not the enumeration. | `Status` (using the `OrderStatus` enumeration) | `OrderStatus` (redundant with the type name) |

### Commonly Used Attribute Names

These attribute names are so common that they form a de facto standard. Use them consistently:

| Attribute Name | Type | Purpose |
|---|---|---|
| `Name` | String | The display name of the object. |
| `Description` | String | A longer textual description. |
| `Code` | String | A short code or identifier (e.g., country code, product code). |
| `Status` | Enumeration | The current state in a workflow. |
| `IsActive` | Boolean | Whether the object is active (soft-delete flag or feature toggle). |
| `IsDeleted` | Boolean | Soft-delete flag (see Pattern 3). |
| `SortOrder` | Integer | Manual sort position. |
| `CreatedDate` | DateTime | When the object was first created. |
| `CreatedBy` | Association | Who created the object. |
| `ChangedDate` | DateTime | When the object was last modified. |
| `ChangedBy` | Association | Who last modified the object. |
| `ExternalId` | String or Long | Identifier from an external system. |
| `Remarks` | String | Free-text notes. |

### Association Naming

| Rule | Example | Anti-Pattern |
|---|---|---|
| Use the format `ParentEntity_ChildEntity`. | `Customer_Order` | `CustOrd`, `Rel_1`, `Association1` |
| For self-referential associations, describe the relationship. | `Employee_Manager` (Employee to Employee, where one is the manager) | `Employee_Employee` (ambiguous) |
| For multiple associations between the same entities, differentiate by role. | `Order_BillingAddress`, `Order_ShippingAddress` | `Order_Address1`, `Order_Address2` |
| Keep association names readable. They appear in XPath expressions. | `[Module.Order_Customer/Module.Customer/Name = 'Acme']` | `[Module.Rel1/Module.E2/Name = 'Acme']` |

### Enumeration Naming

| Rule | Example | Anti-Pattern |
|---|---|---|
| Use PascalCase for the enumeration name. | `OrderStatus` | `order_status`, `ORDERSTATUS` |
| Use PascalCase for enumeration values. | `InProgress`, `OnHold`, `Cancelled` | `in_progress`, `IN_PROGRESS`, `inProgress` |
| Prefix with the domain concept if the enumeration is generic. | `OrderStatus`, `TaskPriority` | `Status` (which entity's status?), `Priority` (of what?) |
| Keep values short but descriptive. | `Draft`, `Submitted`, `Approved`, `Rejected` | `D`, `S`, `A`, `R` |
| Captions (display values) can use spaces and natural language. | Caption: "In Progress" for value `InProgress` | -- |

### Module Naming

| Rule | Example | Anti-Pattern |
|---|---|---|
| Use PascalCase. | `OrderManagement` | `order_management`, `ordermanagement` |
| Name modules after the business domain they serve. | `HumanResources`, `Invoicing`, `CustomerRelations` | `Module1`, `Utilities`, `Misc` |
| Keep module names concise (1-3 words). | `CRM` | `CustomerRelationshipManagementModule` |
| Marketplace modules keep their original names. | `CommunityCommons` | Do not rename Marketplace modules. |

### Consistency Checklist

Use this checklist when reviewing your domain model naming:

| Check | Pass? |
|---|---|
| All entity names are PascalCase and singular. | |
| All attribute names are PascalCase. | |
| All Boolean attributes start with `Is`, `Has`, `Can`, or `Should`. | |
| All DateTime attributes end with `Date`, `Time`, or `DateTime`. | |
| All association names follow `Parent_Child` format. | |
| All enumeration names and values are PascalCase. | |
| No abbreviations that are not universally understood. | |
| No generic names (`Item`, `Data`, `Record`, `Info`). | |
| Audit attributes (`CreatedDate`, `ChangedDate`, `CreatedBy`, `ChangedBy`) are named consistently across all entities. | |
| Non-persistable entities are clearly identifiable by their name or module. | |

### Naming and Refactoring

Renaming entities and attributes in Mendix is safe -- Studio Pro updates all references (microflows, pages, XPath expressions) automatically. However:

- The database table/column is **not** renamed (see Section 11 on data migration).
- Marketplace modules and published APIs that reference the old name will break.
- Team members working on branches may have merge conflicts if the rename touches many files.

Best practice: establish naming conventions at the start of the project. Retrofitting conventions onto a mature application is expensive and risky.

---

## Quick Reference Summary

### Entity Type Decision Tree

```
Do you need to store the data permanently?
  |
  +-- Yes --> Persistable entity
  |     |
  |     +-- Does it store files? --> Generalize from System.FileDocument
  |     +-- Does it store images? --> Generalize from System.Image
  |     +-- Is it a user type? --> Generalize from System.User (via Administration.Account)
  |     +-- Otherwise --> Standard persistable entity
  |
  +-- No --> Non-persistable entity
        |
        +-- Search form? --> NPE with search criteria attributes
        +-- API wrapper? --> NPE matching the API schema
        +-- View model? --> NPE with display attributes
        +-- Wizard state? --> NPE with step tracking
```

### Association Configuration Cheat Sheet

| Scenario | Type | Owner | Delete Behavior |
|---|---|---|---|
| Order has many OrderLines | Reference (1-*) | OrderLine owns | Delete lines with order |
| Customer has many Orders | Reference (1-*) | Order owns | Prevent delete if orders exist |
| Employee has one ParkingSpot | Reference (1-1) | Employee owns | Keep (clear reference) |
| Student enrolled in many Courses | Reference set (*-*) | Both | Keep (manual cleanup) |
| Task has optional Category | Reference (1-*) | Task owns | Keep (clear reference) |

### Index Decision Table

| Data Volume | Query Frequency | Recommendation |
|---|---|---|
| Under 1,000 rows | Any | No index needed |
| 1,000 - 10,000 rows | Frequent filters/sorts | Index filtered/sorted attributes |
| 10,000 - 100,000 rows | Any filters/sorts | Index all query-relevant attributes |
| Over 100,000 rows | Any | Index aggressively. Compound indexes for multi-attribute queries. |

### Access Rule Template

```
Entity: [EntityName]
  Role: [RoleName]
  XPath: [constraint or empty for unrestricted]
  Create: [Yes/No]
  Delete: [Yes/No]
  Attributes:
    [Attribute1]: [None/Read/Read-Write]
    [Attribute2]: [None/Read/Read-Write]
    ...
```

### Event Handler Decision Table

| Need | Handler Type |
|---|---|
| Set default values that reference other objects | Before Create |
| Validate before save | Before Commit |
| Update computed fields | Before Commit |
| Populate audit trail | Before Commit |
| Send notifications after save | After Commit |
| Trigger external integrations | After Commit |
| Prevent deletion based on business rules | Before Delete |
| Archive data before deletion | Before Delete |
| Clean up external resources | After Delete |

---

## Further Reading

- [Mendix Domain Model Documentation](https://docs.mendix.com/refguide/domain-model/)
- [Mendix Associations](https://docs.mendix.com/refguide/associations/)
- [Mendix Access Rules](https://docs.mendix.com/refguide/access-rules/)
- [Mendix Indexes](https://docs.mendix.com/refguide/indexes/)
- [Mendix Event Handlers](https://docs.mendix.com/refguide/event-handlers/)
- [Mendix Non-Persistable Objects](https://docs.mendix.com/refguide/persistability/)
- [Mendix Data Validation](https://docs.mendix.com/refguide/validation-rules/)
- [Mendix Performance Best Practices](https://docs.mendix.com/howto/general/community-best-practices-for-app-performance/)

---

<div align="center">

**[Back to Home](../README.md)**

</div>
