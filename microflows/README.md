[Home](../README.md) > **Microflows**

---

# Mendix Microflows: A Comprehensive Guide

Microflows are the backbone of server-side logic in Mendix. This guide covers everything from the basics of the microflow editor to advanced patterns, performance tuning, and debugging. It is written for developers who want practical, actionable knowledge rather than a restatement of the documentation.

---

## Table of Contents

1. [What is a Microflow](#1-what-is-a-microflow)
2. [Microflow Editor Basics](#2-microflow-editor-basics)
3. [Activities Reference](#3-activities-reference)
4. [Decisions and Branching](#4-decisions-and-branching)
5. [Loops](#5-loops)
6. [Parameters and Return Values](#6-parameters-and-return-values)
7. [Error Handling](#7-error-handling)
8. [Security](#8-security)
9. [Performance Best Practices](#9-performance-best-practices)
10. [Common Patterns](#10-common-patterns)
11. [Debugging](#11-debugging)
12. [Testing Microflows](#12-testing-microflows)
13. [Integration with Nanoflows](#13-integration-with-nanoflows)
14. [Common Pitfalls](#14-common-pitfalls)

---

## 1. What is a Microflow

A microflow is a visual representation of server-side logic in Mendix. Instead of writing lines of code in a text editor, you compose logic by dragging activities, decisions, and connectors onto a canvas. The Mendix runtime compiles this visual flow into executable code that runs on the server (Java under the hood).

### How Microflows Differ from Traditional Code

| Aspect | Traditional Code | Mendix Microflow |
|---|---|---|
| **Authoring** | Text-based (Java, C#, Python) | Visual canvas with drag-and-drop |
| **Execution** | Server (or client, depending on language) | Always server-side |
| **Version control** | Line-by-line diffs | Mendix-managed model diffs |
| **Debugging** | IDE debugger, breakpoints on lines | Studio Pro debugger, breakpoints on activities |
| **Error handling** | try/catch blocks | Error boundary activities |
| **Transaction scope** | Manually managed | Automatic per top-level microflow |
| **Access control** | Framework-dependent | Built-in role-based security |

### Microflow vs. Nanoflow vs. Java Action

Choosing the right execution mechanism matters. Here is a decision framework:

| Criterion | Microflow | Nanoflow | Java Action |
|---|---|---|---|
| **Runs on** | Server | Client (browser/device) | Server |
| **Database access** | Full (create, retrieve, change, delete, commit) | Limited (only committed data visible) | Full |
| **Network required** | Yes | No (runs offline-capable) | Yes |
| **Transaction support** | Yes (automatic rollback on error) | No | Yes (participates in microflow transaction if called from one) |
| **Use for** | Business logic, integrations, data manipulation, scheduled events | UI logic, offline apps, fast client-side validation | Complex algorithms, third-party Java libraries, performance-critical operations |
| **Visible to end user** | Causes a round-trip (loading indicator) | Instant (no server call) | Same as microflow (called from one) |
| **Security** | Role-based allowed roles | No server-side security (client-side only) | Inherits from calling microflow |

**Rules of thumb:**

- Default to a microflow for any logic that touches the database, calls external services, or needs transactional safety.
- Use a nanoflow when you need instant client-side responsiveness (e.g., toggling UI elements, simple calculations, offline logic).
- Drop to a Java action when you hit a wall: complex string manipulation, cryptography, image processing, or when you need a specific Java library.

---

## 2. Microflow Editor Basics

### Canvas Layout

The microflow editor in Studio Pro is a visual canvas. Every microflow has exactly one green **Start Event** (circle) and at least one red **End Event** (circle with a border). Logic flows left-to-right by convention, though the engine does not care about spatial arrangement.

Key areas of the editor:

| Area | Purpose |
|---|---|
| **Canvas** | The main working area where you place and connect activities |
| **Toolbox** (right panel) | Lists all available activities, decisions, and events you can drag onto the canvas |
| **Properties panel** (bottom or side) | Shows and edits properties of the selected element |
| **Toolbar** (top) | Run, debug, zoom, auto-arrange, and alignment tools |
| **Connector area** | Hover over an activity to see connection points; drag to the next activity |
| **Annotations** | Free-text boxes you can attach to activities for documentation |

### Start and End Events

**Start Event:** The single entry point. It defines the input parameters of the microflow. Double-click it to configure parameters.

**End Event:** Defines what the microflow returns. You can have multiple end events (e.g., one per branch of a decision), but every path must eventually reach one. Each end event specifies a return value. If the microflow return type is `Boolean`, every end event must return either `true` or `false`.

### Toolbar Essentials

| Button | What it does |
|---|---|
| **Run / Debug** | Starts the application in run or debug mode |
| **Auto-arrange** | Re-layouts the microflow for readability (use sparingly on large flows) |
| **Align** | Aligns selected elements horizontally or vertically |
| **Zoom** | Zoom in/out; use Ctrl+scroll for quick zooming |
| **Error list** | Shows validation errors in the current microflow |

### Naming Conventions

Mendix does not enforce naming, but consistent conventions save time:

| Type | Convention | Example |
|---|---|---|
| **Retrieve action** | Prefix with the entity name | `Order_Retrieve`, `Customer_List` |
| **Decision** | Phrase as a question | `Is order valid?`, `Has active subscription?` |
| **Microflow name** | `ACT_` (page action), `SUB_` (sub-microflow), `SE_` (scheduled event), `DS_` (data source), `VAL_` (validation) | `ACT_Order_Submit`, `SUB_Email_Send`, `SE_CleanupExpiredSessions` |
| **Variables** | camelCase, descriptive | `orderTotal`, `isApproved`, `customerList` |

---

## 3. Activities Reference

Activities are the building blocks of microflows. Each one performs a specific operation. Below is a detailed reference for the most commonly used activities.

### Object Activities

#### Create Object

Creates a new in-memory object of a specified entity. The object is **not** committed to the database until you explicitly commit it.

| Property | Description |
|---|---|
| **Entity** | The entity to instantiate |
| **Commit** | `Yes` commits immediately; `No` keeps in memory; `Yes without events` skips before/after commit event handlers |
| **Member values** | Set initial attribute values and associations |
| **Variable name** | The name you use to reference this object later in the flow |

**Example pseudocode:**
```
Create OrderLine
  Entity: MyModule.OrderLine
  Commit: No
  Set Quantity = $InputQuantity
  Set Product = $SelectedProduct
  Set Order = $CurrentOrder
  Output: $NewOrderLine
```

**Tip:** Prefer `Commit: No` and batch your commits. Creating and committing in a loop is one of the most common performance mistakes (see [Performance Best Practices](#9-performance-best-practices)).

#### Change Object

Modifies attributes or associations on an existing object. Does not create a new object.

| Property | Description |
|---|---|
| **Object** | The variable to change |
| **Commit** | Same options as Create Object |
| **Refresh in client** | If `Yes`, the UI updates to reflect changes (only relevant if this microflow is called from a page) |
| **Member values** | The attributes/associations to change |

**When to refresh in client:** Only set this to `Yes` on the last change activity for a given object in a flow, and only if the user is looking at a page that displays this data. Unnecessary refreshes cause extra round-trips.

#### Delete Object(s)

Permanently removes object(s) from the database. This is immediate and cannot be undone within the same microflow (there is no "soft delete" built in).

| Property | Description |
|---|---|
| **Object(s)** | A single object variable or a list variable |
| **Refresh in client** | Whether to update the UI |

**Warning:** Deleting a committed object is permanent. If the microflow fails after the delete but before the end event, the transaction rolls back and the delete is undone. However, if the delete happens in a separate transaction (e.g., in a sub-microflow with its own error handling), it stays deleted.

#### Retrieve

Fetches objects from the database or from an in-memory association. This is the activity you will use most often.

| Property | Description |
|---|---|
| **Source** | `Database` (SQL query) or `By association` (in-memory traversal) |
| **Entity** | The entity to retrieve |
| **XPath constraint** | Filter expression (only for database retrieves) |
| **Sorting** | Order the results |
| **Range** | `All`, `First`, or `Custom` (offset + limit) |
| **Variable name** | Output variable (a list, or a single object if Range is `First`) |

**Database vs. By Association:**

| Factor | Database | By Association |
|---|---|---|
| **When to use** | You need filtered/sorted data from the DB | You already have the parent object and need related objects |
| **Performance** | SQL query each time | No query if objects are already loaded in context |
| **XPath** | Supported | Not applicable |
| **Returns** | Fresh data from DB | In-memory state (may include uncommitted changes) |
| **Gotcha** | May not see uncommitted objects | May see stale data if another user changed the DB |

**XPath constraint examples:**
```
[Amount > 100]
[Status = 'Approved']
[MyModule.Order_Customer/MyModule.Customer/Name = $CustomerName]
[CreatedDate > '[%BeginOfCurrentDay%]']
```

#### Aggregate List

Performs a calculation over a list of objects without retrieving all individual objects. Significantly more efficient than retrieving a full list and iterating.

| Function | Description | Example |
|---|---|---|
| **Count** | Number of objects | Count of OrderLines for an Order |
| **Sum** | Sum of a numeric attribute | Total revenue |
| **Average** | Average of a numeric attribute | Average order value |
| **Minimum** | Lowest value | Earliest date |
| **Maximum** | Highest value | Largest order amount |

**Tip:** Always prefer Aggregate List over retrieving a list and looping to calculate sums or counts. The aggregate runs as a SQL function on the database, which is orders of magnitude faster for large datasets.

#### Commit Object(s)

Writes in-memory changes to the database. Any objects created or changed with `Commit: No` remain in memory until you explicitly commit them.

| Property | Description |
|---|---|
| **Object(s)** | A single object or a list |
| **With events** | `Yes` fires before/after commit event handlers; `No` skips them |
| **Refresh in client** | Whether to update the UI |

**Transaction behavior:** All commits within a top-level microflow share the same database transaction. If the microflow fails (unhandled error), all commits roll back.

### Integration Activities

#### Java Action Call

Calls a Java action defined in your project or a marketplace module. Use this when visual logic is insufficient.

| Property | Description |
|---|---|
| **Java action** | The action to call |
| **Parameters** | Map microflow variables to Java action parameters |
| **Output variable** | The return value |

**Common uses:** Encryption/decryption, file manipulation, complex regex, calling native Java libraries, performance-critical loops.

#### Microflow Call

Calls another microflow as a sub-microflow. The called microflow runs within the same transaction unless you configure error handling to create a separate transaction.

| Property | Description |
|---|---|
| **Microflow** | The microflow to call |
| **Parameters** | Map variables to the sub-microflow's input parameters |
| **Output variable** | Captures the return value |

**Tip:** Use sub-microflows to break complex logic into reusable, testable units. A microflow with more than 15-20 activities is a candidate for decomposition.

### Logging and User Feedback

#### Log Message

Writes a message to the Mendix runtime log. Essential for debugging and audit trails in production.

| Property | Description |
|---|---|
| **Log level** | `Trace`, `Debug`, `Info`, `Warning`, `Error`, `Critical` |
| **Log node** | A category string (e.g., `OrderProcessing`, `Integration_SAP`) |
| **Template** | The message text, can include `{1}`, `{2}` placeholders |
| **Parameters** | Values to substitute into the template |

**Log level guidance:**

| Level | Use for |
|---|---|
| **Trace** | Extremely verbose, loop iterations, variable dumps |
| **Debug** | Development-time diagnostics |
| **Info** | Normal operational events (order created, email sent) |
| **Warning** | Unexpected but recoverable situations |
| **Error** | Failures that need attention |
| **Critical** | System-level failures (database down, out of memory) |

**Example:**
```
Log Message
  Level: Info
  Node: OrderProcessing
  Template: "Order {1} submitted by {2}, total: {3}"
  Parameters: $Order/OrderNumber, $CurrentUser/Name, $Order/TotalAmount
```

#### Show Message

Displays a pop-up message to the user. Only works when the microflow is triggered from the UI (not from a scheduled event or web service).

| Property | Description |
|---|---|
| **Type** | `Information`, `Warning`, `Error` |
| **Template** | Message text with optional placeholders |
| **Blocking** | If `Yes`, the user must dismiss the dialog before continuing |

#### Download File

Sends a file document to the user's browser for download.

| Property | Description |
|---|---|
| **File document** | The `System.FileDocument` (or specialization) to download |
| **Show file in browser** | If `Yes`, attempts to display in-browser (e.g., PDF). If `No`, forces download. |

**Tip:** Generate files (Excel, PDF, CSV) using marketplace modules like the Excel Exporter or Document Generation, then use Download File as the last step.

---

## 4. Decisions and Branching

Decisions allow your microflow to take different paths based on conditions. They are equivalent to `if/else` and `switch` statements in traditional code.

### Exclusive Split (Boolean)

The most common decision. Evaluates an expression to `true` or `false` and takes one of two outgoing paths.

**Visual:** A diamond shape with two outgoing connectors labeled `true` and `false`.

**Expression examples:**

| Expression | Evaluates |
|---|---|
| `$Order/Status = 'Approved'` | Enum comparison |
| `$Order/TotalAmount > 1000` | Numeric comparison |
| `$Customer != empty` | Null check |
| `$OrderList != empty` | List not empty (has at least one item) |
| `$Order/TotalAmount > 1000 and $Customer/IsVIP` | Compound condition |
| `length($Order/Description) > 0` | String length check |
| `contains($Email, '@')` | String contains |

**Pseudocode pattern — guard clause:**
```
Start
  -> Retrieve $Order from database
  -> Decision: $Order != empty?
     true  -> Continue with business logic
     false -> Show message "Order not found" -> End (return false)
```

### Exclusive Split (Enumeration)

When your decision has more than two outcomes, use an enumeration split. Each enum value gets its own outgoing path.

**Example:** An `OrderStatus` enum with values `Draft`, `Submitted`, `Approved`, `Shipped`, `Cancelled`.

```
Decision: $Order/Status
  -> Draft:     Show message "Cannot process draft orders"
  -> Submitted: Call SUB_Order_Validate
  -> Approved:  Call SUB_Order_FulfillApproval
  -> Shipped:   Call SUB_Order_TrackShipment
  -> Cancelled: Log warning, end
```

**Tip:** Always handle every enum value, or add a default path. Unhandled values cause runtime errors.

### Inheritance Split

Used when you have a generalization/specialization hierarchy. The decision checks the actual runtime type of an object.

**Example:** You have `Document` (generalization) with specializations `Invoice`, `Receipt`, and `Contract`. An inheritance split on a `$Document` variable creates one path per specialization.

```
Inheritance split: $Document
  -> Invoice:  Cast to Invoice, process invoice logic
  -> Receipt:  Cast to Receipt, process receipt logic
  -> Contract: Cast to Contract, process contract logic
```

After the split, each path gives you a variable cast to the specific type, so you can access specialization-specific attributes.

### Merge

A merge brings multiple paths back together into a single flow. It is a diamond shape with multiple incoming connectors and one outgoing connector. No logic executes at the merge; it simply rejoins paths.

**When to use:** After a decision where both branches eventually continue with the same subsequent logic.

```
Decision: $Order/IsUrgent?
  true  -> Change $Order/Priority = 'High'
  false -> Change $Order/Priority = 'Normal'
  -> Merge -> Commit $Order -> End
```

### Error Handling with Custom Error Handlers

Every activity can have a custom error handler attached. Instead of the default behavior (abort the microflow and roll back), you can catch the error and handle it.

**Setting up a custom error handler:**

1. Right-click an activity (or select a range of activities).
2. Choose "Set error handler."
3. Select an activity to route to when an error occurs.
4. The error handler path is shown as a red connector.

**Error handler flow:**

| Element | Description |
|---|---|
| **Error handler connector** | Red dashed line from the failing activity to the error handler path |
| **$latestError** | A `System.Error` object automatically available in the error handler scope |
| **$latestError/Message** | The error message string |
| **$latestError/Name** | The error class name |
| **Error handler end event** | Can return a value or re-throw |

**Example: Wrapping a REST call with error handling:**
```
Start
  -> Call REST service (with custom error handler)
     Success -> Parse response -> End (return $Result)
     Error   -> Log Error: "REST call failed: {1}" with $latestError/Message
             -> Create ErrorResponse object
             -> End (return $ErrorResponse)
```

**Important:** When you set a custom error handler on an activity, the transaction is **not** rolled back for that error. Any commits that happened before the error are retained. If you want to roll back, you must explicitly throw an error (using an End Event with a custom error message) from your error handler path.

---

## 5. Loops

### Loop Activity

The loop activity iterates over a list. On each iteration, a single object from the list is available as the loop variable.

| Property | Description |
|---|---|
| **Iterate over** | A list variable |
| **Loop variable name** | The name for the current item in each iteration |

**Visual:** A rectangular container on the canvas. You place activities inside the loop container, and they execute once per item in the list.

**Basic loop pseudocode:**
```
Retrieve $OrderLineList from database
  -> Loop over $OrderLineList as $CurrentOrderLine
       -> Change $CurrentOrderLine/Subtotal = $CurrentOrderLine/Quantity * $CurrentOrderLine/UnitPrice
  -> Commit $OrderLineList   <-- commit OUTSIDE the loop
  -> End
```

### Break and Continue Patterns

Mendix does not have explicit `break` or `continue` activities, but you can achieve the same effect:

**Continue pattern (skip an iteration):**
```
Loop over $List as $Item
  -> Decision: Should skip?
     true  -> (connect directly to the end of the loop body, no further activities)
     false -> Process $Item
```

Place a decision at the start of the loop body. The `true` branch connects to the loop's closing point (the merge at the bottom of the loop container), skipping the remaining activities.

**Break pattern (exit the loop early):**

There is no native break. Workarounds:

1. **Boolean flag:** Create a `$ShouldStop` Boolean variable before the loop. Set it to `true` when you want to break. Add a decision at the top of the loop: if `$ShouldStop`, skip all activities. The loop still iterates over remaining items but does nothing.

2. **Filter the list first:** If you know you only need a subset, filter or limit the list before entering the loop. Use an XPath constraint or the `List operation` activity to reduce the list.

3. **Use a Java action:** For truly complex iteration with early termination, a Java action may be cleaner.

### Performance Considerations for Loops

Loops are where most performance problems originate. Here are the critical rules:

| Do | Do Not |
|---|---|
| Commit the list **after** the loop | Commit each object **inside** the loop |
| Retrieve associated data **before** the loop (batch retrieve) | Retrieve inside the loop (N+1 problem) |
| Use Aggregate List for sums/counts | Loop and accumulate manually |
| Process in batches for very large lists (1000+ objects) | Iterate over unbounded lists |
| Use a list variable to collect objects, then commit the list once | Create + commit individual objects per iteration |

**Batch processing pattern for large lists:**
```
Set $Offset = 0
Set $BatchSize = 500
Set $HasMore = true

Loop while $HasMore:
  Retrieve $Batch from DB [range: $Offset to $Offset + $BatchSize]
  Decision: $Batch is empty?
    true  -> Set $HasMore = false
    false -> Process $Batch
             Commit $Batch
             Set $Offset = $Offset + $BatchSize
```

Since Mendix does not have a while loop, you implement this with a microflow that calls itself recursively or use a loop over a sufficiently large dummy list with a break flag.

---

## 6. Parameters and Return Values

### Input Parameters

Input parameters define what data the microflow needs to execute. They are configured on the Start Event.

| Parameter type | Description | Example |
|---|---|---|
| **Object** | A single entity instance | `$Order` (MyModule.Order) |
| **List** | A list of entity instances | `$OrderLines` (List of MyModule.OrderLine) |
| **Boolean** | True/false | `$IsApproved` |
| **Integer/Long** | Whole number | `$Quantity` |
| **Decimal** | Decimal number | `$TotalAmount` |
| **String** | Text | `$SearchQuery` |
| **DateTime** | Date and time | `$StartDate` |
| **Enumeration** | An enum value | `$Status` (MyModule.OrderStatus) |

### Passing Objects vs. Lists

| Consideration | Single Object | List |
|---|---|---|
| **When to use** | Operating on one specific record | Batch operations, multi-select actions |
| **Memory impact** | Minimal | Proportional to list size |
| **Association traversal** | Direct (e.g., `$Order/Customer`) | Must loop or use list operations |
| **Null safety** | Always check `!= empty` | Check list is not empty, and individual items if needed |

**Important behavior: object references are passed by reference.** When you pass an object to a sub-microflow and the sub-microflow changes it, the changes are visible in the calling microflow too, even without committing. This is because both microflows reference the same in-memory object.

```
Main microflow:
  Create $Order (Commit: No)
  Call SUB_SetDefaults($Order)   <-- SUB changes $Order/Status to 'Draft'
  -> At this point, $Order/Status is already 'Draft' in the main flow
  Commit $Order
```

### Return Values

Every microflow has a return type. It can be:

| Return type | Description |
|---|---|
| **Nothing** | The microflow does not return a value (void) |
| **Boolean** | Common for validation microflows |
| **String** | Return a message or identifier |
| **Integer/Long** | Return a count or ID |
| **Decimal** | Return a calculated value |
| **DateTime** | Return a date |
| **Enumeration** | Return a status |
| **Object** | Return a single entity instance |
| **List** | Return a list of entity instances |

**Setting the return value:** Each End Event has a "Return value" field. If your microflow has multiple end events (e.g., after a decision), each one must specify a return value of the declared return type.

**Mapping outputs in the caller:**

When you call a sub-microflow, the output is assigned to a variable:
```
Call SUB_CalculateTotal($Order)
  Output variable: $CalculatedTotal (Decimal)
```

You can then use `$CalculatedTotal` in subsequent activities and expressions.

### Passing Data to Pages

When a microflow is used as a page action (e.g., button click), the page's data view object is automatically available as a parameter. You do not need to configure this manually; Mendix infers it from the context.

When a microflow is used as a data source for a data view, the microflow must return an object of the entity the data view expects.

When a microflow is used as a data source for a list view or data grid, the microflow must return a list.

---

## 7. Error Handling

### The Default: Automatic Rollback

By default, if any activity in a microflow throws an error, the entire microflow aborts. All database changes made within that microflow's transaction are rolled back. The user sees a generic error message.

This is the safest default. You do not lose data, and the system remains consistent.

### Error Boundaries

An error boundary wraps a section of your microflow in a "try/catch" equivalent. You define:

1. **The scope:** Which activities are covered by the error handler.
2. **The error handler path:** Where to route execution if an error occurs within the scope.
3. **The rollback behavior:** Whether to roll back changes made within the scope.

**Rollback options on error handler:**

| Option | Behavior |
|---|---|
| **Rollback** | All database changes since the last commit point within the scope are undone |
| **No rollback** | Changes are preserved (use with caution) |

### Custom Error Handlers in Practice

**Pattern: Retry with logging**
```
Start
  -> Call REST service [error handler -> $RetryPath]
     Success -> Process response -> End

$RetryPath:
  -> Log Warning: "First attempt failed: {1}" with $latestError/Message
  -> Call REST service (second attempt) [error handler -> $FinalErrorPath]
     Success -> Process response -> End

$FinalErrorPath:
  -> Log Error: "REST call failed after retry: {1}" with $latestError/Message
  -> Show message: "Service unavailable, please try again later"
  -> End
```

**Pattern: Catch and wrap**
```
Start
  -> [Error handler on entire section -> $CatchPath]
     -> Retrieve data
     -> Process data
     -> Commit
     -> End (return true)

$CatchPath:
  -> Log Error with $latestError/Message
  -> Create $ErrorLog object with details
  -> Commit $ErrorLog (without events)
  -> End (return false)
```

### Rollback Behavior Deep Dive

Understanding transaction scope is critical for correct error handling:

| Scenario | What happens |
|---|---|
| **Unhandled error, no custom error handler** | Entire microflow transaction rolls back. All creates, changes, deletes are undone. |
| **Custom error handler with rollback** | Only changes within the error boundary scope are rolled back. Changes committed before the scope are retained. |
| **Custom error handler without rollback** | Nothing is rolled back. All changes (including those that led to the error) are retained. |
| **Sub-microflow called with its own error handler** | The sub-microflow's error handler controls rollback within its scope. The calling microflow continues on the error path. |

**Gotcha:** Objects that were changed but not committed are still changed in memory even after rollback. Rollback only affects the database. If you continue using a changed-but-rolled-back object, it still has the changed values in memory. Retrieve it again from the database to get the clean state.

### Logging Strategies

A good logging strategy makes production debugging possible. Here are recommendations:

| Strategy | Implementation |
|---|---|
| **Structured log nodes** | Use dot-separated log nodes: `Module.Feature.Operation` (e.g., `Order.Payment.Charge`) |
| **Correlation IDs** | Pass a unique ID (e.g., UUID) through sub-microflows and include it in every log message |
| **Input/output logging** | Log input parameters at the start and return values at the end (at Debug level) |
| **Error context** | When logging errors, include the object ID, user, and operation that failed |
| **Log levels per environment** | Use `Trace`/`Debug` in development, `Info`/`Warning` in production |

**Example: Structured logging in a payment flow**
```
Start ($Order, $PaymentMethod)
  -> Log Debug [Payment.Process]: "Starting payment for Order {1}, method {2}"
  -> Call Payment Gateway [error handler -> $ErrorPath]
  -> Log Info [Payment.Process]: "Payment successful for Order {1}, transaction {2}"
  -> End

$ErrorPath:
  -> Log Error [Payment.Process]: "Payment failed for Order {1}: {2}" with $Order/Id, $latestError/Message
  -> End
```

---

## 8. Security

### Allowed Roles

Every microflow has an "Allowed roles" property. Only users with one of the listed roles can execute the microflow.

| Configuration | Behavior |
|---|---|
| **No roles selected** | Only callable from other microflows, scheduled events, or web services. Not directly accessible from pages. |
| **Specific roles selected** | Only users with those roles can trigger the microflow from the UI or call it via API |
| **All roles selected** | Any authenticated user can execute it |

**Tip:** Follow the principle of least privilege. If a microflow deletes data, only give access to Administrator or a specific management role.

### Entity Access vs. Microflow Security

There are two layers of security, and they interact in important ways:

| Layer | What it controls | When it applies |
|---|---|---|
| **Entity access** | Which attributes and associations a user can read/write, which objects they can create/delete | Always (unless explicitly disabled on the microflow) |
| **Microflow security (allowed roles)** | Who can execute the microflow | When the microflow is called from the UI or API |

**Critical concept:** By default, entity access rules apply inside microflows. This means that even if a microflow retrieves all Orders, a user with the `Customer` role will only see their own Orders (assuming entity access is configured that way).

### The "Apply Entity Access" Parameter

Each microflow has an "Apply entity access" checkbox:

| Setting | Behavior | When to use |
|---|---|---|
| **Enabled (checked)** | Entity access rules are applied. Retrieves are filtered, attribute reads/writes are restricted. | Default for user-facing microflows. Use this when you want the security layer to protect data. |
| **Disabled (unchecked)** | Entity access rules are bypassed. The microflow runs with full access. | Scheduled events, system-level operations, web services where you handle authorization yourself. |

**Warning:** Disabling entity access is a security decision. If you disable it, your microflow can see and modify all data regardless of the user's role. Only do this when:

- The microflow runs as a scheduled event (no user context).
- The microflow is a web service handler where you implement custom authorization.
- You explicitly need system-level access (e.g., admin dashboard calculations).

**Common mistake:** Developers disable entity access because a retrieve "doesn't return data" during testing. The real fix is to configure entity access rules correctly, not to bypass them.

### Practical Security Checklist

| Check | Why |
|---|---|
| Set allowed roles on every user-facing microflow | Prevents unauthorized access |
| Keep "Apply entity access" enabled unless you have a specific reason | Defense in depth |
| Do not expose delete microflows to end users without confirmation | Prevents accidental data loss |
| Validate input parameters in the microflow | Users can manipulate page data |
| Log security-relevant actions (role changes, data exports) | Audit trail |
| Use separate microflows for admin vs. user operations | Cleaner security boundaries |

---

## 9. Performance Best Practices

### Batch Commits

The single most impactful optimization: **never commit inside a loop.**

**Bad:**
```
Loop over $OrderLines as $Line
  -> Change $Line/Subtotal = ...
  -> Commit $Line              <-- N separate database transactions!
```

**Good:**
```
Loop over $OrderLines as $Line
  -> Change $Line/Subtotal = ... (Commit: No)
-> Commit $OrderLines           <-- Single bulk commit after the loop
```

Performance comparison:

| Approach | 100 objects | 1,000 objects | 10,000 objects |
|---|---|---|---|
| Commit per object | ~2s | ~20s | ~200s+ |
| Batch commit | ~0.1s | ~0.5s | ~3s |

These are rough estimates, but the magnitude of difference is real.

### Avoiding N+1 Retrieves

The N+1 problem occurs when you retrieve a list of N objects, then inside a loop, retrieve associated data for each object individually.

**Bad (N+1):**
```
Retrieve $Orders (100 orders)
Loop over $Orders as $Order
  -> Retrieve $Customer by association $Order/Customer   <-- 100 individual retrievals!
  -> Use $Customer/Name
```

**Good (batch retrieve):**
```
Retrieve $Orders (100 orders)
Retrieve $Customers from database [MyModule.Order_Customer/MyModule.Order/Id = $Orders/Id]
   -- or use a single retrieve with appropriate XPath
Loop over $Orders as $Order
  -> Retrieve $Customer by association $Order/Customer   <-- Already in memory, no DB hit
```

The second approach leverages the fact that Mendix caches retrieved objects in memory within a request. If you retrieve the associated customers in one batch query first, the "by association" retrieves inside the loop are served from the cache.

Alternatively, if you only need customer data for display, consider using a data view with a nested data source rather than a microflow loop.

### Optimizing Loops

| Technique | Description |
|---|---|
| **Move retrieves outside** | Retrieve all needed data before the loop starts |
| **Collect and commit** | Add changed objects to a list, commit the list after the loop |
| **Filter before looping** | Use XPath constraints to reduce the list size before iterating |
| **Use Aggregate List** | For sums, counts, averages, use the database function instead of looping |
| **Limit list size** | Always set a range on retrieves (e.g., first 1000). Unbounded retrieves on large tables are dangerous. |
| **Consider Java for heavy computation** | If your loop does complex calculations over thousands of objects, a Java action may be 10-100x faster |

### Limiting Retrieved Data

Always ask: "Do I need all these objects?"

| Technique | How |
|---|---|
| **XPath constraints** | Filter at the database level: `[Status = 'Active']` |
| **Range: First** | When you only need one object, use Range: First instead of retrieving a list and taking the head |
| **Range: Custom** | Paginate large datasets: offset + limit |
| **Sorting + limit** | Get the "top N" by sorting and limiting |
| **Attribute-level** | If you only need one attribute, consider Aggregate List or a dedicated microflow that returns just that value |

### XPath vs. Database Retrieve

Both retrieve from the database, but they are configured differently:

| Aspect | XPath Retrieve | OQL (via Dataset) |
|---|---|---|
| **Ease of use** | Simple, visual | Requires SQL-like knowledge |
| **Joins** | Implicit through associations | Explicit JOIN syntax |
| **Aggregation** | Limited (use Aggregate List activity) | Full GROUP BY, HAVING support |
| **Subqueries** | Not supported | Supported |
| **Use case** | Standard CRUD operations | Reporting, complex queries, analytics |

**XPath performance tips:**

- Use indexed attributes in constraints for faster lookups.
- Avoid `contains()` on large text fields (no index, full scan).
- Prefer `=` over `contains()` when checking exact values.
- Use `[%CurrentDateTime%]` tokens instead of passing calculated dates.
- Limit the depth of association traversals (each `/` can add a JOIN).

---

## 10. Common Patterns

### Guard Clause Pattern

Validate preconditions at the top of the microflow and exit early if they fail. This keeps the "happy path" logic clean and un-nested.

```
Start ($Order)
  -> Decision: $Order = empty?
     true  -> Log Warning "Order is null" -> End (return false)
     false -> continue
  -> Decision: $Order/Status != 'Draft'?
     true  -> Show message "Only draft orders can be submitted" -> End (return false)
     false -> continue
  -> [Main business logic here]
  -> End (return true)
```

**Benefits:** Each guard clause handles one specific precondition. The main logic only executes when all preconditions are met. This is much easier to read than deeply nested decisions.

### Service Integration (REST Call + Response Handling)

A complete pattern for calling an external REST API:

```
Start ($CustomerId)
  -> Create request headers (if needed)
  -> Call REST service (GET https://api.example.com/customers/{1})
     [Error handler -> $ServiceErrorPath]
     -> HTTP Response: $HttpResponse
     -> Decision: $HttpResponse/StatusCode = 200?
        true  -> Import mapping: JSON -> CustomerResponse entity
               -> Process $CustomerResponse
               -> End (return $CustomerResponse)
        false -> Log Warning "Unexpected status: {1}" with $HttpResponse/StatusCode
               -> End (return empty)

$ServiceErrorPath:
  -> Log Error "REST call failed: {1}" with $latestError/Message
  -> Decision: Is timeout? (check $latestError/Message contains "timeout")
     true  -> Retry logic or return cached data
     false -> End (return empty)
```

**Key considerations for integrations:**

| Concern | Solution |
|---|---|
| **Timeouts** | Configure timeout on the REST call activity (default is often 30s, reduce if possible) |
| **Retries** | Implement retry logic with exponential backoff for transient failures |
| **Response validation** | Always check the HTTP status code before processing the body |
| **Error mapping** | Map error responses to your domain's error entity |
| **Logging** | Log request URL (without sensitive params), status code, and response time |
| **Certificates** | Configure client certificates in the Mendix runtime settings, not in the microflow |

### Validation Microflow

Used as a form validation before save/submit. Returns a Boolean or a string with an error message.

```
Microflow: VAL_Order_BeforeSubmit
Parameters: $Order
Return type: String (empty = valid, non-empty = error message)

Start ($Order)
  -> Decision: $Order/CustomerName = empty or length($Order/CustomerName) = 0?
     true  -> End (return "Customer name is required")
  -> Decision: $Order/TotalAmount <= 0?
     true  -> End (return "Order total must be greater than zero")
  -> Decision: $Order/OrderLines is empty? (retrieve by association, count = 0)
     true  -> End (return "Order must have at least one line item")
  -> End (return '')   <-- empty string = no error = valid
```

**In the calling page:** Set the button's microflow to call `VAL_Order_BeforeSubmit`. Check the return value. If non-empty, show the error message. If empty, proceed with the submit logic.

**Alternative approach:** Return a Boolean and use `addFeedback` (via a Java action or the Community Commons module) to show field-level validation messages.

### Scheduled Event Microflow

Scheduled events run on a timer (every X minutes/hours/days). They have no user context and no UI.

```
Microflow: SE_CleanupExpiredSessions
Parameters: None
Return type: Nothing
Apply entity access: No (no user context)

Start
  -> Log Info [Scheduler.Cleanup]: "Starting session cleanup"
  -> Retrieve $ExpiredSessions [ExpiryDate < '[%CurrentDateTime%]']
     Range: First 1000 (always limit!)
  -> Decision: $ExpiredSessions is empty?
     true  -> Log Info "No expired sessions found" -> End
  -> Delete $ExpiredSessions
  -> Log Info "Deleted {1} expired sessions" with length($ExpiredSessions)
  -> End
```

**Scheduled event best practices:**

| Practice | Why |
|---|---|
| Always limit retrieve range | Prevents memory issues on large tables |
| Process in batches | Long-running operations should commit in batches to avoid lock contention |
| Log start and end | So you can see in production logs when the job ran and how long it took |
| Set "Apply entity access" to No | There is no user context in a scheduled event |
| Handle errors gracefully | An unhandled error in a scheduled event logs a stack trace but does not alert anyone by default. Add explicit error handling and notifications. |
| Use a guard clause for concurrent runs | Prevent overlapping executions by checking/setting a flag in the database |

### Before/After Commit Event Handlers

Event handlers fire automatically when objects are created, changed, committed, deleted, or rolled back. They are configured on the entity, not on the microflow.

**Before Commit:**
```
Microflow: BCo_Order_BeforeCommit
Parameters: $Order
Return type: Boolean (true = allow commit, false = cancel commit)

Start ($Order)
  -> Change $Order/LastModified = [%CurrentDateTime%]
  -> Decision: $Order/TotalAmount < 0?
     true  -> End (return false)   <-- prevents the commit!
  -> End (return true)
```

**After Commit:**
```
Microflow: ACo_Order_AfterCommit
Parameters: $Order
Return type: Nothing

Start ($Order)
  -> Decision: $Order/Status has changed to 'Approved'?
     true  -> Call SUB_SendApprovalEmail($Order)
             -> Call SUB_NotifyWarehouse($Order)
  -> End
```

**Event handler caveats:**

| Caveat | Detail |
|---|---|
| **Runs inside the same transaction** | If the before-commit handler fails, the commit is cancelled. If the after-commit handler fails, the entire transaction (including the commit) is rolled back. |
| **Fires on every commit** | Including commits from scheduled events, web services, and other microflows. Make sure your handler logic is efficient. |
| **Recursive triggers** | If your commit handler changes and commits another object that has its own handler, you can get infinite loops. Guard against this. |
| **Commit without events** | Use `Commit: Yes without events` to skip handlers when you know they are not needed (e.g., bulk imports). |
| **No UI context** | Event handlers may fire without a user session (e.g., from a scheduled event). Do not use Show Message or other UI activities. |

---

## 11. Debugging

### Setting Breakpoints

In Studio Pro, you can set breakpoints on any activity in a microflow:

1. Right-click an activity and choose "Toggle Breakpoint" (or press F9 with the activity selected).
2. A red dot appears on the activity.
3. Run the application in Debug mode (F6 or the Debug button).
4. When execution reaches the breakpoint, Studio Pro pauses and highlights the activity.

### Stepping Through

Once execution is paused at a breakpoint:

| Action | Shortcut | Description |
|---|---|---|
| **Step over** | F8 | Execute the current activity and move to the next one |
| **Step into** | F7 | If the current activity is a microflow call, enter that microflow |
| **Step out** | Shift+F8 | Run the rest of the current sub-microflow and return to the caller |
| **Continue** | F9 | Resume execution until the next breakpoint |

### Variable Inspection

When paused at a breakpoint, the **Variables** pane shows:

- All variables in scope (parameters, created objects, loop variables).
- Object attributes and their current values.
- Association targets (you can expand to see associated objects).
- List variables with their current size and contents.

**Tip:** You can add expressions to the **Watch** pane to evaluate custom expressions in real-time.

### Common Debugging Scenarios

#### Scenario 1: Retrieve Returns No Data

**Symptoms:** A retrieve activity returns an empty list or `empty` object when you expect data.

**Debugging steps:**
1. Set a breakpoint on the retrieve activity.
2. Step over it and check the output variable.
3. If empty, check:
   - Is "Apply entity access" enabled? If so, does the current user have access to the entity?
   - Is the XPath constraint correct? Copy it and test in a data grid.
   - Are you looking for uncommitted objects? Database retrieves only find committed data.
   - Is the data actually in the database? Check with a data grid on a test page.

#### Scenario 2: Object Values Are Unexpected

**Symptoms:** An object's attributes have values you did not expect at a certain point in the flow.

**Debugging steps:**
1. Set breakpoints before and after each Change Object activity.
2. Inspect the object at each step.
3. Check if a sub-microflow is modifying the object (remember: objects are passed by reference).
4. Check if a before/after commit handler is changing the object.

#### Scenario 3: Error in Production (No Debugger)

**Approach:**
1. Add `Log Message` activities at strategic points (before/after key activities, in error handlers).
2. Use structured log nodes so you can filter by module.
3. Include the object ID and user name in log messages.
4. Use the Mendix Developer Portal or runtime logs to find the relevant log entries.
5. Reproduce locally with the same data if possible.

#### Scenario 4: Microflow Takes Too Long

**Debugging steps:**
1. Add `Log Message` activities with timestamps at the start and end of suspected slow sections.
2. Check for N+1 retrieve patterns (retrieves inside loops).
3. Check for commits inside loops.
4. Use the Mendix runtime statistics (Admin → Runtime Statistics) to see which microflows take the most time.
5. Look at the database query log for slow queries.

### Debugger Limitations

| Limitation | Workaround |
|---|---|
| Cannot debug nanoflows | Use browser developer tools (console.log equivalent) |
| Cannot debug scheduled events easily | Trigger the same microflow from a test page instead |
| Multi-user debugging can be confusing | Set breakpoints only on your own session (user-specific breakpoints) |
| Breakpoints do not persist across Studio Pro restarts by default | Re-set them or save a debug configuration |

---

## 12. Testing Microflows

### The Unit Testing Module

Mendix provides the **UnitTesting** module (available from the Marketplace) for automated testing of microflows.

**Setup:**
1. Download the UnitTesting module from the Marketplace.
2. Add the `UnitTesting.TestSuite` page to your navigation.
3. Create test microflows following the naming convention.

### Writing Test Microflows

Test microflows follow specific conventions:

| Convention | Detail |
|---|---|
| **Module** | Place test microflows in a `_Tests` or `Tests` module (or folder) |
| **Naming** | Prefix with `Test_`: e.g., `Test_Order_CalculateTotal` |
| **Parameters** | Test microflows must have no input parameters |
| **Return type** | Boolean: `true` = pass, `false` = fail |
| **Registration** | The UnitTesting module discovers test microflows by naming convention |

**Test microflow structure:**
```
Microflow: Test_Order_CalculateTotal
Parameters: None
Return type: Boolean

Start
  -> Create $Order (Commit: No)
     Set Status = 'Draft'
  -> Create $OrderLine1 (Commit: No)
     Set Quantity = 2, UnitPrice = 10.00, Order = $Order
  -> Create $OrderLine2 (Commit: No)
     Set Quantity = 1, UnitPrice = 25.00, Order = $Order
  -> Call SUB_Order_CalculateTotal($Order)
  -> Decision: $Order/TotalAmount = 45.00?
     true  -> End (return true)     <-- Test passes
     false -> Log Error "Expected 45.00, got {1}" with $Order/TotalAmount
             -> End (return false)  <-- Test fails
```

### Structuring Testable Logic

To make microflows testable, follow these design principles:

| Principle | How to apply |
|---|---|
| **Separate logic from UI** | Keep Show Message, Download File, and page navigation in a thin "action" microflow. Put business logic in a separate sub-microflow that can be tested in isolation. |
| **Pure functions** | Where possible, design microflows that take inputs and return outputs without side effects (no commits, no external calls). Test these easily. |
| **Inject dependencies** | Instead of hardcoding a REST endpoint, pass it as a parameter or use a configuration entity. In tests, point to a mock. |
| **Small microflows** | A microflow that does one thing is easier to test than a 50-activity monolith. |
| **Avoid relying on currentUser** | Pass the user (or user data) as a parameter so tests can provide a test user. |

### Testing Patterns

**Arrange-Act-Assert:**
```
-- Arrange
Create test data (objects with known values)

-- Act
Call the microflow under test

-- Assert
Check that output matches expected values
Check that objects were created/changed/deleted as expected
Return true if all assertions pass, false otherwise
```

**Cleanup:**
Test microflows should clean up after themselves. Delete any objects created during the test, or run tests within a transaction that gets rolled back (the UnitTesting module can be configured to do this).

**Testing error cases:**
```
Microflow: Test_Order_RejectInvalidTotal
Start
  -> Create $Order with TotalAmount = -100
  -> Call SUB_Order_Validate($Order)
     [Error handler -> $ExpectedError]
  -> Log Error "Expected an error but none was thrown"
  -> End (return false)

$ExpectedError:
  -> Decision: $latestError/Message contains "Total must be positive"?
     true  -> End (return true)
     false -> Log Error "Wrong error message: {1}" with $latestError/Message
             -> End (return false)
```

---

## 13. Integration with Nanoflows

### When to Call a Microflow from a Nanoflow

Nanoflows run on the client. Sometimes they need server-side capabilities:

| Need | Solution |
|---|---|
| Database retrieve with server-side filtering | Call a microflow from the nanoflow |
| Commit objects to the database | Call a microflow (nanoflows can commit, but without full transaction support) |
| External service calls | Call a microflow (server-to-server calls avoid CORS and credential exposure) |
| Complex business rules | Call a microflow to leverage server-side transaction safety |
| File generation | Call a microflow (file I/O is server-side) |

### Passing Data Between Microflows and Nanoflows

**Nanoflow calling a microflow:**

```
Nanoflow: NF_QuickValidate
  -> Validate client-side fields (instant, no round-trip)
  -> Decision: Client validation passed?
     false -> Show validation message -> End
     true  -> Call Microflow MF_ServerValidateAndSave($Order)
              [This triggers a server round-trip]
           -> Decision: $Result = true?
              true  -> Close page
              false -> Show error message
```

**Data passing rules:**

| Direction | What you can pass | What you cannot pass |
|---|---|---|
| **Nanoflow -> Microflow** | Objects, lists, primitives (string, int, bool, etc.) | Non-persistable entities are not sent to the server |
| **Microflow -> Nanoflow (return)** | Objects, lists, primitives | Large lists (performance: everything is serialized over HTTP) |

**Performance consideration:** Every microflow call from a nanoflow is an HTTP request. Minimize round-trips:

- Batch multiple operations into a single microflow call instead of calling multiple microflows sequentially from a nanoflow.
- Return all needed data in one call (e.g., return a non-persistable wrapper entity with multiple associations) rather than making separate calls for each piece of data.

### Hybrid Patterns

**Optimistic UI update:**
```
Nanoflow: NF_ToggleFavorite
  -> Change $Item/IsFavorite = not($Item/IsFavorite)   <-- Instant UI update
  -> Call Microflow MF_PersistFavorite($Item)           <-- Server sync in background
     [Error handler -> $Rollback]
  -> End

$Rollback:
  -> Change $Item/IsFavorite = not($Item/IsFavorite)   <-- Revert on failure
  -> Show message "Could not save, please try again"
  -> End
```

**Offline-first with sync:**
```
Nanoflow (offline): NF_CreateOrder_Offline
  -> Create $Order (local)
  -> Create $OrderLines (local)
  -> [User fills in form]
  -> Commit locally
  -> When online: sync triggers microflow MF_ProcessSyncedOrder on server
```

---

## 14. Common Pitfalls

### 1. Object State Issues

**The problem:** You retrieve an object, pass it to a sub-microflow, the sub-microflow changes it, and now back in the calling flow the object has values you did not expect.

**Why it happens:** Objects are passed by reference. Any change to the object in a sub-microflow (even without committing) is visible in the caller.

**How to avoid:**
- Be intentional about which microflows modify objects.
- Document whether a sub-microflow has side effects (changes the input object).
- If you need a "read-only" copy, retrieve the object again from the database into a separate variable before passing it to an untrusted sub-microflow.
- Use a naming convention like `SUB_Order_UpdateStatus` (clearly modifies) vs. `SUB_Order_CalculateTotal` (should not modify the order, only return a value).

**Especially dangerous pattern:**
```
Retrieve $Order
Call SUB_Something($Order)        <-- This changes $Order/Status to 'Processing'
Decision: $Order/Status = 'Draft'?
  true -> [You expect to be here, but you never arrive]
```

### 2. Long-Running Microflows Blocking the UI

**The problem:** A microflow triggered by a button takes 30 seconds to complete. The user sees a loading spinner and may click the button again, triggering a second execution.

**Symptoms:**
- Users complain about "frozen" pages.
- Duplicate data appears (user clicked Submit twice).
- Timeout errors in the browser.

**Solutions:**

| Approach | Description |
|---|---|
| **Progress bar** | Use the Progress Bar activity (Mendix 9+) to show incremental progress to the user |
| **Asynchronous processing** | Start a background process (via the Process Queue or Task Queue module) and immediately return to the user. Poll for completion. |
| **Disable the button** | Use a nanoflow to disable the button after click, re-enable after the microflow returns |
| **Optimize the microflow** | Apply the performance best practices from [section 9](#9-performance-best-practices) |
| **Set reasonable timeouts** | Configure HTTP request timeouts for external service calls |

**Rule of thumb:** If a microflow takes more than 2-3 seconds, either optimize it or make it asynchronous.

### 3. Accidentally Deleting Committed Data

**The problem:** You delete objects that are already committed to the database, and the microflow completes successfully. The data is gone forever. There is no recycle bin.

**Scenarios where this bites you:**
- A delete action has incorrect XPath, matching more objects than intended.
- A cascade delete (via delete behavior on associations) removes more objects than expected.
- A scheduled event deletes data based on a date calculation that has an off-by-one error.

**How to protect yourself:**

| Protection | Implementation |
|---|---|
| **Soft delete** | Add a `Boolean IsDeleted` attribute. "Delete" sets it to `true`. Filter all retrieves with `[IsDeleted = false]`. |
| **Confirmation dialogs** | Always show a confirmation dialog before deleting user-visible data |
| **Logging** | Log every delete operation with the object ID and relevant attributes |
| **Count before delete** | Retrieve the count of objects that match your delete criteria, log it, and add a guard clause if the count is unexpectedly high |
| **Database backups** | Maintain regular database backups as a last resort recovery mechanism |
| **Restrict delete permissions** | Only allow admin roles to execute delete microflows |

**Delete behavior on associations:**

| Setting | Effect |
|---|---|
| **Delete [entity] objects as well** | Cascade delete: deleting the parent deletes all children. Dangerous if you do not understand the full association graph. |
| **Delete [entity] object only if not associated** | Prevents deletion if there are still associated objects. Safe but can surprise users. |
| **Keep [entity] objects** | Only deletes the parent; children are orphaned. |

Always review delete behavior settings on associations when debugging unexpected data loss.

### 4. Overuse of Change-and-Commit in Loops

**The problem:** You change an attribute and commit the object on every iteration of a loop. This results in N database transactions instead of 1.

**Bad:**
```
Loop over $Invoices as $Invoice
  -> Change $Invoice/Status = 'Sent' (Commit: Yes)      <-- DB write per iteration
  -> Call REST: Send invoice to accounting system
  -> Change $Invoice/SyncedAt = [%CurrentDateTime%] (Commit: Yes)  <-- ANOTHER DB write!
```

This is 2N database commits for N invoices. For 500 invoices, that is 1,000 individual transactions.

**Good:**
```
Loop over $Invoices as $Invoice
  -> Change $Invoice/Status = 'Sent' (Commit: No)
  -> Call REST: Send invoice to accounting system
  -> Change $Invoice/SyncedAt = [%CurrentDateTime%] (Commit: No)
-> Commit $Invoices                                       <-- Single batch commit
```

**Even better (with error handling):**
```
Create $FailedInvoices (empty list)
Loop over $Invoices as $Invoice
  -> Change $Invoice/Status = 'Sent' (Commit: No)
  -> Call REST [error handler -> $InvoiceError]
     Success -> Change $Invoice/SyncedAt = [%CurrentDateTime%] (Commit: No)
  -> Continue

$InvoiceError:
  -> Log Warning "Failed to sync invoice {1}" with $Invoice/InvoiceNumber
  -> Add $Invoice to $FailedInvoices
  -> Continue loop

-> Commit $Invoices
-> Decision: $FailedInvoices not empty?
   true  -> Call SUB_HandleFailedInvoices($FailedInvoices)
-> End
```

### 5. Ignoring Entity Access in Sub-Microflows

**The problem:** Your top-level microflow has "Apply entity access" enabled, but you call a sub-microflow that has it disabled. The sub-microflow runs with elevated privileges, potentially exposing data.

**Why it is dangerous:** A user triggers a button (entity access enforced), which calls a sub-microflow (entity access disabled). The sub-microflow retrieves all orders for all customers, not just the current user's orders. If it returns that data or acts on it, you have a security issue.

**How to avoid:**
- Be consistent: if the top-level microflow applies entity access, sub-microflows should too (unless there is a documented reason).
- Review sub-microflows when changing security settings.
- Use the "Find usages" feature to see where a microflow is called from.

### 6. Not Handling Empty Results

**The problem:** You retrieve an object (Range: First), do not check if it is empty, and then try to use its attributes. This causes a NullPointerException at runtime.

**Bad:**
```
Retrieve $Order (First) where [OrderNumber = $InputNumber]
Change $Order/Status = 'Processing'    <-- NullPointerException if no order found!
```

**Good:**
```
Retrieve $Order (First) where [OrderNumber = $InputNumber]
Decision: $Order = empty?
  true  -> Show message "Order not found" -> End
  false -> Change $Order/Status = 'Processing' -> Continue
```

**Always check for empty** after:
- Any database retrieve with Range: First
- Any retrieve by association that might return empty
- Any microflow call that returns an object

### 7. Hardcoding Configuration Values

**The problem:** You hardcode API URLs, email addresses, thresholds, and other configuration values directly in microflow expressions.

**Why it is a problem:** When you deploy to a different environment (test, acceptance, production), you have to change the microflow. This means redeploying the app for a configuration change.

**Solution:** Create a `Configuration` entity (singleton) with attributes for configurable values. Retrieve it at the start of the microflow. Alternatively, use constants (which can be overridden per environment in the Mendix Cloud or your deployment pipeline).

```
-- Instead of:
Call REST "https://api.production.example.com/orders"

-- Do:
Retrieve $Config (first) from MyModule.Configuration
Call REST $Config/ApiBaseUrl + "/orders"
```

### 8. Mixing UI and Logic in a Single Microflow

**The problem:** A single microflow validates input, processes business logic, calls external services, commits data, shows messages, closes pages, and refreshes data views. It is 40 activities long, impossible to test, and hard to maintain.

**Solution:** Decompose into layers:

```
ACT_Order_Submit ($Order)             <-- Action microflow (thin, UI concerns only)
  -> Call VAL_Order_Validate($Order)  <-- Returns error string or empty
     -> If error: Show message, End
  -> Call SUB_Order_Process($Order)   <-- Pure business logic, testable
     -> If error: Show message, End
  -> Close page
  -> End
```

| Layer | Prefix | Contains | Testable? |
|---|---|---|---|
| **Action** | `ACT_` | Show message, close page, refresh, download file | No (UI-dependent) |
| **Validation** | `VAL_` | Input validation, return error messages | Yes |
| **Sub-microflow** | `SUB_` | Business logic, data manipulation | Yes |
| **Scheduled event** | `SE_` | Timer-triggered logic | Yes |
| **Data source** | `DS_` | Retrieve and return data for pages | Yes |

---

## Quick Reference: Microflow Activity Cheat Sheet

| Activity | What It Does | Key Gotcha |
|---|---|---|
| **Create Object** | Creates a new in-memory object | Not committed until you explicitly commit |
| **Change Object** | Modifies an existing object | Changes are in-memory; commit to persist |
| **Delete Object(s)** | Permanently deletes from DB | Cascade delete can remove more than expected |
| **Retrieve** | Gets objects from DB or by association | Database: only committed data. By association: in-memory state |
| **Aggregate List** | Count, sum, avg, min, max at DB level | Much faster than looping for calculations |
| **Commit** | Persists in-memory changes to DB | Batch commits outside loops for performance |
| **Microflow Call** | Calls a sub-microflow | Objects passed by reference (changes visible to caller) |
| **Java Action Call** | Calls Java code | Runs in same transaction unless configured otherwise |
| **Log Message** | Writes to runtime log | Use structured log nodes for production debugging |
| **Show Message** | Displays a popup to the user | Does not work in scheduled events or web services |
| **Download File** | Sends a file to the browser | Only works in user-facing microflows |
| **Exclusive Split** | Boolean or enum decision | Handle all enum values to avoid runtime errors |
| **Inheritance Split** | Checks object runtime type | Use when working with generalizations |
| **Merge** | Rejoins branching paths | No logic; purely structural |
| **Loop** | Iterates over a list | Never commit inside a loop |
| **Error Handler** | Catches errors on an activity | Rollback only affects DB, not in-memory state |
| **End Event** | Terminates the flow and returns a value | Every path must reach an end event |

---

## Quick Reference: Naming Convention Summary

| Prefix | Purpose | Example |
|---|---|---|
| `ACT_` | User action from a page | `ACT_Order_Submit` |
| `SUB_` | Reusable sub-microflow | `SUB_Email_Send` |
| `SE_` | Scheduled event handler | `SE_CleanupExpiredTokens` |
| `DS_` | Data source for a widget | `DS_Dashboard_GetStats` |
| `VAL_` | Validation logic | `VAL_Order_BeforeSubmit` |
| `BCo_` | Before commit event handler | `BCo_Order_SetDefaults` |
| `ACo_` | After commit event handler | `ACo_Order_SendNotification` |
| `BDe_` | Before delete event handler | `BDe_Order_CheckDependencies` |
| `ADe_` | After delete event handler | `ADe_Order_LogDeletion` |
| `Test_` | Unit test microflow | `Test_Order_CalculateTotal` |

---

## Summary

Microflows are the workhorse of Mendix application logic. The key principles to internalize:

1. **Commit outside loops.** This single practice prevents most performance issues.
2. **Check for empty.** Every retrieve should be followed by a null check before use.
3. **Decompose.** Break large flows into sub-microflows. Test them in isolation.
4. **Handle errors.** Use custom error handlers on external service calls and risky operations.
5. **Respect security.** Keep "Apply entity access" enabled unless you have a documented reason not to.
6. **Log strategically.** Structured logs with correlation IDs make production debugging possible.
7. **Guard your data.** Be cautious with deletes. Use soft deletes for important entities. Log everything.
8. **Keep UI and logic separate.** Action microflows handle the UI; sub-microflows handle the logic.

Master these principles and you will build Mendix applications that are performant, maintainable, and reliable.

---

<div align="center">

**[Back to Home](../README.md)**

</div>
