# Mendix Nanoflows: A Comprehensive Guide

## Practical Reference for Mendix Developers

**Version:** 1.0
**Date:** February 2026

---

## Table of Contents

1. [What Is a Nanoflow?](#1-what-is-a-nanoflow)
2. [When to Use Nanoflows vs. Microflows](#2-when-to-use-nanoflows-vs-microflows)
3. [Supported Activities](#3-supported-activities)
4. [Working with Data](#4-working-with-data)
5. [Offline Support](#5-offline-support)
6. [JavaScript Actions](#6-javascript-actions)
7. [UI Interactions](#7-ui-interactions)
8. [Performance Considerations](#8-performance-considerations)
9. [Error Handling](#9-error-handling)
10. [Security Implications](#10-security-implications)
11. [Common Patterns](#11-common-patterns)
12. [Debugging](#12-debugging)

---

## 1. What Is a Nanoflow?

### Definition

A nanoflow is a client-side logic flow in Mendix. It looks like a microflow in Studio Pro -- you drag activities onto a canvas, connect them, set conditions -- but the similarity is visual. The execution model is fundamentally different.

When a microflow runs, the Mendix Runtime on the server receives the request, executes each step against the database, and sends results back. When a nanoflow runs, everything happens in the user's browser (or native mobile device). No HTTP request goes to the server unless you explicitly make one.

### Client-Side Execution Model

Here is what happens when a nanoflow fires:

1. The user triggers an event -- a button click, an on-change handler, a page load event.
2. The Mendix Client (the JavaScript runtime that powers every Mendix app in the browser) picks up the event and starts executing the nanoflow steps.
3. Each activity runs locally. Object creation creates an in-memory JavaScript object. Attribute changes modify that object in local memory. Retrieve operations pull from the client's local object cache (not the database).
4. If the nanoflow includes a "Call Microflow" activity, that is the only point where the browser sends a request to the server. The nanoflow pauses, waits for the response, and then continues.
5. When the nanoflow finishes, the Mendix Client applies any UI changes -- page navigations, refreshes, validation messages.

The Mendix Client compiles nanoflows into JavaScript at deployment time. They ship as part of the client bundle. This means there is zero server round-trip overhead for purely local logic.

### Offline-First Capability

Nanoflows are the only logic mechanism that works when the device has no network connection. This is by design:

- In an offline-first app, the Mendix Client maintains a local SQLite database on the device.
- Nanoflows operate against this local database for retrieves, creates, changes, and deletes.
- Data synchronization with the server happens separately -- either automatically or when you explicitly trigger it.
- Microflows cannot run offline. Period. If you try to call a microflow from an offline page, the call will fail.

This makes nanoflows mandatory for any offline-capable application, but their usefulness extends well beyond that scenario.

### How They Differ from Microflows at a Glance

| Aspect | Nanoflow | Microflow |
|---|---|---|
| Execution location | Client (browser / native device) | Server (Mendix Runtime) |
| Network required | No (except for explicit server calls) | Yes, always |
| Database access | Client cache or local offline DB | Full server database |
| Language compiled to | JavaScript | Java |
| Available in offline apps | Yes | No (cannot be called directly) |
| Entity access rules applied | At sync / server boundary | On every operation |
| Visible to end user | Yes (source is in the client bundle) | No (runs server-side) |

---

## 2. When to Use Nanoflows vs. Microflows

### The Core Decision

The question is not "which is better?" -- it is "where should this logic run?" Client-side and server-side execution have different trade-offs, and picking the wrong one creates problems that are painful to fix later.

### Decision Matrix

Use the following table to guide your decision. If any row lands firmly in the microflow column, use a microflow -- even if other rows favor a nanoflow.

| Factor | Use a Nanoflow | Use a Microflow | Notes |
|---|---|---|---|
| **Offline requirement** | Must work offline | Online-only is acceptable | This is a hard constraint. If the page must work offline, you have no choice -- nanoflows only. |
| **Latency sensitivity** | User expects instant response (< 50ms) | A brief loading state is acceptable | Nanoflows skip the network round-trip entirely. Useful for real-time form validation, toggling UI states, or filtering already-loaded data. |
| **Data volume** | Working with a small set already on the client (< 1,000 objects) | Querying or aggregating large datasets (thousands+ rows) | Nanoflows operate on objects already in the client cache. If you need to search through 50,000 records, do it on the server. |
| **Security sensitivity** | No sensitive business rules or secrets involved | Contains authorization logic, pricing rules, API keys, or any secret | Nanoflow logic is visible in the browser. Anyone with dev tools open can read it. |
| **Integration calls** | No external service calls needed | Calls REST/SOAP/OData services, sends emails, writes files | Nanoflows cannot directly call external services. You must route through a microflow. |
| **Database writes** | Creating/changing objects that will sync later (offline) or be committed via a microflow call | Direct, immediate database commits required | Nanoflows cannot commit to the server database directly. They modify the client cache. |
| **Computation complexity** | Simple: conditionals, string formatting, basic math | Complex: loops over large lists, heavy aggregations, PDF generation | The browser's JavaScript engine is single-threaded. Heavy computation blocks the UI. |
| **Transaction requirements** | No transactional guarantees needed | Must be atomic (all-or-nothing) | Only the server provides database transactions. Nanoflows have no transaction concept. |

### Common Scenarios and Recommendations

| Scenario | Recommendation | Why |
|---|---|---|
| Validate a form field on change | Nanoflow | Instant feedback, no server needed, simple logic |
| Save a new record to the database | Microflow | Needs database commit and server-side validation |
| Toggle a boolean to show/hide a UI section | Nanoflow | Pure UI state, instant response |
| Calculate a running total on a page | Nanoflow (if data is already loaded) | Avoids a round-trip for each keystroke |
| Enforce that only managers can approve requests | Microflow | Authorization logic must not run on the client |
| Apply a discount based on secret pricing tiers | Microflow | Business rules and pricing logic must stay server-side |
| Navigate to another page | Nanoflow | Client-side navigation is instant |
| Generate a PDF report | Microflow | Requires server-side libraries and file handling |
| Filter a list that is already displayed on the page | Nanoflow | Data is already in the client cache |
| Search across the full customer database | Microflow | Requires server-side database query |
| Sync offline data when connectivity returns | Nanoflow triggers the sync | The sync activity is available in nanoflows |
| Send an email notification | Microflow | Requires server-side SMTP integration |
| Log an audit trail entry | Microflow | Audit data should be committed server-side, tamper-proof |

### The Hybrid Approach

In practice, many user interactions combine both. A common pattern:

1. **Nanoflow** validates the form locally (instant feedback).
2. **Nanoflow** calls a **microflow** to persist the data (server commit).
3. **Nanoflow** shows a success message or navigates to the next page.

This gives the user instant validation feedback while ensuring data integrity on the server. The nanoflow orchestrates the flow; the microflow handles the parts that require the server.

---

## 3. Supported Activities

### Understanding the Divide

Not every activity in Studio Pro is available in nanoflows. The general rule: if it requires server infrastructure (database transactions, file storage, external service connectors), it is microflow-only. If it manipulates objects in memory or controls the UI, it works in nanoflows.

### Object Activities

| Activity | Nanoflow | Microflow | Notes |
|---|---|---|---|
| Create Object | Yes | Yes | In nanoflows, creates the object in the client's memory / local DB. |
| Change Object | Yes | Yes | Modifies attributes on an in-memory object. |
| Delete Object | Yes | Yes | In nanoflows, removes from client cache / local DB. Server delete requires a microflow. |
| Retrieve | Yes | Yes | Nanoflow retrieves come from the client cache or local offline database -- never the server DB directly. |
| Commit | No | Yes | Nanoflows cannot commit to the server database. Use a microflow call to persist data. |
| Rollback | Yes | Yes | Reverts an object in the client cache to its last-known committed state. |

### List Activities

| Activity | Nanoflow | Microflow | Notes |
|---|---|---|---|
| Aggregate List | Yes | Yes | Runs on the client-side list. Keep the list small. |
| Create List | Yes | Yes | |
| List Operation (union, intersect, etc.) | Yes | Yes | |
| Filter/Find | Yes | Yes | Uses XPath on the client cache (limited compared to server XPath). |
| Sort | Yes | Yes | |
| Head / Tail | Yes | Yes | |

### Variable and Flow Activities

| Activity | Nanoflow | Microflow | Notes |
|---|---|---|---|
| Create Variable | Yes | Yes | |
| Change Variable | Yes | Yes | |
| Decision (exclusive split) | Yes | Yes | |
| Merge | Yes | Yes | |
| Loop | Yes | Yes | Be careful with loop size -- runs on the UI thread. |
| Break / Continue | Yes | Yes | |
| End Event | Yes | Yes | |

### Action Call Activities

| Activity | Nanoflow | Microflow | Notes |
|---|---|---|---|
| Call Nanoflow | Yes | No | Nanoflows can call other nanoflows (composition). Microflows cannot call nanoflows. |
| Call Microflow | Yes | Yes | From a nanoflow, this triggers a server round-trip. The nanoflow waits for the response. |
| Call JavaScript Action | Yes | No | Nanoflow-exclusive. This is how you extend nanoflows with custom JavaScript. |
| Call Java Action | No | Yes | Java actions run on the server only. |
| Call REST Service | No | Yes | Use a microflow, then call that microflow from the nanoflow. |
| Call Web Service | No | Yes | Same approach -- wrap in a microflow. |
| Call External Action (OData) | No | Yes | |

### Client Activities (Nanoflow-Only or Shared)

| Activity | Nanoflow | Microflow | Notes |
|---|---|---|---|
| Show Page | Yes | Yes | In nanoflows, navigation is instant (no round-trip). |
| Close Page | Yes | Yes | |
| Show Home Page | Yes | Yes | |
| Show Message | Yes | Yes | Dialogs in nanoflows appear without server delay. |
| Show Validation Message | Yes | Yes | |
| Download File | No | Yes | Files are stored server-side. Download requires a server response. |
| Show Progress | Yes | No | Nanoflow-only. Displays a blocking progress indicator. |
| Hide Progress | Yes | No | Paired with Show Progress. |
| Synchronize | Yes | No | Nanoflow-only. Triggers offline data sync. |
| Sign Out | Yes | Yes | |

### Integration Activities

| Activity | Nanoflow | Microflow | Notes |
|---|---|---|---|
| Call REST | No | Yes | External HTTP calls must go through the server. |
| Call SOAP | No | Yes | |
| Import/Export XML Mapping | No | Yes | |
| Send Email (Email Connector) | No | Yes | |

### Logging and Workflow Activities

| Activity | Nanoflow | Microflow | Notes |
|---|---|---|---|
| Log Message | Yes | Yes | In nanoflows, logs to the browser console (not the server log). |
| Cast Object | Yes | Yes | |
| Generate Document | No | Yes | Requires server-side document template engine. |
| Call Workflow | No | Yes | Workflow engine runs server-side. |

### The Summary Rule

If you are ever unsure, ask yourself: "Does this need something that only exists on the server?" If yes, use a microflow or call a microflow from your nanoflow. If no, a nanoflow is likely the better choice for responsiveness.

---

## 4. Working with Data

### The Client Cache

Every Mendix app in the browser maintains a client-side object cache. When a page loads, the Mendix Client fetches the objects that page needs and stores them in memory. Nanoflows work exclusively against this cache (in online apps) or the local SQLite database (in offline apps).

Understanding this is critical. When a nanoflow retrieves objects, it is not querying the server database. It is looking at what the client already has.

### Creating Objects in a Nanoflow

When you use "Create Object" in a nanoflow:

- A new object is instantiated in client memory.
- It has no database ID yet (it has not been committed).
- You can set attributes, associate it with other objects in the cache, and display it on a page.
- The object exists only on the client until you explicitly send it to the server (via a microflow call or offline sync).

**Practical example -- creating a new order line:**

```
[Start]
  --> Create Object: OrderLine
       - Quantity = 1
       - UnitPrice = $Product/Price
       - OrderLine_Order = $CurrentOrder
       - OrderLine_Product = $SelectedProduct
  --> Change Object: $CurrentOrder
       - TotalAmount = $CurrentOrder/TotalAmount + $NewOrderLine/UnitPrice
  --> [End: $NewOrderLine]
```

This entire flow runs instantly. The user sees the new line item appear on the page with no loading spinner. The data has not been saved to the server yet.

### Retrieving Objects

Nanoflow retrieves come from the client cache or local database. There are two retrieve modes:

| Mode | What It Does | When to Use |
|---|---|---|
| **By Association** | Follows an association from a given object to its related object(s). | When you already have the parent/related object in context. Fast and reliable. |
| **From Database** | Queries the client cache (online) or local SQLite DB (offline) using XPath. | When you need to find objects that are not directly associated with your current context. |

**Important limitations of nanoflow retrieves:**

1. **Online apps**: "From Database" retrieves search the client cache, not the server database. If an object is not already loaded on the client, the nanoflow will not find it. This catches people off guard regularly.

2. **Offline apps**: "From Database" retrieves query the local SQLite database, which contains a defined subset of server data (controlled by your offline-first data configuration). The data may be stale if the user has not synced recently.

3. **XPath constraints**: Nanoflow XPath supports a subset of what server-side XPath supports. Complex constraints involving reverse associations or nested path expressions may not work. Test your constraints early.

4. **No aggregate queries against the database**: You can aggregate a list you have already retrieved, but you cannot issue a COUNT or SUM query directly against the client-side database in XPath.

### Calling Microflows for Server Data

When you need data that is not in the client cache, the pattern is:

1. **Nanoflow** calls a **microflow** with any parameters the server needs (search term, filter criteria, page number).
2. **Microflow** queries the database, applies security rules, and returns the result (an object, a list, or a primitive).
3. **Nanoflow** receives the result and continues.

**Structure:**

```
[Start]
  --> Show Progress: "Searching..."
  --> Call Microflow: ACT_SearchCustomers
       - Parameter: $SearchTerm
       - Return: $CustomerList (List of Customer)
  --> Hide Progress
  --> Decision: $CustomerList is empty?
       - True --> Show Message: "No results found."
       - False --> Show Page: CustomerSearchResults (pass $CustomerList)
  --> [End]
```

Each microflow call is one HTTP request. The nanoflow blocks (waits) until the response comes back. Design your microflows to return everything the nanoflow needs in a single call when possible.

### Modifying and Passing Objects

Nanoflows can change object attributes freely:

- **Change Object** modifies attributes in the client cache immediately.
- The object is in a "dirty" state -- it has unsaved changes.
- If the user navigates away or the page closes, uncommitted changes are lost (unless you have explicitly handled this).
- To persist changes, call a microflow that commits the object, or (in offline apps) the changes are committed locally and synced later.

**Object passing between nanoflows:**

When one nanoflow calls another, objects are passed by reference. This means the called nanoflow operates on the same in-memory object. Changes made in the inner nanoflow are immediately visible in the outer nanoflow when it resumes.

### Data Flow Patterns

| Pattern | Description | When to Use |
|---|---|---|
| **Local create, then server commit** | Create and populate objects in a nanoflow, then call a microflow to commit them all at once. | Standard form submission in online apps. |
| **Server fetch, then local display** | Call a microflow to retrieve data, then use the returned objects in local nanoflow logic (filtering, sorting, formatting). | Search results, complex queries that need server-side data access. |
| **Offline create, then sync** | Create objects in the local DB, continue working offline, sync when connected. | Field worker apps, inspections, data collection. |
| **Optimistic local update** | Change the object locally and update the UI first, then call a microflow in the background to persist it. If the server call fails, revert. | Like buttons, toggles, quantity adjustments. |
| **Cache-first read** | Retrieve from the client cache first. If the result is empty or stale, call a microflow to refresh. | Dashboards, reference data, frequently viewed lists. |

---

## 5. Offline Support

### How Offline-First Works in Mendix

Mendix offline-first apps use a local SQLite database on the device (or IndexedDB in the browser for PWAs). The architecture works like this:

1. **Initial sync**: When the user first opens the app, the Mendix Client downloads a subset of the server data to the local database. Which entities and how much data is controlled by the offline-first configuration in Studio Pro.

2. **Normal operation**: The user interacts with the app entirely through nanoflows. All reads, creates, changes, and deletes happen against the local database. The app works identically whether the device is online or offline.

3. **Synchronization**: Periodically (or when triggered), the Mendix Client syncs changes bidirectionally. Local changes are uploaded to the server; server changes are downloaded to the device.

### Nanoflows Are Mandatory Offline

In an offline-first profile page, you cannot attach a microflow to a button. Studio Pro will not allow it. Every piece of logic on offline pages must be a nanoflow. The only way to execute server-side logic is through the "Call Microflow" activity inside a nanoflow, and that call will fail if the device is offline (which you must handle).

### Configuring Offline Data

In Studio Pro, each entity that should be available offline needs configuration:

| Setting | Description | Impact |
|---|---|---|
| **Download mode** | All, Constrained, None, or Nothing (for new objects only) | Controls what data is synced to the device. "All" syncs every record; "Constrained" uses an XPath to limit the set. |
| **Sync behavior** | Upload changes, Download changes, or Both | Controls sync direction. |
| **XPath constraint** | Filters which objects sync to the device | Use this to limit data per user. For example, sync only records assigned to the current user. |

### Synchronization Considerations

**What triggers a sync:**

| Trigger | How It Works |
|---|---|
| **Automatic (startup sync)** | Happens when the app starts if the device is online. Downloads data based on offline configuration. |
| **Nanoflow Synchronize activity** | You explicitly trigger a full or selective sync from a nanoflow. |
| **Synchronize Unsynchronized Objects** | Syncs only objects that have local changes. More targeted than a full sync. |
| **Save button (default)** | In some page templates, the save button triggers a microflow call, which implicitly syncs the changed object. |

**Selective synchronization:**

Starting with Mendix 10, you can perform selective sync -- synchronizing specific entities or even specific objects rather than the full dataset. This is important for apps with large offline datasets where a full sync takes too long.

```
[Start]
  --> Synchronize
       - Type: Unsynchronized Objects
       - Entities: [Order, OrderLine]
  --> Decision: Sync successful?
       - True --> Show Message: "Data saved."
       - False --> Show Message: "Sync failed. Changes saved locally."
  --> [End]
```

### Conflict Handling

Conflicts occur when both the device and the server have changed the same object since the last sync. Mendix handles this with a "last write wins" strategy by default, but you need to understand the nuances:

| Scenario | Default Behavior | How to Handle |
|---|---|---|
| **Device changed, server unchanged** | Device changes are applied to the server. | No conflict. Works as expected. |
| **Server changed, device unchanged** | Server changes are downloaded to the device. | No conflict. Works as expected. |
| **Both changed the same object** | Device changes are sent to the server. The server applies them, overwriting its own changes. | This is "device wins." If you need different behavior, implement a conflict resolution microflow. |
| **Device changed, server deleted the object** | The sync will attempt to update a non-existent object. This triggers an error. | Handle this in error handling. You may need to recreate the object or inform the user. |
| **Device deleted, server changed the object** | The device sends a delete request. The server deletes the object, losing its own changes. | If the server change was important, you need custom conflict detection. |

**Implementing custom conflict resolution:**

1. Add a `LastModifiedDate` attribute (DateTime) to your entity.
2. Set it in both the nanoflow (local change) and the server-side microflow (before-commit).
3. In the synchronization commit microflow, compare the incoming `LastModifiedDate` with the server's current value.
4. If the server's version is newer, you have a conflict. Decide: merge, reject, or prompt the user.

### Offline Data Limits

| Concern | Guidance |
|---|---|
| **Local DB size** | SQLite on mobile devices has practical limits. Keep offline datasets under 50MB where possible. Test on the lowest-spec target device. |
| **Number of entities** | Each offline entity adds to sync time. Only sync what the user actually needs offline. |
| **Image/file sync** | Binary data (images, documents) can bloat the local DB. Consider syncing file metadata only and downloading files on demand when online. |
| **Sync duration** | Full syncs on large datasets can take minutes on slow connections. Use selective sync. Show progress to the user. |
| **Stale data** | Offline data can be hours or days old. Show the last sync time to users so they know how fresh their data is. |

---

## 6. JavaScript Actions

### What They Are

JavaScript actions are the escape hatch. When nanoflows cannot do something natively -- access a browser API, call a third-party JavaScript library, manipulate the DOM, interact with device hardware -- you write a JavaScript action and call it from a nanoflow.

A JavaScript action is a `.js` file inside your Mendix project that follows a specific contract: it receives typed parameters and returns a typed result. Studio Pro generates the boilerplate; you fill in the implementation.

### Creating a JavaScript Action

In Studio Pro:

1. Right-click a module folder > **Add other** > **JavaScript action**.
2. Name it descriptively (e.g., `GetCurrentGPSLocation`, `CopyToClipboard`, `FormatCurrency`).
3. Define **input parameters** -- each has a name and a type (String, Integer, Boolean, Decimal, DateTime, Object, List, Enumeration).
4. Define the **return type** -- same type options, or Nothing.
5. Studio Pro generates a `.js` file. Open it and implement the logic.

### Anatomy of a JavaScript Action

```javascript
// This file was generated by Mendix Studio Pro.
//
// WARNING: Only the following code will be retained when actions are regenerated:
// - the import list
// - the code between BEGIN USER CODE and END USER CODE
// - the code between BEGIN EXTRA CODE and END EXTRA CODE
// Other code you write will be lost the next time you deploy the project.
import { Big } from "big.js";

// BEGIN EXTRA CODE
// Put reusable helper functions here.
// END EXTRA CODE

/**
 * Copies the given text to the user's clipboard.
 * @param {string} textToCopy - The text to copy.
 * @returns {Promise.<boolean>} - True if successful, false otherwise.
 */
export async function CopyToClipboard(textToCopy) {
    // BEGIN USER CODE
    try {
        await navigator.clipboard.writeText(textToCopy);
        return true;
    } catch (error) {
        console.error("Failed to copy to clipboard:", error);
        return false;
    }
    // END USER CODE
}
```

**Key rules:**

- Only write code between `BEGIN USER CODE` / `END USER CODE` and `BEGIN EXTRA CODE` / `END EXTRA CODE`. Everything else gets overwritten on regeneration.
- The function must return a `Promise` if it does anything asynchronous (which most browser APIs do).
- Studio Pro passes Mendix objects as JavaScript objects with getter/setter methods. Use `myObject.get("AttributeName")` and `myObject.set("AttributeName", value)`.
- For Big (decimal) values, Mendix uses the `big.js` library. The import is auto-included.

### Working with Mendix Objects in JavaScript Actions

When you pass a Mendix object as a parameter, you interact with it through the Mendix Client API:

```javascript
export async function CalculateLineTotal(orderLine) {
    // BEGIN USER CODE
    const quantity = orderLine.get("Quantity");
    const unitPrice = orderLine.get("UnitPrice"); // Returns a Big decimal

    const total = unitPrice.times(quantity);
    orderLine.set("LineTotal", total);

    return orderLine;
    // END USER CODE
}
```

**Common object operations:**

| Operation | Code | Notes |
|---|---|---|
| Get attribute | `obj.get("AttrName")` | Returns the native JS type or Big for decimals. |
| Set attribute | `obj.set("AttrName", value)` | Modifies the object in the client cache. |
| Get GUID | `obj.getGuid()` | The object's unique identifier. |
| Get entity type | `obj.getEntity()` | Returns the fully qualified entity name (e.g., `MyModule.Customer`). |
| Check if attribute has changed | `obj.isAttributeReadOnly("AttrName")` | Useful for conditional logic. |

### Working with Lists

Lists passed to JavaScript actions are standard JavaScript arrays of Mendix objects:

```javascript
export async function FilterHighValueOrders(orderList, threshold) {
    // BEGIN USER CODE
    return orderList.filter(order => {
        const total = order.get("TotalAmount");
        return total.gte(threshold); // Big.js comparison
    });
    // END USER CODE
}
```

### Calling External Libraries

You can import npm packages or local JavaScript modules:

```javascript
// BEGIN EXTRA CODE
import { format } from "date-fns";
// END EXTRA CODE

export async function FormatDateLocalized(dateValue, formatPattern) {
    // BEGIN USER CODE
    if (!dateValue) return "";
    return format(new Date(dateValue), formatPattern);
    // END USER CODE
}
```

To include an npm package:

1. Add it to the `package.json` in your Mendix project's `javascriptsource` folder (or the `themesource` folder depending on your project structure).
2. Run `npm install` in that directory.
3. Import it in the `BEGIN EXTRA CODE` section.

### Accessing Browser APIs

JavaScript actions give nanoflows access to everything the browser provides:

| Use Case | Browser API | Example |
|---|---|---|
| Geolocation | `navigator.geolocation` | Get the user's GPS coordinates. |
| Clipboard | `navigator.clipboard` | Copy/paste text. |
| Local Storage | `window.localStorage` | Persist small amounts of data outside the Mendix cache. |
| Camera (mobile) | `navigator.mediaDevices.getUserMedia()` | Access the device camera directly. |
| Notifications | `Notification` API | Show browser push notifications. |
| Speech | `SpeechRecognition` / `speechSynthesis` | Voice input / text-to-speech. |
| Vibration | `navigator.vibrate()` | Haptic feedback on mobile. |
| Network status | `navigator.onLine` | Check if the device has connectivity. |
| Screen orientation | `screen.orientation` | Detect or lock screen orientation. |

**Example -- checking network status:**

```javascript
export async function IsDeviceOnline() {
    // BEGIN USER CODE
    return navigator.onLine;
    // END USER CODE
}
```

### Returning Complex Data

If you need to return multiple values from a JavaScript action, you have two options:

1. **Modify an input object's attributes** (pass a Mendix object, set multiple attributes on it, return it).
2. **Return a single value** and call the action multiple times (less efficient but sometimes clearer).
3. **Create a non-persistable entity** specifically for the return value, pass it in, populate it, return it.

Option 1 or 3 is almost always preferable. Avoid making multiple round-trips when one will do.

### Async/Await and Promises

Modern JavaScript actions should use `async/await`:

```javascript
export async function GetGPSCoordinates(locationObject) {
    // BEGIN USER CODE
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject(new Error("Geolocation is not supported by this browser."));
            return;
        }

        navigator.geolocation.getCurrentPosition(
            (position) => {
                locationObject.set("Latitude", new Big(position.coords.latitude.toString()));
                locationObject.set("Longitude", new Big(position.coords.longitude.toString()));
                locationObject.set("Accuracy", new Big(position.coords.accuracy.toString()));
                resolve(locationObject);
            },
            (error) => {
                reject(new Error("GPS error: " + error.message));
            },
            {
                enableHighAccuracy: true,
                timeout: 10000,
                maximumAge: 0
            }
        );
    });
    // END USER CODE
}
```

If your JavaScript action returns a Promise, the nanoflow will automatically wait for it to resolve before continuing to the next activity.

---

## 7. UI Interactions

### Nanoflows as the UI Orchestration Layer

Nanoflows are ideal for controlling the user interface because they run on the client -- where the UI lives. There is no round-trip delay between deciding to show a page and the page actually appearing.

### Show Page

The "Show Page" activity in a nanoflow opens a page immediately. You can pass objects as page parameters.

**Options:**

| Setting | Description | Typical Use |
|---|---|---|
| **Page** | The page to open | Select from your project's pages. |
| **Page object** | The object to pass as the page parameter | The page's data view receives this object. |
| **Page title** | Override the page title dynamically | Useful for context-dependent titles (e.g., "Edit Order #1234"). |
| **Location** | Content (replace current), Popup, or Modal | Content for main navigation; popups for auxiliary screens. |

**Modal dialog pattern:**

```
[Start]
  --> Create Object: ConfirmationHelper (non-persistable)
       - Message = "Are you sure you want to delete this order?"
       - ConfirmAction = "Delete"
  --> Show Page: ConfirmationDialog (modal)
       - Pass $ConfirmationHelper
  --> [End]
```

The nanoflow on the confirmation dialog's "Yes" button then executes the actual delete logic.

### Close Page

"Close Page" closes the current page. In a popup or modal context, it closes the popup and returns control to the underlying page. You can optionally specify how many levels to close.

**Multi-level close:**

If you opened Page A > Page B > Page C, calling Close Page with `numberOfPagesToClose = 2` from Page C will close both C and B, returning to A.

### Show Message

Displays a blocking dialog box with a message. The nanoflow pauses until the user dismisses it.

| Message Type | Icon | When to Use |
|---|---|---|
| Information | Blue "i" icon | Confirmations, status updates |
| Warning | Yellow triangle | Non-critical issues, "are you sure?" prompts |
| Error | Red circle | Failures, validation errors (when a dialog is appropriate) |

**Avoid overusing blocking dialogs.** Users find them disruptive. For non-critical feedback, prefer validation messages or inline notifications.

### Show Validation Message

Displays a validation message on a specific widget -- typically a text input field. This is the gold standard for form validation in nanoflows because it highlights exactly which field has the problem.

```
[Start]
  --> Decision: $Order/CustomerName is empty?
       - True --> Validation Feedback
                   - Object: $Order
                   - Member: CustomerName
                   - Message: "Customer name is required."
                   - End: false (continue checking other fields)
       - False --> (continue)
  --> Decision: $Order/TotalAmount <= 0?
       - True --> Validation Feedback
                   - Object: $Order
                   - Member: TotalAmount
                   - Message: "Order total must be greater than zero."
                   - End: false
       - False --> (continue)
  --> Decision: $HasErrors?
       - True --> [End: false]
       - False --> Call Microflow: ACT_Order_Save
                   --> [End: true]
```

### Navigation

Nanoflows handle navigation cleanly:

| Activity | What It Does | Use Case |
|---|---|---|
| Show Page | Opens a specific page (replace content, popup, or modal) | Primary navigation |
| Close Page | Closes current page / popup / modal | Cancel, done, back |
| Show Home Page | Navigates to the app's home page | After logout, on error, "go home" button |
| Sign Out | Signs the user out and redirects to the login page | Logout button |

**Conditional navigation:**

```
[Start]
  --> Decision: $User/Role = 'Admin'?
       - True --> Show Page: AdminDashboard
       - False --> Decision: $User/Role = 'Manager'?
            - True --> Show Page: ManagerDashboard
            - False --> Show Page: EmployeeDashboard
  --> [End]
```

This runs instantly because the decision logic is client-side. No server call needed to decide which page to show (assuming the role information is already on the client).

### Show Progress / Hide Progress

For nanoflows that include a microflow call (which introduces a network delay), you can wrap the call with progress indicators:

```
[Start]
  --> Show Progress: "Saving your changes..."
  --> Call Microflow: ACT_SaveOrder
  --> Hide Progress
  --> Close Page
  --> [End]
```

**Best practices for progress indicators:**

- Always pair Show Progress with Hide Progress. If an error occurs between them, the progress indicator will stick. Use error handling (covered in Section 9) to ensure Hide Progress runs on all paths.
- Keep progress messages short and action-oriented ("Saving...", "Loading data...", "Syncing...").
- Do not show progress for operations that take under 200ms. It creates a distracting flash.

### Refresh in Client

After a microflow returns data that has been changed on the server, the client cache might be stale. You have several options:

1. **Return the modified object from the microflow** -- the client cache updates automatically.
2. **Use the "Refresh in Client" option** on the microflow's commit activity -- this tells the client to refresh all widgets displaying that object.
3. **Call the "Refresh Object" JavaScript action** from the nanoflow for finer control.

---

## 8. Performance Considerations

### The Single-Thread Reality

Nanoflows run on the browser's main thread -- the same thread that handles rendering, user input, animations, and every other piece of JavaScript on the page. If your nanoflow takes 500ms to execute, the browser freezes for 500ms. No scrolling, no button clicks, no animations. The UI is dead until the nanoflow finishes.

This is not a problem for typical nanoflows (which complete in under 5ms). It becomes a problem when developers treat nanoflows like microflows and try to do heavy work on the client.

### What "Lightweight" Means in Practice

| Guideline | Why |
|---|---|
| **Avoid looping over more than a few hundred objects** | Each iteration is a synchronous JavaScript operation. 10,000 iterations can block the UI for seconds. |
| **Do not sort or filter very large lists in nanoflows** | Use a microflow to sort/filter on the server and return the result. |
| **Keep nanoflow depth shallow** | Nanoflow A calling B calling C calling D calling E creates a deep call stack. Each call adds overhead. Keep it to 2-3 levels max. |
| **Avoid string concatenation in large loops** | JavaScript string operations create new string objects each time. In a loop, this causes excessive garbage collection. |
| **Do not use nanoflows for file processing** | Parsing CSVs, processing images, or manipulating binary data should happen on the server. |
| **Return only what you need from microflows** | If a microflow returns 5,000 objects but the nanoflow only needs 50, add filtering on the server side. Every object returned is serialized, sent over the network, and deserialized in the client. |

### Minimizing Microflow Round-Trips

Each "Call Microflow" from a nanoflow is an HTTP request. On a fast network, that is 50-200ms. On a slow mobile connection, that is 500-2000ms.

**Anti-pattern: Multiple sequential microflow calls**

```
[Start]
  --> Call Microflow: GetCustomerDetails     (200ms)
  --> Call Microflow: GetCustomerOrders       (200ms)
  --> Call Microflow: GetCustomerPreferences  (200ms)
  --> Call Microflow: GetCustomerBalance      (200ms)
  --> Show Page: CustomerDashboard
[End]

Total: ~800ms of waiting
```

**Better pattern: Single microflow that returns everything**

```
[Start]
  --> Call Microflow: GetCustomerDashboardData  (250ms)
       - Returns: CustomerDashboardDTO (non-persistable entity
         with associations to all needed data)
  --> Show Page: CustomerDashboard
[End]

Total: ~250ms of waiting
```

Create a non-persistable entity (or a set of them) that bundles all the data the page needs. Fetch it in one round-trip.

### Measuring Nanoflow Performance

| Method | How |
|---|---|
| **Browser dev tools Performance tab** | Record a trace, look for long-running JavaScript tasks during nanoflow execution. |
| **Console timing** | In a JavaScript action, use `console.time("myLabel")` / `console.timeEnd("myLabel")` to measure specific operations. |
| **Network tab** | Watch for microflow calls (XHR requests to `/xas/`). Check their timing and payload size. |
| **Mendix built-in profiling** | In Studio Pro's Run > Advanced menu, enable client-side profiling to see nanoflow execution times. |

### Performance Comparison: Nanoflow vs. Microflow

| Operation | Nanoflow | Microflow | Winner |
|---|---|---|---|
| Toggle a boolean attribute | < 1ms | 50-200ms (network + server) | Nanoflow |
| Validate 5 form fields | < 5ms | 50-200ms | Nanoflow |
| Sort a list of 50 items | < 5ms | 50-200ms | Nanoflow |
| Sort a list of 10,000 items | 200-500ms (UI blocks) | 60-220ms (server is fast at this) | Microflow |
| Filter 100 objects by a string attribute | < 10ms | 50-200ms | Nanoflow |
| Full-text search across 100,000 records | Not feasible | 100-500ms (with DB indexes) | Microflow |
| Calculate aggregate over 5,000 records | 50-200ms (UI blocks) | 60-220ms | Microflow (no UI blocking) |
| Show a page | < 5ms | 50-200ms | Nanoflow |
| Navigate to the next step in a wizard | < 5ms | 50-200ms | Nanoflow |

### Lazy Loading Pattern

Do not load all data upfront. Load what is visible, then load more on demand:

```
[Start: Page Load]
  --> Call Microflow: GetFirst20Orders
       - Returns: $OrderList
  --> Change Variable: $PageNumber = 1
  --> [End]

[Load More Button]
  --> Show Progress: "Loading..."
  --> Change Variable: $PageNumber = $PageNumber + 1
  --> Call Microflow: GetOrdersPage
       - Parameter: $PageNumber
       - Returns: $MoreOrders
  --> List Operation: $OrderList = $OrderList + $MoreOrders
  --> Hide Progress
  --> [End]
```

---

## 9. Error Handling

### The Nanoflow Error Model

Nanoflows support structured error handling, similar to try/catch in programming languages. When an activity fails (a microflow call returns an error, a JavaScript action throws an exception, or a validation fails), you can catch that error and respond gracefully instead of showing the user a generic red error banner.

### Setting Up Error Handling

Every activity in a nanoflow has an "Error Handling" setting with three options:

| Option | Behavior | When to Use |
|---|---|---|
| **Abort** (default) | The nanoflow stops immediately. A generic error message is shown to the user. | Only for truly unexpected errors where you have no recovery strategy. |
| **Custom without rollback** | The nanoflow continues along a custom error path. Object changes are preserved. | When you want to handle the error and keep any partial work done so far. |
| **Custom with rollback** | The nanoflow continues along a custom error path. Object changes made in this nanoflow are reverted. | When partial changes would leave the data in an inconsistent state. |

### Try/Catch Pattern in Nanoflows

The visual equivalent of try/catch:

```
[Start]
  --> Show Progress: "Saving..."
  --> Call Microflow: ACT_SaveOrder           <-- Error handling: Custom without rollback
       |                                           |
       | (success path)                           | (error path)
       v                                           v
  --> Hide Progress                           --> Hide Progress
  --> Close Page                              --> Log Message: $latestError
  --> [End: success]                          --> Show Message: "Could not save.
                                                   Please check your connection
                                                   and try again."
                                              --> [End: failure]
```

The `$latestError` variable is automatically available on the error path. It contains the error message from the failed activity.

### The $latestError Variable

When an activity fails and you have custom error handling configured, Mendix provides a special variable:

| Variable | Type | Content |
|---|---|---|
| `$latestError` | String | The error message from the failed activity |
| `$latestSoapFault` | SoapFault object | Only available for failed web service calls (not common in nanoflows) |

`$latestError` contains the raw error message. For microflow calls, this is whatever error message the microflow generated (either from a throw or an unhandled exception). For JavaScript actions, this is the message from the thrown Error object.

### Error Propagation

Understanding how errors propagate through nested nanoflows:

| Situation | Behavior |
|---|---|
| **Sub-nanoflow throws, outer nanoflow has error handling on the call** | The outer nanoflow catches the error and follows the error path. |
| **Sub-nanoflow throws, outer nanoflow does NOT have error handling** | The error propagates up. If no handler is found, the user sees a generic error dialog. |
| **Microflow throws, nanoflow has error handling on the call** | The nanoflow catches it. `$latestError` contains the microflow's error message. |
| **JavaScript action throws, nanoflow has error handling** | The nanoflow catches it. `$latestError` contains the Error object's message. |
| **JavaScript action rejects a Promise, nanoflow has error handling** | Same as above -- rejected promises are caught by the nanoflow's error handler. |

### User Feedback on Failures

Do not just catch errors silently. The user needs to know what happened and what to do about it.

**Good error feedback patterns:**

| Situation | Feedback | Implementation |
|---|---|---|
| Server unreachable | "Unable to reach the server. Your changes are saved locally and will sync when you reconnect." | Show Message (Warning) |
| Validation error from server | Show the specific validation message on the relevant field | Validation Feedback activity |
| Permission denied | "You don't have permission to perform this action. Contact your administrator." | Show Message (Error) |
| Timeout | "The request took too long. Please try again." | Show Message (Warning) |
| Unknown error | "Something went wrong. Please try again. If the problem persists, contact support." + Log the full error for developers | Show Message (Error) + Log Message |

**Anti-patterns:**

- Catching an error and doing nothing (silent failure). The user thinks the action succeeded.
- Showing the raw `$latestError` to the user. It often contains technical details (stack traces, SQL errors) that confuse users and may leak sensitive information.
- Not logging the error. Even if you show a friendly message to the user, log the technical details to the console for debugging.

### Handling Errors with Progress Indicators

A common bug: Show Progress is called, then a microflow fails, and Hide Progress is never called. The user is stuck with a permanent spinner.

**Always ensure Hide Progress is called on both success and error paths:**

```
[Start]
  --> Show Progress: "Processing..."
  --> Call Microflow: ACT_ProcessData     <-- Error handling: Custom without rollback
       |                                       |
       | (success)                            | (error)
       v                                       v
  --> Hide Progress                       --> Hide Progress
  --> Show Message: "Done."               --> Show Message: "Processing failed."
  --> [End]                               --> [End]
```

### JavaScript Action Error Handling

In JavaScript actions, throw standard JavaScript errors:

```javascript
export async function ValidateCustomFormat(inputString, formatPattern) {
    // BEGIN USER CODE
    if (!inputString) {
        throw new Error("Input string is required.");
    }

    const regex = new RegExp(formatPattern);
    if (!regex.test(inputString)) {
        throw new Error(
            "Input '" + inputString + "' does not match the expected format."
        );
    }

    return true;
    // END USER CODE
}
```

The nanoflow's error handler catches this and puts the Error message into `$latestError`.

For async operations, reject the promise or let the `async` function throw:

```javascript
export async function FetchExternalData(url) {
    // BEGIN USER CODE
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error("HTTP " + response.status + ": " + response.statusText);
    }
    return await response.text();
    // END USER CODE
}
```

---

## 10. Security Implications

### The Fundamental Reality

Everything in a nanoflow runs on the client. The client is the user's browser. The user controls their browser. This means:

**Anything in a nanoflow is visible to the user.**

This is not a theoretical concern. It is trivially easy. A user opens browser dev tools, looks at the JavaScript source, and reads your nanoflow logic. Mendix compiles nanoflows to JavaScript, and while it is not pretty, it is readable enough for someone motivated to extract business rules, conditions, and string literals from it.

### What This Means in Practice

| Nanoflow Contains | Risk | What to Do Instead |
|---|---|---|
| API keys or secrets | User extracts the key and uses it independently, potentially incurring costs or accessing data they should not | Store secrets server-side. Pass them only to microflows. Never hardcode them in nanoflows or JavaScript actions. |
| Pricing calculation logic | Competitor or customer reverse-engineers your pricing model | Calculate prices in a microflow. Return only the result to the client. |
| Discount eligibility rules | User figures out how to qualify for discounts they should not receive | Evaluate discount eligibility server-side. |
| Authorization/permission checks | User bypasses the check by modifying the client-side JavaScript | Always enforce permissions server-side (entity access rules + microflow security). Nanoflow checks are UX conveniences, not security barriers. |
| Feature flag logic | User discovers unreleased features or enables features they should not have | Evaluate feature flags on the server. Return only the boolean result. |
| Hardcoded URLs to internal systems | User discovers internal infrastructure endpoints | Keep internal URLs in server-side constants. |
| Sensitive business rules (underwriting, risk scoring, fraud detection) | User understands and games the system | All sensitive logic must run in microflows. |

### The Two-Layer Security Model

Treat nanoflow security checks as **UX helpers**, not as actual security:

**Layer 1 -- Nanoflow (UX):**

```
[Start]
  --> Decision: $CurrentUser/IsManager?
       - True --> Show Page: ApprovalForm
       - False --> Show Message: "Only managers can approve requests."
  --> [End]
```

This provides a good user experience -- non-managers immediately see a helpful message instead of getting an error after a server round-trip.

**Layer 2 -- Microflow + Entity Access (Actual Security):**

The ApprovalForm's save button calls a microflow. That microflow checks the user's role server-side. The entity access rules prevent non-managers from modifying the approval status. Even if someone bypasses the nanoflow check (by manipulating the client), the server rejects the action.

**Both layers are needed.** The nanoflow provides instant feedback. The server provides actual enforcement. Never rely on only one.

### Entity Access Rules Still Apply

Even though nanoflows manipulate objects on the client, entity access rules are enforced at the server boundary:

| Operation | Where Access Rules Are Checked |
|---|---|
| Nanoflow creates/changes an object locally | No access rule check (it is in the client cache only) |
| Nanoflow calls a microflow that commits the object | Server checks entity access rules before commit |
| Offline app syncs changes to the server | Server checks entity access rules during sync |
| Nanoflow retrieves objects from cache | Only objects that passed access rules when loaded are in the cache |

The practical effect: a user could theoretically modify any attribute on a client-side object in their browser's memory, but the moment that object is sent to the server (via microflow commit or sync), the server's access rules reject unauthorized changes.

### Client-Side Storage Risks

| Storage Location | Visibility | Risk |
|---|---|---|
| Client object cache (in-memory) | Visible via browser dev tools (Memory tab) | User can inspect any object currently loaded |
| IndexedDB / Local Storage | Visible via browser dev tools (Application tab) | Persistent data visible to anyone with access to the browser |
| Offline SQLite database (mobile) | Accessible if device is rooted/jailbroken | All offline-synced data can be extracted |
| JavaScript source (nanoflow logic) | Visible via browser dev tools (Sources tab) | All nanoflow conditions, constants, and logic readable |

### Practical Security Checklist for Nanoflows

| Check | Action |
|---|---|
| Does the nanoflow contain any hardcoded strings that are sensitive? | Move them to server-side constants, access via microflow. |
| Does the nanoflow make authorization decisions? | Ensure the same check exists server-side (microflow or entity access). |
| Does the nanoflow calculate prices, totals, or financial values? | Either calculate server-side, or validate the result server-side before committing. |
| Could a user benefit from modifying the local object before it syncs/commits? | Add server-side validation in the commit microflow. |
| Does a JavaScript action reference internal URLs or service endpoints? | Route calls through a server-side microflow instead. |
| Is any PII (personal data) being processed in nanoflow logic beyond what is displayed? | Minimize PII in client-side logic. Process it server-side. |

### Never Trust Client-Side Computed Values

If a nanoflow calculates a total, a discount, a tax amount, or any value that affects money or permissions, **recalculate it on the server before committing**.

```
Nanoflow (UX, instant feedback):
  --> Change $Order/EstimatedTotal = calculated value
  --> Show updated total on the page

Microflow (actual save):
  --> Recalculate TotalAmount from line items (server-side)
  --> Compare with what the client sent
  --> If they match: commit
  --> If they differ: log a warning, commit the server-calculated value
```

---

## 11. Common Patterns

### Pattern 1: Client-Side Form Validation

**Problem:** You want to validate a form before submitting to the server. Server validation works but takes 200ms+ per attempt, which is frustrating on complex forms.

**Solution:** Validate locally in a nanoflow, then call a microflow only when the form is valid.

```
[Start]
  --> Create Variable: $IsValid (Boolean) = true
  --> Decision: $Customer/Name is empty?
       - True --> Validation Feedback on $Customer/Name: "Name is required."
                  Change Variable: $IsValid = false
       - False --> (continue)
  --> Decision: $Customer/Email is empty?
       - True --> Validation Feedback on $Customer/Email: "Email is required."
                  Change Variable: $IsValid = false
       - False --> Decision: $Customer/Email does not match email pattern?
            - True --> Validation Feedback on $Customer/Email: "Enter a valid email address."
                       Change Variable: $IsValid = false
            - False --> (continue)
  --> Decision: $Customer/PhoneNumber length < 10?
       - True --> Validation Feedback on $Customer/PhoneNumber: "Phone number must be at least 10 digits."
                  Change Variable: $IsValid = false
       - False --> (continue)
  --> Decision: $IsValid?
       - True --> Call Microflow: ACT_Customer_Save
                  --> Close Page
       - False --> [End] (stay on page, validation messages are shown)
```

**Key details:**

- Do not stop at the first error. Check every field so the user can fix all issues at once.
- Use the `$IsValid` flag pattern to track overall form validity without short-circuiting.
- Do not rely solely on client-side validation. The microflow should also validate, because a malicious user can skip the nanoflow entirely.

### Pattern 2: Optimistic UI Updates

**Problem:** The user clicks a "like" button or toggles a favorite. You want the UI to respond instantly, but the change must persist on the server.

**Solution:** Update the UI immediately via the nanoflow, then call a microflow to persist the change. If the microflow fails, revert.

```
[Start]
  --> Change Object: $Post
       - IsLikedByCurrentUser = not($Post/IsLikedByCurrentUser)
       - LikeCount = if $Post/IsLikedByCurrentUser
                     then $Post/LikeCount + 1
                     else $Post/LikeCount - 1
  --> Call Microflow: ACT_Post_ToggleLike     <-- Error handling: Custom without rollback
       |                                           |
       | (success)                                | (error)
       v                                           v
  --> [End]                                   --> Change Object: $Post (revert)
                                                   - IsLikedByCurrentUser = not($Post/IsLikedByCurrentUser)
                                                   - LikeCount = (revert count)
                                              --> Show Message: "Could not save. Please try again."
                                              --> [End]
```

The user sees the like count change instantly. If the server call fails, the change is reverted and the user is notified.

### Pattern 3: Conditional Visibility Logic

**Problem:** A section of the page should show or hide based on a user's selection in a dropdown or checkbox.

**Solution:** Use a non-persistable helper entity with boolean attributes that control visibility.

**Setup:**

1. Create a non-persistable entity: `PageHelper` with attributes `ShowAdvancedOptions` (Boolean), `ShowShippingAddress` (Boolean), etc.
2. On the page's data view, create the `PageHelper` object via a nanoflow.
3. Bind conditional visibility on page sections to these attributes.
4. When the user changes a value, an on-change nanoflow toggles the relevant boolean.

**On-change nanoflow:**

```
[Start: $Customer/OrderType changed]
  --> Decision: $Customer/OrderType = 'Shipping'?
       - True --> Change Object: $PageHelper
                   - ShowShippingAddress = true
       - False --> Change Object: $PageHelper
                   - ShowShippingAddress = false
  --> [End]
```

**Why use a helper entity instead of the actual entity?**

- You do not pollute your domain model with UI-only attributes.
- The helper is non-persistable, so it is never committed to the database.
- Multiple visibility conditions can be controlled independently.

### Pattern 4: Local Filtering and Sorting

**Problem:** You have a list of objects displayed on the page and want the user to filter or sort them without a server call.

**Solution:** Use nanoflows to filter and sort the client-side list.

**Filtering:**

```
[Start: Search text changed]
  --> Decision: $SearchText is empty?
       - True --> Change Variable: $DisplayedList = $FullList
       - False --> Create List: $FilteredList (empty)
                   --> Loop: $Item in $FullList
                        --> Decision: $Item/Name contains $SearchText
                             (case-insensitive)
                             - True --> List Operation:
                                        Add $Item to $FilteredList
                             - False --> (continue)
                   --> Change Variable: $DisplayedList = $FilteredList
  --> [End]
```

**Sorting:**

For sorting, you can use a nanoflow "Sort" activity on a list, specifying the attribute and direction. If you need multi-column sorting or custom sort logic, a JavaScript action is more practical:

```javascript
export async function SortByAttribute(list, attributeName, ascending) {
    // BEGIN USER CODE
    return list.sort((a, b) => {
        const valA = a.get(attributeName);
        const valB = b.get(attributeName);

        if (valA === valB) return 0;
        if (valA === null || valA === undefined) return 1;
        if (valB === null || valB === undefined) return -1;

        const comparison = valA < valB ? -1 : 1;
        return ascending ? comparison : -comparison;
    });
    // END USER CODE
}
```

**Performance note:** Keep the list under a few hundred items for client-side filtering. For larger datasets, use a microflow with server-side filtering.

### Pattern 5: Wizard / Multi-Step Form

**Problem:** A complex data entry process needs to be broken into multiple steps with back/forward navigation.

**Solution:** Use a non-persistable `WizardState` entity to track the current step, and nanoflows for navigation between steps.

**Setup:**

1. Create `WizardState` (non-persistable): `CurrentStep` (Integer), `TotalSteps` (Integer), and associations to the data being collected at each step.
2. Use conditional visibility on the page to show only the widgets for the current step.
3. Next/Previous buttons trigger nanoflows that change `CurrentStep`.

**Next button nanoflow:**

```
[Start]
  --> Call Nanoflow: ValidateCurrentStep
       - Returns: $StepIsValid (Boolean)
  --> Decision: $StepIsValid?
       - True --> Decision: $WizardState/CurrentStep = $WizardState/TotalSteps?
            - True --> Call Microflow: ACT_SubmitWizardData
                       --> Show Page: WizardComplete
            - False --> Change Object: $WizardState
                         - CurrentStep = $WizardState/CurrentStep + 1
       - False --> (stay on current step, validation messages shown)
  --> [End]
```

Each step validates locally before allowing progression. The final step calls a microflow to commit everything at once.

### Pattern 6: Debounced Search Input

**Problem:** A search field triggers a microflow on every keystroke, causing excessive server calls.

**Solution:** Use a JavaScript action to debounce the input, then trigger the search nanoflow only after the user stops typing.

**JavaScript action -- Debounce:**

```javascript
// BEGIN EXTRA CODE
let debounceTimer = null;
// END EXTRA CODE

export async function DebouncedAction(delayMs) {
    // BEGIN USER CODE
    return new Promise((resolve) => {
        if (debounceTimer) {
            clearTimeout(debounceTimer);
        }
        debounceTimer = setTimeout(() => {
            resolve(true);
        }, delayMs);
    });
    // END USER CODE
}
```

**On-change nanoflow on the search input:**

```
[Start: $SearchHelper/SearchText changed]
  --> Call JavaScript Action: DebouncedAction
       - delayMs = 300
  --> Decision: $SearchHelper/SearchText length >= 3?
       - True --> Show Progress: "Searching..."
                  --> Call Microflow: ACT_Search
                       - SearchTerm = $SearchHelper/SearchText
                       - Returns: $Results
                  --> Hide Progress
       - False --> Change Variable: $Results = empty list
  --> [End]
```

The nanoflow fires on every keystroke, but the debounce JavaScript action delays execution by 300ms. If the user types another character within that window, the previous call is cancelled. The microflow only fires when the user pauses.

### Pattern 7: Confirm Before Delete

**Problem:** The user clicks a delete button. You want to confirm before actually deleting.

**Solution:** Use a nanoflow with a decision or a confirmation popup.

**Simple approach (Show Message with type Confirmation is not available in nanoflows):**

Since nanoflows do not have a built-in confirmation dialog activity, use one of these alternatives:

**Option A -- Custom confirmation page:**

```
[Start]
  --> Show Page: DeleteConfirmation (modal)
       - Pass $Order
  --> [End]
```

On the confirmation page, the "Yes, Delete" button runs:

```
[Start]
  --> Show Progress: "Deleting..."
  --> Call Microflow: ACT_Order_Delete
  --> Hide Progress
  --> Close Page
  --> Close Page (close the parent page too, if needed)
  --> [End]
```

**Option B -- JavaScript action with native confirm():**

```javascript
export async function ShowConfirmDialog(message) {
    // BEGIN USER CODE
    return window.confirm(message);
    // END USER CODE
}
```

```
[Start]
  --> Call JavaScript Action: ShowConfirmDialog
       - message = "Are you sure you want to delete this order?"
       - Returns: $Confirmed (Boolean)
  --> Decision: $Confirmed?
       - True --> Call Microflow: ACT_Order_Delete
                  --> Close Page
       - False --> [End]
```

Option A looks better (styled to match your app). Option B is faster to implement and uses the browser's native dialog.

### Pattern 8: Loading State Management

**Problem:** Multiple microflow calls need to execute, and the UI should reflect the current loading state without stacking multiple progress indicators.

**Solution:** Use a helper entity to manage loading state.

```
[Start: Page Load]
  --> Change Object: $PageHelper
       - IsLoading = true
       - LoadingMessage = "Loading dashboard data..."
  --> Call Microflow: ACT_GetDashboardData
       - Returns: $DashboardData
  --> Change Object: $PageHelper
       - IsLoading = false
  --> [End]
```

Bind the loading overlay's visibility to `$PageHelper/IsLoading` and bind a text widget to `$PageHelper/LoadingMessage`. This gives you full control over the loading UX without relying on the generic progress indicator.

---

## 12. Debugging

### The Challenge

Nanoflows run in the browser, which means server-side Mendix logs do not capture nanoflow execution. You need different tools.

### Browser Developer Tools

The browser's dev tools are your primary debugging instrument for nanoflows. Here is what each tab gives you:

| Tab | What to Look For | Nanoflow Relevance |
|---|---|---|
| **Console** | Errors, warnings, `console.log()` output from JavaScript actions, Mendix client messages | Log Message activities in nanoflows write here. JavaScript action errors appear here. |
| **Network** | XHR/Fetch requests to `/xas/` (microflow calls), timing, payload size | Every "Call Microflow" from a nanoflow generates an XHR request. Look for failed requests (red), slow requests, and large payloads. |
| **Sources** | JavaScript source code, breakpoints | Nanoflow-compiled JavaScript is here, though it is hard to read. JavaScript actions are more debuggable. Set breakpoints in your JS action code. |
| **Application** | IndexedDB, Local Storage, Session Storage | In offline apps, the local database is an IndexedDB database. You can browse its contents. |
| **Performance** | Flame charts, function execution timing | Record a trace while triggering a nanoflow to see exactly how long each step takes and whether it blocks the main thread. |
| **Memory** | Heap snapshots | Useful for finding memory leaks in JavaScript actions or tracking down issues with large object caches. |

### Using Console.log in JavaScript Actions

The most direct way to debug nanoflow behavior is to add logging in JavaScript actions:

```javascript
export async function ProcessOrder(order) {
    // BEGIN USER CODE
    console.log("ProcessOrder called with:", {
        guid: order.getGuid(),
        status: order.get("Status"),
        total: order.get("TotalAmount")?.toString()
    });

    // ... processing logic ...

    console.log("ProcessOrder result:", {
        newStatus: order.get("Status"),
        isValid: result
    });

    return result;
    // END USER CODE
}
```

Use `console.group()` / `console.groupEnd()` to organize complex debugging output:

```javascript
console.group("Order Validation");
console.log("Checking required fields...");
// ... checks ...
console.log("Checking business rules...");
// ... checks ...
console.groupEnd();
```

### The Nanoflow Debugger in Studio Pro

Studio Pro includes a nanoflow debugger that works similarly to the microflow debugger:

1. **Set breakpoints**: Click the line between two activities to set a breakpoint (red circle appears).
2. **Run the app locally**: The app runs in your browser as usual.
3. **Trigger the nanoflow**: Click the button or perform the action that fires the nanoflow.
4. **Studio Pro pauses execution**: The debugger highlights the current activity. You can inspect variables and objects.
5. **Step through**: Use Step Into, Step Over, and Continue to walk through the nanoflow.

**Debugger panels:**

| Panel | Shows |
|---|---|
| **Variables** | Current values of all variables in scope (strings, numbers, booleans, etc.) |
| **Current Object** | Attributes and associations of the object in context |
| **Call Stack** | The chain of nanoflow calls if you are inside a sub-nanoflow |
| **Breakpoints** | All active breakpoints across all nanoflows |

**Limitations of the Studio Pro nanoflow debugger:**

- It requires the app to run locally (cannot debug a deployed app).
- It works only in the browser, not in native mobile apps (use Chrome DevTools for that via remote debugging).
- JavaScript action internals are not visible in the Studio Pro debugger. For those, use browser dev tools.
- Debugging pauses the nanoflow execution, which can cause timeouts on any pending microflow calls.

### Debugging Offline Apps

Offline apps add complexity because data lives in a local database:

| Technique | How |
|---|---|
| **Inspect IndexedDB** | Open browser dev tools > Application > IndexedDB. Browse the local database tables to see what data is synced. |
| **Monitor sync requests** | Watch the Network tab during sync. Look at the requests to `/xas/` endpoints. Check for errors. |
| **Force sync** | Add a temporary "Debug Sync" button that triggers a Synchronize activity. Use this to test sync behavior on demand. |
| **Check sync errors** | Sync errors appear in the browser console. Look for conflict messages, access rule violations, or validation failures. |
| **Clear local data** | In the browser's Application tab, you can delete the IndexedDB database to simulate a first-time install. |

### Common Client-Side Issues and How to Diagnose Them

| Issue | Symptom | Diagnosis | Fix |
|---|---|---|---|
| **Nanoflow does not fire** | Nothing happens when the user clicks the button | Check the button's on-click event is set to the nanoflow. Check conditional visibility -- the button might be hidden. Check browser console for JavaScript errors. | Fix the event binding or resolve the JS error. |
| **Retrieve returns empty** | The nanoflow logic expects objects but gets an empty list | The objects are not in the client cache. In online apps, they may not have been loaded by the page. In offline apps, they may not be in the sync scope. | Ensure the page loads the needed objects, or use a microflow to fetch them. |
| **Object attribute is null/undefined** | A decision or calculation fails because an attribute has no value | The attribute was not set before this point, or the object was not fully loaded. | Add null checks in decisions. Ensure objects are fully loaded before processing. |
| **Microflow call fails silently** | The nanoflow appears to hang or skip steps after a microflow call | The microflow threw an error and the nanoflow has no error handling. | Add custom error handling to the microflow call activity. |
| **Progress indicator never disappears** | The app shows a permanent spinner | A nanoflow called Show Progress but the Hide Progress was skipped (error path not handled). | Ensure Hide Progress is on every possible path, including error paths. |
| **Page shows stale data after a microflow call** | The microflow changed data on the server, but the page still shows old values | The client cache was not refreshed. | Return the modified object from the microflow, or enable "Refresh in Client" on the commit. |
| **Performance degrades over time** | The app gets slower the longer it is open | Memory leak in a JavaScript action, or the client cache is growing unbounded. | Profile with the Memory tab. Check for event listeners that are not cleaned up. |
| **Offline sync fails** | Sync shows an error or objects do not appear after sync | Access rule violations, validation errors on the server, or sync scope misconfiguration. | Check the browser console for sync error details. Review entity access and sync configuration. |
| **Nanoflow works locally but not in production** | Logic behaves differently after deployment | Different data state, missing objects in cache, or different timing. | Compare the client-side data state. Check that all referenced constants and enumerations are deployed. |
| **JavaScript action error not caught** | Generic error banner appears instead of your custom error handling | The error handling on the JavaScript action call is still set to "Abort" (default). | Change it to "Custom without rollback" and add an error path. |

### Adding Diagnostic Logging to Nanoflows

For nanoflows you expect to debug often, add explicit logging:

```
[Start]
  --> Log Message: "NF_ValidateOrder started. Order ID: " + $Order/OrderNumber
  --> (... validation logic ...)
  --> Log Message: "NF_ValidateOrder result: IsValid = " + toString($IsValid)
  --> [End]
```

These Log Messages go to the browser console (`console.log()`). They persist across page navigations until the user clears the console or closes the browser.

For production apps, consider wrapping diagnostic logs in a condition:

```
[Start]
  --> Decision: $AppSettings/EnableDebugLogging?
       - True --> Log Message: "NF_ValidateOrder diagnostic info..."
       - False --> (skip logging)
  --> (... rest of the nanoflow ...)
```

This lets you enable verbose logging without deploying code changes.

### Remote Debugging for Mobile Apps

For Mendix native mobile apps running on a physical device:

| Platform | Tool | Setup |
|---|---|---|
| **Android** | Chrome DevTools (remote debugging) | Enable USB debugging on the device. Connect via USB. Open `chrome://inspect` in Chrome on your computer. |
| **iOS** | Safari Web Inspector | Enable Web Inspector on the iOS device (Settings > Safari > Advanced). Connect via USB. Open Safari on your Mac and find the device under Develop menu. |
| **Both** | Mendix Make It Native app | Connects to your locally running app. Errors appear in your local Studio Pro console and the device's remote dev tools. |

### Debugging Checklist

When a nanoflow is not working as expected, go through this checklist:

1. **Open browser console** -- look for red errors or yellow warnings.
2. **Check the Network tab** -- are microflow calls succeeding? Look for HTTP 4xx/5xx responses.
3. **Verify object state** -- use a Log Message or JavaScript action to print the current object's attributes.
4. **Check conditional paths** -- add Log Messages before and after each decision to see which path is taken.
5. **Check for null values** -- the most common nanoflow bug is an unexpected null/empty attribute.
6. **Test with breakpoints** -- if you can reproduce locally, use the Studio Pro nanoflow debugger.
7. **Isolate the problem** -- create a minimal nanoflow that reproduces the issue. Remove complexity until you find the offending activity.
8. **Check data availability** -- especially for retrieves. Is the data actually in the client cache or local DB?
9. **Review error handling** -- ensure all microflow calls and JavaScript action calls have custom error handling configured.
10. **Check timing** -- if the issue is intermittent, it may be a race condition. Look for async operations completing out of order.

---

## Quick Reference

### Nanoflow Activity Cheat Sheet

| Category | Works in Nanoflow | Microflow Only |
|---|---|---|
| **Object** | Create, Change, Delete, Retrieve, Rollback | Commit |
| **List** | All (Aggregate, Create, Filter, Sort, etc.) | -- |
| **Flow** | Decision, Merge, Loop, Break, Continue | -- |
| **Calls** | Call Nanoflow, Call Microflow, Call JS Action | Call Java Action, Call REST, Call SOAP, Call OData |
| **Client** | Show/Close Page, Show Message, Validation, Show/Hide Progress, Synchronize, Sign Out, Log Message | Download File, Generate Document |
| **Integration** | -- | REST, SOAP, XML Mapping, Email |

### Decision Framework Summary

```
Do I need this to work offline?
  YES --> Nanoflow (mandatory)
  NO  --> Does this logic contain secrets or sensitive business rules?
            YES --> Microflow
            NO  --> Does it need database access beyond what's on the client?
                      YES --> Microflow (or nanoflow calling a microflow)
                      NO  --> Does it need to be instant (< 50ms)?
                                YES --> Nanoflow
                                NO  --> Either works. Prefer nanoflow for
                                        UI logic, microflow for data logic.
```

### Naming Conventions

Consistent naming makes your project navigable. A common convention:

| Type | Prefix | Example |
|---|---|---|
| Nanoflow (general) | `NF_` | `NF_ValidateOrderForm` |
| Nanoflow (on-change event) | `OCH_` | `OCH_Customer_EmailChanged` |
| Nanoflow (on-click event) | `ACT_` (or `NF_`) | `ACT_Order_Delete` |
| Nanoflow (page data source) | `DS_` | `DS_GetCurrentOrder` |
| Nanoflow (on-page-load) | `OPL_` | `OPL_InitializeDashboard` |
| JavaScript Action | `JSA_` | `JSA_CopyToClipboard` |

The exact convention does not matter as much as consistency. Pick one and stick with it across the project.

---

## Further Reading

- [Mendix Documentation -- Nanoflows](https://docs.mendix.com/refguide/nanoflows/) -- Official reference for all nanoflow activities and properties.
- [Mendix Documentation -- JavaScript Actions](https://docs.mendix.com/refguide/javascript-actions/) -- How to create and use custom JavaScript actions.
- [Mendix Documentation -- Offline-First](https://docs.mendix.com/refguide/offline-first/) -- Complete guide to offline-first app development.
- [Mendix Documentation -- Client Activities](https://docs.mendix.com/refguide/client-activities/) -- Reference for Show Page, Show Message, and other client activities.
- [Mendix Documentation -- Nanoflow Error Handling](https://docs.mendix.com/refguide/error-handling-in-nanoflows/) -- Official documentation on error handling in nanoflows.
- [Mendix Documentation -- Data Synchronization](https://docs.mendix.com/refguide/synchronization/) -- How offline data sync works, including conflict resolution.
