# Mendix Pages and UI Design Guide

## A Practical Reference for Building Effective User Interfaces in Mendix

**Version:** 1.0
**Date:** February 2026
**Classification:** Public

---

## Table of Contents

1. [Page Types](#1-page-types)
   - [Responsive Pages](#responsive-pages)
   - [Native Mobile Pages](#native-mobile-pages)
   - [Pop-Up Pages](#pop-up-pages)
   - [Page Templates](#page-templates)
   - [Choosing the Right Page Type](#choosing-the-right-page-type)
2. [Layouts and Navigation](#2-layouts-and-navigation)
   - [Layout Structure](#layout-structure)
   - [Layout Types and Inheritance](#layout-types-and-inheritance)
   - [Navigation Documents](#navigation-documents)
   - [Menu Widgets](#menu-widgets)
   - [Responsive Design](#responsive-design)
   - [Sidebar and Header Patterns](#sidebar-and-header-patterns)
3. [Widgets](#3-widgets)
   - [Built-In Widgets Reference](#built-in-widgets-reference)
   - [Configuring Widgets](#configuring-widgets)
   - [Custom Widgets](#custom-widgets)
   - [Pluggable Widget API](#pluggable-widget-api)
   - [Widget Events and Actions](#widget-events-and-actions)
4. [Data Views, List Views, and Data Grids](#4-data-views-list-views-and-data-grids)
   - [Data View](#data-view)
   - [List View](#list-view)
   - [Data Grid 2](#data-grid-2)
   - [Template Grid](#template-grid)
   - [When to Use Which](#when-to-use-which)
   - [Performance Implications](#performance-implications)
   - [Lazy Loading](#lazy-loading)
   - [Search Capabilities](#search-capabilities)
5. [Conditional Visibility and Editability](#5-conditional-visibility-and-editability)
   - [Expression-Based Visibility](#expression-based-visibility)
   - [Role-Based Visibility](#role-based-visibility)
   - [Conditional Editability](#conditional-editability)
   - [Dynamic Forms](#dynamic-forms)
   - [Common Patterns and Pitfalls](#common-patterns-and-pitfalls)
6. [Snippets and Building Blocks](#6-snippets-and-building-blocks)
   - [Snippets](#snippets)
   - [Building Blocks](#building-blocks)
   - [When to Use Snippets vs Building Blocks](#when-to-use-snippets-vs-building-blocks)
   - [Organizing Reusable UI Components](#organizing-reusable-ui-components)
7. [Styling with Atlas](#7-styling-with-atlas)
   - [Atlas UI Framework Overview](#atlas-ui-framework-overview)
   - [Design Properties](#design-properties)
   - [Customizing SCSS](#customizing-scss)
   - [Theme Overrides](#theme-overrides)
   - [Working with Design Tokens](#working-with-design-tokens)
   - [Responsive Utility Classes](#responsive-utility-classes)
8. [Accessibility](#8-accessibility)
   - [ARIA Labels](#aria-labels)
   - [Keyboard Navigation](#keyboard-navigation)
   - [Screen Reader Support](#screen-reader-support)
   - [Color Contrast](#color-contrast)
   - [Accessibility Testing](#accessibility-testing)
9. [Performance Optimization](#9-performance-optimization)
   - [Reducing Page Load Time](#reducing-page-load-time)
   - [Widget Count Optimization](#widget-count-optimization)
   - [Lazy Loading Strategies](#lazy-loading-strategies)
   - [Data Source Optimization](#data-source-optimization)
   - [Image and Asset Optimization](#image-and-asset-optimization)
   - [Profiling and Measuring Performance](#profiling-and-measuring-performance)
10. [Common UI Patterns](#10-common-ui-patterns)
    - [Master-Detail](#master-detail)
    - [Wizard / Stepper](#wizard--stepper)
    - [Dashboard Layout](#dashboard-layout)
    - [Search-and-Filter](#search-and-filter)
    - [Infinite Scroll and Pagination](#infinite-scroll-and-pagination)
    - [Confirmation Dialogs](#confirmation-dialogs)
    - [Empty States and Loading Indicators](#empty-states-and-loading-indicators)

---

## 1. Page Types

Mendix pages are the primary interface between your application and its users. Every screen a user sees is a page, and choosing the correct page type is the first decision you make when building any piece of UI.

### Responsive Pages

Responsive pages are the default and most commonly used page type in Mendix. They render in a web browser and automatically adapt their layout to the viewport size of the device.

**Key characteristics:**

- Rendered as HTML/CSS/JavaScript in the browser
- Adapt to desktop, tablet, and mobile screen sizes using the Atlas grid system
- Support all web-based widgets from the Mendix Marketplace
- Can be opened in content, full-screen, or pop-up mode
- Served from the Mendix Runtime over HTTP/HTTPS

**When to use responsive pages:**

- Building web applications accessed through a browser
- Applications that must work across desktop and mobile browsers without a native app
- Internal tools, portals, dashboards, and admin panels
- Any application where you do not need device-native features (camera, GPS, push notifications) that require native integration

**Creating a responsive page:**

1. Right-click a module in the App Explorer
2. Select **Add page**
3. Choose a layout that targets the **Responsive** profile
4. Select a page template or start with a blank page
5. Set the page title and URL (for deep-linking support)

**Page URLs and deep linking:**

Every responsive page can have a URL assigned in its properties. This enables deep linking, bookmarking, and sharing URLs directly to specific pages. URL parameters map to page parameters, letting you pass entity IDs or other values through the URL.

```
Page URL:  /orders/{OrderId}
Resolves:  https://yourapp.com/p/orders/12345
```

Set page URLs in the page properties under the **General** tab. Use descriptive, lowercase, hyphenated paths. Avoid exposing internal IDs in URLs when not necessary for usability.

### Native Mobile Pages

Native mobile pages are designed for Mendix Native Mobile apps, built on React Native. They render using native device components rather than HTML, delivering a look and feel that matches the host operating system (iOS or Android).

**Key characteristics:**

- Rendered using React Native components, not a web view
- Access to device-native features: camera, GPS, biometrics, push notifications, file system
- Offline-first architecture with local data synchronization
- Separate navigation profile from responsive pages
- Only available in apps built with the Mendix Native Mobile Builder

**When to use native mobile pages:**

- Apps distributed through the Apple App Store or Google Play Store
- Applications requiring offline functionality with automatic data sync
- Use cases demanding native performance (smooth animations, gesture handling)
- Apps that need deep integration with device hardware

**Key differences from responsive pages:**

| Feature | Responsive | Native Mobile |
|---------|-----------|---------------|
| Rendering | HTML/CSS in browser | React Native components |
| Offline support | Limited (requires custom PWA work) | Built-in offline-first |
| Device features | Browser APIs only | Full native access |
| Distribution | URL in browser | App Store / Play Store |
| Styling | SCSS/CSS | Native styling system |
| Widget compatibility | All web widgets | Native-specific widgets only |

**Offline-first considerations:**

Native pages use a local SQLite database that synchronizes with the server. Design your pages with the understanding that:

- Data may be stale if the device has not synced recently
- Synchronization conflicts must be handled in your domain model
- Large datasets should use selective sync to limit what is stored on-device
- Images and files have separate sync behavior from entity data

### Pop-Up Pages

Pop-up pages (also called modal pages or dialog pages) display on top of the current page as an overlay. They keep the user in context while presenting additional information or capturing input.

**Key characteristics:**

- Render as a modal dialog overlaying the current page
- Block interaction with the underlying page until closed
- Have a configurable size: small, medium, large, or full-screen
- Can be closed by the user (close button) or programmatically (via a microflow or nanoflow)
- Share the same data context as the calling page when opened from a widget action

**When to use pop-up pages:**

- Confirmation dialogs ("Are you sure you want to delete this?")
- Quick-edit forms that do not warrant a full page navigation
- Detail views opened from a list item
- Wizard steps within a contained workflow
- Displaying supplementary information without losing the parent page context

**Pop-up sizing guidelines:**

| Size | Approximate Width | Use Case |
|------|-------------------|----------|
| Small | ~400px | Confirmations, simple inputs |
| Medium | ~600px | Edit forms, detail views |
| Large | ~900px | Complex forms, data grids |
| Full-screen | Viewport width | Dashboards, document editing |

**Opening a pop-up page:**

Pop-up pages are opened through the **Show page** action in microflows, nanoflows, or widget event handlers (such as an on-click action). Set the **Page location** property to **Pop-up** in the page's properties.

**Best practices for pop-ups:**

- Do not nest pop-ups more than one level deep. If you find yourself opening a pop-up from a pop-up, reconsider your navigation design.
- Always provide a clear way to close the pop-up (Save, Cancel, or an X button).
- Use pop-ups for focused tasks. If the form has more than 8-10 fields, consider a full page instead.
- Set a meaningful page title so users know what the pop-up is for.
- Use the **Close page** action in your save/cancel microflows to programmatically close the pop-up after the action completes.

### Page Templates

Page templates are pre-built page designs that serve as starting points when creating new pages. They accelerate development by providing proven layouts for common use cases.

**Built-in template categories:**

- **Blank** -- An empty page with only the layout structure
- **Dashboard** -- Multi-column layouts with card-style widgets for KPIs and charts
- **List** -- Pages with a data grid or list view as the primary content
- **Detail** -- Single-record detail views with a data view and form fields
- **Form** -- Input forms for creating or editing entity instances
- **Master-Detail** -- Split-pane layouts with a list on one side and detail on the other
- **Wizard** -- Multi-step forms with a progress indicator
- **Login** -- Authentication pages with branded login forms

**Creating custom page templates:**

You can create your own page templates to enforce consistency across your application:

1. Create a module specifically for templates (e.g., `UI_Templates`)
2. Design a page with the layout and placeholder widgets you want
3. Right-click the page and select **Create page template**
4. Set the template name, category, and description
5. Mark placeholder areas where developers should replace content

Custom templates are particularly valuable in large teams where multiple developers build pages simultaneously. They reduce the "blank page" problem and ensure a consistent baseline design.

### Choosing the Right Page Type

Use this decision framework:

1. **Is this a native mobile app?** Use native mobile pages.
2. **Is this a quick action that keeps the user in context?** Use a pop-up page.
3. **Is this a standalone screen the user navigates to?** Use a responsive page.
4. **Are you starting a new page?** Start from a page template, then customize.

---

## 2. Layouts and Navigation

Layouts define the structural skeleton of your pages. Navigation defines how users move between pages. Together, they form the foundation of your application's user experience.

### Layout Structure

A layout in Mendix is a reusable page structure that defines regions (header, sidebar, content area, footer) shared across multiple pages. Every page must reference a layout.

**Anatomy of a layout:**

```
+--------------------------------------------------+
|                    HEADER                         |
|  [Logo]  [Navigation Menu]         [User Menu]   |
+--------+-----------------------------------------+
|        |                                         |
| SIDE   |              CONTENT                    |
| BAR    |           (page content                 |
|        |            renders here)                |
| [Nav]  |                                         |
| [Nav]  |                                         |
| [Nav]  |                                         |
|        |                                         |
+--------+-----------------------------------------+
|                    FOOTER                         |
+--------------------------------------------------+
```

**Layout components:**

- **Layout containers**: Structural containers that divide the layout into rows and columns. They use the Atlas 12-column grid system.
- **Placeholders**: Regions within the layout where page-specific content is inserted. Every layout needs at least one placeholder, typically the main content area.
- **Widgets in layouts**: Any widget placed directly in the layout (not in a placeholder) appears on every page that uses that layout. Headers, navigation menus, and footers are typically placed here.
- **Scroll containers**: Special containers that define scrollable regions. You typically have one scroll container in your layout that wraps the main content area.

**Scroll container regions:**

The scroll container is a critical layout widget with three fixed regions:

| Region | Behavior | Typical Content |
|--------|----------|-----------------|
| Top | Fixed, does not scroll | Header, navigation bar |
| Center | Scrollable | Main content placeholder |
| Bottom | Fixed, does not scroll | Footer, action bar |

Configure the scroll container's **Scroll behavior** property. The center region scrolls while top and bottom remain fixed. You can also nest scroll containers for split-pane layouts, though this should be done carefully to avoid confusing scroll behavior.

### Layout Types and Inheritance

Mendix supports layout inheritance, where one layout extends another. This lets you build a hierarchy:

```
Atlas_Default (base layout)
  +-- Layout_Sidebar (adds sidebar navigation)
  |     +-- Layout_Sidebar_Collapsed (sidebar starts collapsed)
  +-- Layout_FullWidth (no sidebar, full-width content)
  +-- Layout_Popup (minimal chrome for pop-up pages)
```

**Base layout**: Defines the outermost structure (scroll container, header, footer). Does not reference another layout.

**Derived layout**: References a parent layout and adds content or structure within the parent's placeholders. This creates a chain: base layout > derived layout > page.

**Best practices for layout hierarchy:**

- Keep the hierarchy shallow. Two levels (base + one derived) is ideal. Three levels is the practical maximum before maintenance becomes difficult.
- Put truly global elements (app header, global navigation) in the base layout.
- Put context-specific elements (sidebar nav, section headers) in derived layouts.
- Create a separate minimal layout for pop-up pages that strips out navigation and footers.
- Create a separate layout for login/authentication pages that removes the sidebar and shows a centered content area.

### Navigation Documents

Navigation documents define the menu structure and routing for your application. Each navigation profile (responsive web, tablet, phone, native mobile) has its own navigation document.

**Navigation profiles:**

| Profile | Target | Configuration |
|---------|--------|---------------|
| Responsive Web | Desktop and mobile browsers | Primary navigation document for web apps |
| Tablet (Web) | Tablet browsers | Optional, falls back to responsive if not set |
| Phone (Web) | Phone browsers | Optional, falls back to responsive if not set |
| Native Phone | Native mobile app | Required for native apps, separate navigation tree |
| Native Tablet | Native tablet app | Optional, falls back to native phone if not set |

**Configuring navigation:**

1. Open the **Navigation** document from the App Explorer
2. Select the profile you want to configure
3. Set the **Default home page** -- the first page users see after login
4. Build the navigation tree by adding menu items
5. Each menu item has a caption, icon, target page, and optional visibility rules

**Navigation item properties:**

- **Caption**: The text displayed in navigation menus
- **Icon**: A glyphicon or image shown alongside the caption
- **On click**: The action to perform (typically **Show a page**)
- **Visible for**: User roles that can see this navigation item (security-based visibility)

**Role-based navigation:**

Set the **Visible for** property on navigation items to control which user roles see which menu entries. This is distinct from page access rights. A user might have access to a page (they can open it via a deep link) but not see it in the navigation. Conversely, if you show a navigation item but the user lacks page access, they will get an error when clicking it. Always keep navigation visibility and page access in sync.

### Menu Widgets

Mendix provides several widgets for rendering navigation menus on pages and layouts:

**Menu bar:**
A horizontal menu typically placed in the header. Renders the navigation tree as a horizontal bar with dropdown submenus. Supports one level of nesting.

**Navigation tree:**
A vertical, collapsible tree menu typically placed in a sidebar. Renders the full navigation tree with expandable sections. Supports multiple levels of nesting.

**Simple menu bar:**
A simplified horizontal menu that renders as a flat list of links without dropdown functionality. Good for secondary navigation within a section.

**Menu source options:**
All menu widgets can pull their items from one of three sources:

1. **Navigation document**: Automatically renders items from the selected navigation profile. Changes to the navigation document are reflected everywhere.
2. **Menu document**: A standalone menu document that can be reused across multiple widgets. Useful when you need a menu that differs from the main navigation.
3. **Pages**: Manually configured menu items pointing to specific pages. Gives full control but requires manual maintenance.

**Recommendation**: Use the navigation document as the source for your primary menu. Use menu documents for secondary navigation (e.g., a settings sub-menu). Use manual pages only for small, static menus that rarely change.

### Responsive Design

Mendix uses a 12-column grid system (based on Bootstrap's grid) for responsive layouts. Containers, layout grids, and widgets can be configured to span different numbers of columns at different breakpoints.

**Breakpoints:**

| Breakpoint | Name | Width | Typical Device |
|------------|------|-------|----------------|
| xs | Extra small | < 576px | Phones (portrait) |
| sm | Small | >= 576px | Phones (landscape) |
| md | Medium | >= 768px | Tablets |
| lg | Large | >= 992px | Desktops |
| xl | Extra large | >= 1200px | Large desktops |

**Layout grid configuration:**

The layout grid widget lets you define rows and columns with responsive behavior:

```
Desktop (lg):     [----4----] [----4----] [----4----]   (3 columns)
Tablet (md):      [------6------] [------6------]       (2 columns)
Phone (xs):       [------------12------------]          (1 column, stacked)
```

Set column widths per breakpoint in the layout grid's properties. Each row's columns must add up to 12 at every breakpoint.

**Responsive visibility:**

You can hide widgets at specific breakpoints using the **Visible** design property:

- **Phone only**: Shows only on xs/sm breakpoints
- **Tablet and above**: Shows on md and larger
- **Desktop only**: Shows on lg and larger

This lets you create device-specific UI variations within a single page. For example, show a compact card layout on phones and a data grid on desktops.

**Best practices for responsive design:**

- Design mobile-first: start with the smallest screen and add complexity for larger screens
- Test at every breakpoint, not just desktop. Use browser developer tools to simulate device sizes.
- Avoid horizontal scrolling. If content overflows horizontally on mobile, reduce column counts or use scroll containers.
- Use percentage-based widths rather than fixed pixel widths for containers.
- Collapse sidebar navigation into a hamburger menu on small screens. Atlas layouts handle this automatically.
- Large data grids do not work well on phones. Switch to a list view or card layout for mobile breakpoints.

### Sidebar and Header Patterns

**Fixed sidebar with collapsible toggle:**

The Atlas default sidebar layout includes a sidebar region that can be toggled between expanded and collapsed states. The sidebar state persists during the user's session.

To implement a collapsible sidebar:
1. Use a layout with a scroll container that has left and center regions
2. Place navigation in the left region
3. Add a toggle button that sets a boolean attribute controlling the sidebar width
4. Use conditional CSS classes to switch between expanded (250px) and collapsed (60px) widths

**Sticky header:**

The header in a scroll container's top region is sticky by default (it stays visible as the user scrolls the center content). To make the entire page scrollable instead (header scrolls away), place all content including the header inside the center region.

**Breadcrumb navigation:**

For hierarchical applications with deep page structures, add breadcrumb navigation below the header. Use a combination of text widgets with page links or use a breadcrumb widget from the Marketplace. Each breadcrumb segment should link to its parent page.

---

## 3. Widgets

Widgets are the building blocks of Mendix pages. Every piece of UI -- from a simple text label to a complex data grid -- is a widget. Understanding the widget catalog and how to configure widgets effectively is fundamental to building good Mendix applications.

### Built-In Widgets Reference

Mendix provides a comprehensive set of built-in widgets. Here is a categorized reference:

**Input widgets:**

| Widget | Purpose | Key Properties |
|--------|---------|----------------|
| Text Box | Single-line text input | Placeholder, max length, regex validation |
| Text Area | Multi-line text input | Rows, max length, counter |
| Number Input | Numeric input with formatting | Decimal precision, grouping, min/max |
| Date Picker | Date and/or time selection | Format, placeholder, min/max date |
| Drop-Down | Single selection from a list | Data source (enum or association) |
| Radio Buttons | Single selection displayed as radio buttons | Layout (horizontal/vertical) |
| Check Box | Boolean toggle | Label position |
| Reference Selector | Select an associated object | Selectable objects data source |
| Reference Set Selector | Select multiple associated objects | Selectable objects, display attribute |
| Input Reference Set Selector | Multi-select with search | Search functionality built in |
| File Manager | File upload and download | Max file size, allowed extensions |
| Image Uploader | Image upload with preview | Max file size, thumbnail size |

**Display widgets:**

| Widget | Purpose | Key Properties |
|--------|---------|----------------|
| Text | Static or dynamic text display | Render mode (text, heading, paragraph) |
| Dynamic Text | Text with parameters from data context | Template with placeholders |
| Image | Display static or dynamic images | Source (static, dynamic, URL) |
| Label | Form field label | For (associated input widget) |
| Page Title | Displays the page title | Render as heading level |

**Container widgets:**

| Widget | Purpose | Key Properties |
|--------|---------|----------------|
| Container | Generic div wrapper | Class, style, visibility |
| Group Box | Collapsible container with header | Collapsible, header caption |
| Tab Container | Tabbed content panels | Tab pages, default tab |
| Scroll Container | Scrollable region with fixed areas | Top/center/bottom regions |
| Layout Grid | Responsive column grid | Rows, columns, breakpoint widths |
| Table | Fixed-row, fixed-column layout | Row count, column count |
| Header | Semantic header element | Contains arbitrary widgets |
| Footer | Semantic footer element | Contains arbitrary widgets |
| Sidebar Toggle | Toggles sidebar visibility | Target region |

**Button widgets:**

| Widget | Purpose | Key Properties |
|--------|---------|----------------|
| Action Button | General-purpose button | On-click action, style, icon |
| Link Button | Styled as a hyperlink | On-click action |
| Drop-Down Button | Button with dropdown menu | Menu items with actions |
| Sign-Out Button | Signs the user out | Redirect page after sign-out |

**Data widgets:**

| Widget | Purpose | Key Properties |
|--------|---------|----------------|
| Data View | Displays a single object | Data source, editable |
| List View | Displays a list of objects | Data source, page size, templates |
| Data Grid 2 | Tabular data with sorting, filtering | Columns, data source, pagination |
| Template Grid | Grid of templated items | Data source, rows/columns, template |
| Gallery | Card-based grid layout | Data source, items per row, template |

**Navigation widgets:**

| Widget | Purpose | Key Properties |
|--------|---------|----------------|
| Menu Bar | Horizontal navigation menu | Source (navigation/menu document) |
| Navigation Tree | Vertical collapsible menu | Source, expandable |
| Simple Menu Bar | Flat horizontal links | Source |
| Open Link Button | Opens a URL | URL attribute or expression |

### Configuring Widgets

Every widget has a properties panel in Studio Pro with several tabs:

**General tab:**
Core widget configuration. For input widgets, this includes the attribute binding, placeholder text, label, and validation. For display widgets, this includes content configuration and rendering options.

**Data source tab (data widgets only):**
Configures where the widget gets its data. Options include:

- **Context**: Uses the data view context from a parent widget
- **Microflow**: Calls a microflow to retrieve data
- **Nanoflow**: Calls a nanoflow (client-side) to retrieve data
- **Database**: Retrieves directly from the database with XPath constraints
- **Association**: Follows an association from the current context

**Events tab:**
Configures actions triggered by user interactions:

- **On click**: Action when the widget is clicked
- **On change**: Action when the value changes (input widgets)
- **On enter**: Action when the user presses Enter
- **On leave**: Action when focus leaves the widget

**Appearance tab:**
Visual configuration including:

- **Design properties**: Pre-defined visual options from the Atlas theme (e.g., button style, spacing)
- **Class**: Custom CSS class names to apply
- **Style**: Inline CSS styles (use sparingly -- prefer classes)

**Common tab:**
Properties shared across all widgets:

- **Name**: A unique identifier used in microflows and visibility expressions
- **Tab index**: Controls keyboard tab order
- **Visibility**: Conditional visibility rules (covered in Section 5)
- **Editable**: Conditional editability rules (covered in Section 5)

**Validation tab (input widgets):**
Configure client-side validation:

- **Required**: Whether the field must have a value
- **Validation expression**: A Mendix expression that must evaluate to true
- **Validation message**: The error message shown when validation fails

Example validation expression for an email field:
```
if $currentObject/Email != empty and not(contains($currentObject/Email, '@')) then 'Please enter a valid email address' else ''
```

### Custom Widgets

When built-in widgets do not meet your needs, you can use custom widgets from the Mendix Marketplace or build your own.

**Finding widgets in the Marketplace:**

1. In Studio Pro, go to the **Marketplace** pane (View > Marketplace)
2. Search for the widget you need
3. Review the widget's documentation, ratings, and compatibility
4. Click **Download** to add it to your project

**Popular Marketplace widgets:**

| Widget | Purpose | Publisher |
|--------|---------|-----------|
| Rich Text Editor | WYSIWYG text editing | Mendix |
| Charts | Data visualization (line, bar, pie) | Mendix |
| Tree View | Hierarchical data display | Mendix |
| Carousel | Image/content slider | Mendix |
| Maps | Interactive maps with markers | Mendix |
| Progress Bar | Visual progress indicator | Mendix |
| Badge | Notification badge/count | Mendix |
| Signature | Capture handwritten signatures | Community |
| Barcode Scanner | Scan barcodes/QR codes | Mendix |
| Video Player | Embedded video playback | Mendix |

**Evaluating custom widgets:**

Before adding a Marketplace widget to your project, evaluate it on these criteria:

- **Mendix version compatibility**: Does it support your Studio Pro version?
- **Maintenance status**: When was it last updated? Is it actively maintained?
- **Publisher**: Mendix-published widgets get official support. Community widgets may not.
- **Reviews and downloads**: Higher numbers indicate more community validation.
- **Platform support**: Does it support responsive web, native mobile, or both?
- **Dependencies**: Does it add large JavaScript libraries to your bundle?

### Pluggable Widget API

The Pluggable Widget API (introduced in Mendix 8) is the modern framework for building custom widgets using React (for web) or React Native (for native mobile).

**Architecture overview:**

A pluggable widget consists of:

1. **Widget XML**: Defines the widget properties (what the developer configures in Studio Pro)
2. **React Component**: The rendering logic (JSX/TSX)
3. **Preview Component**: Optional component for rendering a preview in Studio Pro's design mode
4. **SCSS Styles**: Widget-specific styling

**Widget XML structure:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<widget id="com.example.mywidget" pluginWidget="true"
        needsEntityContext="true"
        xmlns="http://www.mendix.com/widget/1.0/"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.mendix.com/widget/1.0/
        ../xsd/widget.xsd">
    <name>My Widget</name>
    <description>A custom widget example</description>
    <properties>
        <propertyGroup caption="General">
            <property key="label" type="string">
                <caption>Label</caption>
                <description>The label text</description>
            </property>
            <property key="dataAttribute" type="attribute">
                <caption>Data Attribute</caption>
                <description>The attribute to display</description>
                <attributeTypes>
                    <attributeType name="String"/>
                    <attributeType name="Integer"/>
                </attributeTypes>
            </property>
            <property key="onClickAction" type="action">
                <caption>On Click</caption>
                <description>Action to trigger on click</description>
            </property>
        </propertyGroup>
    </properties>
</widget>
```

**React component:**

```tsx
import { createElement, ReactElement } from "react";
import { MyWidgetContainerProps } from "../typings/MyWidgetProps";

export function MyWidget(props: MyWidgetContainerProps): ReactElement {
    const value = props.dataAttribute?.displayValue ?? "";

    const handleClick = () => {
        if (props.onClickAction?.canExecute) {
            props.onClickAction.execute();
        }
    };

    return (
        <div className="my-widget" onClick={handleClick}>
            <span className="my-widget-label">{props.label}</span>
            <span className="my-widget-value">{value}</span>
        </div>
    );
}
```

**Setting up a widget development environment:**

1. Install Node.js (LTS version) and Yeoman
2. Install the Mendix widget generator: `npm install -g @mendix/generator-widget`
3. Scaffold a new widget: `yo @mendix/widget MyWidget`
4. Develop using `npm start` for hot-reloading in a test project
5. Build the production widget with `npm run build`
6. The `.mpk` file in `dist/` is the deployable widget

**Key property types in the Pluggable Widget API:**

| Property Type | Purpose | Example Use |
|---------------|---------|-------------|
| `string` | Text configuration | Labels, placeholders |
| `boolean` | Toggle configuration | Show/hide features |
| `integer` | Numeric configuration | Page sizes, limits |
| `attribute` | Bind to an entity attribute | Display or edit data |
| `expression` | Mendix expression | Computed values |
| `action` | Microflow/nanoflow/page action | On-click handlers |
| `object` | Grouped sub-properties | Complex configuration |
| `datasource` | Data source configuration | Lists, grids |
| `icon` | Icon selection | Button icons |
| `widgets` | Nested widget area | Custom layout areas |

### Widget Events and Actions

Widgets communicate with the application through actions. Understanding the action system is important for building interactive pages.

**Available action types:**

| Action | Behavior |
|--------|----------|
| Show a page | Opens a page (in content, pop-up, or full-screen) |
| Call a microflow | Executes server-side logic |
| Call a nanoflow | Executes client-side logic |
| Open link | Opens a URL, phone number, or email |
| Create object | Creates a new entity instance and opens a page |
| Save changes | Commits the current data view object |
| Cancel changes | Rolls back changes to the data view object |
| Close page | Closes the current page (useful for pop-ups) |
| Delete object | Deletes the current object with confirmation |
| Sign out | Signs the user out of the application |
| Synchronize | Synchronizes offline data (native mobile) |

**Action chaining:**

In nanoflows, you can chain multiple actions together. For example, a "Submit and Close" button might:

1. Validate form data (nanoflow logic)
2. Call a microflow to save to the database
3. Show a success message
4. Close the pop-up page

Build this logic in a nanoflow and assign it as the button's on-click action.

---

## 4. Data Views, List Views, and Data Grids

Data presentation widgets are the backbone of most Mendix applications. Choosing the right one for each use case directly impacts usability, performance, and maintainability.

### Data View

The data view displays and optionally allows editing of a single object. It is the most fundamental data widget -- nearly every page that shows or edits data has at least one data view.

**Data source options:**

- **Context**: Receives its object from a surrounding data widget (another data view, a list view, etc.)
- **Microflow**: Calls a microflow that returns a single object
- **Nanoflow**: Calls a nanoflow that returns a single object
- **Listen to widget**: Listens to a data grid or list view selection -- when the user selects an item, the data view updates

**Key properties:**

- **Editable**: Yes (form mode) or No (read-only display mode). When editable, input widgets inside the data view can modify the object's attributes.
- **Show footer**: Shows Save and Cancel buttons automatically. Disable this if you want custom buttons.
- **Close on save/cancel**: Automatically closes the page after saving or canceling. Useful for pop-up edit forms.
- **Empty entity message**: Text displayed when the data source returns no object. Always set this to avoid showing a blank space.

**Nested data views:**

Data views can be nested to display associated objects. For example, an Order data view might contain a nested data view showing the associated Customer:

```
[Data View: Order]
  Order Number: {OrderNumber}
  Order Date: {OrderDate}

  [Data View: Customer (over association Order_Customer)]
    Customer Name: {FullName}
    Email: {Email}
```

This is efficient because the associated object is loaded in the same request as the parent. However, deeply nesting data views (more than 3 levels) can make pages hard to maintain and debug.

**Read-only vs. editable data views:**

Set the data view to **not editable** when displaying information the user should not modify. This has several benefits:

- Input widgets inside render as plain text, which is cleaner and faster
- No commit/rollback overhead
- Prevents accidental changes
- Reduces the client-side object state management

### List View

The list view displays a list of objects, each rendered using a customizable template. It is the most flexible list widget because you have full control over the item layout.

**Data source options:**

- **Database**: XPath query with optional sorting and constraints
- **Microflow**: Returns a list of objects from server-side logic
- **Nanoflow**: Returns a list from client-side logic
- **Association**: Follows an association from the data view context

**Key properties:**

- **Page size**: Number of items to display per page (before pagination or "load more")
- **Scroll direction**: Vertical (default) or horizontal
- **Number of columns**: Items per row (for grid-style rendering)
- **Click action**: What happens when a user clicks an item
- **Pull-down action** (native mobile): Action triggered by pull-to-refresh gesture

**Template design:**

The list view template is the UI that repeats for each item. Design it like you would a single data view:

```
[List View: Orders]
  Template:
  +------------------------------------------+
  | Order #{OrderNumber}     {OrderDate}     |
  | Customer: {Customer/FullName}            |
  | Total: {TotalAmount}        [View] [Edit]|
  +------------------------------------------+
```

Keep list view templates lean. Every widget in the template is multiplied by the number of visible items. A template with 20 widgets displaying 50 items means 1,000 widget instances on the page.

### Data Grid 2

Data Grid 2 is the modern, pluggable replacement for the legacy Data Grid. It provides a tabular data display with sorting, filtering, pagination, and column customization.

**Key features:**

- Column-based layout with configurable headers
- Built-in sorting (click column headers)
- Built-in filtering (per-column filter widgets)
- Pagination (page numbers or virtual scrolling)
- Row click actions
- Column resizing and reordering (configurable)
- Export capabilities (with add-on widgets)
- Dynamic column visibility

**Column types:**

| Column Type | Content | Use Case |
|-------------|---------|----------|
| Attribute | Displays an entity attribute | Text, numbers, dates, enums |
| Dynamic Text | Template with multiple attributes | Combined fields like "FirstName LastName" |
| Custom Content | Any widget(s) | Buttons, images, badges, custom formatting |

**Filter widgets:**

Data Grid 2 supports pluggable filter widgets placed in column headers:

| Filter Widget | Type | Behavior |
|---------------|------|----------|
| Text Filter | String attributes | Contains, starts with, equals |
| Number Filter | Numeric attributes | Equals, greater than, less than, between |
| Date Filter | Date/DateTime attributes | Between, before, after, specific date |
| Drop-Down Filter | Enum/Boolean attributes | Single or multi-select from values |

**Pagination options:**

- **Paging buttons**: Traditional page numbers (Page 1 of 10). Best for desktop applications where users expect structured navigation.
- **Virtual scrolling**: Loads data as the user scrolls. Provides a smoother experience but makes it harder for users to jump to a specific position.
- **Load more button**: Shows a button at the bottom to load the next batch. Good for mobile-friendly list-like displays.

### Template Grid

The template grid displays data in a grid of customizable tiles. It is a hybrid between a list view and a data grid -- it gives you the layout flexibility of a list view in a grid arrangement.

**Key properties:**

- **Rows** and **Columns**: Fixed number of rows and columns per page
- **Page size**: Total items per page (rows x columns)
- **Template**: Custom widget layout for each cell

**Use cases:**

- Product catalogs with image-heavy tiles
- Card-based dashboards
- Image galleries
- Any grid layout where items need rich, custom formatting

**Note**: For new projects, consider the **Gallery** widget as a modern alternative to the template grid. The Gallery widget is pluggable, supports responsive column counts, and has more consistent behavior across devices.

### When to Use Which

| Scenario | Widget | Reason |
|----------|--------|--------|
| View/edit a single record | Data View | Purpose-built for single-object display and editing |
| Display a scrollable list with custom item layout | List View | Full template control per item |
| Display tabular data with sorting and filtering | Data Grid 2 | Built-in sort, filter, and pagination |
| Display data as a grid of cards/tiles | Gallery or Template Grid | Grid layout with custom templates |
| Master-detail: list with detail panel | Data Grid 2 + Data View (listen to) | Grid selection drives detail view |
| Simple read-only list with minimal UI | List View | Lightweight, no grid overhead |
| Data export to Excel/CSV | Data Grid 2 | Export add-on support |
| Mobile-friendly data display | List View or Gallery | Better responsive behavior than grids |

### Performance Implications

The data widget you choose has significant performance consequences:

**Data View:**
- Low overhead. Loads a single object.
- Nested data views over associations are efficient because Mendix batches association retrievals.
- Microflow data sources add one server round-trip. Use nanoflows for data that is already available on the client.

**List View:**
- Performance scales linearly with the number of items and the complexity of the template.
- Every widget in the template is instantiated for every visible item. A template with 15 widgets and a page size of 50 creates 750 widget instances.
- Association-based data in list items can cause N+1 query patterns. Use microflow data sources or XPath constraints to retrieve pre-loaded data.
- **Guideline**: Keep list view templates under 10-12 widgets. If you need more, consider a data grid or a detail pop-up.

**Data Grid 2:**
- Efficient for large datasets because it only renders visible columns and rows.
- Sorting and filtering happens server-side (for database data sources), so the client does not need to load the entire dataset.
- Virtual scrolling mode loads data in chunks, reducing initial load time.
- Custom content columns with complex widgets can slow down rendering. Prefer attribute columns when possible.

**Template Grid / Gallery:**
- Similar performance profile to list views. Total items rendered = rows x columns.
- Image-heavy tiles should use lazy loading for images to reduce initial load.

**General rules of thumb:**

1. Reduce page size to the minimum that provides a good user experience. Users rarely need 100 items visible at once.
2. Favor attribute columns over custom content columns in data grids.
3. Use database data sources over microflow data sources when you can express the query in XPath.
4. Index database columns that are used for sorting and filtering.
5. Use pagination instead of loading all items at once.

### Lazy Loading

Lazy loading defers the retrieval of data until it is needed, reducing initial page load time.

**Built-in lazy loading behaviors:**

- **Data Grid 2 with virtual scrolling**: Only loads the visible rows plus a small buffer. Additional rows are loaded as the user scrolls.
- **List View with "load more" button**: Initially loads the first page of items. The user clicks to load more.
- **Tab containers**: By default, Mendix loads the content of all tabs when the page opens. To lazy-load tab content, set the **Tab rendering** property to **Lazy** (the tab content loads only when the user clicks the tab).
- **Conditional visibility**: Widgets with visibility set to false are not rendered and their data sources are not called. This effectively provides lazy loading -- show a data widget only when the user requests it.

**Implementing lazy loading with a data view:**

You can implement manual lazy loading by wrapping a data widget in a container with conditional visibility:

1. Add a boolean attribute to your context entity (e.g., `ShowDetails`)
2. Add a button: "Show Details" that sets `ShowDetails` to true
3. Wrap the data view in a container with visibility condition: `$currentObject/ShowDetails`
4. The data view's data source only fires when the container becomes visible

### Search Capabilities

**Data Grid 2 filtering:**

Data Grid 2 is the primary widget for search functionality. Each column can have a filter widget that contributes to the overall query:

```
+----------------------------------------------------------------+
| Name [____filter____] | Status [__dropdown__] | Date [__range__] |
|----------------------------------------------------------------|
| Acme Corp              | Active                | 2026-01-15       |
| Beta Inc               | Inactive              | 2026-01-20       |
+----------------------------------------------------------------+
```

Filters are AND-combined: all active filters must match for a row to appear.

**Custom search forms:**

For more complex search requirements, build a custom search form using a non-persistent entity:

1. Create a non-persistent entity `SearchCriteria` with attributes matching your search fields
2. Place a data view with a microflow data source that creates a new `SearchCriteria` object
3. Add input widgets bound to the search attributes
4. Add a "Search" button that calls a microflow, passing the `SearchCriteria` object
5. The microflow constructs an XPath or OQL query and returns results to a list widget

This pattern gives you full control over search logic, including:
- OR conditions across fields
- Full-text search with CONTAINS
- Range searches (date from/to, price min/max)
- Search across associations
- Saved search criteria

**Full-text search:**

Mendix does not have a built-in full-text search engine, but you can approximate it:

```xpath
[contains(Name, $SearchCriteria/SearchTerm) or
 contains(Description, $SearchCriteria/SearchTerm) or
 contains(Email, $SearchCriteria/SearchTerm)]
```

For production applications with serious search requirements, consider integrating with an external search service (Elasticsearch, Algolia) via REST.

---

## 5. Conditional Visibility and Editability

Conditional visibility and editability let you build dynamic pages that adapt based on data, user roles, and application state. Used well, they create focused, contextual interfaces. Used poorly, they create confusing, unpredictable pages.

### Expression-Based Visibility

Expression-based visibility lets you show or hide widgets based on a Mendix expression that evaluates to a Boolean.

**Setting up expression-based visibility:**

1. Select the widget in the page editor
2. Go to the **Common** tab (or the **Visibility** section in the properties panel)
3. Set **Visible** to **Yes** and configure the condition
4. Choose **Based on expression** and enter your expression

**Expression examples:**

Show a "Late" badge when an order is overdue:
```
$currentObject/DueDate < [%CurrentDateTime%] and $currentObject/Status != 'Completed'
```

Show an approval section only for orders above a threshold:
```
$currentObject/TotalAmount > 10000
```

Show different content based on an enumeration value:
```
$currentObject/Status = 'Draft'
```

Show a widget only when an associated object exists:
```
$currentObject/Customer != empty
```

**Important behavior:**

- When a widget is hidden by visibility, it is **not rendered** in the DOM. This means its data sources are not called, its events do not fire, and it does not consume client resources.
- Visibility conditions are evaluated on the client side. The data needed for the expression must already be available in the client's context.
- Changing an attribute that a visibility expression depends on immediately shows/hides the widget without a server round-trip.

### Role-Based Visibility

Role-based visibility controls which widgets are visible based on the current user's role. This is configured separately from expression-based visibility and is applied in addition to it (both must be true for the widget to show).

**Setting up role-based visibility:**

1. Select the widget
2. In the **Visibility** section, find the **Module roles** setting
3. Select which roles can see the widget
4. If no roles are selected, all roles can see the widget (the default)

**Use cases:**

- Show an "Admin Actions" button group only to administrators
- Display cost/margin information only to finance roles
- Show a "Reassign" button only to managers
- Hide technical details from end users

**Security vs. visibility:**

Role-based visibility is a **UI convenience**, not a security mechanism. It hides the widget from the page, but a technically savvy user could still call the underlying microflow or access the data through the API if server-side security is not configured.

Always pair role-based visibility with:

- **Entity access rules**: Restrict which roles can read/write entity attributes
- **Microflow/nanoflow security**: Restrict which roles can execute logic
- **Page access**: Restrict which roles can open specific pages

The rule of thumb: role-based visibility controls what users **see**; entity access and microflow security controls what users **can do**. Both are required.

### Conditional Editability

Conditional editability controls whether input widgets are editable or read-only based on conditions. This is separate from visibility -- the widget is still visible, but it becomes non-interactive.

**Setting up conditional editability:**

1. Select an input widget inside an editable data view
2. In the **Editable** property, choose:
   - **Default** (inherits from the data view)
   - **Never** (always read-only)
   - **Conditionally** (based on an expression or attribute)

**Expression-based editability examples:**

Make a field editable only when the record is in Draft status:
```
$currentObject/Status = 'Draft'
```

Make a field editable only when the user has not submitted:
```
$currentObject/IsSubmitted = false
```

Allow editing only within a time window:
```
$currentObject/CreatedDate > [%BeginOfCurrentDay%]
```

**Attribute-based editability:**

You can also control editability with a Boolean attribute:

1. Add a Boolean attribute to the entity (e.g., `IsEditable`)
2. Set the input widget's **Editable** property to **Based on attribute** > `IsEditable`
3. Control the attribute value in microflows based on business logic

This is useful when editability depends on complex logic that is better expressed in a microflow than an expression.

### Dynamic Forms

Dynamic forms change their structure based on data or context. They are one of the most powerful UI patterns in Mendix but require careful design.

**Pattern: Show/hide sections based on a selection:**

```
[Drop-Down: AccountType]
  Options: Individual, Business, Government

[Container: Individual Fields]
  Visible: $currentObject/AccountType = 'Individual'
  - First Name
  - Last Name
  - Date of Birth

[Container: Business Fields]
  Visible: $currentObject/AccountType = 'Business'
  - Company Name
  - Registration Number
  - Contact Person

[Container: Government Fields]
  Visible: $currentObject/AccountType = 'Government'
  - Agency Name
  - Department
  - Authorization Code
```

When the user selects an account type, the relevant fields appear. The other sections are not rendered, so their validation rules do not fire.

**Pattern: Progressive disclosure:**

Show fields progressively as the user fills out the form:

```
[Step 1: Always visible]
  - Email Address

[Step 2: Visible when Email is not empty]
  - Password
  - Confirm Password

[Step 3: Visible when Password is not empty]
  - First Name
  - Last Name

[Step 4: Visible when Name is not empty]
  - [Submit Button]
```

This reduces cognitive load by showing only what the user needs to focus on right now.

**Pattern: Conditional required fields:**

Some fields should be required only under certain conditions. Implement this with validation expressions in a microflow:

```
// In the Save microflow:
if ($Order/ShippingMethod = 'Delivery' and $Order/DeliveryAddress = empty) then
    // Add validation feedback
    addValidationFeedback($Order, 'DeliveryAddress', 'Delivery address is required for delivery orders')
end if
```

### Common Patterns and Pitfalls

**Pitfall: Too many visibility conditions on one page.**
If you have 20+ containers with different visibility conditions, the page becomes difficult to understand and debug. Consider splitting into multiple pages or using a tab container instead.

**Pitfall: Validation on hidden fields.**
When a required input widget is hidden by visibility, its validation still runs if the widget is inside an editable data view that gets committed. Handle this by:
- Removing the required validation from the widget and doing it in the save microflow (where you can check the visibility condition)
- Using a non-persistent entity as a buffer and only copying validated fields to the persistent entity

**Pitfall: Performance of attribute-based visibility.**
Every visibility expression is re-evaluated when any attribute in the data view context changes. If you have many complex expressions, this can cause noticeable UI lag. Keep visibility expressions simple.

**Pattern: Visibility with user roles and data conditions combined.**
Sometimes you need both role-based and expression-based visibility. For example, only admins can see the "Override Price" field, but only when the order status is "Review":

1. Set module role visibility to "Admin" only
2. Set expression-based visibility to `$currentObject/Status = 'Review'`

Both conditions must be true. The widget shows only for admins looking at orders in Review status.

---

## 6. Snippets and Building Blocks

Reusable UI components are essential for maintaining consistency and reducing duplication in Mendix applications. Mendix provides two mechanisms for this: snippets and building blocks.

### Snippets

A snippet is a reusable piece of page content that can be embedded in multiple pages. Changes to the snippet automatically propagate to all pages that use it. Snippets are the Mendix equivalent of a shared component or partial view.

**Key characteristics:**

- Defined once, used many times across pages
- Changes propagate automatically to all usages
- Can have an entity context (data parameter)
- Rendered at runtime -- the snippet content is included in the page
- Supports all widgets that can be placed on a page
- Can contain other snippets (nesting)

**Creating a snippet:**

1. Right-click a module in the App Explorer
2. Select **Add other** > **Snippet**
3. Optionally set an entity parameter if the snippet needs data context
4. Design the snippet content using the same editor as pages

**Using a snippet on a page:**

1. Drag a **Snippet Call** widget onto the page
2. Select the snippet to embed
3. If the snippet has an entity parameter, ensure it is placed inside a data view of the matching entity type

**Example: Reusable customer card snippet:**

Create a snippet `Snippet_CustomerCard` with entity parameter `Customer`:

```
[Snippet: Snippet_CustomerCard]
  Entity: MyModule.Customer

  +------------------------------------------+
  | [Image: ProfilePhoto]                    |
  | Name: {FullName}                         |
  | Email: {Email}                           |
  | Phone: {PhoneNumber}                     |
  | Member since: {CreatedDate}              |
  +------------------------------------------+
```

Use this snippet anywhere you display a customer: order detail pages, customer lists, dashboards, pop-ups. When you update the card design, every page picks up the change.

**Snippet best practices:**

- Name snippets with a `Snippet_` prefix and a descriptive name
- Group related snippets in a dedicated module (e.g., `UI_Components`)
- Keep snippets focused on a single responsibility -- a snippet that does too much becomes hard to reuse
- Document the expected entity context in the snippet name (e.g., `Snippet_OrderSummary`, `Snippet_UserAvatar`)
- Avoid deeply nesting snippets (snippet within snippet within snippet). Two levels is reasonable; three is the limit.

### Building Blocks

Building blocks are design-time templates that are copied (not referenced) into pages. They serve as reusable starting points that you then customize per page.

**Key characteristics:**

- Copied into the page at design time, not referenced at runtime
- Changes to the building block do not affect existing usages
- Appear in the **Building Blocks** pane in Studio Pro
- Can include placeholder text and sample data
- Primarily used for layout patterns, not data-connected components
- Grouped into categories for easy discovery

**Creating a building block:**

1. Design the UI pattern on a page
2. Select the widgets you want to include
3. Right-click and select **Create building block**
4. Set a name, category, and preview image
5. The building block appears in the Building Blocks pane

**Built-in building block categories:**

Atlas UI ships with building blocks in these categories:

| Category | Examples |
|----------|---------|
| Cards | Info card, action card, image card |
| Headers | Page header with breadcrumb, hero header |
| Lists | List with icon, list with badge |
| Forms | Login form, registration form, search form |
| Dashboards | KPI row, chart card |
| Wizards | Step indicator, wizard form |
| Empty States | No results, error state |
| Footers | Simple footer, footer with links |

### When to Use Snippets vs Building Blocks

| Criterion | Snippet | Building Block |
|-----------|---------|----------------|
| Changes propagate? | Yes, automatically | No, copies are independent |
| Connected to data? | Yes, via entity parameter | No, design-time only |
| Runtime overhead? | Minimal (included in page) | None (copied at design time) |
| Use case | Shared components that must stay in sync | Starter templates for one-off customization |
| Example | Customer card shown on 10 pages | A "hero header" pattern adapted per page |

**Decision guide:**

- If the component should look and behave identically everywhere and changes should propagate, use a **snippet**.
- If you want a starting layout that will be customized on each page, use a **building block**.
- If the component needs data from an entity, you almost certainly need a **snippet**.
- If the component is purely structural (layout grid with spacing classes), a **building block** is fine.

### Organizing Reusable UI Components

As your application grows, organization of reusable components becomes critical:

**Module structure:**

```
UI_Components/
  Snippets/
    Snippet_CustomerCard
    Snippet_OrderSummary
    Snippet_StatusBadge
    Snippet_AddressBlock
    Snippet_FileList
  Building Blocks/
    (stored automatically in the building blocks pane)
  Layouts/
    Layout_MainNav
    Layout_Popup
    Layout_FullWidth
  Page Templates/
    PT_ListPage
    PT_DetailPage
    PT_DashboardPage
```

**Naming conventions:**

| Type | Convention | Example |
|------|-----------|---------|
| Snippet | `Snippet_` + descriptive name | `Snippet_CustomerCard` |
| Building Block | Category + descriptive name | `Card_ProductInfo` |
| Layout | `Layout_` + variant name | `Layout_Sidebar` |
| Page Template | `PT_` + pattern name | `PT_MasterDetail` |

**Cross-module reuse:**

When creating snippets that are used across multiple modules, place them in a shared UI module. Set the module's access rules to allow all necessary modules to access the snippets and their associated entities. Avoid circular dependencies between the UI module and feature modules.

---

## 7. Styling with Atlas

Atlas UI is the design framework that ships with every Mendix application. It provides a theme, design properties, layout components, and SCSS architecture for consistent, customizable styling.

### Atlas UI Framework Overview

Atlas UI provides:

- **Theme**: A complete visual theme with colors, typography, spacing, and component styles
- **Design Properties**: Configurable visual options for widgets (applied in Studio Pro without writing CSS)
- **Page Templates**: Pre-built page designs for common patterns
- **Building Blocks**: Pre-built component templates
- **SCSS Architecture**: A structured stylesheet system you can customize

**Atlas directory structure:**

```
theme/
  web/
    custom-variables.scss    -- Your theme customizations
    main.scss                -- Main stylesheet entry point
    design-properties.json   -- Design property definitions
    settings.json            -- Theme settings
    _custom.scss             -- Custom styles
    sass/
      core/
        _base.scss
        _typography.scss
        _variables.scss
      components/
        _buttons.scss
        _forms.scss
        _navigation.scss
        _data-view.scss
        ...
  native/
    custom-variables.js      -- Native theme customizations
    main.js                  -- Native theme entry point
    design-properties.json   -- Native design properties
```

### Design Properties

Design properties let you apply pre-defined visual variations to widgets without writing CSS. They appear in the **Appearance** tab of the widget properties in Studio Pro.

**Common design properties:**

| Widget | Property | Options |
|--------|----------|---------|
| Buttons | Style | Default, Primary, Success, Warning, Danger, Inverse |
| Buttons | Size | Default, Small, Large |
| Container | Background | Default, Primary, Secondary, Light, Dark |
| Container | Spacing | Inner padding options (small, medium, large) |
| Text | Size | Small, Default, Large |
| Text | Weight | Normal, Semibold, Bold |
| Text | Color | Default, Muted, Success, Warning, Danger |
| Cards | Shadow | None, Small, Medium, Large |
| Cards | Hover | None, Lift |

**How design properties work:**

Design properties map to CSS class names. When you select a design property value, Mendix adds the corresponding CSS class to the widget's HTML element. For example:

- Button style "Primary" adds class `btn-primary`
- Container spacing "Large" adds class `spacing-outer-large`
- Text weight "Bold" adds class `text-bold`

This means you can customize what these design properties do by modifying the corresponding SCSS definitions.

**Creating custom design properties:**

You can define your own design properties in `theme/web/design-properties.json`:

```json
{
    "DivContainer": {
        "Highlight": {
            "type": "Toggle",
            "description": "Add a highlight border",
            "class": "highlight-border"
        },
        "Card Style": {
            "type": "Dropdown",
            "description": "Card visual style",
            "options": [
                { "name": "Flat", "class": "card-flat" },
                { "name": "Elevated", "class": "card-elevated" },
                { "name": "Outlined", "class": "card-outlined" }
            ]
        }
    }
}
```

Then define the corresponding styles in your SCSS:

```scss
.highlight-border {
    border-left: 4px solid $brand-primary;
}

.card-flat {
    box-shadow: none;
    background-color: $gray-lighter;
}

.card-elevated {
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.card-outlined {
    border: 1px solid $gray-light;
}
```

### Customizing SCSS

Atlas uses SCSS (Sassy CSS) for styling. The main customization entry point is `theme/web/custom-variables.scss`.

**Custom variables (the recommended approach):**

Edit `custom-variables.scss` to override Atlas default variables:

```scss
// Brand colors
$brand-primary: #2B5797;
$brand-secondary: #4ECDC4;
$brand-success: #27AE60;
$brand-warning: #F39C12;
$brand-danger: #E74C3C;

// Typography
$font-family-base: 'Inter', 'Helvetica Neue', Arial, sans-serif;
$font-size-base: 14px;
$font-size-large: 18px;
$font-size-small: 12px;

// Spacing
$spacing-small: 8px;
$spacing-medium: 16px;
$spacing-large: 24px;
$spacing-xlarge: 48px;

// Border radius
$border-radius-default: 4px;
$border-radius-large: 8px;
$border-radius-circle: 50%;

// Shadows
$shadow-small: 0 1px 3px rgba(0, 0, 0, 0.12);
$shadow-medium: 0 4px 6px rgba(0, 0, 0, 0.1);
$shadow-large: 0 10px 24px rgba(0, 0, 0, 0.12);

// Navigation
$navigation-bg: #1A1A2E;
$navigation-color: #FFFFFF;
$navigation-item-hover-bg: rgba(255, 255, 255, 0.1);
```

**Custom styles (for additional CSS):**

Add custom CSS rules in `theme/web/_custom.scss`:

```scss
// Custom page header
.page-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: $spacing-medium $spacing-large;
    border-bottom: 1px solid $gray-lighter;

    &__title {
        font-size: 24px;
        font-weight: 600;
        color: $gray-darker;
    }

    &__actions {
        display: flex;
        gap: $spacing-small;
    }
}

// Custom card component
.custom-card {
    background: white;
    border-radius: $border-radius-large;
    padding: $spacing-large;
    box-shadow: $shadow-small;
    transition: box-shadow 0.2s ease;

    &:hover {
        box-shadow: $shadow-medium;
    }

    &__header {
        font-size: $font-size-large;
        font-weight: 600;
        margin-bottom: $spacing-medium;
    }

    &__body {
        color: $gray-dark;
        line-height: 1.5;
    }
}

// Status badge styles
.status-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: $font-size-small;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;

    &--active {
        background-color: lighten($brand-success, 40%);
        color: darken($brand-success, 10%);
    }

    &--inactive {
        background-color: $gray-lighter;
        color: $gray-dark;
    }

    &--warning {
        background-color: lighten($brand-warning, 35%);
        color: darken($brand-warning, 10%);
    }
}
```

**Applying custom classes to widgets:**

Add your custom CSS class names to widgets through the **Class** property in the **Common** or **Appearance** tab. Multiple classes can be separated by spaces:

```
Class: custom-card page-header__actions
```

### Theme Overrides

Sometimes you need to override the styles of built-in Mendix widgets or Atlas components. This requires targeting the correct CSS selectors.

**Overriding built-in widget styles:**

Mendix widgets have predictable CSS class names. Common targets:

```scss
// Override Data Grid 2 header
.mx-datagrid .column-header {
    background-color: $gray-lightest;
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.5px;
}

// Override form input focus state
.form-control:focus {
    border-color: $brand-primary;
    box-shadow: 0 0 0 3px rgba($brand-primary, 0.15);
}

// Override navigation sidebar
.mx-navigation-sidebar {
    background-color: $navigation-bg;

    .mx-navigation-sidebar-item {
        color: $navigation-color;
        padding: 12px 16px;

        &.active {
            background-color: $navigation-item-hover-bg;
            border-left: 3px solid $brand-primary;
        }
    }
}

// Override modal/popup styles
.modal-content {
    border-radius: $border-radius-large;
    border: none;
    box-shadow: $shadow-large;
}

// Override button styles
.btn {
    border-radius: $border-radius-default;
    font-weight: 500;
    text-transform: none;
    letter-spacing: 0;
    transition: all 0.15s ease;

    &:hover {
        transform: translateY(-1px);
    }
}
```

**Finding the right selectors:**

Use your browser's developer tools (F12) to inspect Mendix widgets and find their CSS class names. Mendix generates predictable classes:

- `.mx-dataview` -- Data View wrapper
- `.mx-listview` -- List View wrapper
- `.mx-datagrid` -- Data Grid wrapper
- `.mx-name-{widgetName}` -- Widget-specific class based on the name property
- `.mx-textbox` -- Text input widget
- `.mx-textarea` -- Text area widget
- `.mx-dropdown` -- Drop-down widget
- `.form-group` -- Form field group (label + input)
- `.btn`, `.btn-primary`, `.btn-default` -- Button styles
- `.mx-tabcontainer` -- Tab container
- `.mx-groupbox` -- Group box

**Using the widget Name property for targeted styling:**

Every widget has a **Name** property. Mendix adds a class `.mx-name-{name}` to the widget's HTML element. This lets you target specific widget instances:

```scss
// Style a specific button named "submitButton"
.mx-name-submitButton {
    min-width: 200px;
    font-size: $font-size-large;
}

// Style a specific data grid named "orderGrid"
.mx-name-orderGrid {
    .column-header {
        position: sticky;
        top: 0;
    }
}
```

### Working with Design Tokens

Design tokens are the foundational variables that define your visual language. In Atlas, these are the SCSS variables in `custom-variables.scss`.

**Organizing tokens in a systematic way:**

```scss
// === COLOR TOKENS ===
// Primary palette
$color-primary-50: #E8EAF6;
$color-primary-100: #C5CAE9;
$color-primary-500: #3F51B5;
$color-primary-700: #303F9F;
$color-primary-900: #1A237E;

// Neutral palette
$color-neutral-50: #FAFAFA;
$color-neutral-100: #F5F5F5;
$color-neutral-200: #EEEEEE;
$color-neutral-500: #9E9E9E;
$color-neutral-700: #616161;
$color-neutral-900: #212121;

// Semantic colors
$color-success: #4CAF50;
$color-warning: #FF9800;
$color-danger: #F44336;
$color-info: #2196F3;

// === SPACING TOKENS ===
$space-1: 4px;
$space-2: 8px;
$space-3: 12px;
$space-4: 16px;
$space-6: 24px;
$space-8: 32px;
$space-12: 48px;

// === TYPOGRAPHY TOKENS ===
$font-heading: 'Inter', sans-serif;
$font-body: 'Inter', sans-serif;
$font-mono: 'JetBrains Mono', monospace;

$text-xs: 12px;
$text-sm: 14px;
$text-base: 16px;
$text-lg: 18px;
$text-xl: 20px;
$text-2xl: 24px;
$text-3xl: 30px;
```

Using a token system means every color, spacing value, and font size in your application traces back to a central definition. Changing `$color-primary-500` updates every component that uses it.

### Responsive Utility Classes

Atlas includes utility classes for responsive behavior. You can extend them with your own:

```scss
// Display utilities
.d-none { display: none; }
.d-block { display: block; }
.d-flex { display: flex; }
.d-inline-flex { display: inline-flex; }

// Responsive display utilities
@media (max-width: 767px) {
    .d-md-none { display: none; }
    .d-md-block { display: block; }
}

@media (min-width: 768px) {
    .d-md-none-up { display: none; }
    .d-md-block-up { display: block; }
}

// Flexbox utilities
.flex-row { flex-direction: row; }
.flex-column { flex-direction: column; }
.flex-wrap { flex-wrap: wrap; }
.justify-center { justify-content: center; }
.justify-between { justify-content: space-between; }
.align-center { align-items: center; }
.gap-sm { gap: $spacing-small; }
.gap-md { gap: $spacing-medium; }
.gap-lg { gap: $spacing-large; }

// Spacing utilities
@each $size, $value in (
    'xs': $space-1,
    'sm': $space-2,
    'md': $space-4,
    'lg': $space-6,
    'xl': $space-8
) {
    .p-#{$size} { padding: $value; }
    .px-#{$size} { padding-left: $value; padding-right: $value; }
    .py-#{$size} { padding-top: $value; padding-bottom: $value; }
    .m-#{$size} { margin: $value; }
    .mx-#{$size} { margin-left: $value; margin-right: $value; }
    .my-#{$size} { margin-top: $value; margin-bottom: $value; }
}

// Text utilities
.text-center { text-align: center; }
.text-right { text-align: right; }
.text-muted { color: $gray; }
.text-truncate {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
```

Apply these by adding class names to the widget's **Class** property. For example, setting a container's class to `d-flex justify-between align-center gap-md` creates a flexbox layout with space-between alignment and medium gaps.

---

## 8. Accessibility

Building accessible applications is not optional -- it is a requirement for professional software. Mendix generates HTML that can be made accessible, but you must configure it correctly and follow accessibility best practices.

### ARIA Labels

ARIA (Accessible Rich Internet Applications) labels provide additional context to assistive technologies like screen readers. Mendix widgets support ARIA attributes through specific properties and custom attributes.

**Setting ARIA labels on input widgets:**

Every input widget has a **Label** property. When configured, Mendix generates a proper `<label>` element associated with the input via the `for` attribute. This is the most basic and important accessibility feature. Always set labels on input widgets.

For widgets where a visual label is not desired but accessibility is still needed:

1. Set the label to a meaningful text
2. Set the label visibility to **Hide label** in the widget's design properties

This hides the label visually but keeps it in the HTML for screen readers.

**Custom ARIA attributes:**

For more complex scenarios, add custom ARIA attributes through the widget's **Class** property combined with SCSS, or through custom widgets:

Common ARIA attributes and their purposes:

| Attribute | Purpose | Example |
|-----------|---------|---------|
| `aria-label` | Text alternative for the element | "Close dialog", "Search orders" |
| `aria-labelledby` | Points to another element that labels this one | Reference a heading as the label |
| `aria-describedby` | Points to an element providing additional description | Error message, help text |
| `aria-hidden` | Hides decorative elements from screen readers | Icons next to text labels |
| `aria-live` | Announces dynamic content changes | Error messages, notifications |
| `aria-expanded` | Indicates expand/collapse state | Collapsible sections |
| `aria-required` | Indicates required fields | Form fields that must be filled |

**Mendix-specific ARIA implementation:**

Mendix automatically generates some ARIA attributes:

- Required input fields get `aria-required="true"`
- Invalid fields get `aria-invalid="true"` after validation
- Tab containers generate `role="tablist"`, `role="tab"`, and `role="tabpanel"`
- Buttons get `role="button"` (when not `<button>` elements)
- Data grids generate `role="grid"` with appropriate row and cell roles

For anything beyond the automatic ARIA support, use a pluggable widget or JavaScript action to set custom attributes.

### Keyboard Navigation

Keyboard navigation is critical for users who cannot use a mouse, including users with motor disabilities and power users who prefer keyboard shortcuts.

**Tab order:**

Mendix respects the **Tab index** property on widgets. By default, tab order follows the visual order of widgets on the page (which is usually correct). Set custom tab indices only when the default order is wrong.

Tab index values:

| Value | Behavior |
|-------|----------|
| 0 | Normal tab order (follows document flow) |
| -1 | Removed from tab order (not reachable via Tab key) |
| 1+ | Custom tab order (higher numbers come later) |

**Best practice**: Avoid manually setting tab indices unless absolutely necessary. Keep the default document flow order. If the tab order is wrong, it usually means the widget layout order is wrong -- fix the layout instead.

**Focus management:**

When opening pop-ups or showing dynamically visible content, focus should move to the new content. Mendix handles this automatically for pop-up pages (focus moves to the first focusable element in the pop-up). For dynamically shown content within a page, consider using a nanoflow with a JavaScript action to programmatically set focus.

**Keyboard interactions for common widgets:**

| Widget | Expected Keyboard Behavior |
|--------|--------------------------|
| Buttons | Activated with Enter or Space |
| Drop-downs | Opens with Enter/Space, navigate with arrow keys |
| Tab containers | Navigate tabs with arrow keys, activate with Enter |
| Data grid rows | Navigate with arrow keys, select with Enter/Space |
| Checkboxes | Toggle with Space |
| Date picker | Opens calendar with Enter, navigate with arrow keys |
| Modals | Escape closes the modal |

**Skip navigation links:**

For applications with complex navigation, add a "Skip to main content" link as the first focusable element on the page. This lets keyboard users bypass repetitive navigation menus:

Add this in your layout's header using an HTML/JavaScript snippet widget or a custom pluggable widget.

### Screen Reader Support

Screen readers convert visual UI into spoken text and braille output. Supporting screen readers requires proper semantic HTML, meaningful labels, and correct use of ARIA.

**Semantic heading structure:**

Use proper heading levels to give screen readers an outline of the page. Set the **Render mode** property of text widgets to generate proper heading tags:

```
h1: Page Title (one per page)
  h2: Section Headings
    h3: Subsection Headings
      h4: Detail Headings
```

Never skip heading levels (do not go from h1 to h3). Screen reader users navigate by headings, and skipped levels are confusing.

**Meaningful link and button text:**

Avoid generic text like "Click here" or "Read more." Every button and link should describe its action:

| Bad | Good |
|-----|------|
| Click here | View order details |
| Read more | Read full product description |
| Submit | Submit application |
| X | Close dialog |
| >> | Next page |

If you must use an icon-only button, always add an ARIA label that describes the action.

**Form error messages:**

When validation fails, ensure error messages are:

1. Visually associated with the field (near the field, not in a distant notification)
2. Programmatically associated with the field (via `aria-describedby`)
3. Announced by screen readers (via `aria-live="assertive"` on the error region)

Mendix's built-in validation feedback associates error messages with their fields automatically. If you build custom validation UI, you must handle the ARIA associations yourself.

**Tables and grids:**

Data grids should have proper table semantics. Mendix's Data Grid 2 generates `<table>` markup with `<thead>`, `<tbody>`, `<tr>`, `<th>`, and `<td>` elements, which screen readers can navigate cell by cell. If you use a list view styled to look like a table (with CSS grid or flexbox), screen reader users lose this capability. Use actual data grids for tabular data.

**Dynamic content announcements:**

When content changes dynamically (a notification appears, a list updates, a loading spinner shows), screen readers may not notice. Use `aria-live` regions to announce changes:

- `aria-live="polite"`: Announces when the screen reader finishes its current task (for non-urgent updates)
- `aria-live="assertive"`: Announces immediately, interrupting the current task (for errors and critical alerts)

### Color Contrast

Sufficient color contrast ensures that text is readable by users with low vision or color blindness.

**WCAG contrast requirements:**

| Content | Minimum Ratio (AA) | Enhanced Ratio (AAA) |
|---------|-------------------|---------------------|
| Normal text (< 18px) | 4.5:1 | 7:1 |
| Large text (>= 18px or >= 14px bold) | 3:1 | 4.5:1 |
| UI components and graphics | 3:1 | Not defined |

**Checking contrast in your Atlas theme:**

When setting colors in `custom-variables.scss`, verify contrast ratios:

```scss
// These combinations should be checked:
// $brand-primary on white background
// White text on $brand-primary background
// $gray (muted text) on white background
// Button text on button background for each style

// Use a contrast checker tool:
// - WebAIM Contrast Checker (https://webaim.org/resources/contrastchecker/)
// - Chrome DevTools (inspect element > color picker shows contrast ratio)
// - Axe browser extension
```

**Common contrast problems in Mendix apps:**

| Problem | Solution |
|---------|----------|
| Light gray placeholder text on white input | Darken placeholder color to at least #767676 |
| Disabled button text too light | Ensure disabled state still has 3:1 ratio or add additional visual indicator (icon, strikethrough) |
| Status badges with colored text on colored background | Use dark text on light backgrounds, verify each combination |
| Links that only differ by color | Add underline or other visual indicator |
| Error text in light red on white | Use a darker red (#B71C1C) that meets 4.5:1 |

**Color independence:**

Never use color as the only way to convey information. Supplement with:

- Icons (checkmark for success, X for error)
- Text labels ("Required", "Error", "Complete")
- Patterns or shapes (different chart patterns, underlines)

### Accessibility Testing

**Manual testing checklist:**

1. **Keyboard only**: Navigate the entire application using only the keyboard (Tab, Enter, Space, Escape, Arrow keys). Can you reach and operate every interactive element?
2. **Screen reader**: Test with a screen reader (NVDA on Windows, VoiceOver on macOS). Is every element announced meaningfully?
3. **Zoom**: Zoom to 200%. Does the layout still work? Is anything cut off?
4. **High contrast mode**: Enable Windows High Contrast Mode. Are all elements still visible?
5. **No images**: Disable image loading. Is there alt text for meaningful images?

**Automated testing tools:**

| Tool | Type | What It Checks |
|------|------|---------------|
| Axe (browser extension) | Automated scan | ARIA, contrast, labels, structure |
| WAVE | Browser extension / online | Visual overlay of accessibility issues |
| Lighthouse (Chrome) | Automated audit | Accessibility score with specific findings |
| Pa11y | CLI / CI integration | Automated testing in pipelines |

**Testing cadence:**

- Run automated scans on every significant page during development
- Conduct keyboard-only testing for every new page or major page change
- Perform screen reader testing at least once per sprint
- Include accessibility criteria in your definition of done

---

## 9. Performance Optimization

Slow pages frustrate users and increase abandonment. Mendix generates the UI runtime, so performance optimization focuses on how you configure pages and data sources rather than writing optimized code.

### Reducing Page Load Time

Page load time is affected by the number of widgets, the number and complexity of data sources, and the amount of data transferred.

**Measure first:**

Before optimizing, measure. Use the browser's Network tab to see:

- Total page weight (KB transferred)
- Number of HTTP requests
- Time to first meaningful paint
- Data retrieval times (XHR/Fetch requests)

Use the Mendix Runtime **Performance** logging node (set to TRACE) to see server-side query times.

**Strategies for reducing load time:**

**1. Reduce initial data retrieval:**
- Set appropriate page sizes on list views and data grids (10-20 items, not 100)
- Use pagination rather than loading all records
- Limit the attributes retrieved. If a list only shows Name and Status, do not load all 30 attributes of the entity.
- Use XPath constraints to narrow the result set: `[Active = true()]` rather than loading all records and filtering on the client

**2. Reduce widget count:**
- Audit complex pages for widget count. In Studio Pro, select all widgets on a page (Ctrl+A) and check the status bar for the count.
- Target under 200 widgets per page for good performance. Pages with 500+ widgets will noticeably lag.
- Simplify list view templates. Each widget in the template is multiplied by the page size.
- Replace complex nested layouts with simpler structures. A layout grid with 3 columns containing one widget each is 4 widgets. A single container with flexbox CSS achieves the same with 2 widgets.

**3. Defer non-critical content:**
- Use tab containers with lazy rendering for secondary content
- Use conditional visibility to hide detail sections until the user requests them
- Move rarely-accessed content to separate pages accessible via buttons

**4. Optimize microflow data sources:**
- Microflow data sources add a server round-trip. Each microflow data source on the page is a separate request.
- Combine multiple microflow data sources into one when possible (retrieve all needed data in one microflow, return a non-persistent entity with all fields)
- Use nanoflow data sources for data already available on the client (associated objects, computed values)
- Consider database data sources with XPath when the query can be expressed declaratively

### Widget Count Optimization

Widget count is the single biggest factor in page rendering performance in Mendix. The Mendix client must instantiate, render, and manage every widget instance on the page.

**High-impact reductions:**

| Instead Of | Use | Widget Savings |
|-----------|-----|---------------|
| Nested layout grids for spacing | Single container with CSS padding/margin | 3-5 widgets per instance |
| Separate label + text widget | Text widget with label property | 1 widget per field |
| Multiple containers for styling | One container with multiple CSS classes | 1-3 widgets per group |
| Visible-but-empty placeholders | Conditional visibility (not rendered when hidden) | All hidden widgets |
| Complex list view template with 20 widgets and page size 50 | Simplified template with 8 widgets or reduced page size to 20 | 600+ widgets |

**Calculating widget impact in list views:**

```
Total widget instances = (widgets per template) x (page size)

Example:
Template with 15 widgets, page size 50 = 750 widget instances
Template with 8 widgets, page size 25 = 200 widget instances

Difference: 550 fewer widget instances
```

**Auditing widget count:**

1. Open the page in Studio Pro
2. Press Ctrl+A to select all widgets
3. Check the status bar at the bottom for the count
4. For dynamic counts (list views), multiply: static count + (template widgets x page size)

Target ranges:

| Complexity | Widget Count | Assessment |
|-----------|-------------|------------|
| Simple page | < 50 | Lean and fast |
| Moderate page | 50-150 | Normal range |
| Complex page | 150-300 | Review for optimization opportunities |
| Heavy page | 300-500 | Likely needs simplification |
| Problematic | 500+ | Performance issues likely; refactor |

### Lazy Loading Strategies

Lazy loading is the practice of deferring content loading until the user needs it. This reduces initial page load time and server load.

**Tab container lazy loading:**

Tab containers are the easiest way to implement lazy loading. Set the **Lazy** tab rendering property so that only the active tab's content loads:

```
[Tab Container]
  Tab 1: "Overview" (loads immediately)
    - Summary data view
    - Key metrics

  Tab 2: "Details" (loads when clicked -- lazy)
    - Full detail form
    - Associated objects

  Tab 3: "History" (loads when clicked -- lazy)
    - Activity log data grid
    - 1000+ records that would be expensive to load upfront
```

**Conditional visibility lazy loading:**

Wrap heavy content in a container with conditional visibility:

```
[Data View: Customer]
  Name: {FullName}
  Email: {Email}

  [Button: "Show Order History"]
    On click: Set $Customer/ShowOrders = true

  [Container: visible when $Customer/ShowOrders = true]
    [List View: Orders (data source: XPath over Customer_Order)]
      -- This data source only fires when the container becomes visible
```

**Scroll-triggered loading:**

For very long pages, load content as the user scrolls to it:

1. Place content sections in containers
2. Use a JavaScript action (via nanoflow) with the Intersection Observer API to detect when a section scrolls into view
3. Set a boolean attribute to true when the section is in view
4. Bind container visibility to the boolean

This is an advanced pattern and usually only worth the complexity for pages with extremely heavy content.

**Lazy loading images:**

For pages with many images (product catalogs, image galleries):

- Set appropriate image dimensions to prevent layout shift
- Use thumbnails in list views and full-size images only in detail views
- Consider using the browser's native `loading="lazy"` attribute via custom widget properties

### Data Source Optimization

The data source configuration of your widgets directly impacts server load and response times.

**XPath vs. Microflow data sources:**

| Factor | XPath/Database | Microflow |
|--------|---------------|-----------|
| Server round-trips | 1 (direct query) | 1 (microflow call) |
| Query optimization | Mendix ORM optimizes the query | You control the query |
| Caching | Mendix caches query results | No automatic caching |
| Sorting/Filtering | Handled by database | Handled in microflow logic |
| Complexity | Limited to XPath expressions | Unlimited logic |
| Performance | Generally faster for simple queries | Overhead from microflow execution |

**Use XPath when:**
- The query can be expressed as a simple filter
- Sorting is on indexed columns
- You do not need to aggregate or transform data
- You want Mendix to handle pagination efficiently

**Use microflows when:**
- The query involves complex logic, aggregation, or data from multiple sources
- You need to call external services for data
- The data requires transformation before display
- You need union-style queries across multiple entity types

**Reducing N+1 queries:**

The N+1 problem occurs when a list widget loads N items, and each item triggers a separate query for associated data.

Example of N+1:
```
List View: Orders (loads 50 orders = 1 query)
  Each template shows: Customer/FullName (50 separate queries for Customer)
  Total: 51 queries
```

Mendix mitigates this with batch retrieval of associations. However, you can further optimize by:

- Pre-loading associations in a microflow data source using a single OQL/XPath query with a join
- Using denormalized attributes (store the Customer name on the Order entity) for display-only purposes
- Reducing page size to limit the number of associations retrieved

**Indexing for sort and filter columns:**

If you frequently sort or filter a data grid on a specific attribute, add a database index:

1. Open the entity in the domain model
2. Go to the **Indexes** tab
3. Add an index on the attribute(s) used for sorting/filtering

Indexes dramatically improve query performance for large datasets (100K+ records) but add overhead for writes. Only index columns that are actively used for sorting, filtering, or searching.

### Image and Asset Optimization

Images and static assets can significantly impact page load time, especially on mobile networks.

**Image optimization checklist:**

- **Resize before upload**: Do not upload 4000x3000 photos for a 200x200 thumbnail. Resize on the server or before upload.
- **Use appropriate formats**: JPEG for photographs, PNG for graphics with transparency, SVG for icons and logos
- **Compress images**: Use tools like TinyPNG or ImageOptim to reduce file sizes without visible quality loss
- **Set dimensions**: Always set width and height on image widgets to prevent layout shift during loading
- **Use CDN**: For static assets, configure a CDN in front of your Mendix application

**Static asset best practices:**

- Minimize custom fonts. Each font file adds 20-100KB. Use system fonts when possible, or limit to one or two custom font families.
- Combine and minify SCSS. Mendix does this automatically during deployment, but verify in the browser's Network tab.
- Use SVG icons instead of icon fonts for better performance and flexibility.

### Profiling and Measuring Performance

**Browser Developer Tools:**

| Tab | What to Check |
|-----|--------------|
| Network | Total requests, transfer size, slow requests |
| Performance | Rendering time, long tasks, layout shifts |
| Lighthouse | Performance score, specific recommendations |
| Console | JavaScript errors, warnings |

**Mendix Runtime logging:**

Set the following log nodes to DEBUG or TRACE for performance investigation:

| Log Node | Information |
|----------|------------|
| `ConnectionBus` | Database query details and timing |
| `Core` | Object retrieval and commit timing |
| `Microflows` | Microflow execution timing |
| `RequestHandler` | HTTP request/response timing |

**Setting performance budgets:**

Define acceptable thresholds for your application:

| Metric | Target | Measurement |
|--------|--------|-------------|
| Page load time | < 2 seconds | Time from navigation to interactive |
| Time to first data | < 1 second | Time until first data appears |
| Interaction delay | < 100ms | Time from click to visible response |
| Data grid pagination | < 500ms | Time to load next page of results |
| Pop-up open | < 300ms | Time from click to pop-up visible |

If a page exceeds these budgets, profile it and apply the optimization strategies in this section.

---

## 10. Common UI Patterns

These patterns solve recurring design problems in Mendix applications. Each pattern includes when to use it, how to implement it, and what to watch out for.

### Master-Detail

The master-detail pattern displays a list of items on one side and the selected item's details on the other. It is one of the most common patterns in business applications.

**Implementation approach:**

```
+----------------------------+----------------------------------+
| MASTER (List)              | DETAIL (Selected Item)           |
|                            |                                  |
| [Data Grid 2: Orders]     | [Data View: Order]               |
|  > Order #1001  (selected) |   (listens to Orders grid)       |
|    Order #1002             |                                  |
|    Order #1003             |   Order Number: 1001             |
|    Order #1004             |   Customer: Acme Corp            |
|    Order #1005             |   Date: 2026-01-15               |
|                            |   Status: Processing             |
|                            |                                  |
|                            |   [Line Items List View]         |
|                            |   [Action Buttons]               |
+----------------------------+----------------------------------+
```

**Step-by-step setup:**

1. Add a **Layout Grid** with two columns (4/12 for master, 8/12 for detail)
2. In the left column, place a **Data Grid 2** with your entity data source
3. Configure the grid's **Selection** property: single-select, on-click-select
4. In the right column, place a **Data View** with data source **Listen to widget** and select the data grid
5. Design the detail area inside the data view
6. Set an **Empty entity message** on the data view (e.g., "Select an item to view details")

**Responsive considerations:**

On mobile devices, a side-by-side layout does not work. Use conditional visibility to switch to a stacked layout:

- **Desktop**: Show both master and detail side by side
- **Mobile**: Show only the master list. When an item is clicked, navigate to a separate detail page (or show the detail in a pop-up)

Alternatively, use the grid column breakpoint settings to make the master column full-width on small screens and hide the detail column, using the grid row click to open a separate page.

**Performance tips:**

- Set a reasonable page size on the master list (20-30 items)
- The detail data view re-renders on every selection change, so keep it efficient
- If the detail area has heavy content (multiple data grids, charts), consider lazy-loading them

### Wizard / Stepper

The wizard pattern guides users through a multi-step process, showing one step at a time with progress indication.

**Implementation approach using a tab container:**

```
[Data View: WizardContext (non-persistent entity)]
  CurrentStep: Integer (1, 2, 3...)

  [Container: Progress Bar]
    Step 1: Personal Info  -->  Step 2: Address  -->  Step 3: Review  -->  Step 4: Confirm

  [Tab Container: WizardSteps (render mode: lazy)]
    Tab 1: Personal Information
      - First Name, Last Name, Email
      - [Button: Next] -> nanoflow sets CurrentStep = 2

    Tab 2: Address
      - Street, City, State, Zip
      - [Button: Back] -> nanoflow sets CurrentStep = 1
      - [Button: Next] -> nanoflow sets CurrentStep = 3 (with validation)

    Tab 3: Review
      - Summary of all entered data (read-only)
      - [Button: Back] -> nanoflow sets CurrentStep = 2
      - [Button: Submit] -> microflow to save data

    Tab 4: Confirmation
      - Success message
      - [Button: Done] -> close page or navigate home
```

**Implementation approach using conditional visibility:**

For more control over the wizard layout, use containers with conditional visibility instead of tabs:

```
[Data View: RegistrationWizard]

  [Snippet: WizardProgressBar] -- shows step indicators

  [Container: Step1]
    Visible: $currentObject/CurrentStep = 1
    -- Step 1 content

  [Container: Step2]
    Visible: $currentObject/CurrentStep = 2
    -- Step 2 content

  [Container: Step3]
    Visible: $currentObject/CurrentStep = 3
    -- Step 3 content
```

**Wizard best practices:**

- **Validate per step**: Do not wait until the final step to validate all data. Validate each step's fields when the user clicks "Next" so they can fix issues immediately.
- **Save progress**: For long wizards, save progress after each step (commit the entity). This prevents data loss if the user navigates away.
- **Allow backward navigation**: Let users go back to review and modify previous steps.
- **Show progress**: Display a progress indicator showing which step the user is on and how many steps remain.
- **Keep steps focused**: Each step should have 3-7 fields. If a step has more than 10 fields, split it into two steps.
- **Use non-persistent entities**: Use a non-persistent entity as the wizard context, then commit to persistent entities only on final submission. This prevents incomplete records in the database.

### Dashboard Layout

Dashboards display summarized information from multiple data sources in a scannable, card-based layout.

**Implementation approach:**

```
+--------------------------------------------------+
| Dashboard Header                    [Date Filter] |
+----------+----------+----------+----------+------+
| KPI Card | KPI Card | KPI Card | KPI Card |      |
| Orders   | Revenue  | Customers| Issues   |      |
| 1,234    | $45.2K   | 892      | 23       |      |
+----------+----------+----------+----------+------+
| [Chart: Orders Over Time]    | [List: Recent     |
|                              |  Activities]       |
|                              |                    |
+------------------------------+--------------------+
| [Data Grid: Open Tasks]                           |
|                                                   |
+--------------------------------------------------+
```

**Building dashboard cards:**

Create a reusable snippet for KPI cards:

```
[Snippet: Snippet_KPICard]
  Entity: KPIDashboard (non-persistent)

  [Container: class="kpi-card"]
    [Text: {Label}]           -- "Total Orders"
    [Text: {Value}]           -- "1,234"
    [Text: {Trend}]           -- "+12% from last month"
    [Container: trend-indicator]
      -- Green up arrow or red down arrow based on TrendDirection
```

**Dashboard data loading pattern:**

1. Create a non-persistent entity `DashboardData` with attributes for each KPI
2. Create a microflow `DS_GetDashboardData` that:
   - Queries aggregate data (COUNT, SUM, AVG)
   - Populates the `DashboardData` object
   - Returns the object
3. Use this microflow as the data source for a data view wrapping the entire dashboard
4. Nest KPI cards, charts, and lists inside the data view

**Auto-refresh:**

For dashboards that should update without manual refresh:

1. Add a **Timer** widget (from the Marketplace) or use a nanoflow with a delay action
2. Set the timer to trigger a microflow that refreshes the data view
3. Use a 30-60 second interval. Faster intervals add unnecessary server load.

**Dashboard performance tips:**

- Cache expensive aggregation queries in the Mendix Runtime
- Use database views or stored procedures for complex aggregations (via OQL or Java actions)
- Load chart data asynchronously so the page structure appears immediately
- Use lazy-loaded tabs for secondary dashboard views

### Search-and-Filter

Search-and-filter is a pattern where users can narrow down a dataset using multiple criteria.

**Implementation with Data Grid 2 built-in filters:**

The simplest approach is to use Data Grid 2's built-in column filters:

1. Add a Data Grid 2 with a database data source
2. For each column, add the appropriate filter widget (text filter, number filter, date filter, drop-down filter)
3. Filters combine with AND logic automatically
4. The grid handles pagination, sorting, and filtering server-side

This works well for straightforward filtering. For more complex requirements, use a custom search form.

**Implementation with a custom search form:**

```
[Data View: SearchCriteria (non-persistent entity)]
  Microflow source: DS_CreateSearchCriteria (creates a new empty object)

  +--------------------------------------------------+
  | Search Filters                                    |
  | Name: [________]  Status: [_dropdown_]            |
  | Date From: [____]  Date To: [____]                |
  | Category: [_dropdown_]  Priority: [_dropdown_]    |
  |                                                   |
  | [Search Button]  [Clear Filters Button]           |
  +--------------------------------------------------+

  [Data Grid 2: Results]
    Data source: Microflow DS_SearchOrders
      Input: $SearchCriteria object
      Returns: List of Order
```

**Building the search microflow:**

```
// Microflow: DS_SearchOrders
// Input: $SearchCriteria (non-persistent entity)

// Build XPath constraint dynamically
$constraint = '[true()]'

if ($SearchCriteria/Name != empty) then
    $constraint = $constraint + '[contains(Name, ''' + $SearchCriteria/Name + ''')]'

if ($SearchCriteria/Status != empty) then
    $constraint = $constraint + '[Status = ''' + $SearchCriteria/Status + ''']'

if ($SearchCriteria/DateFrom != empty) then
    $constraint = $constraint + '[OrderDate >= ''' + $SearchCriteria/DateFrom + ''']'

if ($SearchCriteria/DateTo != empty) then
    $constraint = $constraint + '[OrderDate <= ''' + $SearchCriteria/DateTo + ''']'

// Retrieve with constraint
Retrieve from database: Order + $constraint
Sort: OrderDate descending
Pagination: First 25 items
```

**Saved searches:**

Allow users to save their search criteria for repeated use:

1. Create a persistent entity `SavedSearch` associated with the user
2. Store the search criteria as attributes or as a JSON string
3. Add a "Save Search" button that commits the current criteria
4. Add a "Load Search" dropdown that lists saved searches
5. On load, populate the `SearchCriteria` entity from the saved search

**Filter tags/pills:**

Display active filters as removable tags below the search form:

```
Active Filters: [Status: Active x] [Date: Jan 2026 x] [Category: Electronics x]
```

Implement this with a list view bound to the active filter criteria, where each item has a remove button that clears that filter and re-triggers the search.

### Infinite Scroll and Pagination

**Traditional pagination:**

Data Grid 2 handles pagination natively. Configure the paging settings:

- **Page size**: Number of items per page (10, 20, 50)
- **Paging style**: Page numbers, previous/next buttons, or both
- **Show total count**: Display "Showing 1-20 of 450 results"

**Infinite scroll (load more):**

For a mobile-friendly experience where content loads as the user scrolls:

1. Use a **List View** with a defined page size
2. Set the list view's **Pagination** to **Load more** style
3. The list view shows a "Load more" button at the bottom (or auto-loads on scroll, depending on configuration)
4. Each load appends items to the existing list

**Choosing between pagination and infinite scroll:**

| Factor | Pagination | Infinite Scroll |
|--------|-----------|----------------|
| User knows total count | Yes (page X of Y) | No (unbounded) |
| User can jump to position | Yes (page numbers) | No (must scroll sequentially) |
| Good for mobile | Adequate | Better |
| Good for data grids | Yes | Less suitable |
| Good for card/list layouts | Adequate | Better |
| URL-bookmarkable position | Yes (page parameter) | No |
| Performance with large datasets | Consistent | Degrades as items accumulate in DOM |

### Confirmation Dialogs

Confirmation dialogs prevent accidental destructive actions (delete, cancel, submit).

**Built-in confirmation:**

The **Delete object** action has a built-in confirmation dialog. Configure it in the action properties:

- **Confirmation message**: "Are you sure you want to delete this order?"
- **Proceed button caption**: "Delete"
- **Cancel button caption**: "Cancel"

**Custom confirmation dialogs:**

For actions beyond delete, use a pop-up page as a confirmation dialog:

1. Create a small pop-up page with the confirmation message
2. Add "Confirm" and "Cancel" buttons
3. The "Confirm" button calls a microflow that performs the action and closes the page
4. The "Cancel" button closes the page without performing the action

**Confirmation best practices:**

- State the consequence, not just the action: "This will permanently delete the order and all associated line items" instead of "Delete order?"
- Use different button styles: destructive actions should have a red/danger button for the confirm action and a neutral button for cancel
- Do not confirm routine actions. Only confirm destructive or irreversible operations.
- Double-check that the confirmation dialog actually prevents the action (the action is in the confirm path, not in the on-click of the initial button)

### Empty States and Loading Indicators

Empty states and loading indicators handle the transitional moments in your application -- when data is loading or when there is no data to display. These are often overlooked but significantly impact the user experience.

**Empty states:**

Every data widget should have a meaningful empty state. Do not show a blank page when there is no data.

**Empty state components:**

| Component | Purpose |
|-----------|---------|
| Illustration/Icon | Visual indication that the state is intentional, not an error |
| Headline | Brief description of the state ("No orders yet") |
| Description | Explanation or suggestion ("Create your first order to get started") |
| Action button | Primary action to resolve the empty state ("Create Order") |

**Implementing empty states in Mendix:**

For Data Grid 2 and List View, set the **Empty list message** property. For simple text messages, this is sufficient. For richer empty states with illustrations and buttons:

1. Place the data widget inside a container
2. Add a second container below with the empty state content
3. Set the empty state container's visibility to show when the data source returns zero items
4. Use a microflow data source that returns both the list and a count, or use a separate count attribute

**Loading indicators:**

Mendix shows a default loading spinner when data is being retrieved. You can customize this behavior:

- **Progress bar widget**: Shows a progress bar during long-running microflows
- **Custom loading states**: Use a boolean attribute `IsLoading` controlled by nanoflows, with a container showing a skeleton/shimmer UI when true
- **Skeleton screens**: Instead of a spinner, show a placeholder layout that mimics the final content structure. This feels faster to users because they see the page structure immediately.

**Skeleton screen implementation:**

```scss
// Skeleton loading animation
.skeleton {
    background: linear-gradient(
        90deg,
        $gray-lighter 25%,
        $gray-lightest 50%,
        $gray-lighter 75%
    );
    background-size: 200% 100%;
    animation: skeleton-loading 1.5s infinite;
    border-radius: $border-radius-default;
}

@keyframes skeleton-loading {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
}

.skeleton-text {
    @extend .skeleton;
    height: 14px;
    margin-bottom: 8px;
    width: 80%;
}

.skeleton-heading {
    @extend .skeleton;
    height: 24px;
    margin-bottom: 16px;
    width: 60%;
}

.skeleton-image {
    @extend .skeleton;
    height: 200px;
    width: 100%;
}
```

Create a snippet with containers styled as skeleton elements. Show this snippet while data is loading (controlled by a boolean attribute), then swap to the real content when data arrives.

**Error states:**

In addition to empty and loading states, handle error states:

- **Network error**: "Unable to load data. Check your connection and try again." + Retry button
- **Server error**: "Something went wrong. Please try again later." + Retry button
- **Permission error**: "You do not have permission to view this content." + Back button or link to request access
- **Not found**: "The item you are looking for does not exist or has been removed." + Back button

Implement error states using a nanoflow that catches errors from data retrieval microflows and sets an error attribute on a non-persistent context entity. Display different containers based on the error attribute value.

---

## Appendix: Quick Reference

### Widget Selection Cheat Sheet

| I want to... | Use this widget |
|--------------|----------------|
| Show/edit one object | Data View |
| Display a scrollable list | List View |
| Show a sortable, filterable table | Data Grid 2 |
| Display a grid of cards | Gallery or Template Grid |
| Accept text input | Text Box or Text Area |
| Accept a date | Date Picker |
| Accept a selection from options | Drop-Down or Radio Buttons |
| Accept yes/no | Check Box |
| Select an associated object | Reference Selector |
| Upload a file | File Manager |
| Navigate between pages | Menu Bar, Navigation Tree, or buttons |
| Show tabbed content | Tab Container |
| Create a collapsible section | Group Box |
| Display a pop-up | Pop-up page with Show Page action |

### Performance Budget Summary

| Metric | Target |
|--------|--------|
| Widgets per page | < 200 (ideal), < 300 (maximum for complex pages) |
| Widgets per list item template | < 10-12 |
| List view page size | 10-25 items |
| Data grid page size | 20-50 items |
| Page load time | < 2 seconds |
| Microflow data sources per page | Minimize; prefer database sources |
| Image file size | < 200KB for thumbnails, < 1MB for full images |
| Custom fonts | 1-2 families maximum |

### Accessibility Checklist

| Check | Requirement |
|-------|------------|
| Labels | Every input widget has a label (visible or screen-reader-only) |
| Headings | Proper heading hierarchy (h1 > h2 > h3, no skipped levels) |
| Contrast | Text meets 4.5:1 ratio (normal) or 3:1 ratio (large) |
| Keyboard | All interactive elements reachable and operable by keyboard |
| Focus | Focus order is logical; focus is visible |
| Alt text | Meaningful images have alt text; decorative images are hidden from screen readers |
| Errors | Form errors are associated with their fields and announced by screen readers |
| Color | Information is not conveyed by color alone |
| Zoom | Layout works at 200% zoom without horizontal scrolling |
| Motion | Animations respect the prefers-reduced-motion media query |

---

## References

- [Mendix Documentation: Pages](https://docs.mendix.com/refguide/pages/)
- [Mendix Documentation: Widgets](https://docs.mendix.com/refguide/pages/widgets/)
- [Mendix Documentation: Data Widgets](https://docs.mendix.com/refguide/data-widgets/)
- [Mendix Documentation: Atlas UI](https://docs.mendix.com/howto/front-end/atlas-ui/)
- [Mendix Documentation: Pluggable Widget API](https://docs.mendix.com/apidocs-mxsdk/apidocs/pluggable-widgets/)
- [Mendix Marketplace](https://marketplace.mendix.com/)
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [MDN Web Accessibility Guide](https://developer.mozilla.org/en-US/docs/Web/Accessibility)
