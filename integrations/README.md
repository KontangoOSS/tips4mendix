# Mendix Integrations Guide

## A Practical Reference for Connecting Mendix Applications to External Systems

**Version:** 1.0
**Date:** February 2026
**Classification:** Public

---

## Table of Contents

1. [Integration Landscape](#1-integration-landscape)
2. [Consuming REST APIs](#2-consuming-rest-apis)
3. [OData](#3-odata)
4. [SOAP Web Services](#4-soap-web-services)
5. [Messaging and Queues](#5-messaging-and-queues)
6. [File-Based Integration](#6-file-based-integration)
7. [Webhooks](#7-webhooks)
8. [Error Handling for Integrations](#8-error-handling-for-integrations)
9. [Data Mapping](#9-data-mapping)
10. [Authentication for External Services](#10-authentication-for-external-services)
11. [Performance and Rate Limiting](#11-performance-and-rate-limiting)
12. [Testing Integrations](#12-testing-integrations)

---

## 1. Integration Landscape

Mendix applications rarely exist in isolation. In any enterprise setting, your app needs to talk to ERPs, CRMs, data warehouses, SaaS platforms, legacy systems, and other Mendix apps. Choosing the right integration approach from the start saves you from painful refactoring later.

### When to Use Which Method

**REST APIs** are your default choice. Use REST for request-response communication with modern APIs, when the external system exposes JSON or XML endpoints, or when building a service layer for other apps to consume. Mendix provides first-class support for both publishing and consuming REST.

**OData** fits when exposing Mendix data to reporting tools (Excel, Power BI, Tableau) or for Mendix-to-Mendix communication where consumers need ad-hoc query capabilities with built-in filtering and sorting.

**SOAP** is relevant when integrating with older enterprise systems that only expose WSDL-based services. SAP, Oracle, and many government systems still use SOAP. If you have a choice, pick REST -- but when you must use SOAP, Mendix handles it well.

**Messaging (Kafka, RabbitMQ, JMS)** fits fire-and-forget communication, event-driven architectures, or when producing and consuming systems should not be directly coupled. Use messaging when you need guaranteed delivery or when a single event must reach multiple consumers.

**File-based integration** serves batch data transfers, mainframe/legacy integration via SFTP, or large datasets impractical to transfer via API.

**Webhooks** are right when an external system needs to notify your Mendix app about events in real time, avoiding repeated polling.

### Synchronous vs. Asynchronous Patterns

**Synchronous**: The caller sends a request and waits for a response. The microflow blocks until the external system responds or times out. Use when the user is waiting for the result, when the response is needed to continue processing, or when the operation is fast (under 5 seconds). The risk: your app's responsiveness depends on the external system's performance.

**Asynchronous**: The caller sends a message and continues without waiting. Use for long-running operations, when you do not need an immediate response, when you want to decouple from the external system's availability, or when multiple systems must react to the same event.

Mendix async implementation options:

- **Task Queue**: Offload work to background processing. The user-facing microflow creates a task and returns immediately.
- **Process Queue module**: Marketplace module providing a persistent database-backed queue that survives app restarts.
- **Scheduled Events**: Periodic batch processing that polls for work.
- **External message brokers**: Kafka, RabbitMQ, or JMS for true event-driven architectures.

**Hybrid pattern**: Accept a request synchronously, return an acknowledgment immediately, process asynchronously in the background, and notify the caller via callback, webhook, or status polling.

### Decision Matrix

| Scenario | Method | Sync/Async | Rationale |
|----------|--------|------------|-----------|
| Customer lookup by ID | REST | Sync | Fast, user is waiting |
| Submit order to ERP | REST + Queue | Hybrid | Acknowledge quickly, process in background |
| Expose data for Power BI | OData | Sync | Standard protocol for BI tools |
| Nightly data sync | File/REST + Scheduled Event | Async | Batch processing, no user waiting |
| Real-time inventory updates | Kafka/Webhook | Async | Event-driven, multiple consumers |
| Payment gateway | REST | Sync | Need immediate confirmation |
| Multi-app event broadcasting | Kafka | Async | Decoupled, multiple subscribers |
| Legacy mainframe integration | File (SFTP) or SOAP | Async | Often the only option available |

---

## 2. Consuming REST APIs

REST is the backbone of modern Mendix integration. The platform provides comprehensive tooling for both publishing and consuming REST endpoints.

### Published REST Services

Published REST services expose data and operations to external consumers via HTTP.

**Creating one:**

1. Right-click your module > **Add other > Published REST Service**.
2. Set the **Service name** (determines URL path, e.g., `/rest/customerapi/v1`).
3. Define **Resources** representing entities or operations (`customers`, `orders`).
4. For each resource, define **Operations** (GET, POST, PUT, PATCH, DELETE) mapped to microflows.

**Always version your APIs.** Include the version in the URL path (`/rest/customerapi/v1/customers`). When making breaking changes, create a new version and keep the old one running until consumers migrate.

**Operation microflows** receive parameters from URL path, query string, and request body, and return HTTP responses. A GET microflow retrieves an entity and returns it as JSON via export mapping with status 200 (or 404 if not found). A POST microflow uses an import mapping to parse the JSON body, validates, commits, and returns the created entity with status 201.

**Follow standard HTTP status codes consistently:**

| Code | When to Use |
|------|-------------|
| 200 | Successful GET, PUT, PATCH |
| 201 | Successful POST creating a resource |
| 204 | Successful DELETE |
| 400 | Invalid input, validation failure |
| 401 | Missing or invalid authentication |
| 403 | Authenticated but not authorized |
| 404 | Resource does not exist |
| 429 | Rate limit exceeded |
| 500 | Unexpected server failure |

Mendix auto-generates an OpenAPI (Swagger) specification for published REST services -- use it as documentation.

### Consumed REST Services

The **Call REST Service** activity in a microflow is your primary tool for consuming external REST APIs.

**Configuration:**

1. Set the **Location** using a constant for the base URL: `$APIBaseURL + '/customers/' + $CustomerId`.
2. Choose the **HTTP Method**.
3. Configure **Request headers** for authentication and content type.
4. For POST/PUT/PATCH, configure the **Request body** from an export mapping, string variable, or file document.
5. Configure **Response handling**: "Apply import mapping" for automatic JSON-to-entity parsing, or "Store in a string variable" for manual parsing.

**Never hard-code API URLs.** Use constants that vary per environment (dev, acceptance, production).

**Custom error handling:**

1. Set error handling to **Custom with rollback** or **Custom without rollback**.
2. In the error handler path, access `$latestHttpResponse` for the status code and body.
3. Parse error responses for meaningful messages.
4. Decide whether to retry, log, notify, or escalate.

### JSON Mapping

**JSON Structure documents** define the expected shape of JSON data. Create one by pasting a sample JSON response -- Mendix infers the structure including nested objects and arrays.

Tips:
- Use a representative sample with all possible fields including optional ones
- Include at least two items in arrays so Mendix identifies list structures correctly
- For polymorphic responses, create separate JSON structures per variant

### Import and Export Mappings

**Import mappings** convert incoming JSON/XML into Mendix entities. **Export mappings** convert entities into JSON/XML for outgoing requests.

For import mappings, the "Find by key" option is critical for upsert behavior:

| Find By Key | If Not Found | Behavior |
|-------------|--------------|----------|
| Not configured | Create | Always creates new objects (leads to duplicates) |
| Configured | Create | Upsert: creates if no match, updates if match found |
| Configured | Ignore | Only updates existing records |
| Configured | Error | Throws error if no match found |

**Best practice**: Map incoming data to non-persistent entities (NPEs) first, then transform into your domain model in a separate microflow. This decouples your domain model from external formats, allows validation before committing, and makes format changes easier to absorb.

### Handling Pagination

Most REST APIs paginate list endpoints. Common styles: offset-based (`?offset=0&limit=100`), page-based (`?page=1&pageSize=100`), and cursor-based (`?cursor=abc123&limit=100`).

**Pagination microflow pattern:**

1. Initialize: `Offset = 0`, `PageSize = 100`, `HasMore = true`.
2. **While** loop (with a maximum iteration guard):
   - Call REST with current offset/page parameters
   - Import response into entities
   - If returned records < PageSize, set `HasMore = false`
   - Increment Offset by PageSize
3. Commit records in batches rather than holding all in memory.

**When publishing paginated endpoints**, accept `offset`/`limit` query parameters, use XPath retrieve with range settings, and return a response envelope with `data`, `offset`, `limit`, and `total`.

---

## 3. OData

OData (Open Data Protocol) is an OASIS standard for building queryable RESTful APIs. In Mendix, OData is important for Mendix-to-Mendix integration and for exposing data to BI tools.

### Publishing OData Services

1. Right-click module > **Add other > Published OData Service**.
2. Set **Service name** and **Version** (URL: `/odata/customerservice/v1`).
3. Add **Resources** (each maps to a Mendix entity).
4. Select which **Attributes** and **Associations** to publish.
5. Configure **Capabilities**: Readable, Insertable, Updatable, Deletable.

**Security**: OData services respect entity access rules. Ensure consuming user roles have appropriate permissions. Authentication options include username/password, active session, or custom microflow-based validation.

**Performance tips:**
- Expose only attributes consumers need
- Use calculated attributes sparingly (they cannot be filtered/sorted and add overhead)
- Index frequently filtered attributes
- For large datasets, implement server-side pagination limits

### Consuming OData Services

1. Right-click module > **Add other > Consumed OData Service**.
2. Enter the **Metadata URL** (`$metadata` endpoint).
3. Select entities to consume -- Mendix creates **External Entities** in your domain model.

External entities work like regular entities in microflows and pages, with key differences: data is not stored locally (every access triggers an OData request), not all XPath operations are supported, write operations require source support, and performance depends on network latency.

**Retrieval patterns:**
- **Direct in pages**: Use external entities as data sources. Simplest but least control.
- **Microflow retrieval**: More control over transformations and error handling.
- **Local caching**: Retrieve on a schedule, store locally. Fast reads but potentially stale data.

### Filtering

XPath on external entities translates to OData `$filter`:

| XPath | OData Equivalent |
|-------|-----------------|
| `[Name = 'Acme']` | `$filter=Name eq 'Acme'` |
| `[Amount > 100]` | `$filter=Amount gt 100` |
| `[Active = true()]` | `$filter=Active eq true` |
| `[contains(Name, 'Corp')]` | `$filter=contains(Name,'Corp')` |
| `[starts-with(Name, 'A')]` | `$filter=startswith(Name,'A')` |

Combine with `and`/`or`: `[Amount > 100 and Status = 'Active']`. Date filtering works with XPath date tokens like `[%BeginOfCurrentDay%]`.

### Expanding Associations

By default, retrieving an external entity does not load associated entities. Nested data views for external entities cause Mendix to generate `$expand` queries that fetch related data in one request, avoiding the N+1 problem.

**Guidelines:**
- Limit expansion depth -- aim for no more than two levels in production
- Watch data volume on one-to-many expansions (a customer with thousands of orders)
- Consider separate queries when you only need associations for a subset of parents

---

## 4. SOAP Web Services

SOAP is XML-based and was dominant before REST. Many enterprise systems (SAP, Oracle, government platforms) still use SOAP. Mendix provides solid support for consuming SOAP services.

### Consuming WSDL-Based Services

1. Right-click module > **Add other > Consumed Web Service**.
2. Provide the WSDL via URL (often `?wsdl`) or upload a file.
3. Mendix generates domain model entities, import mappings, and export mappings for the WSDL message types.

**Common issues:**

| Problem | Solution |
|---------|----------|
| Import fails with schema errors | Download all XSD files locally, update WSDL references |
| Operations not showing | Check binding style -- document/literal wrapped is fully supported |
| Certificate errors on WSDL URL | Download WSDL file and import from file |

**Calling an operation:**

1. Add a **Call Web Service** activity to your microflow.
2. Select the operation.
3. Map request data using the generated export mapping.
4. Response is parsed via the generated import mapping.
5. Set a reasonable **Timeout** (15-60 seconds depending on operation).
6. Handle SOAP Faults in your error handler -- log the fault code and string, map common faults to user-friendly messages, determine if the fault is retryable.

### WS-Security

WS-Security provides message-level security for SOAP.

**Username Token**: The most common scenario. Configure in the Call Web Service SOAP tab with username, password (from constants), and password type (PasswordText or PasswordDigest).

**Timestamp**: Protects against replay attacks by defining a message validity window. Enable when the service requires it.

**Signing and Encryption**: For high-security scenarios, configure digital signatures (proving message integrity) and encryption (protecting content from intermediaries). Requires certificates uploaded to the Mendix application -- manage through the Developer Portal in Mendix Cloud or runtime settings for on-premises deployments.

### Handling Complex XML Schemas

**Inheritance**: Mendix creates separate entities for each type in the hierarchy with associations for parent-child relationships.

**Choice elements**: Creates optional associations for each possible element -- only one is populated at runtime.

**Recursive types**: Supported with a configurable depth limit in the import mapping.

**Large messages**: Enable MTOM for efficient binary attachments. For large result sets, use pagination/chunking if supported. Consider file-based approaches for very large payloads.

**Namespaces**: Ensure all namespace prefixes and URIs match the WSDL/XSD exactly. Namespace mismatches are a common source of SOAP integration failures.

---

## 5. Messaging and Queues

Message-based integration decouples systems through a message broker. The producer sends and moves on. The consumer processes when ready. This is fundamental to resilient, scalable architectures.

### Kafka Connector

Apache Kafka is a distributed event streaming platform for high-throughput, fault-tolerant messaging. Use the Kafka Connector from the Mendix Marketplace.

**Setup**: Configure bootstrap servers, security protocol (PLAINTEXT, SSL, SASL_PLAINTEXT, SASL_SSL), and SASL mechanism if applicable.

**Producing messages:**
1. Build the payload (typically JSON via export mapping).
2. Use the **Produce Message** action specifying topic, key, and value.
3. Use meaningful keys (entity IDs, customer IDs) -- same key ensures same partition and ordering.
4. Handle production failures with local queuing or retry.

**Consuming messages:**
1. Configure a consumer with group name, topic(s), and offset reset (`earliest` or `latest`).
2. Create a handler microflow receiving key, value, topic, partition, and offset.
3. Start the consumer in an after-startup microflow.

**Critical**: Kafka guarantees at-least-once delivery. Design handlers to be **idempotent** -- safely handle duplicate messages using deduplication tables keyed on offset or business key.

### RabbitMQ

RabbitMQ implements AMQP and suits task queues and sophisticated routing patterns.

**Integration approaches:**
- **Marketplace connectors**: Community modules (evaluate for maturity)
- **REST Management API**: Publish via HTTP (simpler but higher overhead, no consuming)
- **Java action wrapper**: Full AMQP support via the RabbitMQ Java client
- **Sidecar pattern**: Deploy a small bridge service that consumes RabbitMQ and calls your Mendix REST endpoint

**Exchange types**: Direct (exact routing key match), Fanout (broadcast to all bound queues), Topic (pattern-based routing like `orders.europe.#`), Headers (route by message headers).

### JMS

JMS (Java Message Service) is supported by IBM MQ, TIBCO EMS, ActiveMQ, and others. Since Mendix runs on the JVM, JMS integration is natural via Marketplace connectors or custom Java actions.

Key concepts: **Queues** provide point-to-point (one consumer per message), **Topics** provide pub-sub (all subscribers get every message). Use persistent messages for reliability (survive broker restarts) and connection pooling (creating connections per message is expensive).

### Event-Driven Integration Patterns

**Event naming**: Past tense -- "OrderPlaced" not "PlaceOrder" (that is a command).

**Event payload**: Include enough data that consumers do not need callbacks, but no more than necessary.

**Schema evolution**: Add optional fields rather than renaming/removing. Include a version. Consumers should ignore unknown fields.

**Patterns in Mendix:**
- **Saga pattern**: For multi-step processes across services, use a state machine entity tracking progress. Each step publishes an event on completion. Failures trigger compensating events.
- **Event sourcing**: Store events instead of current state. Reconstruct state by replaying events. Powerful for audit trails.
- **CQRS**: Separate write model (processes commands, publishes events) from read model (consumes events, updates read-optimized views).

---

## 6. File-Based Integration

File-based integration remains relevant for batch processing, legacy systems, and regulated data transfers.

### SFTP

Use the **SFTP Connector** from the Mendix Marketplace for secure file transfers.

**Reliable processing pattern:**

1. Scheduled event polls periodically.
2. List remote directory contents.
3. Filter against a tracking table to identify new files.
4. Download to a Mendix FileDocument.
5. Create a tracking record (filename, timestamp, status "processing").
6. Process file contents.
7. Update tracking record to "completed" or "failed".
8. Move/delete remote file (move to archive on success, leave in place on failure).

For production, use SSH key authentication instead of passwords.

### Shared Storage

**S3-compatible storage** (AWS S3, MinIO, Azure Blob): Use the Amazon S3 Connector. Establish conventions for folder naming (`/incoming/{source}/`, `/outgoing/{target}/`) and file naming (include timestamps and sequence numbers).

**Network file shares** (on-premises): Use Java actions to read/write via the server filesystem. Mount the share and reference the path. Apply the same tracking and processing patterns as SFTP.

### Excel and CSV Import/Export

**Excel import** via the Marketplace **Excel Importer** module: define templates mapping columns to entity attributes, execute imports, validate results. For large files (10,000+ rows), process in batches to avoid memory issues.

**CSV import**: For robust parsing, use a Java action with OpenCSV or Apache Commons CSV (handles quoted fields, escaped characters, different delimiters). The built-in approach of splitting by newlines and delimiters breaks on edge cases.

**Export**: Use the Excel Exporter module, or build CSV strings in microflows (wrapping values containing commas/quotes/newlines in double quotes).

### Batch Processing

**Small datasets (under 10K records)**: Retrieve all, loop, commit, log.

**Medium datasets (10K-1M)**: Retrieve in chunks of 1,000, commit per chunk, track progress for resumability.

**Large datasets**: Partition input data, create Task Queue tasks per partition, process in parallel. A coordination microflow monitors completion.

Key principles: **idempotency** (running twice produces the same result), **commit every 100-1,000 records** (not per-record, not all-at-once), **manage memory** (do not load millions of records at once), and **log summaries per chunk with details only for errors**.

---

## 7. Webhooks

Webhooks invert the request-response pattern. Instead of polling for changes, the external system pushes data to your app when something happens.

### Receiving Webhooks in Mendix

1. Create a **Published REST Service** with a POST operation.
2. The handler microflow should **acknowledge quickly** (return 200 within seconds), **validate the payload**, and **queue for processing** rather than processing inline.

**Why queue instead of process inline?** Webhook providers retry on timeout (often 5-30 seconds). If your processing takes longer, you receive duplicates. Queuing gives you control over ordering, retry logic, and error handling.

**Webhook event log entity:**

| Attribute | Type | Purpose |
|-----------|------|---------|
| EventId | String | Provider's event ID (for deduplication) |
| ReceivedAt | DateTime | When received |
| EventType | String | Event type (e.g., "payment.completed") |
| RawPayload | String (unlimited) | Full JSON body |
| Status | Enumeration | Received / Processing / Completed / Failed |
| RetryCount | Integer | Processing attempts |
| ErrorMessage | String | Error details on failure |

### Securing Webhook Endpoints

**Signature verification**: Most providers sign payloads (e.g., HMAC-SHA256). Create a Java action that computes the expected signature from the body and shared secret, then compares it to the received signature using constant-time comparison. Reject on mismatch.

**IP whitelisting**: Restrict the endpoint to the provider's published IP ranges via Developer Portal (Mendix Cloud) or reverse proxy configuration (on-premises).

**Timestamp validation**: Verify the payload timestamp is recent (within 5 minutes) to prevent replay attacks.

### Retry Handling

**When receiving**: Use the webhook event ID for **idempotent processing** -- check your event log before processing. If already processed, return 200 without reprocessing. Return 503 with `Retry-After` header when temporarily unable to process.

**When sending webhooks** from your Mendix app:

1. Persist the event before attempting delivery.
2. Attempt HTTP POST to the subscriber.
3. On failure, retry with **exponential backoff** (1 min, 5 min, 30 min, 2 hours, 12 hours).
4. After max retries (e.g., 10), stop and alert an administrator.
5. A scheduled event processes the retry queue.

---

## 8. Error Handling for Integrations

Integration failures are inevitable. Robust error handling separates production-quality integrations from fragile ones.

### Retry Patterns

**Classify errors first.** Not all errors deserve retries:

| HTTP Status | Retryable? | Notes |
|-------------|-----------|-------|
| 408/502/503/504 | Yes | Transient infrastructure issues |
| 429 | Yes (after delay) | Rate limit; respect Retry-After header |
| 500 | Maybe | Could be transient or persistent |
| 400/401/403/404/422 | No | Fix the request, do not retry |

**Simple retry**: On failure, wait a fixed delay, retry up to N times.

**Exponential backoff with jitter**: Increase delay exponentially (1s, 2s, 4s, 8s...) up to a max. Add random jitter to prevent thundering herd. Typical values: base delay 1s, max delay 60s, max retries 5.

**Mendix implementation**: Wrap Call REST in an error handler. Check status code. If retryable and under max retries, sleep (via Community Commons or Java action), increment counter, loop back.

### Circuit Breaker Pattern

Prevents repeatedly calling a known-failing service, giving it time to recover.

**Three states:**
1. **Closed** (normal): Requests pass through. Monitor failures. If failures exceed threshold in a window, open the circuit.
2. **Open** (failing fast): Requests rejected immediately. After a reset timeout, move to half-open.
3. **Half-Open** (testing): Limited requests allowed. Success closes the circuit. Failure reopens it.

**Mendix implementation**: Track state in an entity with `State` (Closed/Open/HalfOpen), `FailureCount`, `LastFailureTime`, `FailureThreshold`, and `ResetTimeout`. Check state before each external call. Update state on success/failure.

**Fallbacks when open**: Return cached data, return defaults, queue for later, or inform the user the feature is temporarily unavailable.

### Dead Letter Queues

When retries are exhausted, preserve failed messages for investigation and potential reprocessing.

**Mendix DLQ entity:**

| Attribute | Type | Purpose |
|-----------|------|---------|
| OriginalPayload | String (unlimited) | Original message/request |
| ErrorMessage | String (unlimited) | What caused the failure |
| FailedAt | DateTime | Last attempt time |
| RetryCount | Integer | Attempts made |
| Status | Enumeration | Pending / Reprocessed / Discarded |

Build an admin interface for viewing, inspecting, and reprocessing dead letter messages. Set up alerts when new messages land in the DLQ.

### Compensating Transactions

In distributed systems, when a multi-step process fails partway through, compensating transactions undo previously completed steps.

**Example**: Order processing across inventory (reserve), payment (charge), and shipping (create). If shipping fails, you must refund the payment and release the inventory reservation.

**Implementation:**

1. Track saga state in an entity: SagaId, current Step, Status, and IDs needed for compensation (reservation ID, payment transaction ID, etc.).
2. Define compensating actions for each step (release reservation, refund payment, cancel shipment).
3. On failure, walk backward through completed steps, executing compensations.
4. If a compensation fails, log it and continue -- do not stop. Alert administrators for manual cleanup.

**Principles**: Compensating actions must be idempotent. Compensation is not exact reversal (a refund differs from never charging). Perform irreversible steps last. Store enough context in the saga entity to compensate every step.

---

## 9. Data Mapping

Data mapping bridges external formats and your Mendix domain model. Getting it right means clean data flow. Getting it wrong means bugs and data corruption.

### Import Mappings

Transform incoming JSON/XML into Mendix entities. Schema sources: JSON Structure, XML Schema (XSD), or Web Service (WSDL).

**Object handling options:**
- **Create new object**: Always creates fresh entities
- **Find by key**: Looks up by key attributes for upsert behavior (index the key attribute for performance)
- **Call a microflow**: Delegate complex logic

**Non-persistent entity pattern**: Map to NPEs first, then transform to your domain model in a separate microflow. This decouples your domain model from external formats, enables validation before committing, and isolates format changes.

### Export Mappings

Transform Mendix entities into JSON/XML for outgoing requests.

**Customizations:**
- **Optional elements**: Omit fields when empty (prevents `"field": null` in output)
- **Microflow-based values**: Format dates, convert enumerations, compute derived values, apply conditional inclusion
- **Null vs. absent**: JSON distinguishes between `null` and absent. "Optional" controls absence; microflows can set explicit nulls

### JSON Structures

Create from representative samples. Include all fields (including optional), at least two array items, and varied data types. For polymorphic responses, create separate structures per variant. Version structures and name them clearly: `Stripe_PaymentIntent_Response_v1_JSON`.

### Handling Nested Objects

Nested JSON objects map to associated entities. Consider this response:

```json
{
  "orderId": "ORD-001",
  "customer": {
    "id": "CUST-123",
    "address": { "street": "123 Main St", "city": "Springfield" }
  },
  "items": [
    { "productId": "PROD-A", "quantity": 5, "unitPrice": 29.99 }
  ]
}
```

This creates: Order -> Customer (association) -> Address (association), and Order -> OrderItem (one-to-many). The import mapping creates all entities and associations in one operation.

For deeply nested JSON (4+ levels), consider flattening to combined entities, a two-pass approach, or a Java action with Jackson/Gson for full parsing control.

### List Mapping

**Importing lists**: The mapping returns a list of entities. For large lists, process in chunks rather than holding all in memory. Filter at the API level when possible.

**Exporting lists**: Requires a one-to-many association from parent to child entity. Empty lists serialize as `[]` -- use a microflow to exclude the array if the external system does not accept empty arrays.

**Root-level arrays** (`[{...}, {...}]` without a wrapper object): Mendix handles these. Paste the array as the JSON structure sample and Mendix identifies it as a list.

---

## 10. Authentication for External Services

### API Keys

The simplest method. Store the key in a **Constant** (environment-specific). Add it as an HTTP header (`Authorization: Bearer $APIKey` or `X-API-Key: $APIKey`).

**Security**: Never hard-code keys. Rotate periodically. Use environment-specific keys. Restrict scope to minimum necessary. Monitor usage logs.

### OAuth 2.0 Flows

| Flow | Use Case | User Interaction |
|------|----------|-----------------|
| Client Credentials | Server-to-server (no user) | None |
| Authorization Code | User-facing web apps | User logs in via browser |
| Authorization Code + PKCE | SPAs, mobile apps | User logs in via browser |

#### Client Credentials (Most Common for Backend)

1. Send Client ID and Secret to the token endpoint.
2. Receive an access token (and optionally refresh token).
3. Include the token in API requests as `Authorization: Bearer $Token`.
4. Refresh before expiry.

**Mendix implementation:**

1. Constants for Client ID and Secret (per environment).
2. `GetAccessToken` microflow: POST to token endpoint with `grant_type=client_credentials`. Parse response for `access_token` and `expires_in`. Store in a singleton entity.
3. `GetValidAccessToken` microflow: Check stored token expiry (with 60-second buffer). If expired, call `GetAccessToken`. Return valid token.
4. API microflows call `GetValidAccessToken` before each request.

**Refresh proactively** (before expiry) rather than reactively (on 401). In multi-instance deployments, store tokens in the database to avoid rate-limiting the token endpoint.

#### Authorization Code Flow

For user-delegated access. Use the **OIDC SSO** or **OAuth 2.0** Marketplace module. The user is redirected to the authorization server, logs in, and is redirected back with an authorization code. Your app exchanges the code for tokens.

Store refresh tokens securely (encrypted in database). Handle token revocation on logout.

### Certificate-Based Authentication

Mutual TLS (mTLS): both server and client present certificates.

**Mendix Cloud**: Upload client certificate (PFX/PKCS12) via Developer Portal > Environments > Network > Certificates. Associate with the host. Upload CA certificates for self-signed servers.

**On-premises**: Configure runtime settings `ClientCertificates` (path), `ClientCertificatePasswords`, and `ClientCertificateUsages` (host:port).

**Certificate expiration is the number one cause of production outages** in certificate-based integrations. Track expiry dates, set alerts at 90/60/30 days, document the renewal process, and test new certificates before the old ones expire.

---

## 11. Performance and Rate Limiting

### Connection Pooling

Mendix uses Apache HttpClient with a connection pool. Default settings may need tuning:

| Setting | Default | Recommendation |
|---------|---------|----------------|
| `http.client.MaxConnectionsPerRoute` | 2 | 10-20 for high-traffic single-service integrations |
| `http.client.MaxConnectionsTotal` | 20 | Increase proportionally for many integrations |
| `http.client.CleanupAfterSeconds` | 355 | Reduce if services close idle connections |

### Timeout Configuration

**Connection timeout**: How long to establish TCP connection. Set short (5-10 seconds).

**Read timeout**: How long to wait for response data. Set based on operation (10-15s for lookups, 30-60s for complex operations).

Configure via the Call REST **Timeout** property (overall) or runtime settings for granular control:
```
http.client.ConnectionTimeout: 5000   (ms)
http.client.SocketTimeout: 30000      (ms)
```

**Better approach**: Short timeout + 2-3 retries beats a single long timeout. You recover from transient issues faster.

### Handling Rate Limits

**Reactive**: When you get 429, check the `Retry-After` header and wait before retrying.

**Proactive (client-side rate limiting)**: Track request count per period in a `RateLimitTracker` entity. Before each call, check if you are within the limit. If at limit, wait until period resets.

**Batching**: For bulk operations against rate-limited APIs, process in chunks with delays between chunks. Use bulk/batch endpoints when available.

### Caching Responses

**Good candidates**: Reference data, infrequently changing configs, repeated search results.
**Do not cache**: Frequently changing data, sensitive data, write operation responses.

**Strategies:**

- **Entity-based cache**: Cache entity with `CachedAt`/`ExpiresAt` attributes. Check cache before API calls. Scheduled cleanup of expired entries.
- **NPE cache**: Session-scoped, garbage-collected on session end. Good for per-user data.
- **Background sync**: Scheduled event periodically refreshes local copies. Pages read local data. Best performance, trade-off is staleness.

**Cache invalidation**: Time-based (simplest), event-based (webhook triggers invalidation), or manual (admin action). Watch for cache stampedes -- use background refresh or locking so only one request refreshes while others wait.

---

## 12. Testing Integrations

Integration testing is harder than unit testing because it involves external systems you do not control.

### Mocking External Services

**Why mock?** Availability, cost, speed, control, and determinism. Mock responses are instant, predictable, and free.

**Approach 1: Mock server with configurable base URL.** Point your API base URL constant to a mock server (WireMock, Mockoon, Postman Mock Server) in test environments. The mock server returns predefined responses.

**Approach 2: Feature flag.** A `UseMockServices` boolean constant. Integration microflows check it and call either mock sub-microflows or real services. Simple but mixes test logic with production code.

**Approach 3: Service abstraction layer (recommended).** Define interface microflows (`CustomerService_GetById`, `CustomerService_Search`). Implement two versions: real and mock. A constant selects the implementation. Business microflows are unaware of which is behind them.

**Mock data**: Use real response samples. Include edge cases: empty results, max-size results, unicode, error responses (400, 401, 429, 500), slow responses, and malformed responses. Keep mocks updated when the API changes.

### Integration Test Environments

**Sandbox environments**: Many providers offer them (Stripe test keys, PayPal sandbox, Salesforce Developer Edition, Twilio test credentials).

**Shared test environments**: Namespace test data (prefix with "TEST_") to avoid conflicts with other teams.

**Local Docker instances**: Run services locally (Elasticsearch, PostgreSQL, RabbitMQ, Kafka) for development.

**Test data management**: Create setup microflows that build test data programmatically. Clean up afterward. Use unique identifiers (timestamps, UUIDs) to avoid collisions. Avoid shared mutable state between test cases.

### Contract Testing

Verifies that integration conforms to an agreed-upon API specification, catching breaking changes before production.

**Consumer-side**: Test your Mendix app against mocks that conform to the contract (OpenAPI spec, WSDL, OData metadata). Verify correct requests and response handling.

**Provider-side**: Test that real responses match the contract. If you control the provider (another Mendix app), write validation tests. If not, run periodic smoke tests against the provider's test environment.

**Schema validation**: Store expected JSON schemas. After receiving responses, validate with a Java action using a JSON Schema library. Log warnings for minor deviations, errors for major ones. In test, fail on violations. In production, log but attempt graceful processing.

### Monitoring Integration Health in Production

- **Health checks**: Microflow that pings each external service, exposed as a REST endpoint for monitoring
- **Response time tracking**: Log per-call times, track P95/P99, alert on threshold breaches
- **Error rate tracking**: Track non-2xx percentage per service, alert above 5%
- **Circuit breaker monitoring**: Alert on state changes
- **Synthetic transactions**: Periodic full integration tests in production with test data
- **Log correlation**: Include a unique correlation ID in every request, pass it to external services via header, trace end-to-end during troubleshooting

---

## Quick Reference: Integration Checklist

### Before You Start

- [ ] Identify integration method (REST, OData, SOAP, messaging, file, webhook)
- [ ] Determine sync vs. async pattern
- [ ] Obtain API docs, credentials, and test environment access
- [ ] Understand rate limits and SLAs
- [ ] Define data mapping between external formats and domain model

### Implementation

- [ ] URLs, credentials, and config in constants (not hard-coded)
- [ ] Proper authentication (API key, OAuth, certificate)
- [ ] Appropriate timeouts (connection and read)
- [ ] All expected HTTP status codes handled
- [ ] Retry logic for transient errors
- [ ] Import/export mappings or dedicated integration entities
- [ ] Pagination for list endpoints

### Error Handling

- [ ] Errors classified as retryable vs. permanent
- [ ] Exponential backoff with jitter
- [ ] Circuit breaker for critical integrations
- [ ] Dead letter queue for unprocessable messages
- [ ] Compensating actions for multi-step processes

### Testing

- [ ] Mock services for dev and automated testing
- [ ] Happy path, errors, timeouts, and edge cases tested
- [ ] Response schemas validated against contract
- [ ] Realistic data volumes tested

### Operations

- [ ] Response times and error rates monitored
- [ ] Alerts for failures, high latency, circuit breaker trips
- [ ] Certificate and API key expiration tracked
- [ ] Graceful degradation strategy documented

---

## References

- [Mendix Documentation: Integration](https://docs.mendix.com/refguide/integration/)
- [Mendix Documentation: Published REST Services](https://docs.mendix.com/refguide/published-rest-services/)
- [Mendix Documentation: Consumed REST Services](https://docs.mendix.com/refguide/consumed-rest-services/)
- [Mendix Documentation: Published OData Services](https://docs.mendix.com/refguide/published-odata-services/)
- [Mendix Documentation: Consumed OData Services](https://docs.mendix.com/refguide/consumed-odata-services/)
- [Mendix Documentation: Consumed Web Services (SOAP)](https://docs.mendix.com/refguide/consumed-web-services/)
- [Mendix Documentation: Import Mappings](https://docs.mendix.com/refguide/import-mappings/)
- [Mendix Documentation: Export Mappings](https://docs.mendix.com/refguide/export-mappings/)
- [Mendix Marketplace](https://marketplace.mendix.com/)
- [OData Protocol Specification](https://www.odata.org/)
- [OAuth 2.0 Specification (RFC 6749)](https://tools.ietf.org/html/rfc6749)
- [Enterprise Integration Patterns](https://www.enterpriseintegrationpatterns.com/)
