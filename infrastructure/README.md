# Core Infrastructure for Mendix Applications

## A Practical Guide to Runtime, Database, Storage, Networking, and Operations

**Version:** 1.0
**Date:** February 2026

---

## Table of Contents

1. [Mendix Runtime Architecture](#1-mendix-runtime-architecture)
   - [How a Mendix App Runs](#how-a-mendix-app-runs)
   - [Request Lifecycle](#request-lifecycle)
   - [Runtime Components](#runtime-components)
2. [Database Configuration](#2-database-configuration)
   - [Supported Databases](#supported-databases)
   - [Connection Pooling](#connection-pooling)
   - [Sizing Guidelines](#sizing-guidelines)
   - [Schema Ownership and Migrations](#schema-ownership-and-migrations)
3. [File Storage](#3-file-storage)
   - [Local vs. External Storage](#local-vs-external-storage)
   - [S3-Compatible Storage](#s3-compatible-storage)
   - [Azure Blob Storage](#azure-blob-storage)
4. [Memory and JVM Configuration](#4-memory-and-jvm-configuration)
   - [Heap Sizing](#heap-sizing)
   - [Garbage Collection Tuning](#garbage-collection-tuning)
   - [Custom JVM Arguments](#custom-jvm-arguments)
   - [Monitoring Memory Usage](#monitoring-memory-usage)
5. [Logging](#5-logging)
   - [Log Levels and Log Nodes](#log-levels-and-log-nodes)
   - [Configuring Log Destinations](#configuring-log-destinations)
   - [Structured Logging](#structured-logging)
   - [Integrating with Log Platforms](#integrating-with-log-platforms)
6. [Caching](#6-caching)
   - [Object Caching](#object-caching)
   - [Session Management](#session-management)
   - [Cache Invalidation](#cache-invalidation)
7. [Clustering and High Availability](#7-clustering-and-high-availability)
   - [Multi-Instance Architecture](#multi-instance-architecture)
   - [Sticky Sessions](#sticky-sessions)
   - [Shared File Storage Requirements](#shared-file-storage-requirements)
   - [Database Failover](#database-failover)
8. [Reverse Proxy and Load Balancer Setup](#8-reverse-proxy-and-load-balancer-setup)
   - [Nginx Configuration](#nginx-configuration)
   - [Apache Configuration](#apache-configuration)
   - [Caddy Configuration](#caddy-configuration)
   - [WebSocket and Header Forwarding](#websocket-and-header-forwarding)
9. [SSL/TLS Configuration](#9-ssltls-configuration)
   - [TLS Termination Strategies](#tls-termination-strategies)
   - [Certificate Management](#certificate-management)
   - [HSTS](#hsts)
10. [Monitoring and Health Checks](#10-monitoring-and-health-checks)
    - [Built-in Admin Endpoints](#built-in-admin-endpoints)
    - [Application Metrics](#application-metrics)
    - [Health Check Endpoints](#health-check-endpoints)
    - [JMX Metrics](#jmx-metrics)
11. [Backup and Recovery](#11-backup-and-recovery)
    - [Database Backup Strategies](#database-backup-strategies)
    - [File Storage Backup](#file-storage-backup)
    - [Disaster Recovery Planning](#disaster-recovery-planning)
12. [Network Security](#12-network-security)
    - [Firewall Rules](#firewall-rules)
    - [Restricting Admin Ports](#restricting-admin-ports)
    - [VPN Considerations](#vpn-considerations)

---

## 1. Mendix Runtime Architecture

### How a Mendix App Runs

A Mendix application is a Java application running on the Mendix Runtime -- a server built on top of Jetty. The runtime interprets your compiled model (`.mda`) and handles request processing, data access, and business logic.

Three core dependencies:

| Component | Purpose |
|-----------|---------|
| **Mendix Runtime (Java)** | Executes the application model, serves the client |
| **Database** | Stores persistent entities, system tables, user sessions |
| **File Storage** | Stores `FileDocument` and `Image` entity content |

The runtime is stateful -- it holds user sessions, cached objects, and scheduled event state in memory. This directly impacts clustering (see [Section 7](#7-clustering-and-high-availability)).

### Request Lifecycle

```
Client (Browser/API)
    |
[Reverse Proxy / LB]  -- TLS termination, static assets, routing
    |
[Mendix Runtime (Jetty)]
    +-- Authentication (session token / SSO / API key)
    +-- Authorization (module roles, entity access, XPath)
    +-- Business logic (microflows, Java actions)
    +-- Data layer (ORM -> SQL -> DB)
    +-- File I/O (configured storage backend)
    |
[Response to client]
```

- Client communicates via `/xas/` (runtime API) and `/api/` (published services)
- Static assets served from `/mxclientsystem/` and `/widgets/`
- WebSocket connections on `/ws/` for real-time push
- Pages served under `/p/`

### Runtime Components

| Component | Port | Description |
|-----------|------|-------------|
| Application server | 8080 (default) | Main HTTP endpoint |
| Admin port | 8090 (default) | M2EE admin API, health checks, metrics |
| Debugger port | 8000 | Development only; disable in production |
| Scheduled events | Internal | Cron-like microflow execution |
| Session store | In-memory / DB | Active user sessions |

**Deployment artifacts:** `model/` (compiled model), `web/` (static frontend), `userlib/` (custom JARs), `data/files/` (default file storage), `m2ee.yaml` (runtime config).

---

## 2. Database Configuration

### Supported Databases

| Database | Versions | Notes |
|----------|----------|-------|
| **PostgreSQL** | 12 -- 16 | Recommended. Best community support. |
| **SQL Server** | 2019, 2022 | Requires `READ_COMMITTED_SNAPSHOT ON`. |
| **Azure SQL** | Current | Managed SQL Server. |
| **Oracle** | 19c, 21c | Requires specific grants. Higher licensing cost. |
| **MySQL** | 8.0+ | Supported but less common in Mendix deployments. |
| **MariaDB** | 10.6+ | Community alternative to MySQL. |
| **HSQLDB** | Built-in | Development only. Never use in production. |

Use PostgreSQL unless organizational standards mandate otherwise.

### Connection Pooling

| Setting | Default | Recommended | Description |
|---------|---------|-------------|-------------|
| `ConnectionPoolingMaxActive` | 50 | 50 -- 100 | Max concurrent DB connections |
| `ConnectionPoolingMaxIdle` | 50 | 20 -- 50 | Max idle connections kept open |
| `ConnectionPoolingMinIdle` | 0 | 5 -- 10 | Minimum idle connections maintained |
| `ConnectionPoolingMaxWait` | 10000 | 10000 | Max ms to wait for a connection |

- Start with `MaxActive = 50` for most apps; increase if you see `ConnectionPool exhausted` in logs
- Each PostgreSQL connection uses ~10 MB RAM on the DB server
- Keep `MaxActive` below `max_connections` minus a 10 -- 20 safety margin

### Sizing Guidelines

| App Profile | Users | DB RAM | DB CPU | Storage |
|-------------|-------|--------|--------|---------|
| Small | < 100 | 2 -- 4 GB | 2 vCPU | 20 GB |
| Medium | 100 -- 1,000 | 8 -- 16 GB | 4 vCPU | 100 GB |
| Large | 1,000 -- 10,000 | 32 -- 64 GB | 8+ vCPU | 500 GB+ |
| High-throughput API | RPS-based | 16 -- 64 GB | 8+ vCPU | Varies |

**PostgreSQL tuning:** `shared_buffers` = 25% RAM, `effective_cache_size` = 75% RAM, `work_mem` = 4 -- 16 MB, `maintenance_work_mem` = 256 MB -- 1 GB.

### Schema Ownership and Migrations

The Mendix Runtime manages the schema automatically -- creating tables on first start and synchronizing on every deployment. Destructive changes (dropping columns with data) require confirmation.

- Grant the runtime DB user full DDL + DML permissions on its schema
- Use a dedicated schema/database per Mendix app
- **Back up the database before every deployment** -- schema sync can drop data
- On Oracle, grant `CREATE TABLE`, `CREATE SEQUENCE`, `CREATE VIEW` explicitly

---

## 3. File Storage

### Local vs. External Storage

| Aspect | Local File System | External (S3 / Azure Blob) |
|--------|-------------------|---------------------------|
| Setup complexity | Minimal | Moderate |
| Clustering support | No (unless NFS) | Yes |
| Scalability | Limited by disk | Virtually unlimited |
| Recommended for | Development, single-node | Production, any multi-node |

### S3-Compatible Storage

Works with AWS S3, MinIO, Ceph, DigitalOcean Spaces.

```yaml
# m2ee.yaml -- AWS S3
mxruntime:
  com.mendix.storage.s3.AccessKeyId: "YOUR_ACCESS_KEY"
  com.mendix.storage.s3.SecretAccessKey: "YOUR_SECRET_KEY"
  com.mendix.storage.s3.BucketName: "mendix-files"
  com.mendix.storage.s3.EndPoint: "https://s3.amazonaws.com"
  com.mendix.storage.s3.UseV2Auth: false
  com.mendix.storage.PerformDeleteFromStorage: true
```

**For MinIO / non-AWS endpoints**, add `ForcePathStyle: true` (required -- without it, the SDK tries virtual-hosted-style URLs that will fail):

```yaml
  com.mendix.storage.s3.EndPoint: "http://minio:9000"
  com.mendix.storage.s3.ForcePathStyle: true
```

### Azure Blob Storage

```yaml
mxruntime:
  com.mendix.storage.azure.AccountName: "yourstorageaccount"
  com.mendix.storage.azure.AccountKey: "YOUR_ACCOUNT_KEY"
  com.mendix.storage.azure.Container: "mendix-files"
```

Use `SharedAccessSignature` instead of `AccountKey` for scoped access.

**Additional storage settings:** `s3.EncryptionKeys` (AES-256 client-side), `s3.MaxConnections` (default 50), `s3.ConnectionTimeout` (default 10000 ms), `PerformDeleteFromStorage` (default true -- deletes files when entity is deleted).

---

## 4. Memory and JVM Configuration

### Heap Sizing

| App Profile | Min Heap (`-Xms`) | Max Heap (`-Xmx`) |
|-------------|--------------------|--------------------|
| Development | 512 MB | 1 GB |
| Small production | 1 GB | 2 GB |
| Medium production | 2 GB | 4 GB |
| Large production | 4 GB | 8 GB |

- Set `-Xms` equal to `-Xmx` to avoid heap resize pauses
- Leave 30%+ of server RAM for the OS, DB connections, and file cache
- Metaspace (class metadata) is outside the heap -- reserve ~256 MB

### Garbage Collection Tuning

G1GC is the default on Java 11+ and the right choice for most Mendix workloads.

```
-XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:G1HeapRegionSize=8m
-XX:+ParallelRefProcEnabled -XX:InitiatingHeapOccupancyPercent=45
```

Consider ZGC or Shenandoah (Java 17+) for very large heaps (> 16 GB) or sub-10ms latency requirements.

### Custom JVM Arguments

```yaml
# m2ee.yaml
m2ee:
  javaopts:
    - "-Xms2g"
    - "-Xmx4g"
    - "-XX:+UseG1GC"
    - "-XX:MaxGCPauseMillis=200"
    - "-XX:+HeapDumpOnOutOfMemoryError"
    - "-XX:HeapDumpPath=/var/log/mendix/heapdump.hprof"
    - "-Djava.net.preferIPv4Stack=true"
    - "-Dfile.encoding=UTF-8"
```

For Docker, use `JAVA_OPTS` environment variable. **Always enable `-XX:+HeapDumpOnOutOfMemoryError` in production** -- gives you a heap dump for post-mortem analysis instead of a silent crash.

### Monitoring Memory Usage

| Method | How |
|--------|-----|
| Admin API | `GET /admin/runtime/memory` -- heap used, committed, max |
| JMX | VisualVM / JConsole -- live GC stats, thread dumps |
| GC logs | `-Xlog:gc*:file=/var/log/gc.log` |
| Prometheus | JMX Exporter agent -- Grafana-ready metrics |

**Warning signs:** Frequent Full GC (> 1/min), heap consistently > 85% after GC, `OutOfMemoryError` in logs, response times correlated with GC pauses.

---

## 5. Logging

### Log Levels and Log Nodes

**Levels (most to least verbose):** `TRACE` > `DEBUG` > `INFO` > `WARNING` > `ERROR` > `CRITICAL`

| Log Node | Covers |
|----------|--------|
| `Core` | Runtime lifecycle, general operations |
| `ConnectionBus` | Database queries, connection pool |
| `Connector` | Published/consumed web services |
| `REST` | Published REST services |
| `Microflows` | Microflow execution (very verbose at DEBUG) |
| `FileDocumentTransit` | File upload/download |
| `WebUI` | Client interactions |
| `CustomLog` | Your custom Log Message activities |

### Configuring Log Destinations

```yaml
logging:
  - type: file
    name: FileLog
    filename: /var/log/mendix/application.log
    max_size: 100    # MB per file
    max_rotation: 10
  - type: tcpjsonlines
    name: RemoteLog
    host: logstash.internal
    port: 5044
```

| Type | Description |
|------|-------------|
| `file` | Local log file with rotation |
| `tcpjsonlines` | Structured JSON over TCP (Logstash, Fluentd) |
| `syslog` | Standard syslog protocol |
| `console` | Stdout -- use for container deployments |

### Structured Logging

The `tcpjsonlines` output includes `timestamp`, `level`, `node`, `message`, `thread`, and `correlation_id`. To add custom context, embed structured data in the Log Message text and parse it in your pipeline -- Mendix has no native key-value metadata support.

### Integrating with Log Platforms

**ELK:** Point `tcpjsonlines` at Logstash with a `tcp { codec => json_lines }` input. Use a `date` filter on the `timestamp` field. Index as `mendix-%{+YYYY.MM.dd}`.

**Datadog:** Use the Datadog Agent with file or stdout collection. Set `source: mendix` and `service: your-app-name`.

**Splunk:** Use the Universal Forwarder on `/var/log/mendix/` or route `tcpjsonlines` to a Splunk HEC endpoint.

---

## 6. Caching

### Object Caching

Mendix caches persistable objects in the JVM heap at two levels:

| Cache Level | Scope |
|-------------|-------|
| **Session cache** | Per user session. Objects cached until session ends. |
| **Client state** | Objects currently visible in the user's client. |

Entity-level caching is not configurable. You influence it indirectly: use `Range` (offset + limit) on retrieves to reduce cache pressure, and retrieve by ID to leverage cache hits.

### Session Management

| Setting | Default | Description |
|---------|---------|-------------|
| `SessionTimeout` | 600000 (10 min) | Idle session timeout (ms) |
| `SessionKeepAliveUpdatesInterval` | 100000 | Client keep-alive ping interval (ms) |
| `ClusterManagerActionInterval` | 300000 | Cluster session sync interval (ms) |
| `PersistentSessions` | false | Store sessions in DB (required for clustering) |

### Cache Invalidation

- Committed objects: cache entry updated automatically
- Deleted objects: cache entry removed
- Database rollback: affected entries cleared
- **Cross-instance (clustered):** No real-time sync. Instance B reads from DB on next retrieve after Instance A commits. Eventual consistency applies.

**Performance tips:** Monitor heap with many cached entities. Set a reasonable `SessionTimeout`. Process batch retrieves in pages of 100 -- 500. Heavy non-persistable entity (NPE) use increases per-session memory.

---

## 7. Clustering and High Availability

### Multi-Instance Architecture

```
                   +-- [Mendix Instance 1] --+
[Load Balancer] ---|                         |--- [Shared Database]
                   +-- [Mendix Instance 2] --+
                   |                         |
                   +-- [Shared File Storage] -+
```

**Requirements:**
- Shared database (all instances connect to the same DB)
- Shared file storage (S3 or NFS -- local storage will not work)
- `PersistentSessions: true`
- Sticky sessions on the load balancer (recommended)

### Sticky Sessions

Mendix recommends sticky sessions even with persistent sessions. Without them, every request may hit a different instance, forcing DB reads for session state and losing unsaved client state.

**Configure affinity using the `XASSESSIONID` cookie:**

| Load Balancer | Config |
|---------------|--------|
| Nginx | `ip_hash;` or `sticky cookie` directive |
| HAProxy | `cookie XASSESSIONID insert indirect nocache` |
| AWS ALB | Target group stickiness with application cookie |
| Caddy | Hash-based upstream directive |

### Shared File Storage Requirements

| Option | Pros | Cons |
|--------|------|------|
| **S3 / MinIO** | Scalable, no mount config | Latency for large files |
| **NFS mount** | Simple, transparent | Single point of failure |
| **Azure Blob** | Managed | Azure-specific |

### Database Failover

| Strategy | RTO |
|----------|-----|
| PostgreSQL streaming replication + manual promote | Minutes |
| Patroni / Stolon (automated PostgreSQL failover) | Seconds |
| AWS RDS Multi-AZ | ~60 seconds |
| Azure SQL HA | ~30 seconds |
| SQL Server Always On | Seconds -- minutes |

The runtime reconnects automatically when the new primary is reachable. Use virtual IPs or DNS-based failover to avoid config changes.

---

## 8. Reverse Proxy and Load Balancer Setup

### Nginx Configuration

```nginx
upstream mendix {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    ssl_certificate     /etc/ssl/certs/app.example.com.pem;
    ssl_certificate_key /etc/ssl/private/app.example.com.key;

    client_max_body_size 200M;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    location / {
        proxy_pass http://mendix;
        proxy_http_version 1.1;
    }

    location /ws/ {
        proxy_pass http://mendix;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
    }

    location /admin/ { deny all; }
}
```

### Apache Configuration

```apache
<VirtualHost *:443>
    ServerName app.example.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/app.example.com.pem
    SSLCertificateKeyFile /etc/ssl/private/app.example.com.key

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"

    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteRule ^/ws/(.*) ws://127.0.0.1:8080/ws/$1 [P,L]
</VirtualHost>
```

Required modules: `mod_proxy`, `mod_proxy_http`, `mod_proxy_wstunnel`, `mod_rewrite`, `mod_ssl`, `mod_headers`.

### Caddy Configuration

```caddyfile
app.example.com {
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-Proto {scheme}
        header_up X-Real-IP {remote_host}
    }

    @admin path /admin/*
    respond @admin 403

    request_body { max_size 200MB }
}
```

Caddy handles TLS automatically via Let's Encrypt. WebSocket proxying is automatic.

### WebSocket and Header Forwarding

Mendix uses WebSockets on `/ws/` for real-time push. **All proxy configs must support WebSocket upgrades.** Without it, the client falls back to long-polling with higher latency.

Common mistake: `proxy_read_timeout` too low in Nginx. WebSocket connections are long-lived -- use `86400s` for `/ws/`.

**Required headers:**

| Header | Purpose | If Missing |
|--------|---------|------------|
| `X-Forwarded-Proto` | Original protocol (HTTPS) | HTTP URLs generated, cookies lack `Secure` flag |
| `X-Forwarded-For` | Client IP | All requests appear from proxy IP |
| `X-Forwarded-Host` | Original hostname | Redirect URLs use internal hostname |

Enable header trust in the runtime:

```yaml
mxruntime:
  com.mendix.core.EnableHTTPForwardedHeaders: true
```

---

## 9. SSL/TLS Configuration

### TLS Termination Strategies

| Strategy | Where TLS Ends | Use Case |
|----------|---------------|----------|
| **At the reverse proxy** | Nginx / Caddy / ALB | Most common. Simplest. Recommended. |
| **End-to-end** | Runtime itself | Small deployments, dev/test |
| **Re-encryption** | Proxy terminates, re-encrypts to runtime | Strict compliance requirements |

Terminate at the proxy in most cases. To configure TLS directly on the runtime:

```yaml
m2ee:
  javaopts:
    - "-Djavax.net.ssl.keyStore=/path/to/keystore.jks"
    - "-Djavax.net.ssl.keyStorePassword=changeit"
```

### Certificate Management

| Approach | Tool | Renewal |
|----------|------|---------|
| Let's Encrypt (ACME) | Caddy (built-in), certbot, acme.sh | Automatic |
| Organizational CA | Manual or SCEP/EST | Manual / semi-automated |
| Cloud provider | AWS ACM, Azure Key Vault | Automatic |
| Self-signed | openssl | Manual (dev/test only) |

Include the full chain (leaf + intermediates). Use RSA 2048+ or ECDSA P-256. Automate renewal 30+ days before expiry.

### HSTS

Configure at the reverse proxy:

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

Caddy enables HSTS by default. Do not enable `preload` until all subdomains support HTTPS -- the preload list is difficult to leave.

---

## 10. Monitoring and Health Checks

### Built-in Admin Endpoints

Exposed on the admin port (default 8090). **Never publicly accessible.**

| Endpoint | Description |
|----------|-------------|
| `/admin/runtime/status` | Runtime state (running, starting, stopped) |
| `/admin/runtime/memory` | JVM heap and non-heap usage |
| `/admin/runtime/statistics` | Request counts, durations, named users |
| `/admin/runtime/threads` | Active threads |
| `/admin/runtime/cache` | Cache statistics |
| `/admin/runtime/sessions` | Active session count |

```bash
curl -u MxAdmin:your_admin_password http://localhost:8090/admin/runtime/status
```

### Application Metrics

| Metric | Alert Threshold |
|--------|-----------------|
| Request rate (RPS) | Baseline + 50% |
| Response time (p95) | > 2 seconds |
| Error rate (5xx) | > 1% of requests |
| Active sessions | > 80% of licensed users |
| Heap usage after GC | > 85% of max |
| DB pool usage | > 80% of `MaxActive` |
| Thread count | > 200 |

### Health Check Endpoints

For load balancers, `GET /` returns `200 OK` when the app is running. For a deeper check including DB connectivity, use `GET /admin/runtime/status` (requires auth).

**LB settings:** Interval 10 -- 30s, healthy threshold 2, unhealthy threshold 3, timeout 5s.

### JMX Metrics

```yaml
m2ee:
  javaopts:
    - "-Dcom.sun.management.jmxremote"
    - "-Dcom.sun.management.jmxremote.port=9010"
    - "-Dcom.sun.management.jmxremote.ssl=false"
    - "-Dcom.sun.management.jmxremote.authenticate=false"
    - "-Djava.rmi.server.hostname=127.0.0.1"
```

For Prometheus + Grafana, use the [JMX Exporter](https://github.com/prometheus/jmx_exporter) as a Java agent on port 9404. **Never expose JMX to the public internet.**

---

## 11. Backup and Recovery

### Database Backup Strategies

| Strategy | Frequency | RPO | Tool |
|----------|-----------|-----|------|
| Full backup | Daily | 24 hours | `pg_dump`, SQL Server backup |
| WAL archiving | Continuous | Minutes | `pg_basebackup` + WAL, pgBackRest |
| Cloud snapshots | Hourly / daily | 1 -- 24 hours | RDS snapshots, Azure backup |
| Logical replication | Continuous | Seconds | PostgreSQL logical replication |

```bash
# PostgreSQL backup
pg_dump -h localhost -U mendix_user -Fc mendix_app > /backups/mendix_$(date +%Y%m%d).dump

# Restore
pg_restore -h localhost -U mendix_user -d mendix_app --clean --if-exists backup.dump
```

- **Test restores regularly** -- an untested backup is not a backup
- Store backups off-site (different server, region, or cloud account)
- Encrypt at rest: `pg_dump | gpg -e -r backup@company.com > backup.dump.gpg`
- **Back up before every deployment** -- schema sync can be destructive

### File Storage Backup

| Storage Type | Backup Method |
|-------------|---------------|
| Local files | `rsync` to a remote server |
| S3 / MinIO | Cross-region replication, `aws s3 sync`, `mc mirror` |
| Azure Blob | Blob versioning, `azcopy sync` |

**Always back up database and file storage together.** A database referencing nonexistent files (or vice versa) produces broken FileDocument entities.

### Disaster Recovery Planning

| Component | Recovery Action | Target RTO |
|-----------|----------------|------------|
| Database | Restore from backup or promote replica | < 1 hour |
| File storage | Restore from replication or backup | < 2 hours |
| Application | Redeploy from CI/CD pipeline | < 30 minutes |
| Infrastructure | IaC rebuild (Terraform, Ansible) | < 1 hour |

**DR checklist:**
- [ ] Database backups automated, encrypted, stored off-site
- [ ] File storage replication or backup configured
- [ ] CI/CD can redeploy without manual steps
- [ ] Infrastructure defined as code
- [ ] Restore procedure documented and tested quarterly
- [ ] Runbook with step-by-step instructions and contacts

---

## 12. Network Security

### Firewall Rules

| Port | Direction | Source -> Destination | Purpose |
|------|-----------|----------------------|---------|
| 443 | Inbound | Internet -> Proxy | HTTPS access |
| 80 | Inbound | Internet -> Proxy | HTTP redirect to HTTPS |
| 8080 | Internal | Proxy -> Runtime | Application traffic |
| 8090 | Internal | Monitoring -> Runtime | Admin API |
| 5432 | Internal | Runtime -> PostgreSQL | Database |
| 1433 | Internal | Runtime -> SQL Server | Database (if applicable) |
| 9000 | Internal | Runtime -> MinIO/S3 | File storage |
| 9010 | Internal | Monitoring -> Runtime | JMX (if enabled) |

**Default-deny:** Block everything, then open only the ports above to specific source networks.

### Restricting Admin Ports

Port 8090 grants full runtime control (stop, start, memory stats, admin actions). **Never expose to the internet.**

| Method | Implementation |
|--------|---------------|
| Firewall rule | Allow 8090 from monitoring IPs only |
| Bind to localhost | Jetty listens on `127.0.0.1:8090` only |
| Proxy block | `deny all` on `/admin/` in Nginx/Apache |
| Network segmentation | Private subnet, admin via jump host |

In Docker, do not publish port 8090:

```yaml
services:
  mendix:
    ports:
      - "8080:8080"    # 8090 intentionally not published
```

### VPN Considerations

Use a VPN when the database is in a different network, developers need emergency DB access, or runtime and DB span cloud providers.

| Topology | Use Case |
|----------|----------|
| Site-to-site VPN | On-premise to cloud. Persistent. |
| Client VPN | Developer emergency DB access. |
| Cloud peering | AWS VPC / Azure VNet peering. Lower latency. |
| SSH tunnel | Quick, temporary port access. |

- Never expose the database port to the public internet
- Use TLS for DB connections (`sslmode=require` in PostgreSQL)
- Rotate VPN credentials regularly
- Log all VPN connections for audit
- Colocate runtime and database in the same network for batch workloads

---

## Quick Reference: Runtime Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `DatabaseType` | HSQLDB | `POSTGRESQL`, `SQLSERVER`, `ORACLE`, `MYSQL` |
| `DatabaseHost` | localhost | Hostname and port (`host:port`) |
| `DatabaseName` | default | Database/schema name |
| `ConnectionPoolingMaxActive` | 50 | Max active DB connections |
| `SessionTimeout` | 600000 | Session idle timeout (ms) |
| `PersistentSessions` | false | Store sessions in DB (clustering) |
| `com.mendix.core.EnableHTTPForwardedHeaders` | false | Trust X-Forwarded-* headers |
| `com.mendix.storage.s3.EndPoint` | -- | S3 storage endpoint |
| `com.mendix.storage.s3.BucketName` | -- | S3 bucket name |
| `com.mendix.storage.PerformDeleteFromStorage` | true | Delete files on entity delete |
| `LogMinDurationQuery` | 10000 | Log slow queries above this (ms) |
| `ScheduledEventExecution` | NONE | `NONE`, `SPECIFIED`, or `ALL` |

---

*Covers Mendix 9.x and 10.x. Some settings differ in earlier versions. See the [Mendix Runtime Reference](https://docs.mendix.com/refguide/runtime/) for version-specific details.*
