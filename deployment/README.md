[Home](../README.md) > **Deployment**

---

# Deployment Strategies for Mendix Applications

## A Practical Guide for Multi-Environment, Production-Grade Deployments

**Version:** 1.0
**Date:** February 2026
**Classification:** Public

---

## Table of Contents

1. [Deployment Options Overview](#1-deployment-options-overview)
2. [Mendix Cloud Deployment](#2-mendix-cloud-deployment)
3. [Docker Deployment](#3-docker-deployment)
4. [Kubernetes Deployment](#4-kubernetes-deployment)
5. [Cloud Foundry](#5-cloud-foundry)
6. [On-Premise Deployment](#6-on-premise-deployment)
7. [Environment Configuration](#7-environment-configuration)
8. [Database Management Across Environments](#8-database-management-across-environments)
9. [Deployment Pipelines](#9-deployment-pipelines)
10. [Rollback Strategies](#10-rollback-strategies)
11. [Multi-Environment Strategy](#11-multi-environment-strategy)
12. [Secrets Management](#12-secrets-management)

---

## 1. Deployment Options Overview

Mendix applications run on the Mendix Runtime (Java/Jetty). Every deployment target needs the runtime, a database, and file storage. The choice depends on your control requirements, compliance posture, and operational maturity.

### Comparison Matrix

| Target | Managed By | Best For | Scaling | Effort |
|--------|-----------|----------|---------|--------|
| Mendix Cloud | Mendix | SaaS apps, rapid delivery | Vertical (plan-based) | Lowest |
| Mendix for Private Cloud | Operator on your K8s | Regulated industries, data sovereignty | Horizontal (HPA) | Medium |
| Cloud Foundry | CF platform team | Orgs already on CF (SAP BTP, etc.) | Horizontal (instances) | Medium |
| Docker / Kubernetes | Your team | Full control, hybrid cloud | Horizontal (HPA) | High |
| On-Premise (bare metal/VM) | Your team | Air-gapped, legacy infra | Vertical (bigger VM) | Highest |

### Decision Criteria

- **Mendix Cloud** -- Fastest path to production. Choose this unless you have a specific reason not to.
- **Private Cloud / K8s** -- You need data residency, your own cloud account, or advanced networking.
- **Cloud Foundry** -- Your organization already runs CF (SAP BTP, Pivotal/Tanzu).
- **Docker standalone** -- Development, staging, or small-scale production without K8s overhead.
- **On-Premise** -- Air-gapped networks, legacy compliance mandates, or no cloud access.

---

## 2. Mendix Cloud Deployment

### Environments

Every licensed Mendix Cloud node provides these environments out of the box:

| Environment | Purpose | Database | Persistent Storage |
|-------------|---------|----------|--------------------|
| Acceptance | Testing, UAT | Separate DB | Yes |
| Production | Live traffic | Separate DB | Yes |
| Free App (sandbox) | Prototyping | Shared | No (sleeps after inactivity) |

You can purchase additional environments (e.g., Test, Staging) through Mendix Support.

### Transport Mechanism

1. **Create a deployment package** -- In Studio Pro, select `Project > Create Deployment Package` (produces an `.mda` file).
2. **Upload to Developer Portal** -- Go to the app's Environments page, upload the `.mda`.
3. **Transport** -- Click "Transport" to move a package from one environment to another.
4. **Deploy** -- Select the package and click "Deploy" on the target environment.

Alternatively, use the **Mendix Deploy API** to automate these steps (see [Section 9](#9-deployment-pipelines)).

### Configuration

Set per-environment values in the Developer Portal under `Environment Details > Runtime`:

- **Constants** -- Override Mendix constant values per environment.
- **Scheduled Events** -- Enable/disable specific scheduled events per environment.
- **Custom Runtime Settings** -- JVM arguments, runtime settings, logging levels.
- **Environment Variables** -- Injected as system environment variables into the runtime.

### Scaling

Mendix Cloud scaling is tied to your subscription plan:

| Plan | RAM | vCPU | Horizontal Scaling |
|------|-----|------|--------------------|
| S | 1 GB | Shared | No |
| M | 2 GB | 1 | No |
| L | 4 GB | 2 | No |
| XL | 8 GB | 4 | No |
| XXL | 16 GB | 8 | Contact Mendix |

Scaling is vertical -- you upgrade your plan. For horizontal scaling, use Mendix for Private Cloud on Kubernetes.

### Monitoring

Mendix Cloud provides built-in monitoring:

- **Trends** -- CPU, memory, DB connections, request count, response time.
- **Alerts** -- Configurable thresholds for CPU, memory, and critical log messages.
- **Logs** -- Runtime logs accessible through Developer Portal or via the Log API.
- **Application Health** -- Built-in health check endpoint at `/healthcheck`.
- **Integration with APM tools** -- Datadog, Dynatrace, and New Relic via Mendix-supported extensions.

---

## 3. Docker Deployment

Mendix provides an official Docker buildpack that packages your `.mda` file into a runnable container image.

### Official Docker Buildpack

Repository: `https://github.com/mendix/docker-mendix-buildpack`

```bash
# Clone the buildpack
git clone https://github.com/mendix/docker-mendix-buildpack.git
cd docker-mendix-buildpack

# Copy your MDA into the project directory
cp /path/to/your-app.mda project/

# Build the image
docker build \
  --build-arg BUILD_PATH=project \
  -t my-mendix-app:1.0.0 .
```

### Docker Compose for Local / Staging

```yaml
version: "3.8"

services:
  mendix-app:
    build:
      context: ./docker-mendix-buildpack
      args:
        BUILD_PATH: project
    ports:
      - "8080:8080"
    environment:
      ADMIN_PASSWORD: "${ADMIN_PASSWORD:-Admin1!}"
      DATABASE_ENDPOINT: "postgres://mendix:mendix@db:5432/mendix"
      MXRUNTIME_DatabaseType: POSTGRESQL
      MXRUNTIME_MyFirstModule.ApiKey: "${API_KEY}"
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: mendix
      POSTGRES_USER: mendix
      POSTGRES_PASSWORD: mendix
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U mendix"]
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  pgdata:
```

### Key Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `DATABASE_ENDPOINT` | Full JDBC-style connection string | `postgres://user:pass@host:5432/db` |
| `ADMIN_PASSWORD` | MxAdmin password | `Admin1!` |
| `MXRUNTIME_DatabaseType` | DB engine | `POSTGRESQL`, `SQLSERVER` |
| `MXRUNTIME_*` | Any Mendix runtime setting | `MXRUNTIME_com.mendix.storage.s3.AccessKeyId` |
| `S3_ACCESS_KEY_ID` | S3-compatible file storage access key | `minioaccess` |
| `S3_SECRET_ACCESS_KEY` | S3-compatible file storage secret | `miniosecret` |
| `S3_BUCKET_NAME` | Bucket for file documents | `mendix-files` |
| `S3_ENDPOINT` | Custom S3 endpoint (MinIO, etc.) | `http://minio:9000` |

### File Storage in Docker

Mendix stores `FileDocument` entities externally. Use S3/MinIO (preferred -- set `S3_*` env vars), Azure Blob Storage (`MXRUNTIME_com.mendix.storage.azure.*`), or a local volume mount to `/opt/mendix/data/files/` (simple but not scalable).

---

## 4. Kubernetes Deployment

### Mendix for Private Cloud (Managed Operator)

Mendix for Private Cloud installs a Kubernetes Operator that manages Mendix app lifecycles. This is the officially supported path for K8s deployments.

**Installation steps:**

1. Register your cluster in the Mendix Developer Portal under `Apps > Environments > Private Cloud`.
2. Install the Mendix Operator using the provided `kubectl` manifest or Helm chart.
3. Configure a namespace for your environments.
4. Deploy through the Developer Portal -- the operator handles pod creation, DB provisioning, and file storage.

The operator manages runtime pod lifecycle, database/file storage provisioning, ingress configuration, and health checks.

### Helm Chart (Self-Managed)

For teams that want full control without the Mendix Operator:

```yaml
# values.yaml
replicaCount: 2

image:
  repository: registry.example.com/mendix-app
  tag: "1.0.0"
  pullPolicy: IfNotPresent

resources:
  requests:
    memory: "1Gi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "1000m"

env:
  - name: DATABASE_ENDPOINT
    valueFrom:
      secretKeyRef:
        name: mendix-db-secret
        key: endpoint
  - name: ADMIN_PASSWORD
    valueFrom:
      secretKeyRef:
        name: mendix-admin-secret
        key: password

livenessProbe:
  httpGet:
    path: /healthcheck
    port: 8080
  initialDelaySeconds: 60
  periodSeconds: 15

readinessProbe:
  httpGet:
    path: /healthcheck
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

ingress:
  enabled: true
  hosts:
    - host: app.example.com
      paths:
        - path: /
          pathType: Prefix
```

### Resource Sizing Guidelines

| App Complexity | Requests (CPU/Mem) | Limits (CPU/Mem) | Notes |
|---------------|-------------------|-----------------|-------|
| Simple (< 20 entities) | 250m / 512Mi | 500m / 1Gi | Dev/test environments |
| Medium (20-100 entities) | 500m / 1Gi | 1000m / 2Gi | Standard production |
| Complex (100+ entities) | 1000m / 2Gi | 2000m / 4Gi | Heavy integrations, large user base |

### Horizontal Pod Autoscaling

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mendix-app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mendix-app
  minReplicas: 2
  maxReplicas: 8
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 60
    scaleDown:
      stabilizationWindowSeconds: 300
```

**Important considerations for horizontal scaling:**

- Mendix runtime supports clustering -- enable it with `MXRUNTIME_com.mendix.core.SessionIdCookieName` and shared session storage.
- Use sticky sessions (session affinity) on the ingress if you do not configure shared session storage.
- All replicas must point to the same database and file storage backend.

---

## 5. Cloud Foundry

### Overview

Cloud Foundry is the original target platform for Mendix's cloud-native deployments. SAP BTP, Pivotal (Tanzu), and IBM Cloud all run CF under the hood.

### Mendix CF Buildpack

Mendix maintains an official CF buildpack: `https://github.com/mendix/cf-mendix-buildpack`

```bash
# Push with the Mendix buildpack
cf push my-mendix-app \
  -b https://github.com/mendix/cf-mendix-buildpack.git \
  -p your-app.mda \
  -m 1G \
  -k 1G
```

### Manifest File

```yaml
# manifest.yml
applications:
  - name: my-mendix-app
    memory: 1G
    disk_quota: 1G
    instances: 2
    buildpacks:
      - https://github.com/mendix/cf-mendix-buildpack.git#v5.0.0
    path: your-app.mda
    env:
      ADMIN_PASSWORD: ((admin-password))
      DEVELOPMENT_MODE: "false"
      FORCE_WRITE_ARTIFACTS: "true"
      S3_ACCESS_KEY_ID: ((s3-access-key))
      S3_SECRET_ACCESS_KEY: ((s3-secret-key))
      S3_BUCKET_NAME: mendix-files
    services:
      - mendix-db       # bound PostgreSQL service
      - mendix-s3       # bound S3-compatible service
    routes:
      - route: my-mendix-app.cfapps.example.com
```

### Binding Services

CF uses service bindings to inject connection details automatically:

```bash
# Create and bind a PostgreSQL service
cf create-service postgresql small mendix-db
cf bind-service my-mendix-app mendix-db

# Create and bind an S3 service
cf create-service s3 standard mendix-s3
cf bind-service my-mendix-app mendix-s3

# Restage to pick up bindings
cf restage my-mendix-app
```

### SAP BTP Specifics

On SAP BTP, use the `postgresql-db` service and SAP Object Store. Configure `xs-security.json` for XSUAA integration and use MTA descriptors for multi-module deployments.

---

## 6. On-Premise Deployment

### Prerequisites

| Component | Minimum Requirement |
|-----------|-------------------|
| Java | JRE 11 or 17 (match your Mendix version) |
| Database | PostgreSQL 12+, SQL Server 2019+, or Oracle 19c+ |
| OS | Windows Server 2019+ or Linux (RHEL 8+, Ubuntu 20.04+) |
| Disk | 10 GB + projected file storage |
| Memory | 2 GB minimum, 4 GB recommended per app instance |

### Windows Service Installation

1. **Extract the Mendix runtime** to a directory (e.g., `C:\Mendix\runtime\`).
2. **Place your `.mda`** in the deployment directory (e.g., `C:\Mendix\app\`).
3. **Configure `m2ee.yaml`** (see below).
4. **Install as a Windows service** using the Mendix Service Console or `sc.exe`.

Using the Mendix Service Console (from Marketplace): add a new app, point to the `.mda` and runtime directory, configure database/admin/constants, and start -- it registers as a Windows service automatically.

### Linux systemd Setup

Create a systemd unit file:

```ini
# /etc/systemd/system/mendix-app.service
[Unit]
Description=Mendix Application
After=network.target postgresql.service

[Service]
Type=simple
User=mendix
Group=mendix
WorkingDirectory=/opt/mendix/app
ExecStart=/usr/bin/m2ee start
ExecStop=/usr/bin/m2ee stop
Restart=on-failure
RestartSec=10
Environment=M2EE_CONF=/opt/mendix/app/m2ee.yaml

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable mendix-app
sudo systemctl start mendix-app

# Check status
sudo systemctl status mendix-app
journalctl -u mendix-app -f
```

### m2ee-tools Configuration

`m2ee-tools` is the official CLI for managing Mendix runtimes on Linux.

```yaml
# /opt/mendix/app/m2ee.yaml
mxnode:
  mxjar_repo: /opt/mendix/runtime/

m2ee:
  app_name: my-mendix-app
  app_base: /opt/mendix/app/
  runtime_port: 8080
  admin_port: 8090
  admin_pass: changeme

mxruntime:
  DatabaseType: POSTGRESQL
  DatabaseHost: localhost:5432
  DatabaseName: mendix_prod
  DatabaseUserName: mendix
  DatabasePassword: secretpassword
  MicroflowConstants:
    MyModule.ApiEndpoint: "https://api.example.com"
    MyModule.EnableFeatureX: "true"
```

**Common m2ee commands:**

| Command | Purpose |
|---------|---------|
| `m2ee start` | Start the runtime |
| `m2ee stop` | Graceful shutdown |
| `m2ee restart` | Stop then start |
| `m2ee status` | Show runtime status |
| `m2ee update` | Deploy a new `.mda` |
| `m2ee log` | Tail runtime logs |
| `m2ee create_admin_user` | Create or reset MxAdmin |
| `m2ee show_license_information` | Display current license |

---

## 7. Environment Configuration

### Constants Per Environment

Mendix constants are defined in Studio Pro with default values. Override them per environment:

| Method | Where | Format |
|--------|-------|--------|
| Developer Portal | Mendix Cloud > Environment Details > Constants | UI form |
| Environment variable | Docker, K8s, CF | `MX_ModuleName_ConstantName=value` |
| m2ee.yaml | On-premise | Under `mxruntime.MicroflowConstants` |
| Runtime settings | Any platform | `MXRUNTIME_ModuleName.ConstantName=value` |

**Naming convention for environment variables:**

```
MX_<ModuleName>_<ConstantName>

# Examples:
MX_MyModule_ApiEndpoint=https://api.example.com
MX_MyModule_MaxRetries=3
MX_MyModule_EnableDebugMode=false
```

Dots in constant names become underscores. `MX_` prefix is Docker buildpack-specific; for raw runtime settings use `MXRUNTIME_<ModuleName>.<ConstantName>`.

### Scheduled Events Per Environment

Control which scheduled events run in each environment:

| Environment | Recommendation |
|-------------|---------------|
| Development | Disable all scheduled events (run manually for testing) |
| Test | Enable selectively -- only events relevant to test scenarios |
| Acceptance | Enable all -- mirror production behavior |
| Production | Enable all |

**Configuration methods:**

- **Mendix Cloud** -- Toggle each event in Developer Portal > Environment Details > Scheduled Events.
- **Docker/K8s** -- `SCHEDULED_EVENTS=MyModule.DailyCleanup,MyModule.HourlySync` (comma-separated list of enabled events) or `SCHEDULED_EVENTS=ALL` / `SCHEDULED_EVENTS=NONE`.
- **m2ee.yaml** -- Under `mxruntime.ScheduledEventExecution: SPECIFIED` and `MyScheduledEvents: [...]`.

### Custom Runtime Settings

Common runtime settings to tune per environment:

| Setting | Purpose | Dev Value | Prod Value |
|---------|---------|-----------|------------|
| `LogMinDurationQuery` | Log slow queries (ms) | `1000` | `5000` |
| `EnableKeepAlive` | HTTP keep-alive | `true` | `true` |
| `MaxLogMessageLength` | Truncate log messages | `10000` | `10000` |
| `TrackWebServiceUserLastLogin` | Track web service user logins | `false` | `true` |
| `com.mendix.core.SessionTimeout` | Session timeout (ms) | `1800000` | `600000` |
| `com.mendix.storage.PerformDeleteFromStorage` | Delete files on entity delete | `true` | `true` |
| `http.client.MaxConnectionsPerRoute` | Max outbound connections per host | `10` | `50` |
| `http.client.MaxConnectionsTotal` | Max total outbound connections | `50` | `200` |

---

## 8. Database Management Across Environments

### Separate Databases Per Environment

**Never share a database between environments.** Each environment must have its own database instance.

| Environment | Database Name Convention | Purpose |
|-------------|------------------------|---------|
| Development | `mendix_dev` | Local development, rapid iteration |
| Test | `mendix_test` | Automated test runs, disposable data |
| Acceptance | `mendix_acc` | UAT, realistic data (anonymized from prod) |
| Production | `mendix_prod` | Live data |

### Connection String Configuration

**PostgreSQL format:**

```
postgres://username:password@hostname:5432/database_name

# With SSL:
postgres://username:password@hostname:5432/database_name?sslmode=require

# Docker buildpack environment variable:
DATABASE_ENDPOINT=postgres://mendix:secretpass@db-host:5432/mendix_prod
```

**SQL Server format:**

```
# m2ee.yaml style:
DatabaseType: SQLSERVER
DatabaseHost: sqlserver-host:1433
DatabaseName: mendix_prod
DatabaseUserName: mendix_user
DatabasePassword: secretpass
```

### Migration Handling

Mendix handles schema migrations automatically on startup (comparing domain model to DB schema). Key points:

- **Schema sync** adds columns, tables, and indexes automatically.
- **Destructive changes** (removing entities/attributes) are blocked in production unless explicitly approved.
- **Data migrations** -- Use `ASu_AfterStartup` microflows for programmatic data transforms.
- **Best practices** -- Never rename entities (delete and recreate instead). Test schema changes on a prod data copy. Always back up before deployment.

---

## 9. Deployment Pipelines

### Automating MDA/MPA Creation

Use `mxbuild` (the Mendix CLI build tool) to create deployment packages without Studio Pro:

```bash
# Build an MDA from an MPR
mono /opt/mendix/modeler/mxbuild.exe \
  --target=package \
  --java-home=/usr/lib/jvm/java-11 \
  --java-exe-path=/usr/lib/jvm/java-11/bin/java \
  --output=/build/output/my-app.mda \
  /source/my-app.mpr
```

For Mendix 10+, `mxbuild` is available as a container image:

```bash
docker run --rm \
  -v $(pwd)/source:/source \
  -v $(pwd)/output:/output \
  mendix/mxbuild:10.0 \
  --target=package \
  --output=/output/my-app.mda \
  /source/my-app.mpr
```

### CI/CD Integration

**GitLab CI example:**

```yaml
stages:
  - build
  - test
  - deploy

build-mda:
  stage: build
  image: mendix/mxbuild:10.0
  script:
    - mxbuild --target=package --output=app.mda app.mpr
  artifacts:
    paths:
      - app.mda

unit-tests:
  stage: test
  image: mendix/mxbuild:10.0
  script:
    - mxbuild --target=deploy --output=deployment app.mpr
    - m2ee start --wait-for-startup
    - curl -f http://localhost:8080/unittest/

deploy-acceptance:
  stage: deploy
  script:
    - >
      curl -X POST
      "https://deploy.mendix.com/api/v2/apps/${APP_ID}/packages"
      -H "Mendix-ApiKey: ${MENDIX_API_KEY}"
      -F "file=@app.mda"
    - >
      curl -X POST
      "https://deploy.mendix.com/api/v2/apps/${APP_ID}/environments/acceptance/deploy"
      -H "Mendix-ApiKey: ${MENDIX_API_KEY}"
      -d '{"PackageId":"latest"}'
  only:
    - main
```

The same pattern applies to GitHub Actions, Azure DevOps, or any CI system -- the core steps are: build MDA via `mxbuild`, build Docker image, push to registry, deploy to target.

### Blue/Green Deployments

Blue/green eliminates downtime by running two identical environments and switching traffic. Deploy the new version to the inactive environment, run smoke tests, then switch the router/ingress. Keep the old environment running as a fast rollback target.

**Kubernetes implementation:**

```bash
# Deploy new version as green
kubectl apply -f deployment-green.yaml

# Wait for readiness
kubectl rollout status deployment/mendix-app-green

# Switch service selector
kubectl patch service mendix-app \
  -p '{"spec":{"selector":{"version":"green"}}}'

# Rollback if needed
kubectl patch service mendix-app \
  -p '{"spec":{"selector":{"version":"blue"}}}'
```

### Canary Releases

Route a small percentage of traffic to the new version before full rollout:

- **Nginx Ingress** -- Use canary annotations to split traffic by weight.
- **Istio** -- Use `VirtualService` with weighted routing (e.g., 90/10 split between stable and canary).
- **Cloud Foundry** -- Use route mapping with multiple app instances at different ratios.

---

## 10. Rollback Strategies

### Database Rollback Considerations

Mendix applies forward-only schema migrations on startup. This has critical implications for rollback:

| Scenario | Rollback Feasibility | Action |
|----------|---------------------|--------|
| New columns/tables added | Safe to roll back app | Extra columns are ignored by the older runtime |
| Columns/tables removed | **Dangerous** | Data is lost -- restore from backup |
| Data type changed | **Dangerous** | May corrupt data -- restore from backup |
| Data migration microflow ran | Case-by-case | May need a reverse migration microflow |
| No schema changes | Safe | Just redeploy the previous version |

**Rule of thumb:** If the new version only added entities/attributes (no deletions or type changes), you can safely roll back the application without touching the database. The old runtime ignores the extra columns.

### Version Pinning

Always tag your deployment packages with identifiable versions:

```bash
# Tag Docker images with both version and git SHA
docker tag mendix-app:latest myregistry/mendix-app:1.2.3
docker tag mendix-app:latest myregistry/mendix-app:1.2.3-abc1234

# Keep the last N versions in your registry
# (configure retention policies in your container registry)
```

For Mendix Cloud, keep previous deployment packages in the Developer Portal. Do not delete old packages until you are confident the current version is stable.

### Snapshot-Based Recovery

- **PostgreSQL** -- `pg_dump -Fc mendix_prod > backup.dump` before deployment; restore with `pg_restore -d mendix_prod --clean backup.dump`.
- **Mendix Cloud** -- Automatic nightly backups. Create manual snapshots via Developer Portal > Backups. Restore replaces both database and file storage.
- **S3/MinIO** -- Enable bucket versioning. Roll back by restoring previous object versions.
- **Local file storage** -- Include the files directory in your backup routine.

### Rollback Checklist

1. Confirm whether the new version made destructive database changes.
2. If destructive: restore the database from a pre-deployment snapshot.
3. If non-destructive: skip database restore.
4. Redeploy the previous application version (MDA or Docker image).
5. Verify the application starts and passes health checks.
6. Restore file storage if the new version modified or deleted files.
7. Notify stakeholders and document the rollback in your incident log.

---

## 11. Multi-Environment Strategy

### Recommended Topology

`DEV --> TST --> ACC --> PRD` -- each with its own database, file storage, and logging configuration. Scheduled events off in DEV, selective in TST, all on in ACC/PRD. Logging at DEBUG in DEV, INFO in TST/ACC, WARN in PRD.

### Environment Characteristics

| Aspect | Development | Test | Acceptance | Production |
|--------|------------|------|------------|------------|
| **Purpose** | Build, debug | Automated tests, integration | UAT, demo | Live traffic |
| **Data** | Synthetic | Synthetic/seeded | Anonymized prod copy | Real |
| **Deploy frequency** | On every save | On every commit | On release candidate | On approved release |
| **Who deploys** | Developer | CI pipeline | CI pipeline + approval | CI pipeline + approval gate |
| **Logging level** | DEBUG/TRACE | INFO | INFO | WARN/ERROR |
| **Scheduled events** | Disabled | Selective | All enabled | All enabled |
| **Monitoring** | None | Basic | Alerts enabled | Full APM, alerts, dashboards |
| **Access** | Developer only | Dev team | Stakeholders, QA | End users |

### Data Management Across Environments

**Seeding test data:** Use the `DataImporter` module or after-startup microflows. Maintain test data exports (JSON/XML) in version control. For acceptance, periodically copy and anonymize production data.

**Data anonymization:** Snapshot production, restore to acceptance, run an anonymization microflow (or use `postgresql_anonymizer`) to replace PII with synthetic data.

**Never:** share databases between environments, use production credentials in non-production, copy production data without anonymization, or give developers direct production database access.

### Branch-Based Environments

For teams practicing GitFlow or trunk-based development:

| Branch | Environment | Lifecycle |
|--------|------------|-----------|
| `main` / `trunk` | Production | Permanent |
| `release/*` | Acceptance | Per release cycle |
| `develop` | Test | Permanent |
| `feature/*` | Development (local) | Ephemeral |

---

## 12. Secrets Management

### Environment Variable Injection

The simplest approach -- store secrets as environment variables, injected at runtime:

**Docker:**

```bash
# Use a .env file (never commit to version control)
docker run --env-file .env my-mendix-app

# Or pass individually
docker run \
  -e DATABASE_ENDPOINT="postgres://user:pass@host:5432/db" \
  -e MX_MyModule_ApiKey="secret-key" \
  my-mendix-app
```

**Kubernetes:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mendix-secrets
type: Opaque
stringData:
  database-endpoint: "postgres://user:pass@host:5432/db"
  api-key: "secret-key"
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: mendix-app
          envFrom:
            - secretRef:
                name: mendix-secrets
```

### HashiCorp Vault Integration

For organizations using Vault:

**Method 1: Vault Agent Sidecar (Kubernetes)**

```yaml
# Pod annotations for Vault Agent injector
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "mendix-app"
    vault.hashicorp.com/agent-inject-secret-db: "secret/data/mendix/database"
    vault.hashicorp.com/agent-inject-template-db: |
      {{- with secret "secret/data/mendix/database" -}}
      export DATABASE_ENDPOINT="{{ .Data.data.endpoint }}"
      {{- end }}
```

**Method 2: Init container** -- Run a Vault CLI init container that fetches secrets and writes them to a shared volume before the Mendix container starts.

### AWS Secrets Manager

```bash
# Store a secret
aws secretsmanager create-secret \
  --name mendix/production/database \
  --secret-string '{"endpoint":"postgres://user:pass@host:5432/db"}'

# Retrieve in a deployment script
DB_ENDPOINT=$(aws secretsmanager get-secret-value \
  --secret-id mendix/production/database \
  --query 'SecretString' --output text | jq -r '.endpoint')
```

**In Kubernetes, use External Secrets Operator:**

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: mendix-db-secret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: mendix-db-secret
  data:
    - secretKey: database-endpoint
      remoteRef:
        key: mendix/production/database
        property: endpoint
```

### Azure Key Vault

For Azure-hosted deployments, use the Azure Key Vault CSI driver (`SecretProviderClass` with `provider: azure`). Mount secrets as volumes or sync them to Kubernetes secrets. The pattern is the same as AWS -- define a `SecretProviderClass` referencing your Key Vault name and object names.

### Secrets Management Checklist

| Practice | Status |
|----------|--------|
| No secrets in source control (`.mpr`, `.yaml`, `.env` committed) | Required |
| `.env` files listed in `.gitignore` | Required |
| Secrets rotated on a schedule (90 days recommended) | Recommended |
| Separate secrets per environment | Required |
| Audit log for secret access | Recommended |
| Secrets encrypted at rest | Required |
| Least-privilege access to secret stores | Required |
| Break-glass procedure documented for secret store outage | Recommended |

---

## Quick Reference

### Deployment Method Decision Tree

1. Need data sovereignty or air-gapped deployment? -- On-Premise (Section 6) or Private Cloud (Section 4).
2. Already on Cloud Foundry (SAP BTP, Tanzu)? -- Cloud Foundry (Section 5).
3. Need horizontal scaling or custom infrastructure? -- Kubernetes (Section 4) or Docker (Section 3).
4. None of the above? -- Mendix Cloud (Section 2).

---

## References

- [Mendix Documentation -- Deployment](https://docs.mendix.com/developerportal/deploy/)
- [Mendix Docker Buildpack](https://github.com/mendix/docker-mendix-buildpack)
- [Mendix CF Buildpack](https://github.com/mendix/cf-mendix-buildpack)
- [Mendix for Private Cloud](https://docs.mendix.com/developerportal/deploy/private-cloud/)
- [Mendix Deploy API](https://docs.mendix.com/apidocs-mxsdk/apidocs/deploy-api-4/)
- [m2ee-tools](https://github.com/mendix/m2ee-tools)
- [Mendix Runtime Settings](https://docs.mendix.com/refguide/custom-settings/)

---

<div align="center">

**[Back to Home](../README.md)**

</div>
