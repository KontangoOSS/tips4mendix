# CI/CD for Mendix Applications

## A Comprehensive Guide for Mendix Developers

**Version:** 1.0
**Date:** February 2026
**Classification:** Public

---

## Table of Contents

1. [CI/CD Overview for Mendix](#1-cicd-overview-for-mendix)
   - [Why CI/CD Matters for Low-Code](#why-cicd-matters-for-low-code)
   - [Unique Challenges with Mendix](#unique-challenges-with-mendix)
   - [CI/CD Maturity Model](#cicd-maturity-model)
2. [Mendix Platform APIs](#2-mendix-platform-apis)
   - [Build API](#build-api)
   - [Deploy API](#deploy-api)
   - [Team Server API](#team-server-api)
   - [App Repository API](#app-repository-api)
   - [Authentication](#authentication)
3. [Version Control with Team Server](#3-version-control-with-team-server)
   - [Git Support in Mendix 10+](#git-support-in-mendix-10)
   - [Branching Strategies](#branching-strategies)
   - [Managing Merge Conflicts](#managing-merge-conflicts)
4. [Build Automation](#4-build-automation)
   - [Triggering Builds via API](#triggering-builds-via-api)
   - [Deployment Packages](#deployment-packages)
   - [Build-and-Poll Script](#build-and-poll-script)
5. [Testing Strategies](#5-testing-strategies)
   - [Unit Testing with MUnit](#unit-testing-with-munit)
   - [ATS and UI Testing](#ats-and-ui-testing)
   - [Integration and Smoke Tests](#integration-and-smoke-tests)
   - [Test Data Management](#test-data-management)
6. [Quality Gates](#6-quality-gates)
   - [Code Review in Studio Pro](#code-review-in-studio-pro)
   - [Static Analysis and Consistency Checks](#static-analysis-and-consistency-checks)
   - [Security Scanning](#security-scanning)
7. [Deployment Automation](#7-deployment-automation)
   - [Using the Deploy API](#using-the-deploy-api)
   - [Transport Between Environments](#transport-between-environments)
   - [Automated Rollbacks](#automated-rollbacks)
8. [Pipeline Examples](#8-pipeline-examples)
   - [GitHub Actions](#github-actions)
   - [GitLab CI](#gitlab-ci)
   - [Azure DevOps](#azure-devops)
   - [Jenkins](#jenkins)
9. [Environment Management](#9-environment-management)
   - [Constants per Environment](#constants-per-environment)
   - [Scheduled Events](#scheduled-events)
   - [Runtime Settings](#runtime-settings)
10. [Monitoring and Feedback Loops](#10-monitoring-and-feedback-loops)
    - [APM Integration](#apm-integration)
    - [Alerting and Rollback Triggers](#alerting-and-rollback-triggers)
11. [Best Practices](#11-best-practices)
    - [Trunk-Based vs. Feature Branches](#trunk-based-vs-feature-branches)
    - [Release Management](#release-management)
    - [Hotfix Workflows](#hotfix-workflows)

---

## 1. CI/CD Overview for Mendix

### Why CI/CD Matters for Low-Code

Low-code does not mean low-discipline. Mendix apps grow fast -- multiple developers, Java actions, marketplace modules, and integrations compound risk when deploying manually. CI/CD gives you:

- **Repeatable builds** -- eliminate "it works on my machine" by building from Team Server every time
- **Faster feedback** -- catch broken models, failing tests, and security issues before production
- **Audit trail** -- every deployment traces back to a revision, build, and approval
- **Reduced downtime** -- automated rollbacks and health checks shorten recovery
- **Developer confidence** -- teams ship more frequently when deployments are boring

### Unique Challenges with Mendix

| Challenge | Why It Matters |
|-----------|---------------|
| **Binary model format** | `.mpr` files cannot be diffed line-by-line; merge conflicts require Studio Pro |
| **Team Server coupling** | Version control is tied to the Mendix ecosystem |
| **Build server dependency** | Builds require Mendix Build API or `mxbuild` with a licensed toolchain |
| **Marketplace modules** | Third-party modules update independently; version pinning is manual |
| **Environment config** | Constants, scheduled events, runtime settings vary per environment |
| **Model consistency** | A green build does not guarantee a working model |

### CI/CD Maturity Model

| Level | Description | Practices |
|-------|-------------|-----------|
| **0 -- Manual** | Build/deploy through Studio Pro or portal | No automation |
| **1 -- Scripted** | API-triggered builds, manual deploy | Build API calls in scripts |
| **2 -- Automated** | Build + deploy via pipeline | Deploy API, config as code |
| **3 -- Gated** | Tests and checks block bad deploys | MUnit, ATS, static analysis |
| **4 -- Full CI/CD** | Auto-deploy to acceptance, one-click prod | Feature toggles, auto-rollback |

---

## 2. Mendix Platform APIs

All CI/CD automation for Mendix Cloud flows through these APIs. For private cloud / on-premise, use `mxbuild` and your own orchestration.

### Build API

**Base URL:** `https://deploy.mendix.com/api/1/apps/<AppId>/packages/`

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/packages/` | POST | Start a new build |
| `/packages/<PackageId>` | GET | Check build status |
| `/packages/` | GET | List all packages |
| `/packages/<PackageId>` | DELETE | Remove a package |

```bash
# Start a build -- POST with Branch, Revision, Version in body
curl -s -X POST ".../apps/${APP_ID}/packages/" \
  -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"Branch\":\"main\",\"Revision\":\"${REV}\",\"Version\":\"1.2.3\"}"

# Poll status -- returns Succeeded, Building, Failed, or Queued
curl -s ".../apps/${APP_ID}/packages/${PKG_ID}" \
  -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}"
```

### Deploy API

**Base URL:** `https://deploy.mendix.com/api/1/apps/<AppId>/environments/`

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/environments/<Mode>` | GET | Get environment status |
| `/environments/<Mode>/transport` | POST | Deploy a package |
| `/environments/<Mode>/stop` | POST | Stop environment |
| `/environments/<Mode>/start` | POST | Start environment |
| `/environments/<Mode>/clean` | POST | Clean environment (removes DB) |

`Mode` values: `Test`, `Acceptance`, `Production`

```bash
curl -s -X POST ".../apps/${APP_ID}/environments/${ENV}/transport" \
  -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" \
  -H "Content-Type: application/json" -d "{\"PackageId\":\"${PACKAGE_ID}\"}"
```

### Team Server API

**Base URL:** `https://deploy.mendix.com/api/1/apps/<AppId>/`

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/branches/` | GET | List branches |
| `/branches/<Name>/revisions/` | GET | List revisions on a branch |
| `/branches/<Name>/revisions/<Number>` | GET | Get a specific revision |

### App Repository API

**Base URL:** `https://repository.api.mendix.com/v1/` (Git-based Team Server, Mendix 10+)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/repositories/<RepoId>/branches` | GET | List Git branches |
| `/repositories/<RepoId>/branches/<Name>/commits` | GET | List commits |
| `/repositories/<RepoId>/branches/<Name>/commits/<SHA>` | GET | Commit details |

### Authentication

All Mendix Platform APIs use the same headers:

| Header | Value | Source |
|--------|-------|--------|
| `Mendix-Username` | Account email | Mendix portal profile |
| `Mendix-ApiKey` | Personal or service API key | Portal > Settings > API Keys |

**Best practices:**

- Create a dedicated **service account** for CI/CD (not a real person)
- Grant only the required roles (e.g., Transport but not Production deploy)
- Store credentials as encrypted secrets -- never in version control
- Rotate keys quarterly; use separate keys per pipeline/environment

---

## 3. Version Control with Team Server

### Git Support in Mendix 10+

| Aspect | SVN (Mendix 9-) | Git (Mendix 10+) |
|--------|-----------------|-------------------|
| Revision IDs | Sequential numbers | SHA hashes |
| Branching | Centralized | Distributed, local branches |
| Merge model | Lock-based for `.mpr` | Three-way merge in Studio Pro |
| API | Team Server API | App Repository API |
| External Git access | Not supported | Possible via Mendix Git credentials |

Even with Git, you interact with Team Server through Studio Pro for model changes. You cannot edit `.mpr` files in a text editor.

### Branching Strategies

**Recommended: trunk-based with short-lived feature branches**

```
main (trunk)
  ├── feature/ticket-123    (< 2 days, merged via Studio Pro)
  ├── feature/ticket-456    (< 2 days, merged via Studio Pro)
  └── release/1.2.x         (cut when stabilizing for production)
```

| Strategy | When to Use | Trade-offs |
|----------|-------------|------------|
| **Trunk-based** | Small teams (1-4 devs) | Requires discipline; broken trunk blocks everyone |
| **Feature branches** | Larger teams | Merge conflicts grow with branch lifetime |
| **Release branches** | Regulatory environments | Maintenance overhead for backports |
| **GitFlow** | Not recommended for Mendix | Too many long-lived branches; Studio Pro merges are expensive |

**Rules of thumb:**

- **2-day maximum** branch lifetime -- Mendix model conflicts grow exponentially
- Merge `main` into your branch daily before pushing
- Avoid parallel edits to the same page, microflow, or domain model
- Coordinate ownership per module each sprint

### Managing Merge Conflicts

When Studio Pro detects conflicts:

1. **Document-level** -- shows which pages, microflows, entities conflict
2. **Choose theirs or mine** -- per conflicting document (no line-level merge)
3. **Manual reconciliation** -- re-apply lost changes from the other branch

**Prevention:** split work by module, commit multiple times per day, maintain a "who owns what" list.

---

## 4. Build Automation

### Triggering Builds via API

**Flow:** get latest revision (Team Server API) -> trigger build (Build API POST) -> poll every 30s (Build API GET) -> retrieve package ID -> deploy.

```bash
# SVN-based: get latest revision number
LATEST=$(curl -sf ".../apps/${APP_ID}/branches/main/revisions/" \
  -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" | jq -r '.[0].Number')

# Git-based (Mendix 10+): get latest commit SHA
LATEST_SHA=$(curl -sf "https://repository.api.mendix.com/v1/repositories/${REPO_ID}/branches/main/commits" \
  -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" | jq -r '.items[0].sha')
```

### Deployment Packages

| Type | Extension | Contents | Use Case |
|------|-----------|----------|----------|
| **MDA** | `.mda` | Model + runtime + dependencies | Mendix Cloud |
| **MPA** | `.mpa` | Model only | Private cloud, Docker, K8s |

For private cloud, use `mxbuild`:

```bash
mono /opt/mendix/mxbuild/mxbuild.exe \
  --target=package --output=/build/app.mda \
  --java-home=/usr/lib/jvm/java-11 /project/MyApp.mpr
```

### Build-and-Poll Script

Save as `scripts/mendix-build.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
APP_ID="${1:?Usage: build.sh <app-id> <branch> <version>}"
BRANCH="${2:-main}"; VERSION="${3:-0.0.0}"
API="https://deploy.mendix.com/api/1/apps/${APP_ID}"
H=(-H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}")

REV=$(curl -sf "${API}/branches/${BRANCH}/revisions/" "${H[@]}" | jq -r '.[0].Number')
PKG=$(curl -sf -X POST "${API}/packages/" "${H[@]}" -H "Content-Type: application/json" \
  -d "{\"Branch\":\"${BRANCH}\",\"Revision\":\"${REV}\",\"Version\":\"${VERSION}\"}" | jq -r '.PackageId')

for i in $(seq 1 30); do
  S=$(curl -sf "${API}/packages/${PKG}" "${H[@]}" | jq -r '.Status')
  case "$S" in
    Succeeded) echo "${PKG}"; exit 0 ;;
    Failed) exit 1 ;;
    *) sleep 30 ;;
  esac
done
exit 1
```

---

## 5. Testing Strategies

### Unit Testing with MUnit

1. Install **MUnit** from the Mendix Marketplace
2. Create test microflows prefixed with `Test_` in a `_Tests` module
3. Use assertion activities: `AssertTrue`, `AssertEquals`, `AssertNotNull`

**Example test structure:**

```
Test_CalculateDiscount_Above100_Returns10Percent
├── Create: Order with TotalAmount = 150.00
├── Call: SUB_CalculateDiscount(Order)
├── Assert: Order.DiscountPercentage == 10.0
└── Assert: Order.DiscountAmount == 15.0
```

**Running from CI:**

```bash
curl -sf -X POST "https://${APP_URL}/munit/run" \
  -H "Authorization: Bearer ${MUNIT_TOKEN}"

FAILED=$(curl -sf "https://${APP_URL}/munit/results" \
  -H "Authorization: Bearer ${MUNIT_TOKEN}" | jq '.failedCount')
[ "$FAILED" -gt 0 ] && echo "MUnit: ${FAILED} failed" && exit 1
```

**Best practices:** test business logic (not CRUD wrappers), keep tests independent, use `BeforeSetup`/`AfterTeardown` for data, name as `Test_<Unit>_<Scenario>_<Expected>`.

### ATS and UI Testing

| Tool | Pros | Cons |
|------|------|------|
| **ATS** | Mendix-native, no CSS selectors | Licensed, Mendix Cloud only |
| **Selenium** | Widely supported | Brittle selectors with Mendix widgets |
| **Playwright** | Fast, auto-waits, multi-browser | Careful selector strategy needed |
| **Cypress** | Excellent DX, time-travel debug | Single-tab, same-origin only |

**Selector strategy:** use `mx-name-*` classes (set the `Name` property on widgets in Studio Pro), `data-mendix-id` attributes, and avoid generated DOM structure.

**Triggering ATS from CI:**

```bash
RUN_ID=$(curl -sf -X POST "https://ats.mendix.com/api/v2/runs" \
  -H "Authorization: Bearer ${ATS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"suiteId\":\"${SUITE_ID}\",\"environment\":\"${ENV_URL}\"}" \
  | jq -r '.runId')
```

### Integration and Smoke Tests

| Approach | Tool | When |
|----------|------|------|
| Mock services | WireMock, Mockoon | Isolate from external deps |
| Contract tests | Pact | Verify API contracts |
| Smoke tests | curl + jq | Quick post-deploy validation |
| End-to-end | Postman/Newman | Full integration in test env |

### Test Data Management

- **Seeding:** `_Admin/TestDataSetup` microflow creates known entities
- **Isolation:** each suite creates and deletes its own data
- **Snapshots:** restore DB snapshot before each acceptance run
- **Test mode:** set `Testing.IsTestMode = true` to bypass external calls

---

## 6. Quality Gates

### Code Review in Studio Pro

Mendix models cannot be reviewed through traditional PR diffs.

| Approach | How |
|----------|-----|
| **Branch diff** | `Version Control > Merge Changes` in Studio Pro |
| **Portal review** | Team Server commit history and change summaries |
| **Pair review** | Screen-share the branch diff; walkthrough together |
| **Story mapping** | Map commits to user stories; review acceptance criteria |

**Checklist:** domain model changes, microflow logic and error handling, page data sources, security (access rules on entities/microflows/pages), naming conventions (`ACT_`, `SUB_`, `DS_` prefixes).

### Static Analysis and Consistency Checks

Use the **Mendix Model SDK** (`mendixplatformsdk` npm package) to programmatically inspect `.mpr` models -- load a working copy via API, then iterate over `model.allMicroflows()`, `allEntities()`, etc.

**Common checks:** missing error handlers, unused entities/variables, entities without access rules, hardcoded strings, microflows > 25 activities.

**Consistency checks via mxbuild** (non-zero exit on errors):

```bash
mono /opt/mendix/mxbuild/mxbuild.exe --target=package --output=/dev/null /project/MyApp.mpr
```

### Security Scanning

| Tool | Scans | Integration |
|------|-------|-------------|
| **Mendix AQM** | Model complexity, maintainability | Mendix portal (automatic) |
| **OWASP Dependency-Check** | Java deps in `userlib/` | CLI, CI plugins |
| **Snyk** | Dependencies + container images | CLI, CI plugins |
| **SonarQube** | Java actions in `javasource/` | Scanner CLI |

```bash
dependency-check --scan /project/userlib/ --format JSON \
  --out /reports/dependency-check.json --failOnCVSS 7
```

---

## 7. Deployment Automation

### Using the Deploy API

```
1. Stop environment      →  POST .../environments/<Mode>/stop
2. Transport package     →  POST .../environments/<Mode>/transport
3. Set constants         →  PUT  .../environments/<Mode>/settings
4. Start environment     →  POST .../environments/<Mode>/start
5. Health check          →  GET  <AppURL>/
6. Smoke tests           →  Run minimal test suite
```

### Transport Between Environments

```
Build → Test → Acceptance → Production
         │         │             │
       Auto      Auto      Manual gate
```

| Stage | Trigger | Action |
|-------|---------|--------|
| **Build** | Commit to `main` | Build API creates package |
| **Test** | Build succeeds | Auto-deploy, MUnit + smoke tests |
| **Acceptance** | Tests pass | Auto-deploy, ATS regression |
| **Production** | Manual approval | Deploy API + health checks |

### Automated Rollbacks

Record the current package ID before deploying (GET environment status, extract `ModelVersion`). If health checks fail, redeploy the previous package using the same stop/transport/start flow.

**Rollback considerations:**

- DB migrations are **not reversible** -- schema changes may block package rollback
- Test rollback in acceptance before relying on it in production
- For breaking schema changes, deploy in two phases: add new columns first, migrate data later

---

## 8. Pipeline Examples

### Reusable Deploy Script

All pipelines reference this shared script (`scripts/mendix-deploy.sh`):

```bash
#!/usr/bin/env bash
set -euo pipefail
APP_ID="${1:?}"; ENV="${2:?}"; PKG="${3:?}"
H=(-H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}")
BASE="https://deploy.mendix.com/api/1/apps/${APP_ID}/environments/${ENV}"

curl -sf -X POST "${BASE}/stop" "${H[@]}" || true
sleep 10
curl -sf -X POST "${BASE}/transport" "${H[@]}" \
  -H "Content-Type: application/json" -d "{\"PackageId\":\"${PKG}\"}"
curl -sf -X POST "${BASE}/start" "${H[@]}"
echo "Deployed ${PKG} to ${ENV}"
```

### GitHub Actions

```yaml
name: Mendix CI/CD
on:
  push:
    branches: [main]
env:
  APP_ID: ${{ secrets.MENDIX_APP_ID }}
  MX_USER: ${{ secrets.MENDIX_USERNAME }}
  MX_API_KEY: ${{ secrets.MENDIX_API_KEY }}

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      package_id: ${{ steps.build.outputs.package_id }}
    steps:
      - name: Get latest revision
        id: revision
        run: |
          REV=$(curl -sf \
            "https://deploy.mendix.com/api/1/apps/${APP_ID}/branches/main/revisions/" \
            -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" \
            | jq -r '.[0].Number')
          echo "revision=${REV}" >> "$GITHUB_OUTPUT"
      - name: Trigger build
        id: build
        run: |
          PKG=$(curl -sf -X POST \
            "https://deploy.mendix.com/api/1/apps/${APP_ID}/packages/" \
            -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "{\"Branch\":\"main\",\"Revision\":\"${{ steps.revision.outputs.revision }}\",\"Version\":\"1.0.${{ github.run_number }}\"}" \
            | jq -r '.PackageId')
          echo "package_id=${PKG}" >> "$GITHUB_OUTPUT"
      - name: Wait for build
        run: |
          for i in $(seq 1 30); do
            STATUS=$(curl -sf \
              "https://deploy.mendix.com/api/1/apps/${APP_ID}/packages/${{ steps.build.outputs.package_id }}" \
              -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" \
              | jq -r '.Status')
            [ "$STATUS" = "Succeeded" ] && exit 0
            [ "$STATUS" = "Failed" ] && exit 1
            sleep 30
          done
          exit 1

  deploy-test:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/mendix-deploy.sh "${APP_ID}" Test "${{ needs.build.outputs.package_id }}"
      - name: Health check
        run: |
          sleep 60
          for i in $(seq 1 10); do
            [ "$(curl -sf -o /dev/null -w '%{http_code}' https://${TEST_APP_URL}/)" = "200" ] && exit 0
            sleep 15
          done
          exit 1

  deploy-production:
    needs: [build, deploy-test]
    runs-on: ubuntu-latest
    environment: production  # requires manual approval
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/mendix-deploy.sh "${APP_ID}" Production "${{ needs.build.outputs.package_id }}"
```

### GitLab CI

```yaml
stages: [build, deploy-test, deploy-acceptance, deploy-production]

build:
  stage: build
  image: curlimages/curl:latest
  script:
    - REV=$(curl -sf "https://deploy.mendix.com/api/1/apps/${APP_ID}/branches/main/revisions/"
        -H "Mendix-Username:${MX_USER}" -H "Mendix-ApiKey:${MX_API_KEY}" | jq -r '.[0].Number')
    - PKG=$(curl -sf -X POST "https://deploy.mendix.com/api/1/apps/${APP_ID}/packages/"
        -H "Mendix-Username:${MX_USER}" -H "Mendix-ApiKey:${MX_API_KEY}"
        -H "Content-Type:application/json"
        -d "{\"Branch\":\"main\",\"Revision\":\"${REV}\",\"Version\":\"1.0.${CI_PIPELINE_IID}\"}"
        | jq -r '.PackageId')
    - echo "PACKAGE_ID=${PKG}" >> build.env
    - | # poll
      for i in $(seq 1 30); do
        S=$(curl -sf "https://deploy.mendix.com/api/1/apps/${APP_ID}/packages/${PKG}" \
          -H "Mendix-Username:${MX_USER}" -H "Mendix-ApiKey:${MX_API_KEY}" | jq -r '.Status')
        [ "$S" = "Succeeded" ] && exit 0; [ "$S" = "Failed" ] && exit 1; sleep 30
      done; exit 1
  artifacts:
    reports:
      dotenv: build.env

deploy-test:
  stage: deploy-test
  needs: [build]
  script: ./scripts/mendix-deploy.sh "${APP_ID}" Test "${PACKAGE_ID}"

deploy-acceptance:
  stage: deploy-acceptance
  needs: [deploy-test]
  script: ./scripts/mendix-deploy.sh "${APP_ID}" Acceptance "${PACKAGE_ID}"

deploy-production:
  stage: deploy-production
  needs: [deploy-acceptance]
  when: manual
  script: ./scripts/mendix-deploy.sh "${APP_ID}" Production "${PACKAGE_ID}"
```

### Azure DevOps

Same curl pattern as GitHub Actions. Key Azure DevOps specifics:

- **Variables:** `$(MENDIX_APP_ID)` syntax, store in variable groups
- **Output variables:** `echo "##vso[task.setvariable variable=pkgId;isOutput=true]${PKG}"`
- **Approval gates:** configure on the `Production` environment in Pipelines > Environments
- **Deployment jobs:** `deployment:` with `strategy: runOnce:` for environment tracking
- Use `Bash@3` tasks calling `./scripts/mendix-deploy.sh` per stage

### Jenkins

Key Jenkins-specific patterns:

- **Credentials:** `credentials('mendix-api-key')` in `environment` block
- **Build polling:** `waitUntil(initialRecurrencePeriod: 30000)` inside `timeout(time: 15, unit: 'MINUTES')`
- **Manual gate:** `input { message "Deploy to Production?" }` on the production stage
- **Notifications:** `post { failure { slackSend ... } }`

```groovy
pipeline {
    agent any
    environment {
        APP_ID     = credentials('mendix-app-id')
        MX_USER    = credentials('mendix-username')
        MX_API_KEY = credentials('mendix-api-key')
    }
    stages {
        stage('Build') {
            steps {
                script {
                    // Same curl pattern: get revision, trigger build, poll status
                    env.PACKAGE_ID = buildMendixPackage("main", BUILD_NUMBER)
                }
            }
        }
        stage('Deploy Test')       { steps { sh "./scripts/mendix-deploy.sh ${APP_ID} Test ${PACKAGE_ID}" } }
        stage('Deploy Production') {
            input { message "Deploy to Production?" }
            steps { sh "./scripts/mendix-deploy.sh ${APP_ID} Production ${PACKAGE_ID}" }
        }
    }
    post {
        failure { slackSend channel: '#deploys', message: "FAILED: ${BUILD_URL}" }
        success { slackSend channel: '#deploys', message: "Deployed v1.0.${BUILD_NUMBER}" }
    }
}
```

---

## 9. Environment Management

### Constants per Environment

Store environment configs as JSON files in your repo (`config/test.json`, `config/acceptance.json`, `config/production.json`) with constants and scheduled event settings. Keep secrets in CI variables, not in these files.

**Apply via pipeline:**

```bash
cat "config/${ENV,,}.json" \
  | jq '{Constants: .constants | map({Name: .name, Value: .value})}' \
  | curl -sf -X PUT ".../environments/${ENV}/settings" \
    -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" \
    -H "Content-Type: application/json" -d @-
```

### Scheduled Events

```bash
curl -sf -X PUT ".../environments/${ENV}/settings" \
  -H "Mendix-Username: ${MX_USER}" -H "Mendix-ApiKey: ${MX_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "{\"ScheduledEvents\":[{\"Name\":\"MyModule.SE_DailyReport\",\"Enabled\":true},{\"Name\":\"MyModule.SE_DataSync\",\"Enabled\":false}]}"
```

Disable data sync and notification events in Test/Acceptance to avoid sending real emails or hitting production APIs.

### Runtime Settings

| Setting | Example | Purpose |
|---------|---------|---------|
| `DTAPMode` | `P` | Controls runtime behavior |
| `ScheduledEventExecution` | `SPECIFIED` | Only run explicitly enabled events |
| `LogMinDurationQuery` | `5000` | Log queries slower than 5s |

Set via `PUT .../environments/<Mode>/settings` with a `RuntimeSettings` object in the body.

---

## 10. Monitoring and Feedback Loops

### APM Integration

| Tool | Integration | Monitors |
|------|-------------|----------|
| **Datadog** | Java agent in `userlib/`, env vars | JVM metrics, traces, logs |
| **New Relic** | Java agent, license key env var | Transactions, errors, JVM |
| **Dynatrace** | OneAgent on host/container | Full stack, auto-instrumented |
| **Mendix Metrics** | Built-in (Mendix Cloud) | Runtime stats, DB connections |
| **Prometheus** | `/metrics` endpoint | Custom metrics export |

### Alerting and Rollback Triggers

| Event | Channel | Action |
|-------|---------|--------|
| Build failed | Slack / Teams | Notify dev team |
| Deploy failed | Slack + PagerDuty | Notify on-call, create incident |
| Health check failed | PagerDuty | Page on-call, trigger rollback |
| Tests failed | Slack / email | Block promotion |
| Rollback executed | Slack + tracker | Create post-mortem ticket |

**Automatic rollback criteria:**

| Trigger | Threshold | Action |
|---------|-----------|--------|
| Health check failure | 3 consecutive post-deploy | Redeploy previous package |
| Error rate spike | > 5% 5xx in first 10 min | Alert + manual rollback |
| Memory/CPU anomaly | > 90% for 5 min post-deploy | Alert + investigate |
| Response time | p95 > 2x baseline | Alert + investigate |

**Health check pattern:** loop up to N attempts, curl the app URL for HTTP 200, sleep 15s between attempts, exit 1 on exhaustion. Include this in a shared `scripts/healthcheck.sh`.

---

## 11. Best Practices

### Trunk-Based vs. Feature Branches

| Factor | Trunk-Based | Feature Branches |
|--------|-------------|------------------|
| **Team size** | 1-4 devs | 4+ devs |
| **Merge frequency** | Multiple times/day | Every 1-2 days |
| **Conflict risk** | Low | Grows with branch age |
| **CI complexity** | Simple | Per-branch builds |
| **Feature isolation** | Feature toggles | Natural isolation |
| **Mendix fit** | Most teams | With strict 2-day max lifetime |

**Trunk-based rules:**

1. Commit to `main` at least once per day
2. Use feature toggles (boolean constants) instead of long-lived branches
3. Branches merge within 48 hours
4. Full test suite on every commit to `main`
5. `main` stays deployable -- if it breaks, fix it immediately

### Release Management

**Versioning:** `<major>.<minor>.<patch>` -- major for breaking changes, minor for features, patch for fixes.

| Step | Action | Who |
|------|--------|-----|
| 1 | Cut release branch from `main` | Release manager |
| 2 | Update version constant | Developer |
| 3 | Build from release branch | CI (auto) |
| 4 | Deploy to acceptance | CI (auto) |
| 5 | Run full ATS regression | CI (auto) |
| 6 | UAT sign-off | Product owner |
| 7 | Deploy to production | CI (manual gate) |
| 8 | Tag release in Team Server | Release manager |
| 9 | Merge release branch back to `main` | Developer |

**Release checklist:** stories done, MUnit green, ATS green, no critical security findings, DB backup verified, rollback tested, stakeholder approval, constants reviewed.

### Hotfix Workflows

```
main ─────●──────────●──── (ongoing)
          │          ↑
          ▼     merge back
release/1.2 ──●────●
               ▼    ↑
          hotfix/1.2.1──● → Build → Test → Prod
```

1. Branch from the **release tag** (not `main`)
2. Apply the minimal fix -- no new features
3. Deploy through the full pipeline (do not skip environments)
4. Merge the fix back into `main`

| Mistake | Prevention |
|---------|------------|
| Branching from `main` | Always branch from release tag |
| Skipping acceptance | Pipeline enforces all stages |
| Forgetting merge-back | Auto-create PR to `main` after deploy |
| Bundling features | Review must verify minimal change set |

---

## Quick Reference

| API | Base URL |
|-----|----------|
| Build / Deploy / Team Server | `https://deploy.mendix.com/api/1/apps/<AppId>/` |
| App Repository (Git) | `https://repository.api.mendix.com/v1/repositories/<RepoId>/` |
| ATS | `https://ats.mendix.com/api/v2/` |
| Backups | `https://deploy.mendix.com/api/1/apps/<AppId>/environments/<Mode>/snapshots/` |

| Secret | Description |
|--------|-------------|
| `MENDIX_APP_ID` | Application ID from portal |
| `MENDIX_USERNAME` | Service account email |
| `MENDIX_API_KEY` | API key for service account |
| `MENDIX_REPO_ID` | Repository ID (Git-based only) |
| `ATS_TOKEN` | ATS API token |
| `SLACK_WEBHOOK` | Notification webhook |
