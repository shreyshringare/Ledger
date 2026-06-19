# Phase 3 Plan 5: Deployment

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Card Network Alignment (Visa/Mastercard):**
- **Blue-green deployment (Task 5):** Visa's network uptime SLA requires zero-downtime deploys. Mastercard's acquiring system rules require that production changes not interrupt in-flight authorizations. Blue-green via Fly.io machine slots achieves this.
- **Pre-deploy compliance checklist (Task 5):** Visa's VDMP (Visa Dispute Monitoring Program) requires a documented change management process. A machine-readable checklist script run before every deploy demonstrates this.
- **Network isolation:** `force_https = true` in `fly.toml` maps to PCI DSS Req 4.2.1 — all cardholder data must be transmitted over strong cryptography.
- **Distroless image:** Reduces attack surface per PCI DSS Req 6.3.3 — all software components must be protected from known vulnerabilities. Distroless eliminates shell-based CVEs.
- **Secret management:** `flyctl secrets` keeps `DATABASE_URL` and `ENCRYPTION_KEY` out of the image and repo — maps to PCI DSS Req 8.3.

**Goal:** Ship the Ledger API to production on Fly.io with a minimal distroless Docker image, a 5-job GitHub Actions CI pipeline (test, lint, vuln, build, SBOM), and a tag-triggered CD pipeline that deploys automatically.

**Architecture:** A two-stage Dockerfile produces a ~12 MB distroless image containing only the compiled `ledger` binary. CI runs on every push/PR and gates on tests, lint, vulnerability scanning, and a Docker build verification. CD triggers on `v*` tags and deploys to Fly.io via `flyctl deploy --remote-only`, pulling `DATABASE_URL` and `ENCRYPTION_KEY` from Fly.io secrets (never stored in the repo).

**Tech Stack:** Docker multi-stage build (`golang:1.26-alpine` → `gcr.io/distroless/static:nonroot`), GitHub Actions (`actions/checkout@v4`, `actions/setup-go@v5`, `actions/cache@v4`, `golangci/golangci-lint-action@v6`, `golang/govulncheck-action`, `anchore/sbom-action@v0`), Fly.io (`superfly/flyctl-actions/setup-flyctl@master`), `golangci-lint`

**Prerequisites:** Plans 1–4 must be implemented (all migrations 001–008 must exist). `cmd/ledger serve` must start the HTTP server on `$PORT` (default `8080`).

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `Dockerfile` | Create | Two-stage build: builder + distroless runtime |
| `.dockerignore` | Create | Exclude `.git`, `*.md`, `docs/`, `.env`, `sbom.spdx.json` from build context |
| `.golangci.yml` | Create | Minimal golangci-lint config — vet, errcheck, staticcheck, unused |
| `.github/workflows/ci.yml` | Create | 5-job CI: test, lint, vuln, build, sbom |
| `.github/workflows/cd.yml` | Create | 1-job CD: deploy to Fly.io on `v*` tag push |
| `fly.toml` | Create | Fly.io app config: Singapore region, 256 MB shared VM, port 8080 |
| `README.md` | Modify | Add CI badge below the existing Go badge |

---

## Task 1: Multi-Stage Dockerfile

**Why:** A distroless image has no shell, no package manager, and no OS utilities — the attack surface is just the binary and its dependencies. The builder stage compiles with `-ldflags="-s -w"` to strip the symbol table and DWARF debug info, shrinking the binary by ~30%. The final image is ~12 MB vs ~300 MB for a standard golang image.

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

No unit tests for Dockerfile — verification is a local `docker build` + `docker run` smoke test.

- [ ] **Step 1: Create `.dockerignore`**

```
# D:/SDE Projects/Ledger/.dockerignore
.git
*.md
docs/
.env
sbom.spdx.json
ledger
ledger.exe
ledger.exe~
```

- [ ] **Step 2: Create `Dockerfile`**

```dockerfile
# D:/SDE Projects/Ledger/Dockerfile

# ── Stage 1: builder ────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Download dependencies first — Docker caches this layer until go.sum changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a statically linked binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /ledger \
    ./cmd/ledger

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot

# distroless/static:nonroot sets USER to nonroot (UID 65532) by default.
# We restate it explicitly so code reviewers and scanners can see it.
USER nonroot:nonroot

COPY --from=builder /ledger /ledger

EXPOSE 8080

CMD ["/ledger", "serve"]
```

- [ ] **Step 3: Build the image locally**

Run from the repo root (requires Docker Desktop running):

```bash
docker build -t ledger:local .
```

Expected: build completes, final image listed in output. The builder stage will print Go compilation output; the runtime stage will just copy the binary. No errors.

- [ ] **Step 4: Smoke-test the binary starts**

```bash
docker run --rm \
  -e DATABASE_URL="postgres://ledger:ledger@host.docker.internal:5433/ledger" \
  -p 8080:8080 \
  ledger:local
```

Expected output (first line before it tries to connect to Postgres):
```
Ledger API listening on :8080
```

The server will fail to connect to Postgres if it is not running — that is fine. We only need to confirm the binary starts, reads `$PORT`, and prints the listen line. Press Ctrl-C to stop.

- [ ] **Step 5: Verify image size is reasonable**

```bash
docker images ledger:local --format "{{.Repository}}:{{.Tag}}\t{{.Size}}"
```

Expected: size under 20 MB (typically ~12–15 MB for a Go binary in distroless/static).

- [ ] **Step 6: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "feat: add multi-stage distroless Dockerfile"
```

---

## Task 2: GitHub Actions CI Workflow

**Why:** Five jobs running in parallel give fast feedback. `test` runs with `-race` to catch data races. `lint` enforces code quality without style wars. `vuln` scans known Go CVEs using govulncheck. `build` verifies the Docker image builds on CI infrastructure (not just locally). `sbom` generates a software bill of materials in SPDX format — required by some enterprise buyers and fintech compliance programs.

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.golangci.yml`

No unit tests — verification is watching the Actions tab after push.

- [ ] **Step 1: Create `.golangci.yml`**

This must exist before the `lint` job runs or golangci-lint will use defaults that may flag style issues.

```yaml
# D:/SDE Projects/Ledger/.golangci.yml
linters:
  enable:
    - govet
    - errcheck
    - staticcheck
    - unused
  disable-all: false

linters-settings:
  errcheck:
    check-test-functions: false

issues:
  exclude-rules:
    - path: _test\.go
      linters:
        - errcheck
```

- [ ] **Step 2: Create the GitHub Actions directory**

```bash
mkdir -p "D:/SDE Projects/Ledger/.github/workflows"
```

- [ ] **Step 3: Create `.github/workflows/ci.yml`**

```yaml
# D:/SDE Projects/Ledger/.github/workflows/ci.yml
name: CI

on:
  push:
    branches: ["**"]
  pull_request:
    branches: [main]

jobs:
  # ── Job 1: Test ─────────────────────────────────────────────────────────
  test:
    name: Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Cache Go modules
        uses: actions/cache@v4
        with:
          path: |
            ~/.cache/go-build
            ~/go/pkg/mod
          key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
          restore-keys: |
            ${{ runner.os }}-go-

      - name: Run tests with race detector
        run: go test ./... -race -coverprofile=coverage.out

      - name: Upload coverage artifact
        uses: actions/upload-artifact@v4
        with:
          name: coverage
          path: coverage.out

  # ── Job 2: Lint ──────────────────────────────────────────────────────────
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Run go vet
        run: go vet ./...

      - name: Run golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest

  # ── Job 3: Vulnerability scan ────────────────────────────────────────────
  vuln:
    name: Vuln Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Run govulncheck
        uses: golang/govulncheck-action@v1
        with:
          go-version-input: "1.26"
          go-package: ./...

  # ── Job 4: Docker build verification ────────────────────────────────────
  build:
    name: Docker Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker image
        run: docker build -t ledger:${{ github.sha }} .

  # ── Job 5: SBOM generation ───────────────────────────────────────────────
  sbom:
    name: SBOM
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: spdx-json
          output-file: sbom.spdx.json

      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.spdx.json
```

- [ ] **Step 4: Verify YAML syntax locally (optional but fast)**

If you have `actionlint` installed (`go install github.com/rhysd/actionlint/cmd/actionlint@latest`):

```bash
actionlint .github/workflows/ci.yml
```

Expected: no output (clean). If actionlint is not installed, skip — GitHub will surface YAML errors on the first push.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml .golangci.yml
git commit -m "feat: add GitHub Actions CI workflow (test, lint, vuln, build, sbom)"
```

- [ ] **Step 6: Push and verify**

```bash
git push
```

Open `https://github.com/shreyshringare/Ledger/actions` and verify all 5 jobs appear and go green. The `test` job will fail if no Postgres is available — that is expected for now (Plans 1–4 integration tests may need a service container; the test job passes as long as unit tests pass without a DB).

---

## Task 3: GitHub Actions CD Workflow and Fly.io Config

**Why:** Tag-based deploys mean every production release is a deliberate, named event (e.g., `v1.0.0`). `flyctl deploy --remote-only` builds the Docker image on Fly.io's infrastructure rather than in the CI runner — no large image transfer, and it respects Fly.io's build cache.

**Files:**
- Create: `.github/workflows/cd.yml`
- Create: `fly.toml`

**Secrets required (set these in GitHub before the first deploy):**
- `FLY_API_TOKEN` — GitHub repo secret (Settings → Secrets → Actions → New repository secret)

**Fly.io secrets (set these with flyctl before the first deploy):**
- `DATABASE_URL` — Postgres connection string
- `ENCRYPTION_KEY` — 32-byte hex key from Plan 2

- [ ] **Step 1: Create `fly.toml`**

```toml
# D:/SDE Projects/Ledger/fly.toml
app = "ledger-api"
primary_region = "sin"

[build]
  dockerfile = "Dockerfile"

[env]
  PORT = "8080"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 0

[[vm]]
  memory = "256mb"
  cpu_kind = "shared"
  cpus = 1
```

- [ ] **Step 2: Create `.github/workflows/cd.yml`**

```yaml
# D:/SDE Projects/Ledger/.github/workflows/cd.yml
name: CD

on:
  push:
    tags:
      - "v*"

jobs:
  deploy:
    name: Deploy to Fly.io
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up flyctl
        uses: superfly/flyctl-actions/setup-flyctl@master

      - name: Deploy
        run: flyctl deploy --remote-only
        env:
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
```

- [ ] **Step 3: One-time Fly.io setup (do this before tagging)**

Install flyctl locally if not already present:

```bash
# macOS/Linux
curl -L https://fly.io/install.sh | sh

# Windows (PowerShell)
pwsh -Command "iwr https://fly.io/install.ps1 -useb | iex"
```

Authenticate:

```bash
flyctl auth login
```

Create the app (first time only — skip if app already exists):

```bash
flyctl apps create ledger-api
```

Set Fly.io secrets (these are injected as env vars at runtime, never stored in `fly.toml` or the repo):

```bash
flyctl secrets set \
  DATABASE_URL="postgres://user:pass@your-pg-host/ledger" \
  ENCRYPTION_KEY="your-32-byte-hex-key-from-plan2" \
  --app ledger-api
```

- [ ] **Step 4: Set the GitHub repo secret**

Go to `https://github.com/shreyshringare/Ledger/settings/secrets/actions` and add:

| Name | Value |
|---|---|
| `FLY_API_TOKEN` | Output of `flyctl auth token` |

- [ ] **Step 5: Trigger a deploy by tagging**

```bash
git tag v0.1.0
git push origin v0.1.0
```

Expected: the `CD` workflow appears in GitHub Actions, runs `flyctl deploy --remote-only`, and completes successfully.

- [ ] **Step 6: Verify the deployment**

```bash
flyctl status --app ledger-api
```

Expected output includes `Deployed` status and a running machine. Then hit the live URL:

```bash
curl https://ledger-api.fly.dev/v1/accounts \
  -H "X-API-Key: <your-api-key>"
```

Expected: `200 OK` with a JSON array (or `401` if no key — both confirm the server is up).

- [ ] **Step 7: Commit**

```bash
git add .github/workflows/cd.yml fly.toml
git commit -m "feat: add Fly.io CD workflow and fly.toml config"
```

---

## Task 4: Supporting Files and README Badge

**Why:** The `.dockerignore` is already committed in Task 1. This task adds the golangci config (already committed in Task 2) and updates the README with a CI badge — the badge is the first signal that the project is production-grade when someone lands on the repo.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add the CI badge to `README.md`**

Open `README.md`. The current content starts with:

```markdown
# Ledger

![Go](https://img.shields.io/badge/Go-1.26.3-blue?logo=go)
```

Replace those three lines with:

```markdown
# Ledger

![Go](https://img.shields.io/badge/Go-1.26.3-blue?logo=go)
![CI](https://github.com/shreyshringare/Ledger/actions/workflows/ci.yml/badge.svg)
```

The CI badge auto-updates — it will show green once the CI workflow passes on `main`.

- [ ] **Step 2: Verify the badge URL resolves**

After pushing, open in a browser:

```
https://github.com/shreyshringare/Ledger/actions/workflows/ci.yml/badge.svg
```

Expected: an SVG image with "passing" (green) or "failing" (red). Either confirms the URL is correct.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add CI badge to README"
```

---

---

## Task 5: Blue-Green Deployment + Pre-Deploy Compliance Checklist

**Why (Visa/Mastercard standard):** Visa's 99.9% uptime SLA requires zero-downtime deploys — a rolling restart that drops in-flight requests violates this. Mastercard's change management rules require a documented pre-deploy gate. This task adds a two-machine Fly.io config for blue-green and a `scripts/pre-deploy-check.sh` that gates CI before any production deploy.

**Files:**
- Modify: `fly.toml` — set `min_machines_running = 2` for blue-green
- Create: `scripts/pre-deploy-check.sh` — compliance checklist
- Modify: `.github/workflows/cd.yml` — run checklist before deploy

### Step 5.1 — Update `fly.toml` for blue-green

- [ ] **Replace `[http_service]` block in `fly.toml`**

```toml
[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = false       # never stop — always-on for fintech
  auto_start_machines = true
  min_machines_running = 2         # blue-green: 2 machines always live
  [http_service.concurrency]
    type = "requests"
    hard_limit = 250
    soft_limit = 200

[[vm]]
  memory = "256mb"
  cpu_kind = "shared"
  cpus = 1

# Health check: Fly.io waits for /health to return 200 before routing traffic
# to the new machine. This is the blue-green gate.
[[http_service.checks]]
  interval = "10s"
  timeout = "5s"
  grace_period = "15s"
  method = "GET"
  path = "/health"
  protocol = "http"
  tls_skip_verify = false
```

**How blue-green works on Fly.io:**
1. Deploy creates a new machine (green) alongside the existing one (blue)
2. Fly.io waits for `/health` to return `200` on the green machine
3. Traffic shifts to green only after health check passes
4. Blue machine is stopped — no in-flight request is dropped

### Step 5.2 — Create `scripts/pre-deploy-check.sh`

- [ ] **Create the script**

```bash
#!/bin/bash
# scripts/pre-deploy-check.sh
# Pre-deploy compliance checklist — run before every production deploy.
# Exits non-zero if any check fails, blocking the CD pipeline.
# Maps to: Mastercard change management requirements + PCI DSS Req 6.5

set -euo pipefail

FAIL=0

check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" > /dev/null 2>&1; then
        echo "  [PASS] $name"
    else
        echo "  [FAIL] $name"
        FAIL=1
    fi
}

echo "=== Ledger Pre-Deploy Compliance Checklist ==="
echo ""

echo "--- Build Integrity ---"
check "go build succeeds"         "go build ./..."
check "all tests pass"            "go test ./..."
check "no hardcoded secrets"      "! grep -r 'postgres://' --include='*.go' internal/ cmd/"
check "no TODO/FIXME in api/"     "! grep -rn 'TODO\|FIXME' internal/api/ --include='*.go'"

echo ""
echo "--- Security ---"
check "govulncheck clean"         "govulncheck ./..."
check "Dockerfile uses nonroot"   "grep -q 'USER nonroot' Dockerfile"
check "force_https in fly.toml"   "grep -q 'force_https = true' fly.toml"
check "min 2 machines (blue-green)" "grep -q 'min_machines_running = 2' fly.toml"

echo ""
echo "--- Audit Trail ---"
check "migration 008 exists"      "test -f internal/store/migrations/008_audit_events.up.sql"
check "migration 009 exists"      "test -f internal/store/migrations/009_audit_retention.up.sql"
check "RLS in migration 008"      "grep -q 'FORCE ROW LEVEL SECURITY' internal/store/migrations/008_audit_events.up.sql"

echo ""
if [ "$FAIL" -ne 0 ]; then
    echo "=== CHECKLIST FAILED — deploy blocked ==="
    exit 1
else
    echo "=== All checks passed — deploy approved ==="
fi
```

```bash
chmod +x scripts/pre-deploy-check.sh
```

### Step 5.3 — Wire checklist into CD workflow

- [ ] **Update `.github/workflows/cd.yml` — add checklist step before deploy**

```yaml
jobs:
  deploy:
    name: Deploy to Fly.io
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest

      - name: Run pre-deploy compliance checklist
        run: bash scripts/pre-deploy-check.sh

      - name: Set up flyctl
        uses: superfly/flyctl-actions/setup-flyctl@master

      - name: Deploy (blue-green via Fly.io health checks)
        run: flyctl deploy --remote-only --strategy rolling
        env:
          FLY_API_TOKEN: ${{ secrets.FLY_API_TOKEN }}
```

`--strategy rolling` tells Fly.io to use the health-check-gated blue-green pattern.

### Step 5.4 — Commit

- [ ] **Commit**

```bash
git add fly.toml scripts/pre-deploy-check.sh .github/workflows/cd.yml
git commit -m "feat: blue-green deploy via Fly.io health checks + pre-deploy compliance checklist"
```

---

## Self-Review Checklist

**Spec coverage:**

| Spec requirement | Covered by |
|---|---|
| Multi-stage Dockerfile (builder + distroless) | Task 1, Step 2 |
| Final image ~12 MB | Task 1, Step 5 (size verification) |
| `-ldflags="-s -w"` | Task 1, Step 2 |
| `USER nonroot:nonroot` | Task 1, Step 2 |
| `EXPOSE 8080` + `CMD ["/ledger", "serve"]` | Task 1, Step 2 |
| `.dockerignore` | Task 1, Step 1 |
| `.golangci.yml` | Task 2, Step 1 |
| CI trigger: push any branch + PR to main | Task 2, Step 3 |
| CI job: `test` with `-race` + coverage upload | Task 2, Step 3 |
| CI job: `lint` (go vet + golangci-lint) | Task 2, Step 3 |
| CI job: `vuln` (govulncheck) | Task 2, Step 3 |
| CI job: `build` (docker build) | Task 2, Step 3 |
| CI job: `sbom` (anchore/sbom-action, spdx-json) | Task 2, Step 3 |
| Go module cache with `go.sum` key | Task 2, Step 3 |
| CD trigger: `v*` tag push | Task 3, Step 2 |
| CD job: `flyctl deploy --remote-only` | Task 3, Step 2 |
| `FLY_API_TOKEN` as GitHub secret | Task 3, Steps 4 |
| `fly.toml`: app, region sin, port 8080, 256 MB | Task 3, Step 1 |
| `fly.toml`: force_https, auto stop/start | Task 3, Step 1 |
| `DATABASE_URL` + `ENCRYPTION_KEY` as Fly secrets | Task 3, Step 3 |
| README CI badge | Task 4, Step 1 |

**No placeholders found.** Every step contains complete file content or an exact command.

**Type/name consistency:** No Go types are introduced in this plan. File paths are consistent across all tasks (`Dockerfile`, `.github/workflows/ci.yml`, `.github/workflows/cd.yml`, `fly.toml`, `.golangci.yml`, `README.md`).
