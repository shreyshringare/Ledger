# Ledger Threat Model (STRIDE)

**Version:** 1.0  
**Date:** 2026-05-26  
**Scope:** Ledger API — double-entry accounting engine with hash-chain tamper detection

---

## Assets

| Asset | Sensitivity | Why It Matters |
|-------|-------------|----------------|
| Transaction data | HIGH | Financial records; tamper = fraud |
| Account data | MEDIUM | Account names/types; not PII but operationally critical |
| Audit log | HIGH | Chain of custody; must be append-only |
| API keys | HIGH | Compromise = full API access |
| Encryption key (ENCRYPTION_KEY) | HIGH | Decrypts account descriptions |
| Database credentials (DATABASE_URL) | CRITICAL | Full DB access |

---

## Threat Analysis (STRIDE)

### S — Spoofing (pretending to be someone else)

**Threat:** Attacker calls the API pretending to be an authorized client.

**Mitigations:**
- API key authentication: `X-API-Key: <key_id>.<secret>` on every request
- Secrets stored as bcrypt hashes (cost=12) in `api_keys` table — stolen DB dump does not reveal usable keys
- Key scoping: `read` vs `write` — read-only compromise cannot post transactions

**Residual risk:** No mTLS (mutual TLS). An attacker with a valid key can impersonate any client with that key's scope. Acceptable for single-tenant fintech demo; production would add mTLS or key-per-client isolation.

---

### T — Tampering (modifying data without authorization)

**Threat:** Attacker modifies a transaction row directly in the database to change amounts.

**Mitigations:**
- SHA-256 hash chain on transactions: `hash = SHA256(id + description + entries + prev_hash)`. Any row mutation breaks the chain.
- `GET /v1/chain/verify` detects tampering in O(n) — re-walks chain, recomputes all hashes.
- Postgres RLS on `audit_events`: `DENY UPDATE, DELETE` at DB role level — even compromised app credentials cannot mutate audit records.

**Residual risk:** DB superuser (`postgres`) role bypasses RLS. Requires DB-level access control (separate `ledger_app_role` with limited grants). Documented but not fully enforced in dev environment.

---

### R — Repudiation (denying an action happened)

**Threat:** A client claims they never posted a transaction or revoked an API key.

**Mitigations:**
- Immutable audit log: every `account.created`, `transaction.posted`, `api_key.created`, `api_key.revoked` event is recorded to `audit_events` with `actor = api_key_id`.
- `GET /v1/admin/audit-events/verify` re-walks audit chain and detects tampering.

**Residual risk:** Audit log is only as trustworthy as the application code that writes to it. Bypassing the app (direct DB insert by a DBA) could inject fabricated events. Full non-repudiation requires HSM signing or a write-once storage backend (neither in scope).

---

### I — Information Disclosure (leaking data to unauthorized parties)

**Threat:** Attacker reads sensitive data from API responses, logs, or DB dumps.

**Mitigations:**
- Key scoping: `read`-scope keys cannot call write endpoints.
- No PII in structured logs: logs include `api_key_id` (not the secret), `path`, `status`, `duration_ms` only.
- `account.description` encrypted at rest via `pgcrypto pgp_sym_encrypt`. Stolen DB dump without `ENCRYPTION_KEY` cannot read descriptions.
- Correlation ID (`X-Request-ID`) is a random UUID — no user-identifying information embedded.

**Residual risk:** Transaction amounts and account names are stored unencrypted (only `description` is encrypted). Full field-level encryption would require schema redesign.

---

### D — Denial of Service (making the service unavailable)

**Threat:** Attacker floods the API to exhaust resources or trigger DB connection saturation.

**Mitigations:**
- Rate limiting: 100 requests/minute per `api_key_id`, in-memory sliding window. Exceeds → `429 Too Many Requests` with `Retry-After` header.
- Request timeout middleware: 10s per request — long-running queries cannot hold connections indefinitely.
- Body size limit: 1MB max request body — prevents oversized payloads.
- Circuit breaker (gobreaker): after 5 consecutive DB errors in 10s, circuit opens for 30s — protects DB from thundering herd during outages.
- DB connection pool: `MaxConns=25`, `MinConns=2` — bounded resource usage.

**Residual risk:** Rate limiter is in-memory (single instance). Distributed DoS across many clients with many API keys is not mitigated. A Redis-backed limiter would be needed for multi-instance deployments.

---

### E — Elevation of Privilege (gaining more access than authorized)

**Threat:** A `read`-scope API key performs write operations.

**Mitigations:**
- Scope enforcement in `APIKeyAuth` middleware — checks `scope` field before routing; write endpoints require `scope=write`.
- `POST /v1/admin/api-keys` creates keys with explicit scope — cannot self-escalate.

**Residual risk:** No `admin` scope yet. `write`-scope keys have access to all write endpoints including account creation. Production would benefit from finer-grained scoping (e.g., `transactions:write` vs `accounts:write`).

---

## What Is NOT Mitigated (by design)

| Risk | Reason Not Mitigated |
|------|---------------------|
| Multi-tenancy isolation | Single-tenant system; no user concept |
| mTLS (mutual TLS) | Out of scope for single-instance demo |
| HSM key storage for ENCRYPTION_KEY | Fly.io secrets are sufficient for demo context |
| DB superuser bypass of RLS | Requires separate `ledger_app_role` — partially implemented |
| Distributed rate limiting (Redis) | Single-instance deployment; in-memory is sufficient |

---

## Security Controls Summary

| Control | Implementation | Covers |
|---------|---------------|--------|
| API key auth (bcrypt) | `middleware_auth.go` | Spoofing |
| Hash chain (transactions) | `engine.go`, `transaction.go` | Tampering |
| Key scoping | `middleware_auth.go` | Elevation of Privilege |
| Rate limiting | `middleware_ratelimit.go` | DoS |
| Circuit breaker | `store/circuitbreaker.go` | DoS |
| Request timeout | `middleware_security.go` | DoS |
| pgcrypto column encryption | `postgres.go`, migration 007 | Information Disclosure |
| No PII in logs | structured logging | Information Disclosure |
| Pre-commit DSN check | `.githooks/pre-commit` | Information Disclosure |
| Fraud velocity checks | `engine/fraud.go` | Tampering/Fraud |
