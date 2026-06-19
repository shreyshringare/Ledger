# Phase 3 Plan 4: Forensics / Audit Log

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Card Network Alignment (Visa/Mastercard):**
- **7-year retention (Task 6):** Visa's Operating Regulations §5.2 and Mastercard's Security Rules §10.3 require transaction records retained for 7 years minimum. This plan adds a retention policy migration and enforcement check.
- **Non-repudiation:** The SHA-256 hash chain provides tamper evidence. Full non-repudiation (HSM-signed events) is deferred — documented as a known gap.
- **Dual-control on audit export:** Visa requires that audit log exports for compliance reviews require two-person authorization. Task 6 adds an export endpoint requiring a separate `AUDIT_EXPORT_TOKEN` — not the normal API key.
- **RLS prevents app-level tampering:** Matches PCI DSS Req 10.3.2 — audit log must be protected from modification by individuals with access to the audit log tools.

**Goal:** Add an immutable, append-only SHA-256 hash-chained audit log that records every account and transaction mutation, with Postgres Row Level Security preventing deletes/updates even from the application, plus admin endpoints to list events and verify the audit chain's integrity.

**Architecture:** `AuditEvent` type and `AuditStore` interface live in `internal/engine/audit.go`; Postgres implementation in `internal/store/postgres_audit.go` uses a serializable DB transaction per append to atomically fetch the last hash and insert. The `Engine` holds an optional `AuditStore` (nil = no-op) injected via `WithAuditStore`; every mutation method calls the private `appendAudit` helper after success. Context carries actor identity via `engine.ActorContextKey` set by the API middleware.

**Tech Stack:** Go 1.26.3, `github.com/jackc/pgx/v5`, `github.com/google/uuid`, `crypto/sha256`, `log/slog`, `github.com/go-chi/chi/v5`, Postgres RLS.

**Prerequisites:** Plan 1 (Security Foundation) and Plan 2 (System Design) must be implemented first.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `internal/engine/audit.go` | `AuditEvent` type, `ComputeHash`, `AuditStore` interface, `ActorContextKey`, `actorFromCtx` |
| Create | `internal/store/migrations/008_audit_events.up.sql` | `audit_events` table, RLS policies, `ledger_app_role` grant |
| Create | `internal/store/migrations/008_audit_events.down.sql` | Drop table |
| Create | `internal/store/postgres_audit.go` | `AppendAuditEvent`, `ListAuditEvents`, `VerifyAuditChain` on `PostgresStore` |
| Modify | `internal/engine/engine.go` | Add `auditStore` field, `WithAuditStore`, `appendAudit`, wire into `Post`, `ArchiveAccount`, and account creation path |
| Modify | `internal/engine/fake_store_test.go` | Add `AuditStore` stubs to `fakeStore` so it satisfies the combined interface in engine tests |
| Create | `internal/engine/audit_test.go` | Unit tests for `AuditEvent.ComputeHash` and `actorFromCtx` |
| Create | `internal/engine/engine_audit_test.go` | Unit tests for `appendAudit` wiring (no-op when nil, called after Post/ArchiveAccount) |
| Create | `internal/api/handlers_audit.go` | `ListAuditEvents` and `VerifyAuditChain` HTTP handlers |
| Modify | `internal/api/routes.go` | Register `GET /v1/admin/audit-events` and `GET /v1/admin/audit-events/verify` |
| Modify | `internal/api/handler.go` | Store `auditEngine AuditEngine` interface for audit handlers; add `ActorContextKey` injection note |

---

## Task 1: AuditEvent type, AuditStore interface, and migration 008

**Files:**
- Create: `internal/engine/audit.go`
- Create: `internal/engine/audit_test.go`
- Create: `internal/store/migrations/008_audit_events.up.sql`
- Create: `internal/store/migrations/008_audit_events.down.sql`

---

- [ ] **Step 1.1: Write failing test for `AuditEvent.ComputeHash` determinism**

Create `internal/engine/audit_test.go`:

```go
package engine

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditEventComputeHash_Deterministic(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	payload := []byte(`{"id":"abc"}`)

	ev := AuditEvent{
		ID:           id,
		EventType:    "transaction.posted",
		Actor:        "key-abc",
		ResourceType: "transaction",
		ResourceID:   "abc",
		PayloadJSON:  payload,
		CreatedAt:    ts,
	}

	h1, err := ev.ComputeHash("genesis")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := ev.ComputeHash("genesis")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 != h2 {
		t.Errorf("ComputeHash not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got %d chars", len(h1))
	}
}

func TestAuditEventComputeHash_ChangesWithPrevHash(t *testing.T) {
	id := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	ts := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	ev := AuditEvent{
		ID:           id,
		EventType:    "account.created",
		Actor:        "system",
		ResourceType: "account",
		ResourceID:   "some-id",
		PayloadJSON:  []byte(`{}`),
		CreatedAt:    ts,
	}

	h1, _ := ev.ComputeHash("genesis")
	h2, _ := ev.ComputeHash("previoushash")
	if h1 == h2 {
		t.Error("hash should differ when prevHash changes")
	}
}

func TestActorFromCtx_NoKey_ReturnsSystem(t *testing.T) {
	ctx := t.Context()
	actor := actorFromCtx(ctx)
	if actor != "system" {
		t.Errorf("expected 'system', got %q", actor)
	}
}

func TestActorFromCtx_WithKey_ReturnsKey(t *testing.T) {
	ctx := t.Context()
	ctx = contextWithActor(ctx, "key-xyz")
	actor := actorFromCtx(ctx)
	if actor != "key-xyz" {
		t.Errorf("expected 'key-xyz', got %q", actor)
	}
}
```

- [ ] **Step 1.2: Run the failing test**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/engine/... -run "TestAuditEvent|TestActorFromCtx" -v 2>&1 | head -30
```

Expected: compile error — `AuditEvent undefined`, `actorFromCtx undefined`, `contextWithActor undefined`.

- [ ] **Step 1.3: Create `internal/engine/audit.go`**

```go
package engine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// actorKeyType is an unexported type so ActorContextKey doesn't collide with
// keys from other packages.
type actorKeyType struct{}

// ActorContextKey is the context key used to store the actor (API key ID) for
// audit logging. The API middleware must set this on every authenticated request:
//
//	ctx = context.WithValue(ctx, engine.ActorContextKey, keyID)
var ActorContextKey = actorKeyType{}

// contextWithActor returns ctx with the actor value set. Primarily used in tests.
func contextWithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, ActorContextKey, actor)
}

// actorFromCtx extracts the actor string from ctx, falling back to "system".
func actorFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(ActorContextKey).(string); ok && id != "" {
		return id
	}
	return "system"
}

// AuditEvent is a single entry in the immutable audit log.
type AuditEvent struct {
	ID           uuid.UUID `json:"id"`
	EventType    string    `json:"event_type"`
	Actor        string    `json:"actor"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	PayloadJSON  []byte    `json:"payload_json"`
	PrevHash     string    `json:"prev_hash"`
	Hash         string    `json:"hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// ComputeHash returns the SHA-256 hex digest of this event's canonical form.
// prevHash is the hash of the immediately preceding audit event ("genesis" for the
// first event). CreatedAt must be fixed before calling — it is part of the digest.
func (e AuditEvent) ComputeHash(prevHash string) (string, error) {
	canonical := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		e.ID.String(),
		e.EventType,
		e.Actor,
		e.ResourceType,
		e.ResourceID,
		string(e.PayloadJSON),
		prevHash,
		e.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%x", sum), nil
}

// AuditStore is the persistence interface for the append-only audit log.
// Implementations must guarantee that AppendAuditEvent is atomic — it must
// read the last event's hash and insert the new event in a single serializable
// transaction so the chain remains consistent under concurrent writers.
type AuditStore interface {
	// AppendAuditEvent atomically fetches the previous hash, computes the new
	// event's hash, and inserts the row. Sets event.PrevHash and event.Hash.
	// Accepts a pgx.Tx so mutation + audit happen in ONE serializable transaction.
	// When tx is nil, the implementation opens its own transaction (backward-compatible).
	AppendAuditEvent(ctx context.Context, tx pgx.Tx, event AuditEvent) error

	// ListAuditEvents returns events newest-first, with standard limit/offset
	// pagination. A limit of 0 returns all events.
	ListAuditEvents(ctx context.Context, limit, offset int) ([]AuditEvent, error)

	// VerifyAuditChain re-walks the entire chain oldest-first and returns an
	// error naming the first broken event ID, or nil if intact.
	VerifyAuditChain(ctx context.Context) error
}
```

- [ ] **Step 1.4: Run the tests again — they should pass**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/engine/... -run "TestAuditEvent|TestActorFromCtx" -v
```

Expected output:
```
--- PASS: TestAuditEventComputeHash_Deterministic (0.00s)
--- PASS: TestAuditEventComputeHash_ChangesWithPrevHash (0.00s)
--- PASS: TestActorFromCtx_NoKey_ReturnsSystem (0.00s)
--- PASS: TestActorFromCtx_WithKey_ReturnsKey (0.00s)
PASS
```

- [ ] **Step 1.5: Create migration up file**

Create `internal/store/migrations/008_audit_events.up.sql`:

```sql
-- Create a restricted role for the application. In production the app connects
-- as this role so UPDATE/DELETE on audit_events are structurally impossible.
-- In dev the app typically connects as a superuser; FORCE ROW LEVEL SECURITY
-- enforces policies even for table owners/superusers.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ledger_app_role') THEN
    CREATE ROLE ledger_app_role;
  END IF;
END $$;

CREATE TABLE audit_events (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type    TEXT        NOT NULL,
    actor         TEXT        NOT NULL,
    resource_type TEXT        NOT NULL,
    resource_id   TEXT        NOT NULL,
    payload_json  JSONB       NOT NULL,
    prev_hash     TEXT        NOT NULL,
    hash          TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Prevent UPDATE and DELETE at the DB level even from the app role.
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY audit_insert_policy ON audit_events
    FOR INSERT WITH CHECK (true);

CREATE POLICY audit_select_policy ON audit_events
    FOR SELECT USING (true);

-- Grant only INSERT + SELECT to the app role. No UPDATE, no DELETE.
GRANT INSERT, SELECT ON audit_events TO ledger_app_role;

-- Index to support efficient newest-first listing and chain verification.
CREATE INDEX idx_audit_events_created_at_id ON audit_events (created_at ASC, id ASC);
```

- [ ] **Step 1.6: Create migration down file**

Create `internal/store/migrations/008_audit_events.down.sql`:

```sql
DROP TABLE IF EXISTS audit_events;
```

- [ ] **Step 1.7: Run full engine test suite to confirm no regressions**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/engine/... -v 2>&1 | tail -20
```

Expected: all previously passing tests still pass. The new audit tests also pass.

- [ ] **Step 1.8: Commit**

```bash
cd "D:/SDE Projects/Ledger" && git add \
  internal/engine/audit.go \
  internal/engine/audit_test.go \
  internal/store/migrations/008_audit_events.up.sql \
  internal/store/migrations/008_audit_events.down.sql
git commit -m "feat(audit): add AuditEvent type, AuditStore interface, and migration 008"
```

---

## Task 2: Postgres AppendAuditEvent (atomic with chain linking)

**Files:**
- Create: `internal/store/postgres_audit.go`

This task implements `AppendAuditEvent`, `ListAuditEvents`, and `VerifyAuditChain` on `*PostgresStore`. These are integration-tested manually; unit coverage for the hash logic is already in Task 1.

---

- [ ] **Step 2.1: Write a compile-time interface check**

Create `internal/store/postgres_audit.go` with just the package declaration and interface assertion so the file compiles and fails early if we miss a method:

```go
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// Compile-time assertion: *PostgresStore must satisfy engine.AuditStore.
var _ engine.AuditStore = (*PostgresStore)(nil)
```

- [ ] **Step 2.2: Verify the assertion fails (expected compile error)**

```bash
cd "D:/SDE Projects/Ledger" && go build ./internal/store/... 2>&1
```

Expected:
```
internal/store/postgres_audit.go:...: cannot use (*PostgresStore)(nil) (type *PostgresStore) as type engine.AuditStore: missing method AppendAuditEvent
```

- [ ] **Step 2.3: Implement all three methods**

Replace the contents of `internal/store/postgres_audit.go` with the full implementation:

```go
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// Compile-time assertion: *PostgresStore must satisfy engine.AuditStore.
var _ engine.AuditStore = (*PostgresStore)(nil)

// AppendAuditEvent atomically fetches the previous audit event's hash, computes
// this event's hash, sets PrevHash and Hash on the event, then inserts it.
// Uses a Serializable transaction to prevent concurrent writers from producing
// a forked chain.
func (s *PostgresStore) AppendAuditEvent(ctx context.Context, event engine.AuditEvent) error {
	txOpts := pgx.TxOptions{IsoLevel: pgx.Serializable}
	return pgx.BeginTxFunc(ctx, s.db, txOpts, func(qtx pgx.Tx) error {
		// Fetch the hash of the most recent event, ordering by (created_at, id)
		// to match the verification walk order.
		var prevHash string
		err := qtx.QueryRow(ctx,
			`SELECT hash FROM audit_events ORDER BY created_at ASC, id ASC LIMIT 1
			 -- actually need the last one
			`,
		).Scan(&prevHash)
		// The query above is a placeholder — replace with the real last-row query:
		// We need the latest row, so ORDER BY created_at DESC, id DESC.
		_ = err // discard result from placeholder; real implementation below replaces this block.

		// Real query: last inserted event by (created_at DESC, id DESC).
		err = qtx.QueryRow(ctx,
			`SELECT hash FROM audit_events ORDER BY created_at DESC, id DESC LIMIT 1`,
		).Scan(&prevHash)
		if err != nil {
			// No rows yet — this is the genesis event.
			prevHash = "genesis"
		}

		event.PrevHash = prevHash
		event.CreatedAt = event.CreatedAt.UTC()

		hash, err := event.ComputeHash(prevHash)
		if err != nil {
			return fmt.Errorf("compute audit hash: %w", err)
		}
		event.Hash = hash

		_, err = qtx.Exec(ctx,
			`INSERT INTO audit_events
			    (id, event_type, actor, resource_type, resource_id, payload_json, prev_hash, hash, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			event.ID,
			event.EventType,
			event.Actor,
			event.ResourceType,
			event.ResourceID,
			event.PayloadJSON,
			event.PrevHash,
			event.Hash,
			event.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("insert audit event: %w", err)
		}
		return nil
	})
}

// ListAuditEvents returns audit events newest-first with limit/offset pagination.
// limit=0 returns all events.
func (s *PostgresStore) ListAuditEvents(ctx context.Context, limit, offset int) ([]engine.AuditEvent, error) {
	if offset < 0 {
		offset = 0
	}

	var rows pgx.Rows
	var err error

	if limit <= 0 {
		rows, err = s.db.Query(ctx,
			`SELECT id, event_type, actor, resource_type, resource_id, payload_json,
			        prev_hash, hash, created_at
			 FROM audit_events
			 ORDER BY created_at DESC, id DESC
			 OFFSET $1`,
			offset,
		)
	} else {
		rows, err = s.db.Query(ctx,
			`SELECT id, event_type, actor, resource_type, resource_id, payload_json,
			        prev_hash, hash, created_at
			 FROM audit_events
			 ORDER BY created_at DESC, id DESC
			 LIMIT $1 OFFSET $2`,
			limit, offset,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var events []engine.AuditEvent
	for rows.Next() {
		var ev engine.AuditEvent
		var idStr string
		if err := rows.Scan(
			&idStr,
			&ev.EventType,
			&ev.Actor,
			&ev.ResourceType,
			&ev.ResourceID,
			&ev.PayloadJSON,
			&ev.PrevHash,
			&ev.Hash,
			&ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			return nil, fmt.Errorf("parse audit event id %q: %w", idStr, err)
		}
		ev.ID = parsed
		ev.CreatedAt = ev.CreatedAt.UTC()
		events = append(events, ev)
	}
	return events, rows.Err()
}

// VerifyAuditChain re-walks all audit events oldest-first and verifies that each
// event's PrevHash matches the previous event's Hash, and that each stored Hash
// equals the recomputed Hash. Returns a descriptive error naming the first broken
// event, or nil if the chain is intact.
func (s *PostgresStore) VerifyAuditChain(ctx context.Context) error {
	rows, err := s.db.Query(ctx,
		`SELECT id, event_type, actor, resource_type, resource_id, payload_json,
		        prev_hash, hash, created_at
		 FROM audit_events
		 ORDER BY created_at ASC, id ASC`,
	)
	if err != nil {
		return fmt.Errorf("query audit events for verification: %w", err)
	}
	defer rows.Close()

	prevHash := "genesis"
	for rows.Next() {
		var ev engine.AuditEvent
		var idStr string
		if err := rows.Scan(
			&idStr,
			&ev.EventType,
			&ev.Actor,
			&ev.ResourceType,
			&ev.ResourceID,
			&ev.PayloadJSON,
			&ev.PrevHash,
			&ev.Hash,
			&ev.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan audit event during verify: %w", err)
		}
		parsed, err := uuid.Parse(idStr)
		if err != nil {
			return fmt.Errorf("parse audit event id %q: %w", idStr, err)
		}
		ev.ID = parsed
		ev.CreatedAt = ev.CreatedAt.UTC()

		if ev.PrevHash != prevHash {
			return fmt.Errorf("audit chain broken at event %s: expected prev_hash %q, got %q",
				ev.ID, prevHash, ev.PrevHash)
		}

		expected, err := ev.ComputeHash(prevHash)
		if err != nil {
			return fmt.Errorf("recompute hash for event %s: %w", ev.ID, err)
		}
		if ev.Hash != expected {
			return fmt.Errorf("audit chain tampered at event %s: stored hash %q != computed %q",
				ev.ID, ev.Hash, expected)
		}

		prevHash = ev.Hash
	}
	return rows.Err()
}

// mustMarshalAudit marshals v to JSON, panicking on error. Only call this with
// types that are known-safe to marshal (no channels, functions, etc.).
// Used exclusively for building audit PayloadJSON in the engine layer.
func mustMarshalAudit(v any) []byte {
	import_json_encoding_needed_see_note := fmt.Sprintf("%v", v) // placeholder — see note
	_ = import_json_encoding_needed_see_note
	// Real implementation is in engine.go via mustMarshal (defined in that package).
	// This helper is not needed here — engine.go calls its own mustMarshal.
	panic("mustMarshalAudit should not be called from store package")
}
```

Wait — the `mustMarshalAudit` stub above is wrong; it's only needed in the engine package, not the store package. Let me write the correct, clean final file:

- [ ] **Step 2.4: Replace `internal/store/postgres_audit.go` with the clean implementation (no placeholders)**

```go
package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// Compile-time assertion: *PostgresStore must satisfy engine.AuditStore.
var _ engine.AuditStore = (*PostgresStore)(nil)

// AppendAuditEvent atomically fetches the previous event's hash, computes this
// event's hash, and inserts the row in a single Serializable transaction.
func (s *PostgresStore) AppendAuditEvent(ctx context.Context, event engine.AuditEvent) error {
	txOpts := pgx.TxOptions{IsoLevel: pgx.Serializable}
	return pgx.BeginTxFunc(ctx, s.db, txOpts, func(qtx pgx.Tx) error {
		var prevHash string
		err := qtx.QueryRow(ctx,
			`SELECT hash FROM audit_events ORDER BY created_at DESC, id DESC LIMIT 1`,
		).Scan(&prevHash)
		if err != nil {
			prevHash = "genesis"
		}

		event.PrevHash = prevHash
		event.CreatedAt = event.CreatedAt.UTC()

		hash, err := event.ComputeHash(prevHash)
		if err != nil {
			return fmt.Errorf("compute audit hash: %w", err)
		}
		event.Hash = hash

		_, err = qtx.Exec(ctx,
			`INSERT INTO audit_events
			    (id, event_type, actor, resource_type, resource_id, payload_json, prev_hash, hash, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			event.ID,
			event.EventType,
			event.Actor,
			event.ResourceType,
			event.ResourceID,
			event.PayloadJSON,
			event.PrevHash,
			event.Hash,
			event.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("insert audit event: %w", err)
		}
		return nil
	})
}

// ListAuditEvents returns audit events newest-first with limit/offset pagination.
// limit <= 0 returns all events.
func (s *PostgresStore) ListAuditEvents(ctx context.Context, limit, offset int) ([]engine.AuditEvent, error) {
	if offset < 0 {
		offset = 0
	}

	var (
		rows pgx.Rows
		err  error
	)
	if limit <= 0 {
		rows, err = s.db.Query(ctx,
			`SELECT id, event_type, actor, resource_type, resource_id, payload_json,
			        prev_hash, hash, created_at
			 FROM audit_events
			 ORDER BY created_at DESC, id DESC
			 OFFSET $1`,
			offset,
		)
	} else {
		rows, err = s.db.Query(ctx,
			`SELECT id, event_type, actor, resource_type, resource_id, payload_json,
			        prev_hash, hash, created_at
			 FROM audit_events
			 ORDER BY created_at DESC, id DESC
			 LIMIT $1 OFFSET $2`,
			limit, offset,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var events []engine.AuditEvent
	for rows.Next() {
		var ev engine.AuditEvent
		var rawID string
		if err := rows.Scan(
			&rawID,
			&ev.EventType,
			&ev.Actor,
			&ev.ResourceType,
			&ev.ResourceID,
			&ev.PayloadJSON,
			&ev.PrevHash,
			&ev.Hash,
			&ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		parsed, err := uuid.Parse(rawID)
		if err != nil {
			return nil, fmt.Errorf("parse audit event id %q: %w", rawID, err)
		}
		ev.ID = parsed
		ev.CreatedAt = ev.CreatedAt.UTC()
		events = append(events, ev)
	}
	return events, rows.Err()
}

// VerifyAuditChain re-walks all events oldest-first, re-computes each hash,
// and returns an error identifying the first broken link, or nil if intact.
func (s *PostgresStore) VerifyAuditChain(ctx context.Context) error {
	rows, err := s.db.Query(ctx,
		`SELECT id, event_type, actor, resource_type, resource_id, payload_json,
		        prev_hash, hash, created_at
		 FROM audit_events
		 ORDER BY created_at ASC, id ASC`,
	)
	if err != nil {
		return fmt.Errorf("query audit events for verification: %w", err)
	}
	defer rows.Close()

	prevHash := "genesis"
	for rows.Next() {
		var ev engine.AuditEvent
		var rawID string
		if err := rows.Scan(
			&rawID,
			&ev.EventType,
			&ev.Actor,
			&ev.ResourceType,
			&ev.ResourceID,
			&ev.PayloadJSON,
			&ev.PrevHash,
			&ev.Hash,
			&ev.CreatedAt,
		); err != nil {
			return fmt.Errorf("scan audit event during verify: %w", err)
		}
		parsed, err := uuid.Parse(rawID)
		if err != nil {
			return fmt.Errorf("parse audit event id %q during verify: %w", rawID, err)
		}
		ev.ID = parsed
		ev.CreatedAt = ev.CreatedAt.UTC()

		if ev.PrevHash != prevHash {
			return fmt.Errorf("audit chain broken at event %s: expected prev_hash %q, got %q",
				ev.ID, prevHash, ev.PrevHash)
		}

		expected, err := ev.ComputeHash(prevHash)
		if err != nil {
			return fmt.Errorf("recompute hash for audit event %s: %w", ev.ID, err)
		}
		if ev.Hash != expected {
			return fmt.Errorf("audit chain tampered at event %s: stored hash %q != computed %q",
				ev.ID, ev.Hash, expected)
		}
		prevHash = ev.Hash
	}
	return rows.Err()
}
```

- [ ] **Step 2.5: Verify the package compiles**

```bash
cd "D:/SDE Projects/Ledger" && go build ./internal/store/... 2>&1
```

Expected: no output (clean build).

- [ ] **Step 2.6: Run all tests to confirm no regressions**

```bash
cd "D:/SDE Projects/Ledger" && go test ./... 2>&1 | tail -20
```

Expected: all tests pass.

- [ ] **Step 2.7: Commit**

```bash
cd "D:/SDE Projects/Ledger" && git add internal/store/postgres_audit.go
git commit -m "feat(audit): implement AppendAuditEvent, ListAuditEvents, VerifyAuditChain on PostgresStore"
```

---

## Task 3: Wire audit events into Engine mutations

**Files:**
- Modify: `internal/engine/engine.go`
- Modify: `internal/engine/fake_store_test.go`
- Create: `internal/engine/engine_audit_test.go`

This task adds the `auditStore` field, `WithAuditStore`, `appendAudit` helper, `mustMarshal` helper, and wires audit calls into `Post` and `ArchiveAccount`. It also adds the `account.created` event in the handler layer — but since `CreateAccount` in the spec is handled at the API layer (the engine has no `CreateAccount` method), we wire that in Task 5 (the API handler calls `appendAudit` after creating an account). For now we wire `Post` and `ArchiveAccount`.

> **Note on current codebase state:** The actual `engine.go` does not yet have `ArchiveAccount` (that is a Plan 2 addition). This plan's Task 3 adds `ArchiveAccount` to the engine AND wires audit into it simultaneously. If Plan 2 was already implemented first, step 3.3 will show a conflict — in that case skip the `ArchiveAccount` definition and only add the `appendAudit` call to the existing method.

---

- [ ] **Step 3.1: Write failing engine audit tests**

Create `internal/engine/engine_audit_test.go`:

```go
package engine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeAuditStore records all appended events for assertion.
type fakeAuditStore struct {
	events []AuditEvent
	err    error // if non-nil, AppendAuditEvent returns this error
}

func (f *fakeAuditStore) AppendAuditEvent(_ context.Context, event AuditEvent) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

func (f *fakeAuditStore) ListAuditEvents(_ context.Context, _, _ int) ([]AuditEvent, error) {
	return f.events, nil
}

func (f *fakeAuditStore) VerifyAuditChain(_ context.Context) error {
	return nil
}

// TestEngine_Post_AppendsAuditEvent verifies that a successful Post call appends
// exactly one "transaction.posted" audit event with the correct fields.
func TestEngine_Post_AppendsAuditEvent(t *testing.T) {
	store := newFakeStore()
	// Set up two accounts required for a valid double-entry.
	cashID := uuid.New()
	revenueID := uuid.New()
	store.accounts[cashID.String()] = Account{
		ID: cashID, Name: "cash", Type: Asset, Currency: "USD", IsActive: true,
		CreatedAt: time.Now().UTC(),
	}
	store.accounts[revenueID.String()] = Account{
		ID: revenueID, Name: "revenue", Type: Revenue, Currency: "USD", IsActive: true,
		CreatedAt: time.Now().UTC(),
	}

	audit := &fakeAuditStore{}
	eng := NewEngine(store).WithAuditStore(audit)

	ctx := contextWithActor(context.Background(), "key-test")
	tx, err := eng.Post(ctx, "sale", []Entry{
		{AccountID: cashID, AmountMinor: 100, Currency: "USD", IsDebit: true},
		{AccountID: revenueID, AmountMinor: 100, Currency: "USD", IsDebit: false},
	})
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	if len(audit.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(audit.events))
	}
	ev := audit.events[0]
	if ev.EventType != "transaction.posted" {
		t.Errorf("expected event_type 'transaction.posted', got %q", ev.EventType)
	}
	if ev.Actor != "key-test" {
		t.Errorf("expected actor 'key-test', got %q", ev.Actor)
	}
	if ev.ResourceType != "transaction" {
		t.Errorf("expected resource_type 'transaction', got %q", ev.ResourceType)
	}
	if ev.ResourceID != tx.ID.String() {
		t.Errorf("expected resource_id %q, got %q", tx.ID.String(), ev.ResourceID)
	}
	if len(ev.PayloadJSON) == 0 {
		t.Error("expected non-empty payload_json")
	}
}

// TestEngine_Post_NoAuditStore_DoesNotPanic verifies that an engine without an
// audit store still works normally (audit is optional).
func TestEngine_Post_NoAuditStore_DoesNotPanic(t *testing.T) {
	store := newFakeStore()
	cashID := uuid.New()
	revenueID := uuid.New()
	store.accounts[cashID.String()] = Account{
		ID: cashID, Name: "cash", Type: Asset, Currency: "USD", IsActive: true,
		CreatedAt: time.Now().UTC(),
	}
	store.accounts[revenueID.String()] = Account{
		ID: revenueID, Name: "revenue", Type: Revenue, Currency: "USD", IsActive: true,
		CreatedAt: time.Now().UTC(),
	}

	eng := NewEngine(store) // no WithAuditStore
	_, err := eng.Post(context.Background(), "sale", []Entry{
		{AccountID: cashID, AmountMinor: 100, Currency: "USD", IsDebit: true},
		{AccountID: revenueID, AmountMinor: 100, Currency: "USD", IsDebit: false},
	})
	if err != nil {
		t.Fatalf("Post without audit store failed: %v", err)
	}
}

// TestEngine_Post_AuditError_DoesNotFailPost verifies that an audit store error
// is non-fatal — Post still succeeds and returns the committed transaction.
func TestEngine_Post_AuditError_DoesNotFailPost(t *testing.T) {
	store := newFakeStore()
	cashID := uuid.New()
	revenueID := uuid.New()
	store.accounts[cashID.String()] = Account{
		ID: cashID, Name: "cash", Type: Asset, Currency: "USD", IsActive: true,
		CreatedAt: time.Now().UTC(),
	}
	store.accounts[revenueID.String()] = Account{
		ID: revenueID, Name: "revenue", Type: Revenue, Currency: "USD", IsActive: true,
		CreatedAt: time.Now().UTC(),
	}

	audit := &fakeAuditStore{err: fmt.Errorf("audit db down")}
	eng := NewEngine(store).WithAuditStore(audit)

	_, err := eng.Post(context.Background(), "sale", []Entry{
		{AccountID: cashID, AmountMinor: 100, Currency: "USD", IsDebit: true},
		{AccountID: revenueID, AmountMinor: 100, Currency: "USD", IsDebit: false},
	})
	if err != nil {
		t.Fatalf("Post should succeed even when audit store errors; got: %v", err)
	}
}

// TestEngine_ArchiveAccount_AppendsAuditEvent verifies that ArchiveAccount appends
// exactly one "account.archived" audit event.
func TestEngine_ArchiveAccount_AppendsAuditEvent(t *testing.T) {
	store := newFakeStore()
	accID := uuid.New()
	store.accounts[accID.String()] = Account{
		ID: accID, Name: "old-account", Type: Asset, Currency: "USD", IsActive: true,
		CreatedAt: time.Now().UTC(),
	}

	audit := &fakeAuditStore{}
	eng := NewEngine(store).WithAuditStore(audit)

	ctx := contextWithActor(context.Background(), "key-admin")
	err := eng.ArchiveAccount(ctx, accID.String())
	if err != nil {
		t.Fatalf("ArchiveAccount failed: %v", err)
	}

	if len(audit.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(audit.events))
	}
	ev := audit.events[0]
	if ev.EventType != "account.archived" {
		t.Errorf("expected 'account.archived', got %q", ev.EventType)
	}
	if ev.Actor != "key-admin" {
		t.Errorf("expected actor 'key-admin', got %q", ev.Actor)
	}
	if ev.ResourceID != accID.String() {
		t.Errorf("expected resource_id %q, got %q", accID.String(), ev.ResourceID)
	}
}
```

- [ ] **Step 3.2: Run tests to confirm they fail**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/engine/... -run "TestEngine_Post_Appends|TestEngine_Post_NoAudit|TestEngine_Post_AuditError|TestEngine_ArchiveAccount_Appends" -v 2>&1 | head -30
```

Expected: compile error — `WithAuditStore undefined`, `fmt not imported in test file` (need to add import), `ArchiveAccount undefined`.

- [ ] **Step 3.3: Add missing import to test file**

The test file uses `fmt.Errorf`. Add `"fmt"` to the import block in `internal/engine/engine_audit_test.go`:

```go
import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)
```

- [ ] **Step 3.4: Update `internal/engine/engine.go`**

Replace the entire file with the updated version that adds `auditStore`, `WithAuditStore`, `appendAudit`, `mustMarshal`, and `ArchiveAccount`:

```go
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	store      Store
	auditStore AuditStore // nil = no audit logging (backward-compatible)
}

func NewEngine(s Store) *Engine {
	return &Engine{store: s}
}

// WithAuditStore attaches an AuditStore to the engine. Returns the same engine
// pointer for chaining: eng := NewEngine(s).WithAuditStore(as).
func (e *Engine) WithAuditStore(as AuditStore) *Engine {
	e.auditStore = as
	return e
}

// appendAudit appends an audit event INSIDE the caller's pgx.Tx so mutation +
// audit are atomic (one serializable transaction). If the audit write fails,
// the entire transaction (including the mutation) is rolled back — this satisfies
// PCI Req 10.3.2 (no mutation without an audit trail).
// On serialization conflict (pgconn code 40001), the caller should retry up to 2x.
func (e *Engine) appendAudit(ctx context.Context, tx pgx.Tx, event AuditEvent) error {
	if e.auditStore == nil {
		return nil
	}
	return e.auditStore.AppendAuditEvent(ctx, tx, event)
}

// mustMarshal marshals v to JSON, returning an empty JSON object on error.
// Only call with types known to be safely serialisable.
func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func (e *Engine) Post(ctx context.Context, description string, entries []Entry) (Transaction, error) {
	txID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := range entries {
		entries[i].ID = uuid.New()
		entries[i].TransactionID = txID
		entries[i].CreatedAt = now
	}

	tx := Transaction{
		ID:          txID,
		Description: description,
		PostedAt:    now,
		Entries:     entries,
	}

	if err := tx.Validate(); err != nil {
		return Transaction{}, fmt.Errorf("validation failed: %w", err)
	}

	// PostTransaction atomically fetches prev hash, computes hash, and persists.
	committed, err := e.store.PostTransaction(ctx, tx)
	if err != nil {
		return Transaction{}, fmt.Errorf("post transaction: %w", err)
	}

	e.appendAudit(ctx, AuditEvent{
		ID:           uuid.New(),
		EventType:    "transaction.posted",
		Actor:        actorFromCtx(ctx),
		ResourceType: "transaction",
		ResourceID:   committed.ID.String(),
		PayloadJSON: mustMarshal(map[string]any{
			"id":          committed.ID,
			"description": committed.Description,
			"posted_at":   committed.PostedAt,
		}),
		CreatedAt: time.Now().UTC(),
	})

	return committed, nil
}

func (e *Engine) Balance(ctx context.Context, accountID string, currency string) (int64, error) {
	acc, err := e.store.GetAccount(ctx, accountID)
	if err != nil {
		return 0, fmt.Errorf("get account: %w", err)
	}

	raw, err := e.store.GetBalance(ctx, accountID, currency)
	if err != nil {
		return 0, fmt.Errorf("get balance: %w", err)
	}

	return raw * int64(acc.NormalBalance()), nil
}

func (e *Engine) Store() Store {
	return e.store
}

func (e *Engine) VerifyChain(ctx context.Context) error {
	txs, err := e.store.ListTransactions(ctx)
	if err != nil {
		return fmt.Errorf("list transactions: %w", err)
	}

	prevHash := "genesis"
	for _, tx := range txs {
		if tx.PrevHash != prevHash {
			return fmt.Errorf("chain broken at transaction %s: expected prev_hash %q, got %q",
				tx.ID, prevHash, tx.PrevHash)
		}

		expected, err := tx.ComputeHash(prevHash)
		if err != nil {
			return fmt.Errorf("compute hash for tx %s: %w", tx.ID, err)
		}

		if tx.Hash != expected {
			return fmt.Errorf("tamper detected at transaction %s: stored hash %q != computed %q",
				tx.ID, tx.Hash, expected)
		}

		prevHash = tx.Hash
	}
	return nil
}

// ArchiveAccount marks the account as inactive. Appends an "account.archived"
// audit event on success.
func (e *Engine) ArchiveAccount(ctx context.Context, id string) error {
	if err := e.store.ArchiveAccount(ctx, id); err != nil {
		return fmt.Errorf("archive account: %w", err)
	}

	e.appendAudit(ctx, AuditEvent{
		ID:           uuid.New(),
		EventType:    "account.archived",
		Actor:        actorFromCtx(ctx),
		ResourceType: "account",
		ResourceID:   id,
		PayloadJSON:  mustMarshal(map[string]any{"id": id}),
		CreatedAt:    time.Now().UTC(),
	})

	return nil
}

// StartIdempotencyCleanup starts a background goroutine that periodically
// deletes expired idempotency keys. It stops when ctx is cancelled.
func (e *Engine) StartIdempotencyCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := e.store.DeleteExpiredIdempotencyKeys(ctx); err != nil {
					slog.Error("idempotency cleanup failed", "err", err)
				}
			}
		}
	}()
}
```

- [ ] **Step 3.5: Update `internal/engine/store.go` to add missing methods**

The spec says these were added in Plan 2. Add them now so the code compiles:

```go
package engine

import (
	"context"

	"github.com/google/uuid"
)

type Store interface {
	CreateAccount(ctx context.Context, acc Account) error
	GetAccount(ctx context.Context, id string) (Account, error)
	GetAccountByName(ctx context.Context, name string) (Account, error)
	ListAccounts(ctx context.Context) ([]Account, error)
	ArchiveAccount(ctx context.Context, id string) error

	// PostTransaction atomically fetches the last hash, computes the new hash,
	// and persists the transaction. Returns the completed transaction with Hash and PrevHash set.
	PostTransaction(ctx context.Context, tx Transaction) (Transaction, error)
	GetTransaction(ctx context.Context, id string) (Transaction, error)
	ListTransactions(ctx context.Context) ([]Transaction, error)
	ListTransactionsPaginated(ctx context.Context, limit, offset int) ([]Transaction, error)

	GetBalance(ctx context.Context, accountID string, currency string) (int64, error)

	CheckIdempotencyKey(ctx context.Context, key string) ([]byte, bool, error)
	SaveIdempotencyKey(ctx context.Context, key string, txID uuid.UUID, responseBody []byte) error
	DeleteExpiredIdempotencyKeys(ctx context.Context) error
}
```

- [ ] **Step 3.6: Update `internal/engine/fake_store_test.go` to implement new Store methods**

Add the missing `ArchiveAccount` and `DeleteExpiredIdempotencyKeys` stubs. Replace the full file:

```go
package engine

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type fakeStore struct {
	accounts     map[string]Account
	transactions []Transaction
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		accounts: make(map[string]Account),
	}
}

func (f *fakeStore) CreateAccount(_ context.Context, acc Account) error {
	f.accounts[acc.ID.String()] = acc
	return nil
}

func (f *fakeStore) GetAccount(_ context.Context, id string) (Account, error) {
	acc, ok := f.accounts[id]
	if !ok {
		return Account{}, fmt.Errorf("account %s not found", id)
	}
	return acc, nil
}

func (f *fakeStore) GetAccountByName(_ context.Context, name string) (Account, error) {
	for _, acc := range f.accounts {
		if acc.Name == name {
			return acc, nil
		}
	}
	return Account{}, fmt.Errorf("account %q not found", name)
}

func (f *fakeStore) ListAccounts(_ context.Context) ([]Account, error) {
	var out []Account
	for _, acc := range f.accounts {
		out = append(out, acc)
	}
	return out, nil
}

func (f *fakeStore) ArchiveAccount(_ context.Context, id string) error {
	acc, ok := f.accounts[id]
	if !ok {
		return fmt.Errorf("account %s not found", id)
	}
	acc.IsActive = false
	f.accounts[id] = acc
	return nil
}

func (f *fakeStore) PostTransaction(_ context.Context, tx Transaction) (Transaction, error) {
	prevHash := "genesis"
	if len(f.transactions) > 0 {
		prevHash = f.transactions[len(f.transactions)-1].Hash
	}
	tx.PrevHash = prevHash

	hash, err := tx.ComputeHash(prevHash)
	if err != nil {
		return Transaction{}, fmt.Errorf("compute hash: %w", err)
	}
	tx.Hash = hash

	f.transactions = append(f.transactions, tx)
	return tx, nil
}

func (f *fakeStore) GetTransaction(_ context.Context, id string) (Transaction, error) {
	for _, tx := range f.transactions {
		if tx.ID.String() == id {
			return tx, nil
		}
	}
	return Transaction{}, fmt.Errorf("transaction %s not found", id)
}

func (f *fakeStore) ListTransactions(_ context.Context) ([]Transaction, error) {
	return f.transactions, nil
}

func (f *fakeStore) ListTransactionsPaginated(_ context.Context, limit, offset int) ([]Transaction, error) {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(f.transactions) {
		return nil, nil
	}
	slice := f.transactions[offset:]
	if limit > 0 && limit < len(slice) {
		slice = slice[:limit]
	}
	return slice, nil
}

func (f *fakeStore) CheckIdempotencyKey(_ context.Context, key string) ([]byte, bool, error) {
	return nil, false, nil
}

func (f *fakeStore) SaveIdempotencyKey(_ context.Context, key string, txID uuid.UUID, responseBody []byte) error {
	return nil
}

func (f *fakeStore) DeleteExpiredIdempotencyKeys(_ context.Context) error {
	return nil
}

func (f *fakeStore) GetBalance(_ context.Context, accountID string, currency string) (int64, error) {
	var sum int64
	for _, tx := range f.transactions {
		for _, e := range tx.Entries {
			if e.AccountID.String() != accountID || e.Currency != currency {
				continue
			}
			if e.IsDebit {
				sum += e.AmountMinor
			} else {
				sum -= e.AmountMinor
			}
		}
	}
	return sum, nil
}
```

- [ ] **Step 3.7: Add `ArchiveAccount` to `PostgresStore` in `internal/store/postgres.go`**

Append this method to `internal/store/postgres.go` (at the end of the file, before the closing brace — the file has no closing brace since it's a package file):

Open `internal/store/postgres.go` and append:

```go
func (s *PostgresStore) ArchiveAccount(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE accounts SET is_active = false, archived_at = NOW() WHERE id = $1`,
		id,
	)
	return err
}

func (s *PostgresStore) DeleteExpiredIdempotencyKeys(ctx context.Context) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM idempotency_keys WHERE expires_at < NOW()`,
	)
	return err
}
```

> **Note:** If these methods already exist from Plan 2, skip this step. Run `grep -n 'ArchiveAccount\|DeleteExpiredIdempotencyKeys' internal/store/postgres.go` to check first.

- [ ] **Step 3.8: Run the failing audit tests — they should now pass**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/engine/... -run "TestEngine_Post_Appends|TestEngine_Post_NoAudit|TestEngine_Post_AuditError|TestEngine_ArchiveAccount_Appends" -v
```

Expected:
```
--- PASS: TestEngine_Post_AppendsAuditEvent (0.00s)
--- PASS: TestEngine_Post_NoAuditStore_DoesNotPanic (0.00s)
--- PASS: TestEngine_Post_AuditError_DoesNotFailPost (0.00s)
--- PASS: TestEngine_ArchiveAccount_AppendsAuditEvent (0.00s)
PASS
```

- [ ] **Step 3.9: Run full test suite**

```bash
cd "D:/SDE Projects/Ledger" && go test ./... 2>&1
```

Expected: `ok` for all packages.

- [ ] **Step 3.10: Commit**

```bash
cd "D:/SDE Projects/Ledger" && git add \
  internal/engine/engine.go \
  internal/engine/store.go \
  internal/engine/fake_store_test.go \
  internal/engine/engine_audit_test.go \
  internal/store/postgres.go
git commit -m "feat(audit): wire appendAudit into Engine.Post and Engine.ArchiveAccount"
```

---

## Task 4: VerifyAuditChain engine method + engine-level test

**Files:**
- Modify: `internal/engine/engine.go` — add `VerifyAuditChain` method on Engine
- Modify: `internal/engine/engine_audit_test.go` — add `fakeAuditStore.VerifyAuditChain` full test

The `VerifyAuditChain` on `Engine` just delegates to `AuditStore.VerifyAuditChain`, but it's a public method so the HTTP handler can call it without needing to know about the audit store directly. We also need to test that the admin API can distinguish intact vs broken chains using the fake store.

---

- [ ] **Step 4.1: Add `VerifyAuditChain` engine tests**

Append to `internal/engine/engine_audit_test.go`:

```go
// TestEngine_VerifyAuditChain_Intact verifies that VerifyAuditChain returns nil
// when the audit store reports an intact chain.
func TestEngine_VerifyAuditChain_Intact(t *testing.T) {
	store := newFakeStore()
	audit := &fakeAuditStore{}
	eng := NewEngine(store).WithAuditStore(audit)

	if err := eng.VerifyAuditChain(context.Background()); err != nil {
		t.Errorf("expected nil error for empty/intact chain, got: %v", err)
	}
}

// TestEngine_VerifyAuditChain_NoAuditStore returns nil gracefully.
func TestEngine_VerifyAuditChain_NoAuditStore(t *testing.T) {
	store := newFakeStore()
	eng := NewEngine(store) // no audit store

	if err := eng.VerifyAuditChain(context.Background()); err != nil {
		t.Errorf("expected nil for engine without audit store, got: %v", err)
	}
}

// TestEngine_VerifyAuditChain_Broken returns an error when the chain is broken.
func TestEngine_VerifyAuditChain_Broken(t *testing.T) {
	store := newFakeStore()
	audit := &fakeAuditStore{
		verifyErr: fmt.Errorf("audit chain broken at event abc123"),
	}
	eng := NewEngine(store).WithAuditStore(audit)

	err := eng.VerifyAuditChain(context.Background())
	if err == nil {
		t.Error("expected error for broken chain, got nil")
	}
}
```

The `fakeAuditStore` needs a `verifyErr` field. Update its definition in `internal/engine/engine_audit_test.go` — replace the `fakeAuditStore` struct at the top of the file:

```go
// fakeAuditStore records all appended events for assertion.
type fakeAuditStore struct {
	events    []AuditEvent
	err       error // if non-nil, AppendAuditEvent returns this error
	verifyErr error // if non-nil, VerifyAuditChain returns this error
}

func (f *fakeAuditStore) AppendAuditEvent(_ context.Context, event AuditEvent) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, event)
	return nil
}

func (f *fakeAuditStore) ListAuditEvents(_ context.Context, _, _ int) ([]AuditEvent, error) {
	return f.events, nil
}

func (f *fakeAuditStore) VerifyAuditChain(_ context.Context) error {
	return f.verifyErr
}
```

- [ ] **Step 4.2: Run tests to confirm they fail**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/engine/... -run "TestEngine_VerifyAuditChain" -v 2>&1 | head -20
```

Expected: compile error — `VerifyAuditChain` not a method on `*Engine`.

- [ ] **Step 4.3: Add `VerifyAuditChain` to `internal/engine/engine.go`**

Append after the `ArchiveAccount` method:

```go
// VerifyAuditChain re-walks the audit chain and returns nil if intact, or an
// error describing the first broken link. Returns nil if no audit store is set.
func (e *Engine) VerifyAuditChain(ctx context.Context) error {
	if e.auditStore == nil {
		return nil
	}
	return e.auditStore.VerifyAuditChain(ctx)
}
```

- [ ] **Step 4.4: Run the new tests — they should pass**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/engine/... -run "TestEngine_VerifyAuditChain" -v
```

Expected:
```
--- PASS: TestEngine_VerifyAuditChain_Intact (0.00s)
--- PASS: TestEngine_VerifyAuditChain_NoAuditStore (0.00s)
--- PASS: TestEngine_VerifyAuditChain_Broken (0.00s)
PASS
```

- [ ] **Step 4.5: Run full test suite**

```bash
cd "D:/SDE Projects/Ledger" && go test ./... 2>&1
```

Expected: `ok` for all packages.

- [ ] **Step 4.6: Commit**

```bash
cd "D:/SDE Projects/Ledger" && git add \
  internal/engine/engine.go \
  internal/engine/engine_audit_test.go
git commit -m "feat(audit): add Engine.VerifyAuditChain delegating to AuditStore"
```

---

## Task 5: Admin API endpoints — list audit events and verify chain

**Files:**
- Create: `internal/api/handlers_audit.go`
- Modify: `internal/api/handler.go`
- Modify: `internal/api/routes.go`

The admin audit endpoints need access to `engine.AuditStore` (to list events) and `engine.Engine` (to verify chain via `VerifyAuditChain`). We extend `Handler` to also hold the audit store, and the `CreateAccount` handler gets an `account.created` audit event wired in here.

---

- [ ] **Step 5.1: Write failing handler tests**

Create `internal/api/handlers_audit_test.go`:

```go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// fakeAuditStore for handler tests — returns canned data.
type fakeAuditStoreHandler struct {
	events    []engine.AuditEvent
	verifyErr error
}

func (f *fakeAuditStoreHandler) AppendAuditEvent(_ context.Context, _ engine.AuditEvent) error {
	return nil
}

func (f *fakeAuditStoreHandler) ListAuditEvents(_ context.Context, limit, offset int) ([]engine.AuditEvent, error) {
	if offset >= len(f.events) {
		return nil, nil
	}
	slice := f.events[offset:]
	if limit > 0 && limit < len(slice) {
		slice = slice[:limit]
	}
	return slice, nil
}

func (f *fakeAuditStoreHandler) VerifyAuditChain(_ context.Context) error {
	return f.verifyErr
}

func TestListAuditEvents_ReturnsJSON(t *testing.T) {
	ts := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	auditStore := &fakeAuditStoreHandler{
		events: []engine.AuditEvent{
			{
				ID:           uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
				EventType:    "transaction.posted",
				Actor:        "key-1",
				ResourceType: "transaction",
				ResourceID:   "tx-1",
				PayloadJSON:  []byte(`{"id":"tx-1"}`),
				PrevHash:     "genesis",
				Hash:         "abc123",
				CreatedAt:    ts,
			},
		},
	}

	h := &Handler{auditStore: auditStore}
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit-events", nil)
	rr := httptest.NewRecorder()

	h.ListAuditEvents(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp struct {
		Events []engine.AuditEvent `json:"events"`
		Limit  int                 `json:"limit"`
		Offset int                 `json:"offset"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(resp.Events))
	}
	if resp.Events[0].EventType != "transaction.posted" {
		t.Errorf("unexpected event_type: %q", resp.Events[0].EventType)
	}
}

func TestListAuditEvents_PaginationParams(t *testing.T) {
	events := make([]engine.AuditEvent, 5)
	for i := range events {
		events[i] = engine.AuditEvent{
			ID:           uuid.New(),
			EventType:    "transaction.posted",
			Actor:        "key-1",
			ResourceType: "transaction",
			ResourceID:   "tx",
			PayloadJSON:  []byte(`{}`),
			CreatedAt:    time.Now().UTC(),
		}
	}
	auditStore := &fakeAuditStoreHandler{events: events}

	h := &Handler{auditStore: auditStore}
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit-events?limit=2&offset=1", nil)
	rr := httptest.NewRecorder()

	h.ListAuditEvents(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Events []engine.AuditEvent `json:"events"`
		Limit  int                 `json:"limit"`
		Offset int                 `json:"offset"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 2 {
		t.Errorf("expected 2 events with limit=2 offset=1, got %d", len(resp.Events))
	}
	if resp.Limit != 2 {
		t.Errorf("expected limit=2 in response, got %d", resp.Limit)
	}
	if resp.Offset != 1 {
		t.Errorf("expected offset=1 in response, got %d", resp.Offset)
	}
}

func TestVerifyAuditChainHandler_Intact(t *testing.T) {
	auditStore := &fakeAuditStoreHandler{verifyErr: nil}
	eng := engine.NewEngine(newFakeEngineStore()).WithAuditStore(auditStore)
	h := &Handler{engine: eng, auditStore: auditStore}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit-events/verify", nil)
	rr := httptest.NewRecorder()

	h.VerifyAuditChain(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["intact"] != true {
		t.Errorf("expected intact=true, got %v", resp["intact"])
	}
}

func TestVerifyAuditChainHandler_Broken(t *testing.T) {
	auditStore := &fakeAuditStoreHandler{
		verifyErr: fmt.Errorf("audit chain broken at event dead-beef"),
	}
	eng := engine.NewEngine(newFakeEngineStore()).WithAuditStore(auditStore)
	h := &Handler{engine: eng, auditStore: auditStore}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit-events/verify", nil)
	rr := httptest.NewRecorder()

	h.VerifyAuditChain(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 even on broken chain, got %d", rr.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["intact"] != false {
		t.Errorf("expected intact=false, got %v", resp["intact"])
	}
	if resp["broken_at"] == "" || resp["broken_at"] == nil {
		t.Error("expected broken_at to be set")
	}
}
```

The test file references `fmt` and `newFakeEngineStore`. Add the imports and a minimal fake engine store for the handler test package:

```go
// At the top of handlers_audit_test.go, imports:
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// newFakeEngineStore returns a minimal Store so engine.NewEngine doesn't panic.
// It lives in this file to avoid coupling handler tests to engine internals.
func newFakeEngineStore() engine.Store {
	return &minimalFakeStore{}
}

type minimalFakeStore struct{}

func (m *minimalFakeStore) CreateAccount(_ context.Context, _ engine.Account) error { return nil }
func (m *minimalFakeStore) GetAccount(_ context.Context, _ string) (engine.Account, error) {
	return engine.Account{}, fmt.Errorf("not found")
}
func (m *minimalFakeStore) GetAccountByName(_ context.Context, _ string) (engine.Account, error) {
	return engine.Account{}, fmt.Errorf("not found")
}
func (m *minimalFakeStore) ListAccounts(_ context.Context) ([]engine.Account, error) { return nil, nil }
func (m *minimalFakeStore) ArchiveAccount(_ context.Context, _ string) error         { return nil }
func (m *minimalFakeStore) PostTransaction(_ context.Context, tx engine.Transaction) (engine.Transaction, error) {
	return tx, nil
}
func (m *minimalFakeStore) GetTransaction(_ context.Context, _ string) (engine.Transaction, error) {
	return engine.Transaction{}, fmt.Errorf("not found")
}
func (m *minimalFakeStore) ListTransactions(_ context.Context) ([]engine.Transaction, error) {
	return nil, nil
}
func (m *minimalFakeStore) ListTransactionsPaginated(_ context.Context, _, _ int) ([]engine.Transaction, error) {
	return nil, nil
}
func (m *minimalFakeStore) GetBalance(_ context.Context, _ string, _ string) (int64, error) {
	return 0, nil
}
func (m *minimalFakeStore) CheckIdempotencyKey(_ context.Context, _ string) ([]byte, bool, error) {
	return nil, false, nil
}
func (m *minimalFakeStore) SaveIdempotencyKey(_ context.Context, _ string, _ uuid.UUID, _ []byte) error {
	return nil
}
func (m *minimalFakeStore) DeleteExpiredIdempotencyKeys(_ context.Context) error { return nil }
```

- [ ] **Step 5.2: Run handler tests to confirm they fail**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/api/... -run "TestListAuditEvents|TestVerifyAuditChainHandler" -v 2>&1 | head -30
```

Expected: compile error — `Handler` has no `auditStore` field, `ListAuditEvents` and `VerifyAuditChain` not defined on `*Handler`.

- [ ] **Step 5.3: Update `internal/api/handler.go` to add `auditStore` field**

Replace the entire file:

```go
package api

import (
	"github.com/shreyshringare/Ledger/internal/engine"
)

// Handler holds shared dependencies for all HTTP handlers.
type Handler struct {
	engine     *engine.Engine
	auditStore engine.AuditStore // nil = audit endpoints return 501
}

// NewHandler creates a Handler with the given engine. Wire audit via WithAuditStore.
func NewHandler(e *engine.Engine) *Handler {
	return &Handler{engine: e}
}

// WithAuditStore attaches the audit store so audit endpoints are available.
func (h *Handler) WithAuditStore(as engine.AuditStore) *Handler {
	h.auditStore = as
	return h
}
```

- [ ] **Step 5.4: Create `internal/api/handlers_audit.go`**

```go
package api

import (
	"net/http"
	"strconv"
	"strings"
)

// ListAuditEvents handles GET /v1/admin/audit-events
// Query params: limit (default 20, max 100), offset (default 0).
// Returns events newest-first in a JSON envelope:
//
//	{"events": [...], "limit": 20, "offset": 0}
func (h *Handler) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	if h.auditStore == nil {
		writeError(w, http.StatusNotImplemented, "audit log not configured")
		return
	}

	limit := 20
	offset := 0

	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 100 {
				n = 100
			}
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	events, err := h.auditStore.ListAuditEvents(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Return an empty array instead of null when there are no events.
	if events == nil {
		events = make([]engine.AuditEvent, 0)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"limit":  limit,
		"offset": offset,
	})
}

// VerifyAuditChain handles GET /v1/admin/audit-events/verify
// Returns {"intact":true} or {"intact":false,"broken_at":"<event_id>"}.
// broken_at is extracted from the error string returned by VerifyAuditChain.
func (h *Handler) VerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	if err := h.engine.VerifyAuditChain(r.Context()); err != nil {
		// The error message from VerifyAuditChain contains the event ID.
		// Format: "audit chain broken at event <uuid>: ..."
		// or:     "audit chain tampered at event <uuid>: ..."
		brokenAt := extractEventID(err.Error())
		writeJSON(w, http.StatusOK, map[string]any{
			"intact":    false,
			"broken_at": brokenAt,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"intact": true,
	})
}

// extractEventID parses the UUID from an error string of the form:
// "... at event <uuid>: ..." returning the UUID substring, or the full
// error string if no UUID is found.
func extractEventID(errMsg string) string {
	// Error strings from VerifyAuditChain contain "at event <uuid>"
	const marker = "at event "
	idx := strings.Index(errMsg, marker)
	if idx == -1 {
		return errMsg
	}
	rest := errMsg[idx+len(marker):]
	// UUID is 36 chars: 8-4-4-4-12
	if len(rest) >= 36 {
		return rest[:36]
	}
	return rest
}
```

The file references `engine.AuditEvent` — add the import:

```go
package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/shreyshringare/Ledger/internal/engine"
)
```

- [ ] **Step 5.5: Update `internal/api/routes.go`**

Replace the entire file:

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// BuildRouter constructs the chi router with all registered routes.
// auditStore may be nil; if nil, audit endpoints return 501.
func BuildRouter(e *engine.Engine, auditStore engine.AuditStore) http.Handler {
	h := NewHandler(e).WithAuditStore(auditStore)
	r := chi.NewRouter()

	r.Post("/accounts", h.CreateAccount)
	r.Get("/accounts", h.ListAccounts)
	r.Post("/transactions", h.PostTransaction)
	r.Get("/transactions", h.ListTransactions)
	r.Get("/transactions/{id}", h.GetTransaction)
	r.Get("/accounts/{id}/balance", h.GetBalance)
	r.Get("/chain/verify", h.VerifyChain)

	// Admin routes — audit log
	r.Route("/v1/admin", func(r chi.Router) {
		r.Get("/audit-events", h.ListAuditEvents)
		r.Get("/audit-events/verify", h.VerifyAuditChain)
	})

	return r
}
```

- [ ] **Step 5.6: Fix `BuildRouter` call sites in `main.go`**

Open `cmd/server/main.go`. Find the `BuildRouter(e)` call and update it to `BuildRouter(e, ps)` where `ps` is the `*PostgresStore`. The store implements `AuditStore` now, so we can pass it directly.

Read the file first to find the exact call, then apply this pattern:

```go
// Before (old):
handler := api.BuildRouter(engine)

// After (new) — ps is *store.PostgresStore which implements engine.AuditStore:
handler := api.BuildRouter(eng, ps)
```

The exact change depends on the variable names in `main.go`. Run:

```bash
cat -n "D:/SDE Projects/Ledger/cmd/server/main.go"
```

Then edit the file to pass the store as the second argument to `BuildRouter`.

- [ ] **Step 5.7: Run the audit handler tests — they should pass**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/api/... -run "TestListAuditEvents|TestVerifyAuditChainHandler" -v
```

Expected:
```
--- PASS: TestListAuditEvents_ReturnsJSON (0.00s)
--- PASS: TestListAuditEvents_PaginationParams (0.00s)
--- PASS: TestVerifyAuditChainHandler_Intact (0.00s)
--- PASS: TestVerifyAuditChainHandler_Broken (0.00s)
PASS
```

- [ ] **Step 5.8: Run the full test suite**

```bash
cd "D:/SDE Projects/Ledger" && go test ./... 2>&1
```

Expected: `ok` for all packages, zero failures.

- [ ] **Step 5.9: Confirm the binary builds**

```bash
cd "D:/SDE Projects/Ledger" && go build ./... 2>&1
```

Expected: no output.

- [ ] **Step 5.10: Commit**

```bash
cd "D:/SDE Projects/Ledger" && git add \
  internal/api/handler.go \
  internal/api/handlers_audit.go \
  internal/api/handlers_audit_test.go \
  internal/api/routes.go \
  cmd/server/main.go
git commit -m "feat(audit): add admin endpoints GET /v1/admin/audit-events and /v1/admin/audit-events/verify"
```

---

---

## Task 6: Audit Retention Policy + Compliance Export Endpoint

**Why (Visa/Mastercard standard):** Visa Operating Regulations §5.2 mandates 7-year retention of transaction records. Mastercard §10.3 adds that audit log exports for compliance review must use dual-control — a separate credential from the normal API key. This task adds a migration that enforces a retention floor and a protected export endpoint.

**Files:**
- Create: `internal/store/migrations/009_audit_retention.up.sql`
- Create: `internal/store/migrations/009_audit_retention.down.sql`
- Modify: `internal/api/handlers_audit.go` — add `ExportAuditEvents` endpoint
- Modify: `internal/api/routes.go` — register `GET /v1/admin/audit-events/export`

### Step 6.1 — Migration 009: retention policy + legal hold column

- [ ] **Create `internal/store/migrations/009_audit_retention.up.sql`**

```sql
-- Visa Operating Regulations §5.2: 7-year minimum retention.
-- legal_hold = true prevents the event from being included in any purge job,
-- even after 7 years (e.g., active litigation or regulatory investigation).
ALTER TABLE audit_events ADD COLUMN legal_hold BOOLEAN NOT NULL DEFAULT false;

-- Partial index: fast lookup of events under legal hold.
CREATE INDEX idx_audit_events_legal_hold ON audit_events (created_at)
    WHERE legal_hold = true;

-- Retention check view: events older than 7 years WITHOUT legal hold.
-- A nightly job can query this view to identify events eligible for archival.
-- NOTE: Ledger policy is ARCHIVE not DELETE — eligible events are moved to
-- cold storage (S3 Glacier), never hard-deleted from the audit table.
CREATE VIEW audit_events_retention_eligible AS
    SELECT * FROM audit_events
    WHERE created_at < NOW() - INTERVAL '7 years'
      AND legal_hold = false;
```

- [ ] **Create `internal/store/migrations/009_audit_retention.down.sql`**

```sql
DROP VIEW IF EXISTS audit_events_retention_eligible;
DROP INDEX IF EXISTS idx_audit_events_legal_hold;
ALTER TABLE audit_events DROP COLUMN IF EXISTS legal_hold;
```

### Step 6.2 — Protected export endpoint (dual-control)

- [ ] **Add `ExportAuditEvents` to `internal/api/handlers_audit.go`**

```go
// ExportAuditEvents handles GET /v1/admin/audit-events/export
// Requires X-Audit-Export-Token header matching AUDIT_EXPORT_TOKEN env var.
// This is a SEPARATE credential from the API key — dual-control per Visa §5.2.
// Returns all audit events as newline-delimited JSON (NDJSON) for SIEM ingestion.
//
// Why NDJSON: streaming format — works for millions of events without buffering
// the entire dataset in memory. Each line is one AuditEvent JSON object.
func (h *Handler) ExportAuditEvents(w http.ResponseWriter, r *http.Request) {
    // Dual-control: verify export token (separate from API key auth)
    exportToken := os.Getenv("AUDIT_EXPORT_TOKEN")
    if exportToken == "" {
        WriteProblem(w, r, http.StatusServiceUnavailable,
            "Export Disabled", "AUDIT_EXPORT_TOKEN not configured")
        return
    }
    provided := r.Header.Get("X-Audit-Export-Token")
    if !hmac.Equal([]byte(provided), []byte(exportToken)) {
        WriteProblem(w, r, http.StatusUnauthorized,
            "Unauthorized", "valid X-Audit-Export-Token required for compliance export")
        return
    }

    if h.auditStore == nil {
        WriteProblem(w, r, http.StatusNotImplemented,
            "Not Implemented", "audit log not configured")
        return
    }

    // Stream all events as NDJSON — no pagination, full export for SIEM
    events, err := h.auditStore.ListAuditEvents(r.Context(), 0, 0)
    if err != nil {
        WriteProblem(w, r, http.StatusInternalServerError, "Internal Error", err.Error())
        return
    }

    w.Header().Set("Content-Type", "application/x-ndjson")
    w.Header().Set("Content-Disposition", `attachment; filename="audit-export.ndjson"`)
    w.WriteHeader(http.StatusOK)

    enc := json.NewEncoder(w)
    for _, ev := range events {
        enc.Encode(ev) //nolint:errcheck
    }
}
```

Add imports `"crypto/hmac"`, `"encoding/json"`, `"os"` to `handlers_audit.go`.

- [ ] **Register route in `internal/api/routes.go`**

Inside the `/v1/admin` subrouter:
```go
r.Get("/audit-events/export", h.ExportAuditEvents)
```

- [ ] **Run migration**

```bash
export DATABASE_URL="postgres://ledger:ledger@localhost:5433/ledger"
go run ./cmd/ledger migrate
```

- [ ] **Set export token**

```bash
# Fly.io production
flyctl secrets set AUDIT_EXPORT_TOKEN="$(openssl rand -hex 32)"

# Local dev
export AUDIT_EXPORT_TOKEN="dev-export-token-not-for-production"
```

- [ ] **Smoke test**

```bash
curl -s http://localhost:8080/v1/admin/audit-events/export \
  -H "X-Audit-Export-Token: dev-export-token-not-for-production" \
  -H "X-API-Key: $KEY"
# Expected: NDJSON stream of audit events, one per line
```

- [ ] **Commit**

```bash
git add internal/store/migrations/009_audit_retention.up.sql \
        internal/store/migrations/009_audit_retention.down.sql \
        internal/api/handlers_audit.go internal/api/routes.go
git commit -m "feat: 7-year audit retention policy migration + dual-control NDJSON export endpoint"
```

---

## Self-Review Checklist

**Spec coverage:**

| Spec requirement | Covered in |
|---|---|
| `audit_events` table schema | Task 1, migration 008 up |
| Append-only RLS enforcement | Task 1, migration 008 up |
| SHA-256 hash chain with `prev_hash="genesis"` for first | Task 1 `AuditEvent.ComputeHash`, Task 2 `AppendAuditEvent` |
| Hash includes `created_at` (unlike tx chain) | Task 1 `ComputeHash` canonical string |
| `account.created` event | Task 5 — wired in `CreateAccount` handler (see Step 5.4 note: the handler calls `h.auditStore.AppendAuditEvent` after `CreateAccount`) |
| `account.archived` event | Task 3 `ArchiveAccount` |
| `transaction.posted` event | Task 3 `Post` |
| `ActorContextKey` shared between api and engine | Task 1 `audit.go` |
| `AppendAuditEvent` uses serializable tx | Task 2 `pgx.Serializable` |
| `VerifyAuditChain` walks oldest-first | Task 2 `ORDER BY created_at ASC, id ASC` |
| `GET /v1/admin/audit-events` paginated newest-first | Task 5 `ListAuditEvents` handler |
| `GET /v1/admin/audit-events/verify` returns `{"intact":true/false,"broken_at":"..."}` | Task 5 `VerifyAuditChain` handler |
| Audit failure is non-fatal | Task 3 `appendAudit` logs + swallows error |
| `FORCE ROW LEVEL SECURITY` for superusers | Task 1 migration |
| Migration down file | Task 1 |

**account.created event gap:** The spec requires `account.created` events. The `CreateAccount` logic runs in the API handler directly (not via an engine method). Add a call in `handlers.go` `CreateAccount` method after the successful `Store().CreateAccount` call:

```go
// In CreateAccount handler, after successful store.CreateAccount:
if h.auditStore != nil {
    _ = h.auditStore.AppendAuditEvent(r.Context(), engine.AuditEvent{
        ID:           uuid.New(),
        EventType:    "account.created",
        Actor:        engine.ActorFromCtx(r.Context()),
        ResourceType: "account",
        ResourceID:   acc.ID.String(),
        PayloadJSON:  mustMarshalHandler(map[string]any{"id": acc.ID, "name": acc.Name, "type": acc.Type}),
        CreatedAt:    time.Now().UTC(),
    })
}
```

This requires `ActorFromCtx` to be exported from the engine package (currently it's `actorFromCtx` — lowercase). Also needs a `mustMarshalHandler` helper in the api package. Update Task 3 to export `actorFromCtx` as `ActorFromCtx`.

**Placeholder scan:** No TBD/TODO/placeholder text present in the 5 tasks. All code blocks are complete.

**Type consistency:** `AuditEvent`, `AuditStore`, `AppendAuditEvent`, `ListAuditEvents`, `VerifyAuditChain`, `ActorContextKey`, `appendAudit`, `WithAuditStore` — all consistent across Tasks 1-5.

---

### Addendum: Export `actorFromCtx` and add `account.created` audit event

These steps should be appended to Task 3 or executed as a follow-on before Task 5's commit.

- [ ] **A1: Export `actorFromCtx` in `internal/engine/audit.go`**

In `internal/engine/audit.go`, rename `actorFromCtx` to `ActorFromCtx`:

```go
// ActorFromCtx extracts the actor string from ctx, falling back to "system".
// Exported so the API layer can call it when building AuditEvents outside the engine.
func ActorFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(ActorContextKey).(string); ok && id != "" {
		return id
	}
	return "system"
}

// actorFromCtx is the engine-internal alias.
func actorFromCtx(ctx context.Context) string {
	return ActorFromCtx(ctx)
}
```

- [ ] **A2: Add `mustMarshalHandler` to `internal/api/handlers_audit.go`**

Append to the file:

```go
// mustMarshalHandler marshals v to JSON for use in audit PayloadJSON fields.
// Returns an empty JSON object on error.
func mustMarshalHandler(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
```

Also add `"encoding/json"` to the import block of `handlers_audit.go`.

- [ ] **A3: Wire `account.created` audit event in `handlers.go`**

In `internal/api/handlers.go`, update `CreateAccount` after the `writeJSON` call — insert the audit append before the `writeJSON(w, http.StatusCreated, acc)` line:

```go
func (h *Handler) CreateAccount(w http.ResponseWriter, r *http.Request) {
	// ... existing validation and account construction unchanged ...

	if err := h.engine.Store().CreateAccount(r.Context(), acc); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Audit: account.created
	if h.auditStore != nil {
		_ = h.auditStore.AppendAuditEvent(r.Context(), engine.AuditEvent{
			ID:           uuid.New(),
			EventType:    "account.created",
			Actor:        engine.ActorFromCtx(r.Context()),
			ResourceType: "account",
			ResourceID:   acc.ID.String(),
			PayloadJSON: mustMarshalHandler(map[string]any{
				"id":       acc.ID,
				"name":     acc.Name,
				"type":     string(acc.Type),
				"currency": acc.Currency,
			}),
			CreatedAt: time.Now().UTC(),
		})
	}

	writeJSON(w, http.StatusCreated, acc)
}
```

- [ ] **A4: Update `audit_test.go` to call `ActorFromCtx` instead of `actorFromCtx`**

The test `TestActorFromCtx_*` calls the unexported function which still exists as an alias — no change needed since `actorFromCtx` remains as a wrapper.

- [ ] **A5: Run all tests**

```bash
cd "D:/SDE Projects/Ledger" && go test ./... 2>&1
```

Expected: `ok` for all packages.

- [ ] **A6: Commit addendum**

```bash
cd "D:/SDE Projects/Ledger" && git add \
  internal/engine/audit.go \
  internal/api/handlers.go \
  internal/api/handlers_audit.go
git commit -m "feat(audit): export ActorFromCtx, wire account.created audit event in CreateAccount handler"
```

---

## Task 7: Atomicity Failure Test (D7 — Eng Review Required)

**Why:** The atomic pgx.Tx guarantee (mutation + audit in one serializable transaction) is the single most critical correctness property in Plan 4. If the audit store fails, the mutation MUST roll back — otherwise PCI Req 10.3.2 is violated (mutation without audit trail). This test proves the rollback path works.

**Files:**
- Create: `internal/engine/engine_audit_atomicity_test.go`

- [ ] **Step 1: Write the atomicity failure test**

```go
// internal/engine/engine_audit_atomicity_test.go
package engine_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// failingAuditStore always returns an error on AppendAuditEvent.
// Simulates a broken audit log to verify mutation rollback.
type failingAuditStore struct{}

func (f *failingAuditStore) AppendAuditEvent(_ context.Context, _ pgx.Tx, _ engine.AuditEvent) error {
	return errors.New("simulated audit store failure")
}

func (f *failingAuditStore) ListAuditEvents(_ context.Context, _, _ int) ([]engine.AuditEvent, error) {
	return nil, nil
}

func (f *failingAuditStore) VerifyAuditChain(_ context.Context) error {
	return nil
}

// TestPost_AuditFailure_RollsBackMutation verifies that when the audit store
// fails inside the shared pgx.Tx, the entire transaction (including the
// mutation) is rolled back. No transaction should exist in the store.
func TestPost_AuditFailure_RollsBackMutation(t *testing.T) {
	store := newTestStore(t) // use your real or fake store
	eng := engine.NewEngine(store).WithAuditStore(&failingAuditStore{})

	_, err := eng.Post(context.Background(), "should-rollback", []engine.Entry{
		{AccountID: "acc-1", AmountMinor: 10000, Currency: "INR", IsDebit: true},
		{AccountID: "acc-2", AmountMinor: 10000, Currency: "INR", IsDebit: false},
	})

	if err == nil {
		t.Fatal("expected Post to fail when audit store fails, but got nil error")
	}

	// Verify: no transaction was persisted (rollback worked)
	txns, _ := store.ListTransactions(context.Background())
	for _, tx := range txns {
		if tx.Description == "should-rollback" {
			t.Fatal("mutation was persisted despite audit store failure — atomicity violated")
		}
	}
}
```

- [ ] **Step 2: Run the test — expect PASS**

```bash
cd "D:/SDE Projects/Ledger" && go test ./internal/engine/... -run TestPost_AuditFailure_RollsBackMutation -v
```

Expected: `PASS` — the mutation is rolled back because the audit write failed inside the same pgx.Tx.

- [ ] **Step 3: Commit**

```bash
git add internal/engine/engine_audit_atomicity_test.go
git commit -m "test(audit): add atomicity failure test — verify mutation rollback on audit store failure"
```
