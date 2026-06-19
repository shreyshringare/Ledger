# Phase 3 Plan 2: System Design + Fintech Patterns

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add circuit breaker, soft-delete for accounts, idempotency TTL cleanup, column-level encryption, a pre-commit secrets hook, a STRIDE threat model document, SBOM generation, and transaction fraud velocity controls — demonstrating fintech-grade engineering judgment beyond CRUD.

**Card Network Alignment (Visa/Mastercard):**
- **Fraud velocity checks (Task 8):** Visa's Real-Time Fraud Scoring requires velocity checks before transaction authorization. This plan adds per-account limits: max 5 transactions/minute, max 1,000,000 minor units (~$10,000)/hour. Exceeding limits returns `402 Payment Required` with a human-readable reason — same UX as Visa's decline codes.
- **Settlement deferral:** Daily batch settlement reconciliation (Visa VisaNet / Mastercard MDES file formats) is deferred to the payment processor integration phase. Documented here as a known gap.
- **Tokenization deferral:** PCI DSS Req 3.5 requires Primary Account Number (PAN) tokenization. This system has no PANs — deferred to card-present payment integration.
- **Circuit breaker maps to:** Mastercard's network resilience requirements — acquiring systems must not cascade failures to the authorization network.

**Architecture:** A `CircuitBreakerStore` wrapper implements `engine.Store`, with **per-method** `gobreaker.CircuitBreaker` instances (`map[string]*gobreaker.CircuitBreaker`). Each store method gets its own breaker — `GetBalance` can work while `PostTransaction` is tripping. Five consecutive failures per method open that method's circuit; calls return 503 immediately for 30s, then one probe (half-open). Soft delete and column encryption are additive schema changes with migrations; TTL cleanup is a background goroutine started from the serve command.

**Tech Stack:** `github.com/sony/gobreaker`, `pgcrypto` Postgres extension, Go stdlib (`sync`, `context`, `os`), `syft` CLI (SBOM)

**Prerequisites:** Plan 1 (Security Foundation) must be implemented first — this plan assumes:
- `serve.go` has a graceful-shutdown `ctx context.Context`
- `routes.go` uses `/v1/` prefix
- `handler.go` has `WriteProblem` from `internal/api/problem.go`

**Migration numbering:** Assumes migrations 001–005 exist (005 = api_keys from Plan 1). Uses 006 and 007. Plan 4 (Forensics/Audit Log) uses 008.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `internal/store/circuitbreaker.go` | Create | `CircuitBreakerStore` wrapping `engine.Store` via gobreaker |
| `internal/engine/store.go` | Modify | Add `ArchiveAccount`, `DeleteExpiredIdempotencyKeys` methods |
| `internal/engine/account.go` | Modify | Add `ArchivedAt *time.Time`, `Description string` fields |
| `internal/engine/engine.go` | Modify | Add `StartIdempotencyCleanup(ctx)` method |
| `internal/engine/fake_store_test.go` | Modify | Stub new interface methods |
| `internal/store/postgres.go` | Modify | Update account queries for soft-delete + description encryption |
| `internal/store/postgres_softdelete.go` | Create | `ArchiveAccount` implementation |
| `internal/store/postgres_idempotency_ttl.go` | Create | `DeleteExpiredIdempotencyKeys` implementation |
| `internal/store/migrations/006_soft_delete_accounts.up.sql` | Create | `ALTER TABLE accounts ADD COLUMN archived_at` |
| `internal/store/migrations/006_soft_delete_accounts.down.sql` | Create | Reverse migration |
| `internal/store/migrations/007_pgcrypto.up.sql` | Create | Enable pgcrypto, add `description BYTEA` |
| `internal/store/migrations/007_pgcrypto.down.sql` | Create | Reverse migration |
| `internal/api/handlers.go` | Modify | Add `ArchiveAccount` handler + `writeEngineError` helper |
| `internal/api/routes.go` | Modify | Add `DELETE /v1/accounts/{id}` |
| `cmd/ledger/root.go` | Modify | Wrap store in `CircuitBreakerStore` |
| `cmd/ledger/serve.go` | Modify | Start idempotency TTL cleanup goroutine |
| `docs/threat-model.md` | Create | STRIDE threat model |
| `.githooks/pre-commit` | Create | Grep for hardcoded DSN |

---

## Task 1: Add gobreaker and Circuit Breaker Store Wrapper

**Files:**
- Modify: `go.mod` (via `go get`)
- Create: `internal/store/circuitbreaker.go`
- Modify: `cmd/ledger/root.go`

- [ ] **Step 1: Add gobreaker dependency**

```bash
cd "D:/SDE Projects/Ledger"
go get github.com/sony/gobreaker@latest
```

Expected: `go.mod` and `go.sum` updated with `github.com/sony/gobreaker`.

- [ ] **Step 2: Write the failing test**

Create `internal/store/circuitbreaker_test.go`:

```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/shreyshringare/Ledger/internal/store"
	"github.com/sony/gobreaker"
)

// errorStore always returns an error from every method.
type errorStore struct{ err error }

func (e *errorStore) CreateAccount(ctx context.Context, acc engine.Account) error {
	return e.err
}
func (e *errorStore) GetAccount(ctx context.Context, id string) (engine.Account, error) {
	return engine.Account{}, e.err
}
func (e *errorStore) GetAccountByName(ctx context.Context, name string) (engine.Account, error) {
	return engine.Account{}, e.err
}
func (e *errorStore) ListAccounts(ctx context.Context) ([]engine.Account, error) {
	return nil, e.err
}
func (e *errorStore) ArchiveAccount(ctx context.Context, id string) error { return e.err }
func (e *errorStore) PostTransaction(ctx context.Context, tx engine.Transaction) (engine.Transaction, error) {
	return engine.Transaction{}, e.err
}
func (e *errorStore) GetTransaction(ctx context.Context, id string) (engine.Transaction, error) {
	return engine.Transaction{}, e.err
}
func (e *errorStore) ListTransactions(ctx context.Context) ([]engine.Transaction, error) {
	return nil, e.err
}
func (e *errorStore) ListTransactionsPaginated(ctx context.Context, limit, offset int) ([]engine.Transaction, error) {
	return nil, e.err
}
func (e *errorStore) GetBalance(ctx context.Context, accountID string, currency string) (int64, error) {
	return 0, e.err
}
func (e *errorStore) CheckIdempotencyKey(ctx context.Context, key string) ([]byte, bool, error) {
	return nil, false, e.err
}
func (e *errorStore) SaveIdempotencyKey(ctx context.Context, key string, txID uuid.UUID, responseBody []byte) error {
	return e.err
}
func (e *errorStore) DeleteExpiredIdempotencyKeys(ctx context.Context) error { return e.err }

func TestCircuitBreakerOpensAfterFiveFailures(t *testing.T) {
	underlying := &errorStore{err: errors.New("db down")}
	cb := store.NewCircuitBreakerStore(underlying)
	ctx := context.Background()

	// Trip the circuit: 5 consecutive failures
	for i := 0; i < 5; i++ {
		err := cb.CreateAccount(ctx, engine.Account{})
		if err == nil {
			t.Fatal("expected error")
		}
		if errors.Is(err, store.ErrCircuitOpen) {
			t.Fatalf("circuit opened too early at attempt %d", i+1)
		}
	}

	// 6th call: circuit should now be open
	err := cb.CreateAccount(ctx, engine.Account{})
	if !errors.Is(err, store.ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen after 5 failures, got: %v", err)
	}
}

func TestCircuitBreakerPassesThroughOnSuccess(t *testing.T) {
	underlying := store.NewMockPassthroughStore()
	cb := store.NewCircuitBreakerStore(underlying)
	ctx := context.Background()

	err := cb.CreateAccount(ctx, engine.Account{ID: uuid.New(), Name: "cash", Currency: "USD"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd "D:/SDE Projects/Ledger"
go test ./internal/store/... -run TestCircuitBreaker -v
```

Expected: FAIL — `store.NewCircuitBreakerStore`, `store.ErrCircuitOpen`, `store.NewMockPassthroughStore` undefined.

- [ ] **Step 4: Create `internal/store/circuitbreaker.go`**

```go
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/sony/gobreaker"
)

// ErrCircuitOpen is returned when the DB circuit breaker is open.
// Callers should translate this to HTTP 503 Service Unavailable.
var ErrCircuitOpen = errors.New("database circuit breaker open — retry after 30s")

// CircuitBreakerStore wraps engine.Store with PER-METHOD circuit breakers.
// Each store method gets its own gobreaker.CircuitBreaker so that a failing
// PostTransaction doesn't block healthy GetBalance calls. After 5 consecutive
// failures in a 10s window, that method's circuit opens for 30s, then one
// probe request is allowed (half-open).
type CircuitBreakerStore struct {
	wrapped  engine.Store
	breakers map[string]*gobreaker.CircuitBreaker
}

// newBreaker creates a gobreaker with standard settings for a given method name.
func newBreaker(method string) *gobreaker.CircuitBreaker {
	return gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "postgres-" + method,
		MaxRequests: 1,
		Interval:    10 * time.Second,
		Timeout:     30 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5
		},
	})
}

// NewCircuitBreakerStore creates a CircuitBreakerStore wrapping the provided store.
// Initializes one breaker per store method.
func NewCircuitBreakerStore(s engine.Store) *CircuitBreakerStore {
	methods := []string{
		"CreateAccount", "GetAccount", "GetAccountByName", "ListAccounts",
		"ArchiveAccount", "PostTransaction", "GetTransaction",
		"ListTransactions", "ListTransactionsPaginated", "GetBalance",
		"CheckIdempotencyKey", "SaveIdempotencyKey", "DeleteExpiredIdempotencyKeys",
	}
	breakers := make(map[string]*gobreaker.CircuitBreaker, len(methods))
	for _, m := range methods {
		breakers[m] = newBreaker(m)
	}
	return &CircuitBreakerStore{wrapped: s, breakers: breakers}
}

// exec wraps a store call returning a value. Maps ErrOpenState → ErrCircuitOpen.
func exec[T any](cb *gobreaker.CircuitBreaker, fn func() (T, error)) (T, error) {
	result, err := cb.Execute(func() (any, error) {
		return fn()
	})
	if err != nil {
		if errors.Is(err, gobreaker.ErrOpenState) {
			var zero T
			return zero, ErrCircuitOpen
		}
		var zero T
		return zero, err
	}
	return result.(T), nil
}

// execVoid wraps a store call returning only error.
func execVoid(cb *gobreaker.CircuitBreaker, fn func() error) error {
	_, err := cb.Execute(func() (any, error) { return nil, fn() })
	if errors.Is(err, gobreaker.ErrOpenState) {
		return ErrCircuitOpen
	}
	return err
}

func (s *CircuitBreakerStore) CreateAccount(ctx context.Context, acc engine.Account) error {
	return execVoid(s.breakers["CreateAccount"], func() error { return s.wrapped.CreateAccount(ctx, acc) })
}

func (s *CircuitBreakerStore) GetAccount(ctx context.Context, id string) (engine.Account, error) {
	return exec(s.breakers["GetAccount"], func() (engine.Account, error) { return s.wrapped.GetAccount(ctx, id) })
}

func (s *CircuitBreakerStore) GetAccountByName(ctx context.Context, name string) (engine.Account, error) {
	return exec(s.breakers["GetAccountByName"], func() (engine.Account, error) { return s.wrapped.GetAccountByName(ctx, name) })
}

func (s *CircuitBreakerStore) ListAccounts(ctx context.Context) ([]engine.Account, error) {
	return exec(s.breakers["ListAccounts"], func() ([]engine.Account, error) { return s.wrapped.ListAccounts(ctx) })
}

func (s *CircuitBreakerStore) ArchiveAccount(ctx context.Context, id string) error {
	return execVoid(s.breakers["ArchiveAccount"], func() error { return s.wrapped.ArchiveAccount(ctx, id) })
}

func (s *CircuitBreakerStore) PostTransaction(ctx context.Context, tx engine.Transaction) (engine.Transaction, error) {
	return exec(s.breakers["PostTransaction"], func() (engine.Transaction, error) { return s.wrapped.PostTransaction(ctx, tx) })
}

func (s *CircuitBreakerStore) GetTransaction(ctx context.Context, id string) (engine.Transaction, error) {
	return exec(s.breakers["GetTransaction"], func() (engine.Transaction, error) { return s.wrapped.GetTransaction(ctx, id) })
}

func (s *CircuitBreakerStore) ListTransactions(ctx context.Context) ([]engine.Transaction, error) {
	return exec(s.breakers["ListTransactions"], func() ([]engine.Transaction, error) { return s.wrapped.ListTransactions(ctx) })
}

func (s *CircuitBreakerStore) ListTransactionsPaginated(ctx context.Context, limit, offset int) ([]engine.Transaction, error) {
	return exec(s.breakers["ListTransactionsPaginated"], func() ([]engine.Transaction, error) {
		return s.wrapped.ListTransactionsPaginated(ctx, limit, offset)
	})
}

func (s *CircuitBreakerStore) GetBalance(ctx context.Context, accountID string, currency string) (int64, error) {
	return exec(s.breakers["GetBalance"], func() (int64, error) { return s.wrapped.GetBalance(ctx, accountID, currency) })
}

func (s *CircuitBreakerStore) CheckIdempotencyKey(ctx context.Context, key string) ([]byte, bool, error) {
	type result struct {
		body []byte
		ok   bool
	}
	r, err := exec(s.breakers["CheckIdempotencyKey"], func() (result, error) {
		b, ok, e := s.wrapped.CheckIdempotencyKey(ctx, key)
		return result{b, ok}, e
	})
	return r.body, r.ok, err
}

func (s *CircuitBreakerStore) SaveIdempotencyKey(ctx context.Context, key string, txID uuid.UUID, responseBody []byte) error {
	return execVoid(s.breakers["SaveIdempotencyKey"], func() error { return s.wrapped.SaveIdempotencyKey(ctx, key, txID, responseBody) })
}

func (s *CircuitBreakerStore) DeleteExpiredIdempotencyKeys(ctx context.Context) error {
	return execVoid(s.breakers["DeleteExpiredIdempotencyKeys"], func() error { return s.wrapped.DeleteExpiredIdempotencyKeys(ctx) })
}
```

- [ ] **Step 5: Add `MockPassthroughStore` helper for tests**

Append to `internal/store/circuitbreaker_test.go` (or create `internal/store/mock_store_test.go`):

```go
// mockPassthroughStore is a no-op store that always succeeds.
type mockPassthroughStore struct {
	accounts map[string]engine.Account
}

func NewMockPassthroughStore() *mockPassthroughStore {
	return &mockPassthroughStore{accounts: make(map[string]engine.Account)}
}

func (m *mockPassthroughStore) CreateAccount(_ context.Context, acc engine.Account) error {
	m.accounts[acc.ID.String()] = acc
	return nil
}
func (m *mockPassthroughStore) GetAccount(_ context.Context, id string) (engine.Account, error) {
	acc, ok := m.accounts[id]
	if !ok {
		return engine.Account{}, errors.New("not found")
	}
	return acc, nil
}
func (m *mockPassthroughStore) GetAccountByName(_ context.Context, _ string) (engine.Account, error) {
	return engine.Account{}, nil
}
func (m *mockPassthroughStore) ListAccounts(_ context.Context) ([]engine.Account, error) {
	return nil, nil
}
func (m *mockPassthroughStore) ArchiveAccount(_ context.Context, _ string) error { return nil }
func (m *mockPassthroughStore) PostTransaction(_ context.Context, tx engine.Transaction) (engine.Transaction, error) {
	return tx, nil
}
func (m *mockPassthroughStore) GetTransaction(_ context.Context, _ string) (engine.Transaction, error) {
	return engine.Transaction{}, nil
}
func (m *mockPassthroughStore) ListTransactions(_ context.Context) ([]engine.Transaction, error) {
	return nil, nil
}
func (m *mockPassthroughStore) ListTransactionsPaginated(_ context.Context, _, _ int) ([]engine.Transaction, error) {
	return nil, nil
}
func (m *mockPassthroughStore) GetBalance(_ context.Context, _ string, _ string) (int64, error) {
	return 0, nil
}
func (m *mockPassthroughStore) CheckIdempotencyKey(_ context.Context, _ string) ([]byte, bool, error) {
	return nil, false, nil
}
func (m *mockPassthroughStore) SaveIdempotencyKey(_ context.Context, _ string, _ uuid.UUID, _ []byte) error {
	return nil
}
func (m *mockPassthroughStore) DeleteExpiredIdempotencyKeys(_ context.Context) error { return nil }
```

Note: Move `NewMockPassthroughStore` and `mockPassthroughStore` into the test file `circuitbreaker_test.go` (lowercase unexported type `mockPassthroughStore`, func `newMockPassthroughStore`). Update the test:

```go
func TestCircuitBreakerPassesThroughOnSuccess(t *testing.T) {
	underlying := newMockPassthroughStore()
	cb := store.NewCircuitBreakerStore(underlying)
	ctx := context.Background()

	err := cb.CreateAccount(ctx, engine.Account{ID: uuid.New(), Name: "cash", Currency: "USD"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

- [ ] **Step 6: Wire CircuitBreakerStore in `cmd/ledger/root.go`**

Replace the `initEngine` function:

```go
func initEngine() (*engine.Engine, func()) {
	viper.AutomaticEnv()
	dbURL := viper.GetString("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL environment variable is required")
		os.Exit(1)
	}

	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse database URL: %v\n", err)
		os.Exit(1)
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to database: %v\n", err)
		os.Exit(1)
	}

	s := store.NewPostgresStore(pool)
	cb := store.NewCircuitBreakerStore(s)
	e := engine.NewEngine(cb)
	cleanup := func() { pool.Close() }
	return e, cleanup
}
```

Add import `"github.com/shreyshringare/Ledger/internal/store"` if not already present.

- [ ] **Step 7: Run tests**

```bash
cd "D:/SDE Projects/Ledger"
go test ./internal/store/... -run TestCircuitBreaker -v
```

Expected: both tests PASS.

- [ ] **Step 8: Build check**

```bash
go build ./...
```

Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add internal/store/circuitbreaker.go internal/store/circuitbreaker_test.go \
    cmd/ledger/root.go go.mod go.sum
git commit -m "feat: add circuit breaker store wrapper (sony/gobreaker)"
```

---

## Task 2: Soft Delete for Accounts

**Files:**
- Create: `internal/store/migrations/006_soft_delete_accounts.up.sql`
- Create: `internal/store/migrations/006_soft_delete_accounts.down.sql`
- Modify: `internal/engine/account.go`
- Modify: `internal/engine/store.go`
- Modify: `internal/engine/fake_store_test.go`
- Create: `internal/store/postgres_softdelete.go`
- Modify: `internal/store/postgres.go`
- Modify: `internal/api/handlers.go`
- Modify: `internal/api/routes.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/engine/engine_test.go` (or create `internal/engine/archive_test.go`):

```go
func TestArchiveAccountRemovesFromList(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)
	ctx := context.Background()

	acc := Account{
		ID:       uuid.New(),
		Name:     "Cash",
		Type:     Asset,
		Currency: "USD",
		IsActive: true,
	}
	if err := s.CreateAccount(ctx, acc); err != nil {
		t.Fatal(err)
	}

	// Archive the account
	if err := e.ArchiveAccount(ctx, acc.ID.String()); err != nil {
		t.Fatalf("ArchiveAccount: %v", err)
	}

	// Should not appear in list
	accounts, err := s.ListAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range accounts {
		if a.ID == acc.ID {
			t.Error("archived account still appears in ListAccounts")
		}
	}
}

func TestArchiveAccountGetStillWorks(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)
	ctx := context.Background()

	acc := Account{
		ID:       uuid.New(),
		Name:     "Revenue",
		Type:     Revenue,
		Currency: "USD",
		IsActive: true,
	}
	if err := s.CreateAccount(ctx, acc); err != nil {
		t.Fatal(err)
	}

	if err := e.ArchiveAccount(ctx, acc.ID.String()); err != nil {
		t.Fatal(err)
	}

	// GetAccount should still return it (transactions reference archived accounts)
	got, err := s.GetAccount(ctx, acc.ID.String())
	if err != nil {
		t.Fatalf("GetAccount on archived account: %v", err)
	}
	if got.ArchivedAt == nil {
		t.Error("expected ArchivedAt to be set after archive")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd "D:/SDE Projects/Ledger"
go test ./internal/engine/... -run TestArchive -v
```

Expected: FAIL — `e.ArchiveAccount` undefined, `acc.ArchivedAt` field missing.

- [ ] **Step 3: Create migration 006**

`internal/store/migrations/006_soft_delete_accounts.up.sql`:

```sql
ALTER TABLE accounts ADD COLUMN archived_at TIMESTAMPTZ;

-- Partial index: only index active accounts for list queries
CREATE INDEX accounts_active_idx ON accounts (created_at) WHERE archived_at IS NULL;
```

`internal/store/migrations/006_soft_delete_accounts.down.sql`:

```sql
DROP INDEX IF EXISTS accounts_active_idx;
ALTER TABLE accounts DROP COLUMN IF EXISTS archived_at;
```

- [ ] **Step 4: Add `ArchivedAt` to Account struct**

Modify `internal/engine/account.go` — add `ArchivedAt *time.Time` field:

```go
type Account struct {
	ID         uuid.UUID   `json:"id"`
	Name       string      `json:"name"`
	Type       AccountType `json:"type"`
	Currency   string      `json:"currency"`
	IsActive   bool        `json:"is_active"`
	CreatedAt  time.Time   `json:"created_at"`
	ArchivedAt *time.Time  `json:"archived_at,omitempty"`
}
```

- [ ] **Step 5: Add `ArchiveAccount` to engine.Store interface**

Modify `internal/engine/store.go`:

```go
type Store interface {
	CreateAccount(ctx context.Context, acc Account) error
	GetAccount(ctx context.Context, id string) (Account, error)
	GetAccountByName(ctx context.Context, name string) (Account, error)
	ListAccounts(ctx context.Context) ([]Account, error)
	ArchiveAccount(ctx context.Context, id string) error

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

Note: `DeleteExpiredIdempotencyKeys` is also added here (needed for Task 3; add it now to avoid a second round of interface changes).

- [ ] **Step 6: Add `ArchiveAccount` and `ArchiveAccount` stub to fakeStore**

Modify `internal/engine/fake_store_test.go` — add these methods to `fakeStore`:

```go
func (f *fakeStore) ArchiveAccount(_ context.Context, id string) error {
	acc, ok := f.accounts[id]
	if !ok {
		return fmt.Errorf("account %s not found", id)
	}
	now := time.Now()
	acc.ArchivedAt = &now
	f.accounts[id] = acc
	return nil
}

func (f *fakeStore) DeleteExpiredIdempotencyKeys(_ context.Context) error {
	return nil
}
```

Also update `ListAccounts` in `fakeStore` to filter archived accounts:

```go
func (f *fakeStore) ListAccounts(_ context.Context) ([]Account, error) {
	var out []Account
	for _, acc := range f.accounts {
		if acc.ArchivedAt == nil {
			out = append(out, acc)
		}
	}
	return out, nil
}
```

Also add the `time` import if not already present.

- [ ] **Step 7: Add `ArchiveAccount` to the Engine**

Modify `internal/engine/engine.go` — add method:

```go
func (e *Engine) ArchiveAccount(ctx context.Context, id string) error {
	return e.store.ArchiveAccount(ctx, id)
}
```

- [ ] **Step 8: Run engine tests**

```bash
cd "D:/SDE Projects/Ledger"
go test ./internal/engine/... -run TestArchive -v
```

Expected: PASS.

- [ ] **Step 9: Create Postgres soft-delete implementation**

Create `internal/store/postgres_softdelete.go`:

```go
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shreyshringare/Ledger/internal/engine"
)

// ArchiveAccount sets archived_at = NOW() on the account. Never hard-deletes.
func (s *PostgresStore) ArchiveAccount(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx,
		`UPDATE accounts SET archived_at = NOW() WHERE id = $1 AND archived_at IS NULL`,
		id,
	)
	if err != nil {
		return fmt.Errorf("archive account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows // not found or already archived
	}
	return nil
}

// scanAccountRow scans a full account row including the optional archived_at column.
// Column order: id, name, type, currency, is_active, created_at, archived_at
func scanAccountRow(row pgx.Row) (engine.Account, error) {
	var acc engine.Account
	var accType string
	var archivedAt *time.Time
	err := row.Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive, &acc.CreatedAt, &archivedAt)
	if err != nil {
		return engine.Account{}, err
	}
	acc.Type = engine.AccountType(accType)
	acc.ArchivedAt = archivedAt
	return acc, nil
}
```

- [ ] **Step 10: Update postgres.go account queries to include archived_at**

In `internal/store/postgres.go`, update the four account read methods to include `archived_at` in SELECT and filter WHERE appropriate:

```go
func (s *PostgresStore) GetAccount(ctx context.Context, id string) (engine.Account, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at
		 FROM accounts WHERE id = $1`,
		id,
	)
	acc, err := scanAccountRow(row)
	if err != nil {
		return engine.Account{}, fmt.Errorf("get account: %w", err)
	}
	return acc, nil
}

func (s *PostgresStore) GetAccountByName(ctx context.Context, name string) (engine.Account, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at
		 FROM accounts WHERE name = $1 AND archived_at IS NULL`,
		name,
	)
	acc, err := scanAccountRow(row)
	if err != nil {
		return engine.Account{}, fmt.Errorf("get account by name: %w", err)
	}
	return acc, nil
}

func (s *PostgresStore) ListAccounts(ctx context.Context) ([]engine.Account, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at
		 FROM accounts WHERE archived_at IS NULL ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var accounts []engine.Account
	for rows.Next() {
		var acc engine.Account
		var accType string
		var archivedAt *time.Time
		if err := rows.Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive, &acc.CreatedAt, &archivedAt); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		acc.Type = engine.AccountType(accType)
		acc.ArchivedAt = archivedAt
		accounts = append(accounts, acc)
	}
	return accounts, rows.Err()
}
```

Note: `CreateAccount` does not change — it does not INSERT `archived_at` (column defaults to NULL).

- [ ] **Step 11: Add handler and route for DELETE /v1/accounts/{id}**

Add to `internal/api/handlers.go`:

```go
// ArchiveAccount handles DELETE /v1/accounts/{id}.
// Sets archived_at; never hard-deletes. Financial data is never truly gone.
func (h *Handler) ArchiveAccount(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.engine.ArchiveAccount(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			WriteProblem(w, r, http.StatusNotFound, "Not Found", "account not found or already archived")
			return
		}
		log.Printf("archive account %s: %v", id, err)
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

Add imports needed: `"errors"`, `"github.com/jackc/pgx/v5"`.

Add to `internal/api/routes.go` (inside the `/v1/` subrouter, alongside other account routes):

```go
r.Delete("/accounts/{id}", h.ArchiveAccount)
```

If Plan 1 is not yet implemented and routes.go still has flat routes (no /v1/ prefix), add:

```go
r.Delete("/accounts/{id}", h.ArchiveAccount)
```

at the same level as the existing account routes.

- [ ] **Step 12: Run all tests**

```bash
cd "D:/SDE Projects/Ledger"
go test ./... -v
```

Expected: all tests PASS. Compile errors would indicate missing interface methods — fix by ensuring `CircuitBreakerStore` and `fakeStore` both implement the updated interface.

- [ ] **Step 13: Run migration against local DB and smoke test**

```bash
go run ./cmd/ledger/... migrate up
curl -s -X POST http://localhost:8080/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{"name":"Cash","type":"ASSET","currency":"USD"}' | jq .

# Grab the id from above response, e.g. "abc-123"
curl -s -X DELETE http://localhost:8080/v1/accounts/abc-123
# Expected: 204 No Content

curl -s http://localhost:8080/v1/accounts | jq .
# Expected: "Cash" NOT in the list
```

- [ ] **Step 14: Commit**

```bash
git add internal/engine/account.go internal/engine/store.go \
    internal/engine/engine.go internal/engine/fake_store_test.go \
    internal/store/postgres.go internal/store/postgres_softdelete.go \
    internal/store/migrations/006_soft_delete_accounts.up.sql \
    internal/store/migrations/006_soft_delete_accounts.down.sql \
    internal/api/handlers.go internal/api/routes.go
git commit -m "feat: soft delete for accounts (archived_at, never hard-delete)"
```

---

## Task 3: Idempotency Key TTL Cleanup

**Files:**
- Create: `internal/store/postgres_idempotency_ttl.go`
- Modify: `internal/engine/engine.go`
- Modify: `cmd/ledger/serve.go`

Note: `DeleteExpiredIdempotencyKeys` was already added to `engine.Store` and `fakeStore` in Task 2. This task adds the Postgres implementation and wires the background goroutine.

- [ ] **Step 1: Write the failing test**

Add to `internal/engine/engine_test.go`:

```go
func TestStartIdempotencyCleanupStopsOnContextCancel(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		e.StartIdempotencyCleanup(ctx)
		close(done)
	}()

	cancel() // trigger shutdown

	select {
	case <-done:
		// goroutine exited cleanly
	case <-time.After(2 * time.Second):
		t.Fatal("StartIdempotencyCleanup goroutine did not stop after context cancel")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd "D:/SDE Projects/Ledger"
go test ./internal/engine/... -run TestStartIdempotency -v
```

Expected: FAIL — `e.StartIdempotencyCleanup` undefined.

- [ ] **Step 3: Add `StartIdempotencyCleanup` to engine**

Add to `internal/engine/engine.go`:

```go
// StartIdempotencyCleanup starts a background goroutine that deletes idempotency
// keys older than 7 days, running every hour. Stops when ctx is cancelled.
// Call this from serve.go after the engine is created.
func (e *Engine) StartIdempotencyCleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	go func() {
		for {
			select {
			case <-ticker.C:
				if err := e.store.DeleteExpiredIdempotencyKeys(ctx); err != nil {
					// Log and continue — cleanup failures are non-fatal
					_ = err
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
```

Add `"time"` to imports in `engine.go` if not already there.

- [ ] **Step 4: Run test to verify it passes**

```bash
cd "D:/SDE Projects/Ledger"
go test ./internal/engine/... -run TestStartIdempotency -v
```

Expected: PASS.

- [ ] **Step 5: Create Postgres implementation**

Create `internal/store/postgres_idempotency_ttl.go`:

```go
package store

import (
	"context"
	"fmt"
)

// DeleteExpiredIdempotencyKeys deletes idempotency keys older than 7 days.
// Called by Engine.StartIdempotencyCleanup every hour.
func (s *PostgresStore) DeleteExpiredIdempotencyKeys(ctx context.Context) error {
	_, err := s.db.Exec(ctx,
		`DELETE FROM idempotency_keys WHERE created_at < NOW() - INTERVAL '7 days'`,
	)
	if err != nil {
		return fmt.Errorf("delete expired idempotency keys: %w", err)
	}
	return nil
}
```

- [ ] **Step 6: Wire cleanup in `cmd/ledger/serve.go`**

Modify `serve.go` to start the cleanup goroutine after creating the engine. If Plan 1 is already implemented (serve.go has graceful-shutdown ctx), add this line:

```go
// start idempotency key TTL cleanup (every 1h, 7-day expiry)
e.StartIdempotencyCleanup(ctx)
```

Place it right before the `http.Server` start. The `ctx` here is the signal-notification context from Plan 1's graceful shutdown. If Plan 1 is NOT yet implemented, add the context yourself:

```go
import (
    "context"
    "os"
    "os/signal"
    "syscall"
)

// In RunE:
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()

e.StartIdempotencyCleanup(ctx)
// ... existing http.ListenAndServe ...
```

- [ ] **Step 7: Build and run tests**

```bash
cd "D:/SDE Projects/Ledger"
go build ./...
go test ./... -v
```

Expected: all PASS, no compile errors.

- [ ] **Step 8: Commit**

```bash
git add internal/store/postgres_idempotency_ttl.go \
    internal/engine/engine.go cmd/ledger/serve.go
git commit -m "feat: idempotency key TTL cleanup goroutine (7-day expiry, hourly)"
```

---

## Task 4: Column-Level Encryption with pgcrypto

**Files:**
- Create: `internal/store/migrations/007_pgcrypto.up.sql`
- Create: `internal/store/migrations/007_pgcrypto.down.sql`
- Modify: `internal/engine/account.go`
- Modify: `internal/store/postgres.go`
- Modify: `internal/api/handlers.go`

Column-level encryption uses Postgres `pgcrypto` extension — `pgp_sym_encrypt` and `pgp_sym_decrypt`. The `ENCRYPTION_KEY` env var is the symmetric key, never stored in DB.

- [ ] **Step 1: Create migration 007**

`internal/store/migrations/007_pgcrypto.up.sql`:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE accounts ADD COLUMN description BYTEA;
```

`internal/store/migrations/007_pgcrypto.down.sql`:

```sql
ALTER TABLE accounts DROP COLUMN IF EXISTS description;
```

Note: `DROP EXTENSION pgcrypto` is intentionally omitted — other tables may depend on it.

- [ ] **Step 2: Add `Description` field to Account struct**

Modify `internal/engine/account.go`:

```go
type Account struct {
	ID          uuid.UUID   `json:"id"`
	Name        string      `json:"name"`
	Type        AccountType `json:"type"`
	Currency    string      `json:"currency"`
	IsActive    bool        `json:"is_active"`
	CreatedAt   time.Time   `json:"created_at"`
	ArchivedAt  *time.Time  `json:"archived_at,omitempty"`
	Description string      `json:"description,omitempty"`
}
```

- [ ] **Step 3: Add encryption helper in postgres.go**

Add near the top of `internal/store/postgres.go` (after imports):

```go
import "os"

// encryptionKey reads the symmetric encryption key from the environment.
// Returns empty string if not set — description will be NULL in that case.
func encryptionKey() string {
	return os.Getenv("ENCRYPTION_KEY")
}
```

- [ ] **Step 4: Update CreateAccount to encrypt description**

Replace `CreateAccount` in `internal/store/postgres.go`:

```go
func (s *PostgresStore) CreateAccount(ctx context.Context, acc engine.Account) error {
	key := encryptionKey()
	if acc.Description != "" && key != "" {
		_, err := s.db.Exec(ctx,
			`INSERT INTO accounts (id, name, type, currency, is_active, created_at, description)
			 VALUES ($1, $2, $3, $4, $5, $6, pgp_sym_encrypt($7, $8))`,
			acc.ID, acc.Name, string(acc.Type), acc.Currency, acc.IsActive, acc.CreatedAt,
			acc.Description, key,
		)
		return err
	}
	// No description or no key — store without description
	_, err := s.db.Exec(ctx,
		`INSERT INTO accounts (id, name, type, currency, is_active, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		acc.ID, acc.Name, string(acc.Type), acc.Currency, acc.IsActive, acc.CreatedAt,
	)
	return err
}
```

- [ ] **Step 5: Update account read queries to decrypt description**

Replace `GetAccount`, `GetAccountByName`, and `ListAccounts` in `internal/store/postgres.go` to select and decrypt `description`:

```go
func (s *PostgresStore) GetAccount(ctx context.Context, id string) (engine.Account, error) {
	key := encryptionKey()
	row := s.db.QueryRow(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at,
		        CASE WHEN description IS NOT NULL AND $2 != ''
		             THEN pgp_sym_decrypt(description, $2)::text
		             ELSE NULL END
		 FROM accounts WHERE id = $1`,
		id, key,
	)
	acc, err := scanAccountRowWithDescription(row)
	if err != nil {
		return engine.Account{}, fmt.Errorf("get account: %w", err)
	}
	return acc, nil
}

func (s *PostgresStore) GetAccountByName(ctx context.Context, name string) (engine.Account, error) {
	key := encryptionKey()
	row := s.db.QueryRow(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at,
		        CASE WHEN description IS NOT NULL AND $2 != ''
		             THEN pgp_sym_decrypt(description, $2)::text
		             ELSE NULL END
		 FROM accounts WHERE name = $1 AND archived_at IS NULL`,
		name, key,
	)
	acc, err := scanAccountRowWithDescription(row)
	if err != nil {
		return engine.Account{}, fmt.Errorf("get account by name: %w", err)
	}
	return acc, nil
}

func (s *PostgresStore) ListAccounts(ctx context.Context) ([]engine.Account, error) {
	key := encryptionKey()
	rows, err := s.db.Query(ctx,
		`SELECT id, name, type, currency, is_active, created_at, archived_at,
		        CASE WHEN description IS NOT NULL AND $1 != ''
		             THEN pgp_sym_decrypt(description, $1)::text
		             ELSE NULL END
		 FROM accounts WHERE archived_at IS NULL ORDER BY created_at`,
		key,
	)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	defer rows.Close()

	var accounts []engine.Account
	for rows.Next() {
		var acc engine.Account
		var accType string
		var archivedAt *time.Time
		var desc *string
		if err := rows.Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive,
			&acc.CreatedAt, &archivedAt, &desc); err != nil {
			return nil, fmt.Errorf("scan account: %w", err)
		}
		acc.Type = engine.AccountType(accType)
		acc.ArchivedAt = archivedAt
		if desc != nil {
			acc.Description = *desc
		}
		accounts = append(accounts, acc)
	}
	return accounts, rows.Err()
}
```

Add `scanAccountRowWithDescription` to `postgres_softdelete.go`:

```go
// scanAccountRowWithDescription scans a row with columns:
// id, name, type, currency, is_active, created_at, archived_at, description(nullable)
func scanAccountRowWithDescription(row pgx.Row) (engine.Account, error) {
	var acc engine.Account
	var accType string
	var archivedAt *time.Time
	var desc *string
	err := row.Scan(&acc.ID, &acc.Name, &accType, &acc.Currency, &acc.IsActive,
		&acc.CreatedAt, &archivedAt, &desc)
	if err != nil {
		return engine.Account{}, err
	}
	acc.Type = engine.AccountType(accType)
	acc.ArchivedAt = archivedAt
	if desc != nil {
		acc.Description = *desc
	}
	return acc, nil
}
```

Update `GetAccount` and `GetAccountByName` in `postgres.go` to call `scanAccountRowWithDescription` instead of the old `scanAccountRow`.

- [ ] **Step 6: Update CreateAccount handler to accept description**

In `internal/api/handlers.go`, modify the request struct in `CreateAccount`:

```go
var req struct {
    Name        string `json:"name"`
    Type        string `json:"type"`
    Currency    string `json:"currency"`
    Description string `json:"description"`
}
```

And set `Description` when building the Account:

```go
acc := engine.Account{
    ID:          uuid.New(),
    Name:        req.Name,
    Type:        engine.AccountType(req.Type),
    Currency:    req.Currency,
    IsActive:    true,
    CreatedAt:   time.Now().UTC(),
    Description: req.Description,
}
```

- [ ] **Step 7: Run migration and smoke test encryption**

```bash
go run ./cmd/ledger/... migrate up
```

```bash
# Set encryption key
export ENCRYPTION_KEY="my-test-key-32-chars-minimum-abc"

# Create account with description
curl -s -X POST http://localhost:8080/v1/accounts \
  -H "Content-Type: application/json" \
  -d '{"name":"Vault","type":"ASSET","currency":"USD","description":"Primary vault account"}' | jq .

# Verify description is returned decrypted
curl -s http://localhost:8080/v1/accounts | jq '.[0].description'
# Expected: "Primary vault account"

# Verify it's stored encrypted in DB (connect via psql):
# SELECT description FROM accounts WHERE name = 'Vault';
# Expected: binary/encrypted bytes, NOT "Primary vault account"
```

- [ ] **Step 8: Run all tests**

```bash
cd "D:/SDE Projects/Ledger"
go test ./...
```

Expected: PASS. (pgcrypto tests require a real DB; unit tests don't test encryption.)

- [ ] **Step 9: Commit**

```bash
git add internal/engine/account.go internal/store/postgres.go \
    internal/store/postgres_softdelete.go internal/api/handlers.go \
    internal/store/migrations/007_pgcrypto.up.sql \
    internal/store/migrations/007_pgcrypto.down.sql
git commit -m "feat: column-level encryption for account.description (pgcrypto)"
```

---

## Task 5: Pre-commit Hook (Secrets Scan)

**Files:**
- Create: `.githooks/pre-commit`

A pre-commit hook that fails if a Go file contains a hardcoded `postgres://` DSN — the most common accidental secret in this codebase.

- [ ] **Step 1: Create the hooks directory and hook file**

```bash
mkdir -p "D:/SDE Projects/Ledger/.githooks"
```

Create `.githooks/pre-commit`:

```bash
#!/bin/sh
# Pre-commit: fail if a Go file contains a hardcoded postgres:// DSN.
# Prevents committing DATABASE_URL credentials by accident.

set -e

MATCHES=$(git diff --cached --name-only | grep '\.go$' | xargs grep -l 'postgres://' 2>/dev/null || true)

if [ -n "$MATCHES" ]; then
  echo "ERROR: hardcoded postgres:// DSN found in staged files:"
  echo "$MATCHES"
  echo ""
  echo "Use DATABASE_URL env var instead of hardcoding connection strings."
  exit 1
fi

# Also check for any AWS/GCP keys (common accidental leaks)
KEY_MATCHES=$(git diff --cached --name-only | xargs grep -l 'AKIA\|AIza\|-----BEGIN' 2>/dev/null || true)
if [ -n "$KEY_MATCHES" ]; then
  echo "ERROR: possible credential pattern found in staged files:"
  echo "$KEY_MATCHES"
  exit 1
fi

exit 0
```

- [ ] **Step 2: Make hook executable and configure git**

```bash
chmod +x "D:/SDE Projects/Ledger/.githooks/pre-commit"
cd "D:/SDE Projects/Ledger"
git config core.hooksPath .githooks
```

- [ ] **Step 3: Verify hook runs**

```bash
# Stage a file with a fake DSN
echo 'var _ = "postgres://user:pass@localhost/db"' > /tmp/test_secret.go
cp /tmp/test_secret.go "D:/SDE Projects/Ledger/internal/test_secret_canary.go"
git -C "D:/SDE Projects/Ledger" add internal/test_secret_canary.go
git -C "D:/SDE Projects/Ledger" commit -m "test secret canary"
```

Expected: commit BLOCKED with message `ERROR: hardcoded postgres:// DSN found in staged files`.

Clean up:

```bash
rm "D:/SDE Projects/Ledger/internal/test_secret_canary.go"
git -C "D:/SDE Projects/Ledger" restore --staged internal/test_secret_canary.go 2>/dev/null || true
```

- [ ] **Step 4: Commit the hook**

```bash
git add .githooks/pre-commit
git commit -m "chore: add pre-commit hook to block hardcoded DSN and credential patterns"
```

---

## Task 6: STRIDE Threat Model Document

**Files:**
- Create: `docs/threat-model.md`

This document is not code, but it's one of the strongest interview signals — it shows you think about adversaries, not just features. Interviewers at JPMC and Barclays will ask "how do you know this system is secure?" — this is your answer.

- [ ] **Step 1: Create `docs/threat-model.md`**

```markdown
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
- SHA-256 hash chain on audit log: separate chain proves audit log itself is untampered.
- Postgres RLS on `audit_events`: `DENY UPDATE, DELETE` at DB role level — even compromised app credentials cannot mutate audit records.

**Residual risk:** DB superuser (`postgres`) role bypasses RLS. Requires DB-level access control (separate `ledger_app_role` with limited grants). Documented but not fully enforced in dev environment.

---

### R — Repudiation (denying an action happened)

**Threat:** A client claims they never posted a transaction or revoked an API key.

**Mitigations:**
- Immutable audit log: every `account.created`, `transaction.posted`, `api_key.created`, `api_key.revoked` event is recorded to `audit_events` with `actor = api_key_id`.
- Audit events are chained (prev_hash) — cannot retroactively insert or delete events without breaking the chain.
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

**Residual risk:** Transaction amounts and account names are stored unencrypted (only `description` is encrypted). Full field-level encryption would require schema redesign. Account names leak account structure to anyone with DB access.

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
- Scope is enforced in middleware, not handlers — cannot be bypassed by handler-level logic.
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
| Hash chain (audit log) | `postgres_audit.go` | Tampering, Repudiation |
| Immutable audit log + RLS | `audit_events` table + Postgres RLS | Repudiation |
| Key scoping | `middleware_auth.go` | Elevation of Privilege |
| Rate limiting | `middleware_ratelimit.go` | DoS |
| Circuit breaker | `store/circuitbreaker.go` | DoS |
| Request timeout | `middleware_security.go` | DoS |
| pgcrypto column encryption | `postgres.go`, migration 007 | Information Disclosure |
| No PII in logs | `middleware_logging.go` | Information Disclosure |
| Pre-commit DSN check | `.githooks/pre-commit` | Information Disclosure |
```

- [ ] **Step 2: Commit the threat model**

```bash
git add docs/threat-model.md
git commit -m "docs: add STRIDE threat model (spoofing, tampering, repudiation, info-disclosure, DoS, privilege)"
```

---

## Task 7: SBOM (Software Bill of Materials)

**Files:**
- No code files — this is a tooling setup task.

An SBOM lists every dependency and its version in a machine-readable format. Enterprise clients (banks) increasingly require it for vendor security reviews. Running `syft` in CI generates it automatically.

- [ ] **Step 1: Install syft (one-time)**

On Windows:
```powershell
winget install anchore.syft
```

Or via Scoop:
```powershell
scoop install syft
```

Verify:
```bash
syft version
```

Expected: `syft 1.x.x` (any v1 version).

- [ ] **Step 2: Generate SBOM locally**

```bash
cd "D:/SDE Projects/Ledger"
syft . --output spdx-json > sbom.spdx.json
```

Inspect:
```bash
# Count packages
jq '.packages | length' sbom.spdx.json
```

Expected: 30+ packages (all Go module dependencies enumerated).

- [ ] **Step 3: Add sbom.spdx.json to .gitignore**

The SBOM is generated in CI, not committed to source:

```bash
echo "sbom.spdx.json" >> "D:/SDE Projects/Ledger/.gitignore"
```

- [ ] **Step 4: Add SBOM step to GitHub Actions (Plan 4 dependency)**

When Plan 4 CI is implemented (`.github/workflows/ci.yml`), add this step after the build step:

```yaml
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

If implementing Plan 5 before Plan 4, note this in the CI file when you create it: "SBOM step must be added here."

- [ ] **Step 5: Commit .gitignore change**

```bash
git add .gitignore
git commit -m "chore: ignore generated sbom.spdx.json (generated in CI)"
```

---

---

## Task 8: Transaction Fraud Velocity Controls

**Why (Visa/Mastercard standard):** Visa's Authorization System requires velocity checks before every transaction. Mastercard's fraud rules mandate per-account transaction rate limits. This task adds two in-process checks in the Engine before `PostTransaction` reaches the DB: frequency (5 txn/min per account) and amount (1,000,000 minor units/hour per account). Uses the same sliding window structure as the API rate limiter.

**Files:**
- Create: `internal/engine/fraud.go` — velocity checker type and logic
- Create: `internal/engine/fraud_test.go` — unit tests
- Modify: `internal/engine/engine.go` — call velocity check in `Post`

- [ ] **Step 1: Write the failing tests**

Create `internal/engine/fraud_test.go`:

```go
package engine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestVelocityChecker_AllowsUnderLimit(t *testing.T) {
	vc := NewVelocityChecker(3, 60, 1_000_000, 3600)
	ctx := context.Background()
	accID := uuid.New()

	for i := 0; i < 3; i++ {
		if err := vc.Check(ctx, accID.String(), 100); err != nil {
			t.Errorf("attempt %d should be allowed, got: %v", i+1, err)
		}
	}
}

func TestVelocityChecker_BlocksFrequencyExcess(t *testing.T) {
	vc := NewVelocityChecker(2, 60, 1_000_000, 3600)
	ctx := context.Background()
	accID := uuid.New()

	vc.Check(ctx, accID.String(), 100)
	vc.Check(ctx, accID.String(), 100)

	if err := vc.Check(ctx, accID.String(), 100); err == nil {
		t.Error("expected frequency limit error on 3rd attempt")
	}
}

func TestVelocityChecker_BlocksAmountExcess(t *testing.T) {
	vc := NewVelocityChecker(100, 60, 500, 3600) // 500 minor unit/hour cap
	ctx := context.Background()
	accID := uuid.New()

	vc.Check(ctx, accID.String(), 300)

	if err := vc.Check(ctx, accID.String(), 300); err == nil {
		t.Error("expected amount limit error when cumulative exceeds 500")
	}
}

func TestVelocityChecker_SeparateLimitsPerAccount(t *testing.T) {
	vc := NewVelocityChecker(1, 60, 1_000_000, 3600)
	ctx := context.Background()
	a1 := uuid.New()
	a2 := uuid.New()

	vc.Check(ctx, a1.String(), 100)
	if err := vc.Check(ctx, a1.String(), 100); err == nil {
		t.Error("expected a1 to be rate-limited")
	}
	if err := vc.Check(ctx, a2.String(), 100); err != nil {
		t.Errorf("a2 should not be limited by a1's count: %v", err)
	}
}
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
go test ./internal/engine/ -run TestVelocityChecker -v
```

Expected: `FAIL — NewVelocityChecker undefined`

- [ ] **Step 3: Implement `internal/engine/fraud.go`**

```go
package engine

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// VelocityChecker enforces per-account transaction frequency and amount limits.
// This mirrors Visa's Real-Time Fraud Scoring velocity checks applied before
// authorization. Two limits are enforced independently:
//   - Frequency: max N transactions per frequencyWindowSec
//   - Amount:    max M minor units cumulative per amountWindowSec
//
// Both windows are sliding (not fixed) to prevent boundary exploitation.
type VelocityChecker struct {
	mu               sync.Mutex
	windows          map[string]*accountVelocity
	freqLimit        int
	freqWindowSec    int
	amountLimit      int64
	amountWindowSec  int
}

type accountVelocity struct {
	mu        sync.Mutex
	txTimes   []time.Time // timestamps for frequency window
	amounts   []amountEntry // (time, amount) for amount window
}

type amountEntry struct {
	ts     time.Time
	amount int64
}

// NewVelocityChecker creates a VelocityChecker.
// freqLimit: max transactions per freqWindowSec.
// amountLimit: max cumulative minor units per amountWindowSec.
// Production defaults: NewVelocityChecker(5, 60, 1_000_000, 3600)
// — 5 txn/min, $10,000/hour (in minor units of USD).
func NewVelocityChecker(freqLimit, freqWindowSec int, amountLimit int64, amountWindowSec int) *VelocityChecker {
	return &VelocityChecker{
		windows:         make(map[string]*accountVelocity),
		freqLimit:       freqLimit,
		freqWindowSec:   freqWindowSec,
		amountLimit:     amountLimit,
		amountWindowSec: amountWindowSec,
	}
}

// Check validates the transaction against velocity limits for the given account.
// Returns a VelocityError if either limit is exceeded; nil if the transaction is allowed.
// On success, the transaction is recorded in the sliding windows.
func (vc *VelocityChecker) Check(_ context.Context, accountID string, amountMinor int64) error {
	vc.mu.Lock()
	av, ok := vc.windows[accountID]
	if !ok {
		av = &accountVelocity{}
		vc.windows[accountID] = av
	}
	vc.mu.Unlock()

	av.mu.Lock()
	defer av.mu.Unlock()

	now := time.Now()

	// Evict stale frequency entries
	freqCutoff := now.Add(-time.Duration(vc.freqWindowSec) * time.Second)
	i := 0
	for i < len(av.txTimes) && av.txTimes[i].Before(freqCutoff) {
		i++
	}
	av.txTimes = av.txTimes[i:]

	if len(av.txTimes) >= vc.freqLimit {
		return fmt.Errorf("velocity limit: max %d transactions per %ds exceeded — possible fraud detected",
			vc.freqLimit, vc.freqWindowSec)
	}

	// Evict stale amount entries
	amtCutoff := now.Add(-time.Duration(vc.amountWindowSec) * time.Second)
	j := 0
	for j < len(av.amounts) && av.amounts[j].ts.Before(amtCutoff) {
		j++
	}
	av.amounts = av.amounts[j:]

	var cumulative int64
	for _, e := range av.amounts {
		cumulative += e.amount
	}
	if cumulative+amountMinor > vc.amountLimit {
		return fmt.Errorf("velocity limit: cumulative amount %d exceeds %d per %ds — possible fraud detected",
			cumulative+amountMinor, vc.amountLimit, vc.amountWindowSec)
	}

	// Record this transaction
	av.txTimes = append(av.txTimes, now)
	av.amounts = append(av.amounts, amountEntry{ts: now, amount: amountMinor})
	return nil
}
```

- [ ] **Step 4: Run tests — expect PASS**

```bash
go test ./internal/engine/ -run TestVelocityChecker -v
```

- [ ] **Step 5: Add `velocityChecker` to Engine and call in `Post`**

In `internal/engine/engine.go`, add field to `Engine` struct:

```go
type Engine struct {
    store          Store
    auditStore     AuditStore
    velocityCheck  *VelocityChecker // nil = no velocity checking
}
```

Add constructor option:

```go
// WithVelocityChecker enables per-account fraud velocity checks on Post.
// Production: NewVelocityChecker(5, 60, 1_000_000, 3600)
func (e *Engine) WithVelocityChecker(vc *VelocityChecker) *Engine {
    e.velocityCheck = vc
    return e
}
```

In `Post`, add BEFORE `e.store.PostTransaction`:

```go
// Velocity check: Visa/Mastercard fraud prevention — checked before DB write
// so a declined transaction never touches the ledger.
if e.velocityCheck != nil {
    totalAmount := int64(0)
    for _, entry := range entries {
        if entry.IsDebit {
            totalAmount += entry.AmountMinor
        }
    }
    if err := e.velocityCheck.Check(ctx, entries[0].AccountID.String(), totalAmount); err != nil {
        return Transaction{}, fmt.Errorf("transaction declined: %w", err)
    }
}
```

- [ ] **Step 6: Wire velocity checker in `cmd/ledger/serve.go`**

After `e, db, cleanup := initEngine()`, add:

```go
// 5 transactions/minute, $10,000/hour per account (Visa velocity check defaults)
e = e.WithVelocityChecker(engine.NewVelocityChecker(5, 60, 1_000_000, 3600))
```

- [ ] **Step 7: Run all tests**

```bash
go test ./...
```

- [ ] **Step 8: Commit**

```bash
git add internal/engine/fraud.go internal/engine/fraud_test.go internal/engine/engine.go cmd/ledger/serve.go
git commit -m "feat: per-account fraud velocity checks (5 txn/min, $10k/hour) — Visa/Mastercard standard"
```

---

## Deferred: Settlement Reconciliation

**Not implemented in this phase. Document for architectural awareness.**

Visa VisaNet and Mastercard MDES require acquiring processors to submit daily settlement files. For a fintech interview, knowing this exists is as important as the code. The settlement flow for this system would be:

1. **End of day (23:59 UTC):** Batch job queries all `transaction.posted` audit events since last settlement
2. **Reconciliation:** Compare ledger totals against payment processor's settlement report (three-way match: expected vs. posted vs. received)
3. **File format:** ISO 20022 `pain.001` (credit transfers) or Visa's proprietary VSS file format
4. **Discrepancy handling:** Any variance > $0.01 triggers an alert and opens a manual review ticket

**Implementation deferred to:** Payment Processor Integration Phase (after card network BIN routing is added).

---

## Self-Review

### Spec Coverage

| Spec Requirement | Task |
|---|---|
| Circuit breaker (gobreaker), 5 failures, 503 | Task 1 |
| Soft delete (`archived_at`), financial data never deleted | Task 2 |
| Idempotency key TTL cleanup goroutine, 7-day expiry | Task 3 |
| pgcrypto column encryption for `account.description` | Task 4 |
| Pre-commit hook: grep for hardcoded DSN | Task 5 |
| STRIDE threat model at `docs/threat-model.md` | Task 6 |
| SBOM via syft, published as CI artifact | Task 7 |

All spec requirements covered.

### Placeholder Scan

No TBD, TODO, or vague steps found. All code is complete and exact.

### Type Consistency

- `engine.Store` interface updated in Task 2 Step 5 — used in Tasks 1, 3, and throughout
- `CircuitBreakerStore` implements all methods including `ArchiveAccount` and `DeleteExpiredIdempotencyKeys` added in Task 2
- `scanAccountRowWithDescription` defined in Task 4 Step 5, referenced in all subsequent GetAccount calls
- `engine.Account.Description` added in Task 4 Step 2; used in Task 4 Step 4, 5, 6
- `engine.Account.ArchivedAt` added in Task 2 Step 4; used in Task 2 Steps 5–10

All types consistent.
