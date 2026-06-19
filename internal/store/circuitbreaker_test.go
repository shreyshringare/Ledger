package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/shreyshringare/Ledger/internal/store"
)

// errorStore always returns an error from every method.
type errorStore struct{ err error }

func (e *errorStore) CreateAccount(_ context.Context, acc engine.Account) error { return e.err }
func (e *errorStore) GetAccount(_ context.Context, id string) (engine.Account, error) {
	return engine.Account{}, e.err
}
func (e *errorStore) GetAccountByName(_ context.Context, name string) (engine.Account, error) {
	return engine.Account{}, e.err
}
func (e *errorStore) ListAccounts(_ context.Context) ([]engine.Account, error) { return nil, e.err }
func (e *errorStore) ArchiveAccount(_ context.Context, id string) error        { return e.err }
func (e *errorStore) PostTransaction(_ context.Context, tx engine.Transaction) (engine.Transaction, error) {
	return engine.Transaction{}, e.err
}
func (e *errorStore) GetTransaction(_ context.Context, id string) (engine.Transaction, error) {
	return engine.Transaction{}, e.err
}
func (e *errorStore) ListTransactions(_ context.Context) ([]engine.Transaction, error) {
	return nil, e.err
}
func (e *errorStore) ListTransactionsPaginated(_ context.Context, _, _ int) ([]engine.Transaction, error) {
	return nil, e.err
}
func (e *errorStore) GetBalance(_ context.Context, _ string, _ string) (int64, error) {
	return 0, e.err
}
func (e *errorStore) CheckIdempotencyKey(_ context.Context, _ string) ([]byte, bool, error) {
	return nil, false, e.err
}
func (e *errorStore) SaveIdempotencyKey(_ context.Context, _ string, _ uuid.UUID, _ []byte) error {
	return e.err
}
func (e *errorStore) DeleteExpiredIdempotencyKeys(_ context.Context) error { return e.err }

// mockPassthroughStore is a no-op store that always succeeds.
type mockPassthroughStore struct {
	accounts map[string]engine.Account
}

func newMockPassthroughStore() *mockPassthroughStore {
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
	underlying := newMockPassthroughStore()
	cb := store.NewCircuitBreakerStore(underlying)
	ctx := context.Background()

	err := cb.CreateAccount(ctx, engine.Account{ID: uuid.New(), Name: "cash", Currency: "USD"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Ensure unused imports don't cause issues (time used in future tests)
var _ = time.Now
