package reconcile_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/shreyshringare/Ledger/internal/reconcile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalStore implements engine.Store for reconciler tests.
type minimalStore struct {
	txs []engine.Transaction
}

func (m *minimalStore) ListTransactions(_ context.Context) ([]engine.Transaction, error) {
	return m.txs, nil
}
func (m *minimalStore) CreateAccount(_ context.Context, _ engine.Account) error { return nil }
func (m *minimalStore) GetAccount(_ context.Context, _ string) (engine.Account, error) {
	return engine.Account{}, nil
}
func (m *minimalStore) GetAccountByName(_ context.Context, _ string) (engine.Account, error) {
	return engine.Account{}, nil
}
func (m *minimalStore) ListAccounts(_ context.Context) ([]engine.Account, error) { return nil, nil }
func (m *minimalStore) ArchiveAccount(_ context.Context, _ string) error         { return nil }
func (m *minimalStore) PostTransaction(_ context.Context, tx engine.Transaction) (engine.Transaction, error) {
	m.txs = append(m.txs, tx)
	return tx, nil
}
func (m *minimalStore) GetTransaction(_ context.Context, _ string) (engine.Transaction, error) {
	return engine.Transaction{}, nil
}
func (m *minimalStore) ListTransactionsPaginated(_ context.Context, _, _ int) ([]engine.Transaction, error) {
	return nil, nil
}
func (m *minimalStore) GetBalance(_ context.Context, _, _ string) (int64, error) { return 0, nil }
func (m *minimalStore) CheckIdempotencyKey(_ context.Context, _ string) ([]byte, bool, error) {
	return nil, false, nil
}
func (m *minimalStore) SaveIdempotencyKey(_ context.Context, _ string, _ uuid.UUID, _ []byte) error {
	return nil
}
func (m *minimalStore) DeleteExpiredIdempotencyKeys(_ context.Context) error { return nil }

func TestReconcile_Matched(t *testing.T) {
	accID := uuid.New()
	s := &minimalStore{txs: []engine.Transaction{
		{
			ID:          uuid.New(),
			Description: "Customer payment INV-001",
			PostedAt:    time.Now(),
			Entries: []engine.Entry{
				{AccountID: accID, AmountMinor: 10000, Currency: "INR", IsDebit: true},
			},
		},
	}}

	stmt := []reconcile.StatementEntry{
		{ExternalID: "BANK-001", Description: "Customer payment INV-001", AmountMinor: 10000, Currency: "INR", Date: time.Now()},
	}

	results, summary, err := reconcile.Reconcile(context.Background(), s, accID.String(), stmt)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.Matched)
	assert.Equal(t, reconcile.Matched, results[0].Status)
}

func TestReconcile_Missing(t *testing.T) {
	s := &minimalStore{}
	stmt := []reconcile.StatementEntry{
		{ExternalID: "BANK-002", Description: "Unknown payment", AmountMinor: 5000, Currency: "INR", Date: time.Now()},
	}
	results, summary, err := reconcile.Reconcile(context.Background(), s, uuid.New().String(), stmt)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.Missing)
	assert.Equal(t, reconcile.Missing, results[0].Status)
}

func TestReconcile_Mismatch(t *testing.T) {
	accID := uuid.New()
	s := &minimalStore{txs: []engine.Transaction{
		{
			ID:          uuid.New(),
			Description: "Supplier payment",
			PostedAt:    time.Now(),
			Entries: []engine.Entry{
				{AccountID: accID, AmountMinor: 9000, Currency: "INR", IsDebit: true},
			},
		},
	}}
	stmt := []reconcile.StatementEntry{
		{ExternalID: "BANK-003", Description: "Supplier payment", AmountMinor: 10000, Currency: "INR", Date: time.Now()},
	}
	results, summary, err := reconcile.Reconcile(context.Background(), s, accID.String(), stmt)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.Mismatched)
	assert.Equal(t, reconcile.Mismatch, results[0].Status)
}

func TestReconcile_Duplicate(t *testing.T) {
	s := &minimalStore{}
	stmt := []reconcile.StatementEntry{
		{ExternalID: "BANK-004", Description: "Duplicate", AmountMinor: 1000, Currency: "INR", Date: time.Now()},
		{ExternalID: "BANK-004", Description: "Duplicate", AmountMinor: 1000, Currency: "INR", Date: time.Now()},
	}
	results, summary, err := reconcile.Reconcile(context.Background(), s, uuid.New().String(), stmt)
	require.NoError(t, err)
	assert.Equal(t, 2, summary.Duplicate)
	assert.Equal(t, reconcile.Duplicate, results[0].Status)
}
