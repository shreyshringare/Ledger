package engine

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func BenchmarkPost(b *testing.B) {
	s := newFakeStore()
	s.accounts[uuid.Nil.String()] = Account{ID: uuid.Nil, Type: Asset, Currency: "INR", IsActive: true}
	debitID := uuid.New()
	s.accounts[debitID.String()] = Account{ID: debitID, Type: Asset, Currency: "INR", IsActive: true}
	creditID := uuid.New()
	s.accounts[creditID.String()] = Account{ID: creditID, Type: Liability, Currency: "INR", IsActive: true}

	e := NewEngine(s)
	ctx := context.Background()

	entries := []Entry{
		{AccountID: debitID, AmountMinor: 10000, Currency: "INR", IsDebit: true},
		{AccountID: creditID, AmountMinor: 10000, Currency: "INR", IsDebit: false},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.Post(ctx, "bench", entries)
	}
}

func BenchmarkVerifyChain(b *testing.B) {
	s := newFakeStore()
	debitID := uuid.New()
	s.accounts[debitID.String()] = Account{ID: debitID, Type: Asset, Currency: "INR", IsActive: true}
	creditID := uuid.New()
	s.accounts[creditID.String()] = Account{ID: creditID, Type: Liability, Currency: "INR", IsActive: true}

	e := NewEngine(s)
	ctx := context.Background()
	entries := []Entry{
		{AccountID: debitID, AmountMinor: 10000, Currency: "INR", IsDebit: true},
		{AccountID: creditID, AmountMinor: 10000, Currency: "INR", IsDebit: false},
	}
	// Seed 1000 transactions
	for i := 0; i < 1000; i++ {
		_, _ = e.Post(ctx, "seed", entries)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.VerifyChain(ctx)
	}
}

func BenchmarkValidate(b *testing.B) {
	debitID := uuid.New()
	creditID := uuid.New()
	tx := Transaction{
		Description: "bench",
		Entries: []Entry{
			{AccountID: debitID, AmountMinor: 10000, Currency: "INR", IsDebit: true},
			{AccountID: creditID, AmountMinor: 10000, Currency: "INR", IsDebit: false},
		},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tx.Validate()
	}
}
