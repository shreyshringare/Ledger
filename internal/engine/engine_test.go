package engine

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func makeAccount(name string, accType AccountType) Account {
	return Account{
		ID:        uuid.New(),
		Name:      name,
		Type:      accType,
		Currency:  "USD",
		IsActive:  true,
		CreatedAt: time.Now().UTC(),
	}
}

func TestPost_ValidTransaction(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)
	ctx := context.Background()

	cash := makeAccount("Cash", Asset)
	revenue := makeAccount("Revenue", Revenue)
	s.CreateAccount(ctx, cash)
	s.CreateAccount(ctx, revenue)

	entries := []Entry{
		{AccountID: cash.ID, AmountMinor: 1000, Currency: "USD", IsDebit: true},
		{AccountID: revenue.ID, AmountMinor: 1000, Currency: "USD", IsDebit: false},
	}

	tx, err := e.Post(ctx, "First sale", entries)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if tx.Hash == "" {
		t.Fatal("expected hash to be set")
	}
	if tx.PrevHash != "genesis" {
		t.Errorf("expected prev_hash=genesis, got %q", tx.PrevHash)
	}
}

func TestPost_UnbalancedTransaction(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)
	ctx := context.Background()

	cash := makeAccount("Cash", Asset)
	s.CreateAccount(ctx, cash)

	entries := []Entry{
		{AccountID: cash.ID, AmountMinor: 1000, Currency: "USD", IsDebit: true},
		{AccountID: cash.ID, AmountMinor: 500, Currency: "USD", IsDebit: false},
	}

	_, err := e.Post(ctx, "Bad tx", entries)
	if err == nil {
		t.Fatal("expected error for unbalanced transaction, got nil")
	}
}

func TestBalance_AssetAccount(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)
	ctx := context.Background()

	cash := makeAccount("Cash", Asset)
	revenue := makeAccount("Revenue", Revenue)
	s.CreateAccount(ctx, cash)
	s.CreateAccount(ctx, revenue)

	entries := []Entry{
		{AccountID: cash.ID, AmountMinor: 5000, Currency: "USD", IsDebit: true},
		{AccountID: revenue.ID, AmountMinor: 5000, Currency: "USD", IsDebit: false},
	}
	e.Post(ctx, "Sale", entries)

	balance, err := e.Balance(ctx, cash.ID.String(), "USD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if balance != 5000 {
		t.Errorf("expected balance 5000, got %d", balance)
	}
}

func TestBalance_RevenueAccount(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)
	ctx := context.Background()

	cash := makeAccount("Cash", Asset)
	revenue := makeAccount("Revenue", Revenue)
	s.CreateAccount(ctx, cash)
	s.CreateAccount(ctx, revenue)

	entries := []Entry{
		{AccountID: cash.ID, AmountMinor: 5000, Currency: "USD", IsDebit: true},
		{AccountID: revenue.ID, AmountMinor: 5000, Currency: "USD", IsDebit: false},
	}
	e.Post(ctx, "Sale", entries)

	// Revenue is credit-normal: raw = -5000, × NormalBalance(-1) = +5000
	balance, err := e.Balance(ctx, revenue.ID.String(), "USD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if balance != 5000 {
		t.Errorf("expected balance 5000, got %d", balance)
	}
}

func TestVerifyChain_Intact(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)
	ctx := context.Background()

	cash := makeAccount("Cash", Asset)
	revenue := makeAccount("Revenue", Revenue)
	s.CreateAccount(ctx, cash)
	s.CreateAccount(ctx, revenue)

	for i := 0; i < 3; i++ {
		entries := []Entry{
			{AccountID: cash.ID, AmountMinor: 100, Currency: "USD", IsDebit: true},
			{AccountID: revenue.ID, AmountMinor: 100, Currency: "USD", IsDebit: false},
		}
		if _, err := e.Post(ctx, "tx", entries); err != nil {
			t.Fatalf("post failed: %v", err)
		}
	}

	if err := e.VerifyChain(ctx); err != nil {
		t.Errorf("expected chain intact, got: %v", err)
	}
}

func TestVerifyChain_Tampered(t *testing.T) {
	s := newFakeStore()
	e := NewEngine(s)
	ctx := context.Background()

	cash := makeAccount("Cash", Asset)
	revenue := makeAccount("Revenue", Revenue)
	s.CreateAccount(ctx, cash)
	s.CreateAccount(ctx, revenue)

	entries := []Entry{
		{AccountID: cash.ID, AmountMinor: 100, Currency: "USD", IsDebit: true},
		{AccountID: revenue.ID, AmountMinor: 100, Currency: "USD", IsDebit: false},
	}
	e.Post(ctx, "tx", entries)

	// Tamper: corrupt the stored hash directly
	s.transactions[0].Hash = "deadbeef"

	if err := e.VerifyChain(ctx); err == nil {
		t.Error("expected tamper detection, got nil")
	}
}
