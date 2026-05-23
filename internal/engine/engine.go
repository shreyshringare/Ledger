package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Engine struct {
	store Store
}

func NewEngine(s Store) *Engine {
	return &Engine{store: s}
}

func (e *Engine) Post(ctx context.Context, description string, entries []Entry) (Transaction, error) {
	prevHash, err := e.store.GetLastHash(ctx)
	if err != nil {
		return Transaction{}, fmt.Errorf("get last hash: %w", err)
	}

	txID := uuid.New()
	now := time.Now().UTC()
	for i := range entries {
		entries[i].ID = uuid.New()
		entries[i].TransactionID = txID
		entries[i].CreatedAt = now
	}

	tx := Transaction{
		ID:          txID,
		Description: description,
		PostedAt:    now,
		PrevHash:    prevHash,
		Entries:     entries,
	}

	if err := tx.Validate(); err != nil {
		return Transaction{}, fmt.Errorf("validation failed: %w", err)
	}

	hash, err := tx.ComputeHash(prevHash)
	if err != nil {
		return Transaction{}, fmt.Errorf("compute hash: %w", err)
	}
	tx.Hash = hash

	if err := e.store.PostTransaction(ctx, tx); err != nil {
		return Transaction{}, fmt.Errorf("post transaction: %w", err)
	}

	return tx, nil
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
