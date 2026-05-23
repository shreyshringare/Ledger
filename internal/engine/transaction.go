package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

type Entry struct {
	ID            uuid.UUID
	TransactionID uuid.UUID
	AccountID     uuid.UUID
	AmountMinor   int64
	Currency      string
	IsDebit       bool
	CreatedAt     time.Time
}

type Transaction struct {
	ID          uuid.UUID
	Description string
	PostedAt    time.Time
	Hash        string
	PrevHash    string
	Entries     []Entry
}

// Validate() checks the double-entry invariant: sum of debits == sum of credits.
func (t Transaction) Validate() error {
	var debits, credits int64
	for _, entry := range t.Entries {
		if entry.IsDebit {
			debits += entry.AmountMinor
		} else {
			credits += entry.AmountMinor
		}
	}
	if debits != credits {
		return fmt.Errorf("double-entry violation: debits %d != credits %d", debits, credits)
	}
	if len(t.Entries) < 2 {
		return fmt.Errorf("transaction must have at least 2 entries")
	}
	return nil
}

// ComputeHash produces a SHA-256 hash of this transaction's data.
// Entries are sorted by AccountID for deterministic hashing.

func (t Transaction) ComputeHash(prevHash string) (string, error) {
	type entrySnapshot struct {
		AccountID   string `json:"account_id"`
		AmountMinor int64  `json:"amount_minor"`
		Currency    string `json:"currency"`
		IsDebit     bool   `json:"is_debit"`
	}
	snapshots := make([]entrySnapshot, len(t.Entries))
	for i, e := range t.Entries {
		snapshots[i] = entrySnapshot{
			AccountID:   e.AccountID.String(),
			AmountMinor: e.AmountMinor,
			Currency:    e.Currency,
			IsDebit:     e.IsDebit,
		}
	}
	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].AccountID < snapshots[j].AccountID
	})

	entriesJSON, err := json.Marshal(snapshots)
	if err != nil {
		return "", fmt.Errorf("marshal entries: %w", err)
	}

	input := fmt.Sprintf("%s|%s|%s|%s",
		t.ID.String(),
		t.Description,
		prevHash,
		string(entriesJSON),
	)

	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash), nil
}
