package reconcile

import (
	"context"
	"fmt"
	"time"

	"github.com/shreyshringare/Ledger/internal/engine"
)

// StatementEntry represents one line from an external bank statement.
// ExternalID is the bank's reference number for the transaction.
type StatementEntry struct {
	ExternalID  string    `json:"external_id"`
	Description string    `json:"description"`
	AmountMinor int64     `json:"amount_minor"` // positive = credit to account, negative = debit
	Currency    string    `json:"currency"`
	Date        time.Time `json:"date"`
}

// MatchStatus describes the reconciliation result for one statement entry.
type MatchStatus string

const (
	Matched   MatchStatus = "matched"   // found in ledger, amounts agree
	Missing   MatchStatus = "missing"   // not found in ledger at all
	Mismatch  MatchStatus = "mismatch"  // found but amount differs
	Duplicate MatchStatus = "duplicate" // external_id appears more than once in statement
)

// ReconciliationResult is the outcome for one statement entry.
type ReconciliationResult struct {
	Entry        StatementEntry `json:"entry"`
	Status       MatchStatus    `json:"status"`
	LedgerTxID   string         `json:"ledger_tx_id,omitempty"`
	LedgerAmount int64          `json:"ledger_amount_minor,omitempty"`
	Note         string         `json:"note,omitempty"`
}

// Summary aggregates the reconciliation run.
type Summary struct {
	Total      int `json:"total"`
	Matched    int `json:"matched"`
	Missing    int `json:"missing"`
	Mismatched int `json:"mismatched"`
	Duplicate  int `json:"duplicate"`
}

// Reconcile compares statement entries against all transactions in the ledger
// for the given accountID. Matching strategy: a ledger transaction "matches" a
// statement entry when the net amount on accountID equals the statement amount
// and the transaction description contains the external ID.
//
// This is the same reconciliation logic used in real banking settlement systems:
// after each settlement cycle, the ledger is compared line-by-line against the
// external statement and any discrepancy triggers an investigation workflow.
func Reconcile(ctx context.Context, s engine.Store, accountID string, statement []StatementEntry) ([]ReconciliationResult, Summary, error) {
	txs, err := s.ListTransactions(ctx)
	if err != nil {
		return nil, Summary{}, fmt.Errorf("list transactions: %w", err)
	}

	// Index ledger: map description substring → net amount on accountID
	type ledgerEntry struct {
		txID   string
		amount int64 // positive = net debit on account, negative = net credit
	}
	ledgerIndex := make(map[string]ledgerEntry)
	for _, tx := range txs {
		var net int64
		for _, e := range tx.Entries {
			if e.AccountID.String() != accountID {
				continue
			}
			if e.IsDebit {
				net += e.AmountMinor
			} else {
				net -= e.AmountMinor
			}
		}
		if net != 0 {
			ledgerIndex[tx.Description] = ledgerEntry{txID: tx.ID.String(), amount: net}
		}
	}

	// Detect duplicates in statement
	seen := make(map[string]int)
	for _, e := range statement {
		seen[e.ExternalID]++
	}

	results := make([]ReconciliationResult, 0, len(statement))
	var summary Summary
	summary.Total = len(statement)

	for _, entry := range statement {
		result := ReconciliationResult{Entry: entry}

		if seen[entry.ExternalID] > 1 {
			result.Status = Duplicate
			result.Note = fmt.Sprintf("external_id %q appears %d times in statement", entry.ExternalID, seen[entry.ExternalID])
			summary.Duplicate++
			results = append(results, result)
			continue
		}

		ledger, found := ledgerIndex[entry.Description]
		if !found {
			result.Status = Missing
			result.Note = fmt.Sprintf("no ledger transaction found matching description %q", entry.Description)
			summary.Missing++
			results = append(results, result)
			continue
		}

		if ledger.amount != entry.AmountMinor {
			result.Status = Mismatch
			result.LedgerTxID = ledger.txID
			result.LedgerAmount = ledger.amount
			result.Note = fmt.Sprintf("amount mismatch: statement %d, ledger %d", entry.AmountMinor, ledger.amount)
			summary.Mismatched++
			results = append(results, result)
			continue
		}

		result.Status = Matched
		result.LedgerTxID = ledger.txID
		result.LedgerAmount = ledger.amount
		summary.Matched++
		results = append(results, result)
	}

	return results, summary, nil
}
