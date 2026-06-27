package mcp

import "fmt"

// PostTransactionInput is validated BEFORE it ever reaches engine.Post().
// Reject malformed or out-of-range agent input at the boundary, not inside business logic.
type PostTransactionInput struct {
	Description string       `json:"description"`
	Entries     []EntryInput `json:"entries"`
	Currency    string       `json:"currency"`
}

// EntryInput represents one side of a double-entry transaction.
type EntryInput struct {
	AccountID   string `json:"account_id"`
	AmountMinor int64  `json:"amount_minor"`
	IsDebit     bool   `json:"is_debit"`
	Currency    string `json:"currency"`
}

// Validate hard-gates the input before it reaches the engine.
func (in PostTransactionInput) Validate() error {
	if len(in.Description) == 0 || len(in.Description) > 500 {
		return fmt.Errorf("description must be 1-500 characters")
	}
	if len(in.Entries) < 2 {
		return fmt.Errorf("transaction must have at least 2 entries")
	}
	for i, e := range in.Entries {
		if e.AmountMinor <= 0 {
			return fmt.Errorf("entry %d: amount must be positive, got %d", i, e.AmountMinor)
		}
		if e.AccountID == "" {
			return fmt.Errorf("entry %d: account_id required", i)
		}
		if len(e.Currency) != 3 {
			return fmt.Errorf("entry %d: currency must be 3-letter ISO code, got %q", i, e.Currency)
		}
	}
	return nil
}

// FraudRingInput filters for the detect_fraud_rings tool.
type FraudRingInput struct {
	MinFlowMinor int64 `json:"min_flow_minor"`
	MinCycleSize int   `json:"min_cycle_size"`
}

// Validate hard-gates the fraud ring filter inputs.
func (in FraudRingInput) Validate() error {
	if in.MinFlowMinor < 0 {
		return fmt.Errorf("min_flow_minor cannot be negative")
	}
	if in.MinCycleSize < 2 {
		return fmt.Errorf("min_cycle_size must be at least 2")
	}
	return nil
}
