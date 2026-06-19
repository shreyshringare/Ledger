package engine

import (
	"time"

	"github.com/google/uuid"
)

type AccountType string

const (
	Asset     AccountType = "ASSET"
	Liability AccountType = "LIABILITY"
	Equity    AccountType = "EQUITY"
	Revenue   AccountType = "REVENUE"
	Expense   AccountType = "EXPENSE"
)

type Account struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Type       AccountType `json:"type"`
	Currency   string     `json:"currency"`
	IsActive   bool       `json:"is_active"`
	CreatedAt  time.Time  `json:"created_at"`
	ArchivedAt *time.Time `json:"archived_at,omitempty"`
}

// NormalBalance returns 1 if account type increases with debits like (Asset,Expense), else -1 if credits.
func (a Account) NormalBalance() int {
	switch a.Type {
	case Asset, Expense:
		return 1
	default:
		return -1
	}
}
