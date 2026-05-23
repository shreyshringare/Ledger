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
	ID        uuid.UUID
	Name      string
	Type      AccountType
	Currency  string
	IsActive  bool
	CreatedAt time.Time
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
