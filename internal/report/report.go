package report

import (
	"context"
	"fmt"

	"github.com/shreyshringare/Ledger/internal/engine"
)

// TrialBalanceRow is one account's net balance in the trial balance.
type TrialBalanceRow struct {
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
	AccountType string `json:"account_type"`
	Currency    string `json:"currency"`
	DebitTotal  int64  `json:"debit_total_minor"`
	CreditTotal int64  `json:"credit_total_minor"`
	NetBalance  int64  `json:"net_balance_minor"` // positive = debit-side, negative = credit-side
}

// TrialBalance computes a trial balance from all transactions.
// Sum of all DebitTotal must equal sum of all CreditTotal if the ledger is valid.
func TrialBalance(ctx context.Context, s engine.Store) ([]TrialBalanceRow, error) {
	accounts, err := s.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	txs, err := s.ListTransactions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}

	type accKey struct{ id, currency string }
	debits := make(map[accKey]int64)
	credits := make(map[accKey]int64)

	for _, tx := range txs {
		for _, e := range tx.Entries {
			key := accKey{e.AccountID.String(), e.Currency}
			if e.IsDebit {
				debits[key] += e.AmountMinor
			} else {
				credits[key] += e.AmountMinor
			}
		}
	}

	accMap := make(map[string]engine.Account)
	for _, a := range accounts {
		accMap[a.ID.String()] = a
	}

	// Collect all unique account+currency keys
	seen := make(map[accKey]bool)
	for k := range debits {
		seen[k] = true
	}
	for k := range credits {
		seen[k] = true
	}

	rows := make([]TrialBalanceRow, 0, len(seen))
	for k := range seen {
		acc := accMap[k.id]
		d := debits[k]
		c := credits[k]
		rows = append(rows, TrialBalanceRow{
			AccountID:   k.id,
			AccountName: acc.Name,
			AccountType: string(acc.Type),
			Currency:    k.currency,
			DebitTotal:  d,
			CreditTotal: c,
			NetBalance:  d - c,
		})
	}
	return rows, nil
}

// PnLResult is the profit and loss summary.
type PnLResult struct {
	TotalRevenue int64  `json:"total_revenue_minor"`
	TotalExpense int64  `json:"total_expense_minor"`
	NetIncome    int64  `json:"net_income_minor"` // Revenue - Expense
	Currency     string `json:"currency"`
}

// PnL computes profit and loss by summing Revenue and Expense account entries.
// Only entries matching currency are included; pass "" to aggregate all currencies.
func PnL(ctx context.Context, s engine.Store, currency string) ([]PnLResult, error) {
	accounts, err := s.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	txs, err := s.ListTransactions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}

	// Index account types
	accTypes := make(map[string]engine.AccountType)
	for _, a := range accounts {
		accTypes[a.ID.String()] = a.Type
	}

	// Sum revenue (credit increases) and expense (debit increases) by currency
	type totals struct{ revenue, expense int64 }
	byCurrency := make(map[string]*totals)

	for _, tx := range txs {
		for _, e := range tx.Entries {
			if currency != "" && e.Currency != currency {
				continue
			}
			t, ok := byCurrency[e.Currency]
			if !ok {
				t = &totals{}
				byCurrency[e.Currency] = t
			}
			accType := accTypes[e.AccountID.String()]
			switch accType {
			case engine.Revenue:
				// Revenue increases on credit side
				if !e.IsDebit {
					t.revenue += e.AmountMinor
				}
			case engine.Expense:
				// Expense increases on debit side
				if e.IsDebit {
					t.expense += e.AmountMinor
				}
			}
		}
	}

	results := make([]PnLResult, 0, len(byCurrency))
	for cur, t := range byCurrency {
		results = append(results, PnLResult{
			TotalRevenue: t.revenue,
			TotalExpense: t.expense,
			NetIncome:    t.revenue - t.expense,
			Currency:     cur,
		})
	}
	return results, nil
}

// BalanceSheetResult summarises Assets, Liabilities, and Equity at a point in time.
type BalanceSheetResult struct {
	TotalAssets      int64  `json:"total_assets_minor"`
	TotalLiabilities int64  `json:"total_liabilities_minor"`
	TotalEquity      int64  `json:"total_equity_minor"`
	IsBalanced       bool   `json:"is_balanced"` // Assets == Liabilities + Equity
	Currency         string `json:"currency"`
}

// BalanceSheet computes a balance sheet grouped by currency.
// Pass currency="" to return all currencies.
func BalanceSheet(ctx context.Context, s engine.Store, currency string) ([]BalanceSheetResult, error) {
	accounts, err := s.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	txs, err := s.ListTransactions(ctx)
	if err != nil {
		return nil, fmt.Errorf("list transactions: %w", err)
	}

	accTypes := make(map[string]engine.AccountType)
	for _, a := range accounts {
		accTypes[a.ID.String()] = a.Type
	}

	type bals struct{ assets, liabilities, equity int64 }
	byCurrency := make(map[string]*bals)

	for _, tx := range txs {
		for _, e := range tx.Entries {
			if currency != "" && e.Currency != currency {
				continue
			}
			b, ok := byCurrency[e.Currency]
			if !ok {
				b = &bals{}
				byCurrency[e.Currency] = b
			}
			// Net effect: debits increase assets/expenses, credits increase liabilities/equity/revenue
			switch accTypes[e.AccountID.String()] {
			case engine.Asset:
				if e.IsDebit {
					b.assets += e.AmountMinor
				} else {
					b.assets -= e.AmountMinor
				}
			case engine.Liability:
				if !e.IsDebit {
					b.liabilities += e.AmountMinor
				} else {
					b.liabilities -= e.AmountMinor
				}
			case engine.Equity:
				if !e.IsDebit {
					b.equity += e.AmountMinor
				} else {
					b.equity -= e.AmountMinor
				}
			}
		}
	}

	results := make([]BalanceSheetResult, 0, len(byCurrency))
	for cur, b := range byCurrency {
		results = append(results, BalanceSheetResult{
			TotalAssets:      b.assets,
			TotalLiabilities: b.liabilities,
			TotalEquity:      b.equity,
			IsBalanced:       b.assets == b.liabilities+b.equity,
			Currency:         cur,
		})
	}
	return results, nil
}
