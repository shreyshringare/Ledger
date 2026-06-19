package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/spf13/cobra"
)

var postCmd = &cobra.Command{
	Use:   "post",
	Short: "Post a double-entry transaction",
	Example: `  ledger post --desc "Pay rent" \
      --debit "Rent Expense:10000:USD" \
      --credit "Cash:10000:USD"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		desc, _ := cmd.Flags().GetString("desc")
		debits, _ := cmd.Flags().GetStringArray("debit")
		credits, _ := cmd.Flags().GetStringArray("credit")

		e, _, cleanup := initEngine()
		defer cleanup()

		ctx := context.Background()

		var entries []engine.Entry

		for _, d := range debits {
			entry, err := parseEntry(ctx, e, d, true)
			if err != nil {
				return fmt.Errorf("debit %q: %w", d, err)
			}
			entries = append(entries, entry)
		}

		for _, c := range credits {
			entry, err := parseEntry(ctx, e, c, false)
			if err != nil {
				return fmt.Errorf("credit %q: %w", c, err)
			}
			entries = append(entries, entry)
		}

		tx, err := e.Post(ctx, desc, entries)
		if err != nil {
			return fmt.Errorf("post transaction: %w", err)
		}

		fmt.Printf("Transaction posted: %s\n", tx.ID)
		fmt.Printf("Hash: %s\n", tx.Hash)
		fmt.Printf("Entries: %d\n", len(tx.Entries))
		return nil
	},
}

// parseEntry parses "AccountName:AmountMinor:Currency" into an Entry.
func parseEntry(ctx context.Context, e *engine.Engine, raw string, isDebit bool) (engine.Entry, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 3 {
		return engine.Entry{}, fmt.Errorf("format must be AccountName:AmountMinor:Currency (got %q)", raw)
	}

	accountName := parts[0]
	amountStr := parts[1]
	currency := parts[2]

	amount, err := strconv.ParseInt(amountStr, 10, 64)
	if err != nil {
		return engine.Entry{}, fmt.Errorf("invalid amount %q: %w", amountStr, err)
	}
	if amount <= 0 {
		return engine.Entry{}, fmt.Errorf("amount must be positive, got %d", amount)
	}

	acc, err := e.Store().GetAccountByName(ctx, accountName)
	if err != nil {
		return engine.Entry{}, fmt.Errorf("account %q not found: %w", accountName, err)
	}

	return engine.Entry{
		ID:          uuid.New(),
		AccountID:   acc.ID,
		AmountMinor: amount,
		Currency:    currency,
		IsDebit:     isDebit,
	}, nil
}

func init() {
	postCmd.Flags().String("desc", "", "Transaction description (required)")
	postCmd.Flags().StringArray("debit", []string{}, "Debit entry: AccountName:AmountMinor:Currency")
	postCmd.Flags().StringArray("credit", []string{}, "Credit entry: AccountName:AmountMinor:Currency")
	postCmd.MarkFlagRequired("desc")
	rootCmd.AddCommand(postCmd)
}
