package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

var balanceCmd = &cobra.Command{
	Use:   "balance",
	Short: "Show the balance of an account",
	Example: `  ledger balance --name "Cash" --currency USD`,
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		currency, _ := cmd.Flags().GetString("currency")

		e, _, cleanup := initEngine()
		defer cleanup()

		ctx := context.Background()

		acc, err := e.Store().GetAccountByName(ctx, name)
		if err != nil {
			return fmt.Errorf("account %q not found: %w", name, err)
		}

		balance, err := e.Balance(ctx, acc.ID.String(), currency)
		if err != nil {
			return fmt.Errorf("get balance: %w", err)
		}

		fmt.Printf("Account:  %s (%s)\n", acc.Name, acc.Type)
		fmt.Printf("Currency: %s\n", currency)
		fmt.Printf("Balance:  %d (minor units)\n", balance)
		return nil
	},
}

func init() {
	balanceCmd.Flags().String("name", "", "Account name (required)")
	balanceCmd.Flags().String("currency", "USD", "Currency code")
	balanceCmd.MarkFlagRequired("name")
	rootCmd.AddCommand(balanceCmd)
}
