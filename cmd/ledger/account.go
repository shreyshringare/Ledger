package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/spf13/cobra"
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage accounts",
}

var accountCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new account",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		accType, _ := cmd.Flags().GetString("type")
		currency, _ := cmd.Flags().GetString("currency")

		e, cleanup := initEngine()
		defer cleanup()

		acc := engine.Account{
			ID:        uuid.New(),
			Name:      name,
			Type:      engine.AccountType(accType),
			Currency:  currency,
			IsActive:  true,
			CreatedAt: time.Now().UTC(),
		}

		if err := e.Store().CreateAccount(context.Background(), acc); err != nil {
			return fmt.Errorf("create account: %w", err)
		}

		fmt.Printf("Account created: %s (%s) [%s]\n", acc.Name, acc.Type, acc.ID)
		return nil
	},
}

var accountListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		e, cleanup := initEngine()
		defer cleanup()

		accounts, err := e.Store().ListAccounts(context.Background())
		if err != nil {
			return fmt.Errorf("list accounts: %w", err)
		}

		if len(accounts) == 0 {
			fmt.Println("No accounts found.")
			return nil
		}

		fmt.Printf("%-36s  %-20s  %-12s  %s\n", "ID", "Name", "Type", "Currency")
		fmt.Println("─────────────────────────────────────────────────────────────────────────")
		for _, a := range accounts {
			fmt.Printf("%-36s  %-20s  %-12s  %s\n", a.ID, a.Name, a.Type, a.Currency)
		}
		return nil
	},
}

func init() {
	accountCreateCmd.Flags().String("name", "", "Account name (required)")
	accountCreateCmd.Flags().String("type", "", "Account type: ASSET, LIABILITY, EQUITY, REVENUE, EXPENSE (required)")
	accountCreateCmd.Flags().String("currency", "USD", "Currency code")
	accountCreateCmd.MarkFlagRequired("name")
	accountCreateCmd.MarkFlagRequired("type")

	accountCmd.AddCommand(accountCreateCmd)
	accountCmd.AddCommand(accountListCmd)
	rootCmd.AddCommand(accountCmd)
}
