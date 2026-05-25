package main

import (
	"fmt"
	"strings"

	"github.com/shreyshringare/Ledger/internal/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// migrateURL converts a postgres:// URL to pgx5:// for golang-migrate's pgx/v5 driver.
func migrateURL(dbURL string) string {
	for _, prefix := range []string{"postgres://", "postgresql://"} {
		if strings.HasPrefix(dbURL, prefix) {
			return "pgx5://" + dbURL[len(prefix):]
		}
	}
	return dbURL // already pgx5:// or other scheme
}

var migrateCmd = &cobra.Command{
	Use:          "migrate",
	Short:        "Run database migrations",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		viper.AutomaticEnv()
		dbURL := viper.GetString("DATABASE_URL")
		if dbURL == "" {
			return fmt.Errorf("DATABASE_URL environment variable is required")
		}

		if err := store.RunMigrations(migrateURL(dbURL)); err != nil {
			return fmt.Errorf("migrations failed: %w", err)
		}

		fmt.Println("Migrations applied successfully")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(migrateCmd)
}
