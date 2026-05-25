package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/shreyshringare/Ledger/internal/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:          "ledger",
	Short:        "A double-entry accounting engine with SHA-256 hash chaining",
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// migrateURL converts a postgres:// URL to pgx5:// for golang-migrate's pgx/v5 driver.
func migrateURL(dbURL string) string {
	for _, prefix := range []string{"postgres://", "postgresql://"} {
		if strings.HasPrefix(dbURL, prefix) {
			return "pgx5://" + dbURL[len(prefix):]
		}
	}
	return dbURL // already pgx5:// or other scheme
}

func initEngine() (*engine.Engine, func()) {
	viper.AutomaticEnv()
	dbURL := viper.GetString("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL environment variable is required")
		os.Exit(1)
	}

	if err := store.RunMigrations(migrateURL(dbURL)); err != nil {
		fmt.Fprintf(os.Stderr, "migrations failed: %v\n", err)
		os.Exit(1)
	}

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to database: %v\n", err)
		os.Exit(1)
	}

	s := store.NewPostgresStore(pool)
	e := engine.NewEngine(s)
	cleanup := func() { pool.Close() }
	return e, cleanup
}
