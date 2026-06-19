package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

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

func initEngine() (*engine.Engine, *pgxpool.Pool, func()) {
	viper.AutomaticEnv()
	dbURL := viper.GetString("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL environment variable is required")
		os.Exit(1)
	}

	cfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse database URL: %v\n", err)
		os.Exit(1)
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"

	nCPU := runtime.NumCPU()
	if nCPU < 4 {
		nCPU = 4
	}
	cfg.MaxConns = int32(nCPU)
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to database: %v\n", err)
		os.Exit(1)
	}
	slog.Info("db pool configured",
		"max_conns", cfg.MaxConns,
		"min_conns", cfg.MinConns,
	)

	s := store.NewPostgresStore(pool)
	cb := store.NewCircuitBreakerStore(s)
	e := engine.NewEngine(cb)
	cleanup := func() { pool.Close() }
	return e, pool, cleanup
}
