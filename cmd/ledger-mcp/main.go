package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/shreyshringare/Ledger/internal/mcp"
	"github.com/shreyshringare/Ledger/internal/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "ledger-mcp",
	Short: "Ledger MCP server — exposes post_transaction, verify_chain, detect_fraud_rings as MCP tools",
}

var (
	flagStdio bool
	flagPort  int
)

var serveCmd = &cobra.Command{
	Use:          "serve",
	Short:        "Start the MCP server (--stdio or --http --port N)",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		e := initEngine()
		tools := mcp.NewTools(e)
		srv := mcp.NewServer(tools)

		if flagStdio {
			fmt.Fprintln(os.Stderr, "ledger-mcp: listening on stdio")
			return srv.ServeStdio(os.Stdin, os.Stdout)
		}

		addr := fmt.Sprintf(":%d", flagPort)
		fmt.Fprintf(os.Stderr, "ledger-mcp: listening on %s\n", addr)
		return http.ListenAndServe(addr, srv)
	},
}

func init() {
	serveCmd.Flags().BoolVar(&flagStdio, "stdio", false, "serve JSON-RPC 2.0 over stdin/stdout")
	serveCmd.Flags().IntVar(&flagPort, "port", 9000, "HTTP port when not using --stdio")
	rootCmd.AddCommand(serveCmd)
}

func initEngine() *engine.Engine {
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

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect to database: %v\n", err)
		os.Exit(1)
	}

	s := store.NewPostgresStore(pool)
	cb := store.NewCircuitBreakerStore(s)
	return engine.NewEngine(cb)
}
