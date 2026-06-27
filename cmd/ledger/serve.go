// cmd/ledger/serve.go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/shreyshringare/Ledger/internal/api"
	"github.com/shreyshringare/Ledger/internal/engine"
	"github.com/shreyshringare/Ledger/internal/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serveCmd = &cobra.Command{
	Use:          "serve",
	Short:        "Start the HTTP API server",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		e, pool, cleanup := initEngine()
		defer cleanup()

		// Create a context that lives for the duration of the serve command.
		// Used for background goroutines (idempotency cleanup, etc.).
		serveCtx, serveCancel := context.WithCancel(context.Background())
		defer serveCancel()

		// Start idempotency key TTL cleanup (runs hourly, 7-day expiry)
		e.StartIdempotencyCleanup(serveCtx)

		// Fraud velocity checks: 5 txn/min, $10,000/hour per account (Visa/Mastercard standard)
		e = e.WithVelocityChecker(engine.NewVelocityChecker(5, 60, 1_000_000, 3600))

		viper.AutomaticEnv()
		port := viper.GetString("PORT")
		if port == "" {
			port = "8080"
		}

		apiKeyStore := store.NewPostgresStore(pool)
		handler := api.NewHandler(e, api.WithAPIKeyStore(apiKeyStore))
		handler.InitRateLimiter(100, 60) // 100 requests per 60 seconds per API key

		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.Handle("/", api.BuildRouter(handler))

		srv := &http.Server{
			Addr:         ":" + port,
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		// Start server in background goroutine
		go func() {
			slog.Info("Ledger API listening", "addr", srv.Addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "server error: %v\n", err)
				os.Exit(1)
			}
		}()

		// Block until SIGTERM or SIGINT (Ctrl+C)
		// Buffered channel of size 1: signal.Notify requires buffered channel
		// to avoid missing the signal if goroutine isn't ready to receive yet.
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
		<-quit

		slog.Info("shutdown signal received — draining in-flight requests (30s max)")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}

		slog.Info("server stopped cleanly")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
