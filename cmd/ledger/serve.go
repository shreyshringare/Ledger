package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/shreyshringare/Ledger/internal/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serveCmd = &cobra.Command{
	Use:          "serve",
	Short:        "Start the HTTP API server",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		e, cleanup := initEngine()
		defer cleanup()

		viper.AutomaticEnv()
		port := viper.GetString("PORT")
		if port == "" {
			port = "8080"
		}

		addr := ":" + port
		fmt.Fprintf(os.Stdout, "Ledger API listening on %s\n", addr)
		return http.ListenAndServe(addr, api.BuildRouter(e))
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
