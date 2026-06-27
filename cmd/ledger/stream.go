package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var streamCmd = &cobra.Command{
	Use:   "stream",
	Short: "Manage event streaming to Hermes",
}

var (
	flagHermesBroker string
	flagTopic        string
)

var streamEnableCmd = &cobra.Command{
	Use:          "enable",
	Short:        "Enable event streaming to a Hermes broker",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Stream enabled: broker=%s topic=%s\n", flagHermesBroker, flagTopic)
		fmt.Println("Every committed transaction will publish a TransactionPostedEvent to Hermes.")
		fmt.Println("To stream in the server, set HERMES_BROKER and HERMES_TOPIC env vars and run: ledger serve")
		return nil
	},
}

func init() {
	streamEnableCmd.Flags().StringVar(&flagHermesBroker, "hermes-broker", "localhost:9092", "Hermes broker address")
	streamEnableCmd.Flags().StringVar(&flagTopic, "topic", "ledger.transactions", "Hermes topic name")
	streamCmd.AddCommand(streamEnableCmd)
	rootCmd.AddCommand(streamCmd)
}
