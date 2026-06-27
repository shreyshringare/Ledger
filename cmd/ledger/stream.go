package main

import (
	"fmt"

	"github.com/shreyshringare/Ledger/internal/stream"
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
		fmt.Printf("Connecting to Hermes broker at %s (topic: %s)...\n", flagHermesBroker, flagTopic)
		pub, err := stream.NewPublisher(flagHermesBroker, flagTopic)
		if err != nil {
			return fmt.Errorf("cannot reach Hermes broker at %s: %w", flagHermesBroker, err)
		}
		pub.Close()
		fmt.Printf("OK — broker reachable. Set these env vars before running `ledger serve`:\n")
		fmt.Printf("  export HERMES_BROKER=%s\n", flagHermesBroker)
		fmt.Printf("  export HERMES_TOPIC=%s\n", flagTopic)
		return nil
	},
}

func init() {
	streamEnableCmd.Flags().StringVar(&flagHermesBroker, "hermes-broker", "localhost:9092", "Hermes broker address")
	streamEnableCmd.Flags().StringVar(&flagTopic, "topic", "ledger.transactions", "Hermes topic name")
	streamCmd.AddCommand(streamEnableCmd)
	rootCmd.AddCommand(streamCmd)
}
