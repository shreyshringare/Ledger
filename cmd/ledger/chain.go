package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

var chainCmd = &cobra.Command{
	Use:   "chain",
	Short: "Hash chain operations",
}

var chainVerifyCmd = &cobra.Command{
	Use:          "verify",
	Short:        "Verify the integrity of the transaction hash chain",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		e, cleanup := initEngine()
		defer cleanup()

		if err := e.VerifyChain(context.Background()); err != nil {
			fmt.Printf("TAMPER DETECTED: %v\n", err)
			return err
		}

		fmt.Println("Chain intact — no tampering detected")
		return nil
	},
}

func init() {
	chainCmd.AddCommand(chainVerifyCmd)
	rootCmd.AddCommand(chainCmd)
}
