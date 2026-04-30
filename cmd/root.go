package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command {
	Use: "kurn",
	Short: "Network traffic analyzer",
	Long: "Kurn is a CLI tool for PCAP anaylsis and packet trace extraction for network traffic protocols.",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println("cobra root error", err)
		os.Exit(1)
	}
}