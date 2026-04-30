package cmd

import (
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command {
	Use: "start", 
	Short: "open dashboard", 
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}