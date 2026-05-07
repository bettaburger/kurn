package cmd

import (
	"github.com/spf13/cobra"
)

var saved string

var fileSaved = &cobra.Command {
	Use: "saved",
	Short: "display saved pcap files",
	RunE: func(cmd *cobra.Command, args []string) error {
		// do something 
		return nil
	},
}

func init() {
	rootCmd.AddCommand(fileSaved)
	fileSaved.Flags().StringVarP(&saved, "saved", "s", "SAVED", "display saved pcap files") // ./kurn saved

}

