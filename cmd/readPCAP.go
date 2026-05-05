package cmd

import (
	"github.com/spf13/cobra"
)

var readPCAP = &cobra.Command {
	Use: "read [path to pcap file]", 
	Short: "parse pcap file into readable code ",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// run process 
		pcapFile := args[0]
		process(pcapFile)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(readPCAP)
	readPCAP.Flags().StringVarP(&read, "read", "r", "READ", "parse pcap file")	// run via ./kurn read

}