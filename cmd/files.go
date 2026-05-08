package cmd

import (
	"github.com/spf13/cobra"
	"github.com/bettaburger/kurn/internal/server/lite"
	"database/sql"
	"fmt"

)

var saved string

// FileSaved describes saved command
var FileSaved = &cobra.Command {
	Use: "saved",
	Short: "display saved pcap files",
	RunE: func(cmd *cobra.Command, args []string) error {
		// show saved files from db
		db, err := sql.Open("sqlite3", "pcap.db") 
		if err != nil {
			return err
		}
		defer db.Close()
		files, err := lite.ListSavedFiles(db)
		if err != nil {
			fmt.Println("saved files error: ", err)
		}
		for _, f := range files {
			fmt.Println(f)
		}
		return nil
	},
}

// DeleteFile describes delete file command
var DeleteFile = &cobra.Command {
	Use: "delete",
	Short: "delete",
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil 
	},
}
func init() {
	rootCmd.AddCommand(FileSaved)
	FileSaved.Flags().StringVarP(&saved, "saved", "s", "SAVED", "display saved pcap files") // ./kurn saved



}

