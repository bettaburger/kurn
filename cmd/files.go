package cmd

import (
	"github.com/spf13/cobra"
	"github.com/bettaburger/kurn/internal/server/lite"
	"database/sql"
	"fmt"
	"strconv"

)

var saved string
var delete string

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
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// run del function
		id, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Must be an id number (1...n)")
		}
		db, err := sql.Open("sqlite3", "pcap.db")
		if err != nil {
			return err 
		}
		defer db.Close() 
		lite.DelPFile(db, id)
		fmt.Printf("deleted %d\n", id)
		return nil 
	},
}
func init() {
	rootCmd.AddCommand(FileSaved)
	rootCmd.AddCommand(DeleteFile)
	FileSaved.Flags().StringVarP(&saved, "saved", "s", "SAVED", "display saved pcap files") // ./kurn saved

	DeleteFile.Flags().StringVarP(&delete, "delete", "d", "DELETE", "delete a pcap file from saved") // ./kurn delete <id>



}

