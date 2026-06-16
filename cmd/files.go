package cmd

import (
	"github.com/spf13/cobra"
	"github.com/bettaburger/kurn/internal/server/lite"
	"database/sql"
	"fmt"
	"strconv"
)

var list bool	// list history
var delete bool // delete a file from history


// FilesCmd describes files command
var FilesCmd = &cobra.Command {
	Use: "files",
	Short: "display previous files",
	RunE: func(cmd *cobra.Command, args []string) error {
		// show saved files from db
		switch {
		case list:
			db, err := sql.Open("sqlite3", "pcap.db") 
			if err != nil {
				return err
			}
			defer db.Close()
			// call list files
			files, err := lite.ListSavedFiles(db)
			if err != nil {
				fmt.Println("filescmd error: ", err)
			}
			for _, f := range files {
				fmt.Println(f)
			}
		
		case delete:
			id, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("must be an integer (1...n) %v", err) 
			}
			db, err := sql.Open("sqlite3", "pcap.db")
			if err != nil {
				return err 
			}
			defer db.Close() 
			// call delete function 
			rows, err := lite.DelPFile(db, id)
			if err != nil {
				return fmt.Errorf("failed to delete file %d, %v", id, err)
			}
			if rows == 0 {
				fmt.Printf("no row found with id %d\n try ./kurn files -l for full list \n", id)
				return nil
			}
			fmt.Printf("deleted %d\n", id)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(FilesCmd)
	FilesCmd.Flags().BoolVarP(&list, "list",  "l", false, "display history of pcap files") // ./kurn files -l
	FilesCmd.Flags().BoolVarP(&delete, "delete", "d", false, "delete a pcap file from history") // ./kurn files -d <id>
}

