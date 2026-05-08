package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"database/sql"
	"github.com/bettaburger/kurn/internal/server/lite"
	"github.com/bettaburger/kurn/internal/server"
	_ "github.com/mattn/go-sqlite3"

)
var read string

// ReadPCAP describes read command
var ReadPCAP = &cobra.Command {
	Use: "read [path to pcap file]", 
	Short: "read file packets and parse",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// run process 
		pcapFile := args[0]

		db, err := sql.Open("sqlite3", "pcap.db") 
		if err != nil {
			return err
		}
		defer db.Close()

		// create table 
		_, err = lite.CreateTable(db)
		if err != nil {
			fmt.Println(err)
		}
		fileInfo, err := os.Stat(pcapFile)
		if err != nil {
			return err
		}
		// pcapfile per read
		pf := lite.PFile{
			Filename: fileInfo.Name(),
			Path: pcapFile, 
			Size: uint64(fileInfo.Size()),
		}
		// call hash
		hash := lite.CreateSHA256HashFile(pcapFile)
		pf.Hash256 = hash

		id, err := lite.InsertPFile(db, pf)
		if err != nil {
			return err
		}
		fmt.Println("Inserted ID:", id)
		fmt.Println("Hash:", pf.Hash256)
		server.Process(pcapFile) //pcap.db build 
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ReadPCAP)
	ReadPCAP.Flags().StringVarP(&read, "read", "r", "READ", "parse the pcap file")	// run via ./kurn read

}