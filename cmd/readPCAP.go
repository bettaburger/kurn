package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"database/sql"
	"github.com/bettaburger/kurn/internal/server"
	_ "github.com/mattn/go-sqlite3"

)
var read string

var readPCAP = &cobra.Command {
	Use: "read [path to pcap file]", 
	Short: "parse pcap file into readable code ",
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
		_, err = server.CreateTable(db)
		if err != nil {
			fmt.Println(err)
		}
		fileInfo, err := os.Stat(pcapFile)
		if err != nil {
			return err
		}

		pf := server.PFile{
			Filename: fileInfo.Name(),
			Path: pcapFile, 
			Size: uint64(fileInfo.Size()),
		}
		// hash
		hash := server.CreateSHA256HashFile(pcapFile)
		pf.Hash256 = hash

		id, err := server.InsertPFile(db, pf)
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
	rootCmd.AddCommand(readPCAP)
	readPCAP.Flags().StringVarP(&read, "read", "r", "READ", "parse the pcap file")	// run via ./kurn read

}