package lite

import (
	"database/sql"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"io"
	"fmt"
)

type PFile struct {
	id int64
	Filename string
	Path string
	Size uint64
	Hash256 string 
}

func CreateTable(db *sql.DB) (sql.Result, error) {
	query := `CREATE TABLE IF NOT EXISTS pcapfiles(
	id INTEGER PRIMARY KEY AUTOINCREMENT, 
	filename TEXT, 
	path TEXT, 
	size INTEGER,
	hash256 TEXT UNIQUE
	);`
	return db.Exec(query)
}

// insert pcap file into pcap.db
func InsertPFile(db *sql.DB, pf PFile) (int64, error) {
	query := `INSERT INTO pcapfiles(filename, path, size, hash256) 
	VALUES (?, ?, ?, ?)
	ON CONFLICT(hash256) DO NOTHING;
	`
	result, err := db.Exec(query, pf.Filename, pf.Path, pf.Size, pf.Hash256)
	if err != nil {
		return 0, fmt.Errorf("add pcapfile: %v", err)
	}
	rows, _ := ReturnRows(result) 
	if rows == 0 {
		return 0, fmt.Errorf("pcap file already exits")
	}
	
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("add pcapfile: %v", err)
	}
	return id, nil // return new album id
}


// hash packet contents
func CreateSHA256HashFile(filepath string) string {
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Println("unable to open file for hash: ", err)
	}
	defer file.Close()
	h := sha256.New()
	// create the buffer
	var bufferSize uint64 = 1024*1024 //1MB
	buf := make([]byte, bufferSize)
	for {
		// number of bytes
		n, err := file.Read(buf)
		if n > 0 {
			_, err := h.Write(buf[:n])
			if err != nil {
				fmt.Println("error hashing ", err)
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("error reading file ", err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func getSHA256Hash(data string) string {
	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}