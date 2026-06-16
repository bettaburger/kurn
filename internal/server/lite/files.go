package lite

import (
	"database/sql"
	"fmt"
)

// delete pcap file from pcap.db by ID number 
func DelPFile(db *sql.DB, id int) (int64, error){
	delQ := `DELETE FROM pcapfiles WHERE id = ?`
	row, err := db.Exec(delQ, id)
	if err != nil {
		return 0, fmt.Errorf("del pcapfile: %v", err)
	}
	return ReturnRows(row)
}

// returns number of rows affected by an update, insert or delete
func ReturnRows(row sql.Result) (int64, error) { return row.RowsAffected() }

// list current queries in db
// next -> filter queries via id, pf, path, size or hash
func ListSavedFiles(db *sql.DB) ([]PFile, error) {
	listQ := `SELECT * FROM pcapfiles`
	rows, err := db.Query(listQ)
	if err != nil {
		return nil, err
	}
	// hold files
	var files []PFile
	for rows.Next() {
		var pf PFile
		if err := rows.Scan(&pf.id, &pf.Filename, &pf.Path, &pf.Size, &pf.Hash256); err != nil {
			return files, err
		}
		files = append(files, pf)
	}
	if err = rows.Err(); err != nil {
		return files, err 
	}
	return files, nil
}

func ListFormat(files []PFile) {
	for _, file := range files {
		fmt.Printf("ID: %v \n", file.id, file.Filename, file.Path, file.Size)
	} 
	

}
