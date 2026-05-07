package server 

import "encoding/hex"
import "fmt"

/*
converts the payload bytes into hex. function calls hexdump -C
hexademical, hex bytes, ascii 
*/
func encodePayload(p []byte) {
	fmt.Println(hex.Dump([]byte(p)))
}

// have a way to properly read the ascii translation
// tcp stream read
