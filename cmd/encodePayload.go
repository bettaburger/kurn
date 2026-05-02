package cmd 

import "encoding/hex"
import "fmt"

func encodePayload(p []byte) {
	fmt.Println(hex.Dump([]byte(p)))
}

