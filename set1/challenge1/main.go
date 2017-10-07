// Code to convert hex to base64
// 1. STDIN string
// 2. Decode hexidecimal string to bytes
// 3. Base64 encode the bytes

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	b64 "encoding/base64"
)

func main() {
	str := os.Args[1:]
	bs, err := hex.DecodeString(str[0])
	if err != nil {
		log.Fatal(err)
	}
	bEnc := b64.StdEncoding.EncodeToString(bs)
	fmt.Println(bEnc)
}
