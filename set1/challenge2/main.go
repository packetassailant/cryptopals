// Code for Fixed XOR
// 1. STDIN two strings of equal length
// 2. Decode hexidecimal string to bytes
// 3. Perform byte for byte (idx) XOR

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func xorBytes(b ...[]byte) []byte {
	xorResult := make([]byte, len(b[0]))
	fmt.Printf("Original value: %v\n", b[0])
	fmt.Printf("XORed value: %v\n", b[1])
	for x := 0; x < len(b[1]); x++ {
		xorResult[x] = b[0][x] ^ b[1][x]
	}
	return xorResult
}

func main() {
	str := os.Args[1:]

	b1, err := hex.DecodeString(str[0])
	b2, err := hex.DecodeString(str[1])
	if err != nil {
		log.Fatal(err)
	}
	result := xorBytes(b1, b2)
	fmt.Printf("Byte to Hex result: %x\n", result)
}
