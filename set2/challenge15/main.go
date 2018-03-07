// PKCS#7 Padding Validation
// 1. This simply calls our prior Pkcs7Unpad function
// 2. Loops over padding length and if the literal length integer doesn't match a byte of same integer value then function throws error

package main

import (
	"fmt"
	"log"

	"github.com/packetassailant/cryptopals/crypt"
)

func main() {
	valStr := []byte("ICE ICE BABY\x04\x04\x04\x04")
	inValStr := []byte("HOT HOT BABY\x04\x03\x04\x04")

	valResult, err := crypt.Pkcs7Unpad(valStr, 16)
	fmt.Printf("Valid result: %v\n", valResult)
	inValResult, err := crypt.Pkcs7Unpad(inValStr, 16)
	//The following falls to error as expected
	fmt.Printf("Invalid result: %v\n", inValResult)
	if err != nil {
		log.Fatal(err)
	}
}
