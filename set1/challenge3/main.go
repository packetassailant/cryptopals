// Code for Single Byte XOR cipher
// 1. STDIN XOR'ed cipher string
// 2. Decode hexidecimal string to bytes
// 3. Perform byte for byte (idx) XOR using single UTF8 ascii char
// 4. Iterate over each XOR'ed ascii char cipher text scoring the highest presence of UTF8 chars
// 5. HIghest XOR'ed cipher text bytes are formated to their UTF8 ascii equivs and printed

package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

var charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.' \\"

func encodeDecode(input []byte, key string) []byte {
	var bArr = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		bArr[i] += input[i] ^ key[i%len(key)]
	}
	return bArr
}

func scoreChars(text []byte) int {
	count := 0

	for _, x := range text {
		for _, y := range charSet {
			if byte(y) == x {
				count = count + 1
			}
		}
	}
	return count
}

func main() {
	scoreHolder := 0
	highXorScore := ""
	str := os.Args[1:]
	b1, err := hex.DecodeString(str[0])
	if err != nil {
		log.Fatal(err)
	}

	for x := 0; x <= 255; x++ {
		c := fmt.Sprintf("%c", x)
		results := encodeDecode(b1, c)
		if scoreChars(results) > scoreHolder {
			scoreHolder = scoreChars(results)
			highXorScore = string(results)
		}
	}
	fmt.Println(highXorScore)
}
