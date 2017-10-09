// Code to detect a single XOR char string within a file
// 1. STDIN XOR'ed cipher string
// 2. Decode hexidecimal string to bytes
// 3. Perform byte for byte (idx) XOR using single UTF8 ascii char
// 4. Iterate over each XOR'ed ascii char cipher text scoring the highest presence of UTF8 chars
// 5. Maintain a func variable to score char total for each string in file
// 6. Highest XOR cipher text char count gets ascii formatted and printed

package main

import (
	"bufio"
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

func processCipherText(f *os.File) {
	scoreHolder := 0
	highXorScore := ""
	xorStr := ""
	origCipherTxt := ""

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		xorStr = scanner.Text()
		b1, err := hex.DecodeString(xorStr)
		if err != nil {
			log.Fatal(err)
		}
		for x := 0; x <= 255; x++ {
			c := fmt.Sprintf("%c", x)
			results := encodeDecode(b1, c)
			if scoreChars(results) > scoreHolder {
				scoreHolder = scoreChars(results)
				highXorScore = string(results)
				origCipherTxt = xorStr
			}
		}
	}
	fmt.Printf("Character Score: %d\n", scoreHolder)
	fmt.Printf("Original Cipher Text: %s\n", origCipherTxt)
	fmt.Printf("The Decrypted Text: %s\n", highXorScore)
}

func main() {
	file := os.Args[1:]
	fh, err := os.Open(file[0])
	if err != nil {
		log.Fatal(err)
	}
	processCipherText(fh)
}
