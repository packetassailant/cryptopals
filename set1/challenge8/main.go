// Code to detect AES in ECB mode
// 1. STDIN file of hex encoded ciphertexts
// 2. Hex decode to byte slice
// 3. Read each ciphertext into a slice of keyblock length slices
// 4. Iterate and compare each ciphertexts keyblock slices to test for equality

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
)

func readFile(fn string) (err error) {
	file, err := os.Open(fn)
	defer file.Close()

	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(file)

	blocksize := 16
	for scanner.Scan() {
		line := scanner.Text()
		ciphertext, _ := hex.DecodeString(line)
		fmt.Println("Processing Line: ", line)
		var cipherSlice [][]byte
		for bs, be := 0, blocksize; bs < len(ciphertext); bs, be = bs+blocksize, be+blocksize {
			cipherSlice = append(cipherSlice, ciphertext[bs:be])
		}
		for a := 0; a < len(cipherSlice)-1; a++ {
			for b := a + 1; b < len(cipherSlice); b++ {
				if reflect.DeepEqual(cipherSlice[a], cipherSlice[b]) {
					fmt.Printf("Found a block match of %v at postion %d\n", cipherSlice[a], b)
				}
			}
		}
	}
	return
}

func main() {
	file := os.Args[1:]
	readFile(file[0])
}
