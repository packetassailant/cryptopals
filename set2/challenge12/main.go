// byte at a time ECB decrypt
// 1. Detect block size by prepadding the ciphertext until the length increases (count new bytes up until increase)
// 2. Detect unknown string size by prepadding the ciphertext until the length increases (count increase and round up for blocksize padding)
// 3. Detect ECB by feeding in at least 32 bytes of deterministic padding ("YELLOW SUBMARINEYELLOW SUBMARINE")
// 4. Detect the unknown string by:
// 4a. Preseeding padding (unknown string length),
// 4b. Encrypt based on #2 size where N will be the first char of the uknown string and [0:N-1] is padding "AAA+++N"
// 4c. Create a second preseeded ciphertext containing the same preseed value but N'th character is deterministic "AAA+++a", AAA+++b" so on
// 4d. Compare the equality of the ciphertexts until a match has been found
// 4e. Save the N'th characters into an array until the unknown string length has been exhausted (you have the unknown string)

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	"github.com/packetassailant/cryptopals/crypt"
	"github.com/packetassailant/cryptopals/rand"
)

var key = rand.String(16)

func encryptionOracle(plaintext, base64text string) (ciphertext []byte, err error) {
	ptBytes := []byte(plaintext)
	plainBytes, err := base64.StdEncoding.DecodeString(base64text)
	if err != nil {
		log.Fatal(err)
	}
	ptBytes = append(ptBytes, plainBytes...)
	return crypt.EncryptAesECB(ptBytes, []byte(key))
}

func detectBlockSize(initSize int, b string) int {
	count := 1
	//Start pre-padding the ciphertext
	for {
		a := strings.Repeat("A", count)
		ciphertext, err := encryptionOracle(a, b)
		if err != nil {
			log.Fatal(err)
		}
		if len(ciphertext) > initSize {
			return len(ciphertext) - initSize
		}
		count++
	}
}

func detectOracleSize(initSize int, b string) int {
	count := 1
	//Start pre-padding the ciphertext
	for {
		a := strings.Repeat("A", count)
		ciphertext, err := encryptionOracle(a, b)
		if err != nil {
			log.Fatal(err)
		}
		if len(ciphertext) > initSize {
			return len(ciphertext) - count
		}
		count++
	}
}

func bruteOracle(plaintext string, oraclesize, blocksize int) []byte {
	oracleSizeRnd := (oraclesize/blocksize + 1) * blocksize
	var unknownResult = []byte{}
	fmt.Println("-------Bruting Oracle-------")
	for x := oracleSizeRnd - 1; x > 0; x-- {
		bruteChars := strings.Repeat("A", x)
		bruteBlockOne, _ := encryptionOracle(bruteChars, plaintext)
		for v := 0; v <= 256; v++ {
			seedChars := []byte(bruteChars)
			seedChars = append(seedChars, unknownResult...)
			seedChars = append(seedChars, []byte(string(v))...)

			bruteBlockTwo, _ := encryptionOracle(string(seedChars), plaintext)
			if len(bruteBlockOne) < oracleSizeRnd {
				return unknownResult
			}
			if bytes.Compare(bruteBlockOne[:oracleSizeRnd], bruteBlockTwo[:oracleSizeRnd]) == 0 {
				unknownResult = append(unknownResult, []byte(string(v))...)
				break
			}
		}
	}
	return unknownResult
}

func main() {
	a := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	b := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	initCiphertext, err := encryptionOracle("", b)
	ciphertext, err := encryptionOracle(a, b)
	if err != nil {
		log.Fatal(err)
	}
	blockmode := crypt.DetectOracle(ciphertext, len(key))
	fmt.Println(blockmode)

	blocksize := detectBlockSize(len(initCiphertext), b)
	fmt.Println("Detected blocksize of:", blocksize)

	oraclesize := detectOracleSize(len(initCiphertext), b)
	fmt.Println("Detected string size of:", oraclesize)

	ukns := bruteOracle(b, oraclesize, blocksize)
	fmt.Println("The unknown string is: ", string(ukns))
}
