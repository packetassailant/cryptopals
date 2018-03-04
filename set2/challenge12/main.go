// byte at a time ECB decrypt (easier)
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

var (
	key         = rand.String(16)
	unknownText = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
)

func encryptionOracle(controlChars string) (ciphertext []byte, err error) {
	ptBytes := []byte(controlChars)
	plainBytes, err := base64.StdEncoding.DecodeString(unknownText)
	if err != nil {
		log.Fatal(err)
	}
	ptBytes = append(ptBytes, plainBytes...)
	return crypt.EncryptAesECB(ptBytes, []byte(key))
}

func detectBlockSize() int {
	ciphertextOrig, _ := encryptionOracle("")
	count := 1
	//Start pre-padding the ciphertext
	for {
		a := strings.Repeat("A", count)
		ciphertextNew, err := encryptionOracle(a)
		if err != nil {
			log.Fatal(err)
		}
		if len(ciphertextNew) > len(ciphertextOrig) {
			return len(ciphertextNew) - len(ciphertextOrig)
		}
		count++
	}
}

func detectOracleSize() int {
	ciphertextOrig, _ := encryptionOracle("")
	count := 1
	//Start pre-padding the ciphertext
	for {
		a := strings.Repeat("A", count)
		ciphertextNew, err := encryptionOracle(a)
		if err != nil {
			log.Fatal(err)
		}
		if len(ciphertextNew) > len(ciphertextOrig) {
			return len(ciphertextOrig) - count
		}
		count++
	}
}

func bruteOracle(blocksize, oraclesize int) []byte {
	var unknownResult []byte
	unknownStringSizeRnd := ((oraclesize / blocksize) + 1) * blocksize
	for x := unknownStringSizeRnd - 1; x > 0; x-- {
		bruteChars := strings.Repeat("A", x)
		ciphertextOne, _ := encryptionOracle(bruteChars)
		ciphertextOneA := ciphertextOne[:unknownStringSizeRnd]
		for char := 0; char < 256; char++ {
			seedChars := []byte(bruteChars)
			seedChars = append(seedChars, unknownResult...)
			seedChars = append(seedChars, []byte(string(char))...)
			ciphertextTwo, _ := encryptionOracle(string(seedChars))
			ciphertextTwoA := ciphertextTwo[:unknownStringSizeRnd]
			if bytes.Equal(ciphertextOneA, ciphertextTwoA) {
				unknownResult = append(unknownResult, []byte(string(char))...)
				break
			}
		}
	}
	return unknownResult
}

func main() {
	controlChars := strings.Repeat("A", 64)
	ciphertext, err := encryptionOracle(controlChars)

	blockmode := crypt.DetectOracle(ciphertext, len(key))
	fmt.Println(blockmode)

	blocksize := detectBlockSize()
	fmt.Println("Detected blocksize of:", blocksize)

	oraclesize := detectOracleSize()
	fmt.Println("Detected string size of:", oraclesize)

	resultString := bruteOracle(blocksize, oraclesize)
	fmt.Println(string(resultString))

	if err != nil {
		log.Fatal(err)
	}
}
