// byte at a time ECB decrypt (harder)
// 1. Detect length of rand prepended string by providing control characters
// 2. Start of the control characters is also the offset or length of the prepended characters
// 3. The rest is similar to Challenge 12 with the exception of starting the prepended bytes offset [prependsize:remainder]

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
	key                 = rand.String(16)
	unknownPrependChars = string(rand.GenRandBytes(50, 200))
	unknownText         = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
)

func encryptionOracle(controlChars string) (ciphertext []byte, err error) {
	ptBytes := []byte(unknownPrependChars + controlChars)
	plainBytes, err := base64.StdEncoding.DecodeString(unknownText)
	if err != nil {
		log.Fatal(err)
	}
	ptBytes = append(ptBytes, plainBytes...)
	return crypt.EncryptAesECB(ptBytes, []byte(key))
}

// Doing named returns here to control our naked return values
func detectPrefixSize(blocksize int) (idx, prePadSize int) {
	for prePadSize = 0; prePadSize < blocksize; prePadSize++ {
		iters := 10
		prefixPadding := strings.Repeat("A", prePadSize)
		seedValue := strings.Repeat("STIMULUSRESPONSE", iters)
		cipherBuff, _ := encryptionOracle(prefixPadding + seedValue)
		var preblock []byte
		count := 0
		for pos := 0; pos < len(cipherBuff); pos = pos + blocksize {
			block := cipherBuff[pos : pos+blocksize]
			if bytes.Equal(block, preblock) {
				count++
			} else {
				idx = pos
				preblock = block
				count = 1
			}
			if count == iters {
				return
			}
		}
	}
	return
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
			return len(ciphertextNew) - count
		}
		count++
	}
}

func bruteOracle(blocksize, preSizeRnd, prePadSize, oraclesize int) []byte {
	unknownStringSize := oraclesize - preSizeRnd - prePadSize
	var unknownResult []byte
	unknownStringSizeRnd := (unknownStringSize/blocksize + 1) * blocksize
	for x := unknownStringSizeRnd - 1; x > 0; x-- {
		bruteChars := strings.Repeat("A", x+prePadSize)
		ciphertextOne, _ := encryptionOracle(bruteChars)
		ciphertextOne = ciphertextOne[preSizeRnd : unknownStringSizeRnd+preSizeRnd]
		for char := 0; char <= 256; char++ {
			seedChars := []byte(bruteChars)
			seedChars = append(seedChars, unknownResult...)
			seedChars = append(seedChars, []byte(string(char))...)
			ciphertextTwo, _ := encryptionOracle(string(seedChars))
			ciphertextTwo = ciphertextTwo[preSizeRnd : unknownStringSizeRnd+preSizeRnd]
			if bytes.Equal(ciphertextOne, ciphertextTwo) {
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

	preSizeRnd, prePadSize := detectPrefixSize(blocksize)
	fmt.Println("Detected prefix size of:", preSizeRnd)
	fmt.Println("Detected pad alignment size of:", prePadSize)

	oraclesize := detectOracleSize()
	fmt.Println("Detected string size of:", oraclesize)

	resultString := bruteOracle(blocksize, preSizeRnd, prePadSize, oraclesize)
	fmt.Println(string(resultString))

	if err != nil {
		log.Fatal(err)
	}
}
