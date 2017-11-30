// Code to detect ECB or CBC block mode
// 1. ECB is stateless and deterministic (control the input and the blocks will repeat)
// 2. Provide a large deterministic plaintext sample in order to produce numerous sample blocks
// 3. If ECB not found then assume that is because of a block IV (i.e., CBC)

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/packetassailant/cryptopals/crypt"
	"github.com/packetassailant/cryptopals/rand"
)

const keysize = 16

func selectEncrypt() int {
	return rand.StringWithVarLength(1, 2)
}

func encryptionOracle(s string) (ciphertext []byte, err error) {
	key := rand.String(keysize)

	ptBytes := []byte(s)
	pre := rand.GenRandBytes(5, 10)
	ptBytes = append(pre, ptBytes...)
	post := rand.GenRandBytes(5, 10)
	ptBytes = append(ptBytes, post...)
	i := selectEncrypt()
	switch i {
	case 1:
		return crypt.EncryptAesCBC(ptBytes, []byte(key))

	case 2:
		return crypt.EncryptAesECB(ptBytes, []byte(key))
	}
	return
}

// go run main.go AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
func main() {
	plaintext := os.Args[1:]
	ciphertext, err := encryptionOracle(plaintext[0])
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	result := crypt.DetectOracle(ciphertext, keysize)
	fmt.Println(result)
}
