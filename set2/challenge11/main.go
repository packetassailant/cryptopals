package main

import (
	"fmt"
	"log"

	"github.com/packetassailant/cryptopals/set2/challenge11/crypt"
	"github.com/packetassailant/cryptopals/set2/challenge11/rand"
)

func selectEncrypt() int {
	return rand.StringWithVarLength(1, 2)
}

func encryptionOracle(s string) (ciphertext []byte, err error) {
	key := rand.String(16)
	fmt.Println(key)

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

func main() {
	ciphertext, err := encryptionOracle("this is a test")
	if err != nil {
		log.Fatalf("Error: %s", err)
	}
	fmt.Println(ciphertext)
}
