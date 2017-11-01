// Code to implement AES ECB
// 1. Base64 decode to get ciphertext
// 2. Decrypt ciphertext (AES 128) with 16 byte key

package main

import (
	"crypto/aes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

func decryptAes128(ciphertext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	plaintext := make([]byte, len(ciphertext))
	blocksize := 16

	for bs, be := 0, blocksize; bs < len(ciphertext); bs, be = bs+blocksize, be+blocksize {
		cipher.Decrypt(plaintext[bs:be], ciphertext[bs:be])
	}
	return plaintext
}

func main() {
	file := flag.String("file", "", "the file to decrypt")
	key := flag.String("key", "", "The decryption key")
	flag.Parse()

	fileBytes, err := ioutil.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}
	k := []byte(*key)

	result := decryptAes128(fileBytes, k)
	fmt.Printf("%s", result)
}
