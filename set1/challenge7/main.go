package main

import (
	"crypto/aes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

func decryptAes128Ecb(ciphertext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := make([]byte, len(ciphertext))
	bs := len(key)
	for len(ciphertext) > 0 {
		cipher.Decrypt(ciphertext, plaintext)
		ciphertext = ciphertext[bs:]
		plaintext = plaintext[bs:]
	}
	//Start here

	return []byte("4")
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

	result := decryptAes128Ecb(fileBytes, k)
	fmt.Println(result)
}
