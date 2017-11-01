// Code to implement AES ECB
// 1. Base64 decode to get ciphertext
// 2. Decrypt ciphertext (AES 128) with 16 byte key

package main

import (
	"crypto/aes"
	"flag"
	"fmt"
	"log"
)

func encryptAes128(plaintext, key, ciphertext []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d bytes NewCipher key with block size of %d bytes\n", len(key), block.BlockSize())
	iv := ciphertext[:aes.BlockSize]
	fmt.Println(iv)
}

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
	plaintext := flag.String("plaintext", "", "the plaintext to encrypt")
	ciphertext := flag.String("ciphertext", "", "the ciphertext to decrypt")
	key := flag.String("key", "", "the encryption/decryption key")
	// iv := flag.String("iv", "", "The initialization vector for the block chain")
	// encrypt := flag.Bool("encrypt", false, "encrypt")
	// decrypt := flag.Bool("decrypt", false, "decrypt")
	flag.Parse()

	encryptAes128([]byte(*plaintext), []byte(*key), []byte(*ciphertext))

	// file := flag.String("file", "", "the file to decrypt")
	// key := flag.String("key", "", "The decryption key")
	// flag.Parse()

	// fileBytes, err := ioutil.ReadFile(*file)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// k := []byte(*key)

	// result := decryptAes128(fileBytes, k)
	// fmt.Printf("%s", result)
}
