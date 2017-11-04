// Code to implement AES CBC (static IV of []byte* 16)
// 1. Base64 decode to get ciphertext
// 2. Decrypt ciphertext (AES 128) with 16 byte key

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

func encryptAes(plaintext, key []byte) (ciphertext []byte, ciphertextB64 string, err error) {
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	fmt.Printf("CBC Key: %s\n", hex.EncodeToString(key))
	fmt.Printf("CBC IV: %s\n", hex.EncodeToString(iv))

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	ciphertextB64 = base64.URLEncoding.EncodeToString(ciphertext)

	return
}

func decryptAes(ciphertext, key []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	if len(ciphertext) < aes.BlockSize {
		fmt.Printf("ciphertext is too short")
		return
	}
	// Typical implementation would
	// * Have an initial 0'th rand IV
	// * Slice the IV from [:ciphertext]
	// * Slice the ciphertext [ciphertext:]

	iv := make([]byte, 16)

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)
	plaintext = ciphertext

	return
}

func main() {
	plaintext := flag.String("plaintext", "", "the plaintext to encrypt")
	ciphertext := flag.String("ciphertext", "", "the base64 encoded ciphertext to decrypt")
	file := flag.String("file", "", "the file to decrypt")
	key := flag.String("key", "", "the encryption/decryption key")
	flag.Parse()

	// go run main.go -plaintext='HHHHHello World!' -key="opensesame123456"
	if *plaintext != "" && *key != "" {
		result, resultB64, _ := encryptAes([]byte(*plaintext), []byte(*key))
		fmt.Printf("B 64: %v\n", resultB64)
		fmt.Printf("Bytes: %v\n", result)
	}

	// go run main.go -ciphertext='jCIQ0BlqXYh9DIhcgfgyA5fHVd7H2o7Q87G37hXjYc4=' -key="opensesame123456"
	if *ciphertext != "" && *key != "" {
		sDec, _ := base64.StdEncoding.DecodeString(*ciphertext)
		result, _ := decryptAes(sDec, []byte(*key))
		fmt.Printf("Bytes: %v\n", result)
		fmt.Printf("String: %s\n", result)
	}

	// go run main.go -file=raw.txt -key="YELLOW SUBMARINE"
	if *file != "" && *key != "" {
		fileBytes, err := ioutil.ReadFile(*file)
		if err != nil {
			log.Fatal(err)
		}
		k := []byte(*key)

		result, _ := decryptAes(fileBytes, k)
		fmt.Println(string(result))
	}

}
