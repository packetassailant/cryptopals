package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"reflect"
)

//Pkcs7Pad appends padding. (Borrowed from Golang Examples)
func Pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

//Pkcs7Unpad returns slice of the original data without padding.  (Borrowed from Golang Examples)
func Pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

//DetectOracle identifies stateless and deterministic blocks
func DetectOracle(ciphertext []byte, blocksize int) string {
	var cipherSlice [][]byte
	for bs, be := 0, blocksize; bs < len(ciphertext); bs, be = bs+blocksize, be+blocksize {
		cipherSlice = append(cipherSlice, ciphertext[bs:be])
	}
	for a := 0; a < len(cipherSlice)-1; a++ {
		for b := a + 1; b < len(cipherSlice); b++ {
			if reflect.DeepEqual(cipherSlice[a], cipherSlice[b]) {
				return fmt.Sprint("Found ECB block mode encryption")
			}
		}
	}
	return fmt.Sprintln("Found CBC block mode encryption")
}

//EncryptAesECB symmetric encrypt using ECB cipher
func EncryptAesECB(plaintext, key []byte) (ciphertext []byte, err error) {
	msg, err := Pkcs7Pad(plaintext, len(key))

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext = make([]byte, len(msg))

	blocksize := len(key)
	for bs, be := 0, blocksize; bs < len(ciphertext); bs, be = bs+blocksize, be+blocksize {
		block.Encrypt(ciphertext[bs:be], msg[bs:be])
	}
	return
}

//EncryptAesCBC symmetric encrypt using CBC cipher
func EncryptAesCBC(plaintext, key []byte) (ciphertext []byte, err error) {
	msg, err := Pkcs7Pad(plaintext, len(key))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext = make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	// fmt.Printf("CBC Key: %s\n", hex.EncodeToString(key))
	// fmt.Printf("CBC IV: %s\n", hex.EncodeToString(iv))

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], msg)

	return
}

//DecryptAes128 AES decryption function
func DecryptAes128(ciphertext, key []byte) []byte {
	cipher, err := aes.NewCipher(key)

	plaintext := make([]byte, len(ciphertext))
	blocksize := len(key)

	for bs, be := 0, blocksize; bs < len(ciphertext); bs, be = bs+blocksize, be+blocksize {
		cipher.Decrypt(plaintext[bs:be], ciphertext[bs:be])
	}
	msg, err := Pkcs7Unpad(plaintext, blocksize)
	if err != nil {
		log.Fatal(err)
	}
	return msg
}
