package main

import (
	"fmt"
	"os"
	"strconv"
)

func pad(plaintext string, blocksize int) []byte {
	padBlock := make([]byte, len(plaintext))
	copy(padBlock, plaintext)
	ctsize := len(plaintext)
	bsdiff := blocksize - ctsize

	for i := 0; i <= bsdiff; i++ {
		padBlock = append(padBlock, byte(bsdiff))
	}
	return padBlock

}

func main() {
	str := os.Args[1:]
	plaintext := str[0]
	size, _ := strconv.Atoi(str[1])
	padBlock := pad(plaintext, size)
	fmt.Printf("% 02X\n", padBlock)
}
