package main

import (
	"flag"
	"fmt"
)

func encodeDecode(input []byte, key string) []byte {
	var bArr = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		bArr[i] += input[i] ^ key[i%len(key)]
	}
	return bArr
}

func main() {
	phrase := flag.String("phrase", "", "the string to XOR")
	key := flag.String("key", "", "The XOR key")
	flag.Parse()

	b := []byte(*phrase)

	result := encodeDecode(b, *key)
	fmt.Printf("%x\n", result)
}
