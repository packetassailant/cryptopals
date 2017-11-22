package main

import "github.com/packetassailant/cryptopals/set2/challenge11/rand"
import "fmt"

func randEncrypt() {
	i := rand.StringWithVarLength(1, 2)
	fmt.Println(i)
}

func encryptionOracle(s string) {
	key := rand.String(16)
	fmt.Println(key)

	ptBytes := []byte(s)
	pre := rand.GenRandBytes(5, 10)
	ptBytes = append(pre, ptBytes...)
	post := rand.GenRandBytes(5, 10)
	ptBytes = append(ptBytes, post...)
	fmt.Println(string(ptBytes))
}

func main() {
	// encryptionOracle("this is a test")
	for x := 0; x < 1000; x++ {
		randEncrypt()
	}

}
