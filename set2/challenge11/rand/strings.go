package rand

import (
	"math/rand"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

//StringWithCharset PRNG w dynamic Charset
func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

//StringWithVarLength generates random length string
func StringWithVarLength(min, max int) int {
	//max+1 makes the max number inclusive of the range rather than n-1
	return seededRand.Intn((max+1)-min) + min
}

//String PRNG w constant Charset
func String(length int) string {
	return StringWithCharset(length, charset)
}

//GenRandBytes returns a random length byte slice
func GenRandBytes(min, max int) []byte {
	b := StringWithVarLength(min, max)
	randBytes := make([]byte, b)
	str := String(b)
	copy(randBytes[:], str)
	return randBytes
}
