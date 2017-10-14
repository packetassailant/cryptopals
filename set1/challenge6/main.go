package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"sort"

	b64 "encoding/base64"
)

type cipherTexts struct {
	ct1 string
	ct2 string
}

var ctMap = map[int]*cipherTexts{}

func generateKeys(s string) map[int]*cipherTexts {
	// stats, err := f.Stat()
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// var size = stats.Size()
	b := []byte(s)
	// bufReader := bytes.NewReader(f)
	// _, err = bufReader.Read(b)
	bReader := bytes.NewReader(b)

	for i := 2; i <= 40; i++ {
		keysize1 := make([]byte, i)
		keysize2 := make([]byte, i)
		binary.Read(bReader, binary.BigEndian, keysize1)
		binary.Read(bReader, binary.BigEndian, keysize2)
		ctMap[i] = &cipherTexts{
			ct1: fmt.Sprintf("%s", keysize1),
			ct2: fmt.Sprintf("%s", keysize2),
		}
		// fmt.Printf("Key1: %s : %v\n", keysize1, len(keysize1))
		// fmt.Printf("Key2: %s : %v\n", keysize2, len(keysize2))
		bReader.Seek(0, 0)
	}
	return ctMap
}

func getHammingValue(bm map[int]string) int {
	count := 0
	bm1 := []rune(bm[0])
	bm2 := []rune(bm[1])

	for i := 0; i < len(bm1); i++ {
		if bm1[i] != bm2[i] {
			count++
		}
	}
	return count
}

func keyToBin(s ...string) map[int]string {
	binMap := make(map[int]string)

	if len(s[0]) != len(s[1]) {
		log.Fatal("Each string is not of even length")
	}
	for i := range s {
		binStr := ""
		for _, x := range s[i] {
			binStr += fmt.Sprintf("%.8b", x)
		}
		binMap[i] = binStr
	}
	return binMap
}

func main() {
	file := flag.String("file", "", "The encrypted file")
	flag.Parse()

	fileBytes, err := ioutil.ReadFile(*file)
	fileStr := fmt.Sprintf("%s", fileBytes)
	decFileBytes, _ := b64.StdEncoding.DecodeString(fileStr)
	if err != nil {
		log.Fatal(err)
	}
	decFileStr := fmt.Sprintf("%s", decFileBytes)

	cm := generateKeys(decFileStr)

	var keys []int
	for k := range cm {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		fmt.Printf("Processing key: %d\n", k)
		binMap := keyToBin(cm[k].ct1, cm[k].ct2)
		hamCount := getHammingValue(binMap)
		fmt.Printf("Hamming Distance: %v\n", float64(hamCount)/float64(k))
	}
}
