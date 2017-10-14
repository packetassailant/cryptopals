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
	ct3 string
	ct4 string
	ct5 string
}

var ctMap = map[int]*cipherTexts{}

func generateKeys(s string) map[int]*cipherTexts {
	b := []byte(s)
	bReader := bytes.NewReader(b)

	for i := 2; i <= 40; i++ {
		keysize1 := make([]byte, i)
		keysize2 := make([]byte, i)
		keysize3 := make([]byte, i)
		keysize4 := make([]byte, i)
		keysize5 := make([]byte, i)
		binary.Read(bReader, binary.BigEndian, keysize1)
		binary.Read(bReader, binary.BigEndian, keysize2)
		binary.Read(bReader, binary.BigEndian, keysize3)
		binary.Read(bReader, binary.BigEndian, keysize4)
		binary.Read(bReader, binary.BigEndian, keysize5)
		ctMap[i] = &cipherTexts{
			ct1: fmt.Sprintf("%s", keysize1),
			ct2: fmt.Sprintf("%s", keysize2),
			ct3: fmt.Sprintf("%s", keysize3),
			ct4: fmt.Sprintf("%s", keysize4),
			ct5: fmt.Sprintf("%s", keysize5),
		}
		bReader.Seek(0, 0)
	}
	return ctMap
}

func getHammingValue(bm map[int]string, key int) float64 {
	var (
		c0  = 0.00
		c1  = 0.00
		c2  = 0.00
		c3  = 0.00
		avg = 0.00
	)

	bm0 := []rune(bm[0])
	bm1 := []rune(bm[1])
	bm2 := []rune(bm[2])
	bm3 := []rune(bm[3])
	bm4 := []rune(bm[4])

	for i := 0; i < len(bm0); i++ {
		if bm0[i] != bm1[i] {
			c0++
		}
		if bm1[i] != bm2[i] {
			c1++
		}
		if bm2[i] != bm3[i] {
			c2++
		}
		if bm3[i] != bm4[i] {
			c3++
		}
	}
	avg = (c0/float64(key) + c1/float64(key) + c2/float64(key) + c3/float64(key)) / 4
	return avg
}

func keyToBin(s ...string) map[int]string {
	binMap := make(map[int]string)

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
		binMap := keyToBin(
			cm[k].ct1,
			cm[k].ct2,
			cm[k].ct3,
			cm[k].ct4,
			cm[k].ct5,
		)
		hamCount := getHammingValue(binMap, k)
		fmt.Printf("Hamming Distance: %.4f\n", hamCount)
	}
}
