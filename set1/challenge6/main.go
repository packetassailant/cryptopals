package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sort"

	"github.com/spf13/pflag"

	b64 "encoding/base64"
)

type cipherTexts struct {
	ct1 string
	ct2 string
	ct3 string
	ct4 string
	ct5 string
}

var (
	flags   = pflag.FlagSet{SortFlags: false}
	ctMap   = map[int]*cipherTexts{}
	opts    cmdLineOpts
	charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.' \\"
)

type cmdLineOpts struct {
	infile       string
	cipherOne    string
	cipherTwo    string
	key          string
	minKeySize   int
	maxKeySize   int
	numBlockSize int
	keyBlockSize int
	decode64     bool
}

func init() {
	flags.StringVarP(&opts.infile, "infile", "i", "", "FILEPATH to a encrypted file")
	flags.StringVar(&opts.cipherOne, "c1", "", "INITIAL cipher string for Hamming Distance comparison")
	flags.StringVar(&opts.cipherTwo, "c2", "", "SECOND cipher string for Hamming Distance comparison")
	flags.IntVar(&opts.minKeySize, "min", 2, "The MINIMUM keysize")
	flags.IntVar(&opts.maxKeySize, "max", 40, "The MAXIMUM keysize")
	flags.IntVar(&opts.numBlockSize, "numblock", 4, "Number of blocks to test based on single KEYSIZE")
	flags.IntVar(&opts.keyBlockSize, "keyblock", 0, "Size of block based on KEYSIZE length")
	flags.StringVar(&opts.key, "key", "", "The symmetric XOR key")
	flags.BoolVar(&opts.decode64, "decode64", false, "Helper to Base64 decode file")

	flags.Usage = usage
	flags.Parse(os.Args[1:])

	if flags.NFlag() == 0 {
		flags.PrintDefaults()
		os.Exit(1)
	}
	if opts.infile == "" && (opts.cipherOne == "" || opts.cipherTwo == "") {
		log.Fatal("Fatal: Either --infile or --c1 and --c2 value is required")
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Example Usage(One Edit Distance): %s --c1 'this is a test' --c2 'wokka wokka!!!'\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Example Usage(Bulk Edit Distance): %s -i encfile.raw --min 4 --max 50 --numblock\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Example Usage(Score Blocks): %s --keyblock 13 -i encfile.raw\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Example Usage(Decrypt file): %s --infile=raw.txt --key='the symmetric XOR key'\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Example Usage(B64 decode): %s --infile=enc.txt --decode64\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Flags: %s {OPTION]...\n", os.Args[0])
	flags.PrintDefaults()
	os.Exit(0)
}

func generateKeys(s string) map[int]*cipherTexts {
	b := []byte(s)
	bReader := bytes.NewReader(b)

	for i := opts.minKeySize; i <= opts.maxKeySize; i++ {
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

func getHammingValue(s1, s2 string) int {
	count := 0
	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			count++
		}
	}
	return count
}

func getHammingValues(bm map[int]string, key int) float64 {
	var keys []int
	for k := range bm {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	countTotal := 0.00
	for k := 0; k < len(keys); k++ {
		if k >= 1 {
			prev := k - 1
			hamCount := getHammingValue(bm[prev], bm[k])
			countTotal += float64(hamCount) / float64(key)
		}
	}
	avg := countTotal / 4
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

func getKeySizeBlocks(bs int, file string) []string {
	b := []byte(file)
	bReader := bytes.NewReader(b)
	blockSlice := []string{}
	for true {
		block := make([]byte, bs)
		_, err := bReader.Read(block)
		if err == io.EOF {
			break
		}
		blockSlice = append(blockSlice, string(block))
	}
	return blockSlice
}

func transposeBlocks(bs []string) map[int][]byte {
	transMap := map[int][]byte{}
	for x := 0; x < opts.keyBlockSize; x++ {
		transSlice := []byte{}
		for _, v := range bs {
			transSlice = append(transSlice, v[x])
		}
		transMap[x] = transSlice
	}
	return transMap
}

func encodeDecode(input []byte, key string) []byte {
	var bArr = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		bArr[i] += input[i] ^ key[i%len(key)]
	}
	return bArr
}

func scoreChars(text []byte) int {
	count := 0

	for _, x := range text {
		for _, y := range charSet {
			if byte(y) == x {
				count = count + 1
			}
		}
	}
	return count
}

func extractKey(keys []int, transMap map[int][]byte) []byte {
	keySlice := []byte{}

	for _, k := range keys {
		scoreHolder := 0
		highXorScore := ""
		var highChar []byte
		fmt.Println("Processing Key: ", k)
		for x := 0; x <= 255; x++ {
			c := fmt.Sprintf("%c", x)
			results := encodeDecode(transMap[k], c)
			if scoreChars(results) > scoreHolder {
				highChar = []byte(c)
				scoreHolder = scoreChars(results)
				highXorScore = string(results)
			}
		}
		keySlice = append(keySlice, highChar[0])
		fmt.Println(scoreHolder)
		fmt.Println(highXorScore)
	}
	return keySlice
}

func main() {
	if opts.cipherOne != "" && opts.cipherTwo != "" {
		bm := keyToBin(opts.cipherOne, opts.cipherTwo)
		hamCount := getHammingValue(bm[0], bm[1])
		fmt.Printf("Hamming Distance: %d\n", hamCount)
	} else if opts.decode64 && opts.infile != "" {
		fileBytes, err := ioutil.ReadFile(opts.infile)
		fileStr := fmt.Sprintf("%s", fileBytes)
		decFileBytes, _ := b64.StdEncoding.DecodeString(fileStr)
		if err != nil {
			log.Fatal(err)
		}
		decFileStr := fmt.Sprintf("%s", decFileBytes)
		fmt.Println(decFileStr)
	} else if opts.key != "" && opts.infile != "" {
		fileBytes, err := ioutil.ReadFile(opts.infile)
		if err != nil {
			log.Fatal(err)
		}
		result := encodeDecode(fileBytes, opts.key)
		fmt.Println(string(result))
	} else if opts.keyBlockSize != 0 && opts.infile != "" {
		fileBytes, err := ioutil.ReadFile(opts.infile)
		if err != nil {
			log.Fatal(err)
		}
		decFileStr := fmt.Sprintf("%s", fileBytes)
		blockSlice := getKeySizeBlocks(opts.keyBlockSize, decFileStr)
		transMap := transposeBlocks(blockSlice)
		var keys []int
		for k := range transMap {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		encKey := extractKey(keys, transMap)
		fmt.Printf("The encryption key: %s\n", encKey)
	} else if opts.infile != "" {
		fileBytes, err := ioutil.ReadFile(opts.infile)
		if err != nil {
			log.Fatal(err)
		}
		decFileStr := fmt.Sprintf("%s", fileBytes)
		cm := generateKeys(decFileStr)
		var keys []int
		for k := range cm {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		hcMap := make(map[float64]int)
		for _, k := range keys {
			binMap := keyToBin(
				cm[k].ct1,
				cm[k].ct2,
				cm[k].ct3,
				cm[k].ct4,
				cm[k].ct5,
			)
			hamCount := getHammingValues(binMap, k)
			hcMap[hamCount] = k
		}
		var hckeys []float64
		for k := range hcMap {
			hckeys = append(hckeys, k)
		}
		sort.Float64s(hckeys)
		fmt.Println("*********Keys Sorted by Hamming Distance*********")
		for _, k := range hckeys {
			fmt.Printf("Processing key: %d\n", hcMap[k])
			fmt.Printf("Normalized Hamming Distance: %.4f\n", k)
		}
	}
}
