package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

func readFile(fn string) (err error) {
	file, err := os.Open(fn)
	defer file.Close()

	if err != nil {
		return err
	}

	reader := bufio.NewReader(file)

	var line string
	for {
		line, err = reader.ReadString('\n')

		fmt.Printf(" > Read %d characters\n", len(line))

		if err != nil {
			break
		}
	}

	if err != io.EOF {
		fmt.Printf(" > Failed!: %v\n", err)
	}

	return
}

func main() {
	file := os.Args[1:]
	readFile(file[0])
}
