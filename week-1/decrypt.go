package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

func isLetter(char byte) bool {
	if (65 <= char && char <= 90) || (97 <= char && char <= 122) {
		return true
	}

	return false
}

func getChar(chars []byte) byte {
	if len(chars) == 0 {
		return byte(32)
	}

	char := chars[0]

	for _, c := range chars {
		if c != char {
			return byte(95)
		}
	}

	return char
}

func xor(x, y []byte) []byte {
	size := int(math.Min(float64(len(y)), float64(len(x))))
	output := make([]byte, size)

	for i := 0; i < size; i++ {
		output[i] = x[i] ^ y[i]
	}

	return output
}

func getMessage(plaintexts [][]byte) string {
	var message string
	var max int

	for _, plaintext := range plaintexts {
		if len(plaintext) > max {
			max = len(plaintext)
		}
	}

	for i := 0; i < max; i++ {
		var chars []byte
		for _, plaintext := range plaintexts {
			if i < len(plaintext) && isLetter(plaintext[i]) {
				chars = append(chars, plaintext[i])
			}
		}

		message += string(getChar(chars))
	}

	return message
}

func decrypt(ciphers [][]byte, target int) string {
	var plaintexts [][]byte

	for i, cipher := range ciphers {
		xors := make([][]byte, len(ciphers))

		for j, cipher2 := range ciphers {
			xorText := xor(cipher, cipher2)
			xors[j] = xorText
		}

		for _, xorBytes := range xors {
			var plaintext []byte
			for j, b := range xorBytes {
				if isLetter(b) && j < len(ciphers[target]) {
					a := xor([]byte(" "), xor([]byte{ciphers[i][j]}, []byte{ciphers[target][j]}))
					plaintext = append(plaintext, a[0])
				} else {
					plaintext = append(plaintext, byte(95))
				}
			}
			plaintexts = append(plaintexts, plaintext)
		}
	}

	return getMessage(plaintexts)
}

func main() {
	var ciphers [][]byte

	cipherFile, _ := os.Open("./input")
	defer cipherFile.Close()

	cipherScanner := bufio.NewScanner(cipherFile)

	for cipherScanner.Scan() {
		cipher, _ := hex.DecodeString(cipherScanner.Text())
		ciphers = append(ciphers, cipher)
	}

	for i := range ciphers {
		message := decrypt(ciphers, i)
		fmt.Printf("m%d = %s\n", i, message)
	}
}
