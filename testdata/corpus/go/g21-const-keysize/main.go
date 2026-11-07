package main

import (
	"crypto/rand"
	"crypto/rsa"
)

const keyBits = 3072

func main() {
	_, _ = rsa.GenerateKey(rand.Reader, keyBits)
}
