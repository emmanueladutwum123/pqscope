package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
}
