package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func newKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func main() {
	_, _ = newKey(2048)
}
