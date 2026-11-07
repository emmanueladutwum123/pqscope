package main

import (
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	_ = key
}
