package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

func main() {
	curve := elliptic.P521()
	_, _ = ecdsa.GenerateKey(curve, rand.Reader)
}
