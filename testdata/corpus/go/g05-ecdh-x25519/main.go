package main

import (
	"crypto/ecdh"
	"crypto/rand"
)

func main() {
	curve := ecdh.X25519()
	alice, _ := curve.GenerateKey(rand.Reader)
	bob, _ := curve.GenerateKey(rand.Reader)
	secret, _ := alice.ECDH(bob.PublicKey())
	_ = secret
}
