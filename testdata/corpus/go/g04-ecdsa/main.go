package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

func main() {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := sha256.Sum256([]byte("hello"))
	sig, _ := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	_ = ecdsa.VerifyASN1(&priv.PublicKey, digest[:], sig)
}
