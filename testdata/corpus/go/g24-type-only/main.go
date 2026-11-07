package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

func Sign(k *rsa.PrivateKey, digest []byte) ([]byte, error) {
	return k.Sign(rand.Reader, digest, crypto.SHA256)
}
