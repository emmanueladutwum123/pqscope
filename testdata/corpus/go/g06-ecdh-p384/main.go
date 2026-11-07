package kex

import (
	"crypto/ecdh"
	"crypto/rand"
)

func NewKey() (*ecdh.PrivateKey, error) {
	return ecdh.P384().GenerateKey(rand.Reader)
}
