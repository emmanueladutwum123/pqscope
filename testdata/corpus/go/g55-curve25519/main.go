package main

import "golang.org/x/crypto/curve25519"

func shared(priv, pub []byte) ([]byte, error) {
	return curve25519.X25519(priv, pub)
}
