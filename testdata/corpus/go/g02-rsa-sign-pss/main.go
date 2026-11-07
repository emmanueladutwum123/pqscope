package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func Sign(key *rsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
}
