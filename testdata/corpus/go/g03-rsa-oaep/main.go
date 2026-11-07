package box

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func Seal(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
}

func Open(priv *rsa.PrivateKey, ct []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), nil, priv, ct, nil)
}
