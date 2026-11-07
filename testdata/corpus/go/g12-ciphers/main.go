package ciphers

import (
	"crypto/aes"
	"crypto/des"
	"crypto/rc4"
)

func Make(key []byte) {
	_, _ = des.NewCipher(key[:8])
	_, _ = des.NewTripleDESCipher(key[:24])
	_, _ = rc4.NewCipher(key)
	_, _ = aes.NewCipher(key[:32])
}
