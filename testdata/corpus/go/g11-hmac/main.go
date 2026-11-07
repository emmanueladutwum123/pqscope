package mac

import (
	"crypto/hmac"
	"crypto/sha256"
)

func Tag(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}
