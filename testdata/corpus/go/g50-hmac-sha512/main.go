package main

import (
	"crypto/hmac"
	"crypto/sha512"
)

func mac(key, msg []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(msg)
	return h.Sum(nil)
}
