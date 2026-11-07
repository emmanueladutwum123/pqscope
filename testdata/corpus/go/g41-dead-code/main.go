package main

import (
	"crypto/md5"
	"crypto/sha256"
)

func main() {
	data := []byte("x")
	if false {
		_ = md5.Sum(data)
	}
	_ = sha256.Sum256(data)
}
