package main

import (
	"crypto/mlkem"
	"crypto/sha512"
)

func main() {
	dk, _ := mlkem.GenerateKey1024()
	_ = sha512.Sum384(dk.Bytes())
}
