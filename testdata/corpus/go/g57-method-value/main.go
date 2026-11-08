package main

import (
	"crypto/sha256"
	"hash"
)

var newHash func() hash.Hash = sha256.New
