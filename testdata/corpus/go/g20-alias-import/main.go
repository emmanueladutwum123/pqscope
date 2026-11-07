package main

import (
	cr "crypto/rand"
	r "crypto/rsa"
)

func main() {
	_, _ = r.GenerateKey(cr.Reader, 4096)
}
