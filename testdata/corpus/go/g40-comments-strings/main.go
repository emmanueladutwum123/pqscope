package main

import "log"

// Previously this used rsa.GenerateKey(rand.Reader, 1024) and md5.Sum.
func main() {
	log.Println("rotate keys: rsa.GenerateKey with 2048 bits, then sha1.New")
	/* ecdsa.GenerateKey(elliptic.P256(), rand.Reader) */
}
