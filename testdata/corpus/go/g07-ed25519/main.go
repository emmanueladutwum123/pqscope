package main

import "crypto/ed25519"

func main() {
	pub, priv, _ := ed25519.GenerateKey(nil)
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		panic("bad signature")
	}
}
