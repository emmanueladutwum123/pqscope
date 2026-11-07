package main

import (
	"crypto/dsa"
	"crypto/rand"
)

func main() {
	var params dsa.Parameters
	_ = dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
	priv := dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	_ = dsa.GenerateKey(&priv, rand.Reader)
}
