package main

import "golang.org/x/crypto/ssh"

var algos = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoRSA,
}
