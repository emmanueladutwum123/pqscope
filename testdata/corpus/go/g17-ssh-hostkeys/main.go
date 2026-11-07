package sshclient

import "golang.org/x/crypto/ssh"

func Config() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoRSA,
		},
	}
}
