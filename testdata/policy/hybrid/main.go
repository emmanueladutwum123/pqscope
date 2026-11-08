package main

import (
	"crypto/sha256"
	"crypto/tls"
)

func main() {
	cfg := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	_ = sha256.Sum256([]byte(cfg.ServerName))
}
