// Command tlsserver is a TLS 1.3 test server for pqscope's network
// integration tests. It completes handshakes with a fresh self-signed
// certificate and offers either the hybrid or only the classical group.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net"
	"time"
)

func main() {
	addr := flag.String("addr", ":4433", "listen address")
	groups := flag.String("groups", "hybrid", "hybrid (X25519MLKEM768, X25519) or classical (X25519)")
	flag.Parse()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pqscope-go-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		log.Fatal(err)
	}
	curves := []tls.CurveID{tls.X25519MLKEM768, tls.X25519}
	if *groups == "classical" {
		curves = []tls.CurveID{tls.X25519}
	}
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}},
		CurvePreferences: curves,
		MinVersion:       tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s with %s groups", *addr, *groups)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			_ = c.(*tls.Conn).Handshake()
		}(c)
	}
}
