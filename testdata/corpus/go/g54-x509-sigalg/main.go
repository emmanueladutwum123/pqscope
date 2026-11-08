package main

import "crypto/x509"

var tmpl = x509.Certificate{
	SignatureAlgorithm: x509.ECDSAWithSHA384,
}
