package pki

import "crypto/x509"

var Leaf = x509.Certificate{
	SignatureAlgorithm: x509.SHA256WithRSA,
}

var Intermediate = x509.Certificate{
	SignatureAlgorithm: x509.ECDSAWithSHA384,
}
