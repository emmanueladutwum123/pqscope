// Package testkeys generates key material for tests, so that no private key
// is ever committed. It is imported only by tests.
//
// Write records every encoding of each private key it writes, so a test can
// assert that none of them appears in pqscope's output.
package testkeys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// OIDs of NIST post-quantum algorithms (NIST CSOR).
var (
	OIDMLDSA65  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDMLKEM768 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
)

// Set is the generated material.
type Set struct {
	Dir string
	// Secrets are strings derived from private keys that must never appear in
	// output: PEM body lines, whole base64 encodings, and private scalars in
	// hex and decimal.
	Secrets []string
}

func (s *Set) secret(v string) {
	if len(v) >= 16 {
		s.Secrets = append(s.Secrets, v)
	}
}

// privatePEM writes a private key PEM file and records its secrets.
func (s *Set) privatePEM(name, typ string, der []byte, headers map[string]string) error {
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Headers: headers, Bytes: der})
	s.pemSecrets(data, der)
	return os.WriteFile(filepath.Join(s.Dir, name), data, 0o600)
}

func (s *Set) pemSecrets(pemData, der []byte) {
	for _, line := range strings.Split(string(pemData), "\n") {
		if !strings.HasPrefix(line, "-----") && !strings.Contains(line, ":") {
			s.secret(line)
		}
	}
	if der != nil {
		s.secret(base64.StdEncoding.EncodeToString(der))
		s.secret(hex.EncodeToString(der))
	}
}

func (s *Set) bigSecrets(ns ...*big.Int) {
	for _, n := range ns {
		s.secret(n.Text(10))
		s.secret(n.Text(16))
	}
}

func (s *Set) ecdsaSecrets(k *ecdsa.PrivateKey) error {
	d, err := k.Bytes()
	if err != nil {
		return err
	}
	s.secret(hex.EncodeToString(d))
	s.bigSecrets(new(big.Int).SetBytes(d))
	return nil
}

func (s *Set) write(name string, data []byte) error {
	return os.WriteFile(filepath.Join(s.Dir, name), data, 0o644)
}

// Write generates every kind of key material the config layer reads into dir.
// File names state the expected asset.
func Write(dir string) (*Set, error) {
	s := &Set{Dir: dir}
	steps := []func() error{
		s.rsa, s.ecdsa, s.ed25519, s.x25519, s.openSSH, s.pqc, s.certificates, s.misc,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Set) rsa() error {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	s.bigSecrets(k.D, k.Primes[0], k.Primes[1])
	if err := s.privatePEM("rsa2048-pkcs1.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k), nil); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	if err := s.privatePEM("rsa2048-pkcs8.pem", "PRIVATE KEY", der, nil); err != nil {
		return err
	}
	// Legacy encrypted PEM: the size is not visible.
	junk := make([]byte, 64)
	_, _ = rand.Read(junk)
	if err := s.privatePEM("rsa-encrypted.key", "RSA PRIVATE KEY", junk, map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00112233445566778899AABBCCDDEEFF"}); err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return err
	}
	return s.write("rsa2048-public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
}

func (s *Set) ecdsa() error {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	if err := s.ecdsaSecrets(k); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	return s.privatePEM("ecdsa-p384-sec1.key", "EC PRIVATE KEY", der, nil)
}

func (s *Set) ed25519() error {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.secret(hex.EncodeToString(k.Seed()))
	s.secret(base64.StdEncoding.EncodeToString(k.Seed()))
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return s.privatePEM("ed25519-pkcs8.pem", "PRIVATE KEY", der, nil)
}

func (s *Set) x25519() error {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.secret(hex.EncodeToString(k.Bytes()))
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return s.privatePEM("x25519-pkcs8.pem", "PRIVATE KEY", der, nil)
}

func (s *Set) openSSH() error {
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.secret(hex.EncodeToString(ed.Seed()))
	block, err := ssh.MarshalPrivateKey(ed, "")
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(block)
	s.pemSecrets(data, block.Bytes)
	if err := os.WriteFile(filepath.Join(s.Dir, "id_ed25519"), data, 0o600); err != nil {
		return err
	}

	rk, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	s.bigSecrets(rk.D, rk.Primes[0], rk.Primes[1])
	block, err = ssh.MarshalPrivateKeyWithPassphrase(rk, "", []byte("correct horse"))
	if err != nil {
		return err
	}
	data = pem.EncodeToMemory(block)
	s.pemSecrets(data, block.Bytes)
	if err := os.WriteFile(filepath.Join(s.Dir, "id_rsa"), data, 0o600); err != nil {
		return err
	}

	pub, err := ssh.NewPublicKey(&rk.PublicKey)
	if err != nil {
		return err
	}
	return s.write("authorized_keys", append([]byte("# deploy key\n"), ssh.MarshalAuthorizedKey(pub)...))
}

type spki struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// pqc writes ML-DSA and ML-KEM keys by OID alone. The key bytes are random:
// pqscope classifies these algorithms without decoding keys.
func (s *Set) pqc() error {
	priv := make([]byte, 32)
	_, _ = rand.Read(priv)
	der, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA65}, priv})
	if err != nil {
		return err
	}
	s.secret(hex.EncodeToString(priv))
	if err := s.privatePEM("mldsa65-pkcs8.pem", "PRIVATE KEY", der, nil); err != nil {
		return err
	}
	pub := make([]byte, 1184)
	_, _ = rand.Read(pub)
	der, err = asn1.Marshal(spki{pkix.AlgorithmIdentifier{Algorithm: OIDMLKEM768}, asn1.BitString{Bytes: pub, BitLength: len(pub) * 8}})
	if err != nil {
		return err
	}
	return s.write("mlkem768-public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func (s *Set) certificates() error {
	ca, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	if err := s.ecdsaSecrets(ca); err != nil {
		return err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &ca.PublicKey, ca)
	if err != nil {
		return err
	}
	if err := s.write("ca-ecdsa-p256-selfsigned.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})); err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	leaf, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	s.bigSecrets(leaf.D, leaf.Primes[0], leaf.Primes[1])
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "server.example"},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"server.example"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leaf.PublicKey, ca)
	if err != nil {
		return err
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	if err := s.write("leaf-rsa3072.crt", leafPEM); err != nil {
		return err
	}
	if err := s.write("leaf-rsa3072.der", leafDER); err != nil {
		return err
	}

	leafKeyDER := x509.MarshalPKCS1PrivateKey(leaf)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: leafKeyDER})
	s.pemSecrets(keyPEM, leafKeyDER)
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	s.secret(b64(keyPEM))
	secret := fmt.Sprintf(`apiVersion: v1
kind: Secret
metadata:
  name: server-tls
type: kubernetes.io/tls
data:
  tls.crt: %s
  tls.key: %s
`, b64(leafPEM), b64(keyPEM))
	if err := s.write("secret.yaml", []byte(secret)); err != nil {
		return err
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.secret(hex.EncodeToString(edKey.Seed()))
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "csr.example"}}, edKey)
	if err != nil {
		return err
	}
	if err := s.write("ed25519.csr", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})); err != nil {
		return err
	}
	return s.mldsaCertificate()
}

// mldsaCertificate hand-builds a self-signed certificate with an ML-DSA-65
// key and signature OID. The key and signature bytes are random; parsing
// does not verify them.
func (s *Set) mldsaCertificate() error {
	name, err := asn1.Marshal(pkix.Name{CommonName: "pq.example"}.ToRDNSequence())
	if err != nil {
		return err
	}
	pub := make([]byte, 1952)
	_, _ = rand.Read(pub)
	alg := pkix.AlgorithmIdentifier{Algorithm: OIDMLDSA65}
	tbs, err := asn1.Marshal(struct {
		Version  int `asn1:"optional,explicit,default:0,tag:0"`
		Serial   *big.Int
		SigAlg   pkix.AlgorithmIdentifier
		Issuer   asn1.RawValue
		Validity struct{ NotBefore, NotAfter time.Time }
		Subject  asn1.RawValue
		SPKI     spki
	}{
		Version: 2, Serial: big.NewInt(3), SigAlg: alg,
		Issuer:   asn1.RawValue{FullBytes: name},
		Validity: struct{ NotBefore, NotAfter time.Time }{time.Now().UTC().Truncate(time.Second), time.Now().UTC().Add(time.Hour).Truncate(time.Second)},
		Subject:  asn1.RawValue{FullBytes: name},
		SPKI:     spki{alg, asn1.BitString{Bytes: pub, BitLength: len(pub) * 8}},
	})
	if err != nil {
		return err
	}
	sig := make([]byte, 3309)
	_, _ = rand.Read(sig)
	der, err := asn1.Marshal(struct {
		TBS    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, alg, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	if err != nil {
		return err
	}
	return s.write("mldsa65-selfsigned.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func (s *Set) misc() error {
	// DH parameters: only the prime's length matters to pqscope.
	p, err := rand.Prime(rand.Reader, 512)
	if err != nil {
		return err
	}
	p.Lsh(p, 1536) // 2048 bits; not prime, which parsing does not check
	der, err := asn1.Marshal(struct{ P, G *big.Int }{p, big.NewInt(2)})
	if err != nil {
		return err
	}
	if err := s.write("dhparam2048.pem", pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: der})); err != nil {
		return err
	}
	junk := make([]byte, 128)
	_, _ = rand.Read(junk)
	if err := s.privatePEM("encrypted-pkcs8.pem", "ENCRYPTED PRIVATE KEY", junk, nil); err != nil {
		return err
	}
	// A PEM block embedded in an unrelated text file.
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	s.secret(hex.EncodeToString(k.Seed()))
	kder, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
	s.pemSecrets(block, kder)
	return s.write("notes.env", append([]byte("API_URL=https://example.org\nSIGNING_KEY=\"\n"), append(block, '"', '\n')...))
}
