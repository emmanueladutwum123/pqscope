//lint:file-ignore SA1019 pqscope must recognise deprecated DSA keys in order to report them.

package config

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // only to recognise legacy DSA keys
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// material is one asset found in key material. Nothing here ever holds
// private key bytes: evidence is built only from public data (the public key
// fingerprint, certificate names and dates).
type material struct {
	asset    model.Asset
	symbol   string
	line     int
	evidence string
}

// keyMaterial finds every PEM block in data, and, when der is set and there
// are none, tries data as DER. line0 is the line of data's first byte in the
// file.
func (s *Scanner) keyMaterial(data []byte, line0 int, der bool) ([]material, []string) {
	var out []material
	var notes []string
	found := false
	for off := 0; ; {
		i := bytes.Index(data[off:], []byte("-----BEGIN "))
		if i < 0 {
			break
		}
		start := off + i
		block, rest := pem.Decode(data[start:])
		if block == nil {
			off = start + len("-----BEGIN ")
			continue
		}
		found = true
		line := line0 + bytes.Count(data[:start], []byte("\n"))
		m, note := s.pemBlock(block, line)
		out = append(out, m...)
		if note != "" {
			notes = append(notes, fmt.Sprintf("line %d: %s", line, note))
		}
		off = len(data) - len(rest)
	}
	if !found && der {
		out = append(out, s.derBlob(data, line0)...)
	}
	return out, notes
}

func (s *Scanner) pemBlock(b *pem.Block, line int) ([]material, string) {
	encrypted := strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED")
	switch b.Type {
	case "CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CERTIFICATE":
		return s.certificate(b.Bytes, line), ""
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		return s.csr(b.Bytes, line), ""
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			pub = nil
		}
		return s.keyFinding(pub, b.Bytes, "public-key", "public key (SPKI)", line), ""
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(b.Bytes)
		if err != nil {
			return nil, "unparseable RSA public key"
		}
		return s.keyFinding(pub, nil, "public-key", "public key (PKCS#1)", line), ""
	case "PRIVATE KEY":
		return s.pkcs8(b.Bytes, line)
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY":
		if encrypted {
			family := map[string]string{"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "ECDSA", "DSA PRIVATE KEY": "DSA"}[b.Type]
			a, err := familyAsset(s.db, family, model.PrimitiveSignature, model.ParamsUnknown)
			if err != nil {
				return nil, err.Error()
			}
			return []material{{a, "private-key", line, "encrypted private key (legacy PEM); size not visible"}}, ""
		}
		return s.legacyPrivate(b, line)
	case "ENCRYPTED PRIVATE KEY":
		return nil, "encrypted PKCS#8 private key: the algorithm is not visible without the passphrase"
	case "OPENSSH PRIVATE KEY":
		return s.openSSHPrivate(b, line)
	case "DH PARAMETERS":
		var params struct{ P, G *big.Int }
		if _, err := asn1.Unmarshal(b.Bytes, &params); err != nil || params.P == nil {
			return nil, "unparseable DH parameters"
		}
		a, err := familyAsset(s.db, "DH", model.PrimitiveKeyAgreement, strconv.Itoa(params.P.BitLen()))
		if err != nil {
			return nil, err.Error()
		}
		return []material{{a, "dh-parameters", line, fmt.Sprintf("DH parameters, %d-bit prime", params.P.BitLen())}}, ""
	}
	return nil, ""
}

// derBlob tries a DER file as each structure in turn.
func (s *Scanner) derBlob(data []byte, line int) []material {
	if m := s.certificate(data, line); m != nil {
		return m
	}
	if _, err := x509.ParseCertificateRequest(data); err == nil {
		return s.csr(data, line)
	}
	if pub, err := x509.ParsePKIXPublicKey(data); err == nil {
		return s.keyFinding(pub, data, "public-key", "public key (SPKI, DER)", line)
	}
	if m, _ := s.pkcs8(data, line); m != nil {
		return m
	}
	if k, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return s.privateFinding(k, "PKCS#1, DER", line)
	}
	if k, err := x509.ParseECPrivateKey(data); err == nil {
		return s.privateFinding(k, "SEC 1, DER", line)
	}
	return nil
}

// spki is a SubjectPublicKeyInfo, parsed only far enough to read its OID.
type spki struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// oidAsset maps an algorithm OID that crypto/x509 does not know.
func (s *Scanner) oidAsset(oid asn1.ObjectIdentifier) (model.Asset, bool) {
	a := s.names.lookup("oids", oid.String())
	if len(a) == 0 {
		return model.Asset{}, false
	}
	return a[0], true
}

// publicAsset classifies a parsed public key. raw, if set, is the key's SPKI,
// used for keys crypto/x509 could not parse.
func (s *Scanner) publicAsset(pub any, raw []byte) (model.Asset, bool) {
	exact := func(family, primitive, params string) (model.Asset, bool) {
		a, err := familyAsset(s.db, family, primitive, params)
		return a, err == nil
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return exact("RSA", model.PrimitiveSignature, strconv.Itoa(k.N.BitLen()))
	case *ecdsa.PublicKey:
		return exact("ECDSA", model.PrimitiveSignature, k.Curve.Params().Name)
	case ed25519.PublicKey:
		return exact("EdDSA", model.PrimitiveSignature, "Ed25519")
	case *ecdh.PublicKey:
		switch k.Curve() {
		case ecdh.X25519():
			return exact("X25519", model.PrimitiveKeyAgreement, "X25519")
		case ecdh.P256():
			return exact("ECDH", model.PrimitiveKeyAgreement, "P-256")
		case ecdh.P384():
			return exact("ECDH", model.PrimitiveKeyAgreement, "P-384")
		case ecdh.P521():
			return exact("ECDH", model.PrimitiveKeyAgreement, "P-521")
		}
	case *dsa.PublicKey:
		return exact("DSA", model.PrimitiveSignature, strconv.Itoa(k.P.BitLen()))
	}
	if raw != nil {
		var info spki
		if _, err := asn1.Unmarshal(raw, &info); err == nil {
			return s.oidAsset(info.Algorithm.Algorithm)
		}
	}
	return model.Asset{}, false
}

// fingerprint is the SHA-256 of the public key's SPKI, in OpenSSH's
// "SHA256:base64" form.
func fingerprint(pub any, raw []byte) string {
	if raw == nil {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return ""
		}
		raw = der
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func (s *Scanner) keyFinding(pub any, raw []byte, symbol, what string, line int) []material {
	a, ok := s.publicAsset(pub, raw)
	if !ok {
		return nil
	}
	ev := what
	if fp := fingerprint(pub, raw); fp != "" {
		ev += ", " + fp
	}
	return []material{{a, symbol, line, ev}}
}

// privateFinding reports a parsed private key by its public half only.
func (s *Scanner) privateFinding(key any, format string, line int) []material {
	var pub any
	switch k := key.(type) {
	case *ed25519.PrivateKey: // x/crypto/ssh returns a pointer for OpenSSH keys
		pub = k.Public()
	case crypto.Signer:
		pub = k.Public()
	case *ecdh.PrivateKey:
		pub = k.PublicKey()
	case *dsa.PrivateKey:
		pub = &k.PublicKey
	default:
		return nil
	}
	return s.keyFinding(pub, nil, "private-key", "private key ("+format+"), public key", line)
}

// pkcs8 reads an unencrypted PKCS#8 private key. Algorithms crypto/x509 does
// not know are classified by OID alone; their key bytes are never decoded.
func (s *Scanner) pkcs8(der []byte, line int) ([]material, string) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return s.privateFinding(k, "PKCS#8", line), ""
	}
	var info struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey asn1.RawValue
	}
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, "unparseable PKCS#8 private key"
	}
	a, ok := s.oidAsset(info.Algorithm.Algorithm)
	if !ok {
		return nil, "PKCS#8 private key with unknown algorithm " + info.Algorithm.Algorithm.String()
	}
	return []material{{a, "private-key", line, "private key (PKCS#8); public key not derived"}}, ""
}

func (s *Scanner) legacyPrivate(b *pem.Block, line int) ([]material, string) {
	switch b.Type {
	case "RSA PRIVATE KEY":
		if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
			return s.privateFinding(k, "PKCS#1", line), ""
		}
	case "EC PRIVATE KEY":
		if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
			return s.privateFinding(k, "SEC 1", line), ""
		}
	case "DSA PRIVATE KEY":
		// OpenSSL's DSA format: SEQUENCE { version, p, q, g, y, x }.
		var k struct{ Version, P, Q, G, Y, X *big.Int }
		if _, err := asn1.Unmarshal(b.Bytes, &k); err == nil && k.P != nil {
			pub := &dsa.PublicKey{Parameters: dsa.Parameters{P: k.P, Q: k.Q, G: k.G}, Y: k.Y}
			return s.keyFinding(pub, nil, "private-key", "private key (DSA), public key", line), ""
		}
	}
	return nil, "unparseable " + strings.ToLower(b.Type)
}

func (s *Scanner) openSSHPrivate(b *pem.Block, line int) ([]material, string) {
	key, err := ssh.ParseRawPrivateKey(pem.EncodeToMemory(b))
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing) && missing.PublicKey != nil:
		// Passphrase-protected: the public key is stored in the clear.
		return s.sshPublic(missing.PublicKey, "private-key", "private key (OpenSSH, passphrase-protected), public key", line), ""
	case err != nil:
		return nil, "unparseable OpenSSH private key"
	}
	return s.privateFinding(key, "OpenSSH", line), ""
}

// sshPublic classifies an SSH public key, using its Go form when there is
// one so RSA sizes are known.
func (s *Scanner) sshPublic(pk ssh.PublicKey, symbol, what string, line int) []material {
	ev := what + ", " + ssh.FingerprintSHA256(pk)
	if c, ok := pk.(ssh.CryptoPublicKey); ok {
		if a, ok := s.publicAsset(c.CryptoPublicKey(), nil); ok {
			return []material{{a, symbol, line, ev}}
		}
	}
	for _, a := range s.ssh(sshPubkey, pk.Type()) {
		if a.Primitive == model.PrimitiveSignature {
			return []material{{a, symbol, line, ev}}
		}
	}
	return nil
}

// authorizedKeys reads OpenSSH public key lines (*.pub, authorized_keys).
func (s *Scanner) authorizedKeys(data []byte) []material {
	var out []material
	for i, line := range splitLines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		out = append(out, s.sshPublic(pk, "ssh-public-key", "SSH public key", i+1)...)
	}
	return out
}

// sigAlgs maps X.509 signature algorithms to the signing family and digest.
var sigAlgs = map[x509.SignatureAlgorithm]struct{ family, hash string }{
	x509.MD5WithRSA:       {"RSA", "MD5"},
	x509.SHA1WithRSA:      {"RSA", "SHA-1"},
	x509.SHA256WithRSA:    {"RSA", "SHA-256"},
	x509.SHA384WithRSA:    {"RSA", "SHA-384"},
	x509.SHA512WithRSA:    {"RSA", "SHA-512"},
	x509.SHA256WithRSAPSS: {"RSA", "SHA-256"},
	x509.SHA384WithRSAPSS: {"RSA", "SHA-384"},
	x509.SHA512WithRSAPSS: {"RSA", "SHA-512"},
	x509.DSAWithSHA1:      {"DSA", "SHA-1"},
	x509.DSAWithSHA256:    {"DSA", "SHA-256"},
	x509.ECDSAWithSHA1:    {"ECDSA", "SHA-1"},
	x509.ECDSAWithSHA256:  {"ECDSA", "SHA-256"},
	x509.ECDSAWithSHA384:  {"ECDSA", "SHA-384"},
	x509.ECDSAWithSHA512:  {"ECDSA", "SHA-512"},
	x509.PureEd25519:      {"EdDSA", ""},
}

// certificate reports a certificate's subject key, the issuer's signature
// algorithm and its digest. A self-signed certificate's issuer key is its
// subject key, so the signature's parameters are known.
func (s *Scanner) certificate(der []byte, line int) []material {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	name := cert.Subject.CommonName
	if name == "" {
		name = cert.Subject.String()
	}
	desc := fmt.Sprintf("certificate %q, issuer %q, expires %s", name, cert.Issuer.String(), cert.NotAfter.UTC().Format("2006-01-02"))
	subject, ok := s.publicAsset(cert.PublicKey, cert.RawSubjectPublicKeyInfo)
	var out []material
	if ok {
		out = append(out, material{subject, "x509:subject-public-key", line, desc + ", key " + fingerprint(cert.PublicKey, cert.RawSubjectPublicKeyInfo)})
	}
	selfSigned := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	return append(out, s.signature(cert.SignatureAlgorithm, outerSigOID(der), subject, ok && selfSigned, line, desc)...)
}

func (s *Scanner) csr(der []byte, line int) []material {
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil
	}
	desc := fmt.Sprintf("certificate request %q", req.Subject.String())
	subject, ok := s.publicAsset(req.PublicKey, req.RawSubjectPublicKeyInfo)
	var out []material
	if ok {
		out = append(out, material{subject, "csr:public-key", line, desc + ", key " + fingerprint(req.PublicKey, req.RawSubjectPublicKeyInfo)})
	}
	// A CSR is signed by its own key.
	return append(out, s.signature(req.SignatureAlgorithm, outerSigOID(der), subject, ok, line, desc)...)
}

// outerSigOID reads the signatureAlgorithm OID of a certificate or CSR, both
// SEQUENCE { tbs, signatureAlgorithm, signature }.
func outerSigOID(der []byte) asn1.ObjectIdentifier {
	var outer struct {
		TBS    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil
	}
	return outer.SigAlg.Algorithm
}

func (s *Scanner) signature(alg x509.SignatureAlgorithm, oid asn1.ObjectIdentifier, signer model.Asset, signerKnown bool, line int, desc string) []material {
	ev := desc + ", signed with " + alg.String()
	sa, known := sigAlgs[alg]
	if !known {
		a, ok := s.oidAsset(oid)
		if !ok {
			return nil
		}
		return []material{{a, "x509:signature", line, desc + ", signed with " + oid.String()}}
	}
	var out []material
	switch {
	case signerKnown && signer.Algorithm == sa.family:
		out = append(out, material{signer, "x509:signature", line, ev})
	case sa.family == "EdDSA":
		if a, err := familyAsset(s.db, "EdDSA", model.PrimitiveSignature, "Ed25519"); err == nil {
			out = append(out, material{a, "x509:signature", line, ev})
		}
	default:
		if a, err := familyAsset(s.db, sa.family, model.PrimitiveSignature, model.ParamsUnknown); err == nil {
			out = append(out, material{a, "x509:signature", line, ev})
		}
	}
	if sa.hash != "" {
		if e, ok := s.db.ByID(sa.hash); ok {
			if a, err := e.Asset(model.PrimitiveHash); err == nil {
				out = append(out, material{a, "x509:signature-hash", line, ev})
			}
		}
	}
	return out
}
