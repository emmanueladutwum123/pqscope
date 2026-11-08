package bench

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OpenSSL holds sizes measured from OpenSSL's own output, as bench/run.sh
// leaves it: one directory per knowledge DB ID holding pub.der (a
// SubjectPublicKeyInfo) and, as the algorithm allows, ct and ss (from
// `pkeyutl -encap`) and sig (from `pkeyutl -sign`).
type OpenSSL struct {
	Version string
	Sizes   map[[2]string]int // (algorithm, field) → bytes
}

// LoadOpenSSL reads dir. A missing dir is not an error: it returns nil, and
// the sizes table records that OpenSSL was not run.
func LoadOpenSSL(dir string) (*OpenSSL, error) {
	version, err := os.ReadFile(filepath.Join(dir, "version.txt"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	o := &OpenSSL{Version: strings.TrimSpace(string(version)), Sizes: map[[2]string]int{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		alg := e.Name()
		d := filepath.Join(dir, alg)
		der, err := os.ReadFile(filepath.Join(d, "pub.der"))
		if err != nil {
			return nil, fmt.Errorf("openssl %s: %w", alg, err)
		}
		n, err := spkiKeySize(alg, der)
		if err != nil {
			return nil, fmt.Errorf("openssl %s: %w", alg, err)
		}
		o.Sizes[[2]string{alg, FieldPublicKey}] = n
		for file, field := range map[string]string{"ct": FieldCiphertext, "ss": FieldSharedSecret, "sig": FieldSignature} {
			fi, err := os.Stat(filepath.Join(d, file))
			switch {
			case errors.Is(err, os.ErrNotExist):
			case err != nil:
				return nil, err
			default:
				o.Sizes[[2]string{alg, field}] = int(fi.Size())
			}
		}
	}
	if len(o.Sizes) == 0 {
		return nil, fmt.Errorf("openssl: no algorithms under %s", dir)
	}
	return o, nil
}

// spkiKeySize returns the public key size as the sizes table counts it: the
// subjectPublicKey bit string's bytes (RFC 5280, Section 4.1), which for the
// post-quantum keys is the raw key (FIPS 203, 204 and 205 encodings), for EC
// the uncompressed point and for X25519 the 32-byte key. For RSA, whose bit
// string holds a PKCS #1 RSAPublicKey, it is the modulus size.
func spkiKeySize(alg string, der []byte) (int, error) {
	var spki struct {
		Algorithm asn1.RawValue
		Key       asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return 0, err
	}
	if len(rest) > 0 || spki.Key.BitLength%8 != 0 {
		return 0, errors.New("malformed SubjectPublicKeyInfo")
	}
	if strings.HasPrefix(alg, "RSA-") {
		pub, err := x509.ParsePKCS1PublicKey(spki.Key.Bytes)
		if err != nil {
			return 0, err
		}
		return pub.Size(), nil
	}
	return len(spki.Key.Bytes), nil
}
