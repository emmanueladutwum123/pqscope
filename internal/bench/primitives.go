package bench

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"
)

// Implementations measured.
const (
	ImplStdlib = "go-stdlib"
	ImplCIRCL  = "circl"
)

// Size fields, in bytes as they travel: what a peer or certificate carries.
// Private keys never leave their owner, so they are not measured.
const (
	FieldPublicKey    = "public_key"
	FieldCiphertext   = "ciphertext"
	FieldSignature    = "signature"
	FieldSharedSecret = "shared_secret"
)

// Message is what every signature operation signs: 128 bytes, about the size
// of the content a TLS 1.3 CertificateVerify signs (RFC 8446, Section 4.4.3).
var Message = bytes.Repeat([]byte{0x20}, 128)

// sigSamples is how many signatures are made to size a variable-length
// signature (ECDSA's DER), so it reports the observed maximum.
const sigSamples = 64

// Primitive is one algorithm, in one implementation, that can be measured.
// Algorithm is a knowledge DB entry ID.
type Primitive struct {
	Algorithm string
	Impl      string
	Kind      string // "kem" (including key agreement in KEM roles) or "signature"
	kem       *kemOps
	sig       *sigOps
}

// kemOps measures a KEM, or Diffie-Hellman in KEM roles: encap is the
// responder's work (a fresh ephemeral key and the shared secret against the
// peer's public key, which is the "ciphertext" sent back) and decap the
// initiator's. Both start from encoded bytes, so parsing the peer's key or
// ciphertext is included, as it is in a handshake.
type kemOps struct {
	generate func() (pk []byte, decap func(ct []byte) ([]byte, error), err error)
	encap    func(pk []byte) (ct, ss []byte, err error)
}

// sigOps measures a signature scheme. verify parses the public key each time,
// as a TLS client does with each certificate. pubSize is the public key size
// reported, when it differs from the encoding verify takes (RSA's modulus).
// variable marks a signature encoding whose length varies.
type sigOps struct {
	generate func() (pk []byte, sign func(msg []byte) ([]byte, error), err error)
	verify   func(pk, msg, sig []byte) (bool, error)
	pubSize  func(pk []byte) int
	variable bool
}

// Primitives lists every algorithm the benchmark measures: those in SPEC
// Section 11, with ML-KEM-768 and -1024 measured in both the standard library
// (what crypto/tls uses) and CIRCL (which also has ML-KEM-512).
func Primitives() []Primitive {
	return []Primitive{
		{Algorithm: "X25519", Impl: ImplStdlib, Kind: "kem", kem: ecdhKEM(ecdh.X25519())},
		{Algorithm: "ECDH-P256", Impl: ImplStdlib, Kind: "kem", kem: ecdhKEM(ecdh.P256())},
		{Algorithm: "ML-KEM-512", Impl: ImplCIRCL, Kind: "kem", kem: circlKEM(mlkem512.Scheme())},
		{Algorithm: "ML-KEM-768", Impl: ImplCIRCL, Kind: "kem", kem: circlKEM(mlkem768.Scheme())},
		{Algorithm: "ML-KEM-1024", Impl: ImplCIRCL, Kind: "kem", kem: circlKEM(mlkem1024.Scheme())},
		{Algorithm: "ML-KEM-768", Impl: ImplStdlib, Kind: "kem", kem: stdMLKEM768()},
		{Algorithm: "ML-KEM-1024", Impl: ImplStdlib, Kind: "kem", kem: stdMLKEM1024()},
		{Algorithm: "X25519MLKEM768", Impl: ImplStdlib, Kind: "kem", kem: hybridX25519MLKEM768()},
		{Algorithm: "RSA-2048", Impl: ImplStdlib, Kind: "signature", sig: rsaSig(2048)},
		{Algorithm: "RSA-3072", Impl: ImplStdlib, Kind: "signature", sig: rsaSig(3072)},
		{Algorithm: "ECDSA-P256", Impl: ImplStdlib, Kind: "signature", sig: ecdsaSig()},
		{Algorithm: "ML-DSA-44", Impl: ImplCIRCL, Kind: "signature", sig: mldsaSig(mldsa44.Scheme(), signMLDSA44)},
		{Algorithm: "ML-DSA-65", Impl: ImplCIRCL, Kind: "signature", sig: mldsaSig(mldsa65.Scheme(), signMLDSA65)},
		{Algorithm: "ML-DSA-87", Impl: ImplCIRCL, Kind: "signature", sig: mldsaSig(mldsa87.Scheme(), signMLDSA87)},
		{Algorithm: "SLH-DSA-128s", Impl: ImplCIRCL, Kind: "signature", sig: slhdsaSig(slhdsa.SHA2_128s)},
		{Algorithm: "SLH-DSA-128f", Impl: ImplCIRCL, Kind: "signature", sig: slhdsaSig(slhdsa.SHA2_128f)},
	}
}

// Op names.
const (
	OpKeygen = "keygen"
	OpEncap  = "encap"
	OpDecap  = "decap"
	OpSign   = "sign"
	OpVerify = "verify"
)

// PrimitiveResult is one operation's latency.
type PrimitiveResult struct {
	Algorithm, Impl, Op string
	Stats
}

// SizeResult is one measured size.
type SizeResult struct {
	Algorithm, Impl, Field string
	Bytes                  int
	Variable               bool // the encoding's length varies (ECDSA's DER); Bytes is the maximum seen
}

// Run measures one primitive: every operation's latency and every size. It
// first checks the primitive works (decap recovers the secret, a signature
// verifies), so a broken adapter cannot produce numbers.
func (p Primitive) Run(cfg Config) ([]PrimitiveResult, []SizeResult, error) {
	var res []PrimitiveResult
	var sizes []SizeResult
	add := func(op string, f func() error) error {
		st, err := measure(cfg, f)
		if err != nil {
			return fmt.Errorf("%s %s %s: %w", p.Algorithm, p.Impl, op, err)
		}
		res = append(res, PrimitiveResult{p.Algorithm, p.Impl, op, st})
		return nil
	}
	size := func(field string, n int, variable bool) {
		sizes = append(sizes, SizeResult{p.Algorithm, p.Impl, field, n, variable})
	}
	fail := func(err error) ([]PrimitiveResult, []SizeResult, error) {
		return nil, nil, fmt.Errorf("%s %s: %w", p.Algorithm, p.Impl, err)
	}

	switch {
	case p.kem != nil:
		k := p.kem
		pk, decap, err := k.generate()
		if err != nil {
			return fail(err)
		}
		ct, ss, err := k.encap(pk)
		if err != nil {
			return fail(err)
		}
		got, err := decap(ct)
		if err != nil {
			return fail(fmt.Errorf("decapsulation: %w", err))
		}
		if !bytes.Equal(got, ss) {
			return fail(errors.New("decapsulation does not recover the shared secret"))
		}
		size(FieldPublicKey, len(pk), false)
		size(FieldCiphertext, len(ct), false)
		size(FieldSharedSecret, len(ss), false)
		for _, step := range []struct {
			op string
			f  func() error
		}{
			{OpKeygen, func() error { _, _, err := k.generate(); return err }},
			{OpEncap, func() error { _, _, err := k.encap(pk); return err }},
			{OpDecap, func() error { _, err := decap(ct); return err }},
		} {
			if err := add(step.op, step.f); err != nil {
				return nil, nil, err
			}
		}
	case p.sig != nil:
		s := p.sig
		pk, signer, err := s.generate()
		if err != nil {
			return fail(err)
		}
		var sig []byte
		longest := 0
		samples := 1
		if s.variable {
			samples = sigSamples
		}
		for range samples {
			if sig, err = signer(Message); err != nil {
				return fail(err)
			}
			longest = max(longest, len(sig))
		}
		ok, err := s.verify(pk, Message, sig)
		if err != nil {
			return fail(fmt.Errorf("verification: %w", err))
		}
		if !ok {
			return fail(errors.New("signature does not verify"))
		}
		pub := len(pk)
		if s.pubSize != nil {
			pub = s.pubSize(pk)
		}
		size(FieldPublicKey, pub, false)
		size(FieldSignature, longest, s.variable)
		for _, step := range []struct {
			op string
			f  func() error
		}{
			{OpKeygen, func() error { _, _, err := s.generate(); return err }},
			{OpSign, func() error { _, err := signer(Message); return err }},
			{OpVerify, func() error {
				ok, err := s.verify(pk, Message, sig)
				if err == nil && !ok {
					err = errors.New("signature does not verify")
				}
				return err
			}},
		} {
			if err := add(step.op, step.f); err != nil {
				return nil, nil, err
			}
		}
	default:
		return fail(errors.New("no operations"))
	}
	return res, sizes, nil
}

// --- key agreement and KEMs ---

func ecdhKEM(curve ecdh.Curve) *kemOps {
	return &kemOps{
		generate: func() ([]byte, func([]byte) ([]byte, error), error) {
			priv, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return priv.PublicKey().Bytes(), func(ct []byte) ([]byte, error) {
				peer, err := curve.NewPublicKey(ct)
				if err != nil {
					return nil, err
				}
				return priv.ECDH(peer)
			}, nil
		},
		encap: func(pk []byte) ([]byte, []byte, error) {
			peer, err := curve.NewPublicKey(pk)
			if err != nil {
				return nil, nil, err
			}
			eph, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			ss, err := eph.ECDH(peer)
			return eph.PublicKey().Bytes(), ss, err
		},
	}
}

func circlKEM(scheme kem.Scheme) *kemOps {
	return &kemOps{
		generate: func() ([]byte, func([]byte) ([]byte, error), error) {
			pk, sk, err := scheme.GenerateKeyPair()
			if err != nil {
				return nil, nil, err
			}
			enc, err := pk.MarshalBinary()
			return enc, func(ct []byte) ([]byte, error) { return scheme.Decapsulate(sk, ct) }, err
		},
		encap: func(pk []byte) ([]byte, []byte, error) {
			pub, err := scheme.UnmarshalBinaryPublicKey(pk)
			if err != nil {
				return nil, nil, err
			}
			return scheme.Encapsulate(pub)
		},
	}
}

func stdMLKEM768() *kemOps {
	return &kemOps{
		generate: func() ([]byte, func([]byte) ([]byte, error), error) {
			dk, err := mlkem.GenerateKey768()
			if err != nil {
				return nil, nil, err
			}
			return dk.EncapsulationKey().Bytes(), dk.Decapsulate, nil
		},
		encap: func(pk []byte) ([]byte, []byte, error) {
			ek, err := mlkem.NewEncapsulationKey768(pk)
			if err != nil {
				return nil, nil, err
			}
			ss, ct := ek.Encapsulate()
			return ct, ss, nil
		},
	}
}

func stdMLKEM1024() *kemOps {
	return &kemOps{
		generate: func() ([]byte, func([]byte) ([]byte, error), error) {
			dk, err := mlkem.GenerateKey1024()
			if err != nil {
				return nil, nil, err
			}
			return dk.EncapsulationKey().Bytes(), dk.Decapsulate, nil
		},
		encap: func(pk []byte) ([]byte, []byte, error) {
			ek, err := mlkem.NewEncapsulationKey1024(pk)
			if err != nil {
				return nil, nil, err
			}
			ss, ct := ek.Encapsulate()
			return ct, ss, nil
		},
	}
}

// hybridX25519MLKEM768 composes the TLS hybrid from the standard library's
// parts as crypto/tls does: the client share is the ML-KEM-768 encapsulation
// key then the X25519 key, the server share the ML-KEM ciphertext then the
// X25519 key, and the secret the ML-KEM secret then the X25519 secret
// (draft-ietf-tls-ecdhe-mlkem, Section 3).
func hybridX25519MLKEM768() *kemOps {
	pq, ec := stdMLKEM768(), ecdhKEM(ecdh.X25519())
	return &kemOps{
		generate: func() ([]byte, func([]byte) ([]byte, error), error) {
			pqPK, pqDecap, err := pq.generate()
			if err != nil {
				return nil, nil, err
			}
			ecPK, ecDecap, err := ec.generate()
			if err != nil {
				return nil, nil, err
			}
			return append(pqPK, ecPK...), func(ct []byte) ([]byte, error) {
				if len(ct) != mlkem.CiphertextSize768+32 {
					return nil, errors.New("hybrid: bad ciphertext length")
				}
				a, err := pqDecap(ct[:mlkem.CiphertextSize768])
				if err != nil {
					return nil, err
				}
				b, err := ecDecap(ct[mlkem.CiphertextSize768:])
				return append(a, b...), err
			}, nil
		},
		encap: func(pk []byte) ([]byte, []byte, error) {
			if len(pk) != mlkem.EncapsulationKeySize768+32 {
				return nil, nil, errors.New("hybrid: bad public key length")
			}
			ct1, ss1, err := pq.encap(pk[:mlkem.EncapsulationKeySize768])
			if err != nil {
				return nil, nil, err
			}
			ct2, ss2, err := ec.encap(pk[mlkem.EncapsulationKeySize768:])
			return append(ct1, ct2...), append(ss1, ss2...), err
		},
	}
}

// --- signatures ---

// rsaSig is RSASSA-PKCS1-v1_5 with SHA-256 (hashing included), the RSA
// signature most certificates carry. The public key travels as PKCS #1 DER;
// its reported size is the modulus.
func rsaSig(bits int) *sigOps {
	return &sigOps{
		generate: func() ([]byte, func([]byte) ([]byte, error), error) {
			k, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				return nil, nil, err
			}
			return x509.MarshalPKCS1PublicKey(&k.PublicKey), func(msg []byte) ([]byte, error) {
				h := sha256.Sum256(msg)
				return rsa.SignPKCS1v15(nil, k, crypto.SHA256, h[:])
			}, nil
		},
		verify: func(pk, msg, sig []byte) (bool, error) {
			pub, err := x509.ParsePKCS1PublicKey(pk)
			if err != nil {
				return false, err
			}
			h := sha256.Sum256(msg)
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil, nil
		},
		pubSize: func(pk []byte) int {
			pub, err := x509.ParsePKCS1PublicKey(pk)
			if err != nil {
				return 0
			}
			return pub.Size()
		},
	}
}

// ecdsaSig is ECDSA P-256 with SHA-256, DER-encoded signatures, and the public
// key as an uncompressed point.
func ecdsaSig() *sigOps {
	return &sigOps{
		generate: func() ([]byte, func([]byte) ([]byte, error), error) {
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			pk, err := k.PublicKey.Bytes()
			return pk, func(msg []byte) ([]byte, error) {
				h := sha256.Sum256(msg)
				return ecdsa.SignASN1(rand.Reader, k, h[:])
			}, err
		},
		verify: func(pk, msg, sig []byte) (bool, error) {
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pk)
			if err != nil {
				return false, err
			}
			h := sha256.Sum256(msg)
			return ecdsa.VerifyASN1(pub, h[:], sig), nil
		},
		variable: true,
	}
}

// ML-DSA signs hedged (FIPS 204, Algorithm 2 with fresh randomness), the
// default FIPS 204 recommends, with an empty context. CIRCL's generic Scheme
// signs deterministically, so the per-parameter-set functions are used.
func signMLDSA44(sk sign.PrivateKey, msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa44.SignatureSize)
	return sig, mldsa44.SignTo(sk.(*mldsa44.PrivateKey), msg, nil, true, sig)
}

func signMLDSA65(sk sign.PrivateKey, msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	return sig, mldsa65.SignTo(sk.(*mldsa65.PrivateKey), msg, nil, true, sig)
}

func signMLDSA87(sk sign.PrivateKey, msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa87.SignatureSize)
	return sig, mldsa87.SignTo(sk.(*mldsa87.PrivateKey), msg, nil, true, sig)
}

func mldsaSig(scheme sign.Scheme, signFn func(sign.PrivateKey, []byte) ([]byte, error)) *sigOps {
	return circlSig(scheme, func(sk sign.PrivateKey) func([]byte) ([]byte, error) {
		return func(msg []byte) ([]byte, error) { return signFn(sk, msg) }
	})
}

// SLH-DSA signs randomized (FIPS 205, Algorithm 22 with opt_rand fresh), the
// SHA2 parameter sets, with an empty context.
func slhdsaSig(id slhdsa.ID) *sigOps {
	scheme := id.Scheme()
	return circlSig(scheme, func(sk sign.PrivateKey) func([]byte) ([]byte, error) {
		return func(msg []byte) ([]byte, error) {
			sig := scheme.Sign(sk, msg, nil)
			if sig == nil {
				return nil, errors.New("slh-dsa: signing failed")
			}
			return sig, nil
		}
	})
}

func circlSig(scheme sign.Scheme, signer func(sign.PrivateKey) func([]byte) ([]byte, error)) *sigOps {
	return &sigOps{
		generate: func() ([]byte, func([]byte) ([]byte, error), error) {
			pk, sk, err := scheme.GenerateKey()
			if err != nil {
				return nil, nil, err
			}
			enc, err := pk.MarshalBinary()
			return enc, signer(sk), err
		},
		verify: func(pk, msg, sig []byte) (bool, error) {
			pub, err := scheme.UnmarshalBinaryPublicKey(pk)
			if err != nil {
				return false, err
			}
			return scheme.Verify(pub, msg, sig, nil), nil
		},
	}
}
