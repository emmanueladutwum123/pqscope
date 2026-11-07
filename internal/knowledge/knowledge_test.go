package knowledge

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/cloudflare/circl/sign/slhdsa"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

func db(t *testing.T) *DB {
	t.Helper()
	d, err := Default()
	if err != nil {
		t.Fatalf("embedded database is invalid: %v", err)
	}
	return d
}

func mustEntry(t *testing.T, id string) Entry {
	t.Helper()
	e, ok := db(t).ByID(id)
	if !ok {
		t.Fatalf("no entry %q", id)
	}
	return e
}

// The migration-benchmark algorithm list must stay fully covered.
func TestBenchmarkAlgorithmsCovered(t *testing.T) {
	tests := []struct {
		algorithm, params string
		primitive         string
		quantum           string
		classicalBits     int
	}{
		{"X25519", "X25519", model.PrimitiveKeyAgreement, model.QuantumVulnerable, 128},
		{"ECDSA", "P-256", model.PrimitiveSignature, model.QuantumVulnerable, 128},
		{"ECDH", "P-256", model.PrimitiveKeyAgreement, model.QuantumVulnerable, 128},
		{"RSA", "2048", model.PrimitiveSignature, model.QuantumVulnerable, 112},
		{"RSA", "2048", model.PrimitivePKE, model.QuantumVulnerable, 112},
		{"RSA", "3072", model.PrimitiveSignature, model.QuantumVulnerable, 128},
		{"ML-KEM", "ML-KEM-512", model.PrimitiveKEM, model.QuantumSafe, 128},
		{"ML-KEM", "ML-KEM-768", model.PrimitiveKEM, model.QuantumSafe, 192},
		{"ML-KEM", "ML-KEM-1024", model.PrimitiveKEM, model.QuantumSafe, 256},
		{"ML-DSA", "ML-DSA-44", model.PrimitiveSignature, model.QuantumSafe, 128},
		{"ML-DSA", "ML-DSA-65", model.PrimitiveSignature, model.QuantumSafe, 192},
		{"ML-DSA", "ML-DSA-87", model.PrimitiveSignature, model.QuantumSafe, 256},
		{"SLH-DSA", "SLH-DSA-128s", model.PrimitiveSignature, model.QuantumSafe, 128},
		{"SLH-DSA", "SLH-DSA-128f", model.PrimitiveSignature, model.QuantumSafe, 128},
		{"Hybrid", "X25519MLKEM768", model.PrimitiveKEM, model.QuantumHybrid, 192},
	}
	for _, tt := range tests {
		t.Run(tt.algorithm+"/"+tt.params+"/"+tt.primitive, func(t *testing.T) {
			e, ok := db(t).Lookup(tt.algorithm, tt.params)
			if !ok {
				t.Fatal("not found")
			}
			a, err := e.Asset(tt.primitive)
			if err != nil {
				t.Fatal(err)
			}
			if a.Quantum != tt.quantum {
				t.Errorf("Quantum = %q, want %q", a.Quantum, tt.quantum)
			}
			if a.ClassicalBits != tt.classicalBits {
				t.Errorf("ClassicalBits = %d, want %d", a.ClassicalBits, tt.classicalBits)
			}
			if e.Sizes == (Sizes{}) {
				t.Error("no sizes recorded")
			}
		})
	}
}

// Sizes are checked against independent implementations rather than restating
// the YAML.
func TestSizesMatchImplementations(t *testing.T) {
	check := func(t *testing.T, name string, got, want int) {
		t.Helper()
		if got != want {
			t.Errorf("%s = %d in the DB, implementation says %d", name, got, want)
		}
	}

	t.Run("ML-KEM stdlib", func(t *testing.T) {
		s := mustEntry(t, "ML-KEM-768").Sizes
		check(t, "public key", s.PublicKey, mlkem.EncapsulationKeySize768)
		check(t, "ciphertext", s.Ciphertext, mlkem.CiphertextSize768)
		check(t, "shared secret", s.SharedSecret, mlkem.SharedKeySize)
		s = mustEntry(t, "ML-KEM-1024").Sizes
		check(t, "public key", s.PublicKey, mlkem.EncapsulationKeySize1024)
		check(t, "ciphertext", s.Ciphertext, mlkem.CiphertextSize1024)
	})

	t.Run("ML-KEM circl", func(t *testing.T) {
		scheme := mlkem512.Scheme()
		s := mustEntry(t, "ML-KEM-512").Sizes
		check(t, "public key", s.PublicKey, scheme.PublicKeySize())
		check(t, "private key", s.PrivateKey, scheme.PrivateKeySize())
		check(t, "ciphertext", s.Ciphertext, scheme.CiphertextSize())
		check(t, "shared secret", s.SharedSecret, scheme.SharedKeySize())
	})

	mldsa := []struct {
		id            string
		pub, priv, sg int
	}{
		{"ML-DSA-44", mldsa44.PublicKeySize, mldsa44.PrivateKeySize, mldsa44.SignatureSize},
		{"ML-DSA-65", mldsa65.PublicKeySize, mldsa65.PrivateKeySize, mldsa65.SignatureSize},
		{"ML-DSA-87", mldsa87.PublicKeySize, mldsa87.PrivateKeySize, mldsa87.SignatureSize},
	}
	for _, tt := range mldsa {
		t.Run(tt.id, func(t *testing.T) {
			s := mustEntry(t, tt.id).Sizes
			check(t, "public key", s.PublicKey, tt.pub)
			check(t, "private key", s.PrivateKey, tt.priv)
			check(t, "signature", s.Signature, tt.sg)
		})
	}

	slh := []struct {
		id        string
		sha, shak slhdsa.ID
	}{
		{"SLH-DSA-128s", slhdsa.SHA2_128s, slhdsa.SHAKE_128s},
		{"SLH-DSA-128f", slhdsa.SHA2_128f, slhdsa.SHAKE_128f},
		{"SLH-DSA-192s", slhdsa.SHA2_192s, slhdsa.SHAKE_192s},
		{"SLH-DSA-192f", slhdsa.SHA2_192f, slhdsa.SHAKE_192f},
		{"SLH-DSA-256s", slhdsa.SHA2_256s, slhdsa.SHAKE_256s},
		{"SLH-DSA-256f", slhdsa.SHA2_256f, slhdsa.SHAKE_256f},
	}
	for _, tt := range slh {
		t.Run(tt.id, func(t *testing.T) {
			s := mustEntry(t, tt.id).Sizes
			for _, id := range []slhdsa.ID{tt.sha, tt.shak} {
				scheme := id.Scheme()
				check(t, "public key", s.PublicKey, scheme.PublicKeySize())
				check(t, "private key", s.PrivateKey, scheme.PrivateKeySize())
				check(t, "signature", s.Signature, scheme.SignatureSize())
			}
		})
	}

	t.Run("hybrid shares are the sum of their components", func(t *testing.T) {
		tests := []struct {
			id, classical, pq string
		}{
			{"X25519MLKEM768", "X25519", "ML-KEM-768"},
			{"SecP256r1MLKEM768", "ECDH-P256", "ML-KEM-768"},
			{"SecP384r1MLKEM1024", "ECDH-P384", "ML-KEM-1024"},
		}
		for _, tt := range tests {
			h := mustEntry(t, tt.id).Sizes
			c, p := mustEntry(t, tt.classical).Sizes, mustEntry(t, tt.pq).Sizes
			check(t, tt.id+" client share", h.PublicKey, c.PublicKey+p.PublicKey)
			check(t, tt.id+" server share", h.Ciphertext, c.PublicKey+p.Ciphertext)
			check(t, tt.id+" shared secret", h.SharedSecret, c.SharedSecret+p.SharedSecret)
		}
	})

	for _, tt := range []struct {
		id   string
		bits int
	}{{"RSA-2048", 2048}, {"RSA-3072", 3072}} {
		t.Run(tt.id, func(t *testing.T) {
			k, err := rsa.GenerateKey(rand.Reader, tt.bits)
			if err != nil {
				t.Fatal(err)
			}
			s := mustEntry(t, tt.id).Sizes
			check(t, "public key", s.PublicKey, k.Size())
			check(t, "signature", s.Signature, k.Size())
		})
	}

	ec := []struct {
		ecdsaID, ecdhID string
		curve           elliptic.Curve
		ecdhCurve       ecdh.Curve
	}{
		{"ECDSA-P256", "ECDH-P256", elliptic.P256(), ecdh.P256()},
		{"ECDSA-P384", "ECDH-P384", elliptic.P384(), ecdh.P384()},
		{"ECDSA-P521", "ECDH-P521", elliptic.P521(), ecdh.P521()},
	}
	for _, tt := range ec {
		t.Run(tt.ecdhID, func(t *testing.T) {
			k, err := tt.ecdhCurve.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := k.ECDH(k.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			s := mustEntry(t, tt.ecdhID).Sizes
			check(t, "public key", s.PublicKey, len(k.PublicKey().Bytes()))
			check(t, "private key", s.PrivateKey, len(k.Bytes()))
			check(t, "shared secret", s.SharedSecret, len(secret))

			sk, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			byteLen := (sk.Params().BitSize + 7) / 8
			s = mustEntry(t, tt.ecdsaID).Sizes
			check(t, "ecdsa private key", s.PrivateKey, byteLen)
			check(t, "ecdsa signature", s.Signature, 2*byteLen)
		})
	}

	t.Run("X25519", func(t *testing.T) {
		k, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s := mustEntry(t, "X25519").Sizes
		check(t, "public key", s.PublicKey, len(k.PublicKey().Bytes()))
		check(t, "private key", s.PrivateKey, len(k.Bytes()))
	})

	t.Run("Ed25519", func(t *testing.T) {
		s := mustEntry(t, "Ed25519").Sizes
		check(t, "public key", s.PublicKey, ed25519.PublicKeySize)
		check(t, "private key", s.PrivateKey, ed25519.SeedSize)
		check(t, "signature", s.Signature, ed25519.SignatureSize)
	})
}

func TestEveryEntryCited(t *testing.T) {
	d := db(t)
	for _, e := range d.Entries() {
		if len(e.Sources) == 0 {
			t.Errorf("%s has no sources", e.ID)
		}
		for _, key := range e.Sources {
			if _, ok := d.Source(key); !ok {
				t.Errorf("%s cites unknown source %q", e.ID, key)
			}
		}
	}
}

func TestReplacementSuggestions(t *testing.T) {
	tests := []struct {
		id, primitive, civilian, cnsa2 string
	}{
		{"ECDH-P256", model.PrimitiveKeyAgreement, "X25519MLKEM768", "ML-KEM-1024"},
		{"RSA-2048", model.PrimitiveSignature, "ML-DSA-65", "ML-DSA-87"},
		{"RSA-2048", model.PrimitivePKE, "ML-KEM-768", "ML-KEM-1024"},
		{"Ed25519", model.PrimitiveSignature, "ML-DSA-65", "ML-DSA-87"},
		{"SHA-1", model.PrimitiveHash, "SHA-256", "SHA-384"},
	}
	for _, tt := range tests {
		t.Run(tt.id+"/"+tt.primitive, func(t *testing.T) {
			r, ok := mustEntry(t, tt.id).Replacement[tt.primitive]
			if !ok {
				t.Fatal("no replacement")
			}
			if r.Civilian != tt.civilian || r.CNSA2 != tt.cnsa2 {
				t.Errorf("got %+v, want civilian %s, cnsa2 %s", r, tt.civilian, tt.cnsa2)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	tests := []struct {
		name, algorithm, params, wantID string
	}{
		{"canonical", "RSA", "2048", "RSA-2048"},
		{"case insensitive", "rsa", "2048", "RSA-2048"},
		{"curve alias ecdsa", "ECDSA", "prime256v1", "ECDSA-P256"},
		{"curve alias ecdh", "ECDH", "secp256r1", "ECDH-P256"},
		{"slh alias", "SLH-DSA", "SLH-DSA-SHAKE-128s", "SLH-DSA-128s"},
		{"same size different family", "DH", "2048", "DH-2048"},
		{"unknown params", "RSA", "unknown", ""},
		{"unknown algorithm", "NOPE", "2048", ""},
		{"algorithm and params from different entries", "ECDSA", "2048", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, ok := db(t).Lookup(tt.algorithm, tt.params)
			if tt.wantID == "" {
				if ok {
					t.Fatalf("found %s, want nothing", e.ID)
				}
				return
			}
			if !ok || e.ID != tt.wantID {
				t.Fatalf("got %q (found=%v), want %q", e.ID, ok, tt.wantID)
			}
		})
	}
}

func TestFind(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		{"P-256", []string{"ECDSA-P256", "ECDH-P256"}},
		{"x25519mlkem768", []string{"X25519MLKEM768"}},
		{" ssh-ed25519 ", []string{"Ed25519"}},
		{"mlkem768x25519-sha256", []string{"mlkem768x25519-sha256"}},
		{"nope", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := db(t).Find(tt.name)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].ID != tt.want[i] {
					t.Errorf("entry %d = %s, want %s", i, got[i].ID, tt.want[i])
				}
			}
		})
	}
}

func TestFamilyQuantum(t *testing.T) {
	tests := []struct {
		algorithm, want string
		ok              bool
	}{
		{"RSA", model.QuantumVulnerable, true},
		{"ml-kem", model.QuantumSafe, true},
		{"Hybrid", model.QuantumHybrid, true},
		{"AES", model.QuantumWeakened, true},
		{"MD5", model.QuantumBrokenNow, true},
		{"NOPE", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			got, ok := db(t).FamilyQuantum(tt.algorithm)
			if got != tt.want || ok != tt.ok {
				t.Errorf("got (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestAssetRejectsWrongPrimitive(t *testing.T) {
	if _, err := mustEntry(t, "ML-KEM-768").Asset(model.PrimitiveSignature); err == nil {
		t.Error("ML-KEM accepted as a signature")
	}
}

func TestParseRejects(t *testing.T) {
	const header = "version: 1\nsources: {s: {title: T, url: \"https://example.org\"}}\n"
	const safe = "{id: A, algorithm: A, params: a, primitives: [kem], classical_bits: 128, quantum: safe, sources: [s]}"
	tests := []struct {
		name, doc, wantErr string
	}{
		{"unknown field", header + "entries:\n  - {id: A, bogus: 1}\n", "bogus"},
		{"no sources", header + "entries:\n  - {id: A, algorithm: A, params: a, primitives: [kem], quantum: safe}\n", "no sources"},
		{"unknown source", header + "entries:\n  - {id: A, algorithm: A, params: a, primitives: [kem], quantum: safe, sources: [x]}\n", "unknown source"},
		{"duplicate id", header + "entries:\n  - " + safe + "\n  - " + safe + "\n", "duplicate id"},
		{"bad primitive", header + "entries:\n  - {id: A, algorithm: A, params: a, primitives: [magic], quantum: safe, sources: [s]}\n", "unknown primitive"},
		{"bad quantum", header + "entries:\n  - {id: A, algorithm: A, params: a, primitives: [kem], quantum: maybe, sources: [s]}\n", "unknown quantum"},
		{"vulnerable without replacement", header + "entries:\n  - {id: A, algorithm: A, params: a, primitives: [kem], quantum: vulnerable, sources: [s]}\n", "no replacement"},
		{"replacement unresolved", header + "entries:\n  - {id: A, algorithm: A, params: a, primitives: [kem], quantum: vulnerable, sources: [s], replacement: {kem: {civilian: Z, cnsa2: Z}}}\n", "not an entry"},
		{"replacement is vulnerable", header + "entries:\n  - {id: A, algorithm: A, params: a, primitives: [kem], quantum: vulnerable, sources: [s], replacement: {kem: {civilian: A, cnsa2: A}}}\n", "is itself vulnerable"},
		{"hybrid without components", header + "entries:\n  - {id: A, algorithm: A, params: a, primitives: [kem], quantum: hybrid, sources: [s]}\n", "components"},
		{"hybrid wrong strength", header + "entries:\n  - " + safe + "\n  - {id: H, algorithm: H, params: h, primitives: [kem], classical_bits: 1, quantum: hybrid, components: [A], sources: [s]}\n", "strongest component"},
		{"source without url", "version: 1\nsources: {s: {title: T}}\nentries: []\n", "https url"},
		{"no version", "sources: {}\nentries: []\n", "invalid version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}
