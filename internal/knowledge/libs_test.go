package knowledge

import (
	"slices"
	"strings"
	"testing"
)

func libs(t *testing.T) *Libs {
	t.Helper()
	l, err := DefaultLibs()
	if err != nil {
		t.Fatalf("embedded libs table is invalid: %v", err)
	}
	return l
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.24", "1.24.0", 0},
		{"v1.6.5", "1.5.0", 1},
		{"0.23.21", "0.23.22", -1},
		{"0.38.0", "v0.38.0", 0},
		{"48.0.0rc1", "48.0.0", -1},
		{"1.79-beta", "1.79", -1},
		{"1.80", "1.79", 1},
		{"1.10", "1.9", 1},
		{"3.5.0+build", "3.5.0", 0},
		{"1.1.1k", "1.1.1", -1}, // letters after the patch are read as a pre-release
		{"0.0.0-20240827094217-dd81d9e9be82", "0.1.0", -1},
	}
	for _, tt := range tests {
		if got := CompareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		if got := CompareVersions(tt.b, tt.a); got != -tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestLibsLookup(t *testing.T) {
	l := libs(t)
	for _, tt := range []struct {
		p    Package
		want string
	}{
		{Package{"pypi", "cryptography"}, "pyca-cryptography"},
		{Package{"pypi", "Liboqs_Python"}, "liboqs-python"},
		{Package{"pypi", "PyCryptodomeX"}, "pycryptodome"},
		{Package{"npm", "@noble/post-quantum"}, "noble-post-quantum"},
		{Package{"maven", "org.bouncycastle:bcprov-jdk18on"}, "bouncycastle"},
		{Package{"golang", "github.com/cloudflare/circl"}, "circl"},
		{Package{"cargo", "openssl-src"}, "openssl"},
	} {
		lib, ok := l.Lookup(tt.p)
		if !ok || lib.ID != tt.want {
			t.Errorf("Lookup(%v) = %q, %v; want %q", tt.p, lib.ID, ok, tt.want)
		}
	}
	if _, ok := l.Lookup(Package{"npm", "cryptography"}); ok {
		t.Error("ecosystem must be part of the key")
	}
}

func provided(t *testing.T, libID, version string) []string {
	t.Helper()
	l := libs(t)
	for _, lib := range l.Libraries() {
		if lib.ID != libID {
			continue
		}
		var out []string
		for _, p := range l.Provides(lib, version) {
			name := p.Asset.Algorithm
			if p.Exact {
				name = p.Asset.Params
			}
			name += "/" + p.Asset.Primitive
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
		return out
	}
	t.Fatalf("no library %s", libID)
	return nil
}

func TestProvides(t *testing.T) {
	tests := []struct {
		lib, version string
		has, hasNot  []string
	}{
		{"go-stdlib", "1.23.4", []string{"RSA/signature", "X25519/key-agreement"}, []string{"ML-KEM-768/kem", "X25519MLKEM768/kem"}},
		{"go-stdlib", "1.24", []string{"ML-KEM-768/kem", "ML-KEM-1024/kem", "X25519MLKEM768/kem"}, []string{"SecP256r1MLKEM768/kem", "X25519MLKEM768/key-agreement"}},
		{"go-stdlib", "1.26.3", []string{"SecP256r1MLKEM768/kem", "SecP384r1MLKEM1024/kem"}, nil},
		{"circl", "v1.3.9", []string{"X448/key-agreement"}, []string{"ML-KEM/kem"}},
		{"circl", "v1.5.0", []string{"ML-KEM/kem", "ML-DSA/signature", "X25519MLKEM768/kem"}, []string{"SLH-DSA/signature"}},
		{"circl", "v1.6.5", []string{"SLH-DSA/signature"}, nil},
		{"pyca-cryptography", "47.0.0", []string{"RSA/signature", "RSA/pke", "DH/key-agreement"}, []string{"ML-KEM/kem"}},
		{"pyca-cryptography", "48.0.0", []string{"ML-KEM/kem", "ML-DSA/signature"}, nil},
		{"pyca-cryptography", "", []string{"RSA/signature"}, []string{"ML-KEM/kem"}},
		{"openssl", "300.5.3+3.5.4", []string{"ML-KEM/kem", "X25519MLKEM768/kem"}, nil},
		{"openssl", "300.4.2+3.4.1", []string{"RSA/signature"}, []string{"ML-KEM/kem"}},
		{"openssl", "300.5.0", []string{"RSA/signature"}, []string{"ML-KEM/kem"}}, // no build metadata: version unknown
		{"x-crypto", "v0.38.0", []string{"mlkem768x25519-sha256/kem"}, nil},
		{"noble-post-quantum", "0.1.0", nil, []string{"ML-KEM/kem"}},
	}
	for _, tt := range tests {
		got := provided(t, tt.lib, tt.version)
		for _, h := range tt.has {
			if !slices.Contains(got, h) {
				t.Errorf("%s %s: missing %s (got %v)", tt.lib, tt.version, h, got)
			}
		}
		for _, h := range tt.hasNot {
			if slices.Contains(got, h) {
				t.Errorf("%s %s: should not provide %s", tt.lib, tt.version, h)
			}
		}
	}
}

func TestProvidedAssetsAreConsistent(t *testing.T) {
	l := libs(t)
	for _, lib := range l.Libraries() {
		for _, p := range l.Provides(lib, "999") {
			if p.Asset.Quantum == "" {
				t.Errorf("%s: %s has no quantum status", lib.ID, p.Asset.Algorithm)
			}
			if p.Exact == (p.Asset.Params == "unknown") {
				t.Errorf("%s: %+v exact=%v", lib.ID, p.Asset, p.Exact)
			}
		}
	}
}

func TestParseLibsRejects(t *testing.T) {
	d := db(t)
	base := string(libsYAML)
	tests := []struct{ name, doc, want string }{
		{"unknown provide", strings.Replace(base, "provides: [ML-KEM, ML-DSA], source: pyca-changelog", "provides: [ML-KEM, Kyber], source: pyca-changelog", 1), `"Kyber" is neither`},
		{"unknown source", strings.Replace(base, "source: ring}", "source: nowhere}", 1), "unknown source"},
		{"duplicate package", strings.Replace(base, "{ecosystem: npm, name: jsrsasign}", "{ecosystem: npm, name: node-forge}", 1), "listed twice"},
		{"bad version_from", strings.Replace(base, "version_from: build-metadata", "version_from: magic", 1), "unknown version_from"},
		{"no checked", strings.Replace(base, `checked: "2026-11-08"`, "", 1), "checked date"},
		{"unknown field", base + "extra: 1\n", "extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.doc == base {
				t.Fatal("case did not change the table")
			}
			if _, err := ParseLibs(d, []byte(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
