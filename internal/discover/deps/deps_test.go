package deps

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

const fixtures = "../../../testdata/deps"

func dep(eco, name, version string, line int) Dependency {
	return Dependency{knowledge.Package{Ecosystem: eco, Name: name}, version, line}
}

// Every listed format parses to the expected packages, versions and lines.
func TestParsers(t *testing.T) {
	tests := []struct {
		file string
		want []Dependency
	}{
		{"go/go.mod", []Dependency{
			dep("golang", "github.com/cloudflare/circl", "v1.6.5", 8),
			dep("golang", "github.com/spf13/cobra", "v1.10.2", 9),
			dep("golang", "golang.org/x/crypto", "v0.37.0", 10),
			dep("golang", "github.com/example/unrelated", "v0.1.0", 13),
			dep("golang", "stdlib", "1.26.3", 5),
		}},
		{"gosum-only/go.sum", []Dependency{
			dep("golang", "github.com/cloudflare/circl", "v1.5.0", 3),
		}},
		{"python/requirements.txt", []Dependency{
			dep("pypi", "cryptography", "48.0.0", 4),
			dep("pypi", "PyCryptodomeX", "", 5),
			dep("pypi", "liboqs_python", "0.12.0", 6),
			dep("pypi", "requests", "2.32.3", 7),
		}},
		{"poetry/poetry.lock", []Dependency{
			dep("pypi", "cffi", "1.17.1", 4),
			dep("pypi", "cryptography", "47.0.0", 10),
		}},
		{"npm/package-lock.json", []Dependency{
			dep("npm", "@noble/post-quantum", "0.2.0", 11),
			dep("npm", "left-pad", "1.3.0", 17),
			dep("npm", "jsrsasign", "11.1.0", 20),
			dep("npm", "node-forge", "1.3.1", 14),
		}},
		{"npm-v1/package-lock.json", []Dependency{
			dep("npm", "express", "4.21.0", 6),
			dep("npm", "node-forge", "0.10.0", 9),
		}},
		{"maven/pom.xml", []Dependency{
			dep("maven", "org.bouncycastle:bcprov-jdk18on", "1.79", 13),
			dep("maven", "junit:junit", "4.13.2", 18),
			dep("maven", "org.bouncycastle:bcprov-jdk15on", "", 26),
		}},
		{"cargo/Cargo.lock", []Dependency{
			dep("cargo", "openssl-src", "300.5.3+3.5.4", 6),
			dep("cargo", "ring", "0.17.8", 11),
			dep("cargo", "rustls", "0.23.22", 16),
			dep("cargo", "serde", "1.0.210", 24),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(fixtures, tt.file))
			if err != nil {
				t.Fatal(err)
			}
			parse, ok := parserFor(filepath.Base(tt.file))
			if !ok {
				t.Fatal("no parser")
			}
			got, err := parse(data)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got  %v\nwant %v", got, tt.want)
			}
		})
	}
}

func TestParserFor(t *testing.T) {
	for name, want := range map[string]bool{
		"requirements.txt": true, "requirements-dev.txt": true, "requirements.in": false,
		"go.mod": true, "Cargo.lock": true, "cargo.lock": false, "package.json": false, "pom.xml": true,
	} {
		if _, ok := parserFor(name); ok != want {
			t.Errorf("parserFor(%q) = %v, want %v", name, ok, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := parsePackageLock([]byte("{not json")); err == nil {
		t.Error("bad package-lock.json should fail")
	}
	if _, err := parsePom([]byte("<project><dependencies>")); err == nil {
		t.Error("truncated pom.xml should fail")
	}
}

func scanFixtures(t *testing.T) Result {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	libs, err := knowledge.DefaultLibs()
	if err != nil {
		t.Fatal(err)
	}
	res, err := New(db, libs).Scan(context.Background(), fixtures)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// key summarises a finding as "path purl name/primitive".
func key(f model.Finding) string {
	name := f.Asset.Algorithm
	if f.Asset.Params != model.ParamsUnknown {
		name = f.Asset.Params
	}
	return f.Location.Path + " " + f.Location.Symbol + " " + name + "/" + f.Asset.Primitive
}

func TestScan(t *testing.T) {
	res := scanFixtures(t)
	var keys []string
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", key(f), err)
		}
		if f.Location.Layer != model.LayerDeps || f.Confidence != CapabilityConfidence || !strings.HasPrefix(f.RuleID, "deps.") {
			t.Errorf("%s: layer %s confidence %v rule %s", key(f), f.Location.Layer, f.Confidence, f.RuleID)
		}
		keys = append(keys, key(f))
	}
	has := []string{
		"go/go.mod pkg:golang/stdlib@1.26.3 SecP256r1MLKEM768/kem",
		"go/go.mod pkg:golang/github.com/cloudflare/circl@v1.6.5 SLH-DSA/signature",
		"go/go.mod pkg:golang/golang.org/x/crypto@v0.37.0 EdDSA/signature",
		"gosum-only/go.sum pkg:golang/github.com/cloudflare/circl@v1.5.0 ML-DSA/signature",
		"python/requirements.txt pkg:pypi/cryptography@48.0.0 ML-KEM/kem",
		"python/requirements.txt pkg:pypi/pycryptodomex RSA/signature",
		"python/requirements.txt pkg:pypi/liboqs-python@0.12.0 ML-DSA/signature",
		"poetry/poetry.lock pkg:pypi/cryptography@47.0.0 RSA/pke",
		"npm/package-lock.json pkg:npm/%40noble/post-quantum@0.2.0 SLH-DSA/signature",
		"npm/package-lock.json pkg:npm/jsrsasign@11.1.0 DSA/signature",
		"npm-v1/package-lock.json pkg:npm/node-forge@0.10.0 EdDSA/signature",
		"maven/pom.xml pkg:maven/org.bouncycastle/bcprov-jdk18on@1.79 ML-KEM/kem",
		"maven/pom.xml pkg:maven/org.bouncycastle/bcprov-jdk15on RSA/signature",
		"cargo/Cargo.lock pkg:cargo/openssl-src@300.5.3%2B3.5.4 X25519MLKEM768/kem",
		"cargo/Cargo.lock pkg:cargo/rustls@0.23.22 X25519MLKEM768/kem",
		"cargo/Cargo.lock pkg:cargo/ring@0.17.8 ECDH/key-agreement",
	}
	hasNot := []string{
		"go/go.mod pkg:golang/golang.org/x/crypto@v0.37.0 mlkem768x25519-sha256/kem", // added in v0.38.0
		"poetry/poetry.lock pkg:pypi/cryptography@47.0.0 ML-KEM/kem",                 // added in 48.0.0
		"maven/pom.xml pkg:maven/org.bouncycastle/bcprov-jdk15on ML-KEM/kem",         // version unknown
		"python/requirements.txt pkg:pypi/pycryptodomex ML-KEM/kem",
	}
	for _, h := range has {
		if !slices.Contains(keys, h) {
			t.Errorf("missing %q", h)
		}
	}
	for _, h := range hasNot {
		if slices.Contains(keys, h) {
			t.Errorf("unexpected %q", h)
		}
	}
	for _, k := range keys {
		for _, unrelated := range []string{"cobra", "requests", "left-pad", "junit", "serde", "cffi", "express", "unrelated"} {
			if strings.Contains(k, unrelated) {
				t.Errorf("unknown package reported: %s", k)
			}
		}
	}
	if res.FilesScanned != 8 || res.Packages != 25 {
		t.Errorf("FilesScanned = %d, Packages = %d", res.FilesScanned, res.Packages)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Path != "go/go.sum" {
		t.Errorf("Skipped = %+v; go.sum next to go.mod should be skipped", res.Skipped)
	}
}

func TestEvidence(t *testing.T) {
	for _, f := range scanFixtures(t).Findings {
		switch key(f) {
		case "python/requirements.txt pkg:pypi/cryptography@48.0.0 ML-KEM/kem":
			if f.Evidence != "cryptography 48.0.0 provides ML-KEM (since 48.0.0)" || f.Location.Line != 4 {
				t.Errorf("evidence %q line %d", f.Evidence, f.Location.Line)
			}
		case "python/requirements.txt pkg:pypi/pycryptodomex RSA/signature":
			if f.Evidence != "PyCryptodomeX (version not pinned) provides RSA" {
				t.Errorf("evidence %q", f.Evidence)
			}
		}
	}
}

func TestPURL(t *testing.T) {
	tests := []struct {
		d    Dependency
		want string
	}{
		{dep("pypi", "Liboqs_Python", "0.12.0", 0), "pkg:pypi/liboqs-python@0.12.0"},
		{dep("npm", "@noble/post-quantum", "0.2.0", 0), "pkg:npm/%40noble/post-quantum@0.2.0"},
		{dep("maven", "org.bouncycastle:bcprov-jdk18on", "1.79", 0), "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.79"},
		{dep("cargo", "openssl-src", "300.5.3+3.5.4", 0), "pkg:cargo/openssl-src@300.5.3%2B3.5.4"},
		{dep("golang", "github.com/cloudflare/circl", "", 0), "pkg:golang/github.com/cloudflare/circl"},
	}
	for _, tt := range tests {
		if got := PURL(tt.d); got != tt.want {
			t.Errorf("PURL(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestScanCancelled(t *testing.T) {
	db, _ := knowledge.Default()
	libs, _ := knowledge.DefaultLibs()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(db, libs).Scan(ctx, fixtures); err == nil {
		t.Error("expected a cancellation error")
	}
}
