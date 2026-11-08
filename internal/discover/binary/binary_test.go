package binary

import (
	"context"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/rules"
)

const fixtures = "../../../testdata/binaries"

func scanner(t *testing.T) *Scanner {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	libs, err := knowledge.DefaultLibs()
	if err != nil {
		t.Fatal(err)
	}
	src, err := source.New(db, rules.FS)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(db, libs, src.SymbolAssets("go"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// key summarises a finding as "path layer symbol name/primitive".
func key(f model.Finding) string {
	name := f.Asset.Algorithm
	if f.Asset.Params != model.ParamsUnknown {
		name += " " + f.Asset.Params
	}
	return f.Location.Path + " " + string(f.Location.Layer) + " " + f.Location.Symbol + " " + name + "/" + f.Asset.Primitive
}

func check(t *testing.T, findings []model.Finding, has, hasNot []string) {
	t.Helper()
	var got []string
	for _, f := range findings {
		got = append(got, key(f))
		if err := f.Validate(); err != nil {
			t.Errorf("%s: %v", key(f), err)
		}
	}
	for _, h := range has {
		if !slices.Contains(got, h) {
			t.Errorf("missing %q", h)
		}
	}
	for _, h := range hasNot {
		for _, g := range got {
			if strings.Contains(g, h) {
				t.Errorf("unexpected %q", g)
			}
		}
	}
	if t.Failed() {
		t.Logf("got:\n%s", strings.Join(got, "\n"))
	}
}

// The milestone 7 acceptance test: crypto imports in ELF, PE and Mach-O,
// built from testdata/binaries/src by build.sh.
func TestImportsInEachFormat(t *testing.T) {
	res, err := scanner(t).Scan(context.Background(), fixtures)
	if err != nil {
		t.Fatal(err)
	}
	var has []string
	for _, bin := range []string{"crypto-elf", "crypto.exe", "crypto-macho"} {
		has = append(has,
			bin+" binary import:RSA_generate_key_ex RSA/signature",
			bin+" binary import:ECDSA_sign ECDSA/signature",
			bin+" binary import:EVP_sha256 SHA-2 SHA-256/hash",
			bin+" binary import:EVP_aes_256_gcm AES 256/cipher",
			bin+" binary import:EVP_md5 MD5 MD5/hash",
		)
	}
	has = append(has,
		"constants-elf-stripped binary constant:P-256 field prime ECDSA P-256/signature",
		"constants-elf-stripped binary constant:ML-KEM-768 OID ML-KEM ML-KEM-768/kem",
	)
	// Binaries with recognised imports do not fall back to constants.
	check(t, res.Findings, has, []string{"crypto-elf binary constant:", "crypto.exe binary constant:", "crypto-macho binary constant:"})
	if res.FilesScanned != 6 {
		t.Errorf("FilesScanned = %d, want the 6 binaries", res.FilesScanned)
	}
	check(t, res.Findings, []string{
		"sodium-elf binary import:crypto_box_keypair X25519 X25519/key-agreement",
		"sodium-elf binary import:crypto_sign_detached EdDSA Ed25519/signature",
	}, []string{"hello-elf "})

	evidence := map[string]string{}
	for _, f := range res.Findings {
		if f.Location.Symbol == "import:RSA_generate_key_ex" {
			evidence[f.Location.Path] = f.Evidence
			if f.Confidence != ImportConfidence {
				t.Errorf("%s: confidence %v", f.Location.Path, f.Confidence)
			}
		}
	}
	for bin, want := range map[string]string{
		"crypto-elf":   "ELF binary imports RSA_generate_key_ex, RSA_new (links ",
		"crypto.exe":   "PE binary imports RSA_generate_key_ex, RSA_new (links KERNEL32.dll, libcrypto-3-x64.dll, msvcrt.dll)",
		"crypto-macho": "Mach-O binary imports RSA_generate_key_ex, RSA_new (links ",
	} {
		if !strings.HasPrefix(evidence[bin], want) {
			t.Errorf("%s evidence = %q, want prefix %q", bin, evidence[bin], want)
		}
	}
	if !strings.Contains(evidence["crypto-elf"], "libcrypto.so.3") || !strings.Contains(evidence["crypto-macho"], "libcrypto.3.dylib") {
		t.Errorf("linked libraries missing: %v", evidence)
	}
	for _, bin := range []string{"crypto-elf", "crypto.exe", "crypto-macho"} {
		if !slices.ContainsFunc(res.Notes, func(n string) bool {
			return strings.HasPrefix(n, bin+": ") && strings.Contains(n, "EVP_PKEY_encapsulate")
		}) {
			t.Errorf("%s: generic EVP_PKEY_encapsulate import not noted: %v", bin, res.Notes)
		}
	}
}

// buildGo cross-compiles the Go fixture.
func buildGo(t *testing.T, goos, goarch string, strip bool) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "gofixture-"+goos)
	args := []string{"build", "-trimpath", "-o", out}
	if strip {
		args = append(args, "-ldflags=-s -w")
	}
	cmd := exec.Command("go", append(args, filepath.Join(fixtures, "gofixture"))...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s/%s: %v\n%s", goos, goarch, err, b)
	}
	return out
}

// The milestone 7 acceptance test, part 2: Go build info, and the crypto
// functions a Go binary links, in every format, stripped or not.
func TestGoBinaries(t *testing.T) {
	s := scanner(t)
	for _, tt := range []struct{ goos, goarch, format string }{
		{"linux", "amd64", "elf"}, {"windows", "amd64", "pe"}, {"darwin", "arm64", "macho"},
	} {
		for _, strip := range []bool{false, true} {
			name := tt.goos
			if strip {
				name += "-stripped"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				bin := buildGo(t, tt.goos, tt.goarch, strip)
				format, err := detect(bin)
				if err != nil || format != tt.format {
					t.Fatalf("detect = %q, %v", format, err)
				}
				findings, _, err := s.ScanFile(bin, "app", format)
				if err != nil {
					t.Fatal(err)
				}
				check(t, findings, []string{
					// Function table: the crypto the linker kept.
					// Exact public functions, which can carry params...
					"app binary go:crypto/rsa.GenerateKey RSA/signature",
					"app binary go:crypto/mlkem.GenerateKey768 ML-KEM ML-KEM-768/kem",
					"app binary go:crypto/sha256.New SHA-2 SHA-256/hash", // also Sum256; the first name labels the finding
					// ...and packages, for functions the compiler inlined away
					// (ecdh.X25519, mldsa65.GenerateKey).
					"app binary go-package:crypto/internal/fips140/mlkem ML-KEM/kem",
					"app binary go-package:crypto/internal/fips140/rsa RSA/signature",
					"app binary go-package:github.com/cloudflare/circl/sign/mldsa/mldsa65 ML-DSA ML-DSA-65/signature",
					// Build info: module versions as dependency capabilities.
					"app deps pkg:golang/github.com/cloudflare/circl@v1.6.5 ML-DSA/signature",
					"app deps pkg:golang/stdlib@" + strings.TrimPrefix(goVersion(t), "go") + " Hybrid X25519MLKEM768/kem",
				}, []string{" binary constant:"})
				for _, f := range findings {
					if f.Location.Layer == model.LayerDeps && !strings.HasPrefix(f.Evidence, "Go build info (go") {
						t.Errorf("build-info evidence = %q", f.Evidence)
					}
				}
			})
		}
	}
}

func goVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOVERSION").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// The constants table is checked against values computed from the standards,
// not trusted as typed.
func TestConstantsMatchStandards(t *testing.T) {
	be := func(n *big.Int, size int) string { return hex.EncodeToString(n.FillBytes(make([]byte, size))) }
	der := func(oid asn1.ObjectIdentifier) string {
		b, err := asn1.Marshal(oid)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b)
	}
	p25519 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// Ed25519 d = -121665/121666 mod p (RFC 8032, 5.1).
	d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p25519))
	d.Mod(d, p25519)
	// SHA-256 H(0): the first 32 bits of the fractional parts of the square
	// roots of the first eight primes (FIPS 180-4, 5.3.3).
	var h0 strings.Builder
	for _, p := range []float64{2, 3, 5, 7, 11, 13, 17, 19} {
		r := math.Sqrt(p)
		h0.WriteString(hex.EncodeToString(big.NewInt(int64((r - math.Floor(r)) * (1 << 32))).FillBytes(make([]byte, 4))))
	}
	want := map[string]string{
		"P-256 field prime":          be(elliptic.P256().Params().P, 32),
		"Curve25519 prime 2^255-19":  be(p25519, 32),
		"Ed25519 constant d":         be(d, 32),
		"SHA-256 initial hash value": h0.String(),
		"rsaEncryption OID":          der(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}),
		"secp256r1 OID":              der(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}),
		"ML-KEM-512 OID":             der(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}),
		"ML-KEM-768 OID":             der(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}),
		"ML-KEM-1024 OID":            der(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}),
		"ML-DSA-44 OID":              der(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}),
		"ML-DSA-65 OID":              der(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}),
		"ML-DSA-87 OID":              der(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}),
	}
	tab := scanner(t).table
	if len(tab.constants) != len(want) {
		t.Errorf("%d constants, want %d", len(tab.constants), len(want))
	}
	for _, c := range tab.constants {
		if got := hex.EncodeToString(c.patterns[0]); got != want[c.name] {
			t.Errorf("%s = %s, computed %s", c.name, got, want[c.name])
		}
	}
}

func TestDetect(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string][]byte{
		"Main.class": {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x41, 0, 0},
		"fat":        {0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02, 0, 0},
		"short":      {0x7f, 'E'},
		"text":       []byte("#!/bin/sh\necho hi\n"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]string{"Main.class": "", "fat": "fat", "short": "", "text": ""} {
		if got, err := detect(filepath.Join(dir, name)); err != nil || got != want {
			t.Errorf("detect(%s) = %q, %v; want %q", name, got, err, want)
		}
	}
	// A truncated universal header is reported as skipped, not a crash.
	res, err := scanner(t).Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Path != "fat" || len(res.Findings) != 0 {
		t.Errorf("skipped %+v, findings %d", res.Skipped, len(res.Findings))
	}
}

func TestSymbolNames(t *testing.T) {
	tab := scanner(t).table
	for name, want := range map[string]string{
		"RSA_new":                   "RSA/signature",
		"RSA_public_encrypt":        "RSA/pke",
		"EVP_aes_128_cbc":           "AES 128/cipher",
		"EVP_des_ede3_cbc":          "3DES 3-key/cipher",
		"crypto_box_easy":           "X25519 X25519/key-agreement",
		"crypto_sign_ed25519_open":  "EdDSA Ed25519/signature",
		"OQS_KEM_ml_kem_768_encaps": "ML-KEM ML-KEM-768/kem",
		"ossl_ml_dsa_sig_encode":    "ML-DSA/signature",
		"X25519_keypair":            "X25519 X25519/key-agreement",
		"EVP_PKEY_encapsulate":      "",
		"printf":                    "",
	} {
		a, ok := tab.lookup(name)
		got := ""
		if ok {
			got = a.Algorithm
			if a.Params != model.ParamsUnknown {
				got += " " + a.Params
			}
			got += "/" + a.Primitive
		}
		if got != want {
			t.Errorf("lookup(%q) = %q, want %q", name, got, want)
		}
	}
	for fn, want := range map[string]string{
		"crypto/internal/fips140/rsa.(*PrivateKey).Sign":                 "crypto/internal/fips140/rsa",
		"github.com/cloudflare/circl/sign/mldsa/mldsa65/internal.Verify": "github.com/cloudflare/circl/sign/mldsa/mldsa65/internal",
		"crypto/sha256.Sum256": "crypto/sha256",
		"main.main":            "main",
	} {
		if got := goPackageOf(fn); got != want {
			t.Errorf("goPackageOf(%q) = %q, want %q", fn, got, want)
		}
	}
	if _, _, ok := tab.lookupGoPackage("crypto/rsax.Foo"); ok {
		t.Error("crypto/rsax must not match crypto/rsa")
	}
	for raw, want := range map[string]string{"_RSA_new": "RSA_new", "RSA_new@OPENSSL_3.0.0": "RSA_new", "RSA_new:libcrypto-3-x64.dll": "RSA_new"} {
		if got := clean(raw, "macho"); got != want {
			t.Errorf("clean(%q) = %q", raw, got)
		}
	}
}

func TestTableRejects(t *testing.T) {
	db, _ := knowledge.Default()
	base := string(symbolsYAML)
	tests := []struct{ name, doc, want string }{
		{"unknown source", strings.Replace(base, "source: openssl-dsa}", "source: nowhere}", 1), "unknown source"},
		{"bad asset", strings.Replace(base, `asset: "DSA:signature"`, `asset: "DSA:sig"`, 1), "bad asset"},
		{"duplicate symbol", strings.Replace(base, "names: [EVP_sha3_512]", "names: [EVP_sha3_256]", 1), "listed twice"},
		{"short constant", strings.Replace(base, `hex: "06092a864886f70d010101"`, `hex: "0609"`, 1), "at least 8 bytes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.doc == base {
				t.Fatal("case did not change the table")
			}
			if _, err := parseTable(db, []byte(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
