package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/rules"
)

func testDB(t *testing.T) *knowledge.DB {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func testScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := New(testDB(t), rules.FS)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func scan(t *testing.T, s *Scanner, name, src string) []model.Finding {
	t.Helper()
	fs, err := s.ScanFile(context.Background(), name, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			t.Errorf("invalid finding %+v: %v", f, err)
		}
	}
	return fs
}

func TestRulePacks(t *testing.T) {
	counts := testScanner(t).RuleCounts()
	total := 0
	for _, n := range counts {
		total += n
	}
	if total < 30 {
		t.Errorf("only %d rules loaded, want at least 30", total)
	}
	for _, lang := range []string{"go", "python"} {
		if counts[lang] == 0 {
			t.Errorf("no %s rules", lang)
		}
	}
}

type want struct {
	line              int
	algorithm, params string
	primitive         string
	confidenceAtMost  float64
}

func TestScanFile(t *testing.T) {
	s := testScanner(t)
	tests := []struct {
		name, file, src string
		want            []want
	}{
		{
			name: "java import and select",
			file: "A.java",
			src:  "import java.security.KeyPairGenerator;\nclass A { void f() throws Exception { KeyPairGenerator.getInstance(\"EC\"); } }\n",
			want: []want{{line: 2, algorithm: "ECDSA", params: "unknown", primitive: "signature"}},
		},
		{
			name: "java select prefix picks the longest match",
			file: "A.java",
			src:  "import javax.crypto.Cipher;\nclass A { void f() throws Exception { Cipher.getInstance(\"AES_256/GCM/NoPadding\"); Cipher.getInstance(\"desede/cbc/pkcs5padding\"); } }\n",
			want: []want{{line: 2, algorithm: "AES", params: "256", primitive: "cipher"}, {line: 2, algorithm: "3DES", params: "3-key", primitive: "cipher"}},
		},
		{
			name: "java class not imported is not resolved",
			file: "A.java",
			src:  "class A { void f() throws Exception { KeyPairGenerator.getInstance(\"RSA\"); } }\n",
		},
		{
			name: "java constructor and named constant",
			file: "A.java",
			src:  "import java.security.spec.*;\nclass A { Object a = new ECGenParameterSpec(\"secp521r1\"); Object b = NamedParameterSpec.ML_KEM_1024; }\n",
			want: []want{{line: 2, algorithm: "ECDSA", params: "P-521", primitive: "signature"}, {line: 2, algorithm: "ML-KEM", params: "ML-KEM-1024", primitive: "kem"}},
		},
		{
			name: "c macro selects the algorithm",
			file: "a.c",
			src:  "void f(void) { EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, 0); }\n",
			want: []want{{line: 1, algorithm: "X25519", params: "X25519", primitive: "key-agreement"}},
		},
		{
			name: "c parameter is not a key size",
			file: "a.c",
			src:  "int f(RSA *r, int bits) { return RSA_generate_key_ex(r, bits, 0, 0); }\n",
			want: []want{{line: 1, algorithm: "RSA", params: "unknown", primitive: "signature", confidenceAtMost: 0.95 * UnresolvedParamsFactor}},
		},
		{
			name: "c #if 0 and if (0) are dead",
			file: "a.c",
			src:  "void f(void) {\n#if 0\nMD5(0, 0, 0);\n#else\nSHA1(0, 0, 0);\n#endif\nif (0) { EVP_md5(); }\n}\n",
			want: []want{{line: 5, algorithm: "SHA-1", params: "SHA-1", primitive: "hash"}},
		},
		{
			name: "c++ grammar for .cpp",
			file: "a.cpp",
			src:  "auto f() { return EVP_sha512(); }\n",
			want: []want{{line: 1, algorithm: "SHA-2", params: "SHA-512", primitive: "hash"}},
		},
		{
			name: "js require with property access",
			file: "a.js",
			src:  "const h = require('crypto').createHash('sha384');\n",
			want: []want{{line: 1, algorithm: "SHA-2", params: "SHA-384", primitive: "hash"}},
		},
		{
			name: "js select params from the options object",
			file: "a.mjs",
			src:  "import { generateKeyPairSync as g } from 'node:crypto';\nconst opts = { namedCurve: 'secp384r1' };\ng('ec', opts);\ng('rsa', { namedCurve: 'P-256' });\n",
			want: []want{{line: 3, algorithm: "ECDSA", params: "P-384", primitive: "signature"}, {line: 4, algorithm: "RSA", params: "unknown", primitive: "signature"}},
		},
		{
			name: "js shadowed crypto is not WebCrypto",
			file: "a.js",
			src:  "const crypto = makeCrypto();\ncrypto.subtle.generateKey({ name: 'ECDSA' }, true, []);\n",
		},
		{
			name: "ts grammar for .ts",
			file: "a.ts",
			src:  "import * as c from 'crypto';\nconst x: string = 'md5';\nc.createHash(x);\n",
			want: []want{{line: 3, algorithm: "MD5", params: "MD5", primitive: "hash"}},
		},
		{
			name: "go aliased import",
			file: "a.go",
			src:  "package p\nimport r \"crypto/rsa\"\nfunc f() { r.GenerateKey(nil, 2048) }\n",
			want: []want{{line: 3, algorithm: "RSA", params: "2048", primitive: "signature"}},
		},
		{
			name: "go unrelated package with the same name",
			file: "a.go",
			src:  "package p\nimport \"example.com/rsa\"\nfunc f() { rsa.GenerateKey(nil, 2048) }\n",
		},
		{
			name: "go package name without an import",
			file: "a.go",
			src:  "package p\nfunc f() { rsa.GenerateKey(nil, 2048) }\n",
		},
		{
			name: "go constant key size",
			file: "a.go",
			src:  "package p\nimport \"crypto/rsa\"\nconst n = 3072\nfunc f() { rsa.GenerateKey(nil, n) }\n",
			want: []want{{line: 4, algorithm: "RSA", params: "3072", primitive: "signature"}},
		},
		{
			name: "go ambiguous variable stays unknown with lower confidence",
			file: "a.go",
			src:  "package p\nimport \"crypto/rsa\"\nfunc f(b bool) { n := 2048; if b { n = 4096 }; rsa.GenerateKey(nil, n) }\n",
			want: []want{{line: 3, algorithm: "RSA", params: "unknown", primitive: "signature", confidenceAtMost: 0.95 * UnresolvedParamsFactor}},
		},
		{
			name: "go curve through params_map",
			file: "a.go",
			src:  "package p\nimport (\n\"crypto/ecdsa\"\n\"crypto/elliptic\"\n)\nfunc f() { ecdsa.GenerateKey(elliptic.P384(), nil) }\n",
			want: []want{{line: 6, algorithm: "ECDSA", params: "P-384", primitive: "signature"}},
		},
		{
			name: "go dead code",
			file: "a.go",
			src:  "package p\nimport \"crypto/md5\"\nfunc f() { if false { md5.Sum(nil) } }\n",
		},
		{
			name: "go else branch of if false is live",
			file: "a.go",
			src:  "package p\nimport \"crypto/md5\"\nfunc f() { if false { } else { md5.Sum(nil) } }\n",
			want: []want{{line: 3, algorithm: "MD5", params: "MD5", primitive: "hash"}},
		},
		{
			name: "go comments and strings",
			file: "a.go",
			src:  "package p\nimport \"crypto/md5\"\n// md5.Sum(x)\nvar s = \"md5.Sum\"\nvar _ = md5.BlockSize\n",
		},
		{
			name: "go duplicate reference on one line is reported once",
			file: "a.go",
			src:  "package p\nimport \"crypto/md5\"\nfunc f() { md5.Sum(nil); md5.Sum(nil) }\n",
			want: []want{{line: 3, algorithm: "MD5", params: "MD5", primitive: "hash"}},
		},
		{
			name: "python from-import alias with kwarg",
			file: "a.py",
			src:  "from cryptography.hazmat.primitives.asymmetric import rsa as R\nR.generate_private_key(public_exponent=65537, key_size=4096)\n",
			want: []want{{line: 2, algorithm: "RSA", params: "4096", primitive: "signature"}},
		},
		{
			name: "python positional fallback",
			file: "a.py",
			src:  "from cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(65537, 3072)\n",
			want: []want{{line: 2, algorithm: "RSA", params: "3072", primitive: "signature"}},
		},
		{
			name: "python select resolves the algorithm",
			file: "a.py",
			src:  "import hashlib\nhashlib.new('SHA1')\n",
			want: []want{{line: 2, algorithm: "SHA-1", params: "SHA-1", primitive: "hash"}},
		},
		{
			name: "python select with unresolvable name reports nothing",
			file: "a.py",
			src:  "import hashlib\ndef f(name):\n    hashlib.new(name)\n",
		},
		{
			name: "python f-string is not a literal",
			file: "a.py",
			src:  "import hashlib\nhashlib.new(f'sha{1}')\n",
		},
		{
			name: "python local function shadows nothing without an import",
			file: "a.py",
			src:  "def md5(x):\n    return x\nmd5(1)\n",
		},
		{
			name: "python dead code with if 0",
			file: "a.py",
			src:  "import hashlib\nif 0:\n    hashlib.md5()\n",
		},
		{
			name: "python raw query rule",
			file: "a.py",
			src:  "import ssl\nctx = ssl.create_default_context()\nctx.set_ecdh_curve('secp384r1')\n",
			want: []want{{line: 3, algorithm: "ECDH", params: "P-384", primitive: "key-agreement"}},
		},
		{
			name: "unsupported extension",
			file: "a.rb",
			src:  "OpenSSL::PKey::RSA.new(1024)\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scan(t, s, tt.file, tt.src)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings, want %d: %+v", len(got), len(tt.want), got)
			}
			for i, w := range tt.want {
				g := got[i]
				if g.Location.Line != w.line || g.Asset.Algorithm != w.algorithm || g.Asset.Params != w.params || g.Asset.Primitive != w.primitive {
					t.Errorf("finding %d = line %d %s %s %s, want line %d %s %s %s", i,
						g.Location.Line, g.Asset.Algorithm, g.Asset.Params, g.Asset.Primitive,
						w.line, w.algorithm, w.params, w.primitive)
				}
				if w.confidenceAtMost > 0 && g.Confidence > w.confidenceAtMost+1e-9 {
					t.Errorf("confidence %v, want at most %v", g.Confidence, w.confidenceAtMost)
				}
				if g.Location.Layer != model.LayerSource || g.RuleID == "" || g.Evidence == "" {
					t.Errorf("incomplete finding %+v", g)
				}
			}
		})
	}
}

func TestFindingsCarryKnowledge(t *testing.T) {
	got := scan(t, testScanner(t), "a.go", "package p\nimport \"crypto/mlkem\"\nfunc f() { mlkem.GenerateKey768() }\n")
	if len(got) != 1 {
		t.Fatalf("got %d findings", len(got))
	}
	a := got[0].Asset
	if a.Quantum != model.QuantumSafe || a.ClassicalBits != 192 {
		t.Errorf("asset %+v not filled from the knowledge DB", a)
	}
}

func TestScanDirectory(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package p\nimport \"crypto/sha1\"\nvar _ = sha1.Sum\n")
	write("sub/b.py", "import hashlib\nhashlib.md5()\n")
	write("node_modules/c.py", "import hashlib\nhashlib.md5()\n")
	write("broken.py", "import hashlib\nhashlib.md5(\n")
	write("big.py", "#"+strings.Repeat("x", MaxFileSize))
	write("README.md", "hashlib.md5()")

	res, err := testScanner(t).Scan(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range res.Findings {
		paths = append(paths, f.Location.Path)
	}
	if got, want := strings.Join(paths, ","), "a.go,broken.py,sub/b.py"; got != want {
		t.Errorf("finding paths = %s, want %s", got, want)
	}
	if res.FilesScanned != 3 {
		t.Errorf("FilesScanned = %d, want 3", res.FilesScanned)
	}
	if len(res.SyntaxErrors) != 1 || res.SyntaxErrors[0] != "broken.py" {
		t.Errorf("SyntaxErrors = %v", res.SyntaxErrors)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Path != "big.py" {
		t.Errorf("Skipped = %v", res.Skipped)
	}

	single, err := testScanner(t).Scan(context.Background(), filepath.Join(root, "a.go"))
	if err != nil || len(single.Findings) != 1 || single.Findings[0].Location.Path != "a.go" {
		t.Errorf("single-file scan = %+v, %v", single, err)
	}
}

func TestScanCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testScanner(t).Scan(ctx, t.TempDir()); err == nil {
		t.Error("expected a context error")
	}
}

func TestRuleValidation(t *testing.T) {
	const header = "version: 1\nlang: go\nrules:\n"
	const ok = "    asset: {primitive: hash, algorithm: MD5, params: MD5}\n    confidence: 0.9\n    source: https://example.org\n"
	tests := []struct {
		name, pack, wantErr string
	}{
		{"valid", "  - id: a\n    ref: crypto/md5.Sum\n" + ok, ""},
		{"no source", "  - id: a\n    ref: crypto/md5.Sum\n    asset: {primitive: hash, algorithm: MD5, params: MD5}\n    confidence: 0.9\n", "source"},
		{"unknown algorithm", "  - id: a\n    ref: x.Y\n    asset: {primitive: hash, algorithm: NOPE}\n    confidence: 0.9\n    source: https://example.org\n", "not a uniform family"},
		{"params not in DB", "  - id: a\n    ref: x.Y\n    asset: {primitive: hash, algorithm: MD5, params: MD6}\n    confidence: 0.9\n    source: https://example.org\n", "not in the knowledge DB"},
		{"wrong primitive", "  - id: a\n    ref: x.Y\n    asset: {primitive: kem, algorithm: MD5, params: MD5}\n    confidence: 0.9\n    source: https://example.org\n", "not used as kem"},
		{"two kinds", "  - id: a\n    ref: x.Y\n    call: x.Z\n" + ok, "exactly one"},
		{"duplicate symbol", "  - id: a\n    ref: x.Y\n" + ok + "  - id: b\n    ref: x.Y\n" + ok, "claimed"},
		{"duplicate id", "  - id: a\n    ref: x.Y\n" + ok + "  - id: a\n    ref: x.Z\n" + ok, "duplicate rule id"},
		{"bad extractor", "  - id: a\n    call: x.Y\n    params_from: arg(1)\n" + ok, "invalid params_from"},
		{"params_from on ref", "  - id: a\n    ref: x.Y\n    params_from: arg[0]\n    asset: {primitive: hash, algorithm: MD5}\n    confidence: 0.9\n    source: https://example.org\n", "no arguments"},
		{"bad query", "  - id: a\n    query: (nope\n" + ok, "query"},
		{"confidence", "  - id: a\n    ref: x.Y\n    asset: {primitive: hash, algorithm: MD5, params: MD5}\n    confidence: 1.5\n    source: https://example.org\n", "confidence"},
		{"unknown field", "  - id: a\n    ref: x.Y\n    bogus: 1\n" + ok, "bogus"},
		{"select_params_from without select", "  - id: a\n    call: x.Y\n    select_params_from: arg[1]\n" + ok, "requires select"},
		{"bad property extractor", "  - id: a\n    call: x.Y\n    params_from: arg[0].a.b\n" + ok, "invalid params_from"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{"go.yaml": {Data: []byte(header + tt.pack)}}
			_, err := New(testDB(t), fsys)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestGoDefaultName(t *testing.T) {
	tests := map[string]string{
		"crypto/rsa":                     "rsa",
		"crypto":                         "crypto",
		"github.com/x/y/v2":              "y",
		"gopkg.in/yaml.v3":               "yaml",
		"golang.org/x/crypto/curve25519": "curve25519",
	}
	for path, want := range tests {
		if got := goDefaultName(path); got != want {
			t.Errorf("goDefaultName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestRules(t *testing.T) {
	s := testScanner(t)
	rules := s.Rules()
	total := 0
	for _, n := range s.RuleCounts() {
		total += n
	}
	if len(rules) != total {
		t.Fatalf("Rules() returned %d rules, RuleCounts() says %d", len(rules), total)
	}
	byID := map[string]RuleInfo{}
	for _, r := range rules {
		if r.Description == "" || !strings.HasPrefix(r.Source, "https://") {
			t.Errorf("%s: missing description or source: %+v", r.ID, r)
		}
		byID[r.ID] = r
	}
	for id, want := range map[string]string{
		"go.rsa.generate":       "RSA (signature) via crypto/rsa.GenerateKey",
		"py.hashlib.new":        "Algorithm selected by the argument to hashlib.new",
		"py.ssl.set-ecdh-curve": "matched by a tree-sitter query",
	} {
		if got := byID[id].Description; !strings.Contains(got, want) {
			t.Errorf("%s: description = %q, want it to contain %q", id, got, want)
		}
	}
}

// TypeScript's import-require has no source field; scanning it once crashed
// the whole scan (found scanning facebook/react for RQ3).
func TestTSImportRequire(t *testing.T) {
	s := testScanner(t)
	scan(t, s, "a.ts", "import c = require(\"crypto\");\nc.createHash(\"md5\");\n")
	scan(t, s, "b.ts", "import type { X } from './x';\nimport './side-effect';\nexport = c;\n")
}
