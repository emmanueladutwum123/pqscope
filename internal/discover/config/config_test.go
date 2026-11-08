package config

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/testkeys"
)

const fixtures = "../../../testdata/config"

func scanner(t *testing.T) *Scanner {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func scanDir(t *testing.T, dir string) Result {
	t.Helper()
	res, err := scanner(t).Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Errorf("%s:%d: %v", f.Location.Path, f.Location.Line, err)
		}
		if f.Location.Layer != model.LayerConfig {
			t.Errorf("%s: layer %s", f.Location.Path, f.Location.Layer)
		}
	}
	return res
}

// key summarises a finding as "path:line name/primitive".
func key(f model.Finding) string {
	name := f.Asset.Algorithm
	if f.Asset.Params != model.ParamsUnknown {
		name += " " + f.Asset.Params
	}
	return f.Location.Path + ":" + itoa(f.Location.Line) + " " + name + "/" + f.Asset.Primitive
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func keys(res Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, key(f))
	}
	return out
}

func check(t *testing.T, got []string, has, hasNot []string) {
	t.Helper()
	for _, h := range has {
		if !slices.Contains(got, h) {
			t.Errorf("missing %q", h)
		}
	}
	for _, h := range hasNot {
		if slices.Contains(got, h) {
			t.Errorf("unexpected %q", h)
		}
	}
	if t.Failed() {
		t.Logf("got:\n%s", strings.Join(got, "\n"))
	}
}

// Every listed configuration format parses.
func TestConfigFormats(t *testing.T) {
	res := scanDir(t, fixtures)
	check(t, keys(res), []string{
		// nginx
		"nginx/nginx.conf:7 Hybrid X25519MLKEM768/kem",
		"nginx/nginx.conf:7 X25519 X25519/key-agreement",
		"nginx/nginx.conf:7 ECDH P-256/key-agreement",
		"nginx/nginx.conf:8 ECDH/key-agreement",
		"nginx/nginx.conf:8 ECDSA/signature",
		"nginx/nginx.conf:8 AES 128/cipher",
		"nginx/nginx.conf:8 ChaCha20-Poly1305 ChaCha20-Poly1305/cipher",
		"nginx/nginx.conf:8 RSA/pke", // AES256-SHA: RSA key transport
		"nginx/nginx.conf:8 SHA-1 SHA-1/hash",
		"nginx/nginx.conf:9 AES 256/cipher",
		"nginx/nginx.conf:9 SHA-2 SHA-384/hash",
		// Apache
		"apache/ssl.conf:4 ECDH P-384/key-agreement",
		"apache/ssl.conf:5 3DES 3-key/cipher",
		"apache/ssl.conf:6 AES 128/cipher",
		// sshd_config
		"ssh/sshd_config:4 Hybrid mlkem768x25519-sha256/kem",
		"ssh/sshd_config:4 Hybrid sntrup761x25519-sha512/kem",
		"ssh/sshd_config:4 DH 2048/key-agreement",
		"ssh/sshd_config:4 SHA-1 SHA-1/hash",
		"ssh/sshd_config:5 EdDSA Ed25519/signature",
		"ssh/sshd_config:5 RSA/signature",
		"ssh/sshd_config:5 SHA-2 SHA-512/hash",
		"ssh/sshd_config:6 3DES 3-key/cipher",
		"ssh/sshd_config:7 HMAC SHA-256/mac",
		"ssh/sshd_config:7 HMAC SHA-1/mac",
		// openssl.cnf
		"openssl/openssl.cnf:11 Hybrid X25519MLKEM768/kem",
		"openssl/openssl.cnf:11 Hybrid SecP384r1MLKEM1024/kem",
		"openssl/openssl.cnf:11 X25519 X25519/key-agreement",
		"openssl/openssl.cnf:12 AES 256/cipher",
		"openssl/openssl.cnf:15 RSA 2048/signature",
		"openssl/openssl.cnf:16 SHA-1 SHA-1/hash",
		// Kubernetes
		"k8s/ingress.yaml:7 ECDH P-384/key-agreement",
		"k8s/ingress.yaml:8 AES 128/cipher",
		"k8s/ingress.yaml:15 AES 256/cipher",
		"k8s/ingress.yaml:26 ECDSA P-384/signature",
	}, []string{
		"nginx/nginx.conf:10 ECDH P-384/key-agreement",    // commented out
		"openssl/openssl.cnf:11 ECDH P-521/key-agreement", // "-secp521r1" removes it
		"ssh/sshd_config:8 DSA 1024/signature",            // "-ssh-dss" removes it
	})
	for _, f := range res.Findings {
		if strings.Contains(f.Location.Symbol, "Certificate/default-key") {
			t.Errorf("Certificate without an algorithm should not be reported: %s", key(f))
		}
	}
	if res.FilesScanned != 5 {
		t.Errorf("FilesScanned = %d, want 5", res.FilesScanned)
	}
}

func TestEvidenceIsTheDirective(t *testing.T) {
	for _, f := range scanDir(t, fixtures).Findings {
		if f.Location.Path == "nginx/nginx.conf" && f.Location.Line == 7 && f.Evidence != "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;" {
			t.Errorf("evidence = %q", f.Evidence)
		}
		if f.Location.Path == "ssh/sshd_config" && f.Location.Line == 4 && f.Location.Symbol != "ssh:KexAlgorithms" {
			t.Errorf("symbol = %q", f.Location.Symbol)
		}
	}
}

func TestCipherNames(t *testing.T) {
	s := scanner(t)
	names := func(tok string) []string {
		var out []string
		for _, a := range s.cipher(tok) {
			out = append(out, s.db.Name(a)+"/"+a.Primitive)
		}
		return out
	}
	tests := map[string][]string{
		"ECDHE-RSA-AES128-GCM-SHA256":   {"ECDH/key-agreement", "RSA/signature", "AES-128/cipher", "SHA-256/hash"},
		"ECDHE-ECDSA-CHACHA20-POLY1305": {"ECDH/key-agreement", "ECDSA/signature", "ChaCha20-Poly1305/cipher"},
		"DHE-RSA-AES256-GCM-SHA384":     {"DH/key-agreement", "RSA/signature", "AES-256/cipher", "SHA-384/hash"},
		"AES128-SHA":                    {"RSA/pke", "AES-128/cipher", "SHA-1/hash"},
		"DES-CBC3-SHA":                  {"RSA/pke", "3DES/cipher", "SHA-1/hash"},
		"RC4-MD5":                       {"RSA/pke", "RC4/cipher", "MD5/hash"},
		"TLS_AES_256_GCM_SHA384":        {"AES-256/cipher", "SHA-384/hash"},
		"HIGH":                          nil,
		"!aNULL":                        nil,
		"ECDHE+AESGCM":                  nil,
		"PSK-AES128-CBC-SHA":            nil,
		"RSA-PSK-AES128-GCM-SHA256":     nil,
		"ECDHE-RSA-AES128-GCM-SHA256-X": nil,
	}
	for tok, want := range tests {
		if got := names(tok); !slices.Equal(got, want) {
			t.Errorf("cipher(%q) = %v, want %v", tok, got, want)
		}
	}
}

// Generated key material: one file per kind.
func TestKeyMaterial(t *testing.T) {
	set, err := testkeys.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	res := scanDir(t, set.Dir)
	check(t, keys(res), []string{
		"rsa2048-pkcs1.key:1 RSA 2048/signature",
		"rsa2048-pkcs8.pem:1 RSA 2048/signature",
		"rsa2048-public.pem:1 RSA 2048/signature",
		"rsa-encrypted.key:1 RSA/signature",
		"ecdsa-p384-sec1.key:1 ECDSA P-384/signature",
		"ed25519-pkcs8.pem:1 EdDSA Ed25519/signature",
		"x25519-pkcs8.pem:1 X25519 X25519/key-agreement",
		"id_ed25519:1 EdDSA Ed25519/signature",
		"id_rsa:1 RSA 3072/signature", // passphrase-protected: public half in the clear
		"authorized_keys:2 RSA 3072/signature",
		"mldsa65-pkcs8.pem:1 ML-DSA ML-DSA-65/signature",
		"mlkem768-public.pem:1 ML-KEM ML-KEM-768/kem",
		"ca-ecdsa-p256-selfsigned.crt:1 ECDSA P-256/signature", // subject key, and the self-signature
		"ca-ecdsa-p256-selfsigned.crt:1 SHA-2 SHA-256/hash",
		"leaf-rsa3072.crt:1 RSA 3072/signature",
		"leaf-rsa3072.crt:1 ECDSA/signature", // issuer's key size is not in the leaf
		"leaf-rsa3072.der:1 RSA 3072/signature",
		"ed25519.csr:1 EdDSA Ed25519/signature",
		"mldsa65-selfsigned.crt:1 ML-DSA ML-DSA-65/signature",
		"dhparam2048.pem:1 DH 2048/key-agreement",
		"notes.env:3 EdDSA Ed25519/signature",
		"secret.yaml:7 RSA 3072/signature",
		"secret.yaml:7 ECDSA/signature",
		"secret.yaml:8 RSA 3072/signature",
	}, nil)

	// The self-signed CA's signature is attributed to its own P-256 key, not
	// an unknown ECDSA key.
	for _, f := range res.Findings {
		if f.Location.Path == "ca-ecdsa-p256-selfsigned.crt" && f.Location.Symbol == "x509:signature" && f.Asset.Params != "P-256" {
			t.Errorf("self-signed signature params = %q", f.Asset.Params)
		}
	}
	if !slices.ContainsFunc(res.Notes, func(n string) bool {
		return strings.HasPrefix(n, "encrypted-pkcs8.pem: line 1: encrypted PKCS#8")
	}) {
		t.Errorf("notes = %v", res.Notes)
	}
	for _, f := range res.Findings {
		if f.Confidence != MaterialConfidence || f.Evidence == "" {
			t.Errorf("%s: confidence %v evidence %q", key(f), f.Confidence, f.Evidence)
		}
	}
}

// No finding may carry private key material, in any field.
func TestNoPrivateKeyBytesInFindings(t *testing.T) {
	set, err := testkeys.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	res := scanDir(t, set.Dir)
	if len(set.Secrets) < 30 {
		t.Fatalf("only %d secrets recorded", len(set.Secrets))
	}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range set.Secrets {
		if strings.Contains(string(out), secret) {
			t.Errorf("private key material in findings: %.40s…", secret)
		}
	}
	if strings.Contains(string(out), "PRIVATE KEY-----") {
		t.Error("findings contain a PEM private key header")
	}
}

func TestClassify(t *testing.T) {
	tests := map[string]fileKind{
		"etc/nginx/nginx.conf":               kindServerConf,
		"etc/nginx/sites-enabled/default":    kindServerConf,
		"etc/ssh/sshd_config":                kindSSHConf,
		"etc/ssh/sshd_config.d/50-pqc.conf":  kindSSHConf,
		"etc/ssl/openssl.cnf":                kindOpenSSLConf,
		"deploy/ingress.yml":                 kindKubernetes,
		"certs/server.crt":                   kindKeyMaterial,
		"keys/ssh_host_ed25519_key":          kindKeyMaterial,
		"keys/ssh_host_ed25519_key.pub":      kindKeyMaterial,
		"main.go":                            kindNone,
		"README.md":                          kindNone,
		"go.sum":                             kindNone,
		"config/app.env":                     kindSniff,
		"testdata/corpus/go/g01/labels.yaml": kindKubernetes,
	}
	for rel, want := range tests {
		if got := classify(rel); got != want {
			t.Errorf("classify(%q) = %d, want %d", rel, got, want)
		}
	}
}

func TestNamesRejects(t *testing.T) {
	db, _ := knowledge.Default()
	base := string(namesYAML)
	tests := []struct{ name, doc, want string }{
		{"unknown entry", strings.Replace(base, "x448: [X448:key-agreement]", "x448: [X449:key-agreement]", 1), `"X449" is not`},
		{"bad primitive", strings.Replace(base, "x448: [X448:key-agreement]", "x448: [X448:kex]", 1), "bad asset"},
		{"duplicate name", strings.Replace(base, "      P-256: [ECDH-P256:key-agreement]\n", "      P-256: [ECDH-P256:key-agreement]\n      p-256: [ECDH-P256:key-agreement]\n", 1), "listed twice"},
		{"unknown source", strings.Replace(base, "sources: [rfc8446, openssl-ciphers]", "sources: [rfc9999]", 1), "unknown source"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.doc == base {
				t.Fatal("case did not change the tables")
			}
			if _, err := parseNames(db, []byte(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
