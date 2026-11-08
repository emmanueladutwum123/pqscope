// Package eval scores pqscope and competing scanners against the labeled
// corpus in testdata/corpus, for the paper's RQ1. Every number it writes
// comes from a scan; nothing is typed in.
//
// A tool's findings are reduced to (file, line, algorithm family) and matched
// against the labels at two granularities: "file" (file and family, fair to
// tools that report no line numbers) and "line" (file, line and family).
package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Label is one expected finding.
type Label struct {
	File      string `yaml:"file"`
	Line      int    `yaml:"line"`
	Algorithm string `yaml:"algorithm"`
	Params    string `yaml:"params"`
	Primitive string `yaml:"primitive"`
}

// Case is one corpus item.
type Case struct {
	ID       string // group/name, such as "go/g01-rsa-keygen"
	Dir      string
	Layer    string // source, config, deps, binary or network
	Language string // for source cases; "-" otherwise
	Kind     string // positive, hard-positive or hard-negative
	Expect   []Label
}

// sourceLanguages are the corpus groups that hold source cases.
var sourceLanguages = []string{"go", "python", "java", "c", "js"}

// layerGroups are the corpus groups that hold one layer each.
var layerGroups = []string{"config", "deps", "binary", "network"}

// LoadCorpus reads every case under dir.
func LoadCorpus(dir string) ([]Case, error) {
	var out []Case
	for _, group := range append(slices.Clone(sourceLanguages), layerGroups...) {
		dirs, err := filepath.Glob(filepath.Join(dir, group, "*", "labels.yaml"))
		if err != nil {
			return nil, err
		}
		for _, lp := range dirs {
			data, err := os.ReadFile(lp)
			if err != nil {
				return nil, err
			}
			var doc struct {
				Layer       string  `yaml:"layer"`
				Kind        string  `yaml:"kind"`
				Description string  `yaml:"description"`
				Expect      []Label `yaml:"expect"`
			}
			if err := yaml.Unmarshal(data, &doc); err != nil {
				return nil, fmt.Errorf("%s: %w", lp, err)
			}
			c := Case{
				ID:     group + "/" + filepath.Base(filepath.Dir(lp)),
				Dir:    filepath.Dir(lp),
				Layer:  doc.Layer,
				Kind:   doc.Kind,
				Expect: doc.Expect,
			}
			if slices.Contains(sourceLanguages, group) {
				c.Layer, c.Language = "source", group
			} else {
				c.Language = "-"
				if c.Layer == "" {
					c.Layer = group
				}
			}
			switch c.Kind {
			case "positive", "hard-positive", "hard-negative":
			default:
				return nil, fmt.Errorf("%s: unknown kind %q", lp, c.Kind)
			}
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("eval: no corpus cases under %s", dir)
	}
	return out, nil
}

// pqFamilies are the families scored for dependency cases: the deps layer's
// contribution is post-quantum capability.
var pqFamilies = []string{"ML-KEM", "ML-DSA", "SLH-DSA", "Hybrid", "sntrup761"}

// keywordFamilies maps substrings of tool-reported names to families, in
// order: the first match wins, so specific names come before general ones.
var keywordFamilies = []struct {
	keys   []string
	family string
}{
	{[]string{"x25519mlkem768", "mlkem768x25519", "secp256r1mlkem768", "secp384r1mlkem1024", "sntrup761x25519", "hybrid"}, "Hybrid"},
	{[]string{"ml-kem", "mlkem", "ml_kem", "kyber"}, "ML-KEM"},
	{[]string{"ml-dsa", "mldsa", "ml_dsa", "dilithium"}, "ML-DSA"},
	{[]string{"slh-dsa", "slhdsa", "slh_dsa", "sphincs"}, "SLH-DSA"},
	{[]string{"hmac"}, "HMAC"},
	{[]string{"x25519", "curve25519"}, "X25519"},
	{[]string{"x448", "curve448"}, "X448"},
	{[]string{"ed25519", "ed448", "eddsa"}, "EdDSA"},
	{[]string{"ecdsa"}, "ECDSA"},
	{[]string{"ecdh"}, "ECDH"},
	{[]string{"rsa"}, "RSA"},
	{[]string{"dsa"}, "DSA"},
	{[]string{"diffie", "ffdh", "dhe-", "_dh_", "modp"}, "DH"},
	{[]string{"3des", "desede", "tripledes", "triple-des", "triple_des", "des-ede3", "des3"}, "3DES"},
	{[]string{"rc4", "arcfour"}, "RC4"},
	{[]string{"chacha"}, "ChaCha20-Poly1305"},
	{[]string{"aes"}, "AES"},
	{[]string{"md5"}, "MD5"},
	{[]string{"sha-1", "sha1"}, "SHA-1"},
	{[]string{"sha3", "sha-3"}, "SHA-3"},
	{[]string{"sha-2", "sha2", "sha256", "sha-256", "sha384", "sha-384", "sha512", "sha-512", "sha224", "sha-224"}, "SHA-2"},
	{[]string{"des"}, "DES"},
}

// Family maps a tool-reported algorithm name to a family, or "".
func Family(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	// JCA's "EC" key algorithm, alone or with a curve ("EC-secp384r1"), is
	// an EC key; the corpus labels EC key generation as ECDSA.
	if s == "ec" || strings.HasPrefix(s, "ec-") {
		return "ECDSA"
	}
	// A generic "ECC" (pqc-audit) is mapped the same way. It undercounts the
	// tool on lines labeled ECDH; rq1_items.csv shows each such item.
	if s == "ecc" || strings.HasPrefix(s, "ecc-") || strings.HasPrefix(s, "ecc ") {
		return "ECDSA"
	}
	for _, kf := range keywordFamilies {
		for _, k := range kf.keys {
			if strings.Contains(s, k) {
				return kf.family
			}
		}
	}
	return ""
}
