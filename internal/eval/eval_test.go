package eval

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const corpusDir = "../../testdata/corpus"

func TestFamily(t *testing.T) {
	for name, want := range map[string]string{
		"RSA-2048": "RSA", "SHA256withRSA": "RSA", "ECDSA": "ECDSA", "ecdh-sha2-nistp256": "ECDH",
		"X25519MLKEM768": "Hybrid", "mlkem768x25519-sha256": "Hybrid", "ML-KEM-768": "ML-KEM", "kyber768": "ML-KEM",
		"ML-DSA-65": "ML-DSA", "SLH-DSA-SHA2-128s": "SLH-DSA", "Ed25519": "EdDSA", "x25519": "X25519",
		"DSA": "DSA", "DH": "", "diffie-hellman": "DH", "DESede": "3DES", "des-is-deprecated": "DES",
		"use-of-md5": "MD5", "use-of-sha1": "SHA-1", "SHA-256": "SHA-2", "sha3-256": "SHA-3",
		"HmacSHA256": "HMAC", "AES-256-GCM": "AES", "use-of-rc4": "RC4", "ChaCha20-Poly1305": "ChaCha20-Poly1305",
		"gcm-detection": "", "certificate": "", "EC": "ECDSA", "EC-secp384r1": "ECDSA", "Diffie-Hellman": "DH",
		"SHA256-RSA": "RSA", "key@68d415f4": "", "ECC": "ECDSA", "eccentric": "",
	} {
		if got := Family(name); got != want {
			t.Errorf("Family(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestAssign(t *testing.T) {
	cases := map[string]bool{"go/g01-rsa-keygen": true, "config/k01-nginx-hybrid": true}
	for path, want := range map[string]string{
		"/src/go/g01-rsa-keygen/main.go":              "go/g01-rsa-keygen|main.go",
		"/data/config/k01-nginx-hybrid/nginx.conf":    "config/k01-nginx-hybrid|nginx.conf",
		"file:///workspace/go/g01-rsa-keygen/main.go": "go/g01-rsa-keygen|main.go",
		"go/g01-rsa-keygen/sub/x.go":                  "go/g01-rsa-keygen|sub/x.go",
		"/src/go/unknown-case/main.go":                "",
		"/src/README.md":                              "",
		"workspace/go/g01-rsa-keygen/main.go":         "go/g01-rsa-keygen|main.go",
		"go/g01-rsa-keygen/src/main.go":               "go/g01-rsa-keygen|src/main.go",
		"/elsewhere/go/g01-rsa-keygen/main.go":        "",
	} {
		c, f, ok := assign(path, cases)
		got := ""
		if ok {
			got = c + "|" + f
		}
		if got != want {
			t.Errorf("assign(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestScore(t *testing.T) {
	cases := []Case{
		{ID: "go/a", Layer: "source", Language: "go", Expect: []Label{{File: "main.go", Line: 3, Algorithm: "RSA"}, {File: "main.go", Line: 4, Algorithm: "MD5"}}},
		{ID: "deps/d", Layer: "deps", Language: "-", Expect: []Label{{File: "go.mod", Line: 3, Algorithm: "ML-KEM"}}},
	}
	items := []Item{
		{"go/a", "main.go", 3, "RSA"},     // tp
		{"go/a", "main.go", 9, "MD5"},     // fp by line, tp by file
		{"go/a", "main.go", 5, "AES"},     // fp
		{"deps/d", "go.mod", 3, "ML-KEM"}, // tp
		{"deps/d", "go.mod", 3, "RSA"},    // ignored: deps cases score post-quantum families only
	}
	tally := map[string]*Tally{}
	for _, o := range score("tool", cases, items) {
		if tally[o.Granularity] == nil {
			tally[o.Granularity] = &Tally{}
		}
		tally[o.Granularity].add(o.Result)
	}
	if got := *tally[ByLine]; got != (Tally{TP: 2, FP: 2, FN: 1}) {
		t.Errorf("line tally = %+v", got)
	}
	if got := *tally[ByFile]; got != (Tally{TP: 3, FP: 1, FN: 0}) {
		t.Errorf("file tally = %+v", got)
	}
	tl := Tally{TP: 3, FP: 1, FN: 1}
	if tl.Precision() != 0.75 || tl.Recall() != 0.75 || tl.F1() != 0.75 {
		t.Errorf("metrics %v %v %v", tl.Precision(), tl.Recall(), tl.F1())
	}
	if (Tally{}).Precision() != 1 || (Tally{FN: 1}).F1() != 0 {
		t.Error("empty denominators")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Each adapter reads output in the tool's documented format.
func TestAdapters(t *testing.T) {
	runs := t.TempDir()
	ran := `{"tool":"%s","version":"1","source":"test","status":"ran","reason":""}`
	writeFile(t, filepath.Join(runs, "cryptoscan-pqc", "tool.json"), strings.ReplaceAll(ran, "%s", "cryptoscan-pqc"))
	writeFile(t, filepath.Join(runs, "cryptoscan-pqc", "cbom.json"), `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
	  {"type":"cryptographic-asset","name":"RSA","cryptoProperties":{"assetType":"algorithm"},
	   "evidence":{"occurrences":[{"location":"/src/go/g01-rsa-keygen/main.go","line":9}]}},
	  {"type":"cryptographic-asset","name":"alg","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"parameterSetIdentifier":"ML-KEM-768"}},
	   "properties":[{"name":"file_path","value":"go/g51-mlkem1024/main.go"}]},
	  {"type":"cryptographic-asset","name":"DSA","evidence":{"occurrences":[{"location":"java/j10-wildcard-import/Main.java:5"}]}},
	  {"type":"cryptographic-asset","name":"ECDSA","evidence":{"occurrences":[{"location":"go/g01-rsa-keygen/labels.yaml:4"}]}},
	  {"type":"library","name":"openssl"}]}`)
	writeFile(t, filepath.Join(runs, "semgrep", "tool.json"), strings.ReplaceAll(ran, "%s", "semgrep"))
	writeFile(t, filepath.Join(runs, "semgrep", "results.json"), `{"results":[
	  {"check_id":"java.lang.security.audit.crypto.use-of-md5","path":"/src/java/j09-weak-digests/Main.java","start":{"line":5}},
	  {"check_id":"generic.secrets.unrelated","path":"/src/java/j09-weak-digests/Main.java","start":{"line":1}}]}`)
	writeFile(t, filepath.Join(runs, "pqc-audit", "tool.json"), strings.ReplaceAll(ran, "%s", "pqc-audit"))
	writeFile(t, filepath.Join(runs, "pqc-audit", "report.json"), `{"findings":[{"file":"/src/python/p01-rsa-keygen/main.py","line_number":"4","algorithm":"RSA"},{"note":"no path"}]}`)
	writeFile(t, filepath.Join(runs, "cbomkit-theia", "tool.json"), `{"tool":"cbomkit-theia","status":"failed","reason":"exit 1"}`)

	cases := map[string]bool{"go/g01-rsa-keygen": true, "go/g51-mlkem1024": true, "java/j09-weak-digests": true, "python/p01-rsa-keygen": true, "java/j10-wildcard-import": true}
	for _, tt := range []struct {
		tool   string
		parse  func(string) ([]rawFinding, error)
		status string
		want   []Item
	}{
		// "path:line" locations are split; a hit in labels.yaml (the answer key) is dropped.
		{"cryptoscan-pqc", parseCBOMDir, "ran", []Item{{"go/g01-rsa-keygen", "main.go", 9, "RSA"}, {"go/g51-mlkem1024", "main.go", 0, "ML-KEM"}, {"java/j10-wildcard-import", "Main.java", 5, "DSA"}}},
		{"semgrep", parseSemgrep, "ran", []Item{{"java/j09-weak-digests", "Main.java", 5, "MD5"}}},
		{"pqc-audit", parseGenericJSON, "ran", []Item{{"python/p01-rsa-keygen", "main.py", 4, "RSA"}}},
		{"cbomkit-theia", parseCBOMDir, "failed", nil},
		{"cbomkit-action", parseCBOMDir, "unavailable", nil},
	} {
		run, items, err := loadCompetitor(runs, tt.tool, tt.parse, cases)
		if err != nil {
			t.Fatal(err)
		}
		if run.Status != tt.status || !slices.Equal(items, tt.want) {
			t.Errorf("%s: status %q items %+v; want %q %+v", tt.tool, run.Status, items, tt.status, tt.want)
		}
	}

	writeFile(t, filepath.Join(runs, "semgrep", "results.json"), `not json`)
	if run, _, _ := loadCompetitor(runs, "semgrep", parseSemgrep, cases); run.Status != "unparsed" {
		t.Errorf("garbage output: status %q", run.Status)
	}
}

func TestLoadCorpus(t *testing.T) {
	cases, err := LoadCorpus(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 200 {
		t.Errorf("corpus has %d cases; milestone 10 needs at least 200", len(cases))
	}
	layers := map[string]int{}
	langs := map[string]int{}
	for _, c := range cases {
		layers[c.Layer]++
		if c.Layer == "source" {
			langs[c.Language]++
		}
	}
	for _, l := range Layers {
		if layers[l] == 0 {
			t.Errorf("no %s cases", l)
		}
	}
	for _, l := range sourceLanguages {
		if langs[l] == 0 {
			t.Errorf("no %s cases", l)
		}
	}
}

// End to end over the real corpus, with no competitor runs: pqscope is
// scored, the others are listed as not run, and every CSV is written.
func TestRunWithoutCompetitors(t *testing.T) {
	rep, err := Run(context.Background(), corpusDir, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := WriteCSVs(rep, out); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rq1_summary.csv", "rq1_items.csv", "rq1_tools.csv", "rq1_ablation.csv", "rq1_corpus.csv"} {
		f, err := os.Open(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := csv.NewReader(f).ReadAll()
		_ = f.Close()
		if err != nil || len(rows) < 2 {
			t.Errorf("%s: %d rows, %v", name, len(rows), err)
		}
	}
	var overall []string
	for _, row := range Summary(rep) {
		if row[0] == "pqscope" && row[1] == ByFile && row[2] == "all" && row[3] == "all" {
			overall = row
		}
	}
	if overall == nil || overall[4] != strconv.Itoa(len(rep.Cases)) {
		t.Fatalf("overall row = %v, want %d cases", overall, len(rep.Cases))
	}
	// Network cases were not probed here, so their labels count as missed.
	for _, tl := range rep.Tools {
		if tl.Tool != "pqscope" && tl.Status != "unavailable" {
			t.Errorf("%s: status %q without a run", tl.Tool, tl.Status)
		}
	}
	if len(rep.Ablation) != 1+len(Layers) || rep.Ablation[0].Config != "all" {
		t.Errorf("ablation = %+v", rep.Ablation)
	}
	if rep.Ablation[1].Recall() >= rep.Ablation[0].Recall() {
		t.Error("turning off the source layer should lower recall")
	}
}
