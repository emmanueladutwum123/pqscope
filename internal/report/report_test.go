package report

import (
	"bytes"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

func testDB(t *testing.T) *knowledge.DB {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func finding(t *testing.T, db *knowledge.DB, id, primitive, path string, line int) model.Finding {
	t.Helper()
	e, ok := db.ByID(id)
	if !ok {
		t.Fatalf("no entry %s", id)
	}
	a, err := e.Asset(primitive)
	if err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding(a, model.Location{Layer: model.LayerSource, Path: path, Line: line}, 0.95)
	f.RuleID = "test." + id
	f.Evidence = "evidence " + id
	return f
}

// sample returns findings with policy results and risk filled in, as scan
// produces them.
func sample(t *testing.T, db *knowledge.DB) []model.Finding {
	fs := []model.Finding{
		finding(t, db, "AES-256", "cipher", "a.go", 1),
		finding(t, db, "RSA-2048", "signature", "a.go", 2),
		finding(t, db, "RSA-2048", "signature", "b.go", 3),
		finding(t, db, "MD5", "hash", "c.py", 4),
		finding(t, db, "X25519MLKEM768", "key-agreement", "d.go", 5),
	}
	verdicts := []struct{ nist, cnsa string }{
		{"compliant", "compliant"}, {"deprecated-2030", "disallowed-now"}, {"deprecated-2030", "unknown"},
		{"broken-now", "broken-now"}, {"compliant", "disallowed-now"},
	}
	for i := range fs {
		fs[i].Policy = []model.PolicyResult{{Policy: "nist", Status: verdicts[i].nist}, {Policy: "cnsa", Status: verdicts[i].cnsa}}
		fs[i].Risk = float64(i) / 10
	}
	return fs
}

func TestGroups(t *testing.T) {
	db := testDB(t)
	got := Groups(db, sample(t, db))
	want := []Group{
		{"MD5", "hash", "broken-now", "civilian: SHA-256; CNSA 2.0: SHA-384", map[string]string{"nist": "broken-now", "cnsa": "broken-now"}, 0.3, 1},
		{"RSA-2048", "signature", "vulnerable", "civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87", map[string]string{"nist": "deprecated-2030", "cnsa": "disallowed-now"}, 0.2, 2},
		{"AES-256", "cipher", "weakened", "", map[string]string{"nist": "compliant", "cnsa": "compliant"}, 0, 1},
		{"X25519MLKEM768", "key-agreement", "hybrid", "", map[string]string{"nist": "compliant", "cnsa": "disallowed-now"}, 0.4, 1},
	}
	if len(got) != len(want) {
		t.Fatalf("Groups = %+v", got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("group %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCountByStatus(t *testing.T) {
	db := testDB(t)
	got := CountByStatus(sample(t, db))
	want := []StatusCount{{"broken-now", 1}, {"vulnerable", 2}, {"weakened", 1}, {"hybrid", 1}}
	if len(got) != len(want) {
		t.Fatalf("CountByStatus = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("count %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSummaryLine(t *testing.T) {
	tests := []struct {
		sum  Summary
		want string
	}{
		{Summary{}, "2 findings"},
		{Summary{Counted: true, FilesScanned: 3}, "2 findings in 3 files scanned"},
		{Summary{Counted: true, FilesScanned: 3, Skipped: 1, SyntaxErrors: 2}, "2 findings in 3 files scanned, 1 skipped, 2 with syntax errors"},
	}
	for _, tt := range tests {
		if got := tt.sum.Line(2); got != tt.want {
			t.Errorf("Line = %q, want %q", got, tt.want)
		}
	}
}

func TestText(t *testing.T) {
	db := testDB(t)
	var buf bytes.Buffer
	if err := Text(&buf, db, sample(t, db), Summary{Counted: true, FilesScanned: 4}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"LOCATION", "RISK", "a.go:2", "0.10", "test.RSA-2048",
		"ASSET           PRIMITIVE      QUANTUM     FINDINGS  NIST             CNSA            MIGRATE TO\n",
		"RSA-2048        signature      vulnerable  2         deprecated-2030  disallowed-now  civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87",
		"Quantum status: 1 broken-now, 2 vulnerable, 1 weakened, 1 hybrid\n",
		"nist: 1 broken-now, 2 deprecated-2030, 2 compliant\n",
		"cnsa: 1 broken-now, 2 disallowed-now, 1 compliant, 1 unknown\n",
		"5 findings in 4 files scanned\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestTextEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, testDB(t), nil, Summary{Counted: true, FilesScanned: 2}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "0 findings in 2 files scanned\n" {
		t.Errorf("empty output = %q", got)
	}
}

func renderHTML(t *testing.T, findings []model.Finding) string {
	t.Helper()
	var buf bytes.Buffer
	err := HTML(&buf, testDB(t), findings, Summary{Target: "./svc", Counted: true, FilesScanned: 4},
		HTMLOptions{ToolVersion: "test", Generated: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestHTML(t *testing.T) {
	db := testDB(t)
	out := renderHTML(t, sample(t, db))
	for _, want := range []string{
		"<!doctype html>",
		"default-src 'none'",
		"Target <code>./svc</code>",
		"5 findings in 4 files scanned",
		"2026-11-07T00:00:00Z",
		`<td class="q q-vulnerable">vulnerable</td><td class="num">2</td><td class="num">0.20</td><td class="p p-deprecated-2030">deprecated-2030</td><td class="p p-disallowed-now">disallowed-now</td><td>civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87</td>`,
		`<th>nist</th><th>cnsa</th>`,
		`<td class="num">0.30</td><td class="p p-broken-now">broken-now</td>`,
		`<tr data-q="broken-now"><td><code>c.py:4</code></td>`,
		`<option value="hybrid">hybrid</option>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
}

func TestHTMLEscapesEvidence(t *testing.T) {
	db := testDB(t)
	f := finding(t, db, "MD5", "hash", `x"><img src=x onerror=alert(1)>.py`, 1)
	f.Evidence = `h = hashlib.md5(b"</code><script>alert(1)</script>")`
	out := renderHTML(t, []model.Finding{f})
	for _, bad := range []string{"<script>alert", "<img src=x", "</code><script>"} {
		if strings.Contains(out, bad) {
			t.Errorf("unescaped input %q in HTML", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped evidence not found")
	}
}

// The report must be one file that works offline.
func TestHTMLSelfContained(t *testing.T) {
	db := testDB(t)
	out := renderHTML(t, sample(t, db))
	if loc := regexp.MustCompile(`(?i)(src|href)\s*=|@import|url\(`).FindString(out); loc != "" {
		t.Errorf("HTML references an external resource: %q", loc)
	}
	if strings.Count(out, "<script>") != 1 || strings.Count(out, "<style>") != 1 {
		t.Error("want exactly one inline script and one inline style block")
	}
}

func TestHTMLEmpty(t *testing.T) {
	out := renderHTML(t, nil)
	if !strings.Contains(out, "No cryptographic assets found.") || strings.Contains(out, `id="findings"`) {
		t.Error("empty report should say so and omit the findings table")
	}
}

func TestPolicyIDs(t *testing.T) {
	db := testDB(t)
	if got := PolicyIDs(sample(t, db)); !reflect.DeepEqual(got, []string{"nist", "cnsa"}) {
		t.Errorf("PolicyIDs = %v", got)
	}
	plain := []model.Finding{finding(t, db, "MD5", "hash", "a.py", 1)}
	if got := PolicyIDs(plain); got != nil {
		t.Errorf("PolicyIDs without policy results = %v", got)
	}
	var buf bytes.Buffer
	if err := Text(&buf, db, plain, Summary{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ASSET  PRIMITIVE  QUANTUM     FINDINGS  MIGRATE TO") {
		t.Errorf("asset table without policies:\n%s", buf.String())
	}
}
