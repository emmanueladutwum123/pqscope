package report

import (
	"bytes"
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

func sample(t *testing.T, db *knowledge.DB) []model.Finding {
	return []model.Finding{
		finding(t, db, "AES-256", "cipher", "a.go", 1),
		finding(t, db, "RSA-2048", "signature", "a.go", 2),
		finding(t, db, "RSA-2048", "signature", "b.go", 3),
		finding(t, db, "MD5", "hash", "c.py", 4),
		finding(t, db, "X25519MLKEM768", "key-agreement", "d.go", 5),
	}
}

func TestGroups(t *testing.T) {
	db := testDB(t)
	got := Groups(db, sample(t, db))
	want := []Group{
		{"MD5", "hash", "broken-now", "civilian: SHA-256; CNSA 2.0: SHA-384", 1},
		{"RSA-2048", "signature", "vulnerable", "civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87", 2},
		{"AES-256", "cipher", "weakened", "", 1},
		{"X25519MLKEM768", "key-agreement", "hybrid", "", 1},
	}
	if len(got) != len(want) {
		t.Fatalf("Groups = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
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
		"LOCATION", "a.go:2", "test.RSA-2048",
		"ASSET", "MIGRATE TO",
		"RSA-2048        signature      vulnerable  2         civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87",
		"Quantum status: 1 broken-now, 2 vulnerable, 1 weakened, 1 hybrid\n",
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
		`<td class="q q-vulnerable">vulnerable</td><td class="num">2</td><td>civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87</td>`,
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
