package sarif

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/schemas"
)

func testDB(t *testing.T) *knowledge.DB {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func finding(t *testing.T, db *knowledge.DB, id, primitive string, loc model.Location) model.Finding {
	t.Helper()
	e, ok := db.ByID(id)
	if !ok {
		t.Fatalf("no entry %s", id)
	}
	a, err := e.Asset(primitive)
	if err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding(a, loc, 0.95)
	f.RuleID = "test." + id
	f.Evidence = "evidence " + id
	return f
}

func encode(t *testing.T, db *knowledge.DB, findings []model.Finding, opts Options) *Log {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, db, findings, opts); err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateSARIF(buf.Bytes()); err != nil {
		t.Fatalf("output does not validate against SARIF 2.1.0:\n%v\n%s", err, buf.Bytes())
	}
	var log Log
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	return &log
}

func TestEveryEntryValidates(t *testing.T) {
	db := testDB(t)
	layers := []model.Layer{model.LayerSource, model.LayerDeps, model.LayerConfig, model.LayerBinary, model.LayerNetwork}
	var findings []model.Finding
	for i, e := range db.Entries() {
		for _, p := range e.Primitives {
			l := layers[i%len(layers)]
			findings = append(findings, finding(t, db, e.ID, p, model.Location{Layer: l, Path: "dir/with space/x.go", Line: i % 3}))
		}
	}
	log := encode(t, db, findings, Options{ToolVersion: "test"})
	if got := len(log.Runs[0].Results); got != len(findings) {
		t.Errorf("%d results for %d findings", got, len(findings))
	}
}

func TestEmpty(t *testing.T) {
	log := encode(t, testDB(t), nil, Options{})
	if log.Runs[0].Results == nil || len(log.Runs[0].Results) != 0 {
		t.Errorf("want an empty results array, got %v", log.Runs[0].Results)
	}
}

func TestResults(t *testing.T) {
	db := testDB(t)
	md5 := finding(t, db, "MD5", "hash", model.Location{Layer: model.LayerSource, Path: "pkg/a b.py", Line: 4, Symbol: "hashlib.md5"})
	rsa := finding(t, db, "RSA-2048", "signature", model.Location{Layer: model.LayerSource, Path: "main.go", Line: 9})
	rsa.Confidence = 0.95 * 0.8
	hybrid := finding(t, db, "X25519MLKEM768", "key-agreement", model.Location{Layer: model.LayerNetwork, Path: "example.org:443"})
	hybrid.RuleID = ""
	unknown := model.NewFinding(model.Asset{Primitive: "signature", Algorithm: "ECDSA", Params: model.ParamsUnknown, Quantum: model.QuantumVulnerable},
		model.Location{Layer: model.LayerSource, Path: "x.go", Line: 1}, 0.76)
	unknown.RuleID = "test.RSA-2048"

	log := encode(t, db, []model.Finding{md5, rsa, hybrid, unknown}, Options{
		ToolVersion: "1.2.3",
		Rules: map[string]Rule{
			"test.MD5": {Description: "MD5 via hashlib.md5", Notes: "misses getattr", HelpURI: "https://docs.python.org/3/library/hashlib.html"},
		},
	})
	run := log.Runs[0]
	if run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver version = %q", run.Tool.Driver.Version)
	}
	rules := run.Tool.Driver.Rules
	wantIDs := []string{"pqscope.network", "test.MD5", "test.RSA-2048"}
	if len(rules) != len(wantIDs) {
		t.Fatalf("rules = %+v", rules)
	}
	for i, id := range wantIDs {
		if rules[i].ID != id {
			t.Errorf("rule %d = %s, want %s", i, rules[i].ID, id)
		}
	}
	if r := rules[1]; r.ShortDescription.Text != "MD5 via hashlib.md5" || r.FullDescription.Text != "misses getattr" || r.HelpURI == "" {
		t.Errorf("described rule = %+v", r)
	}
	if r := rules[2]; r.ShortDescription.Text != "pqscope rule test.RSA-2048" || r.FullDescription != nil {
		t.Errorf("undescribed rule = %+v", r)
	}

	tests := []struct {
		i                int
		level, msg, rule string
		ruleIndex        int
	}{
		{0, "error", "MD5 (hash) is broken today, without a quantum computer. Migrate to civilian: SHA-256; CNSA 2.0: SHA-384.", "test.MD5", 1},
		{1, "warning", "RSA-2048 (signature) is quantum-vulnerable. Migrate to civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87.", "test.RSA-2048", 2},
		{2, "note", "X25519MLKEM768 (key-agreement) is a post-quantum hybrid.", "pqscope.network", 0},
		{3, "warning", "ECDSA (signature, parameters unknown) is quantum-vulnerable. Migrate to civilian: ML-DSA-65; CNSA 2.0: ML-DSA-87.", "test.RSA-2048", 2},
	}
	for _, tt := range tests {
		r := run.Results[tt.i]
		if r.Level != tt.level || r.Message.Text != tt.msg || r.RuleID != tt.rule || r.RuleIndex != tt.ruleIndex {
			t.Errorf("result %d = level %q rule %q[%d] message %q\nwant level %q rule %q[%d] message %q",
				tt.i, r.Level, r.RuleID, r.RuleIndex, r.Message.Text, tt.level, tt.rule, tt.ruleIndex, tt.msg)
		}
	}

	first := run.Results[0]
	pl := first.Locations[0].PhysicalLocation
	if pl.ArtifactLocation.URI != "pkg/a%20b.py" || pl.ArtifactLocation.URIBaseID != SrcRoot || pl.Region.StartLine != 4 || pl.Region.Snippet.Text != "evidence MD5" {
		t.Errorf("physical location = %+v region %+v", pl.ArtifactLocation, pl.Region)
	}
	if first.PartialFingerprints[FingerprintKey] != md5.ID || first.Properties.Symbol != "hashlib.md5" {
		t.Errorf("fingerprints %v, properties %+v", first.PartialFingerprints, first.Properties)
	}
	if c := run.Results[1].Properties.Confidence; c != 0.76 {
		t.Errorf("confidence = %v, want 0.76", c)
	}
	net := run.Results[2].Locations[0]
	if net.PhysicalLocation != nil || len(net.LogicalLocations) != 1 || net.LogicalLocations[0].FullyQualifiedName != "example.org:443" {
		t.Errorf("network location = %+v", net)
	}
}

func TestLevel(t *testing.T) {
	for q, want := range map[string]string{
		model.QuantumBrokenNow: "error", model.QuantumVulnerable: "warning",
		model.QuantumWeakened: "note", model.QuantumHybrid: "note", model.QuantumSafe: "note",
	} {
		if got := Level(q); got != want {
			t.Errorf("Level(%s) = %s, want %s", q, got, want)
		}
	}
}
