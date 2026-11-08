package cbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/internal/schemas"
)

var fixed = Options{
	ToolVersion:  "test",
	Timestamp:    time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC),
	SerialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000",
}

func testDB(t *testing.T) *knowledge.DB {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func finding(t *testing.T, db *knowledge.DB, id, primitive string, layer model.Layer, path string, line int) model.Finding {
	t.Helper()
	e, ok := db.ByID(id)
	if !ok {
		t.Fatalf("no entry %s", id)
	}
	a, err := e.Asset(primitive)
	if err != nil {
		t.Fatal(err)
	}
	f := model.NewFinding(a, model.Location{Layer: layer, Path: path, Line: line, Symbol: "sym." + id}, 0.95)
	f.RuleID = "test." + id
	f.Evidence = "evidence for " + id
	return f
}

func encode(t *testing.T, db *knowledge.DB, findings []model.Finding) ([]byte, *BOM) {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, db, findings, fixed); err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateCycloneDX(buf.Bytes()); err != nil {
		t.Fatalf("output does not validate against CycloneDX 1.6:\n%v\n%s", err, buf.Bytes())
	}
	var bom BOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), &bom
}

// Every knowledge DB entry, as every primitive it supports, in every layer,
// must produce a valid BOM.
func TestEveryEntryValidates(t *testing.T) {
	db := testDB(t)
	layers := []model.Layer{model.LayerSource, model.LayerDeps, model.LayerConfig, model.LayerBinary, model.LayerNetwork}
	var findings []model.Finding
	for i, e := range db.Entries() {
		for _, p := range e.Primitives {
			findings = append(findings, finding(t, db, e.ID, p, layers[i%len(layers)], "dir/file name.go", i+1))
		}
	}
	_, bom := encode(t, db, findings)
	if len(bom.Components) != len(findings) {
		t.Errorf("%d components for %d distinct assets", len(bom.Components), len(findings))
	}
	for _, c := range bom.Components {
		if c.CryptoProperties.AlgorithmProperties.Primitive == "unknown" {
			t.Errorf("%s: primitive not mapped to CycloneDX", c.BOMRef)
		}
	}
}

func TestEmpty(t *testing.T) {
	out, bom := encode(t, testDB(t), nil)
	if len(bom.Components) != 0 || !bytes.Contains(out, []byte(`"components": []`)) {
		t.Errorf("want an empty components array, got:\n%s", out)
	}
}

func TestComponentFields(t *testing.T) {
	db := testDB(t)
	rsaA := finding(t, db, "RSA-2048", "signature", model.LayerSource, "b.go", 9)
	rsaB := finding(t, db, "RSA-2048", "signature", model.LayerSource, "a.go", 3)
	rsaB.Confidence = 0.76
	rsaB.RuleID = "go.rsa.other"
	rsaPKE := finding(t, db, "RSA-2048", "pke", model.LayerSource, "a.go", 4)
	ecdh := finding(t, db, "ECDH-P256", "key-agreement", model.LayerNetwork, "example.org:443", 0)
	ecdh.Policy = []model.PolicyResult{{Policy: "nist", Status: model.PolicyCompliant}}
	ecdh.Risk = 0.4
	ecdh2 := finding(t, db, "ECDH-P256", "key-agreement", model.LayerConfig, "nginx.conf", 7)
	ecdh2.Policy = []model.PolicyResult{{Policy: "nist", Status: model.PolicyDeprecated}}
	mlkem := finding(t, db, "ML-KEM-768", "kem", model.LayerSource, "c.go", 1)
	aes := finding(t, db, "AES-128", "cipher", model.LayerBinary, "bin/app", 0)
	unknown := model.NewFinding(model.Asset{Primitive: "signature", Algorithm: "RSA", Params: model.ParamsUnknown, Quantum: model.QuantumVulnerable},
		model.Location{Layer: model.LayerSource, Path: "d.go", Line: 2}, 0.76)

	_, bom := encode(t, db, []model.Finding{rsaA, rsaB, rsaPKE, ecdh, ecdh2, mlkem, aes, unknown})
	byRef := map[string]Component{}
	for _, c := range bom.Components {
		byRef[c.BOMRef] = c
	}
	if len(byRef) != 6 {
		t.Fatalf("want 6 components, got %d: %v", len(byRef), bom.Components)
	}

	rsa := byRef["crypto/algorithm/RSA/2048/signature"]
	if rsa.Name != "RSA-2048" || rsa.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "2048" {
		t.Errorf("rsa = %+v", rsa)
	}
	if got := rsa.Evidence.Occurrences; len(got) != 2 || got[0].Location != "a.go" || got[0].BOMRef != rsaB.ID || got[0].Line != 3 {
		t.Errorf("occurrences not sorted by location or missing ids: %+v", got)
	}
	id := rsa.Evidence.Identity[0]
	if id.Confidence != 0.95 || len(id.Methods) != 1 || id.Methods[0].Technique != "source-code-analysis" ||
		id.Methods[0].Value != "go.rsa.other, test.RSA-2048" {
		t.Errorf("identity = %+v", id)
	}
	if lvl := rsa.CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel; lvl == nil || *lvl != 0 {
		t.Errorf("vulnerable asset should have quantum level 0, got %v", lvl)
	}
	wantProps(t, rsa, map[string]string{PropQuantum: "vulnerable", PropMigrationCivil: "ML-DSA-65", PropMigrationCNSA2: "ML-DSA-87"})

	if pke := byRef["crypto/algorithm/RSA/2048/pke"]; pke.CryptoProperties.AlgorithmProperties.Primitive != "pke" {
		t.Errorf("pke = %+v", pke)
	}

	e := byRef["crypto/algorithm/ECDH/P-256/key-agreement"]
	ap := e.CryptoProperties.AlgorithmProperties
	if ap.Primitive != "key-agree" || ap.Curve != "nist/P-256" || ap.ParameterSetIdentifier != "" || *ap.ClassicalSecurityLevel != 128 {
		t.Errorf("ecdh algorithm properties = %+v", ap)
	}
	if m := e.Evidence.Identity[0].Methods; len(m) != 2 || m[0].Technique != "dynamic-analysis" || m[1].Technique != "other" {
		t.Errorf("ecdh methods = %+v", m)
	}
	wantProps(t, e, map[string]string{"pqscope:policy:nist": model.PolicyDeprecated, PropRisk: "0.4",
		PropMigrationCivil: "X25519MLKEM768", PropMigrationCNSA2: "ML-KEM-1024"})

	k := byRef["crypto/algorithm/ML-KEM/ML-KEM-768/kem"]
	if lvl := k.CryptoProperties.AlgorithmProperties.NISTQuantumSecurityLevel; lvl == nil || *lvl != 3 {
		t.Errorf("ML-KEM-768 quantum level = %v, want 3", lvl)
	}
	wantProps(t, k, map[string]string{PropQuantum: "safe"})

	a := byRef["crypto/algorithm/AES/128/cipher"]
	if ap := a.CryptoProperties.AlgorithmProperties; ap.Primitive != "block-cipher" || ap.NISTQuantumSecurityLevel != nil {
		t.Errorf("AES properties = %+v; quantum level must be omitted when the DB records none", ap)
	}

	u := byRef["crypto/algorithm/RSA/unknown/signature"]
	if u.Name != "RSA" || u.CryptoProperties.AlgorithmProperties.ParameterSetIdentifier != "" || u.CryptoProperties.AlgorithmProperties.ClassicalSecurityLevel != nil {
		t.Errorf("unknown-params component = %+v", u)
	}
	if id := u.Evidence.Identity[0]; id.Confidence != 0.76 || id.Methods[0].Value != "" {
		t.Errorf("unknown-params identity = %+v", id)
	}
	wantProps(t, u, map[string]string{PropMigrationCivil: "ML-DSA-65"})
}

func wantProps(t *testing.T, c Component, want map[string]string) {
	t.Helper()
	got := map[string]string{}
	for _, p := range c.Properties {
		got[p.Name] = p.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: property %s = %q, want %q (all: %v)", c.BOMRef, k, got[k], v, got)
		}
	}
}

func TestDeterministic(t *testing.T) {
	db := testDB(t)
	var findings []model.Finding
	for i, id := range []string{"RSA-2048", "MD5", "X25519", "SHA-256", "Ed25519"} {
		e, _ := db.ByID(id)
		findings = append(findings, finding(t, db, id, e.Primitives[0], model.LayerSource, "x.go", i+1))
	}
	first, _ := encode(t, db, findings)
	for i := range findings {
		j := len(findings) - 1 - i
		if i < j {
			findings[i], findings[j] = findings[j], findings[i]
		}
	}
	second, _ := encode(t, db, findings)
	if !bytes.Equal(first, second) {
		t.Error("output depends on input order")
	}
}

func TestDefaultsAreFresh(t *testing.T) {
	db := testDB(t)
	a, err := Build(db, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Build(db, nil, Options{})
	if a.SerialNumber == b.SerialNumber {
		t.Error("serial numbers repeat")
	}
	if _, err := time.Parse(time.RFC3339, a.Metadata.Timestamp); err != nil {
		t.Errorf("timestamp: %v", err)
	}
	data, _ := json.Marshal(a)
	if err := schemas.ValidateCycloneDX(data); err != nil {
		t.Errorf("default metadata invalid: %v", err)
	}
}

func TestDuplicateIDsRejected(t *testing.T) {
	db := testDB(t)
	f := finding(t, db, "MD5", "hash", model.LayerSource, "x.py", 1)
	if _, err := Build(db, []model.Finding{f, f}, fixed); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error = %v, want duplicate id", err)
	}
}
