package policy

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
	"github.com/emmanueladutwum123/pqscope/policies"
)

const (
	nist = "nist-ir-8547-2026"
	cnsa = "cnsa-2.0"

	ok      = model.PolicyCompliant
	dep2030 = model.PolicyDeprecated
	dis2035 = model.PolicyDisallowed
	disNow  = model.PolicyDisallowedNow
	broken  = model.PolicyBrokenNow
	unknown = model.PolicyUnknown
)

func testDB(t *testing.T) *knowledge.DB {
	t.Helper()
	db, err := knowledge.Default()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func bundled(t *testing.T) map[string]*Policy {
	t.Helper()
	ps, err := Load(testDB(t), policies.FS)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

// Every (algorithm, strength, primitive) row of the knowledge DB, with its
// expected status under each bundled policy. Written out by hand from the
// cited documents, not derived from the policy files.
var rows = []struct {
	entry, primitive string
	nist, cnsa       string
}{
	{"RSA-1024", "signature", disNow, disNow},
	{"RSA-1024", "pke", disNow, disNow},
	{"RSA-2048", "signature", dep2030, disNow},
	{"RSA-2048", "pke", dep2030, disNow},
	{"RSA-3072", "signature", dep2030, dis2035},
	{"RSA-3072", "pke", dep2030, dis2035},
	{"RSA-4096", "signature", dep2030, dis2035},
	{"RSA-4096", "pke", dep2030, dis2035},
	{"ECDSA-P224", "signature", dep2030, disNow},
	{"ECDSA-P256", "signature", dep2030, disNow},
	{"ECDSA-P384", "signature", dep2030, dis2035},
	{"ECDSA-P521", "signature", dep2030, disNow},
	{"ECDH-P256", "key-agreement", dep2030, disNow},
	{"ECDH-P384", "key-agreement", dep2030, dis2035},
	{"ECDH-P521", "key-agreement", dep2030, disNow},
	{"X25519", "key-agreement", dep2030, disNow},
	{"X448", "key-agreement", dep2030, disNow},
	{"Ed25519", "signature", dep2030, disNow},
	{"Ed448", "signature", dep2030, disNow},
	{"DH-2048", "key-agreement", dep2030, disNow},
	{"DH-3072", "key-agreement", dep2030, dis2035},
	{"MQV", "key-agreement", dep2030, disNow},
	{"DSA-1024", "signature", disNow, disNow},
	{"DSA-2048", "signature", disNow, disNow},
	{"DSA-3072", "signature", disNow, disNow},
	{"ML-KEM-512", "kem", ok, disNow},
	{"ML-KEM-768", "kem", ok, disNow},
	{"ML-KEM-1024", "kem", ok, ok},
	{"ML-DSA-44", "signature", ok, disNow},
	{"ML-DSA-65", "signature", ok, disNow},
	{"ML-DSA-87", "signature", ok, ok},
	{"SLH-DSA-128s", "signature", ok, disNow},
	{"SLH-DSA-128f", "signature", ok, disNow},
	{"SLH-DSA-192s", "signature", ok, disNow},
	{"SLH-DSA-192f", "signature", ok, disNow},
	{"SLH-DSA-256s", "signature", ok, disNow},
	{"SLH-DSA-256f", "signature", ok, disNow},
	{"X25519MLKEM768", "kem", ok, disNow},
	{"X25519MLKEM768", "key-agreement", ok, disNow},
	{"SecP256r1MLKEM768", "kem", ok, disNow},
	{"SecP256r1MLKEM768", "key-agreement", ok, disNow},
	{"SecP384r1MLKEM1024", "kem", ok, disNow},
	{"SecP384r1MLKEM1024", "key-agreement", ok, disNow},
	{"mlkem768x25519-sha256", "kem", ok, disNow},
	{"mlkem768x25519-sha256", "key-agreement", ok, disNow},
	{"sntrup761x25519-sha512", "kem", unknown, disNow},
	{"sntrup761x25519-sha512", "key-agreement", unknown, disNow},
	{"sntrup761", "kem", disNow, disNow},
	{"AES-128", "cipher", ok, disNow},
	{"AES-192", "cipher", ok, disNow},
	{"AES-256", "cipher", ok, ok},
	{"ChaCha20-Poly1305", "cipher", disNow, disNow},
	{"3DES", "cipher", broken, broken},
	{"DES", "cipher", broken, broken},
	{"RC4", "cipher", broken, broken},
	{"MD5", "hash", broken, broken},
	{"SHA-1", "hash", broken, broken},
	{"SHA-256", "hash", ok, disNow},
	{"SHA-384", "hash", ok, ok},
	{"SHA-512", "hash", ok, ok},
	{"SHA3-256", "hash", ok, disNow},
	{"SHA3-512", "hash", ok, disNow},
	{"HMAC-SHA-256", "mac", ok, disNow},
	{"HMAC-SHA-1", "mac", dep2030, disNow},
	{"HMAC-SHA-384", "mac", ok, ok},
	{"HMAC-SHA-512", "mac", ok, ok},
}

func TestEveryRow(t *testing.T) {
	db := testDB(t)
	ps := bundled(t)
	if len(ps) != 2 || ps[nist] == nil || ps[cnsa] == nil {
		t.Fatalf("bundled policies = %v", ps)
	}
	covered := map[[2]string]bool{}
	for _, row := range rows {
		t.Run(row.entry+"/"+row.primitive, func(t *testing.T) {
			e, found := db.ByID(row.entry)
			if !found {
				t.Fatalf("no entry %s", row.entry)
			}
			a, err := e.Asset(row.primitive)
			if err != nil {
				t.Fatal(err)
			}
			for id, want := range map[string]string{nist: row.nist, cnsa: row.cnsa} {
				got := ps[id].Evaluate(a)
				if got.Status != want || got.Policy != id {
					t.Errorf("%s: status %q, want %q", id, got.Status, want)
				}
				if got.Rule == "" || got.Schedule == "" {
					t.Errorf("%s: missing rule or schedule: %+v", id, got)
				}
			}
		})
		covered[[2]string{row.entry, row.primitive}] = true
	}
	// A new knowledge DB entry must be added to the table above.
	for _, e := range db.Entries() {
		for _, p := range e.Primitives {
			if !covered[[2]string{e.ID, p}] {
				t.Errorf("table has no row for %s as %s", e.ID, p)
			}
		}
	}
}

func TestEveryRuleCited(t *testing.T) {
	for id, p := range bundled(t) {
		for _, r := range p.Rules {
			if !strings.Contains(r.Cite.Section, "Sec.") {
				t.Errorf("%s/%s: section %q should name a section", id, r.ID, r.Cite.Section)
			}
		}
	}
}

func TestUnknownParams(t *testing.T) {
	ps := bundled(t)
	tests := []struct {
		name        string
		asset       model.Asset
		policy      string
		want, best  string
		wantRule    bool
		wantFailDis bool // fails a disallowed-2035 threshold
	}{
		{"rsa unknown: rows disagree", model.Asset{Primitive: "signature", Algorithm: "RSA", Params: "unknown"}, nist, unknown, dep2030, false, true},
		{"rsa unknown under cnsa", model.Asset{Primitive: "signature", Algorithm: "RSA", Params: "unknown"}, cnsa, unknown, dis2035, false, true},
		{"rsa-1536 not in DB", model.Asset{Primitive: "pke", Algorithm: "RSA", Params: "1536"}, nist, unknown, dep2030, false, true},
		{"ecdsa unknown: one rule", model.Asset{Primitive: "signature", Algorithm: "ECDSA", Params: "unknown"}, nist, dep2030, "", true, true},
		{"dsa unknown", model.Asset{Primitive: "signature", Algorithm: "DSA", Params: "unknown"}, nist, disNow, "", true, true},
		{"aes unknown: all compliant", model.Asset{Primitive: "cipher", Algorithm: "AES", Params: "unknown"}, nist, ok, "", true, false},
		{"aes unknown under cnsa", model.Asset{Primitive: "cipher", Algorithm: "AES", Params: "unknown"}, cnsa, unknown, ok, false, false},
		{"sha-2 unknown: one rule", model.Asset{Primitive: "hash", Algorithm: "SHA-2", Params: "unknown"}, nist, ok, "", true, false},
		{"unlisted algorithm", model.Asset{Primitive: "signature", Algorithm: "Rainbow", Params: "unknown"}, nist, unknown, "", false, false},
		{"wrong primitive", model.Asset{Primitive: "kem", Algorithm: "MD5", Params: "MD5"}, nist, unknown, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ps[tt.policy].Evaluate(tt.asset)
			if got.Status != tt.want || got.AtBest != tt.best || (got.Rule != "") != tt.wantRule {
				t.Errorf("Evaluate = %+v, want status %q at_best %q rule %v", got, tt.want, tt.best, tt.wantRule)
			}
			if f := Fails(got, dis2035); f != tt.wantFailDis {
				t.Errorf("Fails(disallowed-2035) = %v, want %v", f, tt.wantFailDis)
			}
		})
	}
}

func TestFails(t *testing.T) {
	tests := []struct {
		r         model.PolicyResult
		threshold string
		want      bool
	}{
		{model.PolicyResult{Status: ok}, dis2035, false},
		{model.PolicyResult{Status: dis2035}, dis2035, true},
		{model.PolicyResult{Status: dep2030}, dis2035, true},
		{model.PolicyResult{Status: dep2030}, disNow, false},
		{model.PolicyResult{Status: disNow}, disNow, true},
		{model.PolicyResult{Status: broken}, broken, true},
		{model.PolicyResult{Status: disNow}, broken, false},
		{model.PolicyResult{Status: unknown}, dis2035, false},
		{model.PolicyResult{Status: unknown, AtBest: dep2030}, dis2035, true},
		{model.PolicyResult{Status: unknown, AtBest: dep2030}, disNow, false},
	}
	for _, tt := range tests {
		if got := Fails(tt.r, tt.threshold); got != tt.want {
			t.Errorf("Fails(%+v, %s) = %v, want %v", tt.r, tt.threshold, got, tt.want)
		}
	}
	for s, want := range map[string]bool{ok: false, unknown: false, "bogus": false, dis2035: true, dep2030: true, disNow: true, broken: true} {
		if ValidThreshold(s) != want {
			t.Errorf("ValidThreshold(%q) = %v", s, !want)
		}
	}
}

func TestApply(t *testing.T) {
	ps := bundled(t)
	f := model.NewFinding(model.Asset{Primitive: "kem", Algorithm: "ML-KEM", Params: "ML-KEM-768", Quantum: "safe"},
		model.Location{Layer: model.LayerSource, Path: "a.go", Line: 1}, 0.9)
	f.Policy = []model.PolicyResult{{Policy: nist, Status: broken}, {Policy: "other", Status: ok}}
	findings := []model.Finding{f}
	Apply(findings, ps[nist], ps[cnsa])
	got := findings[0].Policy
	if len(got) != 3 || got[0].Policy != "other" || got[1].Policy != nist || got[1].Status != ok || got[2].Status != disNow {
		t.Errorf("Policy = %+v", got)
	}
}

func TestParseRejects(t *testing.T) {
	db := testDB(t)
	// A full valid policy, so each case can break one thing.
	valid, err := policies.FS.ReadFile(nist + ".yaml")
	if err != nil {
		t.Fatal(err)
	}
	base := string(valid)
	tests := []struct {
		name, doc, wantErr string
	}{
		{"unknown field", strings.Replace(base, "id: rsa-signature", "id: rsa-signature\n    bogus: 1", 1), "bogus"},
		{"bad status", strings.Replace(base, "status: deprecated-2030\n    schedule: Deprecated after 2030; disallowed after 2035\n    note: MQV", "status: maybe\n    schedule: x\n    note: MQV", 1), "unknown status"},
		{"unknown entry", strings.Replace(base, "entries: [RSA-1024]", "entries: [RSA-1024, RSA-768]", 1), "not in the knowledge DB"},
		{"missing pair", strings.Replace(base, "entries: [RSA-1024]", "entries: [RSA-1024]\n    primitives: [signature]", 1), "no rule for RSA-1024 as pke"},
		{"overlap", strings.Replace(base, "entries: [DSA-1024, DSA-2048, DSA-3072]", "entries: [DSA-1024, DSA-2048, DSA-3072, ECDSA-P256]", 1), "also matched"},
		{"wrong primitive", strings.Replace(base, "entries: [AES-128, AES-192, AES-256]", "entries: [AES-128, AES-192, AES-256]\n    primitives: [cipher, hash]", 1), "not used as"},
		{"bad source", strings.Replace(base, "cite: {source: rfc7465", "cite: {source: nope", 1), "known source"},
		{"broken marked compliant", strings.Replace(base, "entries: [MD5]\n    status: broken-now", "entries: [MD5]\n    status: compliant", 1), "broken-now in the knowledge DB"},
		{"no schedule", strings.Replace(base, "schedule: Not approved (56-bit key)", "schedule: \"\"", 1), "no schedule"},
		{"bad version", strings.Replace(base, "version: 1", "version: 2", 1), "unsupported version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.doc == base {
				t.Fatal("test case did not change the policy")
			}
			_, err := Parse(db, []byte(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRequiresMatchingFileName(t *testing.T) {
	data, _ := policies.FS.ReadFile(cnsa + ".yaml")
	_, err := Load(testDB(t), fstest.MapFS{"renamed.yaml": {Data: data}})
	if err == nil || !strings.Contains(err.Error(), "must match the file name") {
		t.Errorf("error = %v", err)
	}
	if _, err := Load(testDB(t), fstest.MapFS{}); err == nil {
		t.Error("empty policy directory should be an error")
	}
}

// When an unknown-params asset's family spans several rules that agree, the
// shared status applies but no single rule is named.
func TestUnknownParamsRulesAgree(t *testing.T) {
	data, _ := policies.FS.ReadFile(nist + ".yaml")
	split := strings.Replace(string(data), "  - id: sha-2\n    entries: [SHA-256, SHA-384, SHA-512]",
		"  - id: sha-256\n    entries: [SHA-256]\n    status: compliant\n    schedule: Approved\n    cite: {source: ir8547, section: \"Sec. 4.1.3\"}\n"+
			"  - id: sha-2\n    entries: [SHA-384, SHA-512]", 1)
	if split == string(data) {
		t.Fatal("replacement did not apply")
	}
	p, err := Parse(testDB(t), []byte(split))
	if err != nil {
		t.Fatal(err)
	}
	got := p.Evaluate(model.Asset{Primitive: "hash", Algorithm: "SHA-2", Params: "unknown"})
	if got.Status != ok || got.Rule != "" || got.Schedule != "Approved" || got.AtBest != "" {
		t.Errorf("Evaluate = %+v", got)
	}
}
