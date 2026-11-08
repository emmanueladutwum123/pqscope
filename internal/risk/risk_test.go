package risk

import (
	"strings"
	"testing"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

func weights(t *testing.T) *Weights {
	t.Helper()
	w, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func finding(layer model.Layer, path, symbol, primitive, quantum string, confidence float64) model.Finding {
	return model.NewFinding(model.Asset{Primitive: primitive, Algorithm: "X", Params: "x", Quantum: quantum},
		model.Location{Layer: layer, Path: path, Line: 1, Symbol: symbol}, confidence)
}

func TestExposure(t *testing.T) {
	w := weights(t)
	tests := []struct {
		layer        model.Layer
		path, symbol string
		want         string
	}{
		{model.LayerNetwork, "example.org:443", "", ExposureNetwork},
		{model.LayerConfig, "etc/nginx/nginx.conf", "", ExposureNetwork},
		{model.LayerSource, "server/tls.go", "crypto/tls.X25519", ExposureNetwork},
		{model.LayerSource, "app/conn.py", "ssl.SSLContext.set_ecdh_curve", ExposureNetwork},
		{model.LayerSource, "app/sign.go", "crypto/rsa.SignPKCS1v15", ExposureInternal},
		{model.LayerDeps, "go.mod", "", ExposureInternal},
		{model.LayerBinary, "bin/app", "", ExposureInternal},
		{model.LayerSource, "server/tls_test.go", "crypto/tls.X25519", ExposureTest},
		{model.LayerSource, "tests/test_crypto.py", "hashlib.md5", ExposureTest},
		{model.LayerSource, "pkg/test_util.py", "hashlib.md5", ExposureTest},
		{model.LayerSource, "Examples/demo/main.go", "crypto/rsa.GenerateKey", ExposureTest},
		{model.LayerSource, "testdata/corpus/go/g01/main.go", "crypto/rsa.GenerateKey", ExposureTest},
		{model.LayerSource, `src\test\Foo.java`, "", ExposureTest},
		{model.LayerSource, "conftest.py", "", ExposureTest},
		{model.LayerSource, "src/main/java/FooTest.java", "", ExposureTest},
		{model.LayerSource, "src/main/java/Latest.java", "", ExposureInternal},
		{model.LayerSource, "pkg/contest.py", "", ExposureInternal},
		{model.LayerSource, "latest/attestation.go", "crypto/ecdsa.Sign", ExposureInternal},
		{model.LayerConfig, "test/fixtures/sshd_config", "", ExposureTest},
	}
	for _, tt := range tests {
		f := finding(tt.layer, tt.path, tt.symbol, "signature", "vulnerable", 1)
		if got := w.ExposureOf(f); got != tt.want {
			t.Errorf("ExposureOf(%s %s %s) = %s, want %s", tt.layer, tt.path, tt.symbol, got, tt.want)
		}
	}
}

func TestScore(t *testing.T) {
	w := weights(t)
	tests := []struct {
		name string
		f    model.Finding
		want float64
	}{
		{"tls key exchange", finding(model.LayerSource, "srv/main.go", "crypto/tls.CurveP256", "key-agreement", "vulnerable", 0.9), 1.0 * 1.0 * 0.9 * 0.9},
		{"internal signature", finding(model.LayerSource, "app/sign.go", "crypto/rsa.SignPSS", "signature", "vulnerable", 0.95), 0.6 * 0.5 * 0.9 * 0.95},
		{"test md5", finding(model.LayerSource, "a_test.go", "crypto/md5.Sum", "hash", "broken-now", 0.95), 0.2 * 0.3 * 1.0 * 0.95},
		{"safe is zero", finding(model.LayerNetwork, "h:443", "", "kem", "safe", 1), 0},
		{"hybrid on the wire", finding(model.LayerNetwork, "h:443", "", "kem", "hybrid", 1), 0.05},
		{"unresolved params lower confidence", finding(model.LayerSource, "app/k.go", "crypto/rsa.GenerateKey", "signature", "vulnerable", 0.76), 0.6 * 0.5 * 0.9 * 0.76},
	}
	for _, tt := range tests {
		got := w.Score(tt.f)
		want := float64(int(tt.want*1000+0.5)) / 1000
		if got != want {
			t.Errorf("%s: Score = %v, want %v", tt.name, got, want)
		}
		if got < 0 || got > 1 {
			t.Errorf("%s: score %v outside [0,1]", tt.name, got)
		}
	}
}

// The ordering the spec asks for: network > internal > test, and key exchange
// above signatures, all else equal.
func TestOrdering(t *testing.T) {
	w := weights(t)
	net := w.Score(finding(model.LayerNetwork, "h:443", "", "key-agreement", "vulnerable", 0.9))
	internal := w.Score(finding(model.LayerSource, "app/x.go", "crypto/ecdh.P256", "key-agreement", "vulnerable", 0.9))
	test := w.Score(finding(model.LayerSource, "app/x_test.go", "crypto/ecdh.P256", "key-agreement", "vulnerable", 0.9))
	sig := w.Score(finding(model.LayerSource, "app/x.go", "crypto/ecdsa.Sign", "signature", "vulnerable", 0.9))
	if !(net > internal && internal > test) {
		t.Errorf("exposure ordering: network %v, internal %v, test %v", net, internal, test)
	}
	if !(internal > sig) {
		t.Errorf("key agreement %v should outrank signature %v", internal, sig)
	}
}

func TestApply(t *testing.T) {
	w := weights(t)
	fs := []model.Finding{finding(model.LayerNetwork, "h:443", "", "kem", "vulnerable", 1)}
	w.Apply(fs)
	if fs[0].Risk != 0.9 {
		t.Errorf("Risk = %v", fs[0].Risk)
	}
}

func TestParseRejects(t *testing.T) {
	base := string(weightsYAML)
	tests := []struct{ name, doc, want string }{
		{"missing primitive", strings.Replace(base, "  mac: 0.3\n", "", 1), `no weight for "mac"`},
		{"out of range", strings.Replace(base, "network: 1.0", "network: 1.5", 1), "outside [0,1]"},
		{"unknown status", strings.Replace(base, "  safe: 0.0\n", "  safe: 0.0\n  doomed: 1\n", 1), `unknown key "doomed"`},
		{"unknown field", base + "extra: 1\n", "extra"},
		{"bad layer", strings.Replace(base, "network_layers: [network, config]", "network_layers: [network, cloud]", 1), "unknown layer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.doc == base {
				t.Fatal("case did not change the weights")
			}
			if _, err := Parse([]byte(tt.doc)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
