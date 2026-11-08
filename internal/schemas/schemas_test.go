package schemas

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVendoredFilesUnchanged(t *testing.T) {
	want := map[string]string{
		"bom-1.6.schema.json":     "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d",
		"spdx.schema.json":        "c41917196639055e9f9670811bac23ef777732144f3ff5a2f39686f61580dbe6",
		"jsf-0.82.schema.json":    "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
		"sarif-schema-2.1.0.json": "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e",
	}
	for name, sum := range want {
		data, err := files.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s has changed; see README.md", name)
		}
	}
}

// The validators must reject documents, not just accept everything.
func TestValidate(t *testing.T) {
	tests := []struct {
		name     string
		validate func([]byte) error
		doc      string
		wantErr  string
	}{
		{"minimal bom", ValidateCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.6"}`, ""},
		{"crypto component", ValidateCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
			{"type":"cryptographic-asset","name":"RSA-2048","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"signature"}}}]}`, ""},
		{"wrong format", ValidateCycloneDX, `{"bomFormat":"SPDX","specVersion":"1.6"}`, "bomFormat"},
		{"unknown crypto primitive", ValidateCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
			{"type":"cryptographic-asset","name":"X","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"key-agreement"}}}]}`, "primitive"},
		{"bad timestamp format", ValidateCycloneDX, `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"yesterday"}}`, "timestamp"},
		{"minimal sarif", ValidateSARIF, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`, ""},
		{"sarif without driver", ValidateSARIF, `{"version":"2.1.0","runs":[{"tool":{},"results":[]}]}`, "driver"},
		{"sarif bad level", ValidateSARIF, `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"message":{"text":"m"},"level":"fatal"}]}]}`, "level"},
		{"sarif unknown property", ValidateSARIF, `{"version":"2.1.0","runs":[],"extra":1}`, "extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.validate([]byte(tt.doc))
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
