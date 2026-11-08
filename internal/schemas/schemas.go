// Package schemas validates pqscope output against the official CycloneDX 1.6
// and SARIF 2.1.0 JSON schemas, which are vendored in this directory. See
// README.md for where each file comes from.
package schemas

import (
	"bytes"
	"embed"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed *.json
var files embed.FS

// Schema IDs, as declared by the vendored files. References between the
// CycloneDX files resolve relative to these.
const (
	CycloneDXID = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	SARIFID     = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)

var resources = map[string]string{
	CycloneDXID: "bom-1.6.schema.json",
	"http://cyclonedx.org/schema/spdx.schema.json":     "spdx.schema.json",
	"http://cyclonedx.org/schema/jsf-0.82.schema.json": "jsf-0.82.schema.json",
	SARIFID: "sarif-schema-2.1.0.json",
}

// offline refuses every URL, so a reference to anything not vendored here
// fails instead of reaching the network.
type offline struct{}

func (offline) Load(url string) (any, error) {
	return nil, fmt.Errorf("schemas: %s is not vendored", url)
}

var compiled = sync.OnceValues(func() (map[string]*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.UseLoader(offline{})
	c.AssertFormat()
	for url, name := range resources {
		data, err := files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("schemas: %s: %w", name, err)
		}
		if err := c.AddResource(url, doc); err != nil {
			return nil, fmt.Errorf("schemas: %s: %w", name, err)
		}
	}
	out := make(map[string]*jsonschema.Schema, 2)
	for _, id := range []string{CycloneDXID, SARIFID} {
		s, err := c.Compile(id)
		if err != nil {
			return nil, fmt.Errorf("schemas: compiling %s: %w", id, err)
		}
		out[id] = s
	}
	return out, nil
})

// ValidateCycloneDX reports whether data is a valid CycloneDX 1.6 JSON BOM.
func ValidateCycloneDX(data []byte) error { return validate(CycloneDXID, data) }

// ValidateSARIF reports whether data is a valid SARIF 2.1.0 log.
func ValidateSARIF(data []byte) error { return validate(SARIFID, data) }

func validate(id string, data []byte) error {
	schemas, err := compiled()
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("schemas: decoding document: %w", err)
	}
	return schemas[id].Validate(doc)
}
