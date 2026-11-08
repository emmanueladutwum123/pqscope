// Package sarif converts findings to a SARIF 2.1.0 log, the format GitHub code
// scanning ingests.
//
// One SARIF rule is written per pqscope rule ID that produced a finding. A
// result's level follows the asset's quantum status: broken-now is an error,
// vulnerable a warning, and weakened, hybrid and safe assets are notes, so the
// inventory stays visible without failing a build. Policy verdicts arrive in
// milestone 4 and do not change the level yet.
package sarif

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"slices"

	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Version is the SARIF version written.
const Version = "2.1.0"

const (
	schemaURL  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	projectURL = "https://github.com/emmanueladutwum123/pqscope"
	// SrcRoot is the uriBaseId that artifact paths are relative to: the
	// scanned directory.
	SrcRoot = "%SRCROOT%"
	// FingerprintKey names the partial fingerprint holding the finding ID.
	FingerprintKey = "pqscopeFindingId/v1"
)

// Rule describes a pqscope rule. Fields may be empty.
type Rule struct {
	Description string
	Notes       string
	HelpURI     string
}

// Options configures the log.
type Options struct {
	ToolVersion string
	Rules       map[string]Rule // keyed by rule ID
}

// Log is a SARIF log, limited to the fields pqscope writes.
type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is one invocation of pqscope.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool identifies pqscope.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver describes pqscope and the rules it ran.
type Driver struct {
	Name           string                `json:"name"`
	Version        string                `json:"version,omitempty"`
	InformationURI string                `json:"informationUri"`
	Rules          []ReportingDescriptor `json:"rules"`
}

// ReportingDescriptor describes a rule.
type ReportingDescriptor struct {
	ID               string          `json:"id"`
	ShortDescription *Message        `json:"shortDescription,omitempty"`
	FullDescription  *Message        `json:"fullDescription,omitempty"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       *RuleProperties `json:"properties,omitempty"`
}

// RuleProperties is a rule's property bag.
type RuleProperties struct {
	Tags []string `json:"tags"`
}

// Message is SARIF text.
type Message struct {
	Text string `json:"text"`
}

// Result is one finding.
type Result struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          ResultProperties  `json:"properties"`
}

// Location is where a result was found: a file region, or a logical location
// such as a network endpoint.
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []LogicalLocation `json:"logicalLocations,omitempty"`
}

// PhysicalLocation is a file and an optional region.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

// ArtifactLocation is a URI relative to SrcRoot.
type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

// Region is a line, with the evidence as its snippet.
type Region struct {
	StartLine int      `json:"startLine"`
	Snippet   *Message `json:"snippet,omitempty"`
}

// LogicalLocation names something that is not a file.
type LogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}

// ResultProperties carries the finding's asset and scores.
type ResultProperties struct {
	Primitive  string               `json:"primitive"`
	Algorithm  string               `json:"algorithm"`
	Params     string               `json:"params"`
	Quantum    string               `json:"quantum"`
	Layer      model.Layer          `json:"layer"`
	Confidence float64              `json:"confidence"`
	Symbol     string               `json:"symbol,omitempty"`
	Migration  string               `json:"migration,omitempty"`
	Policy     []model.PolicyResult `json:"policy,omitempty"`
	Risk       float64              `json:"risk,omitempty"`
	Tags       []string             `json:"tags"`
}

// Level returns the SARIF level for a quantum status.
func Level(quantum string) string {
	switch quantum {
	case model.QuantumBrokenNow:
		return "error"
	case model.QuantumVulnerable:
		return "warning"
	default:
		return "note"
	}
}

var statusPhrase = map[string]string{
	model.QuantumBrokenNow:  "is broken today, without a quantum computer",
	model.QuantumVulnerable: "is quantum-vulnerable",
	model.QuantumWeakened:   "is weakened, not broken, by quantum attack",
	model.QuantumHybrid:     "is a post-quantum hybrid",
	model.QuantumSafe:       "is post-quantum",
}

// fallbackRuleID is used for findings without a rule ID.
func fallbackRuleID(l model.Layer) string { return "pqscope." + string(l) }

// Build converts findings to a SARIF log with one run.
func Build(db *knowledge.DB, findings []model.Finding, opts Options) *Log {
	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[cmp.Or(f.RuleID, fallbackRuleID(f.Location.Layer))] = true
	}
	ids := make([]string, 0, len(ruleIDs))
	for id := range ruleIDs {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	driver := Driver{Name: "pqscope", Version: opts.ToolVersion, InformationURI: projectURL, Rules: []ReportingDescriptor{}}
	index := map[string]int{}
	for i, id := range ids {
		index[id] = i
		r := opts.Rules[id]
		d := ReportingDescriptor{
			ID:               id,
			ShortDescription: &Message{cmp.Or(r.Description, "pqscope rule "+id)},
			HelpURI:          r.HelpURI,
			Properties:       &RuleProperties{Tags: []string{"cryptography", "post-quantum"}},
		}
		if r.Notes != "" {
			d.FullDescription = &Message{r.Notes}
		}
		driver.Rules = append(driver.Rules, d)
	}

	results := make([]Result, 0, len(findings))
	for _, f := range findings {
		id := cmp.Or(f.RuleID, fallbackRuleID(f.Location.Layer))
		results = append(results, result(db, f, id, index[id]))
	}
	return &Log{Schema: schemaURL, Version: Version, Runs: []Run{{Tool: Tool{Driver: driver}, Results: results}}}
}

// Write builds a log and writes it as indented JSON.
func Write(w io.Writer, db *knowledge.DB, findings []model.Finding, opts Options) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Build(db, findings, opts))
}

func result(db *knowledge.DB, f model.Finding, ruleID string, ruleIndex int) Result {
	a := f.Asset
	name := db.Name(a)
	detail := a.Primitive
	if a.Params == model.ParamsUnknown {
		detail += ", parameters unknown"
	}
	text := fmt.Sprintf("%s (%s) %s.", name, detail, cmp.Or(statusPhrase[a.Quantum], "has quantum status "+a.Quantum))
	migration := db.Migration(a)
	if migration != "" {
		text += " Migrate to " + migration + "."
	}

	var loc Location
	if f.Location.Layer == model.LayerNetwork {
		loc.LogicalLocations = []LogicalLocation{{FullyQualifiedName: f.Location.Path, Kind: "endpoint"}}
	} else {
		pl := &PhysicalLocation{ArtifactLocation: ArtifactLocation{URI: fileURI(f.Location.Path), URIBaseID: SrcRoot}}
		if f.Location.Line > 0 {
			pl.Region = &Region{StartLine: f.Location.Line}
			if f.Evidence != "" {
				pl.Region.Snippet = &Message{f.Evidence}
			}
		}
		loc.PhysicalLocation = pl
	}

	return Result{
		RuleID:              ruleID,
		RuleIndex:           ruleIndex,
		Level:               Level(a.Quantum),
		Message:             Message{text},
		Locations:           []Location{loc},
		PartialFingerprints: map[string]string{FingerprintKey: f.ID},
		Properties: ResultProperties{
			Primitive:  a.Primitive,
			Algorithm:  a.Algorithm,
			Params:     a.Params,
			Quantum:    a.Quantum,
			Layer:      f.Location.Layer,
			Confidence: math.Round(f.Confidence*1000) / 1000, // write 0.76, not 0.7600000000000001
			Symbol:     f.Location.Symbol,
			Migration:  migration,
			Policy:     f.Policy,
			Risk:       f.Risk,
			Tags:       []string{"quantum:" + a.Quantum},
		},
	}
}

// fileURI turns a slash-separated relative path into a relative URI
// reference, escaping characters such as spaces.
func fileURI(path string) string {
	return (&url.URL{Path: path}).String()
}
