// Package config is the configuration and key-material layer. It reads TLS
// and SSH server configuration (nginx, Apache httpd, sshd_config and
// ssh_config, openssl.cnf, Kubernetes ingress and cert-manager resources) and
// key material (PEM and DER certificates, public and private keys, CSRs, DH
// parameters, OpenSSH keys and Kubernetes TLS Secrets).
//
// Private key material is never output. A private key is reported by its
// algorithm, size, the fingerprint of its public half, and its path; findings
// carry no bytes, encodings or digests of the private key itself.
package config

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/emmanueladutwum123/pqscope/internal/discover/walk"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Confidence values. A configured name is explicit, but the server software
// may not support it; parsed key material is exact.
const (
	DirectiveConfidence = 0.9
	MaterialConfidence  = 1.0
)

// MaxFileSize bounds the files read, in bytes.
const MaxFileSize = 1 << 20

// Result is the outcome of a config scan.
type Result struct {
	Findings     []model.Finding
	FilesScanned int
	Skipped      []walk.Skipped
	// Notes record material that was seen but could not be classified, such
	// as an encrypted PKCS#8 key, as "path: line N: reason".
	Notes []string
}

// Scanner reads configuration and key material.
type Scanner struct {
	db    *knowledge.DB
	names names
}

// New returns a Scanner using the embedded name tables.
func New(db *knowledge.DB) (*Scanner, error) {
	n, err := parseNames(db, namesYAML)
	if err != nil {
		return nil, err
	}
	return &Scanner{db: db, names: n}, nil
}

type fileKind int

const (
	kindNone fileKind = iota
	kindServerConf
	kindSSHConf
	kindOpenSSLConf
	kindKubernetes
	kindKeyMaterial // PEM, DER or OpenSSH public keys
	kindSniff       // any other text file: scanned for PEM blocks only
)

var keyExts = map[string]bool{".pem": true, ".crt": true, ".cer": true, ".key": true, ".csr": true, ".pub": true, ".der": true, ".p8": true, ".pk8": true}

// noSniff lists extensions not searched for embedded PEM blocks: source code
// (test vectors there belong to the source layer) and documentation (example
// keys in prose), plus files the other layers own.
var noSniff = map[string]bool{
	".go": true, ".py": true, ".java": true, ".js": true, ".ts": true, ".c": true, ".h": true, ".cc": true, ".cpp": true,
	".rs": true, ".rb": true, ".php": true, ".cs": true, ".kt": true, ".swift": true, ".scala": true,
	".md": true, ".rst": true, ".html": true, ".adoc": true,
	".lock": true, ".sum": true, ".mod": true,
	".png": true, ".jpg": true, ".gif": true, ".pdf": true, ".zip": true, ".gz": true, ".tar": true,
}

func classify(rel string) fileKind {
	base := path.Base(rel)
	dir := path.Base(path.Dir(rel))
	ext := strings.ToLower(path.Ext(base))
	switch {
	case base == "sshd_config" || base == "ssh_config" || dir == "sshd_config.d" || dir == "ssh_config.d":
		return kindSSHConf
	case ext == ".cnf":
		return kindOpenSSLConf
	case ext == ".conf" || dir == "sites-available" || dir == "sites-enabled":
		return kindServerConf
	case ext == ".yaml" || ext == ".yml":
		return kindKubernetes
	case keyExts[ext] || base == "authorized_keys" || strings.HasPrefix(base, "id_rsa") || strings.HasPrefix(base, "id_dsa") ||
		strings.HasPrefix(base, "id_ecdsa") || strings.HasPrefix(base, "id_ed25519") ||
		(strings.HasPrefix(base, "ssh_host_") && strings.Contains(base, "_key")):
		return kindKeyMaterial
	case noSniff[ext], base == "go.mod", base == "go.sum", base == "package-lock.json", base == "pom.xml":
		return kindNone
	}
	return kindSniff
}

// Scan reads every configuration and key file under root.
func (s *Scanner) Scan(ctx context.Context, root string) (Result, error) {
	files, err := walk.Files(root, func(rel string) bool { return classify(rel) != kindNone })
	if err != nil {
		return Result{}, err
	}
	var res Result
	seen := map[string]bool{}
	add := func(f model.Finding) {
		if !seen[f.ID] {
			seen[f.ID] = true
			res.Findings = append(res.Findings, f)
		}
	}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		info, err := os.Stat(f.Path)
		if err != nil {
			return Result{}, err
		}
		kind := classify(f.Rel)
		if info.Size() > MaxFileSize {
			if kind != kindSniff {
				res.Skipped = append(res.Skipped, walk.Skipped{Path: f.Rel, Reason: fmt.Sprintf("larger than %d bytes", MaxFileSize)})
			}
			continue
		}
		data, err := os.ReadFile(f.Path)
		if err != nil {
			return Result{}, err
		}
		if kind == kindSniff && !strings.Contains(string(data), "-----BEGIN ") {
			continue
		}
		findings, notes := s.scanFile(f.Rel, kind, data)
		// YAML that is not a Kubernetes resource, and text with no key
		// material, does not count as scanned.
		if (kind != kindSniff && kind != kindKubernetes) || len(findings) > 0 || len(notes) > 0 {
			res.FilesScanned++
		}
		for _, fd := range findings {
			add(fd)
		}
		for _, n := range notes {
			res.Notes = append(res.Notes, f.Rel+": "+n)
		}
	}
	return res, nil
}

// ScanFile scans one file's contents; rel decides how it is read.
func (s *Scanner) ScanFile(rel string, data []byte) ([]model.Finding, []string) {
	return s.scanFile(rel, classify(rel), data)
}

func (s *Scanner) scanFile(rel string, kind fileKind, data []byte) ([]model.Finding, []string) {
	var out []model.Finding
	var notes []string
	directives := func(ds []directive) {
		for _, d := range ds {
			for _, a := range s.resolve(d) {
				f := model.NewFinding(a, model.Location{Layer: model.LayerConfig, Path: rel, Line: d.line, Symbol: d.symbol}, DirectiveConfidence)
				f.RuleID = "config." + strings.SplitN(d.symbol, ":", 2)[0]
				f.Evidence = evidence(d.text)
				out = append(out, f)
			}
		}
	}
	materials := func(ms []material, rule string) {
		for _, m := range ms {
			f := model.NewFinding(m.asset, model.Location{Layer: model.LayerConfig, Path: rel, Line: m.line, Symbol: m.symbol}, MaterialConfidence)
			f.RuleID = rule
			f.Evidence = m.evidence
			out = append(out, f)
		}
	}
	switch kind {
	case kindServerConf:
		directives(parseServerConf(data))
	case kindSSHConf:
		directives(parseSSHConf(data))
	case kindOpenSSLConf:
		directives(parseOpenSSLConf(data))
	case kindKubernetes:
		for _, it := range s.parseKubernetes(data) {
			if it.directive != nil {
				directives([]directive{*it.directive})
			}
			materials(it.material, "config.k8s")
			notes = append(notes, it.notes...)
		}
	case kindKeyMaterial, kindSniff:
		ms, ns := s.keyMaterial(data, 1, kind == kindKeyMaterial)
		if len(ms) == 0 && kind == kindKeyMaterial {
			ms = s.authorizedKeys(data)
		}
		materials(ms, "config.key-material")
		notes = append(notes, ns...)
	}
	return out, notes
}

// evidence trims a directive line to 160 runes.
func evidence(line string) string {
	line = strings.TrimSpace(line)
	if utf8.RuneCountInString(line) > 160 {
		r := []rune(line)
		line = string(r[:160]) + "…"
	}
	return line
}

// Lookup resolves one name in a name table, with the normalisation the
// config parsers apply: "tls-groups", "tls13-suites", "tls-ciphers" (an
// OpenSSL cipher name), "ssh-kex", "ssh-pubkey", "ssh-ciphers" or
// "ssh-macs". Unknown names and tables resolve to nothing.
func (s *Scanner) Lookup(table, name string) []model.Asset {
	switch table {
	case "tls-ciphers":
		return s.cipher(name)
	case "ssh-kex":
		return s.ssh(sshKex, name)
	case "ssh-pubkey":
		return s.ssh(sshPubkey, name)
	case "ssh-ciphers":
		return s.ssh(sshCiphers, name)
	case "ssh-macs":
		return s.ssh(sshMACs, name)
	case "tls-groups", "tls13-suites":
		return s.names.lookup(table, name)
	}
	return nil
}

// Material is one asset found in key material.
type Material struct {
	Asset    model.Asset
	Symbol   string
	Evidence string
}

// Certificate classifies a DER certificate: its subject key, the issuer's
// signature algorithm and that signature's digest.
func (s *Scanner) Certificate(der []byte) []Material {
	var out []Material
	for _, m := range s.certificate(der, 0) {
		out = append(out, Material{m.asset, m.symbol, m.evidence})
	}
	return out
}
