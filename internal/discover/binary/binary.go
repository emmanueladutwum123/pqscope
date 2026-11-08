// Package binary is the binary layer. It reads ELF, PE and Mach-O files
// (including universal Mach-O) and reports:
//
//   - imported symbols of known crypto libraries, such as RSA_new or
//     EVP_sha256, and the same symbols when defined in a statically linked,
//     unstripped binary;
//   - for Go binaries, the module versions in the build info, which become
//     dependency-layer capability findings, and the crypto functions the
//     linker kept, read from the function table that survives stripping;
//   - as a low-confidence fallback for binaries with no recognised symbols,
//     known constants: curve primes, the SHA-256 initial value, and DER OIDs.
//
// Symbol and constant tables live in symbols.yaml, each entry cited.
package binary

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/discover/deps"
	"github.com/emmanueladutwum123/pqscope/internal/discover/source"
	"github.com/emmanueladutwum123/pqscope/internal/discover/walk"
	"github.com/emmanueladutwum123/pqscope/internal/knowledge"
	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// Confidence values by evidence kind.
const (
	ImportConfidence   = 0.8 // a dynamic import: the binary calls the function
	SymbolConfidence   = 0.7 // a defined symbol: the code is linked in
	GoFuncConfidence   = 0.8 // a Go function the linker kept as reachable
	GoPkgConfidence    = 0.7 // functions of a Go crypto package are linked
	ConstantConfidence = 0.4 // a byte pattern: suggestive, not proof
)

// MaxConstantScan bounds the bytes read for the constant fallback.
const MaxConstantScan = 256 << 20

// Result is the outcome of a binary scan.
type Result struct {
	Findings     []model.Finding
	FilesScanned int
	Skipped      []walk.Skipped
	Notes        []string
}

// Scanner reads binaries.
type Scanner struct {
	db     *knowledge.DB
	table  *table
	deps   *deps.Scanner
	goSyms map[string]source.SymbolAsset
}

// New returns a Scanner. goSymbols maps Go function names to assets, from
// the source layer's Go rule pack.
func New(db *knowledge.DB, libs *knowledge.Libs, goSymbols map[string]source.SymbolAsset) (*Scanner, error) {
	t, err := parseTable(db, symbolsYAML)
	if err != nil {
		return nil, err
	}
	return &Scanner{db: db, table: t, deps: deps.New(db, libs), goSyms: goSymbols}, nil
}

// textExts are skipped without opening: they are never executables.
var textExts = map[string]bool{
	".go": true, ".py": true, ".md": true, ".txt": true, ".json": true, ".yaml": true, ".yml": true,
	".toml": true, ".xml": true, ".html": true, ".css": true, ".js": true, ".ts": true, ".c": true, ".h": true,
	".pem": true, ".crt": true, ".key": true, ".conf": true, ".cnf": true, ".sh": true, ".mod": true, ".sum": true, ".lock": true,
}

// Scan reads every executable or library under root.
func (s *Scanner) Scan(ctx context.Context, root string) (Result, error) {
	files, err := walk.Files(root, func(rel string) bool { return !textExts[strings.ToLower(path.Ext(rel))] })
	if err != nil {
		return Result{}, err
	}
	var res Result
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		format, err := detect(f.Path)
		if err != nil {
			return Result{}, err
		}
		if format == "" {
			continue
		}
		findings, notes, err := s.ScanFile(f.Path, f.Rel, format)
		if err != nil {
			res.Skipped = append(res.Skipped, walk.Skipped{Path: f.Rel, Reason: err.Error()})
			continue
		}
		res.FilesScanned++
		res.Findings = append(res.Findings, findings...)
		for _, n := range notes {
			res.Notes = append(res.Notes, f.Rel+": "+n)
		}
	}
	return res, nil
}

// detect returns "elf", "pe", "macho", "fat" or "" from a file's magic.
func detect(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only
	var head [8]byte
	if _, err := io.ReadFull(f, head[:]); err != nil {
		return "", nil // shorter than any binary header
	}
	switch {
	case bytes.Equal(head[:4], []byte{0x7f, 'E', 'L', 'F'}):
		return "elf", nil
	case head[0] == 'M' && head[1] == 'Z':
		return "pe", nil
	}
	switch binary.BigEndian.Uint32(head[:4]) {
	case macho.Magic32, macho.Magic64, 0xcefaedfe, 0xcffaedfe:
		return "macho", nil
	case macho.MagicFat:
		// Java class files share 0xcafebabe; their next word is a version
		// (45 or more), a fat header's is a small architecture count.
		if n := binary.BigEndian.Uint32(head[4:]); n > 0 && n < 20 {
			return "fat", nil
		}
	}
	return "", nil
}

// symbols are the names a binary imports and defines, and its libraries.
type symbols struct {
	imports, defined, libraries []string
	textAddr                    uint64
	pclntab                     []byte
}

// clean strips Mach-O's leading underscore, ELF symbol versions and PE's
// "name:dll" form.
func clean(name, format string) string {
	if format == "macho" || format == "fat" {
		name = strings.TrimPrefix(name, "_")
	}
	if i := strings.IndexAny(name, "@:"); i > 0 {
		name = name[:i]
	}
	return name
}

func readSymbols(p, format string) (symbols, error) {
	var s symbols
	switch format {
	case "elf":
		f, err := elf.Open(p)
		if err != nil {
			return s, err
		}
		defer func() { _ = f.Close() }()
		imps, _ := f.ImportedSymbols()
		for _, i := range imps {
			s.imports = append(s.imports, i.Name)
		}
		s.libraries, _ = f.ImportedLibraries()
		for _, get := range []func() ([]elf.Symbol, error){f.DynamicSymbols, f.Symbols} {
			syms, _ := get()
			for _, sym := range syms {
				if sym.Section != elf.SHN_UNDEF && elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
					s.defined = append(s.defined, sym.Name)
				}
			}
		}
		if sec := f.Section(".gopclntab"); sec != nil {
			s.pclntab, _ = sec.Data()
		}
		if sec := f.Section(".text"); sec != nil {
			s.textAddr = sec.Addr
		}
	case "pe":
		f, err := pe.Open(p)
		if err != nil {
			return s, err
		}
		defer func() { _ = f.Close() }()
		s.imports, _ = f.ImportedSymbols()
		// debug/pe does not implement ImportedLibraries; imports are "name:dll".
		for _, imp := range s.imports {
			if _, dll, ok := strings.Cut(imp, ":"); ok && !slices.Contains(s.libraries, dll) {
				s.libraries = append(s.libraries, dll)
			}
		}
		for _, sym := range f.Symbols {
			if sym.SectionNumber > 0 {
				s.defined = append(s.defined, sym.Name)
			}
		}
		if sec := f.Section(".text"); sec != nil {
			s.textAddr = uint64(sec.VirtualAddress)
		}
	case "macho":
		f, err := macho.Open(p)
		if err != nil {
			return s, err
		}
		defer func() { _ = f.Close() }()
		readMachO(f, &s)
	case "fat":
		ff, err := macho.OpenFat(p)
		if err != nil {
			return s, err
		}
		defer func() { _ = ff.Close() }()
		for _, a := range ff.Arches {
			readMachO(a.File, &s)
		}
	}
	return s, nil
}

func readMachO(f *macho.File, s *symbols) {
	imps, _ := f.ImportedSymbols()
	s.imports = append(s.imports, imps...)
	libs, _ := f.ImportedLibraries()
	s.libraries = append(s.libraries, libs...)
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			if sym.Sect != 0 {
				s.defined = append(s.defined, sym.Name)
			}
		}
	}
	if sec := f.Section("__gopclntab"); sec != nil && s.pclntab == nil {
		s.pclntab, _ = sec.Data()
	}
	if sec := f.Section("__text"); sec != nil && s.textAddr == 0 {
		s.textAddr = sec.Addr
	}
}

// group collects the symbols that resolve to one asset, by evidence kind.
type group struct {
	asset model.Asset
	kind  string
	names []string
}

// ScanFile scans one binary. rel is the path recorded in findings.
func (s *Scanner) ScanFile(p, rel, format string) ([]model.Finding, []string, error) {
	syms, err := readSymbols(p, format)
	if err != nil {
		return nil, nil, fmt.Errorf("unreadable %s: %w", format, err)
	}
	var notes []string
	groups := map[string]*group{}
	var order []string
	add := func(a model.Asset, kind, name string) {
		key := kind + "|" + a.Algorithm + "|" + a.Params + "|" + a.Primitive
		g, ok := groups[key]
		if !ok {
			g = &group{asset: a, kind: kind}
			groups[key] = g
			order = append(order, key)
		}
		if !slices.Contains(g.names, name) {
			g.names = append(g.names, name)
		}
	}
	var generic []string
	for kind, names := range map[string][]string{"import": syms.imports, "symbol": syms.defined} {
		for _, raw := range names {
			name := clean(raw, format)
			if a, ok := s.table.lookup(name); ok {
				add(a, kind, name)
			} else if kind == "import" && s.table.generic[name] && !slices.Contains(generic, name) {
				generic = append(generic, name)
			}
		}
	}

	var out []model.Finding
	if bi, err := buildinfo.ReadFile(p); err == nil {
		out = append(out, s.goBuildInfo(rel, bi)...)
		for _, fn := range goFunctions(p, syms) {
			if sa, ok := s.goSyms[fn]; ok {
				add(sa.Asset, "go", fn)
			} else if a, pkg, ok := s.table.lookupGoPackage(fn); ok {
				add(a, "go-package", pkg)
			}
		}
	}

	if len(groups) == 0 {
		if found, err := s.constants(p); err != nil {
			notes = append(notes, "constant scan: "+err.Error())
		} else {
			for _, c := range found {
				add(c.asset, "constant", c.name)
			}
		}
	}

	libs := ""
	if len(syms.libraries) > 0 {
		slices.Sort(syms.libraries)
		libs = " (links " + strings.Join(slices.Compact(syms.libraries), ", ") + ")"
	}
	slices.Sort(order)
	for _, key := range order {
		g := groups[key]
		slices.Sort(g.names)
		f := model.NewFinding(g.asset, model.Location{Layer: model.LayerBinary, Path: rel, Symbol: g.kind + ":" + g.names[0]}, confidence[g.kind])
		f.RuleID = "binary." + g.kind
		f.Evidence = describe(g, format) + libs
		out = append(out, f)
	}
	if len(generic) > 0 {
		slices.Sort(generic)
		notes = append(notes, "imports algorithm-agnostic crypto APIs "+strings.Join(generic, ", ")+"; the algorithm is chosen at run time")
	}
	return out, notes, nil
}

var confidence = map[string]float64{
	"import": ImportConfidence, "symbol": SymbolConfidence, "go": GoFuncConfidence, "go-package": GoPkgConfidence,
	"constant": ConstantConfidence,
}

var formatNames = map[string]string{"elf": "ELF", "pe": "PE", "macho": "Mach-O", "fat": "universal Mach-O"}

var verbs = map[string]string{
	"import": "imports", "symbol": "defines", "go": "links Go functions", "go-package": "links Go packages",
	"constant": "contains",
}

func describe(g *group, format string) string {
	names := g.names
	more := ""
	if len(names) > 5 {
		more = fmt.Sprintf(" and %d more", len(names)-5)
		names = names[:5]
	}
	return fmt.Sprintf("%s binary %s %s%s", formatNames[format], verbs[g.kind], strings.Join(names, ", "), more)
}

// goBuildInfo turns a Go binary's build info into dependency capabilities:
// the toolchain as the standard library version, and each module.
func (s *Scanner) goBuildInfo(rel string, bi *buildinfo.BuildInfo) []model.Finding {
	origin := "Go build info (" + bi.GoVersion + ")"
	dep := func(name, version string) deps.Dependency {
		return deps.Dependency{Package: knowledge.Package{Ecosystem: "golang", Name: name}, Version: version}
	}
	out := s.deps.Capabilities(rel, origin, dep("stdlib", strings.TrimPrefix(bi.GoVersion, "go")))
	for _, m := range bi.Deps {
		if m.Replace != nil {
			m = m.Replace
		}
		out = append(out, s.deps.Capabilities(rel, origin, dep(m.Path, m.Version))...)
	}
	return out
}

// pclntabMagic starts a Go 1.20+ function table (little-endian 0xfffffff1).
var pclntabMagic = []byte{0xf1, 0xff, 0xff, 0xff, 0x00, 0x00}

// goFunctions returns the names in a Go binary's function table. The table
// is kept even when symbols are stripped. When there is no table section, as
// in PE, the file is searched for the table's header.
func goFunctions(p string, syms symbols) []string {
	data := syms.pclntab
	if data == nil {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for off := 0; ; {
			i := bytes.Index(raw[off:], pclntabMagic)
			if i < 0 {
				return nil
			}
			start := off + i
			// Header: magic, two zero bytes, instruction quantum, pointer size.
			if start+8 <= len(raw) && slices.Contains([]byte{1, 2, 4}, raw[start+6]) && slices.Contains([]byte{4, 8}, raw[start+7]) {
				data = raw[start:]
				break
			}
			off = start + 1
		}
	}
	tab, err := gosym.NewTable(nil, gosym.NewLineTable(data, syms.textAddr))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(tab.Funcs))
	for _, fn := range tab.Funcs {
		out = append(out, fn.Name)
	}
	return out
}

type constantHit struct {
	name  string
	asset model.Asset
}

// constants searches a file for the table's byte patterns.
func (s *Scanner) constants(p string) ([]constantHit, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxConstantScan))
	if err != nil {
		return nil, err
	}
	var out []constantHit
	for _, c := range s.table.constants {
		for _, pat := range c.patterns {
			if bytes.Contains(data, pat) {
				out = append(out, constantHit{c.name, c.asset})
				break
			}
		}
	}
	return out, nil
}
