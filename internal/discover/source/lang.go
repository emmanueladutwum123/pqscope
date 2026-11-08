package source

import (
	"slices"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"
)

// frontend holds the language-specific syntax knowledge the engine needs.
// Detection patterns live in the YAML rule packs, not here.
type frontend interface {
	// imports maps each local name to the fully qualified module it binds.
	collectImports(root *sitter.Node, src []byte) map[string]string
	// collectConsts maps names to their single assigned expression. A name
	// assigned more than one distinct expression maps to nil.
	collectConsts(root *sitter.Node, src []byte) map[string]*sitter.Node
	// skipSubtree reports nodes whose contents are never references (imports).
	skipSubtree(n *sitter.Node) bool
	callParts(n *sitter.Node) (fn, args *sitter.Node, ok bool)
	args(list *sitter.Node, src []byte) (positional []*sitter.Node, keyword map[string]*sitter.Node)
	// refCandidate reports whether n, reached from a parent of the given type
	// through the given field, can be a reference to an imported symbol.
	refCandidate(n *sitter.Node, parentType, field string) bool
	resolve(f *file, n *sitter.Node) (string, bool)
	literal(n *sitter.Node, src []byte) (string, bool)
	identifier(n *sitter.Node, src []byte) (string, bool)
	falseCondition(n *sitter.Node, src []byte) bool
	// dead reports whether the child of parent reached through field is dead
	// code, such as the body of `if false` or C's `#if 0`.
	dead(parent *sitter.Node, field string, src []byte) bool
	// property returns the value of key in an object literal, or nil.
	property(obj *sitter.Node, key string, src []byte) *sitter.Node
}

type language struct {
	name    string
	exts    []string
	grammar *sitter.Language            // the default grammar
	byExt   map[string]*sitter.Language // grammars for extensions that need another one
	front   frontend
}

func (l *language) grammarFor(ext string) *sitter.Language {
	if g, ok := l.byExt[ext]; ok {
		return g
	}
	return l.grammar
}

func (l *language) allGrammars() []*sitter.Language {
	out := []*sitter.Language{l.grammar}
	for _, g := range l.byExt {
		if !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	return out
}

// ifDead is the dead-code test for languages whose only recognised form is
// `if <false>` with the body in field "consequence".
func ifDead(front frontend, parent *sitter.Node, field string, src []byte) bool {
	return field == "consequence" && parent.Type() == "if_statement" && front.falseCondition(parent.ChildByFieldName("condition"), src)
}

var languages = map[string]*language{
	"go":     {name: "go", exts: []string{".go"}, grammar: golang.GetLanguage(), front: goFrontend{}},
	"python": {name: "python", exts: []string{".py"}, grammar: python.GetLanguage(), front: pyFrontend{}},
	"java":   {name: "java", exts: []string{".java"}, grammar: java.GetLanguage(), front: javaFrontend{}},
	"c": {
		name: "c", exts: []string{".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"},
		grammar: c.GetLanguage(),
		byExt: map[string]*sitter.Language{
			".cc": cpp.GetLanguage(), ".cpp": cpp.GetLanguage(), ".cxx": cpp.GetLanguage(),
			".hpp": cpp.GetLanguage(), ".hh": cpp.GetLanguage(), ".hxx": cpp.GetLanguage(),
		},
		front: cFrontend{},
	},
	"js": {
		name: "js", exts: []string{".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"},
		grammar: javascript.GetLanguage(),
		byExt: map[string]*sitter.Language{
			".ts": typescript.GetLanguage(), ".mts": typescript.GetLanguage(), ".cts": typescript.GetLanguage(),
			".tsx": tsx.GetLanguage(),
		},
		front: jsFrontend{},
	},
}

// children calls fn for every child of n with its field name.
func children(n *sitter.Node, fn func(c *sitter.Node, field string)) {
	for i := 0; i < int(n.ChildCount()); i++ {
		fn(n.Child(i), n.FieldNameForChild(i))
	}
}

func namedChildren(n *sitter.Node) []*sitter.Node {
	if n == nil {
		return nil
	}
	out := make([]*sitter.Node, 0, n.NamedChildCount())
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if c := n.NamedChild(i); c.Type() != "comment" {
			out = append(out, c)
		}
	}
	return out
}

// walk visits every node depth-first.
func walk(root *sitter.Node, fn func(n *sitter.Node) bool) {
	stack := []*sitter.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if !fn(n) {
			continue
		}
		for i := int(n.ChildCount()) - 1; i >= 0; i-- {
			stack = append(stack, n.Child(i))
		}
	}
}

// addConst records name = value, marking the name ambiguous on a conflicting
// second assignment.
func addConst(consts map[string]*sitter.Node, name string, value *sitter.Node, src []byte) {
	if prev, seen := consts[name]; seen {
		if prev == nil || prev.Content(src) != value.Content(src) {
			consts[name] = nil
		}
		return
	}
	consts[name] = value
}

// --- Go ---

type goFrontend struct{}

func (goFrontend) collectImports(root *sitter.Node, src []byte) map[string]string {
	out := make(map[string]string)
	walk(root, func(n *sitter.Node) bool {
		if n.Type() != "import_spec" {
			return true
		}
		pathNode := n.ChildByFieldName("path")
		if pathNode == nil {
			return false
		}
		path, err := strconv.Unquote(pathNode.Content(src))
		if err != nil {
			return false
		}
		name := goDefaultName(path)
		if alias := n.ChildByFieldName("name"); alias != nil {
			if alias.Type() != "package_identifier" {
				return false // dot and blank imports bind no name
			}
			name = alias.Content(src)
		}
		out[name] = path
		return false
	})
	return out
}

// goDefaultName guesses a package's name from its import path: the last
// element, skipping a major-version suffix like /v2 or .v3.
func goDefaultName(path string) string {
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	if len(parts) > 1 && isMajorVersion(last) {
		last = parts[len(parts)-2]
	}
	if i := strings.LastIndex(last, ".v"); i > 0 && isMajorVersion(last[i+1:]) {
		last = last[:i]
	}
	return last
}

func isMajorVersion(s string) bool {
	if len(s) < 2 || s[0] != 'v' {
		return false
	}
	_, err := strconv.Atoi(s[1:])
	return err == nil
}

func (goFrontend) collectConsts(root *sitter.Node, src []byte) map[string]*sitter.Node {
	out := make(map[string]*sitter.Node)
	pair := func(names []*sitter.Node, values []*sitter.Node) {
		if len(names) != len(values) {
			return
		}
		for i, n := range names {
			if n.Type() == "identifier" {
				addConst(out, n.Content(src), values[i], src)
			}
		}
	}
	walk(root, func(n *sitter.Node) bool {
		switch n.Type() {
		case "const_spec", "var_spec":
			var names []*sitter.Node
			children(n, func(c *sitter.Node, field string) {
				if field == "name" {
					names = append(names, c)
				}
			})
			pair(names, namedChildren(n.ChildByFieldName("value")))
		case "short_var_declaration", "assignment_statement":
			if op := n.ChildByFieldName("operator"); op != nil && op.Type() != "=" {
				return true
			}
			pair(namedChildren(n.ChildByFieldName("left")), namedChildren(n.ChildByFieldName("right")))
		}
		return true
	})
	return out
}

func (goFrontend) skipSubtree(n *sitter.Node) bool { return n.Type() == "import_declaration" }

func (goFrontend) callParts(n *sitter.Node) (fn, args *sitter.Node, ok bool) {
	if n.Type() != "call_expression" {
		return nil, nil, false
	}
	return n.ChildByFieldName("function"), n.ChildByFieldName("arguments"), true
}

func (goFrontend) args(list *sitter.Node, _ []byte) ([]*sitter.Node, map[string]*sitter.Node) {
	return namedChildren(list), nil
}

func (goFrontend) refCandidate(n *sitter.Node, _, _ string) bool {
	return n.Type() == "selector_expression"
}

func (goFrontend) resolve(f *file, n *sitter.Node) (string, bool) {
	if n == nil || n.Type() != "selector_expression" {
		return "", false
	}
	operand, field := n.ChildByFieldName("operand"), n.ChildByFieldName("field")
	if operand == nil || field == nil || operand.Type() != "identifier" {
		return "", false
	}
	path, ok := f.imports[operand.Content(f.src)]
	if !ok {
		return "", false
	}
	return path + "." + field.Content(f.src), true
}

func (goFrontend) literal(n *sitter.Node, src []byte) (string, bool) {
	text := n.Content(src)
	switch n.Type() {
	case "int_literal":
		return strings.ReplaceAll(text, "_", ""), true
	case "interpreted_string_literal":
		s, err := strconv.Unquote(text)
		return s, err == nil
	case "raw_string_literal":
		return strings.Trim(text, "`"), true
	}
	return "", false
}

func (goFrontend) identifier(n *sitter.Node, src []byte) (string, bool) {
	if n.Type() != "identifier" {
		return "", false
	}
	return n.Content(src), true
}

func (goFrontend) falseCondition(n *sitter.Node, _ []byte) bool {
	return n != nil && n.Type() == "false"
}

func (g goFrontend) dead(parent *sitter.Node, field string, src []byte) bool {
	return ifDead(g, parent, field, src)
}

func (goFrontend) property(*sitter.Node, string, []byte) *sitter.Node { return nil }

// --- Python ---

type pyFrontend struct{}

func (pyFrontend) collectImports(root *sitter.Node, src []byte) map[string]string {
	out := make(map[string]string)
	walk(root, func(n *sitter.Node) bool {
		switch n.Type() {
		case "import_statement":
			children(n, func(c *sitter.Node, field string) {
				if field != "name" {
					return
				}
				switch c.Type() {
				case "dotted_name":
					// "import a.b.c" binds a, which resolves as the module a.
					root := c.Content(src)
					if i := strings.IndexByte(root, '.'); i >= 0 {
						root = root[:i]
					}
					out[root] = root
				case "aliased_import":
					if name, alias := c.ChildByFieldName("name"), c.ChildByFieldName("alias"); name != nil && alias != nil {
						out[alias.Content(src)] = name.Content(src)
					}
				}
			})
			return false
		case "import_from_statement":
			module := n.ChildByFieldName("module_name")
			if module == nil || module.Type() != "dotted_name" {
				return false // relative imports cannot be resolved to a known library
			}
			prefix := module.Content(src) + "."
			children(n, func(c *sitter.Node, field string) {
				if field != "name" {
					return
				}
				switch c.Type() {
				case "dotted_name":
					out[c.Content(src)] = prefix + c.Content(src)
				case "aliased_import":
					if name, alias := c.ChildByFieldName("name"), c.ChildByFieldName("alias"); name != nil && alias != nil {
						out[alias.Content(src)] = prefix + name.Content(src)
					}
				}
			})
			return false
		}
		return true
	})
	return out
}

func (pyFrontend) collectConsts(root *sitter.Node, src []byte) map[string]*sitter.Node {
	out := make(map[string]*sitter.Node)
	walk(root, func(n *sitter.Node) bool {
		if n.Type() != "assignment" {
			return true
		}
		left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		if left != nil && right != nil && left.Type() == "identifier" {
			addConst(out, left.Content(src), right, src)
		}
		return true
	})
	return out
}

func (pyFrontend) skipSubtree(n *sitter.Node) bool {
	switch n.Type() {
	case "import_statement", "import_from_statement", "future_import_statement":
		return true
	}
	return false
}

func (pyFrontend) callParts(n *sitter.Node) (fn, args *sitter.Node, ok bool) {
	if n.Type() != "call" {
		return nil, nil, false
	}
	return n.ChildByFieldName("function"), n.ChildByFieldName("arguments"), true
}

func (pyFrontend) args(list *sitter.Node, src []byte) ([]*sitter.Node, map[string]*sitter.Node) {
	if list == nil || list.Type() != "argument_list" {
		return nil, nil
	}
	var positional []*sitter.Node
	keyword := make(map[string]*sitter.Node)
	for _, c := range namedChildren(list) {
		switch c.Type() {
		case "keyword_argument":
			if name, value := c.ChildByFieldName("name"), c.ChildByFieldName("value"); name != nil && value != nil {
				keyword[name.Content(src)] = value
			}
		case "list_splat", "dictionary_splat":
			// Unknowable positions; stop collecting positional arguments.
			return positional, keyword
		default:
			positional = append(positional, c)
		}
	}
	return positional, keyword
}

// identifier nodes that name something being defined or a keyword, never a
// reference to an import.
var pyNonRefFields = map[string]map[string]bool{
	"attribute":               {"attribute": true},
	"keyword_argument":        {"name": true},
	"function_definition":     {"name": true},
	"class_definition":        {"name": true},
	"default_parameter":       {"name": true},
	"typed_default_parameter": {"name": true},
	"assignment":              {"left": true},
}

func (pyFrontend) refCandidate(n *sitter.Node, parentType, field string) bool {
	switch n.Type() {
	case "attribute":
		return true
	case "identifier":
		if parentType == "parameters" || parentType == "typed_parameter" {
			return false
		}
		return !pyNonRefFields[parentType][field]
	}
	return false
}

func (p pyFrontend) resolve(f *file, n *sitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Type() {
	case "identifier":
		q, ok := f.imports[n.Content(f.src)]
		return q, ok
	case "attribute":
		object, attr := n.ChildByFieldName("object"), n.ChildByFieldName("attribute")
		if object == nil || attr == nil {
			return "", false
		}
		base, ok := p.resolve(f, object)
		if !ok {
			return "", false
		}
		return base + "." + attr.Content(f.src), true
	}
	return "", false
}

func (pyFrontend) literal(n *sitter.Node, src []byte) (string, bool) {
	switch n.Type() {
	case "integer":
		return strings.ReplaceAll(n.Content(src), "_", ""), true
	case "string":
		var b strings.Builder
		for _, c := range namedChildren(n) {
			switch c.Type() {
			case "string_content":
				b.WriteString(c.Content(src))
			case "interpolation", "escape_sequence":
				return "", false
			}
		}
		return b.String(), true
	}
	return "", false
}

func (pyFrontend) identifier(n *sitter.Node, src []byte) (string, bool) {
	if n.Type() != "identifier" {
		return "", false
	}
	return n.Content(src), true
}

func (pyFrontend) falseCondition(n *sitter.Node, src []byte) bool {
	if n == nil {
		return false
	}
	return n.Type() == "false" || (n.Type() == "integer" && n.Content(src) == "0")
}

func (p pyFrontend) dead(parent *sitter.Node, field string, src []byte) bool {
	return ifDead(p, parent, field, src)
}

func (pyFrontend) property(*sitter.Node, string, []byte) *sitter.Node { return nil }
