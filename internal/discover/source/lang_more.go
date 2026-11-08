package source

import (
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// unparen strips parentheses around an expression.
func unparen(n *sitter.Node) *sitter.Node {
	for n != nil && (n.Type() == "parenthesized_expression" || n.Type() == "condition_clause") && n.NamedChildCount() >= 1 {
		n = n.NamedChild(int(n.NamedChildCount()) - 1)
	}
	return n
}

// compact removes whitespace, for dotted names written across lines.
func compact(s string) string { return strings.Join(strings.Fields(s), "") }

// --- Java ---

type javaFrontend struct{}

// wildcardPrefix marks the import map entries for `import pkg.*;`.
const wildcardPrefix = "*"

func (javaFrontend) collectImports(root *sitter.Node, src []byte) map[string]string {
	out := make(map[string]string)
	walk(root, func(n *sitter.Node) bool {
		if n.Type() != "import_declaration" {
			return n.Type() == "program"
		}
		var name string
		wildcard := false
		for _, c := range namedChildren(n) {
			switch c.Type() {
			case "scoped_identifier", "identifier":
				name = compact(c.Content(src))
			case "asterisk":
				wildcard = true
			}
		}
		switch {
		case name == "":
		case wildcard:
			out[wildcardPrefix+name] = name
		default:
			out[name[strings.LastIndexByte(name, '.')+1:]] = name
		}
		return false
	})
	return out
}

func (javaFrontend) collectConsts(root *sitter.Node, src []byte) map[string]*sitter.Node {
	out := make(map[string]*sitter.Node)
	walk(root, func(n *sitter.Node) bool {
		var name, value *sitter.Node
		switch n.Type() {
		case "variable_declarator":
			name, value = n.ChildByFieldName("name"), n.ChildByFieldName("value")
		case "assignment_expression":
			name, value = n.ChildByFieldName("left"), n.ChildByFieldName("right")
		}
		if name != nil && value != nil && name.Type() == "identifier" {
			addConst(out, name.Content(src), value, src)
		}
		return true
	})
	return out
}

func (javaFrontend) skipSubtree(n *sitter.Node) bool {
	return n.Type() == "import_declaration" || n.Type() == "package_declaration"
}

func (javaFrontend) callParts(n *sitter.Node) (fn, args *sitter.Node, ok bool) {
	switch n.Type() {
	case "method_invocation":
		return n, n.ChildByFieldName("arguments"), true
	case "object_creation_expression":
		// A constructor call is matched as a call of the class itself.
		return n.ChildByFieldName("type"), n.ChildByFieldName("arguments"), true
	}
	return nil, nil, false
}

func (javaFrontend) args(list *sitter.Node, _ []byte) ([]*sitter.Node, map[string]*sitter.Node) {
	return namedChildren(list), nil
}

func (javaFrontend) refCandidate(n *sitter.Node, _, _ string) bool {
	return n.Type() == "field_access"
}

func (j javaFrontend) resolve(f *file, n *sitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Type() {
	case "identifier", "type_identifier":
		name := n.Content(f.src)
		if q, ok := f.imports[name]; ok {
			return q, true
		}
		for key, pkg := range f.imports {
			if strings.HasPrefix(key, wildcardPrefix) && f.set.prefixes[pkg+"."+name] {
				return pkg + "." + name, true
			}
		}
		return "", false
	case "method_invocation":
		name := n.ChildByFieldName("name")
		object := n.ChildByFieldName("object")
		if name == nil {
			return "", false
		}
		if object == nil {
			return j.resolve(f, name) // a statically imported method
		}
		base, ok := j.resolve(f, object)
		if !ok {
			return "", false
		}
		return base + "." + name.Content(f.src), true
	case "field_access", "scoped_identifier", "scoped_type_identifier":
		object := n.ChildByFieldName("object")
		field := n.ChildByFieldName("field")
		if n.Type() != "field_access" {
			object, field = n.ChildByFieldName("scope"), n.ChildByFieldName("name")
			if n.Type() == "scoped_type_identifier" && object == nil && n.NamedChildCount() == 2 {
				object, field = n.NamedChild(0), n.NamedChild(1)
			}
		}
		if object != nil && field != nil {
			if base, ok := j.resolve(f, object); ok {
				return base + "." + field.Content(f.src), true
			}
		}
		// A fully qualified name, such as java.security.MessageDigest.
		if text := compact(n.Content(f.src)); f.set.prefixes[text] {
			return text, true
		}
	}
	return "", false
}

func (javaFrontend) literal(n *sitter.Node, src []byte) (string, bool) {
	switch n.Type() {
	case "string_literal":
		var b strings.Builder
		for _, c := range namedChildren(n) {
			if c.Type() != "string_fragment" {
				return "", false
			}
			b.WriteString(c.Content(src))
		}
		return b.String(), true
	case "decimal_integer_literal":
		return strings.TrimRight(strings.ReplaceAll(n.Content(src), "_", ""), "lL"), true
	}
	return "", false
}

func (javaFrontend) identifier(n *sitter.Node, src []byte) (string, bool) {
	if n.Type() != "identifier" {
		return "", false
	}
	return n.Content(src), true
}

func (javaFrontend) falseCondition(n *sitter.Node, _ []byte) bool {
	n = unparen(n)
	return n != nil && n.Type() == "false"
}

func (j javaFrontend) dead(parent *sitter.Node, field string, src []byte) bool {
	return ifDead(j, parent, field, src)
}

func (javaFrontend) property(*sitter.Node, string, []byte) *sitter.Node { return nil }

// --- C and C++ ---

// cFrontend serves C and C++. The C APIs pqscope recognises are global
// functions, so names resolve to themselves; C++ qualified names resolve to
// their written form.
type cFrontend struct{}

func (cFrontend) collectImports(*sitter.Node, []byte) map[string]string { return map[string]string{} }

func (cFrontend) collectConsts(root *sitter.Node, src []byte) map[string]*sitter.Node {
	out := make(map[string]*sitter.Node)
	walk(root, func(n *sitter.Node) bool {
		var name, value *sitter.Node
		switch n.Type() {
		case "init_declarator":
			name, value = n.ChildByFieldName("declarator"), n.ChildByFieldName("value")
		case "preproc_def":
			name, value = n.ChildByFieldName("name"), n.ChildByFieldName("value")
		case "assignment_expression":
			name, value = n.ChildByFieldName("left"), n.ChildByFieldName("right")
		}
		if name != nil && value != nil && name.Type() == "identifier" {
			addConst(out, name.Content(src), value, src)
		}
		return true
	})
	return out
}

func (cFrontend) skipSubtree(n *sitter.Node) bool { return n.Type() == "preproc_include" }

func (cFrontend) callParts(n *sitter.Node) (fn, args *sitter.Node, ok bool) {
	if n.Type() != "call_expression" {
		return nil, nil, false
	}
	return n.ChildByFieldName("function"), n.ChildByFieldName("arguments"), true
}

func (cFrontend) args(list *sitter.Node, _ []byte) ([]*sitter.Node, map[string]*sitter.Node) {
	return namedChildren(list), nil
}

func (cFrontend) refCandidate(*sitter.Node, string, string) bool { return false }

func (cFrontend) resolve(f *file, n *sitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Type() {
	case "identifier":
		return n.Content(f.src), true
	case "qualified_identifier":
		return compact(n.Content(f.src)), true
	}
	return "", false
}

func (cFrontend) literal(n *sitter.Node, src []byte) (string, bool) {
	switch n.Type() {
	case "string_literal":
		var b strings.Builder
		for _, c := range namedChildren(n) {
			if c.Type() != "string_content" {
				return "", false
			}
			b.WriteString(c.Content(src))
		}
		return b.String(), true
	case "number_literal":
		s := strings.TrimRight(n.Content(src), "uUlL")
		if _, err := strconv.ParseInt(s, 0, 64); err != nil {
			return "", false
		}
		return s, true
	case "preproc_arg":
		s := strings.TrimSpace(n.Content(src))
		if u, err := strconv.Unquote(s); err == nil {
			return u, true
		}
		if _, err := strconv.Atoi(s); err == nil {
			return s, true
		}
	}
	return "", false
}

func (cFrontend) identifier(n *sitter.Node, src []byte) (string, bool) {
	if n.Type() != "identifier" {
		return "", false
	}
	return n.Content(src), true
}

func (cFrontend) falseCondition(n *sitter.Node, src []byte) bool {
	n = unparen(n)
	if n == nil {
		return false
	}
	return n.Type() == "false" || (n.Type() == "number_literal" && n.Content(src) == "0")
}

func (c cFrontend) dead(parent *sitter.Node, field string, src []byte) bool {
	if parent.Type() == "preproc_if" && field != "condition" && field != "alternative" {
		cond := parent.ChildByFieldName("condition")
		return cond != nil && cond.Type() == "number_literal" && cond.Content(src) == "0"
	}
	return ifDead(c, parent, field, src)
}

func (cFrontend) property(*sitter.Node, string, []byte) *sitter.Node { return nil }

// --- JavaScript and TypeScript ---

type jsFrontend struct{}

// jsModule normalises a module specifier: Node's "node:" prefix is dropped.
func jsModule(n *sitter.Node, src []byte) (string, bool) {
	if n == nil {
		return "", false // import x = require("m") (TypeScript) has no source field
	}
	s, ok := jsFrontend{}.literal(n, src)
	if !ok || n.Type() != "string" {
		return "", false
	}
	return strings.TrimPrefix(s, "node:"), true
}

// requireCall returns the module of `require('m')`.
func requireCall(n *sitter.Node, src []byte) (string, bool) {
	if n == nil || n.Type() != "call_expression" {
		return "", false
	}
	fn, args := n.ChildByFieldName("function"), namedChildren(n.ChildByFieldName("arguments"))
	if fn == nil || fn.Type() != "identifier" || fn.Content(src) != "require" || len(args) != 1 {
		return "", false
	}
	return jsModule(args[0], src)
}

func (jsFrontend) collectImports(root *sitter.Node, src []byte) map[string]string {
	out := make(map[string]string)
	walk(root, func(n *sitter.Node) bool {
		switch n.Type() {
		case "import_statement":
			module, ok := jsModule(n.ChildByFieldName("source"), src)
			if !ok {
				return false
			}
			walk(n, func(c *sitter.Node) bool {
				switch c.Type() {
				case "import_clause":
					for _, d := range namedChildren(c) {
						if d.Type() == "identifier" { // default import
							out[d.Content(src)] = module
						}
					}
				case "namespace_import":
					for _, d := range namedChildren(c) {
						if d.Type() == "identifier" {
							out[d.Content(src)] = module
						}
					}
				case "import_specifier":
					name, alias := c.ChildByFieldName("name"), c.ChildByFieldName("alias")
					if name == nil {
						return false
					}
					local := name
					if alias != nil {
						local = alias
					}
					out[local.Content(src)] = module + "." + name.Content(src)
					return false
				}
				return true
			})
			return false
		case "variable_declarator":
			module, ok := requireCall(n.ChildByFieldName("value"), src)
			if !ok {
				return true
			}
			name := n.ChildByFieldName("name")
			switch {
			case name == nil:
			case name.Type() == "identifier":
				out[name.Content(src)] = module
			case name.Type() == "object_pattern":
				for _, p := range namedChildren(name) {
					switch p.Type() {
					case "shorthand_property_identifier_pattern":
						out[p.Content(src)] = module + "." + p.Content(src)
					case "pair_pattern":
						key, value := p.ChildByFieldName("key"), p.ChildByFieldName("value")
						if key != nil && value != nil && value.Type() == "identifier" {
							out[value.Content(src)] = module + "." + key.Content(src)
						}
					}
				}
			}
			return false
		}
		return true
	})
	return out
}

func (jsFrontend) collectConsts(root *sitter.Node, src []byte) map[string]*sitter.Node {
	out := make(map[string]*sitter.Node)
	walk(root, func(n *sitter.Node) bool {
		var name, value *sitter.Node
		switch n.Type() {
		case "variable_declarator":
			name, value = n.ChildByFieldName("name"), n.ChildByFieldName("value")
		case "assignment_expression":
			name, value = n.ChildByFieldName("left"), n.ChildByFieldName("right")
		}
		if name != nil && value != nil && name.Type() == "identifier" {
			addConst(out, name.Content(src), value, src)
		}
		return true
	})
	return out
}

func (jsFrontend) skipSubtree(n *sitter.Node) bool { return n.Type() == "import_statement" }

func (jsFrontend) callParts(n *sitter.Node) (fn, args *sitter.Node, ok bool) {
	switch n.Type() {
	case "call_expression":
		return n.ChildByFieldName("function"), n.ChildByFieldName("arguments"), true
	case "new_expression":
		return n.ChildByFieldName("constructor"), n.ChildByFieldName("arguments"), true
	}
	return nil, nil, false
}

func (jsFrontend) args(list *sitter.Node, _ []byte) ([]*sitter.Node, map[string]*sitter.Node) {
	var out []*sitter.Node
	for _, c := range namedChildren(list) {
		if c.Type() == "spread_element" {
			break // unknowable positions from here on
		}
		out = append(out, c)
	}
	return out, nil
}

// jsGlobalObjects name the global object; their members are globals.
var jsGlobalObjects = map[string]bool{"window": true, "self": true, "globalThis": true}

// jsNonRef lists parent types and fields under which an identifier declares
// a name instead of referring to one.
var jsNonRef = map[string]map[string]bool{
	"variable_declarator":   {"name": true},
	"function_declaration":  {"name": true},
	"class_declaration":     {"name": true},
	"method_definition":     {"name": true},
	"assignment_expression": {"left": true},
}

func (jsFrontend) refCandidate(n *sitter.Node, parentType, field string) bool {
	switch n.Type() {
	case "member_expression":
		return true
	case "identifier":
		switch parentType {
		case "formal_parameters", "required_parameter", "optional_parameter", "import_specifier", "import_clause", "namespace_import":
			return false
		}
		return !jsNonRef[parentType][field]
	}
	return false
}

func (j jsFrontend) resolve(f *file, n *sitter.Node) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Type() {
	case "identifier":
		name := n.Content(f.src)
		if q, ok := f.imports[name]; ok {
			return q, true
		}
		// WebCrypto's global crypto object, in browsers and Node.
		if name == "crypto" {
			if _, shadowed := f.consts[name]; !shadowed {
				return "crypto", true
			}
		}
		return "", false
	case "member_expression":
		object, prop := n.ChildByFieldName("object"), n.ChildByFieldName("property")
		if object == nil || prop == nil {
			return "", false
		}
		if object.Type() == "identifier" && jsGlobalObjects[object.Content(f.src)] {
			return prop.Content(f.src), true // window.crypto is crypto
		}
		base, ok := j.resolve(f, object)
		if !ok {
			base, ok = requireCall(object, f.src) // require('crypto').createHash
		}
		if !ok {
			return "", false
		}
		return base + "." + prop.Content(f.src), true
	}
	return "", false
}

func (jsFrontend) literal(n *sitter.Node, src []byte) (string, bool) {
	if n == nil {
		return "", false
	}
	switch n.Type() {
	case "string", "template_string":
		var b strings.Builder
		for _, c := range namedChildren(n) {
			switch c.Type() {
			case "string_fragment":
				b.WriteString(c.Content(src))
			default:
				return "", false // escapes or ${substitutions}
			}
		}
		return b.String(), true
	case "number":
		s := strings.ReplaceAll(n.Content(src), "_", "")
		if _, err := strconv.ParseInt(s, 0, 64); err != nil {
			return "", false
		}
		return s, true
	}
	return "", false
}

func (jsFrontend) identifier(n *sitter.Node, src []byte) (string, bool) {
	if n.Type() != "identifier" {
		return "", false
	}
	return n.Content(src), true
}

func (jsFrontend) falseCondition(n *sitter.Node, _ []byte) bool {
	n = unparen(n)
	return n != nil && n.Type() == "false"
}

func (j jsFrontend) dead(parent *sitter.Node, field string, src []byte) bool {
	return ifDead(j, parent, field, src)
}

func (j jsFrontend) property(obj *sitter.Node, key string, src []byte) *sitter.Node {
	if obj == nil || obj.Type() != "object" {
		return nil
	}
	for _, p := range namedChildren(obj) {
		if p.Type() != "pair" {
			continue
		}
		k := p.ChildByFieldName("key")
		if k == nil {
			continue
		}
		name := k.Content(src)
		if s, ok := j.literal(k, src); ok {
			name = s
		}
		if name == key {
			return p.ChildByFieldName("value")
		}
	}
	return nil
}
