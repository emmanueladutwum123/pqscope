// Package rules embeds the YAML rule packs used by the source discovery layer.
package rules

import "embed"

// FS holds every rule pack, one *.yaml file per language.
//
//go:embed *.yaml
var FS embed.FS
