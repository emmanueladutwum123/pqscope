// Package policies embeds pqscope's bundled policy files. See
// internal/policy for the format.
package policies

import "embed"

// FS holds every bundled policy, one *.yaml file per policy ID.
//
//go:embed *.yaml
var FS embed.FS
