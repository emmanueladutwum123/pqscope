// Package bench measures migration costs (SPEC Section 11): latency and sizes
// of classical and post-quantum primitives, and TLS ClientHello size and
// handshake latency, classical against hybrid. Sizes are measured from real
// outputs and cross-checked against the knowledge DB and OpenSSL; nothing is
// restated from a table.
//
// The package does not import tree-sitter, so bench/netem, which runs it in a
// Linux container under tc netem, cross-compiles without cgo.
package bench
