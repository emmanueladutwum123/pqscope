package config

import (
	"strings"
)

// directive is one recognised configuration line, before its values are
// resolved to assets.
type directive struct {
	line   int
	symbol string // "nginx:ssl_ecdh_curve", "sshd:KexAlgorithms", ...
	kind   valueKind
	value  string
	text   string // the trimmed source line, used as evidence
}

// valueKind says how to split a directive's value and which table to use.
type valueKind int

const (
	tlsGroups valueKind = iota
	tlsCiphers
	tls13Suites
	sshKex
	sshPubkey
	sshCiphers
	sshMACs
	rsaBits
	digest
)

// fields splits a line into whitespace-separated fields, keeping quoted
// strings together and dropping the quotes.
func fields(s string) []string {
	var out []string
	var cur strings.Builder
	quote := rune(0)
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote == 0 && (r == '"' || r == '\''):
			quote = r
		case quote == 0 && (r == ' ' || r == '\t'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func stripComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// opensslCommand maps SSL_CONF command names, used by nginx ssl_conf_command,
// Apache SSLOpenSSLConfCmd and openssl.cnf, to value kinds. Names ignore case.
// See OpenSSL SSL_CONF_cmd(3).
var opensslCommand = map[string]valueKind{
	"groups":       tlsGroups,
	"curves":       tlsGroups,
	"cipherstring": tlsCiphers,
	"ciphersuites": tls13Suites,
}

// parseServerConf reads nginx and Apache httpd configuration. The two share
// *.conf files, but their TLS directives have distinct names:
//
//   - nginx (ngx_http_ssl_module): ssl_ecdh_curve, ssl_ciphers, ssl_conf_command;
//   - Apache (mod_ssl, case-insensitive): SSLOpenSSLConfCmd, SSLCipherSuite.
func parseServerConf(data []byte) []directive {
	var out []directive
	for i, raw := range splitLines(data) {
		line := strings.TrimSuffix(stripComment(raw), ";")
		f := fields(line)
		if len(f) < 2 {
			continue
		}
		d := directive{line: i + 1, text: strings.TrimSpace(raw)}
		switch name := f[0]; {
		case name == "ssl_ecdh_curve":
			d.symbol, d.kind, d.value = "nginx:ssl_ecdh_curve", tlsGroups, f[1]
		case name == "ssl_ciphers":
			d.symbol, d.kind, d.value = "nginx:ssl_ciphers", tlsCiphers, f[1]
		case name == "ssl_conf_command" && len(f) >= 3:
			k, ok := opensslCommand[strings.ToLower(f[1])]
			if !ok {
				continue
			}
			d.symbol, d.kind, d.value = "nginx:ssl_conf_command "+f[1], k, f[2]
		case strings.EqualFold(name, "SSLOpenSSLConfCmd") && len(f) >= 3:
			k, ok := opensslCommand[strings.ToLower(f[1])]
			if !ok {
				continue
			}
			d.symbol, d.kind, d.value = "apache:SSLOpenSSLConfCmd "+f[1], k, f[2]
		case strings.EqualFold(name, "SSLCipherSuite"):
			// SSLCipherSuite [protocol] cipher-spec; protocol is SSL (TLS 1.2
			// and below) or TLSv1.3.
			d.symbol, d.kind, d.value = "apache:SSLCipherSuite", tlsCiphers, f[1]
			if len(f) >= 3 {
				d.value = f[2]
				if strings.EqualFold(f[1], "TLSv1.3") {
					d.kind = tls13Suites
				}
			}
		default:
			continue
		}
		out = append(out, d)
	}
	return out
}

// sshKeyword maps sshd_config and ssh_config keywords to value kinds.
// Keywords ignore case. See sshd_config(5).
var sshKeyword = map[string]valueKind{
	"kexalgorithms":               sshKex,
	"hostkeyalgorithms":           sshPubkey,
	"pubkeyacceptedalgorithms":    sshPubkey,
	"pubkeyacceptedkeytypes":      sshPubkey, // the pre-8.5 name
	"casignaturealgorithms":       sshPubkey,
	"hostbasedacceptedalgorithms": sshPubkey,
	"ciphers":                     sshCiphers,
	"macs":                        sshMACs,
}

// parseSSHConf reads "Keyword value" or "Keyword=value" lines.
func parseSSHConf(data []byte) []directive {
	var out []directive
	for i, raw := range splitLines(data) {
		line := stripComment(raw)
		key, value, ok := strings.Cut(line, "=")
		if f := strings.Fields(line); !ok || strings.ContainsAny(key, " \t") {
			if len(f) < 2 {
				continue
			}
			key, value = f[0], f[1]
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		k, known := sshKeyword[strings.ToLower(key)]
		if !known || value == "" {
			continue
		}
		out = append(out, directive{line: i + 1, symbol: "ssh:" + key, kind: k, value: value, text: strings.TrimSpace(raw)})
	}
	return out
}

// parseOpenSSLConf reads openssl.cnf: SSL_CONF commands in any section, and
// default_bits and default_md, which set the RSA key size and digest for
// `openssl req` and `openssl ca`.
func parseOpenSSLConf(data []byte) []directive {
	var out []directive
	section := ""
	for i, raw := range splitLines(data) {
		line := stripComment(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(value), `"`)
		d := directive{line: i + 1, value: value, text: strings.TrimSpace(raw), symbol: "openssl.cnf:" + key}
		if section != "" {
			d.symbol = "openssl.cnf:[" + section + "]" + key
		}
		if k, ok := opensslCommand[strings.ToLower(key)]; ok {
			d.kind = k
		} else {
			switch strings.ToLower(key) {
			case "default_bits":
				d.kind = rsaBits
			case "default_md":
				d.kind = digest
			default:
				continue
			}
		}
		out = append(out, d)
	}
	return out
}

func splitLines(data []byte) []string {
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}
