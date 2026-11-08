package config

import (
	"strconv"
	"strings"

	"github.com/emmanueladutwum123/pqscope/internal/model"
)

// resolve turns a directive's value into the assets it enables.
func (s *Scanner) resolve(d directive) []model.Asset {
	switch d.kind {
	case tlsGroups:
		return s.each(splitAny(d.value, ":,/"), func(tok string) []model.Asset {
			// OpenSSL 3.5 group lists: "?" marks an optional group and "*" a
			// key share; "-" removes a group from the defaults.
			if strings.HasPrefix(tok, "-") {
				return nil
			}
			return s.names.lookup("tls-groups", strings.TrimLeft(tok, "?*"))
		})
	case tlsCiphers:
		return s.each(splitAny(d.value, ":, "), s.cipher)
	case tls13Suites:
		return s.each(splitAny(d.value, ":,"), func(tok string) []model.Asset {
			return s.names.lookup("tls13-suites", tok)
		})
	case sshKex, sshPubkey, sshCiphers, sshMACs:
		// A list starting with "-" removes algorithms from the defaults; "+"
		// appends and "^" prepends.
		if strings.HasPrefix(d.value, "-") {
			return nil
		}
		value := strings.TrimLeft(d.value, "+^")
		return s.each(splitAny(value, ","), func(tok string) []model.Asset {
			return s.ssh(d.kind, tok)
		})
	case rsaBits:
		bits, err := strconv.Atoi(d.value)
		if err != nil || bits <= 0 {
			return nil
		}
		a, err := familyAsset(s.db, "RSA", model.PrimitiveSignature, strconv.Itoa(bits))
		if err != nil {
			return nil
		}
		return []model.Asset{a}
	case digest:
		return s.names.lookup("digests", d.value)
	}
	return nil
}

func (s *Scanner) each(tokens []string, f func(string) []model.Asset) []model.Asset {
	var out []model.Asset
	for _, t := range tokens {
		out = append(out, f(t)...)
	}
	return out
}

func splitAny(s, seps string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return strings.ContainsRune(seps, r) })
}

// cipher resolves one OpenSSL cipher-list token: a TLS 1.3 suite name, or a
// TLS 1.2 suite name read as [KX-][AUTH-]CIPHER[-MAC]. Exclusions ("!", "-"),
// strength modifiers and keywords such as HIGH resolve to nothing.
func (s *Scanner) cipher(tok string) []model.Asset {
	if tok == "" || strings.ContainsAny(tok[:1], "!-+@") {
		return nil
	}
	if a := s.names.lookup("tls13-suites", tok); a != nil {
		return a
	}
	parts := strings.Split(tok, "-")
	var out []model.Asset
	i := 0
	kx := s.names.lookup("tls12-kx", parts[0])
	if kx != nil {
		out = append(out, kx...)
		i++
	}
	if i < len(parts) {
		if auth := s.names.lookup("tls12-auth", parts[i]); auth != nil {
			out = append(out, auth...)
			i++
		}
	}
	if kx == nil {
		// No key-exchange part: RSA key transport, authenticated by the same key.
		if i > 0 {
			return nil // an auth part without key exchange is not a suite name
		}
		rsa, err := familyAsset(s.db, "RSA", model.PrimitivePKE, model.ParamsUnknown)
		if err != nil {
			return nil
		}
		out = append(out, rsa)
	}
	// The cipher may span several parts (AES128-GCM, CHACHA20-POLY1305); take
	// the longest match.
	matched := 0
	for j := len(parts); j > i; j-- {
		if c := s.names.lookup("tls12-cipher", strings.Join(parts[i:j], "-")); c != nil {
			out = append(out, c...)
			matched = j
			break
		}
	}
	if matched == 0 {
		return nil
	}
	switch rest := parts[matched:]; len(rest) {
	case 0:
	case 1:
		mac := s.names.lookup("tls12-mac", rest[0])
		if mac == nil {
			return nil
		}
		out = append(out, mac...)
	default:
		return nil
	}
	return out
}

// ssh resolves one SSH algorithm name, reducing certificate and
// encrypt-then-MAC variants to their base names.
func (s *Scanner) ssh(kind valueKind, tok string) []model.Asset {
	switch kind {
	case sshKex:
		return s.names.lookup("ssh-kex", tok)
	case sshPubkey:
		base := strings.TrimSuffix(tok, "-cert-v01@openssh.com")
		if a := s.names.lookup("ssh-pubkey", base); a != nil {
			return a
		}
		return s.names.lookup("ssh-pubkey", base+"@openssh.com")
	case sshCiphers:
		return s.names.lookup("ssh-ciphers", tok)
	case sshMACs:
		return s.names.lookup("ssh-macs", strings.TrimSuffix(tok, "-etm@openssh.com"))
	}
	return nil
}
