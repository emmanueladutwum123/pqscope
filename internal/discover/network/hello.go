package network

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// TLS group codepoints from the IANA TLS Supported Groups registry
// (https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8).
var groupIDs = map[string]uint16{
	"secp256r1": 23, "secp384r1": 24, "secp521r1": 25, "x25519": 29, "x448": 30,
	"ffdhe2048": 256, "ffdhe3072": 257, "ffdhe4096": 258,
	"MLKEM512": 512, "MLKEM768": 513, "MLKEM1024": 514,
	"SecP256r1MLKEM768": 4587, "X25519MLKEM768": 4588, "SecP384r1MLKEM1024": 4589,
}

// GroupName returns a group's IANA name, or its codepoint in hex.
func GroupName(id uint16) string {
	for name, v := range groupIDs {
		if v == id {
			return name
		}
	}
	return fmt.Sprintf("0x%04x", id)
}

// GroupID returns the codepoint of a group name, ignoring case.
func GroupID(name string) (uint16, bool) {
	for n, v := range groupIDs {
		if strings.EqualFold(n, name) {
			return v, true
		}
	}
	return 0, false
}

// DefaultGroups is the group list offered when none is configured, most
// preferred first. Key shares are sent for the first two.
var DefaultGroups = []string{"X25519MLKEM768", "x25519", "secp256r1"}

// TLS 1.3 cipher suites (RFC 8446, Appendix B.4).
var suiteNames = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
}

// Signature schemes offered: everything a TLS 1.3 server is likely to hold a
// certificate for, including ML-DSA (IANA TLS SignatureScheme registry).
var signatureSchemes = []uint16{
	0x0403, 0x0503, 0x0603, // ecdsa_secp{256r1,384r1,521r1}_sha{256,384,512}
	0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha{256,384,512}
	0x0807,                 // ed25519
	0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha{256,384,512}
	0x0904, 0x0905, 0x0906, // mldsa{44,65,87}
}

// helloRetryRandom is the ServerHello.random value that marks a
// HelloRetryRequest: SHA-256("HelloRetryRequest") (RFC 8446, Section 4.1.3).
var helloRetryRandom = sha256.Sum256([]byte("HelloRetryRequest"))

// TLS alert descriptions (RFC 8446, Section 6).
var alertNames = map[uint8]string{
	0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
	47: "illegal_parameter", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
	71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
	109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
	120: "no_application_protocol",
}

// keyShare returns a fresh client key share for a group, or false if the
// prober cannot generate one. Hybrid shares concatenate their components in
// the order draft-ietf-tls-ecdhe-mlkem specifies: ML-KEM first for
// X25519MLKEM768, ECDH first for the SecP variants. Private keys are
// discarded: the prober never completes the key exchange.
func keyShare(group uint16) ([]byte, bool) {
	x25519 := func() []byte { k, _ := ecdh.X25519().GenerateKey(rand.Reader); return k.PublicKey().Bytes() }
	p256 := func() []byte { k, _ := ecdh.P256().GenerateKey(rand.Reader); return k.PublicKey().Bytes() }
	p384 := func() []byte { k, _ := ecdh.P384().GenerateKey(rand.Reader); return k.PublicKey().Bytes() }
	mlkem768 := func() []byte { k, _ := mlkem.GenerateKey768(); return k.EncapsulationKey().Bytes() }
	mlkem1024 := func() []byte { k, _ := mlkem.GenerateKey1024(); return k.EncapsulationKey().Bytes() }
	switch group {
	case 29:
		return x25519(), true
	case 23:
		return p256(), true
	case 24:
		return p384(), true
	case 513:
		return mlkem768(), true
	case 514:
		return mlkem1024(), true
	case 4588:
		return append(mlkem768(), x25519()...), true
	case 4587:
		return append(p256(), mlkem768()...), true
	case 4589:
		return append(p384(), mlkem1024()...), true
	}
	return nil, false
}

// buildClientHello returns a TLS record holding a TLS 1.3-only ClientHello
// that offers groups, with key shares for the first `shares` groups the
// prober can generate shares for.
func buildClientHello(serverName string, groups []uint16, shares int) ([]byte, error) {
	random := make([]byte, 32)
	sessionID := make([]byte, 32) // a legacy session ID, for middlebox compatibility (RFC 8446, D.4)
	_, _ = rand.Read(random)
	_, _ = rand.Read(sessionID)

	var b cryptobyte.Builder
	b.AddUint8(22)      // handshake record
	b.AddUint16(0x0301) // legacy record version
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1) // client_hello
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0303) // legacy_version
			b.AddBytes(random)
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sessionID) })
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, s := range []uint16{0x1301, 0x1302, 0x1303} {
					b.AddUint16(s)
				}
			})
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) }) // null compression
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				if serverName != "" && net.ParseIP(serverName) == nil {
					extension(b, 0, func(b *cryptobyte.Builder) { // server_name
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
							b.AddUint8(0) // host_name
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(serverName)) })
						})
					})
				}
				extension(b, 10, func(b *cryptobyte.Builder) { // supported_groups
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, g := range groups {
							b.AddUint16(g)
						}
					})
				})
				extension(b, 13, func(b *cryptobyte.Builder) { // signature_algorithms
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, s := range signatureSchemes {
							b.AddUint16(s)
						}
					})
				})
				extension(b, 43, func(b *cryptobyte.Builder) { // supported_versions
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(0x0304) })
				})
				extension(b, 45, func(b *cryptobyte.Builder) { // psk_key_exchange_modes
					b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(1) })
				})
				extension(b, 51, func(b *cryptobyte.Builder) { // key_share
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						sent := 0
						for _, g := range groups {
							if sent == shares {
								break
							}
							share, ok := keyShare(g)
							if !ok {
								continue
							}
							b.AddUint16(g)
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(share) })
							sent++
						}
					})
				})
			})
		})
	})
	return b.Bytes()
}

func extension(b *cryptobyte.Builder, typ uint16, body func(*cryptobyte.Builder)) {
	b.AddUint16(typ)
	b.AddUint16LengthPrefixed(body)
}

// Hello is what a server answered to the ClientHello.
type Hello struct {
	Offered     []string `json:"offered"`
	Version     string   `json:"version,omitempty"`
	Group       string   `json:"group,omitempty"`
	HelloRetry  bool     `json:"hello_retry,omitempty"` // the server asked for a share of Group
	CipherSuite string   `json:"cipher_suite,omitempty"`
	Alert       string   `json:"alert,omitempty"`
	Error       string   `json:"error,omitempty"`
}

var errNotTLS = errors.New("response is not TLS")

// maxRecord bounds a TLS record body: 2^14 plus expansion (RFC 8446, 5.2).
const maxRecord = 1<<14 + 256

// readServerHello reads records until it has the first handshake message,
// which must be a ServerHello, or an alert. It reads nothing further.
func readServerHello(r io.Reader) (Hello, error) {
	var h Hello
	var hs []byte
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return h, fmt.Errorf("reading record: %w", err)
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if hdr[1] != 3 || n > maxRecord {
			return h, errNotTLS
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return h, fmt.Errorf("reading record: %w", err)
		}
		switch hdr[0] {
		case 21: // alert
			if len(body) >= 2 {
				h.Alert = alertNames[body[1]]
				if h.Alert == "" {
					h.Alert = fmt.Sprintf("alert %d", body[1])
				}
			}
			return h, nil
		case 20: // change_cipher_spec, sent for middlebox compatibility
			continue
		case 22:
			hs = append(hs, body...)
			if len(hs) < 4 {
				continue
			}
			if hs[0] != 2 {
				return h, fmt.Errorf("first handshake message is type %d, not ServerHello", hs[0])
			}
			if size := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]); len(hs) >= 4+size {
				return h, parseServerHello(hs[4:4+size], &h)
			}
		default:
			return h, errNotTLS
		}
	}
}

func parseServerHello(msg []byte, h *Hello) error {
	s := cryptobyte.String(msg)
	var legacyVersion, suite uint16
	var random []byte
	var sessionID, extensions cryptobyte.String
	var compression uint8
	if !s.ReadUint16(&legacyVersion) || !s.ReadBytes(&random, 32) || !s.ReadUint8LengthPrefixed(&sessionID) ||
		!s.ReadUint16(&suite) || !s.ReadUint8(&compression) {
		return errors.New("malformed ServerHello")
	}
	h.HelloRetry = bytes.Equal(random, helloRetryRandom[:])
	h.Version = versionName(legacyVersion)
	h.CipherSuite = suiteNames[suite]
	if h.CipherSuite == "" {
		h.CipherSuite = fmt.Sprintf("0x%04x", suite)
	}
	if s.Empty() {
		return nil // a TLS 1.2 or older ServerHello without extensions
	}
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return errors.New("malformed ServerHello extensions")
	}
	for !extensions.Empty() {
		var typ uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&typ) || !extensions.ReadUint16LengthPrefixed(&data) {
			return errors.New("malformed ServerHello extension")
		}
		switch typ {
		case 43: // supported_versions
			var v uint16
			if !data.ReadUint16(&v) {
				return errors.New("malformed supported_versions")
			}
			h.Version = versionName(v)
		case 51: // key_share: a group and share, or, in a HelloRetryRequest, a group alone
			var g uint16
			if !data.ReadUint16(&g) {
				return errors.New("malformed key_share")
			}
			h.Group = GroupName(g)
		}
	}
	return nil
}

func versionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}
