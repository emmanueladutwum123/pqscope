package network

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// SSH is what an SSH server offered in its KEXINIT (RFC 4253, Section 7.1).
type SSH struct {
	Banner  string   `json:"banner,omitempty"`
	Kex     []string `json:"kex,omitempty"`
	HostKey []string `json:"host_key,omitempty"`
	Ciphers []string `json:"ciphers,omitempty"` // server to client
	MACs    []string `json:"macs,omitempty"`    // server to client
	Error   string   `json:"error,omitempty"`
}

// maxSSHPacket bounds the KEXINIT packet; RFC 4253 requires implementations
// to handle 35000 bytes.
const maxSSHPacket = 35000

// probeSSH exchanges identification strings and reads the server's KEXINIT.
// It sends nothing else: no KEXINIT of its own, so no key exchange starts.
func probeSSH(rw io.ReadWriter, ident string) (SSH, error) {
	var res SSH
	br := bufio.NewReader(rw)
	// RFC 4253, 4.2: the server may send other lines before its version.
	for i := 0; ; i++ {
		if i == 32 {
			return res, errors.New("no SSH identification string")
		}
		line, err := br.ReadString('\n')
		if err != nil {
			return res, fmt.Errorf("reading banner: %w", err)
		}
		if strings.HasPrefix(line, "SSH-") {
			res.Banner = strings.TrimRight(line, "\r\n")
			break
		}
	}
	if !strings.HasPrefix(res.Banner, "SSH-2.0-") && !strings.HasPrefix(res.Banner, "SSH-1.99-") {
		return res, fmt.Errorf("unsupported SSH version %q", res.Banner)
	}
	if _, err := io.WriteString(rw, ident+"\r\n"); err != nil {
		return res, fmt.Errorf("sending identification: %w", err)
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
		return res, fmt.Errorf("reading KEXINIT: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n < 2 || n > maxSSHPacket {
		return res, fmt.Errorf("implausible packet length %d", n)
	}
	packet := make([]byte, n)
	if _, err := io.ReadFull(br, packet); err != nil {
		return res, fmt.Errorf("reading KEXINIT: %w", err)
	}
	padding := int(packet[0])
	if padding+1 > len(packet) {
		return res, errors.New("malformed packet padding")
	}
	payload := cryptobyte.String(packet[1 : len(packet)-padding])
	var msg uint8
	var cookie []byte
	if !payload.ReadUint8(&msg) || msg != 20 || !payload.ReadBytes(&cookie, 16) {
		return res, fmt.Errorf("first packet is message %d, not KEXINIT", msg)
	}
	lists := make([][]string, 10)
	for i := range lists {
		var n uint32
		var l []byte
		if !payload.ReadUint32(&n) || !payload.ReadBytes(&l, int(n)) {
			return res, errors.New("malformed KEXINIT name-list")
		}
		if len(l) > 0 {
			lists[i] = strings.Split(string(l), ",")
		}
	}
	// kex, host key, ciphers c2s, s2c, MACs c2s, s2c, compression c2s, s2c, languages c2s, s2c.
	res.Kex, res.HostKey, res.Ciphers, res.MACs = lists[0], lists[1], lists[3], lists[5]
	return res, nil
}
