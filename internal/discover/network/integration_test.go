//go:build integration

// Integration tests against real TLS and SSH servers, run with
//
//	go test -tags integration ./internal/discover/network/
//
// They need Docker, and use a local `openssl` 3.5 or later when there is one.
// Without Docker the Docker tests skip, unless PQSCOPE_REQUIRE_DOCKER=1 (set
// in CI), which makes a missing Docker a failure. Servers listen only on
// 127.0.0.1.
package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// alpineImage ships OpenSSL 3.5 and OpenSSH 10.
const alpineImage = "alpine:3.22"

func realProber(t *testing.T) *Prober {
	t.Helper()
	return newProber(t, &net.Dialer{}, Options{Resolver: net.DefaultResolver, Timeout: 5 * time.Second, Handshake: true})
}

// probeUntil probes target until it answers, for servers still starting.
func probeUntil(t *testing.T, p *Prober, target string, ready func(Record) bool) Record {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		r := runOne(t, p, target)
		if ready(r) || time.Now().After(deadline) {
			return r
		}
		time.Sleep(time.Second)
	}
}

func helloReady(r Record) bool { return r.Hello != nil && (r.Hello.Group != "" || r.Hello.Alert != "") }

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }() // only used to pick a free port
	return l.Addr().(*net.TCPAddr).Port
}

// --- local OpenSSL ---

func localOpenSSL(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl on PATH")
	}
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		t.Skip("openssl version failed")
	}
	m := regexp.MustCompile(`OpenSSL (\d+)\.(\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Skipf("not OpenSSL: %s", out)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major < 3 || major == 3 && minor < 5 {
		t.Skipf("%s is older than 3.5", strings.TrimSpace(string(out)))
	}
	t.Logf("using %s", strings.TrimSpace(string(out)))
	return path
}

func writeKeyPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pqscope-openssl-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestLocalOpenSSL(t *testing.T) {
	openssl := localOpenSSL(t)
	cert, key := writeKeyPair(t)
	tests := []struct {
		groups, want string
		retry        bool
	}{
		{"X25519MLKEM768:X25519", "X25519MLKEM768", false},
		{"X25519", "x25519", false},
		{"X25519/X25519MLKEM768", "x25519", false}, // "/" separates server-preference tiers (OpenSSL 3.5+); ":" groups are equal
		{"secp256r1", "secp256r1", true},
	}
	for _, tt := range tests {
		t.Run(tt.groups, func(t *testing.T) {
			port := freePort(t)
			cmd := exec.Command(openssl, "s_server", "-accept", "127.0.0.1:"+strconv.Itoa(port), "-cert", cert, "-key", key,
				"-groups", tt.groups, "-tls1_3", "-quiet", "-naccept", "100")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			r := probeUntil(t, realProber(t), "127.0.0.1:"+strconv.Itoa(port), helloReady)
			if r.Hello.Group != tt.want || r.Hello.HelloRetry != tt.retry || r.Hello.Version != "TLS 1.3" {
				t.Errorf("hello = %+v", r.Hello)
			}
			if r.Handshake == nil || r.Handshake.Error != "" || len(r.Handshake.Certificates) != 1 ||
				r.Handshake.Certificates[0].PublicKey != "ECDSA-P256" {
				t.Errorf("handshake = %+v", r.Handshake)
			}
		})
	}
}

// --- Docker ---

func requireDocker(t *testing.T) {
	t.Helper()
	if err := exec.Command("docker", "info").Run(); err != nil {
		if os.Getenv("PQSCOPE_REQUIRE_DOCKER") == "1" {
			t.Fatalf("Docker is required (PQSCOPE_REQUIRE_DOCKER=1) but unavailable: %v", err)
		}
		t.Skip("Docker unavailable")
	}
}

func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// container creates a container publishing port on 127.0.0.1, runs setup
// before starting it (to copy files in), and returns its ID and address.
func container(t *testing.T, port string, setup func(id string), args ...string) (string, string) {
	t.Helper()
	id := docker(t, append([]string{"create", "-p", "127.0.0.1::" + port}, args...)...)
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("container logs:\n%s", out)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})
	if setup != nil {
		setup(id)
	}
	docker(t, "start", id)
	mapped := docker(t, "port", id, port+"/tcp")
	return id, strings.Split(mapped, "\n")[0]
}

// The milestone 6 acceptance test, part 1: OpenSSL 3.5.
func TestDockerOpenSSL35(t *testing.T) {
	requireDocker(t)
	for _, tt := range []struct{ groups, want string }{
		{"X25519MLKEM768:X25519", "X25519MLKEM768"},
		{"X25519", "x25519"},
	} {
		t.Run(tt.groups, func(t *testing.T) {
			script := "apk add --no-cache openssl >/dev/null && openssl version && " +
				"openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=pqscope-openssl35 -days 1 " +
				"-keyout /tmp/k.pem -out /tmp/c.pem 2>/dev/null && " +
				"exec openssl s_server -accept 4433 -cert /tmp/c.pem -key /tmp/k.pem -tls1_3 -quiet -groups " + tt.groups
			id, addr := container(t, "4433", nil, alpineImage, "sh", "-c", script)
			r := probeUntil(t, realProber(t), addr, helloReady)
			if r.Hello.Group != tt.want || r.Hello.HelloRetry {
				t.Fatalf("hello = %+v", r.Hello)
			}
			if logs := docker(t, "logs", id); !strings.Contains(logs, "OpenSSL 3.5") {
				t.Errorf("server is not OpenSSL 3.5: %s", logs)
			} else {
				t.Logf("server: %s", strings.SplitN(logs, "\n", 2)[0])
			}
		})
	}
}

// The milestone 6 acceptance test, part 2: a Go server.
func TestDockerGo(t *testing.T) {
	requireDocker(t)
	bin := filepath.Join(t.TempDir(), "tlsserver")
	build := exec.Command("go", "build", "-o", bin, "../../../testdata/netservers/tlsserver")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the Go test server: %v\n%s", err, out)
	}
	for _, tt := range []struct{ groups, want string }{
		{"hybrid", "X25519MLKEM768"},
		{"classical", "x25519"},
	} {
		t.Run(tt.groups, func(t *testing.T) {
			_, addr := container(t, "4433", func(id string) { docker(t, "cp", bin, id+":/tlsserver") },
				alpineImage, "/tlsserver", "-groups", tt.groups)
			r := probeUntil(t, realProber(t), addr, helloReady)
			if r.Hello.Group != tt.want || r.Hello.HelloRetry {
				t.Fatalf("hello = %+v", r.Hello)
			}
			if r.Handshake == nil || r.Handshake.Error != "" || len(r.Handshake.Certificates) != 1 {
				t.Errorf("handshake = %+v", r.Handshake)
			}
		})
	}
}

// OpenSSH 10 offers the ML-KEM hybrid by default; a restricted server does not.
func TestDockerOpenSSH(t *testing.T) {
	requireDocker(t)
	for _, tt := range []struct {
		name, kex string
		want      []string
		not       []string
	}{
		{"defaults", "", []string{"mlkem768x25519-sha256", "curve25519-sha256"}, nil},
		{"classical only", "curve25519-sha256,ecdh-sha2-nistp256", []string{"curve25519-sha256"}, []string{"mlkem768x25519-sha256"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opt := ""
			if tt.kex != "" {
				opt = " -o KexAlgorithms=" + tt.kex
			}
			script := "apk add --no-cache openssh-server >/dev/null && ssh-keygen -A >/dev/null && " +
				"exec /usr/sbin/sshd -D -e -p 2222" + opt
			_, addr := container(t, "2222", nil, alpineImage, "sh", "-c", script)
			r := probeUntil(t, realProber(t), "ssh://"+addr, func(r Record) bool { return r.SSH != nil && len(r.SSH.Kex) > 0 })
			s := r.SSH
			if s == nil || !strings.Contains(s.Banner, "OpenSSH") {
				t.Fatalf("ssh = %+v", s)
			}
			for _, k := range tt.want {
				if !slices.Contains(s.Kex, k) {
					t.Errorf("kex %v missing %s", s.Kex, k)
				}
			}
			for _, k := range tt.not {
				if slices.Contains(s.Kex, k) {
					t.Errorf("kex %v should not include %s", s.Kex, k)
				}
			}
			t.Logf("%s offers %s", s.Banner, strings.Join(s.Kex, ","))
		})
	}
}
