# Migration-cost benchmarks

`make bench` measures what a post-quantum migration costs in bytes and latency (paper RQ4)
and writes `paper/data/rq4_*.csv`. No number in those files is typed by hand: every size is
measured from a real key, ciphertext or signature, and every latency from timed operations on
the machine named in `rq4_environment.csv`.

```sh
make bench                      # Docker parts, then the host run; several minutes
pqscope bench --quick --runs "" # one iteration of everything, to check the pipeline
```

## What runs where

| Part | Where | Output |
|---|---|---|
| Primitive latency and sizes | the host, `pqscope bench` | `rq4_primitives.csv`, `rq4_sizes.csv` |
| TLS on loopback | the host, `pqscope bench` | `rq4_tls.csv`, env `host` |
| TLS under emulated networks | a Linux container shaped with `tc netem` (`bench/run.sh`, `bench/netem`) | `rq4_tls.csv`, env `docker-linux` |
| Size cross-check | OpenSSL 3.5 in a container (`bench/run.sh`) | the `openssl` column of `rq4_sizes.csv` |

`bench/run.sh` pins `alpine:3.22` by digest. apk installs that branch's current `openssl` and
`iproute2-tc`, and the versions used are recorded in `rq4_environment.csv`. Without Docker, the
script writes nothing, and `pqscope bench` records both Docker parts as not run, so the CSVs
never suggest a check happened when it didn't.

## Primitives

| Algorithm (knowledge DB ID) | Implementation | Operations |
|---|---|---|
| X25519, ECDH-P256 | Go `crypto/ecdh` | keygen, encap, decap (Diffie-Hellman in KEM roles, below) |
| ML-KEM-768, ML-KEM-1024 | Go `crypto/mlkem` (what `crypto/tls` uses) | keygen, encap, decap |
| ML-KEM-512, -768, -1024 | CIRCL | keygen, encap, decap |
| X25519MLKEM768 | Go `crypto/mlkem` + `crypto/ecdh`, composed as `crypto/tls` does | keygen, encap, decap |
| RSA-2048, RSA-3072 | Go `crypto/rsa`, PKCS #1 v1.5 with SHA-256 | keygen, sign, verify |
| ECDSA-P256 | Go `crypto/ecdsa`, SHA-256, DER signatures | keygen, sign, verify |
| ML-DSA-44, -65, -87 | CIRCL, hedged signing, empty context | keygen, sign, verify |
| SLH-DSA-128s, -128f | CIRCL, SHA2 parameter sets, randomized signing, empty context | keygen, sign, verify |

Conventions, chosen to match what a handshake does:

- **Diffie-Hellman in KEM roles.** For X25519 and P-256, `encap` is the responder's work: parse
  the peer's public key, make an ephemeral key, compute the shared secret. The ephemeral public
  key is the "ciphertext". `decap` is the initiator's work: parse it and compute the secret.
- **Parsing is included.** `encap` starts from the encoded public key, `decap` from the encoded
  ciphertext, and `verify` from the encoded public key, as a peer receives them. For ML-DSA,
  unpacking the public key is a real share of verification.
- **Signatures** cover a 128-byte message, about what a TLS 1.3 CertificateVerify signs. RSA and
  ECDSA hash it with SHA-256 inside the timed operation.
- **Before any timing**, each primitive is checked: decapsulation must recover the shared
  secret, and a signature must verify. A broken adapter fails instead of producing numbers.

Each operation runs 5 times untimed. It then runs at least 200 times and for at least 2 seconds,
capped at 200,000 runs. Every call is timed individually, and the CSV reports the mean, the p50
and p99 (nearest rank) and the min and max in nanoseconds, with the sample count.

## Sizes

`rq4_sizes.csv` has what travels: public keys, ciphertexts (or ephemeral public keys),
signatures and shared secrets. Private keys never leave their owner, so they are not measured.
Each size is measured from the implementation's output and compared with two independent
sources:

- **the knowledge DB**, whose sizes `internal/knowledge` tests against the implementations'
  own constants;
- **OpenSSL 3.5's output.** The public key is the `subjectPublicKey` of `openssl pkey -pubout`
  (the RSA modulus for RSA). Ciphertexts and secrets come from `pkeyutl -encap`, signatures
  from `pkeyutl -sign`.

`pqscope bench` exits non-zero if any size disagrees with either source. ECDSA's DER signature
varies in length, so it is reported as the maximum over 64 signatures and marked `variable`,
not compared. The knowledge DB records the fixed 64-byte form. OpenSSL can't export the TLS
hybrid group X25519MLKEM768 as a key, so the hybrid is checked against the knowledge DB only,
whose hybrid sizes are tested to be the sums of their components.

For X25519 and P-256, OpenSSL's `-encap` is DHKEM (RFC 9180). Its ciphertext is the ephemeral
public key, as here. Its shared secret is a KDF output that happens to have the same length as
the raw Diffie-Hellman secret, so that row checks length only.

## TLS

A `crypto/tls` server, with default groups, an in-memory self-signed ECDSA P-256 certificate
and session tickets off, so every handshake is a full one. It is measured against three
clients:

| Client | Offers | Key shares sent |
|---|---|---|
| `classical-x25519` | X25519 | X25519 |
| `hybrid-x25519mlkem768` | X25519MLKEM768 | X25519MLKEM768 |
| `go-default` | Go's default list | X25519MLKEM768 and X25519 |

Each client verifies the server's certificate and keeps no session cache. Per handshake, the
benchmark records:

- the ClientHello and ServerHello record sizes, read from the record headers on the wire;
- the bytes each side sent;
- the negotiated group;
- `tls_handshake`, the time from an established TCP connection to a usable TLS one;
- `tcp_connect+tls_handshake`, the time from dial to a usable TLS connection.

Byte counts are medians over all handshakes. The server's ECDSA signature varies by a byte or
two, and nothing else does.

On the host, each client makes 1,000 handshakes over loopback. The count is fixed, not
time-based, so the run can't exhaust ephemeral ports while closed connections sit in TIME_WAIT.

In the container, `bench/run.sh` shapes the loopback interface for each profile:

| Profile | One-way delay | Added RTT | Loss | MTU | Handshakes per client |
|---|---|---|---|---|---|
| `loopback` | 0 | 0 | 0 | 65536 | 200 |
| `loopback-mtu1500` | 0 | 0 | 0 | 1500 | 200 |
| `rtt2ms` | 1 ms | 2 ms | 0 | 1500 | 200 |
| `rtt40ms` | 20 ms | 40 ms | 0 | 1500 | 200 |
| `rtt150ms` | 75 ms | 150 ms | 0 | 1500 | 200 |
| `rtt40ms-loss1pct` | 20 ms | 40 ms | 1% per packet | 1500 | 500 |

netem on loopback delays every packet once, in either direction, so the added RTT is twice the
delay. An MTU of 1500 makes TCP segment as on Ethernet. Whether a ClientHello fits in one
segment is a real cost of the larger key shares. A connection that fails under loss is counted
in `failures`, not timed. More than half failing is an error.

## Environment

`rq4_environment.csv` records, for `host` and `docker-linux`:

- the OS, architecture, kernel, CPU model and count, memory and CPU frequency governor;
- the Go version, GOMAXPROCS and the CIRCL version;
- the pqscope revision (`git describe --dirty`).

For the container, it also records the Docker version, the netem package, and the OpenSSL
version used. A fact the platform doesn't expose is written as "unknown" or "not applicable"
with the reason, not left blank.

## Known limits

- **One machine, one run.** The numbers describe the recorded machine and its load at the
  time. Background programs, thermal state and, on a laptop, the power source all move them.
  macOS has no CPU governor to pin, and the container runs in Docker Desktop's Linux VM on the
  same hardware, so `docker-linux` latencies include virtualization.
- **Loopback netem is not a WAN.** It adds fixed delay and random loss on one interface. It
  doesn't model jitter, reordering, bandwidth limits or middleboxes. Client and server share
  one kernel and CPU.
- **Go's TLS only.** These are crypto/tls's ClientHellos. Other stacks send different
  extensions, so absolute sizes differ, though the key-share growth (1,184 bytes from client,
  1,088 from server) is fixed by the protocol. The certificate is ECDSA P-256; Go's TLS has no
  ML-DSA certificates, so a post-quantum certificate chain is not measured.
- **Implementations are not optimized equally.** CIRCL and the standard library differ, which
  is why ML-KEM is measured in both. Compare algorithms within one implementation.
