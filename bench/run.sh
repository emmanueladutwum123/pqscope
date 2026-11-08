#!/usr/bin/env bash
# Runs the parts of the migration-cost benchmarks that need Docker, writing
# raw results under bench/out/ for `pqscope bench --runs bench/out` to merge:
#
#   openssl/  OpenSSL 3.5's own keys, ciphertexts, shared secrets and
#             signatures, one directory per knowledge DB ID, to cross-check the
#             sizes pqscope measures. OpenSSL is never a runtime dependency.
#   netem/    TLS handshakes in a Linux container whose loopback interface is
#             shaped with tc netem, one JSON file per network profile.
#
# Without Docker it writes nothing, and `pqscope bench` records both parts as
# not run.
#
# Usage: bench/run.sh [out-dir]
set -euo pipefail

OUT="${1:-bench/out}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Pinned versions. Change them here only. apk installs the alpine 3.22
# branch's current openssl and iproute2-tc; the versions used are recorded.
ALPINE_IMAGE="alpine:3.22@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034"

# Network profiles: name, one-way delay (ms), per-packet loss (%), loopback
# MTU. netem on loopback delays every packet once, so the added RTT is twice
# the delay. An MTU of 1500 makes TCP segment as on Ethernet; loopback's
# default (65536) never splits a ClientHello.
PROFILES="loopback:0:0:65536 loopback-mtu1500:0:0:1500 rtt2ms:1:0:1500 rtt40ms:20:0:1500 rtt150ms:75:0:1500 rtt40ms-loss1pct:20:1:1500"
# Handshakes per client configuration and profile; more under loss, where
# the tail is the point.
NETEM_N="${NETEM_N:-200}"
NETEM_N_LOSS="${NETEM_N_LOSS:-500}"

log() { printf '%s\n' "$*" >&2; }

if ! docker info >/dev/null 2>&1; then
	log "Docker is not available: OpenSSL sizes and netem runs are not produced."
	exit 0
fi
REVISION="$(git -C "$ROOT" describe --always --dirty 2>/dev/null || echo unknown)"

log "== openssl sizes ($ALPINE_IMAGE)"
rm -rf "$OUT/openssl" && mkdir -p "$OUT/openssl"
docker run --rm -v "$OUT/openssl:/out" "$ALPINE_IMAGE" sh -euc '
	apk add --no-cache openssl >/dev/null
	openssl version > /out/version.txt
	cd /tmp
	# The 128-byte message pqscope signs (internal/bench.Message).
	printf "%128s" "" > msg
	key() { # id genpkey-args...
		id=$1; shift
		mkdir -p "/out/$id"
		openssl genpkey -quiet "$@" -out k.pem
		openssl pkey -in k.pem -pubout -outform DER -out "/out/$id/pub.der"
	}
	kem() { key "$@"; openssl pkeyutl -encap -inkey k.pem -out "/out/$1/ct" -secret "/out/$1/ss"; }
	sig() { key "$@"; openssl pkeyutl -sign -rawin -inkey k.pem -in msg -out "/out/$1/sig"; }
	sig_sha256() { key "$@"; openssl pkeyutl -sign -rawin -digest sha256 -inkey k.pem -in msg -out "/out/$1/sig"; }

	kem X25519 -algorithm X25519
	kem ECDH-P256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
	kem ML-KEM-512 -algorithm ML-KEM-512
	kem ML-KEM-768 -algorithm ML-KEM-768
	kem ML-KEM-1024 -algorithm ML-KEM-1024
	sig_sha256 RSA-2048 -algorithm RSA -pkeyopt rsa_keygen_bits:2048
	sig_sha256 RSA-3072 -algorithm RSA -pkeyopt rsa_keygen_bits:3072
	sig_sha256 ECDSA-P256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
	sig ML-DSA-44 -algorithm ML-DSA-44
	sig ML-DSA-65 -algorithm ML-DSA-65
	sig ML-DSA-87 -algorithm ML-DSA-87
	sig SLH-DSA-128s -algorithm SLH-DSA-SHA2-128s
	sig SLH-DSA-128f -algorithm SLH-DSA-SHA2-128f
'
log "   $(cat "$OUT/openssl/version.txt")"

log "== netem TLS ($ALPINE_IMAGE)"
case "$(docker info --format '{{.Architecture}}')" in
aarch64 | arm64) ARCH=arm64 ;;
x86_64 | amd64) ARCH=amd64 ;;
*) log "unsupported Docker architecture"; exit 1 ;;
esac
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$OUT/netem-linux" ./bench/netem)
NOTE="Docker $(docker version --format '{{.Server.Version}}') container ($ARCH) on $(uname -sm); loopback shaped with tc netem"
rm -rf "$OUT/netem" && mkdir -p "$OUT/netem"
docker run --rm --cap-add NET_ADMIN -v "$OUT/netem-linux:/netem:ro" -v "$OUT/netem:/out" \
	-e PROFILES="$PROFILES" -e N="$NETEM_N" -e N_LOSS="$NETEM_N_LOSS" -e REVISION="$REVISION" -e NOTE="$NOTE" \
	"$ALPINE_IMAGE" sh -euc '
	apk add --no-cache iproute2-tc >/dev/null
	note="$NOTE ($(apk info -v 2>/dev/null | grep -E "^iproute2-tc-" | head -1))"
	for p in $PROFILES; do
		IFS=: read -r name delay loss mtu <<EOF
$p
EOF
		tc qdisc del dev lo root 2>/dev/null || true
		ip link set lo mtu "$mtu"
		n=$N
		if [ "$delay" != 0 ] || [ "$loss" != 0 ]; then
			tc qdisc add dev lo root netem delay "${delay}ms" loss "${loss}%"
		fi
		[ "$loss" != 0 ] && n=$N_LOSS
		echo "   $name: $(tc qdisc show dev lo | head -1), mtu $mtu, n=$n" >&2
		/netem -profile "$name" -delay-ms "$delay" -loss "$loss" -mtu "$mtu" -n "$n" \
			-revision "$REVISION" -note "$note" -o "/out/$name.json"
	done
'
log "done: $OUT"
