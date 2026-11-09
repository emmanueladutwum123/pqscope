#!/usr/bin/env bash
# RQ2: which public federal .gov TLS endpoints negotiate hybrid post-quantum
# key exchange. Probes the apex and www of every domain in CISA's federal
# .gov list with standard TLS handshakes (see docs/scanning.md for exactly
# what is sent), then writes paper/data/rq2_*.csv and the raw records.
#
# This connects to thousands of servers you do not operate. Read
# docs/measurement.md first, run it from a vantage point you are entitled to
# scan from, and keep the opt-out list (measure/exclude.txt) current.
#
# Usage: VANTAGE="description of where this runs" measure/rq2.sh [work-dir]
# Settings: RATE (connections/s, default 10), VANTAGE, RQ2_DATA (where the
# tables and raw records go; default paper/data, the paper's baseline).
set -euo pipefail

WORK="${1:-measure/_out/rq2}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${RQ2_DATA:-$ROOT/paper/data}"
mkdir -p "$DATA"
RATE="${RATE:-10}"
VANTAGE="${VANTAGE:-unspecified}"

log() { printf '%s\n' "$*" >&2; }

# The domain list at the commit current when the run starts, recorded.
DOTGOV_COMMIT="$(git ls-remote https://github.com/cisagov/dotgov-data.git refs/heads/main | cut -f1)"
DOTGOV_URL="https://raw.githubusercontent.com/cisagov/dotgov-data/$DOTGOV_COMMIT/current-federal.csv"
log "== domains: cisagov/dotgov-data@$DOTGOV_COMMIT"
curl -sSfL -o "$WORK/current-federal.csv" "$DOTGOV_URL"

# iptoasn.com updates its table hourly, so the file is identified by hash
# and Last-Modified rather than a pinned URL.
ASN_URL="https://iptoasn.com/data/ip2asn-combined.tsv.gz"
log "== ASN table: $ASN_URL"
curl -sSfL -D "$WORK/ip2asn.headers" -o "$WORK/ip2asn-combined.tsv.gz" "$ASN_URL"
ASN_SHA256="$(shasum -a 256 "$WORK/ip2asn-combined.tsv.gz" | cut -d' ' -f1)"
ASN_MODIFIED="$(grep -i '^last-modified:' "$WORK/ip2asn.headers" | tail -1 | cut -d' ' -f2- | tr -d '\r')"

REVISION="$(git -C "$ROOT" describe --always --dirty)"
(cd "$ROOT" && go build -o "$WORK/pqscope" ./cmd/pqscope)
PQ="$WORK/pqscope"

"$PQ" measure rq2-targets --dotgov "$WORK/current-federal.csv" -o "$WORK/targets.txt"
log "== probing $(wc -l < "$WORK/targets.txt" | tr -d ' ') endpoints at $RATE connections/s"
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
"$PQ" net --targets "$WORK/targets.txt" --exclude "$ROOT/measure/exclude.txt" --rate "$RATE" -o "$WORK/net.jsonl"
END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

"$PQ" measure rq2 --dotgov "$WORK/current-federal.csv" --records "$WORK/net.jsonl" \
	--asn "$WORK/ip2asn-combined.tsv.gz" --out "$DATA" \
	--meta "dotgov_source=$DOTGOV_URL" \
	--meta "asn_source=$ASN_URL" \
	--meta "asn_sha256=$ASN_SHA256" \
	--meta "asn_last_modified=$ASN_MODIFIED" \
	--meta "run_start_utc=$START" \
	--meta "run_end_utc=$END" \
	--meta "rate_connections_per_second=$RATE" \
	--meta "probe=pqscope net defaults: ClientHello offering X25519MLKEM768, x25519, secp256r1 with key shares for the first two; then a crypto/tls handshake for certificates" \
	--meta "exclude_entries=$(grep -c -v -E '^[[:space:]]*(#|$)' "$ROOT/measure/exclude.txt" || true)" \
	--meta "vantage=$VANTAGE" \
	--meta "pqscope_revision=$REVISION"

mkdir -p "$DATA/raw"
gzip -9 -n -c "$WORK/net.jsonl" > "$DATA/raw/rq2_net.jsonl.gz"
log "done: $DATA/rq2_*.csv, raw records in $DATA/raw/rq2_net.jsonl.gz"
