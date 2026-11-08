#!/usr/bin/env bash
# Runs pqscope's competitors over the labeled corpus and writes their raw
# output to eval/out/<tool>/, with a tool.json describing each run. It also
# starts the network corpus servers and probes them with pqscope.
#
# Every tool runs in a container pinned by digest (or a pinned package
# version or commit), once over the whole corpus; `pqscope eval` then splits
# results by case. A tool that cannot run is recorded as unavailable with the
# reason, never left out silently.
#
# Usage: eval/run.sh [all|competitors|network] [corpus-dir] [out-dir]
#
# `competitors` downloads and runs third-party scanners (container images and
# pip packages at the pinned versions below); `network` runs only pqscope
# against servers built from alpine:3.22.
set -uo pipefail

MODE="${1:-all}"
CORPUS="$(cd "${2:-testdata/corpus}" && pwd)"
OUT="${3:-eval/out}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Pinned versions. Change them here only.
CBOMKIT_THEIA_IMAGE="ghcr.io/cbomkit/cbomkit-theia@sha256:46a72eadc9849b919fc4c72e1c851f9783e03c35db8fad49ba99341ac97f8dea"
CBOMKIT_ACTION_IMAGE="ghcr.io/cbomkit/cbomkit-action:v2.3.0@sha256:47c2505267dc5f055152616ffa0d0076b7d0824fe9e0de670b572d1ebad2fc4b"
SEMGREP_IMAGE="semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed"
SEMGREP_RULES_COMMIT="16b9e6d45f10649f6a531ec4838ed9924372c3bc"
PYTHON_IMAGE="python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
CRYPTOSCAN_VERSION="0.1.1"
PQC_AUDIT_COMMIT="2b11fc59b0ce8701650a602db51c170953ae0c9e"
NETWORK_TIMEOUT=120

log() { printf '%s\n' "$*" >&2; }

# tool_json name version source status reason
tool_json() {
	mkdir -p "$OUT/$1"
	python3 - "$OUT/$1/tool.json" "$@" <<'PY'
import json, sys
path, name, version, source, status, reason = sys.argv[1:7]
json.dump({"tool": name, "version": version, "source": source, "status": status, "reason": reason},
          open(path, "w"), indent=2)
PY
}

if ! docker info >/dev/null 2>&1; then
	log "Docker is not available: competitors and network cases are recorded as unavailable."
	for t in cbomkit-theia cbomkit-action semgrep cryptoscan-pqc pqc-audit; do
		tool_json "$t" "" "" unavailable "Docker not available"
	done
	tool_json pqscope-network "" "" unavailable "Docker not available"
	tool_json keylens "" "" unavailable "No crypto scanner named Keylens could be found (GitHub search, 2026-11-08)"
	exit 0
fi

competitors() {
# Competitors scan a copy of the corpus without its answer key: labels.yaml,
# READMEs and the network server definitions.
# The leading underscore keeps the go tool (go vet ./..., go mod tidy) from
# treating the staged corpus's Go files as packages of this module.
STAGE="$OUT/_corpus-stage"
rm -rf "$STAGE" && mkdir -p "$STAGE"
rsync -a --exclude labels.yaml --exclude README.md --exclude server.env --exclude server.sh "$CORPUS/" "$STAGE/"
# local: the network stage still needs the server definitions in $CORPUS.
local CORPUS="$STAGE"

run_tool() { # name version source output command...
	# output is a path, relative to the tool's directory, whose presence
	# means the tool produced results. Some tools exit non-zero to gate CI
	# when they find something; with output written, that still counts as a run.
	local name=$1 version=$2 source=$3 output=$4
	shift 4
	rm -rf "${OUT:?}/$name"
	mkdir -p "$OUT/$name"
	log "== $name ($version)"
	local start=$SECONDS code=0
	"$@" >"$OUT/$name/stdout.log" 2>"$OUT/$name/stderr.log" || code=$?
	if [ "$code" -eq 0 ]; then
		tool_json "$name" "$version" "$source" ran ""
	elif [ -n "$(find "$OUT/$name" -path "$OUT/$name/$output" -size +0 2>/dev/null | head -1)" ]; then
		tool_json "$name" "$version" "$source" ran "exit $code with output written (the tool's findings exit code)"
	else
		tool_json "$name" "$version" "$source" failed "exit $code (see stderr.log)"
	fi
	log "   $((SECONDS - start))s"
}

# CBOMkit indexes "project modules"; corpus cases share file names (Main.java,
# main.py) and collapse into one module, so it runs once per case.
cbomkit_action_per_case() {
	local d g c status=0
	for d in "$CORPUS"/java/*/ "$CORPUS"/python/*/; do
		g=$(basename "$(dirname "$d")")
		c=$(basename "$d")
		mkdir -p "$OUT/cbomkit-action/$g/$c"
		docker run --rm -v "${d%/}:/workspace/$g/$c:ro" -v "$OUT/cbomkit-action/$g/$c:/out" \
			-e GITHUB_WORKSPACE=/workspace -e CBOMKIT_LANGUAGES=java,python -e CBOMKIT_OUTPUT_DIR=/out \
			-e CBOMKIT_EXCLUDE= -e CBOMKIT_JAVA_REQUIRE_BUILD=false "$CBOMKIT_ACTION_IMAGE" || status=$?
	done
	return $status
}

# CBOMkit-theia: directories and images (certificates, keys, configs). Not source.
run_tool cbomkit-theia "latest@46a72ead" "$CBOMKIT_THEIA_IMAGE" cbom.json \
	sh -c "docker run --rm -v '$CORPUS:/data:ro' '$CBOMKIT_THEIA_IMAGE' dir /data > '$OUT/cbomkit-theia/cbom.json'"

# CBOMkit (sonar-cryptography) through its GitHub Action image: Java and Python source.
run_tool cbomkit-action "v2.3.0" "$CBOMKIT_ACTION_IMAGE" "*/*/cbom.json" cbomkit_action_per_case

# Semgrep with the community registry's crypto rules for the corpus languages.
RULES="$OUT/semgrep-rules"
rm -rf "$RULES" && mkdir -p "$RULES"
if curl -sfL "https://github.com/semgrep/semgrep-rules/archive/$SEMGREP_RULES_COMMIT.tar.gz" | tar -xz -C "$RULES" --strip-components=1; then
	find "$RULES" -name '*.yaml' | grep -v -E '/(go|python|java|javascript|c)/' | xargs rm -f
	find "$RULES" -name '*.yaml' | grep -v -i -E '(crypto|md5|sha1|sha224|des|rsa|ecb|cipher|rc4|blowfish|hash)' | xargs rm -f
	find "$RULES" -type f ! -name '*.yaml' -delete
	run_tool semgrep "1.184.0+rules@${SEMGREP_RULES_COMMIT:0:8}" "$SEMGREP_IMAGE" results.json \
		sh -c "docker run --rm -v '$CORPUS:/src:ro' -v '$RULES:/rules:ro' '$SEMGREP_IMAGE' semgrep scan --config /rules --json --metrics=off --no-git-ignore --disable-version-check /src > '$OUT/semgrep/results.json'"
else
	tool_json semgrep "1.184.0" "$SEMGREP_IMAGE" failed "could not download semgrep-rules $SEMGREP_RULES_COMMIT"
fi

# cryptoscan-pqc from PyPI.
run_tool cryptoscan-pqc "$CRYPTOSCAN_VERSION" "pypi:cryptoscan-pqc==$CRYPTOSCAN_VERSION in $PYTHON_IMAGE" cbom.json \
	docker run --rm -v "$CORPUS:/src:ro" -v "$OUT/cryptoscan-pqc:/out" "$PYTHON_IMAGE" \
	sh -c "pip install -q --disable-pip-version-check cryptoscan-pqc==$CRYPTOSCAN_VERSION && pqscan scan /src -o /out/cbom.json"

# pqc-audit (pqc-migration-audit) from a pinned commit.
run_tool pqc-audit "${PQC_AUDIT_COMMIT:0:8}" "github:danieleschmidt/pqc-migration-audit@$PQC_AUDIT_COMMIT in $PYTHON_IMAGE" report.json \
	docker run --rm -v "$CORPUS:/src:ro" -v "$OUT/pqc-audit:/out" "$PYTHON_IMAGE" \
	sh -c "pip install -q --disable-pip-version-check https://github.com/danieleschmidt/pqc-migration-audit/archive/$PQC_AUDIT_COMMIT.tar.gz && pqc-audit /src --output /out/report.json --format json"

tool_json keylens "" "" unavailable "No crypto scanner named Keylens could be found (GitHub search, 2026-11-08)"
}

network() {
# Network corpus: start each server and probe it with pqscope.
log "== pqscope-network"
PQSCOPE="$OUT/pqscope-bin"
(cd "$ROOT" && go build -o "$PQSCOPE" ./cmd/pqscope) || { tool_json pqscope-network "" "" failed "build failed"; return; }
rm -rf "$OUT/pqscope-network" && mkdir -p "$OUT/pqscope-network"
status=ran
for dir in "$CORPUS"/network/*/; do
	name=$(basename "$dir")
	# shellcheck disable=SC1091
	IMAGE="" PORT="" PROBE=""
	. "$dir/server.env"
	id=$(docker run -d -p "127.0.0.1::$PORT" "$IMAGE" sh -c "$(cat "$dir/server.sh")")
	addr=$(docker port "$id" "$PORT/tcp" | head -1)
	ok=""
	for _ in $(seq 1 "$NETWORK_TIMEOUT"); do
		if "$PQSCOPE" net "$PROBE://$addr" --findings "$OUT/pqscope-network/$name.json" -o "$OUT/pqscope-network/$name.jsonl" 2>/dev/null &&
			grep -q -E '"(group|kex)"' "$OUT/pqscope-network/$name.jsonl"; then
			ok=1
			break
		fi
		sleep 1
	done
	docker rm -f "$id" >/dev/null
	if [ -z "$ok" ]; then
		log "   $name: server did not answer"
		status=partial
		rm -f "$OUT/pqscope-network/$name.json"
	fi
done
tool_json pqscope-network "$("$PQSCOPE" version)" "eval/run.sh network servers" "$status" ""
}

case "$MODE" in
all) competitors; network ;;
competitors) competitors ;;
network) network ;;
*) log "unknown mode $MODE (want all, competitors or network)"; exit 2 ;;
esac
log "done: $OUT"
