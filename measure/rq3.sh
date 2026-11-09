#!/usr/bin/env bash
# RQ3: how much quantum-vulnerable cryptography the most critical open-source
# projects contain, by layer and exposure. Selects the top distinct projects
# by OpenSSF Criticality Score, shallow-clones each at its default branch's
# head, scans it with pqscope (static analysis only; nothing in the project
# is built or run), deletes the clone, and writes paper/data/rq3_*.csv.
#
# Needs an authenticated gh (root commits and sizes come from the GitHub API)
# and disk for the largest clone. Rerunning resumes: projects already in
# scans.tsv are not scanned again.
#
# Usage: measure/rq3.sh [work-dir]
# Settings: N (projects, default 100), CANDIDATES (default 200), JOBS
# (parallel clones and scans, default 3), SCAN_TIMEOUT (seconds, default 1800).
set -euo pipefail

WORK="${1:-measure/_out/rq3}"
mkdir -p "$WORK/findings" "$WORK/clones"
WORK="$(cd "$WORK" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/paper/data"
N="${N:-100}"
CANDIDATES="${CANDIDATES:-200}"
JOBS="${JOBS:-3}"
SCAN_TIMEOUT="${SCAN_TIMEOUT:-1800}"

# The latest published snapshot. The OpenSSF bucket's objects are no longer
# downloadable, so the copy in the project's repository is used, pinned by
# commit and hash.
CRIT_COMMIT="0e76c6a99d865dddcbd89dff4117f0a54b1abfb8"
CRIT_URL="https://raw.githubusercontent.com/ossf/criticality_score/$CRIT_COMMIT/data/20250725_all.csv.gz"
CRIT_SHA256="86f635183dfdbf023af3d48f499c3f5cb574cc5902d966b20fa38cb35dad61f4"

log() { printf '%s\n' "$*" >&2; }

if [ ! -f "$WORK/criticality.csv.gz" ] || [ "$(shasum -a 256 "$WORK/criticality.csv.gz" | cut -d' ' -f1)" != "$CRIT_SHA256" ]; then
	log "== criticality scores: ossf/criticality_score@$CRIT_COMMIT"
	curl -sSfL -o "$WORK/criticality.csv.gz" "$CRIT_URL"
	echo "$CRIT_SHA256  $WORK/criticality.csv.gz" | shasum -a 256 -c - >/dev/null
fi

REVISION="$(git -C "$ROOT" describe --always --dirty)"
(cd "$ROOT" && go build -o "$WORK/pqscope" ./cmd/pqscope)
PQ="$WORK/pqscope"

# Root commit and size for each candidate. The last page of the commit list,
# one commit per page, holds the root.
"$PQ" measure rq3-select --criticality "$WORK/criticality.csv.gz" --candidates "$CANDIDATES" -o "$WORK/candidates.txt"
touch "$WORK/info.tsv"
while read -r repo; do
	grep -q "^$repo	" "$WORK/info.tsv" && continue
	last="$(gh api -i "repos/$repo/commits?per_page=1" | grep -i '^link:' | grep -o 'page=[0-9]*>; rel="last"' | grep -o '[0-9]*' | head -1 || true)"
	root="$(gh api "repos/$repo/commits?per_page=1&page=${last:-1}" -q '.[0].sha')"
	size="$(gh api "repos/$repo" -q .size)"
	printf '%s\t%s\t%s\n' "$repo" "$root" "$size" >> "$WORK/info.tsv"
done < "$WORK/candidates.txt"
"$PQ" measure rq3-select --criticality "$WORK/criticality.csv.gz" --candidates "$CANDIDATES" \
	--info "$WORK/info.tsv" --n "$N" -o "$WORK/selection.tsv"
log "== $(grep -c '	selected$' "$WORK/selection.tsv") projects to scan with $JOBS jobs"

clone() { # repo dir
	GIT_LFS_SKIP_SMUDGE=1 git clone -q --depth 1 --single-branch --no-tags "https://github.com/$1.git" "$2" 2>>"$2.clone.log"
}

# scan_one clones, scans and deletes one project, appending a line to
# scans.tsv: repo, commit, status, seconds.
scan_one() {
	local repo=$1 dir status commit="" start=$SECONDS code=0
	dir="$WORK/clones/${repo//\//__}"
	rm -rf "$dir"
	# One retry: a large checkout sometimes ends with the remote hanging up.
	if ! clone "$repo" "$dir" && ! { rm -rf "$dir"; clone "$repo" "$dir"; }; then
		status="clone failed"
	else
		commit="$(git -C "$dir" rev-parse HEAD)"
		"$PQ" scan "$dir" --json > "$WORK/findings/${repo//\//__}.json.tmp" 2>"$WORK/findings/${repo//\//__}.err" &
		local pid=$!
		( sleep "$SCAN_TIMEOUT" && kill "$pid" 2>/dev/null ) &
		local watch=$!
		wait "$pid" || code=$?
		kill "$watch" 2>/dev/null || true
		if [ "$code" -eq 0 ]; then
			mv "$WORK/findings/${repo//\//__}.json.tmp" "$WORK/findings/${repo//\//__}.json"
			status=scanned
		elif [ "$code" -ge 128 ]; then
			status="scan timed out after ${SCAN_TIMEOUT}s"
		else
			status="scan failed (exit $code)"
		fi
		rm -f "$WORK/findings/${repo//\//__}.json.tmp"
	fi
	rm -rf "$dir"
	printf '%s\t%s\t%s\t%s\n' "$repo" "$commit" "$status" "$((SECONDS - start))" >> "$WORK/scans.tsv"
	log "   $repo: $status ($((SECONDS - start))s)"
}
export -f scan_one clone log
export WORK PQ SCAN_TIMEOUT

touch "$WORK/scans.tsv"
awk -F'\t' '$7 == "selected" { print $2 }' "$WORK/selection.tsv" | while read -r repo; do
	grep -q "^$repo	[^	]*	scanned	" "$WORK/scans.tsv" || echo "$repo"
done | xargs -P "$JOBS" -I{} bash -c 'scan_one "$1"' _ {}

# Keep only the latest line per project (a resumed run appends).
awk -F'\t' '{ last[$1] = $0 } END { for (r in last) print last[r] }' "$WORK/scans.tsv" | sort > "$WORK/scans.latest.tsv"

"$PQ" measure rq3 --selection "$WORK/selection.tsv" --scans "$WORK/scans.latest.tsv" --findings "$WORK/findings" --out "$DATA" \
	--meta "criticality_source=$CRIT_URL" \
	--meta "criticality_sha256=$CRIT_SHA256" \
	--meta "criticality_snapshot=2025-07-25" \
	--meta "candidates=$CANDIDATES" \
	--meta "projects=$N" \
	--meta "clone=git clone --depth 1 --single-branch --no-tags (default branch head), LFS files not fetched" \
	--meta "scan=pqscope scan --json (source, config, deps, binary layers; reconciliation on)" \
	--meta "scan_timeout_seconds=$SCAN_TIMEOUT" \
	--meta "host=$(uname -sm)" \
	--meta "pqscope_revision=$REVISION"

mkdir -p "$DATA/raw"
# No owner names or macOS metadata in the archive: it is published, and an
# account name in its headers would identify whoever ran the scan.
tar --uid 0 --gid 0 --uname '' --gname '' --no-mac-metadata \
	-C "$WORK/findings" -czf "$DATA/raw/rq3_findings.tar.gz" $(cd "$WORK/findings" && ls ./*.json)
log "done: $DATA/rq3_*.csv, findings in $DATA/raw/rq3_findings.tar.gz"
