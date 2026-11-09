#!/usr/bin/env bash
# One monthly repeat of the RQ2 scan, for the longitudinal trend. Writes
# paper/data/rq2_trend/<YYYY-MM>/ with the same files measure/rq2.sh writes
# for the baseline, from the same vantage point at the same rate. It never
# commits or pushes: review the snapshot, then commit it.
#
# The vantage point is part of the measurement, so the run is skipped (with
# a notification) unless the default gateway's hardware address matches the
# one recorded by measure/rq2-monthly-install.sh. A month that already has a
# snapshot is skipped too.
#
# Usage: measure/rq2-monthly.sh            (normally run by launchd)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/measure/_out/monthly"
mkdir -p "$STATE"
MONTH="$(date -u +%Y-%m)"
DEST="$ROOT/paper/data/rq2_trend/$MONTH"
VANTAGE="home internet connection (consumer ISP); macOS host (Apple M2); the source address has no reverse DNS pointing to the project"

notify() {
	printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$STATE/monthly.log"
	/usr/bin/osascript -e "display notification \"$1\" with title \"pqscope monthly .gov scan\"" >/dev/null 2>&1 || true
}

if [ -e "$DEST/rq2_summary.csv" ]; then
	notify "Skipped: $MONTH already has a snapshot."
	exit 0
fi

gateway_mac() {
	local gw
	gw="$(route -n get default 2>/dev/null | awk '/gateway/ {print $2}')"
	[ -n "$gw" ] && arp -n "$gw" 2>/dev/null | awk '{print $4}'
}
want="$(cat "$STATE/vantage-gateway" 2>/dev/null || true)"
have="$(gateway_mac || true)"
if [ -z "$want" ] || [ "$have" != "$want" ]; then
	notify "Skipped: not on the home network the baseline was scanned from. Run measure/rq2-monthly.sh by hand from there this month."
	exit 0
fi

notify "Started the $MONTH scan (about 10 minutes)."
WORK="$ROOT/measure/_out/rq2-$MONTH"
if RQ2_DATA="$DEST" VANTAGE="$VANTAGE" "$ROOT/measure/rq2.sh" "$WORK" >> "$STATE/monthly.log" 2>&1; then
	share="$(awk -F, '$1=="endpoint" && $2=="all" {printf "%.1f%%", 100*$14}' "$DEST/rq2_summary.csv")"
	notify "Done: $MONTH hybrid adoption $share. Review paper/data/rq2_trend/$MONTH, then commit."
else
	rm -rf "$DEST"
	notify "Failed: see measure/_out/monthly/monthly.log. Nothing was kept."
	exit 1
fi
