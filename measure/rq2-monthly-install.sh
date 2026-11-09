#!/usr/bin/env bash
# Installs the monthly RQ2 repeat as a launchd job for the current user: on
# the 8th of each month at 12:48 local time (or at the next wake if the Mac
# was asleep), it runs measure/rq2-monthly.sh. Run this from the network the
# baseline was scanned from: it records the default gateway's hardware
# address, and the monthly run is skipped on any other network.
#
# Usage: measure/rq2-monthly-install.sh            install or update
#        measure/rq2-monthly-install.sh --remove   uninstall
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="io.github.emmanueladutwum123.pqscope.rq2-monthly"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
STATE="$ROOT/measure/_out/monthly"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
if [ "${1:-}" = "--remove" ]; then
	rm -f "$PLIST"
	echo "removed $LABEL"
	exit 0
fi

mkdir -p "$STATE" "$(dirname "$PLIST")"
gw="$(route -n get default | awk '/gateway/ {print $2}')"
mac="$(arp -n "$gw" | awk '{print $4}')"
case "$mac" in
	*:*:*:*:*:*) printf '%s\n' "$mac" > "$STATE/vantage-gateway" ;;
	*) echo "could not read the default gateway's hardware address" >&2; exit 1 ;;
esac

GO_DIR="$(dirname "$(command -v go)")"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>$LABEL</string>
	<key>ProgramArguments</key>
	<array><string>$ROOT/measure/rq2-monthly.sh</string></array>
	<key>WorkingDirectory</key><string>$ROOT</string>
	<key>EnvironmentVariables</key>
	<dict><key>PATH</key><string>$GO_DIR:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
	<key>StartCalendarInterval</key>
	<dict><key>Day</key><integer>8</integer><key>Hour</key><integer>12</integer><key>Minute</key><integer>48</integer></dict>
	<key>StandardOutPath</key><string>$STATE/launchd.log</string>
	<key>StandardErrorPath</key><string>$STATE/launchd.log</string>
</dict>
</plist>
PLIST
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "installed $LABEL: runs on the 8th of each month at 12:48; gateway $mac recorded"
