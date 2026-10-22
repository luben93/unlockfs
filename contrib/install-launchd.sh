#!/usr/bin/env bash
set -euo pipefail
# Installs the built ./unlockfs as a login launchd agent mounted at ~/.unlockfs/mnt.
cd "$(dirname "$0")/.."
[ -x ./unlockfs ] || { echo "run 'make' first"; exit 1; }
mkdir -p ~/.local/bin ~/.unlockfs/mnt ~/Library/LaunchAgents
install -m 755 unlockfs ~/.local/bin/unlockfs
P=~/Library/LaunchAgents/io.github.unlockfs.plist
cat > "$P" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>io.github.unlockfs</string>
  <key>ProgramArguments</key><array><string>$HOME/.local/bin/unlockfs</string><string>serve</string><string>$HOME/.unlockfs/mnt</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$HOME/.unlockfs/unlockfs.log</string>
</dict></plist>
PL
launchctl bootout "gui/$(id -u)/io.github.unlockfs" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$P"
echo "installed; mounted at ~/.unlockfs/mnt"
