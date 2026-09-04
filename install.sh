#!/usr/bin/env bash
# Install the malware-guard LaunchAgent (runs the process monitor at login).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS="$HOME/Library/LaunchAgents"
LABEL="com.polinrider-guard.monitor"
PLIST="$AGENTS/$LABEL.plist"

mkdir -p "$AGENTS" "$HOME/.local/state/malware-guard"
chmod +x "$HERE/malware-guard.sh" "$HERE/block-c2-hosts.sh"

sed -e "s|__HOME__|$HOME|g" -e "s|__TOOLKIT_DIR__|$HERE|g" \
  "$HERE/com.polinrider-guard.monitor.plist" > "$PLIST"

launchctl unload "$PLIST" 2>/dev/null || true
launchctl load  "$PLIST"
echo "✓ malware-guard loaded. Status:"
launchctl list | grep "$LABEL" || true
echo
echo "Logs:      ~/.local/state/malware-guard/"
echo "Test it:   node -e \"const x='windowsHide'; setTimeout(()=>{}, 8000)\"   (should be killed within ~2s)"
echo "Stop it:   launchctl unload $PLIST"
echo
echo "Now also run the network-side block (needs your password):"
echo "   sudo bash $HERE/block-c2-hosts.sh"
echo
echo "Then install the git hooks:"
echo "   bash $HERE/install-githooks.sh"
