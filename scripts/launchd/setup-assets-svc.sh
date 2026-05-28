#!/usr/bin/env bash
# One-shot installer for the polar-assets-svc launchd auto-start. Run on
# the deploy box; idempotent.
#
#   bash scripts/launchd/setup-assets-svc.sh
#
# Steps:
#   1. Copy the wrapper to ~/.local/bin/polar-assets-svc-launch.sh
#   2. Copy the plist to ~/Library/LaunchAgents/polar.assets-svc.plist
#   3. Bootstrap ~/assets-svc.env from the sample IF it doesn't exist
#      yet (operator fills in real values + chmod 600)
#   4. launchctl load -w to start + auto-start at login
#
# Prerequisites:
#   - Plugin row provisioned via /admin-plugins.html on dock (capture
#     the one-time plaintext into POLAR_PLUGIN_TOKEN in the env file)
#   - assets-svc binary present at $HOME/.local/bin/assets-svc

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_BIN="$HOME/.local/bin"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"
ENV_FILE="$HOME/assets-svc.env"

mkdir -p "$LOCAL_BIN" "$LAUNCH_AGENTS"

echo "→ installing wrapper at $LOCAL_BIN/polar-assets-svc-launch.sh"
install -m 0755 "$SCRIPT_DIR/polar-assets-svc-launch.sh" "$LOCAL_BIN/polar-assets-svc-launch.sh"

echo "→ installing plist at $LAUNCH_AGENTS/polar.assets-svc.plist"
install -m 0644 "$SCRIPT_DIR/polar.assets-svc.plist" "$LAUNCH_AGENTS/polar.assets-svc.plist"
plutil -lint "$LAUNCH_AGENTS/polar.assets-svc.plist"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "→ $ENV_FILE not found — bootstrapping from sample (you must fill in real values + chmod 600)"
  install -m 0600 "$SCRIPT_DIR/assets-svc.env.sample" "$ENV_FILE"
  echo ""
  echo "  ! Provision a plugin row via /admin-plugins.html and paste"
  echo "    the printed plaintext into POLAR_PLUGIN_TOKEN in $ENV_FILE."
  echo "    Re-use dock's METRICS_TOKEN for POLAR_ASSETS_METRICS_TOKEN if"
  echo "    you want Prometheus to scrape both with one bearer."
  echo ""
else
  echo "→ $ENV_FILE already present, leaving untouched"
fi

echo "→ launchctl unload + reload (idempotent)"
launchctl unload "$LAUNCH_AGENTS/polar.assets-svc.plist" 2>/dev/null || true
launchctl load -w "$LAUNCH_AGENTS/polar.assets-svc.plist"

sleep 3
if pgrep -fl assets-svc >/dev/null; then
  echo "✓ assets-svc is running under launchd."
  echo "  log: tail -f /tmp/polar.assets-svc.log"
  echo "  smoke: curl -s http://127.0.0.1:8091/healthz"
else
  echo "✗ assets-svc did not start. Check /tmp/polar.assets-svc.log + ~/assets-svc.env."
  exit 1
fi
