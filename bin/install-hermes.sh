#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${HERMES_SKILLS_DIR:-$HOME/.hermes/skills/research}/osint-hybrid-investigation"
PARENT="$(dirname "$DEST")"
mkdir -p "$PARENT"

# Preserve prior case artifacts during an in-place upgrade.
TMP_CASES=""
if [ -d "$DEST/cases" ]; then
  TMP_CASES="$(mktemp -d)/cases"
  mv "$DEST/cases" "$TMP_CASES"
fi

rm -rf "$DEST"
cp -R "$HERE" "$DEST"

if [ -n "$TMP_CASES" ] && [ -d "$TMP_CASES" ]; then
  rm -rf "$DEST/cases"
  mv "$TMP_CASES" "$DEST/cases"
fi

chmod +x "$DEST/bin/domain_osint.py" "$DEST/bin/install-hermes.sh" "$DEST/bin/check-credentials.py" "$DEST/bin/preflight.py"
printf 'Installed Hermes OSINT Hybrid Framework to:\n  %s\n' "$DEST"
printf 'Existing cases preserved when present.\n'
printf 'Preflight:\n  python3 %s/bin/preflight.py\n' "$DEST"
printf 'Domain runner example:\n  python3 %s/bin/domain_osint.py example.com\n' "$DEST"
