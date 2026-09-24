#!/usr/bin/env bash
#
# make-offline-bundle.sh — produce a self-contained copy of the site an
# instructor can carry on a USB stick and serve from a laptop with no network.
#
# Open Door Range is entirely static: HTML, CSS, ES modules and one wasm binary,
# with no CDN and no request that ever leaves the browser. So an "offline
# bundle" is simply a faithful copy of site/ (including the built pkg/), plus a
# note telling the recipient how to serve it. This script makes that copy and
# zips it, and refuses to build a bundle that would be broken on arrival.
#
# It changes nothing in the repo. Output lands in dist/ (git-ignored territory —
# it is not committed).
#
# Usage:
#   tools/make-offline-bundle.sh            # -> dist/open-door-range-offline.zip
#   tools/make-offline-bundle.sh /path/out  # choose the output directory
#
set -euo pipefail

# Resolve the repo root from this script's location, so it runs from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SITE_DIR="$REPO_ROOT/site"
OUT_DIR="${1:-$REPO_ROOT/dist}"
STAGE="$OUT_DIR/open-door-range-offline"
ZIP_PATH="$OUT_DIR/open-door-range-offline.zip"

echo "Open Door Range — offline bundle"
echo "  site:   $SITE_DIR"
echo "  output: $OUT_DIR"
echo

# The wasm engine must be built, or the bundle boots to a blank page. site/pkg
# is git-ignored and produced by wasm-pack; this script never builds it (that is
# the site build's job), it only insists it is present.
WASM="$SITE_DIR/pkg/odr_wasm_bg.wasm"
if [ ! -f "$WASM" ]; then
  echo "ERROR: $WASM is missing." >&2
  echo "Build the engine first:" >&2
  echo "  wasm-pack build crates/odr-wasm --target web --out-dir ../../site/pkg" >&2
  exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE"

# Copy the whole site verbatim. Everything the page needs is under site/, and
# copying it wholesale means the bundle can never diverge from what ships.
# Exclude editor/OS cruft only.
cp -R "$SITE_DIR/." "$STAGE/"
find "$STAGE" -name '.DS_Store' -delete 2>/dev/null || true

# A plain-language note for whoever receives the stick.
cat > "$STAGE/START-HERE.txt" <<'EOF'
Open Door Range — offline bundle
================================

This folder is the entire virtual range. It needs no internet: everything runs
in your browser, and nothing you do here is ever sent anywhere.

TO RUN IT
---------
A browser will not load ES modules or the wasm engine straight off the disk
(the file:// protocol blocks them for security). So serve this folder with any
tiny local web server and open the address it prints. For example:

  Python 3 (already on most Macs and Linux):
      cd into this folder, then:
      python3 -m http.server 8000
      then open  http://localhost:8000/  in your browser

  Node, if you prefer:
      npx http-server -p 8000

That is all. The first load caches the app for offline use, so after that it
keeps working even if you stop the server or lose the network.

PRIVACY
-------
No accounts, no analytics, no backend. Progress is stored in your own browser
and goes nowhere. Sharing a laptop at a booth? The range has a "Reset session"
button (in the Course panel) that clears this browser's progress for the next
person.
EOF

# Zip it if we can; otherwise leave the folder, which is just as usable.
if command -v zip >/dev/null 2>&1; then
  rm -f "$ZIP_PATH"
  ( cd "$OUT_DIR" && zip -r -q "open-door-range-offline.zip" "open-door-range-offline" )
  echo "Bundle folder: $STAGE"
  echo "Bundle zip:    $ZIP_PATH"
else
  echo "Bundle folder: $STAGE"
  echo "(zip not found on PATH — hand out the folder, or zip it yourself.)"
fi

echo
echo "Done. Hand out the zip (or the folder). Recipient runs START-HERE.txt."
