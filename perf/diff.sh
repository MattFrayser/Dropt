#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <old-snapshot-dir> <new-snapshot-dir>"
    echo ""
    echo "Available snapshots:"
    ls -1d "$(cd "$(dirname "$0")" && pwd)/snapshots"/*/ 2>/dev/null | while read -r d; do
        basename "$d"
    done
    exit 1
fi

OLD_DIR="$1"
NEW_DIR="$2"

# Validate inputs
for dir in "$OLD_DIR" "$NEW_DIR"; do
    if [ ! -f "$dir/collapsed.txt" ]; then
        echo "ERROR: $dir/collapsed.txt not found"
        exit 1
    fi
done

OLD_NAME=$(basename "$OLD_DIR")
NEW_NAME=$(basename "$NEW_DIR")
DIFF_SVG="$NEW_DIR/diff-vs-${OLD_NAME}.svg"

echo "=== Performance Diff ==="
echo "Old: $OLD_NAME"
echo "New: $NEW_NAME"
echo ""

# --- Generate differential flamegraph ---
echo "[1/2] Generating differential flamegraph..."
~/.cargo/bin/inferno-diff-folded "$OLD_DIR/collapsed.txt" "$NEW_DIR/collapsed.txt" \
    | ~/.cargo/bin/inferno-flamegraph > "$DIFF_SVG" 2>/dev/null

echo "  Saved: $DIFF_SVG"
echo "  Red = got slower, Blue = got faster"
echo ""

# --- Side-by-side summary ---
echo "[2/2] Summary comparison:"
echo ""
paste <(
    echo "--- OLD: $OLD_NAME ---"
    head -30 "$OLD_DIR/summary.txt"
) <(
    echo "--- NEW: $NEW_NAME ---"
    head -30 "$NEW_DIR/summary.txt"
) | column -t -s $'\t'
