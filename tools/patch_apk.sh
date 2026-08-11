#!/usr/bin/env bash
set -euo pipefail
# Patch Root-My-Galaxy APK to include manifest entries that point to
# artifacts in this repository. This script runs locally or in CI.
# Requirements: apktool, zipalign (optional), apksigner (optional)
# Usage:
#   ./tools/patch_apk.sh releases/Root-My-Galaxy-v0.2.6-debug.apk
# To sign the rebuilt APK, set these environment variables before running:
#   KEYSTORE=/path/to/keystore.jks
#   KEYSTORE_PASS=keystore-password
#   KEY_ALIAS=key-alias
#   KEY_PASS=key-password

IN_APK="${1:-}"
if [ -z "$IN_APK" ]; then
  echo "Usage: $0 <path-to-apk>" >&2
  exit 2
fi
if [ ! -f "$IN_APK" ]; then
  echo "APK not found: $IN_APK" >&2
  exit 3
fi

WORKDIR="$(mktemp -d)"
OUT_DIR="$WORKDIR/out"
UNSIGNED_OUT="$(dirname "$IN_APK")/Root-My-Galaxy-v0.2.6-debug-unsigned.apk"
SIGNED_OUT="$(dirname "$IN_APK")/Root-My-Galaxy-v0.2.6-debug-signed.apk"

echo "Decompiling $IN_APK -> $OUT_DIR"
apktool d -f "$IN_APK" -o "$OUT_DIR"

SNIPPET_FILE="$(pwd)/manifests/a17-manifest-snippet.xml"
if [ ! -f "$SNIPPET_FILE" ]; then
  echo "Snippet not found at $SNIPPET_FILE" >&2
  exit 4
fi

MANIFEST_FILE="$OUT_DIR/AndroidManifest.xml"
if [ ! -f "$MANIFEST_FILE" ]; then
  echo "Decompiled manifest not found: $MANIFEST_FILE" >&2
  exit 5
fi

# Insert the snippet before the closing </application> tag.
# This is a conservative text merge; if your manifest uses a different
# formatting, adjust the insertion accordingly.
SNIPPET_CONTENT="$(sed 's/"/"\"/g' "$SNIPPET_FILE" | sed ':a;N;$!ba;s/\n/\\n/g')"

awk -v ins="$SNIPPET_CONTENT" 'BEGIN{added=0}
  /<\/application>/ && !added {
    # print snippet unescaped
    sub(/\\n/,"\n",ins)
    printf "%s\n", ins
    added=1
  }
  {print}
' "$MANIFEST_FILE" > "$MANIFEST_FILE.new" && mv "$MANIFEST_FILE.new" "$MANIFEST_FILE"

echo "Rebuilding APK"
apktool b "$OUT_DIR" -o "$UNSIGNED_OUT"

# Optionally align and sign
if [ -n "${KEYSTORE-}" ]; then
  if command -v zipalign >/dev/null 2>&1; then
    echo "Running zipalign"
    TMP_ALIGNED="$WORKDIR/aligned.apk"
    zipalign -v -p 4 "$UNSIGNED_OUT" "$TMP_ALIGNED"
    mv "$TMP_ALIGNED" "$UNSIGNED_OUT"
  fi
  if command -v apksigner >/dev/null 2>&1; then
    echo "Signing APK -> $SIGNED_OUT"
    apksigner sign --ks "$KEYSTORE" --ks-pass "pass:$KEYSTORE_PASS" --key-pass "pass:$KEY_PASS" --out "$SIGNED_OUT" "$UNSIGNED_OUT"
    echo "Signed APK: $SIGNED_OUT"
  else
    echo "apksigner not found; unsigned APK at $UNSIGNED_OUT"
  fi
else
  echo "Unsigned rebuilt APK at: $UNSIGNED_OUT"
fi

echo "Cleaning up temporary workdir: $WORKDIR"
# Leave workdir for inspection by default; remove if you prefer:
# rm -rf "$WORKDIR"

echo "Done"
